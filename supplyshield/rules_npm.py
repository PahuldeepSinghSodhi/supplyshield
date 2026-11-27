"""Static rules for JavaScript (npm) packages.

Uses package.json analysis plus pattern rules over the JavaScript source.
Code is read as text, never executed.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from .common import blob_findings, downgrade_non_shipped, js_secret_strings, unreadable_finding
from .models import Finding

MAX_FILE_BYTES = 2_000_000
LIFECYCLE = ("preinstall", "install", "postinstall")
# Install scripts that are common and benign (native add-on builds).
BENIGN_SCRIPTS = re.compile(r"^\s*(node-gyp rebuild|node-gyp-build|prebuild-install(\s.*)?|husky install)\s*$")
DANGEROUS_SCRIPT = re.compile(r"curl|wget|Invoke-WebRequest|iwr |powershell|bash -c|sh -c|node -e|base64|\|\s*sh")
JS_FILE_IN_SCRIPT = re.compile(r"node\s+([\w./\\-]+\.(?:c|m)?js)")

RULES = [
    # (rule id, category, severity, regex, explanation, fix)
    ("NPM-PROCESS", "process", "medium",
     re.compile(r"""require\(\s*['"](?:node:)?child_process['"]\s*\)|from\s+['"](?:node:)?child_process['"]"""),
     "The package loads child_process to run system commands. Malware uses this to download and run "
     "second-stage programs.",
     "Check which commands are run and why a library needs them."),
    ("NPM-DYNAMIC-EXEC", "exec", "high",
     re.compile(r"\beval\s*\(|\bnew\s+Function\s*\("),
     "Code is built at run time and executed with eval/new Function, so what actually runs cannot be "
     "seen by reading the source.",
     "Check where the executed string comes from."),
    ("NPM-NETWORK", "network", "medium",
     re.compile(r"""require\(\s*['"](?:node:)?(?:https?|net|dns|dgram|tls)['"]\s*\)|from\s+['"](?:node:)?(?:https?|net|dns|dgram|tls)['"]|\bfetch\s*\(|\baxios\b|XMLHttpRequest"""),
     "The package opens network connections. Combined with secret access or install-time execution, "
     "this is how stolen data leaves the machine.",
     "Check the destination address and what data is sent."),
    ("NPM-ENV-DUMP", "secrets", "high",
     re.compile(r"(?:JSON\.stringify|String|querystring\.stringify|new\s+URLSearchParams)\(\s*process\.env\s*\)"),
     "The package turns ALL environment variables into text that can be sent somewhere. Environment "
     "variables usually hold API keys, cloud tokens and passwords.",
     "Libraries should read only the variables they need. Treat as credential theft."),
    # Learned from real data: `debug` lists variable names to find its own DEBUG_* settings, and many
    # tools spread process.env into a child process's environment. Common and harmless on its own.
    ("NPM-ENV-COPY", "secrets", "low",
     re.compile(r"Object\.(?:keys|entries|values)\(\s*process\.env\s*\)|\.\.\.\s*process\.env"),
     "The package reads or copies all environment variables. This is common (for example, to pass them to "
     "a child process) and only dangerous if the data is then sent somewhere.",
     "Check where the data goes."),
    ("NPM-RECON", "recon", "medium",
     re.compile(r"\.(?:hostname|userInfo|networkInterfaces)\s*\(\s*\)"),
     "The package collects identifying details about the machine or user (host name, user name, network "
     "addresses). Install-time malware does this first to fingerprint its victims.",
     "Check why a library needs to know who and where it is running."),
    ("NPM-OBF-IDENTIFIERS", "obfuscation", "medium",
     re.compile(r"\b_0x[0-9a-f]{4,}\b"),
     "Identifiers like _0x1a2b are produced by JavaScript obfuscators, which malware uses to hide its "
     "behaviour.",
     "Legitimate packages rarely ship obfuscated code. Review carefully."),
]
B64_DECODE = re.compile(r"""Buffer\.from\([^)]*['"]base64['"]\s*\)|\batob\s*\(""")


def _scan_js(path: Path, rel: str, install_time: bool) -> list[Finding]:
    try:
        text = path.read_text(encoding="utf-8-sig", errors="replace")
    except OSError as e:  # e.g. blocked by antivirus: report it, never crash
        return [unreadable_finding(rel, e)]
    out: list[Finding] = []
    lines = text.splitlines()
    secret_lines: dict[str, list[tuple[int, str]]] = {"strong": [], "weak": []}
    for lineno, line in enumerate(lines, 1):
        for rule, cat, sev, rx, expl, fix in RULES:
            if rule == "NPM-DYNAMIC-EXEC" and not install_time:
                sev = "medium"  # eval in library code is often a template/compiler; high at install time
            if rx.search(line):
                out.append(Finding(rule, cat, sev, rel, lineno, line.strip()[:100], expl, fix, install_time))
        for kind, _ in js_secret_strings(line):
            secret_lines[kind].append((lineno, line))
    # Bare file names ("id_rsa", "Cookies") count only next to a real credential path in the same file.
    hits = secret_lines["strong"] + (secret_lines["weak"] if secret_lines["strong"] else [])
    for lineno, line in sorted(set(hits)):
        out.append(Finding(
            "NPM-SECRET-PATH", "secrets", "high", rel, lineno, line.strip()[:100],
            "The code refers to a credential location (such as SSH keys, npm tokens or browser password "
            "stores).",
            "No ordinary library needs these files. Treat as credential theft.", install_time))
    # Decoding a hidden payload and executing it in the same file.
    if B64_DECODE.search(text) and RULES[1][3].search(text):
        ln = next(i for i, l in enumerate(lines, 1) if B64_DECODE.search(l))
        out.append(Finding(
            "NPM-DECODE-EXEC", "obfuscation", "critical", rel, ln, lines[ln - 1].strip()[:100],
            "Hidden code is decoded from base64 and executed. This is the classic way malware conceals its "
            "payload from reviewers and keyword-based scanners.",
            "Do not install. Decode the payload in a sandbox to see what it does.", install_time))
    for f in blob_findings(text, rel):
        f.install_time = install_time
        out.append(f)
    return downgrade_non_shipped(out)


def scan_npm(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    install_files: set[str] = set()
    try:
        pkg = json.loads((root / "package.json").read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        pkg = {}

    scripts = pkg.get("scripts") or {}
    for hook in LIFECYCLE:
        cmd = scripts.get(hook)
        if not cmd:
            continue
        for m in JS_FILE_IN_SCRIPT.finditer(cmd):
            install_files.add(Path(m.group(1)).as_posix().lstrip("./"))
        if BENIGN_SCRIPTS.match(cmd):
            sev, expl = "low", ("An install script builds a native add-on. This is common and usually "
                                "benign, but it still runs code during installation.")
        elif DANGEROUS_SCRIPT.search(cmd):
            sev, expl = "critical", ("An install script downloads or runs commands directly from the shell "
                                     "during installation, before the user ever uses the package.")
        else:
            sev, expl = "medium", ("The package runs a script automatically during installation. Most "
                                   "malicious npm packages use this to execute on install.")
        findings.append(Finding(
            "NPM-INSTALL-SCRIPT", "install", sev, "package.json", 0, f'"{hook}": "{cmd}"', expl,
            "Install with --ignore-scripts and review the script before allowing it.", install_time=True))

    for path in sorted(root.rglob("*")):
        if path.suffix not in {".js", ".cjs", ".mjs"} or not path.is_file():
            continue
        if any(p in {"node_modules", ".git", "test", "tests", "__tests__"} for p in path.relative_to(root).parts):
            continue
        if path.stat().st_size > MAX_FILE_BYTES:
            continue
        rel = path.relative_to(root).as_posix()
        findings += _scan_js(path, rel, rel in install_files)
    return findings

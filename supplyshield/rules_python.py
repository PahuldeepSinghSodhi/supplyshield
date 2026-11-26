"""Static rules for Python (PyPI) packages, based on the abstract syntax tree.

Code is parsed, never imported or executed.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

from .common import blob_findings, sensitive_path_hits
from .models import Finding

MAX_FILE_BYTES = 2_000_000

EXEC_FUNCS = {"exec", "eval", "compile", "__import__", "builtins.exec", "builtins.eval"}
DECODE_FUNCS = {
    "base64.b64decode", "base64.b32decode", "base64.b85decode", "base64.a85decode",
    "base64.decodebytes", "zlib.decompress", "marshal.loads", "codecs.decode",
    "bytes.fromhex", "binascii.unhexlify", "binascii.a2b_base64", "lzma.decompress", "gzip.decompress",
}
PROCESS_FUNCS = {
    "os.system", "os.popen", "os.execv", "os.execve", "os.execl", "os.execvp", "os.spawnl", "os.startfile",
    "subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output",
    "subprocess.Popen", "subprocess.getoutput", "pty.spawn",
}
NETWORK_PREFIXES = (
    "urllib.request.", "requests.", "httpx.", "http.client.", "socket.", "ftplib.",
    "smtplib.", "aiohttp.", "urllib3.",
)
DOWNLOAD_AND_RUN = re.compile(r"(curl|wget|Invoke-WebRequest|iwr)\b.*\|\s*(ba)?sh|(curl|wget)\b.*&&\s*(ba)?sh|powershell.*(iex|Invoke-Expression)", re.I)
INSTALL_BASES = {"install", "develop", "egg_info", "build_py", "sdist", "bdist_egg", "build_ext"}


class _Visitor(ast.NodeVisitor):
    def __init__(self, rel: str, install_time: bool):
        self.rel = rel
        self.install_time = install_time
        self.aliases: dict[str, str] = {}
        self.findings: list[Finding] = []

    # --- helpers -----------------------------------------------------
    def _name(self, node: ast.AST) -> str:
        parts = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(self.aliases.get(node.id, node.id))
        else:
            return ""
        return ".".join(reversed(parts))

    def _add(self, rule, cat, sev, node, evidence, expl, fix):
        self.findings.append(Finding(
            rule, cat, sev, self.rel, getattr(node, "lineno", 0), evidence[:100], expl, fix,
            install_time=self.install_time,
        ))

    def _contains_decode(self, node: ast.AST) -> bool:
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call) and self._name(sub.func) in DECODE_FUNCS:
                return True
        return False

    # --- imports -------------------------------------------------------
    def visit_Import(self, node: ast.Import):
        for a in node.names:
            self.aliases[(a.asname or a.name).split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module:
            for a in node.names:
                self.aliases[a.asname or a.name] = f"{node.module}.{a.name}"
        self.generic_visit(node)

    # --- install hooks ---------------------------------------------------
    def visit_ClassDef(self, node: ast.ClassDef):
        if self.install_time:
            for base in node.bases:
                if self._name(base).split(".")[-1] in INSTALL_BASES:
                    self._add(
                        "PY-INSTALL-HOOK", "install", "high", node, f"class {node.name}({self._name(base)})",
                        "setup.py replaces a standard installation step with custom code, so that code runs "
                        "automatically on the user's machine the moment the package is installed.",
                        "Read the custom install class. Prefer wheels (.whl), which do not run setup.py.",
                    )
        self.generic_visit(node)

    # --- calls -------------------------------------------------------------
    def visit_Call(self, node: ast.Call):
        name = self._name(node.func)
        src = ast.unparse(node)

        if name in EXEC_FUNCS:
            literal_only = all(isinstance(a, ast.Constant) for a in node.args)
            if any(self._contains_decode(a) for a in node.args):
                self._add(
                    "PY-DECODE-EXEC", "obfuscation", "critical", node, src,
                    "Hidden code is decoded and then executed. This is the classic way malware conceals its "
                    "payload from reviewers and keyword-based scanners.",
                    "Do not install. Decode the payload in a sandbox to see what it does.",
                )
            elif not literal_only:
                self._add(
                    "PY-DYNAMIC-EXEC", "exec", "high", node, src,
                    "Code is built at run time and executed with exec/eval, so what actually runs cannot be "
                    "seen by reading the source.",
                    "Check where the executed string comes from.",
                )

        elif name in PROCESS_FUNCS and any(
            isinstance(s, ast.Constant) and isinstance(s.value, str) and DOWNLOAD_AND_RUN.search(s.value)
            for s in ast.walk(node)
        ):
            self._add(
                "PY-DOWNLOAD-EXEC", "process", "critical", node, src,
                "A system command downloads something from the internet and runs it immediately "
                "(e.g. 'curl ... | sh'). This is how second-stage malware is fetched.",
                "Do not install. Nothing in a library should download and run remote scripts.",
            )

        elif name in PROCESS_FUNCS:
            self._add(
                "PY-PROCESS", "process", "medium", node, src,
                "The package starts system commands. Legitimate build tools do this, but malware uses it to "
                "download and run second-stage programs.",
                "Check which command is run and why a library needs it.",
            )

        elif name.startswith(NETWORK_PREFIXES):
            self._add(
                "PY-NETWORK", "network", "medium", node, src,
                "The package opens a network connection. Combined with secret access or install-time "
                "execution, this is how stolen data leaves the machine.",
                "Check the destination address and what data is sent.",
            )

        # Bulk copies of all environment variables (API keys, tokens live here).
        if name in {"dict", "json.dumps", "str", "repr", "list"} and any(
            self._name(a) == "os.environ" for a in node.args
        ) or name == "os.environ.copy" or name == "os.environ.items":
            self._add(
                "PY-ENV-DUMP", "secrets", "high", node, src,
                "The package copies ALL environment variables, which usually hold API keys, cloud tokens "
                "and passwords.",
                "Libraries should read only the specific variables they need. Treat as credential theft.",
            )

        if name == "setup" and self.install_time:
            for kw in node.keywords:
                if kw.arg == "cmdclass":
                    self._add(
                        "PY-INSTALL-HOOK", "install", "high", node, "setup(cmdclass=...)",
                        "setup() registers custom commands that run during installation.",
                        "Read every class listed in cmdclass before installing.",
                    )
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant):
        if isinstance(node.value, str):
            hits = sensitive_path_hits(node.value)
            if hits:
                self._add(
                    "PY-SECRET-PATH", "secrets", "high", node, repr(node.value),
                    f"The code refers to a credential location ({', '.join(hits)}) such as SSH keys, cloud "
                    "credentials or browser password stores.",
                    "No ordinary library needs these files. Treat as credential theft.",
                )


def scan_python(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in sorted(root.rglob("*.py")):
        if any(part in {".git", "node_modules", "__pycache__", ".venv", "venv"} for part in path.parts):
            continue
        if path.stat().st_size > MAX_FILE_BYTES:
            continue
        rel = path.relative_to(root).as_posix()
        text = path.read_text(encoding="utf-8-sig", errors="replace")
        install_time = rel == "setup.py"
        try:
            tree = ast.parse(text, filename=rel)
        except SyntaxError:
            findings.append(Finding(
                "PY-UNPARSABLE", "obfuscation", "low", rel, 0, "syntax error",
                "The file cannot be parsed, so it could not be analysed.", "Review manually.",
            ))
            continue
        v = _Visitor(rel, install_time)
        v.visit(tree)
        findings += v.findings
        for f in blob_findings(text, rel):
            f.install_time = install_time
            findings.append(f)
        if install_time and any(f.category in {"process", "network", "secrets", "exec", "obfuscation"}
                                for f in v.findings):
            findings.append(Finding(
                "PY-SETUP-CODE", "install", "high", rel, 0, "risky calls inside setup.py",
                "setup.py itself performs risky actions. setup.py runs automatically when a source "
                "package is installed, before the user ever uses the library.",
                "Install from a wheel, or review setup.py line by line.",
                install_time=True,
            ))
    return findings

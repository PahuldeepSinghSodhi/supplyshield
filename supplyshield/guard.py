"""Pre-install guard: check packages BEFORE pip / npm installs them.

Puts SupplyShield in the path of every install command run by a developer, a
build pipeline or an AI coding agent. For each package in the command it fetches
the package WITHOUT installing it (pip: wheel only; npm: pack with scripts
disabled), scans it, and blocks the command unless every package is SAFE.

AI coding agent (Claude Code), in .claude/settings.json:
    {"hooks": {"PreToolUse": [{"matcher": "Bash",
        "hooks": [{"type": "command", "command": "python -m supplyshield.guard"}]}]}}
  The hook receives the agent's command as JSON on stdin. Exit code 2 blocks the
  command and the reason (stderr) is shown to the agent, which can then choose a
  different package or version.

Shell / CI, before installing:
    python -m supplyshield.guard -- pip install requests==2.31.0

Exit codes: 0 = allowed, 2 = blocked.
Set SUPPLYSHIELD_GUARD_VULNS=0 to skip the known-vulnerability lookup.
"""
from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from .analyzer import scan
from .cli import exit_code
from .loader import LoadError

PIP_VALUE_FLAGS = {"-i", "--index-url", "--extra-index-url", "-c", "--constraint", "-t", "--target",
                   "--prefix", "--root", "--find-links", "-f", "--python-version", "--platform"}
NPM_INSTALL = {"install", "i", "add"}


def parse_installs(command: str) -> list[tuple[str, str]]:
    """Return [(ecosystem, package spec)] for every pip/npm install in a shell command."""
    found: list[tuple[str, str]] = []
    for part in command.replace("&&", ";").replace("||", ";").split(";"):
        try:
            # Windows paths use backslashes, which POSIX-style splitting would treat as escapes.
            tok = [t.strip("\"'") for t in shlex.split(part, posix=os.name != "nt")]
        except ValueError:
            continue
        # strip leading wrappers such as `sudo`, `python -m`, `uv`
        while tok and tok[0] in {"sudo", "uv", "python", "python3", "py", "-m"}:
            tok = tok[1:]
        if len(tok) < 2:
            continue
        tool, verb, args = Path(tok[0]).stem.lower(), tok[1], tok[2:]
        if tool in {"pip", "pip3"} and verb == "install":
            i = 0
            while i < len(args):
                a = args[i]
                if a in ("-r", "--requirement") and i + 1 < len(args):
                    req = Path(args[i + 1])
                    if req.is_file():
                        for line in req.read_text(encoding="utf-8-sig").splitlines():
                            line = line.split("#")[0].strip()
                            if line and not line.startswith("-"):
                                found.append(("pypi", line))
                    i += 2
                    continue
                if a in PIP_VALUE_FLAGS:
                    i += 2
                    continue
                if not a.startswith("-"):
                    found.append(("pypi", a))
                i += 1
        elif tool in {"npm", "pnpm", "yarn"} and verb in NPM_INSTALL:
            found += [("npm", a) for a in args if not a.startswith("-")]
    return found


def _is_local(spec: str) -> bool:
    """A path to a folder or archive (not a registry name such as 'requests')."""
    looks_like_path = spec.startswith((".", "/", "\\", "~")) or "/" in spec or "\\" in spec or \
        spec.lower().endswith((".whl", ".tar.gz", ".tgz", ".zip"))
    return looks_like_path and Path(spec).expanduser().exists()


def _fetch(eco: str, spec: str, dest: Path) -> list[Path]:
    """Download a package without installing it or running any of its code."""
    if eco == "pypi":
        # Wheels only: fetching a source package would make pip run its setup.py.
        cmd = [sys.executable, "-m", "pip", "download", spec, "--no-deps", "--only-binary", ":all:",
               "-d", str(dest), "-q", "--disable-pip-version-check"]
    else:
        npm = shutil.which("npm")
        if npm is None:
            return []
        cmd = [npm, "pack", spec, "--ignore-scripts", "--pack-destination", str(dest), "--silent"]
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    except (OSError, subprocess.TimeoutExpired):
        return []
    return sorted(p for p in dest.iterdir() if p.is_file())


def check(command: str) -> tuple[int, str]:
    """Return (exit code, message) for a shell command: 0 allow, 2 block."""
    installs = parse_installs(command)
    if not installs:
        return 0, ""
    vulns = os.environ.get("SUPPLYSHIELD_GUARD_VULNS", "1") != "0"
    lines, blocked = [], False
    for eco, spec in installs:
        with tempfile.TemporaryDirectory(prefix="supplyshield-guard-") as tmp:
            targets = [Path(spec).expanduser()] if _is_local(spec) else _fetch(eco, spec, Path(tmp))
            if not targets:
                blocked = True
                lines.append(f"BLOCKED {spec}: could not fetch it for scanning (no wheel / package not found). "
                             "Review it manually before installing.")
                continue
            for t in targets:
                try:
                    r = scan(t, vulns=vulns)
                except LoadError as e:
                    blocked = True
                    lines.append(f"BLOCKED {spec}: {e}")
                    continue
                code = exit_code(r)
                status = "ok     " if code == 0 else "BLOCKED"
                blocked |= code != 0
                detail = f"{r.verdict} {r.score}/100"
                if r.vulnerabilities:
                    detail += f", {len(r.vulnerabilities)} known vulnerabilities"
                lines.append(f"{status} {r.package} {r.version}: {detail}")
                for f in [f for f in r.findings if f.severity in ("critical", "high")][:3]:
                    first_sentence = f.explanation.split(". ")[0].rstrip(".")
                    lines.append(f"        - {f.rule_id}: {first_sentence}.")
                for f in r.vulnerabilities[:2]:
                    lines.append(f"        - {f.evidence}: {f.fix}")
    head = ("SupplyShield blocked this install. Choose another package or version, or ask the user."
            if blocked else "SupplyShield: all packages passed.")
    return (2 if blocked else 0), "\n".join([head] + lines)


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == "--":
        command = shlex.join(argv[1:])
    elif argv:
        command = " ".join(argv)
    else:  # agent hook: JSON on stdin
        try:
            # PowerShell prefixes piped text with a byte-order mark; strip it before parsing.
            data = json.loads(sys.stdin.read().lstrip("﻿"))
        except json.JSONDecodeError:
            return 0  # not a hook payload: nothing to check
        command = (data.get("tool_input") or {}).get("command", "")
    code, message = check(command)
    if message:
        print(message, file=sys.stderr if code else sys.stdout)
    return code


if __name__ == "__main__":
    sys.exit(main())

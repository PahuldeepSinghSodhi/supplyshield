"""Command-line interface.

    supplyshield scan <package> [<package> ...] [--vulns] [--json]
    supplyshield diff <old-version> <new-version> [--vulns] [--json]

<package> may be a folder, .tar.gz / .tgz (sdist or npm pack), .whl or .zip.
--vulns also checks the exact version against advisory databases for known
vulnerabilities and known malware (the pip-audit / npm audit part; needs internet).
Exit code: 0 = safe, 1 = suspicious or has known vulnerabilities, 2 = malicious, 3 = error.
"""
from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .analyzer import diff, scan
from .loader import LoadError
from .models import Report
from .report import render

EXIT = {"SAFE": 0, "SUSPICIOUS": 1, "MALICIOUS": 2}
VULNS_HELP = ("also look up known vulnerabilities and known malware for this exact version "
              "(same job as pip-audit / npm audit; uses the OSV.dev database, needs internet)")


def exit_code(report: Report) -> int:
    return max(EXIT[report.verdict], 1 if report.vulnerabilities else 0)


def _summary(label: str, r: Report) -> str:
    vulns = f", {len(r.vulnerabilities)} known vulnerabilities" if r.vulns_checked else ""
    return f"{label} {r.version}: {r.verdict} ({r.score}/100){vulns}"


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    p = argparse.ArgumentParser(prog="supplyshield",
                                description="Detect malicious behaviour in PyPI and npm packages before installing them.")
    p.add_argument("--version", action="version", version=f"supplyshield {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan one or more packages")
    s.add_argument("packages", nargs="+")
    s.add_argument("--vulns", action="store_true", help=VULNS_HELP)
    s.add_argument("--json", action="store_true", help="machine-readable output")
    d = sub.add_parser("diff", help="show risky behaviour introduced by an update")
    d.add_argument("old")
    d.add_argument("new")
    d.add_argument("--vulns", action="store_true", help=VULNS_HELP)
    d.add_argument("--json", action="store_true")
    args = p.parse_args(argv)

    try:
        if args.cmd == "scan":
            reports = [scan(path, vulns=args.vulns) for path in args.packages]
            if args.json:
                print(json.dumps([r.to_dict() for r in reports], indent=2))
            else:
                print("\n".join(render(r) for r in reports))
            return max(exit_code(r) for r in reports)

        old, new, delta = diff(args.old, args.new, vulns=args.vulns)
        if args.json:
            print(json.dumps({"old": old.to_dict(), "new": new.to_dict(), "introduced": delta.to_dict()}, indent=2))
        else:
            print(_summary("Old version", old))
            print(_summary("New version", new) + "\n")
            print(render(delta, title="Behaviour introduced by update"))
        return exit_code(delta)
    except LoadError as e:
        print(f"error: {e}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())

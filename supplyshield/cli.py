"""Command-line interface.

    supplyshield scan <package> [<package> ...] [--json]
    supplyshield diff <old-version> <new-version> [--json]

<package> may be a folder, .tar.gz / .tgz (sdist or npm pack), .whl or .zip.
Exit code: 0 = safe, 1 = suspicious, 2 = malicious, 3 = error.
"""
from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .analyzer import diff, scan
from .loader import LoadError
from .report import render

EXIT = {"SAFE": 0, "SUSPICIOUS": 1, "MALICIOUS": 2}


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    p = argparse.ArgumentParser(prog="supplyshield",
                                description="Detect malicious behaviour in PyPI and npm packages before installing them.")
    p.add_argument("--version", action="version", version=f"supplyshield {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan one or more packages")
    s.add_argument("packages", nargs="+")
    s.add_argument("--json", action="store_true", help="machine-readable output")
    d = sub.add_parser("diff", help="show risky behaviour introduced by an update")
    d.add_argument("old")
    d.add_argument("new")
    d.add_argument("--json", action="store_true")
    args = p.parse_args(argv)

    try:
        if args.cmd == "scan":
            reports = [scan(path) for path in args.packages]
            if args.json:
                print(json.dumps([r.to_dict() for r in reports], indent=2))
            else:
                print("\n".join(render(r) for r in reports))
            return max(EXIT[r.verdict] for r in reports)

        old, new, delta = diff(args.old, args.new)
        if args.json:
            print(json.dumps({"old": old.to_dict(), "new": new.to_dict(), "introduced": delta.to_dict()}, indent=2))
        else:
            print(f"Old version {old.version}: {old.verdict} ({old.score}/100)")
            print(f"New version {new.version}: {new.verdict} ({new.score}/100)\n")
            print(render(delta, title="Behaviour introduced by update"))
        return EXIT[delta.verdict]
    except LoadError as e:
        print(f"error: {e}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())

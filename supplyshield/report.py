"""Human-readable output."""
from __future__ import annotations

import textwrap

from .models import Report

ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
BADGE = {"SAFE": "[ SAFE ]", "SUSPICIOUS": "[ SUSPICIOUS ]", "MALICIOUS": "[ MALICIOUS ]"}


def _wrap(text: str, indent: str) -> str:
    return textwrap.fill(text, width=92, initial_indent=indent, subsequent_indent=indent)


def render(report: Report, title: str = "SupplyShield scan") -> str:
    lines = [
        "=" * 92,
        f"{title}: {report.package} {report.version} ({report.ecosystem})",
        f"Verdict: {BADGE[report.verdict]}   Risk score: {report.score}/100   Findings: {len(report.findings)}",
        "=" * 92,
    ]
    if report.chains:
        lines.append("Attack chains detected:")
        lines += [f"  >> {c}" for c in report.chains]
        lines.append("")
    if not report.findings:
        lines.append("No risky behaviour found.")
    for f in sorted(report.findings, key=lambda f: (ORDER[f.severity], f.file, f.line)):
        where = f.file + (f":{f.line}" if f.line else "")
        tags = []
        if f.install_time:
            tags.append("runs at install")
        if f.new_in_version:
            tags.append("NEW in this version")
        tag = f"  [{', '.join(tags)}]" if tags else ""
        lines.append(f"{f.severity.upper():<9}{f.rule_id:<20}{where}{tag}")
        lines.append(f"         code: {f.evidence}")
        lines.append(_wrap("why:  " + f.explanation, "         "))
        lines.append(_wrap("fix:  " + f.fix, "         "))
        lines.append("")
    return "\n".join(lines)

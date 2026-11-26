"""Human-readable output."""
from __future__ import annotations

import textwrap

from .models import Report

ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
BADGE = {"SAFE": "[ SAFE ]", "SUSPICIOUS": "[ SUSPICIOUS ]", "MALICIOUS": "[ MALICIOUS ]"}


def _wrap(text: str, indent: str) -> str:
    return textwrap.fill(text, width=92, initial_indent=indent, subsequent_indent=indent)


def _vuln_line(report: Report) -> str:
    v = report.vulnerabilities
    if not report.vulns_checked:
        return ""
    if not v:
        return "Known vulnerabilities: none"
    worst = min(v, key=lambda f: ORDER[f.severity]).severity
    return f"Known vulnerabilities: {len(v)} (worst: {worst}) -> update to a fixed version"


def render(report: Report, title: str = "SupplyShield scan") -> str:
    behaviour = [f for f in report.findings if f.category != "vulnerability"]
    lines = [
        "=" * 92,
        f"{title}: {report.package} {report.version} ({report.ecosystem})",
        f"Verdict: {BADGE[report.verdict]}   Risk score: {report.score}/100   Findings: {len(behaviour)}",
    ]
    if vl := _vuln_line(report):
        lines.append(vl)
    lines.append("=" * 92)
    lines += [f"Note: {n}" for n in report.notes]
    if report.notes:
        lines.append("")
    if report.chains:
        lines.append("Attack chains detected:")
        lines += [f"  >> {c}" for c in report.chains]
        lines.append("")
    if not behaviour:
        lines.append("No risky behaviour found.")
        lines.append("")
    for f in sorted(behaviour, key=lambda f: (ORDER[f.severity], f.file, f.line)):
        lines += _finding(f)
    if report.vulnerabilities:
        lines.append("-" * 92)
        lines.append("Known vulnerabilities in this exact version (from advisory databases, like pip-audit / npm audit):")
        lines.append("")
        for f in sorted(report.vulnerabilities, key=lambda f: ORDER[f.severity]):
            lines += _finding(f)
    return "\n".join(lines)


def _finding(f) -> list[str]:
    where = f.file + (f":{f.line}" if f.line else "")
    tags = []
    if f.install_time:
        tags.append("runs at install")
    if f.new_in_version:
        tags.append("NEW in this version")
    tag = f"  [{', '.join(tags)}]" if tags else ""
    label = "id:  " if f.category in ("vulnerability", "malware") else "code:"
    return [
        f"{f.severity.upper():<9}{f.rule_id:<20}{where}{tag}",
        f"         {label} {f.evidence}",
        _wrap("why:  " + f.explanation, "         "),
        _wrap("fix:  " + f.fix, "         "),
        "",
    ]

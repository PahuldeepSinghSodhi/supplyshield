"""Turn findings into a risk score, attack chains and a verdict.

Single signals (a network call, a subprocess) are common in legitimate code.
What separates malware is the COMBINATION of signals, so SupplyShield adds
bonus points when findings form a known attack chain.
"""
from __future__ import annotations

from collections import Counter

from .models import SEVERITY_POINTS, Finding, Report

SUSPICIOUS_AT = 25
MALICIOUS_AT = 60
MAX_REPEATS_PER_RULE = 2  # repeated hits of one rule add little extra evidence

# (chain name, required categories, extra condition, bonus points)
CHAINS = [
    ("Install-time data theft: runs on install, reads secrets and sends them out",
     {"install", "secrets", "network"}, None, 40),
    ("Credential exfiltration: reads secrets and has network access",
     {"secrets", "network"}, None, 25),
    ("Install-time command execution: runs system commands during installation",
     {"install", "process"}, "install_time_process", 20),
    ("Hidden payload: obfuscated code that is executed",
     {"obfuscation", "exec"}, None, 20),
]


def score(findings: list[Finding]) -> tuple[int, list[str]]:
    # A known vulnerability is a bug in an honest package, not evidence of malice, so it is
    # reported separately (see report.py / cli.py) and does not add to the malice score.
    # A known-malware advisory is conclusive on its own.
    if any(f.category == "malware" for f in findings):
        return 100, ["Listed as confirmed malware in an advisory database"]
    findings = [f for f in findings if f.category != "vulnerability"]
    seen: Counter = Counter()
    total = 0
    for f in findings:
        seen[f.rule_id] += 1
        if seen[f.rule_id] <= MAX_REPEATS_PER_RULE:
            total += SEVERITY_POINTS[f.severity]

    # Ignore low-severity findings (e.g. benign native-build scripts) when matching chains.
    cats = {f.category for f in findings if f.severity != "low"}
    if any(f.rule_id.endswith("DECODE-EXEC") for f in findings):
        cats.add("exec")  # decode-then-execute is both obfuscation and execution
    chains = []
    for name, needed, cond, bonus in CHAINS:
        if not needed <= cats:
            continue
        if cond == "install_time_process" and not any(
            f.category == "process" and f.install_time for f in findings
        ):
            continue
        chains.append(name)
        total += bonus
    return min(total, 100), chains


def verdict_for(points: int) -> str:
    if points >= MALICIOUS_AT:
        return "MALICIOUS"
    if points >= SUSPICIOUS_AT:
        return "SUSPICIOUS"
    return "SAFE"


def finalise(report: Report) -> Report:
    report.score, report.chains = score(report.findings)
    report.verdict = verdict_for(report.score)
    return report

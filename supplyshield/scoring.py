"""Turn findings into a risk score, attack chains and a verdict.

Single signals (a network call, a subprocess) are common in legitimate code.
What separates malware is the COMBINATION of signals, so attack chains are part
of the score. Since v0.3 the weights and thresholds are LEARNED from labelled real
and synthetic packages instead of being set by hand (see eval/real/learn_scoring.py).
"""
from __future__ import annotations

import math
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
    ("Install-time reconnaissance: fingerprints the machine during installation",
     {"install", "recon"}, "install_time_recon", 20),
]


CATEGORIES = ["install", "exec", "obfuscation", "process", "network", "secrets", "typosquat", "recon",
              "dependency"]
LEVEL = {"medium": 1, "high": 2, "critical": 3}


def chains_for(findings: list[Finding]) -> list[str]:
    cats = {f.category for f in findings if f.severity != "low"}
    if any(f.rule_id.endswith("DECODE-EXEC") for f in findings):
        cats.add("exec")  # decode-then-execute is both obfuscation and execution
    out = []
    for name, needed, cond, _ in CHAINS:
        if not needed <= cats:
            continue
        if cond and not any(f.category == cond.rsplit("_", 1)[-1] and f.install_time and f.severity != "low"
                            for f in findings):
            continue
        out.append(name)
    return out


def features(findings: list[Finding]) -> dict[str, float]:
    """Inputs for the learned scoring model: strongest severity per category + which attack chains fired."""
    x = {f"{c}_level": 0.0 for c in CATEGORIES}
    for f in findings:
        if f.severity != "low" and f.category in CATEGORIES:
            x[f"{f.category}_level"] = max(x[f"{f.category}_level"], LEVEL[f.severity])
    fired = chains_for(findings)
    for i, (name, *_rest) in enumerate(CHAINS):
        x[f"chain_{i}"] = 1.0 if name in fired else 0.0
    return x


def score(findings: list[Finding]) -> tuple[int, list[str]]:
    # A known vulnerability is a bug in an honest package, not evidence of malice, so it is
    # reported separately (see report.py / cli.py) and does not add to the malice score.
    # A known-malware advisory is conclusive on its own.
    """0-100 risk score from the LEARNED model (v0.3), plus the attack chains that fired."""
    if any(f.category == "malware" for f in findings):
        return 100, ["Listed as confirmed malware in an advisory database"]
    findings = [f for f in findings if f.category != "vulnerability"]
    points = display_score(probability(findings))
    # Decisive evidence floor: a critical finding (download-and-run, decode-and-execute, curl|sh install
    # script) is near-certain on its own, but too rare in the training data for the model to weigh it.
    if any(f.severity == "critical" for f in findings):
        points = max(points, MALICIOUS_AT)
    return points, chains_for(findings)


# ---- learned model (v0.3) ---------------------------------------------------------------------------
# Logistic regression fitted by eval/real/learn_scoring.py on 79 labelled packages (31 malicious: 19 real
# from Datadog's dataset + 12 synthetic; 48 benign: 40 real popular packages + 8 synthetic). Regularisation
# chosen by leave-one-out cross-validation (AUC 0.90 vs 0.87 for the hand-set points); thresholds chosen on
# out-of-fold predictions: SUSPICIOUS maximises detection minus false alarms, MALICIOUS is the lowest
# probability with >= 95% out-of-fold precision.
LEARNED_INTERCEPT = -1.7751
LEARNED_WEIGHTS = {
    "install_level": 1.3809, "exec_level": -1.1353, "obfuscation_level": 1.6702, "process_level": -0.3272,
    "network_level": 0.1545, "secrets_level": 1.1342, "typosquat_level": 1.8876, "recon_level": 1.5384,
    "dependency_level": 0.0,
    "chain_0": 0.1342, "chain_1": 1.4195, "chain_2": 1.0016, "chain_3": 0.4695, "chain_4": 0.9667,
}
P_SUSPICIOUS = 0.1758
P_MALICIOUS = 0.8088


def probability(findings: list[Finding]) -> float:
    x = features(findings)
    z = LEARNED_INTERCEPT + sum(LEARNED_WEIGHTS[k] * v for k, v in x.items())
    return 1 / (1 + math.exp(-z))


def display_score(p: float) -> int:
    """Map the probability onto the familiar 0-100 scale: a package with no findings scores 0, the learned
    SUSPICIOUS threshold maps to 25 and the MALICIOUS threshold to 60 (monotonic, piecewise linear)."""
    p0 = 1 / (1 + math.exp(-LEARNED_INTERCEPT))
    points = [(p0, 0.0), (P_SUSPICIOUS, SUSPICIOUS_AT), (P_MALICIOUS, MALICIOUS_AT), (1.0, 100.0)]
    if p <= p0:
        return 0
    for (pa, sa), (pb, sb) in zip(points, points[1:]):
        if p <= pb:
            return round(sa + (sb - sa) * (p - pa) / (pb - pa))
    return 100


def hand_score(findings: list[Finding]) -> int:
    """v0.1/v0.2 hand-set points (kept for comparison in the evaluation)."""
    seen: Counter = Counter()
    total = 0
    for f in findings:
        if f.category == "vulnerability":
            continue
        seen[f.rule_id] += 1
        if seen[f.rule_id] <= MAX_REPEATS_PER_RULE:
            total += SEVERITY_POINTS[f.severity]
    total += sum(b for name, _, _, b in CHAINS if name in chains_for(findings))
    return min(total, 100)


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

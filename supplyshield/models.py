"""Data structures shared by all SupplyShield modules."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

# Points each severity adds to the risk score (see scoring.py).
SEVERITY_POINTS = {"low": 3, "medium": 10, "high": 25, "critical": 40}


@dataclass
class Finding:
    rule_id: str          # e.g. PY-DECODE-EXEC
    category: str         # install | exec | obfuscation | process | network | secrets | typosquat | dependency
                          # | vulnerability (known bug, from advisories) | malware (known malware, from advisories)
    severity: str         # low | medium | high | critical
    file: str             # path relative to the package root
    line: int             # 0 when not tied to a line
    evidence: str         # short snippet of the offending code
    explanation: str      # plain-language description of the risk
    fix: str              # what the user should do
    install_time: bool = False    # runs automatically during installation
    new_in_version: bool = False  # set by diff.py when absent from the previous version

    def key(self) -> tuple[str, str]:
        if self.category in ("vulnerability", "malware"):
            return (self.rule_id, self.evidence)  # one advisory = one identity
        return (self.rule_id, self.file)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Report:
    package: str
    version: str
    ecosystem: str        # pypi | npm
    source: str           # path that was scanned
    findings: list[Finding] = field(default_factory=list)
    chains: list[str] = field(default_factory=list)
    score: int = 0
    verdict: str = "SAFE"  # SAFE | SUSPICIOUS | MALICIOUS
    vulns_checked: bool = False   # True when the advisory lookup (--vulns) ran successfully
    notes: list[str] = field(default_factory=list)

    @property
    def vulnerabilities(self) -> list[Finding]:
        return [f for f in self.findings if f.category == "vulnerability"]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["findings"] = [f.to_dict() for f in self.findings]
        return d

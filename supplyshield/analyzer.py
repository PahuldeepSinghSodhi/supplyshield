"""Scan one package and compare two versions of a package."""
from __future__ import annotations

from pathlib import Path

from . import advisories
from .common import typosquat_finding
from .loader import OpenedPackage, detect_ecosystem, read_metadata
from .models import Finding, Report
from .rules_npm import scan_npm
from .rules_python import scan_python
from .scoring import finalise


def _analyse(root: Path, source: str, vulns: bool = False) -> tuple[Report, list[str]]:
    eco = detect_ecosystem(root)
    name, version, deps = read_metadata(root, eco)
    findings = scan_npm(root) if eco == "npm" else scan_python(root)
    if (t := typosquat_finding(name, eco)) is not None:
        findings.insert(0, t)
    report = Report(package=name, version=version, ecosystem=eco, source=source, findings=findings)
    if vulns:
        try:
            report.findings = advisories.lookup(name, version, eco) + report.findings
            report.vulns_checked = True
        except advisories.AdvisoryError as e:
            report.notes.append(f"Known-vulnerability check skipped: {e}")
    return finalise(report), deps


def scan(path: str | Path, vulns: bool = False) -> Report:
    """Analyse one package. vulns=True also looks up known vulnerabilities/malware (needs internet)."""
    with OpenedPackage(path) as pkg:
        report, _ = _analyse(pkg.root, str(path), vulns)
    return report


def diff(old_path: str | Path, new_path: str | Path, vulns: bool = False) -> tuple[Report, Report, Report]:
    """Return (old report, new report, report of behaviour introduced by the update).

    Poisoned updates (event-stream 2018, ua-parser-js 2021, XZ Utils 2024) take a trusted
    package and add malicious behaviour in a new release. Judging the new version on its
    own hides that change among existing, accepted behaviour; the diff isolates it.
    """
    with OpenedPackage(old_path) as old_pkg, OpenedPackage(new_path) as new_pkg:
        old, old_deps = _analyse(old_pkg.root, str(old_path), vulns)
        new, new_deps = _analyse(new_pkg.root, str(new_path), vulns)

    old_keys = {f.key() for f in old.findings}
    introduced: list[Finding] = []
    for f in new.findings:
        if f.key() not in old_keys:
            f.new_in_version = True
            introduced.append(f)

    # Learned from real hijacked releases (eslint-config-prettier, cline, ...): the attack usually ADDS an
    # install script that runs a bundled binary or packed code the rules cannot read. On 20 normal updates
    # of popular packages no update added one, so a newly added install hook is a strong signal.
    added_install = [f for f in introduced
                     if f.rule_id in ("NPM-INSTALL-SCRIPT", "PY-INSTALL-HOOK") and f.severity != "low"]
    if added_install:
        f0 = added_install[0]
        introduced.append(Finding(
            "NEW-INSTALL-CODE", "install", "high", f0.file, f0.line, f0.evidence,
            "This update ADDS code that runs automatically during installation; the previous version had "
            "none. Hijacked releases of genuine packages usually work exactly this way.",
            "Do not upgrade until the new install code has been reviewed.", install_time=True,
            new_in_version=True,
        ))

    for dep in sorted(set(new_deps) - set(old_deps)):
        introduced.append(Finding(
            "NEW-DEPENDENCY", "dependency", "low", "(dependencies)", 0, dep,
            f"The update adds a new dependency '{dep}'. The event-stream attack (2018) hid its payload "
            "in a newly added dependency.",
            f"Scan '{dep}' as well before upgrading.",
        ))

    delta = Report(
        package=new.package, version=f"{old.version} -> {new.version}", ecosystem=new.ecosystem,
        source=f"{old_path} -> {new_path}", findings=introduced,
        vulns_checked=old.vulns_checked and new.vulns_checked, notes=old.notes + new.notes,
    )
    if delta.vulns_checked:
        new_keys = {f.key() for f in new.findings}
        fixed = [f.evidence for f in old.vulnerabilities if f.key() not in new_keys]
        if fixed:
            delta.notes.append(f"This update FIXES {len(fixed)} known vulnerabilit"
                               f"{'y' if len(fixed) == 1 else 'ies'}: {', '.join(fixed)}")
    return old, new, finalise(delta)

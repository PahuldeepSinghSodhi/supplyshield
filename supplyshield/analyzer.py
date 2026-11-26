"""Scan one package and compare two versions of a package."""
from __future__ import annotations

from pathlib import Path

from .common import typosquat_finding
from .loader import OpenedPackage, detect_ecosystem, read_metadata
from .models import Finding, Report
from .rules_npm import scan_npm
from .rules_python import scan_python
from .scoring import finalise


def _analyse(root: Path, source: str) -> tuple[Report, list[str]]:
    eco = detect_ecosystem(root)
    name, version, deps = read_metadata(root, eco)
    findings = scan_npm(root) if eco == "npm" else scan_python(root)
    if (t := typosquat_finding(name, eco)) is not None:
        findings.insert(0, t)
    report = Report(package=name, version=version, ecosystem=eco, source=source, findings=findings)
    return finalise(report), deps


def scan(path: str | Path) -> Report:
    with OpenedPackage(path) as pkg:
        report, _ = _analyse(pkg.root, str(path))
    return report


def diff(old_path: str | Path, new_path: str | Path) -> tuple[Report, Report, Report]:
    """Return (old report, new report, report of behaviour introduced by the update).

    Poisoned updates (event-stream 2018, ua-parser-js 2021, XZ Utils 2024) take a trusted
    package and add malicious behaviour in a new release. Judging the new version on its
    own hides that change among existing, accepted behaviour; the diff isolates it.
    """
    with OpenedPackage(old_path) as old_pkg, OpenedPackage(new_path) as new_pkg:
        old, old_deps = _analyse(old_pkg.root, str(old_path))
        new, new_deps = _analyse(new_pkg.root, str(new_path))

    old_keys = {f.key() for f in old.findings}
    introduced: list[Finding] = []
    for f in new.findings:
        if f.key() not in old_keys:
            f.new_in_version = True
            introduced.append(f)

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
    )
    return old, new, finalise(delta)

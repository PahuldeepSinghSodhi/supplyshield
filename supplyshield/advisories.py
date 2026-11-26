"""Known-vulnerability and known-malware lookup (the pip-audit / npm audit part).

Behaviour analysis finds NEW malicious code; it cannot know that an old, honest
version has a published security bug. pip-audit and npm audit cover that by
looking the exact name + version up in advisory databases. SupplyShield does the
same lookup itself against OSV.dev (https://osv.dev), the open database that
pip-audit can use as a source and that imports the GitHub Advisory Database
behind npm audit. OSV also lists confirmed malicious packages (IDs starting
with MAL-) from the OpenSSF malicious-packages project.

Querying OSV directly keeps SupplyShield dependency-free and lets it check a
single downloaded archive, which pip-audit and npm audit cannot do on their own.
This is the only part of SupplyShield that uses the network, and it is opt-in
(--vulns). Only the package name, ecosystem and version are sent.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request

from .models import Finding

OSV_URL = "https://api.osv.dev/v1/query"
ECOSYSTEM = {"pypi": "PyPI", "npm": "npm"}
SEVERITY = {"critical": "critical", "high": "high", "moderate": "medium", "medium": "medium", "low": "low"}


class AdvisoryError(Exception):
    pass


def _post(payload: dict, timeout: float) -> dict:
    req = urllib.request.Request(
        OSV_URL, data=json.dumps(payload).encode(), method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "supplyshield"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as e:
        raise AdvisoryError(f"vulnerability database unreachable ({e})") from e


def _fixed_versions(vuln: dict, name: str) -> list[str]:
    fixed = []
    for aff in vuln.get("affected", []):
        if aff.get("package", {}).get("name", "").lower() != name.lower():
            continue
        for rng in aff.get("ranges", []):
            fixed += [e["fixed"] for e in rng.get("events", []) if "fixed" in e]
    return sorted(set(fixed))


def _severity(vuln: dict) -> str:
    raw = str((vuln.get("database_specific") or {}).get("severity", "")).lower()
    return SEVERITY.get(raw, "medium")


def lookup(name: str, version: str, ecosystem: str, timeout: float = 15.0) -> list[Finding]:
    """Return one finding per known vulnerability / malware advisory for name==version."""
    if version in ("", "?") or ecosystem not in ECOSYSTEM:
        raise AdvisoryError("package version unknown, cannot look up advisories")

    vulns, page_token = [], None
    while True:
        payload = {"package": {"name": name, "ecosystem": ECOSYSTEM[ecosystem]}, "version": version}
        if page_token:
            payload["page_token"] = page_token
        data = _post(payload, timeout)
        vulns += data.get("vulns", [])
        page_token = data.get("next_page_token")
        if not page_token:
            break

    # The same bug is often listed twice (e.g. a GitHub GHSA record and a PyPI PYSEC record
    # with the same CVE). Keep one per bug, preferring records that carry a severity.
    vulns.sort(key=lambda v: 0 if (v.get("database_specific") or {}).get("severity") else 1)
    seen: set[str] = set()
    unique = []
    for v in vulns:
        ids = {v.get("id", "")} | set(v.get("aliases", []))
        if ids & seen:
            continue
        seen |= ids
        unique.append(v)

    findings = []
    for v in unique:
        vid = v.get("id", "?")
        aliases = [a for a in v.get("aliases", []) if a.startswith(("CVE-", "GHSA-"))]
        label = vid + (f" ({', '.join(aliases[:2])})" if aliases else "")
        summary = (v.get("summary") or v.get("details") or "").strip().splitlines()[0:1]
        summary = summary[0][:160] if summary else "No summary provided."

        if vid.startswith("MAL-"):
            findings.append(Finding(
                "KNOWN-MALWARE", "malware", "critical", "(advisory database)", 0, label,
                f"This exact package version is listed as confirmed malware in the OpenSSF "
                f"malicious-packages database: {summary}",
                "Do not install. Remove it if already installed and rotate any secrets on that machine.",
            ))
            continue

        fixed = _fixed_versions(v, name)
        fix = (f"Upgrade to {fixed[-1]} or later." if len(fixed) == 1
               else f"Upgrade to a fixed version ({', '.join(fixed)})." if fixed
               else "No fixed version is listed; consider an alternative package.")
        findings.append(Finding(
            "KNOWN-VULN", "vulnerability", _severity(v), "(advisory database)", 0, label,
            f"This version has a publicly known security vulnerability: {summary}",
            fix,
        ))
    return findings

"""Tests for the known-vulnerability lookup. The database is faked, so no network is used."""
from pathlib import Path

import pytest

from supplyshield import advisories
from supplyshield.analyzer import diff, scan
from supplyshield.cli import exit_code

VULN = {
    "id": "GHSA-x84v-xcm2-53pg", "aliases": ["CVE-2018-18074"],
    "summary": "Insufficiently Protected Credentials in Requests",
    "database_specific": {"severity": "HIGH"},
    "affected": [{"package": {"name": "requests", "ecosystem": "PyPI"},
                  "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.20.0"}]}]}],
}
MALWARE = {"id": "MAL-2024-0001", "summary": "Malicious code in requests-evil (PyPI)"}


def make_pkg(tmp_path: Path, name: str, version: str) -> Path:
    d = tmp_path / f"{name}-{version}"
    d.mkdir()
    (d / "pyproject.toml").write_text(f'[project]\nname = "{name}"\nversion = "{version}"\n')
    return d


def fake_db(monkeypatch, answers: dict):
    """answers maps version -> list of OSV vuln records."""
    def _post(payload, timeout):
        return {"vulns": answers.get(payload["version"], [])}
    monkeypatch.setattr(advisories, "_post", _post)


def test_known_vulnerability_reported_but_not_called_malicious(tmp_path, monkeypatch):
    fake_db(monkeypatch, {"2.19.1": [VULN]})
    r = scan(make_pkg(tmp_path, "requests", "2.19.1"), vulns=True)
    assert r.vulns_checked
    assert len(r.vulnerabilities) == 1
    v = r.vulnerabilities[0]
    assert v.severity == "high" and "CVE-2018-18074" in v.evidence and "2.20.0" in v.fix
    assert r.verdict == "SAFE"          # a bug in an honest package is not malice...
    assert exit_code(r) == 1            # ...but it still fails a CI gate


def test_duplicate_records_for_same_bug_are_merged(tmp_path, monkeypatch):
    pysec_copy = {"id": "PYSEC-2018-28", "aliases": ["CVE-2018-18074", "GHSA-x84v-xcm2-53pg"],
                  "summary": "same bug", "affected": VULN["affected"]}
    fake_db(monkeypatch, {"2.19.1": [pysec_copy, VULN]})
    r = scan(make_pkg(tmp_path, "requests", "2.19.1"), vulns=True)
    assert len(r.vulnerabilities) == 1
    assert r.vulnerabilities[0].severity == "high"   # kept the record that carries a severity


def test_known_malware_forces_malicious(tmp_path, monkeypatch):
    fake_db(monkeypatch, {"1.0.0": [MALWARE]})
    r = scan(make_pkg(tmp_path, "requests-evil", "1.0.0"), vulns=True)
    assert r.verdict == "MALICIOUS" and r.score == 100
    assert any(f.rule_id == "KNOWN-MALWARE" for f in r.findings)


def test_offline_lookup_is_skipped_with_note(tmp_path, monkeypatch):
    def _post(payload, timeout):
        raise advisories.AdvisoryError("vulnerability database unreachable (offline)")
    monkeypatch.setattr(advisories, "_post", _post)
    r = scan(make_pkg(tmp_path, "tidytext", "1.0.0"), vulns=True)
    assert not r.vulns_checked and r.notes and r.verdict == "SAFE"


def test_lookup_off_by_default(tmp_path, monkeypatch):
    def _post(payload, timeout):
        pytest.fail("network used without --vulns")
    monkeypatch.setattr(advisories, "_post", _post)
    assert not scan(make_pkg(tmp_path, "requests", "2.19.1")).vulns_checked


def test_metadata_read_from_files_with_byte_order_mark(tmp_path):
    # Windows editors and PowerShell often save UTF-8 with a BOM; name/version must still be read.
    d = tmp_path / "bom"
    d.mkdir()
    (d / "package.json").write_bytes(b'\xef\xbb\xbf{"name": "lodash", "version": "4.17.15"}')
    r = scan(d)
    assert (r.package, r.version, r.ecosystem) == ("lodash", "4.17.15", "npm")


def test_diff_reports_vulnerabilities_fixed_by_update(tmp_path, monkeypatch):
    fake_db(monkeypatch, {"2.19.1": [VULN], "2.20.0": []})
    _, new, delta = diff(make_pkg(tmp_path, "requests", "2.19.1"),
                         make_pkg(tmp_path, "requests", "2.20.0"), vulns=True)
    assert not new.vulnerabilities
    assert any("FIXES 1 known vulnerability" in n for n in delta.notes)

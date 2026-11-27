"""Scan every real-data package with ONE SupplyShield version (the code folder given) and save verdicts.

usage: python -I scan_all.py <folder containing the supplyshield package> <out.json>
Static only; malware is unpacked to a temp folder that is deleted straight after.
"""
import json
import sys
import tempfile
import time
import zipfile
from pathlib import Path

CODE, OUT = Path(sys.argv[1]), Path(sys.argv[2])
sys.path.insert(0, str(CODE))
from supplyshield.analyzer import scan  # noqa: E402
from supplyshield.loader import OpenedPackage, _find_root  # noqa: E402

R = Path(__file__).parent
items = json.loads((R / "selection.json").read_text())
for s in items:
    s.setdefault("set", "main")
items += json.loads((R / "holdout.json").read_text())

rows = []
for s in items:
    row = {k: s[k] for k in ("set", "label", "ecosystem", "name", "version")}
    with tempfile.TemporaryDirectory(prefix="ss-cmp-", ignore_cleanup_errors=True) as t:
        try:
            t0 = time.perf_counter()
            if s["label"] == "malicious":
                zipfile.ZipFile(s["file"]).extractall(t, pwd=b"infected")
                r = scan(_find_root(Path(t)))
            else:
                with OpenedPackage(s["file"]) as pkg:
                    r = scan(pkg.root)
            row.update(verdict=r.verdict, score=r.score, flagged=r.verdict != "SAFE",
                       rules=sorted({f.rule_id for f in r.findings if f.severity != "low"}),
                       chains=r.chains, ms=round((time.perf_counter() - t0) * 1000))
        except OSError as e:  # antivirus-blocked sample (v0.1 crashes here; it is excluded for both)
            row.update(verdict="ERROR", error=str(e)[:120], flagged=None)
    rows.append(row)
OUT.write_text(json.dumps(rows, indent=2))
print("wrote", OUT, len(rows))

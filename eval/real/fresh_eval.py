"""Final test on the FRESH set (never used for rules or scoring): one SupplyShield version per run.

usage: python -I fresh_eval.py <folder containing the supplyshield package> <out.json> [--hand]
  --hand: score with the old hand-set points (v0.3 code only), to isolate rule changes from scoring changes.
Static only. Malware is extracted to a temporary folder that is deleted straight after.
"""
import json
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path

CODE, OUT = Path(sys.argv[1]), Path(sys.argv[2])
HAND = "--hand" in sys.argv
sys.path.insert(0, str(CODE))
from supplyshield import analyzer, scoring  # noqa: E402
from supplyshield.loader import _find_root  # noqa: E402

if HAND:  # old points + old thresholds on the same (new) findings
    scoring.score = lambda fs: (100 if any(f.category == "malware" for f in fs) else scoring.hand_score(fs),
                                scoring.chains_for(fs))

R = Path(__file__).parent
items = json.loads((R / "fresh.json").read_text())


def verdict(r):
    return {"verdict": r.verdict, "score": r.score, "flagged": r.verdict != "SAFE",
            "rules": sorted({f.rule_id for f in r.findings if f.severity != "low"}),
            "unreadable": any(f.rule_id == "FILE-UNREADABLE" for f in r.findings)}


LEFT_BEHIND = []
rows = []
for it in items:
    row = {k: it.get(k) for k in ("kind", "ecosystem", "name")}
    if it["kind"] == "poisoned_update":
        row.update(old=it["clean_version"], new=it["bad_version"])
        t = tempfile.mkdtemp(prefix="ss-fresh-")
        try:
            zipfile.ZipFile(it["bad_file"]).extractall(t, pwd=b"infected")
            bad_root = _find_root(Path(t))
            row["bad_scan"] = verdict(analyzer.scan(bad_root))
            row["clean_scan"] = verdict(analyzer.scan(it["clean_file"]))
            _, _, delta = analyzer.diff(it["clean_file"], bad_root)
            row["diff"] = verdict(delta)
            row["diff_findings"] = [f"{f.rule_id} {f.file}" for f in delta.findings if f.severity != "low"][:8]
        except OSError as e:  # antivirus blocked extraction or reading: excluded for every version, never bypassed
            row["excluded"] = f"antivirus/OS blocked: {type(e).__name__}"
        finally:
            shutil.rmtree(t, ignore_errors=True)
            if Path(t).exists():
                LEFT_BEHIND.append(t)
    else:
        row.update(old=it.get("prev_version"), new=it["version"])
        row["new_scan"] = verdict(analyzer.scan(it["file"]))
        if it.get("prev_file"):
            row["prev_scan"] = verdict(analyzer.scan(it["prev_file"]))
            _, _, delta = analyzer.diff(it["prev_file"], it["file"])
            row["diff"] = verdict(delta)
    rows.append(row)
    print(row["kind"][:8], row["ecosystem"], row["name"][:30],
          {k: (v["verdict"], v["score"]) for k, v in row.items() if isinstance(v, dict)}, flush=True)
OUT.write_text(json.dumps(rows, indent=2))
print("temporary folders antivirus kept locked:", LEFT_BEHIND)

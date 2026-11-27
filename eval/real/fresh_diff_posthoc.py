"""POST-HOC check of the NEW-INSTALL-CODE diff rule, which was learned FROM the fresh set (not independent).
usage: python -I fresh_diff_posthoc.py <repo root>"""
import json
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path

sys.path.insert(0, sys.argv[1])
from supplyshield import analyzer  # noqa: E402
from supplyshield.loader import _find_root  # noqa: E402

R = Path(__file__).parent
out = []
for it in json.loads((R / "fresh.json").read_text()):
    t = tempfile.mkdtemp(prefix="ss-ph-")
    try:
        if it["kind"] == "poisoned_update":
            zipfile.ZipFile(it["bad_file"]).extractall(t, pwd=b"infected")
            _, _, d = analyzer.diff(it["clean_file"], _find_root(Path(t)))
        elif it.get("prev_file"):
            _, _, d = analyzer.diff(it["prev_file"], it["file"])
        else:
            continue
        row = {"kind": it["kind"], "name": it["name"], "verdict": d.verdict, "score": d.score,
               "rules": sorted({f.rule_id for f in d.findings if f.severity != "low"})}
    except OSError as e:
        row = {"kind": it["kind"], "name": it["name"], "excluded": type(e).__name__}
    finally:
        shutil.rmtree(t, ignore_errors=True)
    out.append(row)
    print(row, flush=True)
(R / "fresh_diff_posthoc.json").write_text(json.dumps(out, indent=2))
for kind in ("poisoned_update", "benign"):
    rs = [r for r in out if r["kind"] == kind and "verdict" in r]
    print(kind, "flagged by diff:", sum(r["verdict"] != "SAFE" for r in rs), "/", len(rs))

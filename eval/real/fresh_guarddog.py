"""GuardDog on the fresh set: 20 poisoned releases + 20 new popular packages. Saves after every package.
usage: python -I fresh_guarddog.py <repo root> <guarddog.exe>"""
import json
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

REPO, GD = Path(sys.argv[1]), sys.argv[2]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "eval"))
from supplyshield.loader import OpenedPackage, _find_root  # noqa: E402
import run_eval  # noqa: E402

R = Path(__file__).parent
CACHE = R / "fresh_guarddog.json"
done = {d["key"]: d for d in json.loads(CACHE.read_text())} if CACHE.exists() else {}
gd = run_eval.t_guarddog(GD)
run_eval.run = lambda cmd, cwd=None: subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                                                    encoding="utf-8", errors="replace", timeout=180)
for it in json.loads((R / "fresh.json").read_text()):
    bad = it["kind"] == "poisoned_update"
    key = f"{it['kind']}/{it['name']}/{it['bad_version'] if bad else it['version']}"
    if key in done:
        continue
    res = {"key": key, "kind": it["kind"], "ecosystem": it["ecosystem"], "name": it["name"]}
    t = tempfile.mkdtemp(prefix="ss-gd-")
    try:
        if bad:
            zipfile.ZipFile(it["bad_file"]).extractall(t, pwd=b"infected")
            res["flagged"], res["detail"] = gd(_find_root(Path(t)), it["ecosystem"])
        else:
            with OpenedPackage(it["file"]) as p:
                res["flagged"], res["detail"] = gd(p.root, it["ecosystem"])
    except subprocess.TimeoutExpired:
        res["flagged"], res["detail"] = None, "timeout (> 180 s)"
    except OSError as e:
        res["flagged"], res["detail"] = None, f"blocked: {type(e).__name__}"
    finally:
        shutil.rmtree(t, ignore_errors=True)
    done[key] = res
    CACHE.write_text(json.dumps(list(done.values()), indent=2))
    print(key, res["flagged"], res["detail"][:60], flush=True)
print("done", len(done))

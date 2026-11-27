"""GuardDog and Bandit on the 20 held-out benign packages (false-alarm comparison).
usage: python -I holdout_tools.py <repo root> <bandit.exe> <guarddog.exe>"""
import json
import subprocess
import sys
from pathlib import Path

REPO, BANDIT, GUARDDOG = (Path(a) for a in sys.argv[1:4])
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "eval"))
from supplyshield.loader import OpenedPackage  # noqa: E402
import run_eval  # noqa: E402

R = Path(__file__).parent
bandit = run_eval.t_bandit(str(BANDIT))
gd = run_eval.t_guarddog(str(GUARDDOG))
CACHE = R / "holdout_tools.json"
done = {o["name"]: o for o in json.loads(CACHE.read_text())} if CACHE.exists() else {}
out = []
for s in json.loads((R / "holdout.json").read_text()):
    if s["name"] in done:  # resume: results are saved after every package
        out.append(done[s["name"]])
        continue
    with OpenedPackage(s["file"]) as pkg:
        orig = run_eval.run
        run_eval.run = lambda cmd, cwd=None: subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                                                            encoding="utf-8", errors="replace", timeout=180)
        try:
            g = gd(pkg.root, s["ecosystem"])
        except subprocess.TimeoutExpired:
            g = (None, "timeout (> 180 s)")
        finally:
            run_eval.run = orig
        b = bandit(pkg.root, s["ecosystem"])
    out.append({"name": s["name"], "ecosystem": s["ecosystem"], "GuardDog": g[0], "GuardDog detail": g[1],
                "Bandit": b[0], "Bandit detail": b[1]})
    print(s["name"], g, b, flush=True)
    CACHE.write_text(json.dumps(out, indent=2))
print("done", len(out))

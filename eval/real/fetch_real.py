"""Select and fetch the real-data corpus. Never installs or runs anything.

Malicious: 10 PyPI + 10 npm random 'malicious_intent' samples (seed 42) from the
blobless clone of DataDog/malicious-software-packages-dataset; only those blobs are fetched.
Benign: top-10 most-downloaded PyPI packages (hugovk list) and 10 most popular npm
packages (npm registry search), downloaded directly with urllib (no pip/npm involved).
"""
import hashlib
import json
import random
import subprocess
import sys
import urllib.request
import zipfile
from pathlib import Path

R = Path(__file__).parent
MAL = R / "malicious"
RAW = "https://raw.githubusercontent.com/DataDog/malicious-software-packages-dataset/main/"
BEN = R / "benign"
UA = {"User-Agent": "supplyshield-eval"}


def get_json(url):
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=60) as r:
        return json.loads(r.read().decode())


def download(url, dest: Path):
    dest.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=120) as r:
        dest.write_bytes(r.read())
    return dest


def sha256(p: Path):
    return hashlib.sha256(p.read_bytes()).hexdigest()


selection = []

# ---------------------------------------------------------------- malicious
tree = (R / "tree.txt").read_text().splitlines()
rng = random.Random(42)
for eco in ("pypi", "npm"):
    pool = sorted(p for p in tree if p.startswith(f"samples/{eco}/malicious_intent/") and p.endswith(".zip"))
    order = rng.sample(pool, len(pool))  # full random order, seed 42; take the first 10 that download
    chosen, failed = [], []
    for p in order:
        if len(chosen) == 10:
            break
        dest = MAL / eco / p.rsplit("/", 1)[-1]
        try:
            r = subprocess.run(["gh", "api", "-H", "Accept: application/vnd.github.raw",
                                f"repos/DataDog/malicious-software-packages-dataset/contents/{p}"],
                               capture_output=True, timeout=120)
            if r.returncode != 0:
                raise RuntimeError(r.stderr.decode(errors="replace").strip()[:150])
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(r.stdout)
            zipfile.ZipFile(dest).namelist()  # encrypted zip must at least list
            chosen.append((p, dest))
        except Exception as e:  # noqa: BLE001
            failed.append({"path": p, "error": str(e)[:200]})
            if len(failed) > 20:
                sys.exit(f"too many download failures for {eco}: {failed[-3:]}")
    if failed:
        print(f"{eco}: {len(failed)} fetch failures (replaced):", json.dumps(failed, indent=1))
    for p, f in chosen:
        parts = p.split("/")
        selection.append({"label": "malicious", "ecosystem": eco, "name": parts[3], "version": parts[4],
                          "file": str(f), "source": p, "sha256": sha256(f)})
    print(f"malicious {eco}: {len(chosen)} from pool of {len(pool)}")

# ---------------------------------------------------------------- benign PyPI
top = get_json("https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json")
names = [row["project"] for row in top["rows"][:10]]
for name in names:
    meta = get_json(f"https://pypi.org/pypi/{name}/json")
    ver = meta["info"]["version"]
    files = meta["urls"]
    pick = next((u for u in files if u["packagetype"] == "sdist"), None) or files[0]
    f = download(pick["url"], BEN / "pypi" / pick["filename"])
    selection.append({"label": "benign", "ecosystem": "pypi", "name": name, "version": ver, "file": str(f),
                      "source": pick["url"], "sha256": sha256(f), "kind": pick["packagetype"]})
print("benign pypi:", names)

# ---------------------------------------------------------------- benign npm
# Candidates: SupplyShield's list of widely used npm names + top registry search hits; then rank all of
# them by real last-week download counts from api.npmjs.org and keep the top 10 (unscoped only).
repo_list = Path(sys.argv[1]).read_text().split()
cands = {n for n in repo_list if not n.startswith("#") and "/" not in n}
res = get_json("https://registry.npmjs.org/-/v1/search?text=keywords:javascript&popularity=1.0"
               "&quality=0.0&maintenance=0.0&size=100")
cands |= {o["package"]["name"] for o in res["objects"] if not o["package"]["name"].startswith("@")}
cands = sorted(cands)
downloads = {}
for i in range(0, len(cands), 100):
    batch = cands[i:i + 100]
    d = get_json("https://api.npmjs.org/downloads/point/last-week/" + ",".join(batch))
    downloads.update({k: v["downloads"] for k, v in d.items() if v})
npm_names = sorted(downloads, key=downloads.get, reverse=True)[:10]
source = f"top 10 of {len(downloads)} candidates by last-week downloads"
print("npm weekly downloads:", {n: downloads[n] for n in npm_names})
for name in npm_names:
    meta = get_json(f"https://registry.npmjs.org/{name.replace('/', '%2F')}/latest")
    url = meta["dist"]["tarball"]
    f = download(url, BEN / "npm" / url.rsplit("/", 1)[-1])
    selection.append({"label": "benign", "ecosystem": "npm", "name": name, "version": meta["version"],
                      "file": str(f), "source": url, "sha256": sha256(f)})
print(f"benign npm ({source}):", npm_names)

(R / "selection.json").write_text(json.dumps(selection, indent=2))
print("total", len(selection))

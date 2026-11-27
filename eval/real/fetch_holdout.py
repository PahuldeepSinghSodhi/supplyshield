"""Held-out benign set: popular packages NOT used while fixing the rules.

PyPI ranks 11-20 of hugovk's most-downloaded list; npm ranks 11-20 by last-week downloads over the
same candidate set as fetch_real.py. Downloaded directly with urllib; nothing is installed or run.
usage: python -I fetch_holdout.py <path to popular_npm.txt>
"""
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

R = Path(__file__).parent
OUT = R / "holdout"
UA = {"User-Agent": "supplyshield-eval"}


def get_json(url):
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=60) as r:
        return json.loads(r.read().decode())


def download(url, dest: Path):
    dest.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=180) as r:
        dest.write_bytes(r.read())
    return dest


sel = []
top = get_json("https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json")
for row in top["rows"][10:20]:
    name = row["project"]
    meta = get_json(f"https://pypi.org/pypi/{name}/json")
    files = meta["urls"]
    pick = next((u for u in files if u["packagetype"] == "sdist"), None) or files[0]
    f = download(pick["url"], OUT / "pypi" / pick["filename"])
    sel.append({"label": "benign", "set": "holdout", "ecosystem": "pypi", "name": name,
                "version": meta["info"]["version"], "file": str(f), "source": pick["url"],
                "sha256": hashlib.sha256(f.read_bytes()).hexdigest()})

cands = {n for n in Path(sys.argv[1]).read_text().split() if not n.startswith("#") and "/" not in n}
res = get_json("https://registry.npmjs.org/-/v1/search?text=keywords:javascript&popularity=1.0"
               "&quality=0.0&maintenance=0.0&size=100")
cands |= {o["package"]["name"] for o in res["objects"] if not o["package"]["name"].startswith("@")}
cands = sorted(cands)
downloads = {}
for i in range(0, len(cands), 100):
    d = get_json("https://api.npmjs.org/downloads/point/last-week/" + ",".join(cands[i:i + 100]))
    downloads.update({k: v["downloads"] for k, v in d.items() if v})
for name in sorted(downloads, key=downloads.get, reverse=True)[10:20]:
    meta = get_json(f"https://registry.npmjs.org/{name}/latest")
    url = meta["dist"]["tarball"]
    f = download(url, OUT / "npm" / url.rsplit("/", 1)[-1])
    sel.append({"label": "benign", "set": "holdout", "ecosystem": "npm", "name": name,
                "version": meta["version"], "file": str(f), "source": url,
                "sha256": hashlib.sha256(f.read_bytes()).hexdigest()})

(R / "holdout.json").write_text(json.dumps(sel, indent=2))
print("holdout:", [(s["ecosystem"], s["name"]) for s in sel])

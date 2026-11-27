"""Fresh, never-seen test data (v0.3 evaluation). Nothing is installed or run.

1. Real POISONED UPDATES: random 'compromised_lib' samples (hijacked releases of genuine packages) from
   Datadog's dataset (15 npm + 5 PyPI, seed 7), each paired with the clean release published just before it
   (from the registry; versions listed as compromised in the dataset manifest are skipped).
2. 20 new popular benign packages (PyPI and npm ranks 21-30), each with its previous release, to measure
   false alarms of both the scanner and the version diff on ordinary updates.

usage: python -I fetch_fresh.py <path to popular_npm.txt>   (needs tree.txt and a signed-in gh CLI)
"""
import hashlib
import json
import random
import subprocess
import sys
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

from packaging.version import InvalidVersion, Version

R = Path(__file__).parent
OUT = R / "fresh"
UA = {"User-Agent": "supplyshield-eval"}
REPO = "repos/DataDog/malicious-software-packages-dataset/contents/"


def get_json(url):
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=90) as r:
        return json.loads(r.read().decode())


def download(url, dest: Path):
    dest.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=180) as r:
        dest.write_bytes(r.read())
    return dest


def gh_raw(path) -> bytes:
    r = subprocess.run(["gh", "api", "-H", "Accept: application/vnd.github.raw", REPO + path],
                       capture_output=True, timeout=300)
    if r.returncode:
        raise RuntimeError(r.stderr.decode(errors="replace")[:150])
    return r.stdout


def sha(p: Path):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def vkey(v):
    try:
        return Version(v)
    except InvalidVersion:
        return None


def previous_npm(name, bad_version, bad_versions):
    meta = get_json("https://registry.npmjs.org/" + urllib.parse.quote(name, safe="@"))
    times, versions = meta.get("time", {}), meta.get("versions", {})
    cutoff = times.get(bad_version)
    cands = [v for v in versions if v not in bad_versions and v != bad_version and v in times
             and (cutoff is None or times[v] < cutoff) and "-" not in v]
    if not cands:
        return None
    if cutoff is None:  # fall back to version order
        cands = [v for v in cands if vkey(v) and vkey(bad_version) and vkey(v) < vkey(bad_version)]
        if not cands:
            return None
        prev = max(cands, key=vkey)
    else:
        prev = max(cands, key=lambda v: times[v])
    return prev, versions[prev]["dist"]["tarball"]


def previous_pypi(name, bad_version, bad_versions, latest=False):
    meta = get_json(f"https://pypi.org/pypi/{name}/json")
    rel = {v: f for v, f in meta["releases"].items() if f and vkey(v) and not vkey(v).is_prerelease}
    if latest:
        v = meta["info"]["version"]
        older = [x for x in rel if vkey(x) < vkey(v)]
        return v, rel.get(v) or meta["urls"], (max(older, key=vkey) if older else None), rel
    cands = [v for v in rel if v not in bad_versions and vkey(bad_version) and vkey(v) < vkey(bad_version)]
    if not cands:
        return None
    prev = max(cands, key=vkey)
    files = rel[prev]
    f = next((x for x in files if x["packagetype"] == "sdist"), files[0])
    return prev, f["url"]


items = []
# ---------------------------------------------------------------- poisoned updates
tree = (R / "tree.txt").read_text().splitlines()
rng = random.Random(7)
for eco, want in (("npm", 15), ("pypi", 5)):
    manifest = json.loads(gh_raw(f"samples/{eco}/manifest.json"))
    pool = sorted(p for p in tree if p.startswith(f"samples/{eco}/compromised_lib/") and p.endswith(".zip"))
    got, skipped = 0, []
    for p in rng.sample(pool, len(pool)):
        if got == want:
            break
        name, bad = p.split("/")[3], p.split("/")[4]
        bad_versions = set(manifest.get(name) or [])
        try:
            prev = previous_npm(name, bad, bad_versions) if eco == "npm" else previous_pypi(name, bad, bad_versions)
            if not prev:
                skipped.append((name, bad, "no earlier clean release on registry"))
                continue
            mal = OUT / "poisoned" / eco / p.rsplit("/", 1)[-1]
            mal.parent.mkdir(parents=True, exist_ok=True)
            mal.write_bytes(gh_raw(p))
            zipfile.ZipFile(mal).namelist()
            clean = download(prev[1], OUT / "clean_prev" / eco / prev[1].rsplit("/", 1)[-1])
        except Exception as e:  # noqa: BLE001
            skipped.append((name, bad, str(e)[:80]))
            continue
        items.append({"kind": "poisoned_update", "ecosystem": eco, "name": name, "bad_version": bad,
                      "clean_version": prev[0], "bad_file": str(mal), "clean_file": str(clean),
                      "bad_source": p, "clean_source": prev[1], "bad_sha256": sha(mal), "clean_sha256": sha(clean)})
        got += 1
    print(f"poisoned {eco}: {got} (skipped {len(skipped)}: {skipped[:6]})", flush=True)

# ---------------------------------------------------------------- fresh benign + previous releases
top = get_json("https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json")
for row in top["rows"][20:30]:
    name = row["project"]
    v, files, older, rel = previous_pypi(name, None, set(), latest=True)
    f = next((x for x in files if x["packagetype"] == "sdist"), files[0])
    new = download(f["url"], OUT / "benign" / "pypi" / f["filename"])
    entry = {"kind": "benign", "ecosystem": "pypi", "name": name, "version": v, "file": str(new),
             "source": f["url"], "sha256": sha(new)}
    if older:
        of = next((x for x in rel[older] if x["packagetype"] == "sdist"), rel[older][0])
        old = download(of["url"], OUT / "benign_prev" / "pypi" / of["filename"])
        entry.update(prev_version=older, prev_file=str(old), prev_source=of["url"], prev_sha256=sha(old))
    items.append(entry)

cands = {n for n in Path(sys.argv[1]).read_text().split() if not n.startswith("#") and "/" not in n}
res = get_json("https://registry.npmjs.org/-/v1/search?text=keywords:javascript&popularity=1.0"
               "&quality=0.0&maintenance=0.0&size=100")
cands |= {o["package"]["name"] for o in res["objects"] if not o["package"]["name"].startswith("@")}
cands = sorted(cands)
downloads = {}
for i in range(0, len(cands), 100):
    d = get_json("https://api.npmjs.org/downloads/point/last-week/" + ",".join(cands[i:i + 100]))
    downloads.update({k: v["downloads"] for k, v in d.items() if v})
for name in sorted(downloads, key=downloads.get, reverse=True)[20:30]:
    meta = get_json(f"https://registry.npmjs.org/{name}")
    latest = meta["dist-tags"]["latest"]
    url = meta["versions"][latest]["dist"]["tarball"]
    new = download(url, OUT / "benign" / "npm" / url.rsplit("/", 1)[-1])
    entry = {"kind": "benign", "ecosystem": "npm", "name": name, "version": latest, "file": str(new),
             "source": url, "sha256": sha(new)}
    t = meta.get("time", {})
    older = [v for v in meta["versions"] if v != latest and "-" not in v and v in t and t[v] < t.get(latest, "9")]
    if older:
        ov = max(older, key=lambda v: t[v])
        ourl = meta["versions"][ov]["dist"]["tarball"]
        old = download(ourl, OUT / "benign_prev" / "npm" / ourl.rsplit("/", 1)[-1])
        entry.update(prev_version=ov, prev_file=str(old), prev_source=ourl, prev_sha256=sha(old))
    items.append(entry)

(R / "fresh.json").write_text(json.dumps(items, indent=2))
print("fresh benign:", [(i["ecosystem"], i["name"]) for i in items if i["kind"] == "benign"])
print("poisoned:", [(i["ecosystem"], i["name"], i["clean_version"], "->", i["bad_version"])
                    for i in items if i["kind"] == "poisoned_update"])

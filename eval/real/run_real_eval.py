"""Run SupplyShield and existing tools on the real-data corpus (selection.json).

Static analysis only: nothing is installed, imported or executed. Each package is
unpacked into a temporary folder, the SAME folder is given to every tool, and the
folder is deleted immediately afterwards.

usage: python -I run_real_eval.py <repo root> <bandit.exe> <pip-audit.exe> <guarddog.exe>
"""
import json
import math
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path

REPO, BANDIT, PIP_AUDIT, GUARDDOG = (Path(a) for a in sys.argv[1:5])
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "eval"))
from supplyshield.analyzer import scan  # noqa: E402
from supplyshield.loader import OpenedPackage, _find_root  # noqa: E402
import run_eval  # noqa: E402  (reuse the existing tool adapters)

R = Path(__file__).parent
NPM = run_eval.shutil.which("npm")
sel = json.loads((R / "selection.json").read_text())

bandit = run_eval.t_bandit(str(BANDIT))
_guarddog = run_eval.t_guarddog(str(GUARDDOG))
GD_TIMEOUT = 180


def guarddog(path, eco):
    """GuardDog with a per-package time limit; a timeout is reported, not counted as a miss."""
    orig = run_eval.run
    run_eval.run = lambda cmd, cwd=None: subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                                                        encoding="utf-8", errors="replace", timeout=GD_TIMEOUT)
    try:
        return _guarddog(path, eco)
    except subprocess.TimeoutExpired:
        return None, f"timeout (> {GD_TIMEOUT} s)"
    finally:
        run_eval.run = orig


def pip_audit_version(name, version):
    with tempfile.TemporaryDirectory() as t:
        req = Path(t, "req.txt")
        req.write_text(f"{name}=={version}\n")
        p = run_eval.run([str(PIP_AUDIT), "-r", str(req), "--no-deps", "--disable-pip", "--progress-spinner", "off"])
    text = (p.stdout + p.stderr).lower()
    if "no known vulnerabilities" in text:
        return False, "no known vulnerabilities"
    if p.returncode != 0 and ("not found" in text or "could not" in text or "error" in text) and "vulnerabilit" not in p.stdout.lower():
        return False, "could not audit (not on PyPI)"
    return p.returncode != 0, (p.stdout.strip().splitlines() or ["?"])[-1][:60]


def npm_audit_version(name, version):
    with tempfile.TemporaryDirectory() as t:
        Path(t, "package.json").write_text(json.dumps(
            {"name": "audit-harness", "version": "1.0.0", "dependencies": {name: version}}))
        inst = run_eval.run([NPM, "install", "--package-lock-only", "--ignore-scripts", "--no-audit"], cwd=Path(t))
        if inst.returncode != 0:
            return False, "could not audit (not on npm)"
        p = run_eval.run([NPM, "audit", "--json"], cwd=Path(t))
        total = json.loads(p.stdout or "{}").get("metadata", {}).get("vulnerabilities", {}).get("total", 0)
    return total > 0, f"{total} vulnerabilities"


def unpack(s, tmp: Path) -> Path:
    if s["label"] == "malicious":
        with zipfile.ZipFile(s["file"]) as z:
            z.extractall(tmp, pwd=b"infected")
        expected = sum(1 for n in zipfile.ZipFile(s["file"]).namelist() if not n.endswith("/"))
        on_disk = [p for p in tmp.rglob("*") if p.is_file()]
        s["files_missing_after_extract"] = expected - len(on_disk)
        # Antivirus (Avast is active on this PC) may block reading detected files. Never bypassed:
        # a sample with any unreadable file is excluded from every tool's score and reported.
        blocked = []
        for p in on_disk:
            try:
                p.open("rb").read(1)
            except OSError:
                blocked.append(p.name)
        s["av_blocked_files"] = blocked
        return _find_root(tmp)
    return None  # benign archives are opened with SupplyShield's own safe loader below


CACHE = R / "rows_cache.json"
cache = json.loads(CACHE.read_text()) if CACHE.exists() else {}
rows = []
for s in sel:
    key = f"{s['label']}/{s['ecosystem']}/{s['name']}/{s['version']}"
    if key in cache:
        rows.append(cache[key])
        print("cached   ", key, flush=True)
        continue
    with tempfile.TemporaryDirectory(prefix="ss-real-", ignore_cleanup_errors=True) as t:
        tmp = Path(t)
        if s["label"] == "malicious":
            root = unpack(s, tmp)
            ctx = None
        else:
            ctx = OpenedPackage(s["file"])
            root = ctx.__enter__().root
        try:
            row = {k: s[k] for k in ("label", "ecosystem", "name", "version")}
            if s.get("av_blocked_files"):
                row.update({"excluded": f"antivirus blocked {len(s['av_blocked_files'])} file(s): "
                                        + ", ".join(s["av_blocked_files"][:3]),
                            "files_missing_after_extract": s.get("files_missing_after_extract", 0)})
                for tool in ("SupplyShield", "GuardDog", "Bandit", "advisory", "known-malware (hindsight)"):
                    row[tool] = None
                row["SupplyShield ms"] = row["GuardDog ms"] = None
                rows.append(row)
                cache[key] = row
                CACHE.write_text(json.dumps(cache, indent=2))
                print("EXCLUDED ", key, "-", row["excluded"], flush=True)
                continue
            t0 = time.perf_counter()
            r = scan(root)
            row["SupplyShield"] = r.verdict != "SAFE"
            row["SupplyShield detail"] = f"{r.verdict} {r.score}"
            row["SupplyShield rules"] = sorted({f.rule_id for f in r.findings})
            row["SupplyShield ms"] = round((time.perf_counter() - t0) * 1000)

            t0 = time.perf_counter()
            row["GuardDog"], row["GuardDog detail"] = guarddog(root, s["ecosystem"])
            row["GuardDog ms"] = round((time.perf_counter() - t0) * 1000)

            row["Bandit"], row["Bandit detail"] = bandit(root, s["ecosystem"])

            if s["ecosystem"] == "pypi":
                row["advisory"], row["advisory detail"] = pip_audit_version(s["name"], s["version"])
            else:
                row["advisory"], row["advisory detail"] = npm_audit_version(s["name"], s["version"])

            v = scan(root, vulns=True)
            row["known-malware (hindsight)"] = any(f.rule_id == "KNOWN-MALWARE" for f in v.findings)
            row["files_missing_after_extract"] = s.get("files_missing_after_extract", 0)
        finally:
            if ctx:
                ctx.__exit__(None, None, None)
    rows.append(row)
    cache[key] = row
    CACHE.write_text(json.dumps(cache, indent=2))
    print(f"{row['label']:<9} {row['ecosystem']:<4} {row['name'][:28]:<28} SS={row['SupplyShield detail']:<14} "
          f"GD={row['GuardDog detail'][:30]:<30} adv={row['advisory detail'][:28]}", flush=True)

(R / "results.json").write_text(json.dumps(rows, indent=2))


def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0, c - h), min(1, c + h))


print("\n=== SUMMARY (n = 20 malicious, 20 benign) ===")
for tool in ("SupplyShield", "GuardDog", "Bandit", "advisory", "known-malware (hindsight)"):
    for eco in ("all", "pypi", "npm"):
        rs = [r for r in rows if r.get(tool) is not None and (eco == "all" or r["ecosystem"] == eco)]
        tp = sum(r[tool] is True and r["label"] == "malicious" for r in rs)
        fn = sum(r[tool] is False and r["label"] == "malicious" for r in rs)
        fp = sum(r[tool] is True and r["label"] == "benign" for r in rs)
        tn = sum(r[tool] is False and r["label"] == "benign" for r in rs)
        if tp + fn + fp + tn == 0:
            continue
        rec = tp / (tp + fn) if tp + fn else float("nan")
        lo, hi = wilson(tp, tp + fn)
        prec = tp / (tp + fp) if tp + fp else float("nan")
        fpr = fp / (fp + tn) if fp + tn else float("nan")
        print(f"{tool:<26} {eco:<5} TP={tp:<2} FN={fn:<2} FP={fp:<2} TN={tn:<2} recall={rec:.2f} "
              f"[95% CI {lo:.2f}-{hi:.2f}] precision={prec:.2f} false-alarm-rate={fpr:.2f}")
for tool in ("SupplyShield", "GuardDog"):
    ms = [r[f"{tool} ms"] for r in rows if r.get(f"{tool} ms") is not None and r.get(tool) is not None]
    print(f"{tool} mean ms/package (completed scans): {sum(ms) / len(ms):.0f}")
print("excluded (antivirus):", [(r["name"], r["excluded"]) for r in rows if r.get("excluded")])
print("files missing after extraction:", sum(r.get("files_missing_after_extract", 0) for r in rows))
print("GuardDog timeouts / errors:", [(r["name"], r["GuardDog detail"]) for r in rows
                                      if r["GuardDog"] is None and not r.get("excluded")])

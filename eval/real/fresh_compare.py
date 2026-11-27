"""Summarise the fresh-set test for each version (fresh_v02.json, fresh_v03hand.json, fresh_v03.json)."""
import json
import math
import sys
from pathlib import Path

R = Path(__file__).parent
VERSIONS = [("v0.2 (rules + hand-set scoring)", "fresh_v02.json"),
            ("v0.3 rules + hand-set scoring", "fresh_v03hand.json"),
            ("v0.3 (rules + learned scoring)", "fresh_v03.json")]


def wilson(k, n, z=1.96):
    if not n:
        return float("nan"), float("nan")
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0, c - h), min(1, c + h)


def frac(vals):
    vals = [v for v in vals if v is not None]
    k, n = sum(vals), len(vals)
    lo, hi = wilson(k, n)
    return f"{k}/{n} ({k / n:.0%}) [{lo:.0%}-{hi:.0%}]" if n else "-"


all_rows = {f: json.loads((R / f).read_text()) for _, f in VERSIONS if (R / f).exists()}
# a sample excluded (antivirus) in ANY run is excluded in all, so every version sees the same packages
excluded = {r["name"] + r["new"] for rows in all_rows.values() for r in rows if r.get("excluded")}
print("excluded (antivirus):", sorted(excluded) or "none")
for label, f in VERSIONS:
    if f not in all_rows:
        continue
    rows = [r for r in all_rows[f] if r["name"] + r["new"] not in excluded]
    pois = [r for r in rows if r["kind"] == "poisoned_update"]
    ben = [r for r in rows if r["kind"] == "benign"]
    print(f"\n== {label} ==")
    print("  poisoned releases flagged (scan alone)   :", frac([r["bad_scan"]["flagged"] for r in pois]))
    print("  poisoned updates flagged by version diff :", frac([r["diff"]["flagged"] for r in pois]))
    print("  false alarms, 20 new popular packages     :", frac([r["new_scan"]["flagged"] for r in ben]))
    print("  false alarms, their previous releases     :", frac([r["prev_scan"]["flagged"] for r in ben if "prev_scan" in r]))
    print("  false alarms, clean releases before attack:", frac([r["clean_scan"]["flagged"] for r in pois]))
    print("  false alarms, diff on normal updates      :", frac([r["diff"]["flagged"] for r in ben if "diff" in r]))
    if "-v" in sys.argv:
        for r in rows:
            keys = ["bad_scan", "diff", "clean_scan"] if r["kind"] == "poisoned_update" else ["new_scan", "prev_scan", "diff"]
            print("   ", r["kind"][:8], r["ecosystem"], f"{r['name'][:28]:<28}", f"{r['old']}->{r['new']}",
                  "  ".join(f"{k}={r[k]['verdict'][:4]}{r[k]['score']}" for k in keys if k in r),
                  ",".join(r.get("diff", {}).get("rules", []))[:70])

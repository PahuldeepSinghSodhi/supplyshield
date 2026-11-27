"""Compare SupplyShield v0.1 and v0.2 on the real data. Excludes the antivirus-blocked sample for both."""
import json
import math
from pathlib import Path

R = Path(__file__).parent
EXCLUDE = {"maya-rangi92-breki"}  # antivirus blocked its files: no tool could read it


def wilson(k, n, z=1.96):
    if n == 0:
        return (float("nan"),) * 2
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0, c - h), min(1, c + h)


def stats(rows, label, subset):
    rs = [r for r in rows if r["label"] == label and r["name"] not in EXCLUDE and subset(r)]
    k = sum(r["flagged"] for r in rs)
    lo, hi = wilson(k, len(rs))
    return f"{k}/{len(rs)} ({k / len(rs):.0%}, 95% CI {lo:.0%}-{hi:.0%})"


for ver in ("v01", "v02"):
    rows = json.loads((R / f"{ver}.json").read_text())
    print(f"\n===== SupplyShield {ver} =====")
    print("malware detected (main, 19)       :", stats(rows, "malicious", lambda r: True))
    print("  pypi / npm                      :", stats(rows, "malicious", lambda r: r["ecosystem"] == "pypi"),
          "/", stats(rows, "malicious", lambda r: r["ecosystem"] == "npm"))
    print("false alarms, tuning benign (20)  :", stats(rows, "benign", lambda r: r["set"] == "main"))
    print("false alarms, HOLDOUT benign (20) :", stats(rows, "benign", lambda r: r["set"] == "holdout"))
    ms = [r["ms"] for r in rows if r.get("ms") is not None]
    print(f"mean time per package             : {sum(ms) / len(ms):.0f} ms")

v1 = {r["name"]: r for r in json.loads((R / "v01.json").read_text())}
v2 = {r["name"]: r for r in json.loads((R / "v02.json").read_text())}
print("\n===== per package (v0.1 -> v0.2) =====")
for n, a in v1.items():
    b = v2[n]
    mark = "" if a.get("flagged") == b.get("flagged") else "  <-- changed"
    print(f"{a['set']:<7} {a['label']:<9} {a['ecosystem']:<4} {n[:28]:<28} {a['verdict']:<10} {a.get('score', ''):>3} -> "
          f"{b['verdict']:<10} {b.get('score', ''):>3}  {','.join(b.get('rules', []))[:60]}{mark}")

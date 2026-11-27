"""Show where each SupplyShield finding came from: benign false alarms and malicious misses."""
import json
import sys
import tempfile
import zipfile
from collections import Counter
from pathlib import Path

REPO = Path(sys.argv[1])
sys.path.insert(0, str(REPO))
from supplyshield.analyzer import scan  # noqa: E402
from supplyshield.loader import OpenedPackage, _find_root  # noqa: E402

R = Path(__file__).parent
sel = json.loads((R / "selection.json").read_text())
want = set(sys.argv[2:])  # optional package names
by_dir = Counter()
for s in sel:
    if want and s["name"] not in want:
        continue
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as t:
        if s["label"] == "malicious":
            zipfile.ZipFile(s["file"]).extractall(t, pwd=b"infected")
            root = _find_root(Path(t))
            try:
                r = scan(root)
            except OSError as e:
                print("SKIP", s["name"], e)
                continue
        else:
            with OpenedPackage(s["file"]) as pkg:
                r = scan(pkg.root)
        print(f"\n### {s['label']} {s['ecosystem']} {s['name']}: {r.verdict} {r.score} chains={r.chains}")
        for f in r.findings:
            top = f.file.split("/")[0] if "/" in f.file else "(root)"
            if s["label"] == "benign":
                by_dir[(f.rule_id, top if top in ("tests", "test", "docs", "testing", "bench", "benchmarks")
                        or f.file in ("noxfile.py", "setup.py", "conftest.py") else "library code")] += 1
            print(f"  {f.severity:<8} {f.rule_id:<18} {f.file}:{f.line}  {f.evidence[:90]}")
print("\n=== benign findings by rule and location ===")
for (rule, where), n in sorted(by_dir.items()):
    print(f"  {rule:<18} {where:<14} {n}")

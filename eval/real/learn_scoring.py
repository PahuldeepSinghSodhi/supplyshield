"""Learn SupplyShield's scoring weights and thresholds from labelled data (replaces hand-set numbers).

Training data = everything seen BEFORE the fresh test set: the 20 synthetic samples, 19 real malware
samples and 40 real popular packages (main + holdout). The fresh set (fetch_fresh.py) is not touched here.

Model: L2-regularised logistic regression on features() from supplyshield/scoring.py (strongest
severity per behaviour category + which attack chains fired). Regularisation strength is chosen by
leave-one-out cross-validation; thresholds are chosen on the OUT-OF-FOLD probabilities, so they are not
fitted to predictions the model has already seen:
  SUSPICIOUS: maximises (detection rate - false-alarm rate)   (Youden's J)
  MALICIOUS:  lowest probability whose out-of-fold precision is at least 95%
usage: python -I learn_scoring.py <repo root>          (needs scikit-learn; evaluation only)
"""
import json
import sys
import tempfile
import zipfile
from pathlib import Path

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import LeaveOneOut, cross_val_predict

REPO = Path(sys.argv[1])
sys.path.insert(0, str(REPO))
from supplyshield.analyzer import scan  # noqa: E402
from supplyshield.loader import OpenedPackage, _find_root  # noqa: E402
from supplyshield.scoring import features  # noqa: E402

R = Path(__file__).parent
EXCLUDE = {"maya-rangi92-breki"}  # antivirus-blocked


def report_for(item):
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as t:
        if item.get("zip"):
            zipfile.ZipFile(item["zip"]).extractall(t, pwd=b"infected")
            return scan(_find_root(Path(t)))
        if Path(item["path"]).is_dir():
            return scan(item["path"])
        with OpenedPackage(item["path"]) as p:
            return scan(p.root)


items = []
for k, m in json.loads((REPO / "samples/labels.json").read_text()).items():
    items.append({"set": "synthetic", "name": k, "y": int(m["malicious"]), "path": str(REPO / "samples" / k)})
for s in json.loads((R / "selection.json").read_text()):
    if s["name"] in EXCLUDE:
        continue
    it = {"set": "real-main", "name": s["name"], "y": int(s["label"] == "malicious")}
    it["zip" if s["label"] == "malicious" else "path"] = s["file"]
    items.append(it)
for s in json.loads((R / "holdout.json").read_text()):
    items.append({"set": "real-holdout", "name": s["name"], "y": 0, "path": s["file"]})

rows, hand = [], []
for it in items:
    r = report_for(it)
    rows.append(features(r.findings))
    hand.append(r.score)
names = list(rows[0])
X = np.array([[row[n] for n in names] for row in rows])
y = np.array([it["y"] for it in items])
print(f"training packages: {len(y)} ({y.sum()} malicious, {len(y) - y.sum()} benign); features: {len(names)}")

results = []
for C in (0.03, 0.1, 0.3, 1.0, 3.0, 10.0, 30.0):
    clf = LogisticRegression(C=C, class_weight="balanced", max_iter=5000)
    p = cross_val_predict(clf, X, y, cv=LeaveOneOut(), method="predict_proba")[:, 1]
    auc = roc_auc_score(y, p)
    print(f"C={C:<5} leave-one-out AUC={auc:.3f}")
    results.append((C, auc, p))
# Prefer the simplest (most regularised) model within 0.005 AUC of the best: with 79 packages, a
# difference that small is one or two packages and not worth weaker regularisation.
top = max(a for _, a, _ in results)
C, auc, oof = min((r for r in results if r[1] >= top - 0.005), key=lambda r: r[0])
print(f"chosen C={C} (most regularised within 0.005 of best AUC {top:.3f})")
print(f"hand-set score AUC on the same data: {roc_auc_score(y, hand):.3f}")


def rates(t, prob):
    pred = prob >= t
    tp, fp = int((pred & (y == 1)).sum()), int((pred & (y == 0)).sum())
    return tp / y.sum(), fp / (len(y) - y.sum()), (tp / (tp + fp) if tp + fp else 1.0)


grid = sorted(set(np.round(oof, 4)))
t_susp = max(grid, key=lambda t: rates(t, oof)[0] - rates(t, oof)[1])
t_mal = min((t for t in grid if rates(t, oof)[2] >= 0.95 and t >= t_susp), default=max(grid))
for label, t in (("SUSPICIOUS", t_susp), ("MALICIOUS", t_mal)):
    tpr, fpr, prec = rates(t, oof)
    print(f"{label:<10} threshold p>={t:.3f}: out-of-fold detection {tpr:.0%}, false alarms {fpr:.0%}, precision {prec:.0%}")
for name, t in (("hand-set SUSPICIOUS (25)", 25), ("hand-set MALICIOUS (60)", 60)):
    tpr, fpr, prec = rates(t, np.array(hand))
    print(f"{name:<26}: detection {tpr:.0%}, false alarms {fpr:.0%}, precision {prec:.0%}")

final = LogisticRegression(C=C, class_weight="balanced", max_iter=5000).fit(X, y)
model = {"intercept": round(float(final.intercept_[0]), 4),
         "weights": {n: round(float(w), 4) for n, w in zip(names, final.coef_[0])},
         "suspicious_at": round(float(t_susp), 4), "malicious_at": round(float(t_mal), 4),
         "C": C, "loo_auc": round(auc, 3), "n_train": int(len(y)), "n_malicious": int(y.sum())}
(R / "learned_model.json").write_text(json.dumps(model, indent=2))
print(json.dumps(model, indent=2))

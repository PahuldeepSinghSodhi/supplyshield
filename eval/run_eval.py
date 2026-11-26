"""Compare SupplyShield with existing tools on the labelled test corpus.

Usage:
    python eval/run_eval.py [--bandit PATH] [--pip-audit PATH] [--guarddog PATH]

Tools that are not installed are reported as "not run"; no result is ever invented.
npm audit runs with --package-lock-only --ignore-scripts, so no sample code executes.
Writes eval/results.csv, eval/results.md and eval/results_table.tex.
"""
from __future__ import annotations

import argparse
import csv
import json
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from supplyshield.analyzer import diff, scan  # noqa: E402

SAMPLES = ROOT / "samples"
OUT = ROOT / "eval"


def run(cmd: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, encoding="utf-8",
                          errors="replace", timeout=300, shell=False)


# ---------------------------------------------------------------- tool adapters
def t_supplyshield(path: Path, eco: str):
    r = scan(path)
    return r.verdict != "SAFE", f"{r.verdict} ({r.score}/100)"


def t_bandit(exe):
    def f(path: Path, eco: str):
        if eco != "pypi":
            return None, "n/a (Python only)"
        p = run([exe, "-r", str(path), "-f", "json", "-q"])
        issues = json.loads(p.stdout or "{}").get("results", [])
        sev = [i["issue_severity"] for i in issues]
        flagged = any(s in ("MEDIUM", "HIGH") for s in sev)
        return flagged, f"{len(issues)} issues ({sum(s != 'LOW' for s in sev)} medium/high)"
    return f


def t_pip_audit(exe):
    def f(path: Path, eco: str):
        if eco != "pypi":
            return None, "n/a (Python only)"
        p = run([exe, str(path)])
        text = (p.stdout + p.stderr).lower()
        if "couldn't find a supported project file" in text:
            return False, "could not audit (setup.py project)"
        if "no known vulnerabilities" in text:
            return False, "no known vulnerabilities"
        return p.returncode != 0, (p.stdout.strip().splitlines() or ["?"])[-1][:60]
    return f


def t_npm_audit(npm):
    def f(path: Path, eco: str):
        if eco != "npm":
            return None, "n/a (npm only)"
        with tempfile.TemporaryDirectory() as tmp:
            dep = path.resolve().as_posix()
            Path(tmp, "package.json").write_text(json.dumps(
                {"name": "audit-harness", "version": "1.0.0", "dependencies": {"sample": f"file:{dep}"}}))
            run([npm, "install", "--package-lock-only", "--ignore-scripts", "--no-audit"], cwd=Path(tmp))
            p = run([npm, "audit", "--json"], cwd=Path(tmp))
            total = json.loads(p.stdout or "{}").get("metadata", {}).get("vulnerabilities", {}).get("total", 0)
        return total > 0, f"{total} vulnerabilities"
    return f


def t_guarddog(exe):
    def f(path: Path, eco: str):
        p = run([exe, eco, "scan", str(path), "--output-format", "json"])
        try:
            data = json.loads(p.stdout)
        except json.JSONDecodeError:
            return None, "error: " + (p.stderr.strip().splitlines() or ["?"])[-1][:50]
        n = data.get("issues", 0)
        hits = [k for k, v in (data.get("results") or {}).items() if v]
        return n > 0, f"{n} issues" + (f" ({', '.join(hits)[:50]})" if hits else "")
    return f


# ---------------------------------------------------------------- main
def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bandit", default=shutil.which("bandit"))
    ap.add_argument("--pip-audit", dest="pip_audit", default=shutil.which("pip-audit"))
    ap.add_argument("--guarddog", default=shutil.which("guarddog"))
    ap.add_argument("--npm", default=shutil.which("npm"))
    args = ap.parse_args()

    tools = {"SupplyShield": t_supplyshield}
    not_run = []
    for name, exe, adapter in [("Bandit", args.bandit, t_bandit), ("pip-audit", args.pip_audit, t_pip_audit),
                               ("npm audit", args.npm, t_npm_audit), ("GuardDog", args.guarddog, t_guarddog)]:
        if exe:
            tools[name] = adapter(exe)
        else:
            not_run.append(name)

    labels = json.loads((SAMPLES / "labels.json").read_text(encoding="utf-8"))
    rows = []
    for rel, meta in labels.items():
        row = {"sample": rel, "ecosystem": meta["ecosystem"], "malicious": meta["malicious"]}
        for tname, fn in tools.items():
            t0 = time.perf_counter()
            flagged, detail = fn(SAMPLES / rel, meta["ecosystem"])
            row[tname] = flagged
            row[tname + " detail"] = detail
            row[tname + " ms"] = round((time.perf_counter() - t0) * 1000)
        rows.append(row)
        print(f"{rel:<34}" + "  ".join(f"{t}={row[t]}" for t in tools))

    # Metrics per tool, over the samples the tool applies to.
    metrics = {}
    for t in tools:
        tp = sum(1 for r in rows if r[t] is True and r["malicious"])
        fn_ = sum(1 for r in rows if r[t] is False and r["malicious"])
        fp = sum(1 for r in rows if r[t] is True and not r["malicious"])
        tn = sum(1 for r in rows if r[t] is False and not r["malicious"])
        applicable = tp + fn_ + fp + tn
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / (tp + fn_) if tp + fn_ else 0.0
        ms = [r[t + " ms"] for r in rows if r[t] is not None]
        metrics[t] = dict(applicable=applicable, tp=tp, fn=fn_, fp=fp, tn=tn,
                          precision=prec, recall=rec, avg_ms=sum(ms) / len(ms) if ms else 0)

    diffs = []
    for old, new in [("pypi/colorlib-1.0", "pypi/colorlib-1.1"), ("npm/minilog-1.0.0", "npm/minilog-1.0.1")]:
        o, n, d = diff(SAMPLES / old, SAMPLES / new)
        diffs.append((old, new, o.verdict, n.verdict, d.verdict, len(d.findings),
                      ", ".join(sorted({f.rule_id for f in d.findings}))))

    # ---- write outputs
    with open(OUT / "results.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    md = ["# Evaluation results", "",
          f"Corpus: {len(rows)} packages ({sum(r['malicious'] for r in rows)} malicious, "
          f"{sum(not r['malicious'] for r in rows)} benign), PyPI and npm. Generated by `eval/run_eval.py`.", "",
          "| Tool | Samples covered | Detected (TP) | Missed (FN) | False alarms (FP) | Precision | Recall | Avg time (ms) |",
          "|---|---|---|---|---|---|---|---|"]
    for t, m in metrics.items():
        md.append(f"| {t} | {m['applicable']} | {m['tp']} | {m['fn']} | {m['fp']} | {m['precision']:.2f} | "
                  f"{m['recall']:.2f} | {m['avg_ms']:.0f} |")
    if not_run:
        md += ["", f"Not run (not installed): {', '.join(not_run)}."]
    md += ["", "## Per-sample results", "",
           "| Sample | Malicious? | " + " | ".join(tools) + " |", "|---|---|" + "---|" * len(tools)]
    for r in rows:
        md.append(f"| {r['sample']} | {'yes' if r['malicious'] else 'no'} | " +
                  " | ".join(r[t + ' detail'] for t in tools) + " |")
    md += ["", "## Version-diff analysis (SupplyShield only)", "",
           "| Old | New | Old verdict | New verdict | Introduced-behaviour verdict | New findings | Rules |",
           "|---|---|---|---|---|---|---|"]
    md += [f"| {a} | {b} | {c} | {d} | {e} | {f} | {g} |" for a, b, c, d, e, f, g in diffs]
    (OUT / "results.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    tex = [r"\begin{table}[t]", r"\centering",
           r"\caption{Detection results on the " + str(len(rows)) + r"-package test corpus.}",
           r"\label{tab:results}", r"\begin{tabular}{lrrrrrr}", r"\hline",
           r"Tool & Covered & TP & FN & FP & Precision & Recall \\", r"\hline"]
    for t, m in metrics.items():
        tex.append(f"{t} & {m['applicable']} & {m['tp']} & {m['fn']} & {m['fp']} & "
                   f"{m['precision']:.2f} & {m['recall']:.2f} \\\\")
    tex += [r"\hline", r"\end{tabular}", r"\end{table}"]
    (OUT / "results_table.tex").write_text("\n".join(tex) + "\n", encoding="utf-8")
    print("\n" + "\n".join(md[:8 + len(metrics) + (2 if not_run else 0)]))


if __name__ == "__main__":
    main()

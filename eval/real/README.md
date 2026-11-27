# Evaluation on real packages

Results: **[results.md](results.md)**. This folder holds the scripts, the list of packages used
([`corpus.json`](corpus.json): names, versions, sources and SHA-256 hashes) and the raw results.
**No package files, and no malware, are stored in this repository.**

## Data

| Set | Source | Selection |
|---|---|---|
| 20 real malicious | [DataDog/malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset) (Apache-2.0; human-triaged) | 10 PyPI + 10 npm, `malicious_intent`, random with seed 42 from 2,503 PyPI / 25,267 npm samples |
| 20 real benign ("main") | PyPI JSON API / npm registry | Top 10 most-downloaded PyPI packages ([hugovk/top-pypi-packages](https://github.com/hugovk/top-pypi-packages)) and top 10 npm packages by last-week downloads (api.npmjs.org) |
| 20 real benign ("holdout") | same | PyPI ranks 11–20 and npm ranks 11–20. **Never used while changing the rules.** |

Dataset bias: most samples in Datadog's dataset were found by GuardDog, which favours GuardDog in a comparison.

## Safety

- Malware was fetched one file at a time (GitHub API), kept outside the repository, and only ever **read**:
  extracted to a temporary folder (password `infected`), scanned, and deleted. Nothing was installed or run.
- Benign packages were downloaded directly with `urllib` (never `pip download`, which can run `setup.py`).
- Antivirus on the test machine (Avast) blocked reading one malware sample; it was **not bypassed**, and that
  sample is excluded from every tool's score.

## Method

1. **Blind run (v0.1)**: SupplyShield 0.1.0, GuardDog 2.10.0 (Semgrep 1.187, 180 s limit per package),
   Bandit 1.9.4, pip-audit 2.10.1 and npm audit (npm 11.17, `--package-lock-only --ignore-scripts`) on the 40
   main packages, before any change. Raw: [`blind_run_all_tools_v01.json`](blind_run_all_tools_v01.json).
2. **Analysis**: every false alarm and miss was traced to its file and rule ([`analyse.py`](analyse.py)).
3. **Fixes (v0.2)**: general rule changes only, listed in [../../CHANGELOG.md](../../CHANGELOG.md).
4. **Re-test**: v0.1 and v0.2 on all 60 packages ([`scan_all.py`](scan_all.py), [`compare.py`](compare.py));
   GuardDog and Bandit on the 20 holdout packages ([`holdout_tools.py`](holdout_tools.py)).

Malware detection after the fixes is measured on the **same** 19 samples that informed them, so it is not an
independent estimate; the holdout false-alarm rate is. With 19–20 packages per group, confidence intervals are
wide (Wilson 95% intervals are given).

## Reproduce

```bash
cd eval/real
git clone --filter=blob:none --no-checkout --depth 1 https://github.com/DataDog/malicious-software-packages-dataset.git dd
git -C dd ls-tree -r --name-only HEAD samples/pypi samples/npm > tree.txt
python fetch_real.py ../../supplyshield/data/popular_npm.txt      # needs the GitHub CLI (gh) signed in
python fetch_holdout.py ../../supplyshield/data/popular_npm.txt
python run_real_eval.py ../.. <bandit> <pip-audit> <guarddog>      # blind multi-tool run
python scan_all.py <folder with SupplyShield version> out.json     # per-version scan of all 60
python compare.py
```

Rankings change monthly, so a re-run months later selects slightly different benign packages; `corpus.json`
records exactly what was used.

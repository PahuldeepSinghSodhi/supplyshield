# Results on real packages

Data, safety and method: [README.md](README.md). Package list: [corpus.json](corpus.json).
19 real malware samples (1 of 20 excluded: antivirus blocked it), 20 popular benign packages ("main"),
20 further popular benign packages never used while changing the rules ("holdout").
Percentages in brackets are Wilson 95% confidence intervals.

## 1. Blind run: all tools, before any change (SupplyShield v0.1)

| Tool | Real malware detected | False alarms (main benign) | Time per package |
|---|---|---|---|
| **SupplyShield 0.1** | **17 / 19 (89%)** [69–97%] | 9 / 20 (45%) [26–66%] | 0.19 s |
| GuardDog 2.10 | 13 / 16 (81%) [57–93%] + 3 timeouts | 7 / 19 (37%) + 1 timeout | 19.8 s |
| Bandit 1.9 (Python only) | 8 / 10 (80%) | 8 / 10 (80%) | – |
| pip-audit / npm audit | **0 / 19 (0%)** | 0 / 20 | – |

- pip-audit reported "no known vulnerabilities" for every Python malware sample; npm audit could not check the
  npm ones (removed from the registry). They look for known bugs, not new malware.
- GuardDog exceeded the 180 s limit on 3 malware samples and 1 benign package; timeouts are not counted as misses.
- Looking the same malware up in OSV.dev *today* (`--vulns`) finds 17 / 19 as known malware. That is
  hindsight: when these packages were first published, no database listed them.

## 2. What the real data taught (v0.1 → v0.2)

Every false alarm and miss was traced to a file and a rule. The fixes are general rules, listed in
[CHANGELOG.md](../../CHANGELOG.md), for example: network access only for calls that open connections;
test/docs/example files downgraded; copying the environment is low while turning it into text is high;
new install-time reconnaissance rule; unreadable files no longer crash the scan.

| SupplyShield | v0.1 | v0.2 |
|---|---|---|
| Real malware detected (same 19 that informed the fixes) | 17 / 19 (89%) | 18 / 19 (95%) |
| False alarms, main benign (used for analysis) | 9 / 20 (45%) | 3 / 20 (15%) |
| **False alarms, holdout benign (never seen)** | **8 / 20 (40%)** [22–61%] | **5 / 20 (25%)** [11–47%] |
| Holdout false alarms rated MALICIOUS | 5 | 2 |
| Synthetic corpus (20 packages) | 10 / 12, 1 false alarm | unchanged |

Gained: `artifact-lab-3-package` (sends `os.environ.__str__()` to a server) and `nabisco` (fingerprints the
host from a `postinstall` script). Lost: `dasdsajdjsaasddsad` (its only signal was `exec` in library code, now
medium). The malware figure is **not independent** (same samples); the holdout false-alarm figure is.

## 3. Holdout comparison (20 unseen popular packages)

| Tool | False alarms |
|---|---|
| **SupplyShield 0.2** | **5 / 20 (25%)** |
| SupplyShield 0.1 | 8 / 20 (40%) |
| GuardDog 2.10 | 7 / 20 (35%) |
| Bandit 1.9 (Python only) | 9 / 10 (90%) |

Remaining SupplyShield false alarms: `setuptools` (it *is* the installer: install hooks and compiler calls),
`pygments` (a syntax highlighter that names `id_rsa` as a file type and contains `AreClientCookiesCached`),
`pyyaml`, `pydantic`, `click`. Fixing secret-path substring matching is the clearest next step.

## 4. v0.3: learned scoring, final test on never-seen data

**Learning** ([learn_scoring.py](learn_scoring.py), model: [learned_model.json](learned_model.json)): logistic
regression on 79 packages seen so far (31 malicious, 48 benign). Leave-one-out AUC 0.90 (hand-set points 0.87);
at 90% detection, out-of-fold false alarms 10% (hand-set 21%). Learned weights: typosquat +1.89,
obfuscation +1.67, reconnaissance +1.54, install-time code +1.38, secrets +1.13, network +0.15,
commands −0.33, `exec`/`eval` −1.14 (more common in honest libraries).

**Fresh set** ([fetch_fresh.py](fetch_fresh.py), list: [fresh_corpus.json](fresh_corpus.json)), never used for
rules or scoring: 20 real **hijacked releases of genuine packages** (Datadog `compromised_lib`, 15 npm + 5 PyPI,
seed 7; e.g. `axios` 1.14.1, `eslint-config-prettier`, `ultralytics`), each with its clean previous release, and
20 new popular packages (ranks 21–30) with their previous releases. Scoped npm names were skipped (dataset naming).

| On never-seen data | v0.2 | v0.3 rules + old scoring | **v0.3** | GuardDog 2.10 |
|---|---|---|---|---|
| Hijacked releases caught | 6/20 (30%) | 6/20 | **11/20 (55%)** [34–74%] | 5/20 (25%) |
| Poisoned updates caught by `diff` | 2/20 (10%) | 2/20 | **11/20 (55%)** | no such feature |
| False alarms, 20 new popular packages | 6/20 (30%) | 6/20 | **5/20 (25%)** | 3/19 (16%) + 1 timeout |
| False alarms, 20 clean releases before attack | 5/20 | 5/20 | **2/20 (10%)** | – |
| False alarms, `diff` on 20 normal updates | 0/20 | 0/20 | **0/20** | – |
| Time per package | ~0.2 s | | ~0.2 s | ~20 s |

- **The learned scoring is what helped;** the rule changes alone did not change the fresh results.
- Real hijacks mostly **add an install script** that runs packed code or a binary the rules cannot read; the
  learned model weights added install-time code strongly. `axios` 1.14.1 only added a dependency carrying the
  malware: dependency scanning is the next step.
- v0.3 lost 3 hijacked releases (`ultralytics`, `elementary-data`, `effect-analyzer`) flagged by v0.2.
- Remaining false alarms are packages whose real job looks like an attack: `botocore` (AWS SDK) reads
  `~/.aws/credentials`; `numpy`, `pytest` run compilers and commands.
- Post-hoc (rule learned from this set, not independent): `NEW-INSTALL-CODE` gave the same 11/19 poisoned updates
  and 0/20 normal-update false alarms ([fresh_diff_posthoc.json](fresh_diff_posthoc.json); `ultralytics` excluded:
  its download differed from the first fetch).

## Limits

Small samples (wide intervals), one malware dataset (found mostly by GuardDog), popular benign packages only
(less popular packages may behave differently), and rules revised after seeing the 40 main packages. Raw results:
[blind_run_all_tools_v01.json](blind_run_all_tools_v01.json), [supplyshield_v01.json](supplyshield_v01.json),
[supplyshield_v02.json](supplyshield_v02.json), [holdout_guarddog_bandit.json](holdout_guarddog_bandit.json).

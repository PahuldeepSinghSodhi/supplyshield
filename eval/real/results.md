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

## Limits

Small samples (wide intervals), one malware dataset (found mostly by GuardDog), popular benign packages only
(less popular packages may behave differently), and rules revised after seeing the 40 main packages. Raw results:
[blind_run_all_tools_v01.json](blind_run_all_tools_v01.json), [supplyshield_v01.json](supplyshield_v01.json),
[supplyshield_v02.json](supplyshield_v02.json), [holdout_guarddog_bandit.json](holdout_guarddog_bandit.json).

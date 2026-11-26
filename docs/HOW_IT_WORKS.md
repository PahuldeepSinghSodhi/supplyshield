# How SupplyShield works

A plain-language explanation of the method, for anyone reviewing this project.

## 1. The core idea

Existing free tools ask: *"Is this package version on a list of known vulnerabilities?"*
SupplyShield asks: *"What does this package's code actually do?"*

It reads the package's files and analyses them **without installing, importing or running anything**.

## 2. The pipeline

1. **Safe loader.** Opens a folder or archive (`.tar.gz`, `.tgz`, `.whl`, `.zip`) into a temporary folder.
   It blocks archive tricks such as `../../` paths and symbolic links that could write outside that folder.
2. **Python rules** ([rules_python.py](../supplyshield/rules_python.py)). Each `.py` file is turned into a
   *syntax tree* (the structure Python itself uses), so renamed imports are still recognised:
   `from base64 import b64decode as d; exec(d("..."))` is caught as a hidden payload.
   Code in `setup.py` is marked **install-time**, because it runs automatically during installation.
3. **npm rules** ([rules_npm.py](../supplyshield/rules_npm.py)). `preinstall` / `install` / `postinstall`
   scripts in `package.json` are graded: `node-gyp rebuild` is low (normal), `curl … | sh` is critical.
   JavaScript files started by these scripts are marked install-time.
4. **Shared checks** ([common.py](../supplyshield/common.py)). These cover random-looking encoded strings
   (hidden payloads), paths to secrets (`~/.ssh`, `.aws/credentials`, `.npmrc`, browser password stores) and
   typosquatting.
5. **Scoring** ([scoring.py](../supplyshield/scoring.py)) turns findings into a score and a verdict.
6. **Report** ([report.py](../supplyshield/report.py)). Every finding shows the file, line, code, **why**
   it is dangerous, and a **fix**.

## 3. Attack-chain scoring: "dangerous combinations of signals"

Each suspicious behaviour (a *signal*) is often perfectly normal on its own:

| Signal | Why a normal package might do it |
|---|---|
| Connects to the internet | A weather library calls a weather API |
| Runs a system command | A build tool calls `git` |
| Reads an environment variable | An app reads a `DEBUG` setting |
| Runs code at install time | A package compiles native code with `node-gyp` |

Flagging each one would bury users in false alarms, and ignoring them would miss malware.
What gives malware away is **several signals together**. To steal passwords, a package must *run at install*,
*read secrets* **and** *send them over the network*. Together, these have only one realistic purpose.

**Points per finding:** low 3 · medium 10 · high 25 · critical 40 (each rule counts at most twice).

**Bonus for known attack chains:**

| Combination | Name | Bonus |
|---|---|---|
| install-time + secrets + network | Install-time data theft | +40 |
| secrets + network | Credential exfiltration | +25 |
| system commands during installation | Install-time command execution | +20 |
| hidden/encoded code + execution | Hidden payload | +20 |

**Verdict:** 0–24 **SAFE** · 25–59 **SUSPICIOUS** · 60–100 **MALICIOUS** (score capped at 100).

**Worked example from the test corpus**

| Package | Findings | Score | Verdict |
|---|---|---|---|
| `clean-weatherlite` | network (10) | 10 | ✅ SAFE |
| `mal-env-harvest` | network (10) + copies all env variables (25) + *credential exfiltration* chain (25) | 60 | 🚨 MALICIOUS |

Both contain the same network call. The **combination** separates the harmless one from the thief.

## 4. Version diff: "what did this update add?"

The event-stream, ua-parser-js and XZ Utils attacks all arrived as **updates to trusted packages**.
`supplyshield diff old new` scans both versions and reports only behaviour that is **new** in the update, plus
newly added dependencies. In the test corpus, `colorlib` 1.0 → 1.1 added an install hook that runs
`curl … | sh`, and the diff isolates exactly that (MALICIOUS, 100/100).

## 5. Typosquatting

Package names are compared with lists of popular packages using **Damerau–Levenshtein distance**: the number of
single-letter edits between two words, where swapping two neighbouring letters counts as **one** edit.
`lodahs` → `lodash` is 1 edit, so it is flagged. Real names such as `requests` are never flagged.

## 6. Limits

- Code assembled at run time (`getattr(os, "sys" + "tem")`) is invisible to static analysis. GuardDog caught
  our two evasive samples; adding rules for such dynamic lookups is the next step.
- The test corpus is small and self-built, so results show feasibility, not real-world accuracy.
- SupplyShield does not find *known vulnerable versions*. Use it **alongside** pip-audit / npm audit.

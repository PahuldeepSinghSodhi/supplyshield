# SupplyShield: talk notes (about 6 minutes plus demo)

## 1. Hook (30 s)
"Every app on your phone is built from hundreds of open-source packages written by strangers. Typing
`pip install` or `npm install` can run their code on your machine immediately. What if one of them is malicious?"

## 2. The problem is real (1 min)
- **event-stream (2018):** a new maintainer added a dependency that stole Bitcoin wallet keys.
- **ua-parser-js (2021):** the maintainer's npm account was hijacked; malicious versions installed a crypto-miner
  and stole credentials. CISA issued an alert.
- **XZ Utils (2024):** a backdoor in a compression library present in most Linux systems (CVE-2024-3094, CVSS 10),
  planted by a contributor who had spent years earning trust.
- The US Executive Order 14028 (2021) made software supply chain security a national priority.

## 3. Why existing tools miss it (1 min)
- `pip-audit`, `npm audit` and Dependabot ask: *"Is this version on a list of known vulnerabilities?"*
- A new malicious package is on no list yet, and that is exactly when attacks succeed.
- Research (Ohm et al. 2020): most malicious packages run **at install time** and steal **credentials**.
- Research tools (MalOSS, Amalfi) work well but need sandboxes, trained models or registry-scale infrastructure.

## 4. Our solution (1.5 min), with the architecture figure
SupplyShield asks: *"What does this package's code actually do?"*
- Safe loader: never installs or runs the code.
- Python: syntax-tree analysis. npm: package.json install scripts and code patterns.
- Flags install-time code, hidden payloads, secret access, network and commands, typosquats.
- **New 1: attack-chain scoring.** One signal is normal; install-time + secrets + network = theft.
- **New 2: version diff.** It shows what an update *added*, which is how event-stream, ua-parser-js and XZ arrived.
- Every finding explains **why** and gives a **fix**. Standard library only, so it runs anywhere.

## 5. Live demo (2 min): `presentation\demo.ps1`

## 6. Results (1 min), with the results table
- 20 inert test packages (12 malicious, 8 benign; PyPI and npm).
- SupplyShield: **10/12 detected, 1 false alarm** (precision 0.91, recall 0.83).
- pip-audit and npm audit: **0/12**. They are built for known vulnerabilities, not new malware.
- Bandit (generic Python analyser): 3/6. It rated `curl ... | sh` in an install hook as *low* severity.
- GuardDog (Datadog's specialised tool): also 10/12 with 1 false alarm, but **different mistakes**. It caught the
  evasive samples and missed the typosquats. It can't tell a harmless install script from `curl | sh`, has no
  version diff, and took **4.2 s per package vs 6 ms**.

## 6b. Real data (1 min)
- 19 real malware samples from Datadog's dataset + 40 of the most-downloaded PyPI/npm packages.
- Blind first run: SupplyShield caught **17/19** real malware; pip-audit and npm audit **0/19**.
- It also exposed the weakness the synthetic test hid: **45% false alarms** on popular packages (even `requests`).
- I traced every false alarm to its cause and fixed the rules (v0.2). On **20 unseen** popular packages:
  false alarms **40% → 25%** (GuardDog: 35%), malware caught **18/19**.

## 7. Honest limits and close (30 s)
- Small self-made corpus, so this shows feasibility, not real-world accuracy.
- Missed code that assembles names at run time; needs dynamic analysis.
- It complements vulnerability scanners; it doesn't replace them.
- "Existing tools ask *is it on a list?* We ask *what does it do?*"

---

## Likely questions

**Q: Didn't you just tune the tool to your test data?**
I kept two sets apart. I changed the rules using the first 40 real packages, then measured false alarms on 20
*unseen* packages I never looked at while tuning: 40% → 25%. The malware figure (18/19) uses the same samples that
informed the fixes, and I say so. One malware sample was actually lost by the changes, which I also report.

**Q: Isn't this what GuardDog or Socket.dev already do?**
They also analyse behaviour, and I tested GuardDog directly. It detects as many samples as mine, so I don't
claim better detection. My differences: the version diff (GuardDog compares a release with its GitHub source, not
the previous release), graded severity and attack chains (GuardDog flags a harmless `node-gyp` script and a
`curl | sh` script identically), explanations, no dependencies, and about 700× faster. GuardDog caught my evasive
samples, so adding dynamic-lookup rules is my next improvement.

**Q: Why not test on real malware?**
Running or distributing real malware is unsafe. The samples imitate documented attack patterns with harmless payloads
and the reserved `.invalid` domain. Testing on the Backstabber's Knife Collection dataset is the main future work.

**Q: Couldn't an attacker just evade your rules?**
Yes. My evasive samples show that. Static analysis raises the cost for attackers; it should be combined with
sandboxed dynamic analysis, such as OpenSSF Package Analysis.

**Q: Why is the comparison with pip-audit fair?**
It isn't a criticism of pip-audit. It shows that the tools most developers rely on cannot catch this attack class
by design. Bandit is included as the fairer code-level baseline.

**Q: How do you avoid false alarms?**
Single signals score low; only combinations reach "malicious". Benign native builds (`node-gyp rebuild`) are recognised.
The one false alarm was rated "suspicious", not "malicious", with a clear explanation.

**Q: How does typosquatting detection work?**
It uses Damerau-Levenshtein edit distance against popular package names. A swap of two letters counts as one edit,
so `lodahs` matches `lodash`.

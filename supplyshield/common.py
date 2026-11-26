"""Checks shared by the Python and npm analysers."""
from __future__ import annotations

import math
import re
from collections import Counter
from importlib import resources

from .models import Finding

# File paths that malware typically reads to steal credentials.
SENSITIVE_PATHS = (
    ".ssh", "id_rsa", "id_ed25519", ".aws/credentials", ".aws\\credentials",
    ".npmrc", ".pypirc", ".git-credentials", ".docker/config.json", ".kube/config",
    "Login Data", "Local State", "Cookies", "wallet.dat", "/etc/passwd", "/etc/shadow",
    ".bash_history", "keychain",
)

_B64_BLOB = re.compile(r"[A-Za-z0-9+/=]{160,}")
_HEX_BLOB = re.compile(r"(?:\\x[0-9a-fA-F]{2}){40,}")


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


def sensitive_path_hits(text: str) -> list[str]:
    return [p for p in SENSITIVE_PATHS if p in text]


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

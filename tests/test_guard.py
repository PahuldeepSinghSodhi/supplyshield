"""Tests for the pre-install guard (AI-agent hook / shell gate). No network is used."""
import io
import json
from pathlib import Path

import pytest

from supplyshield import guard

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    monkeypatch.setenv("SUPPLYSHIELD_GUARD_VULNS", "0")
    monkeypatch.setattr(guard, "_fetch", lambda eco, spec, dest: pytest.fail("network fetch attempted"))


@pytest.mark.parametrize("command,expected", [
    ("pip install requests==2.31.0", [("pypi", "requests==2.31.0")]),
    ("python -m pip install -U flask rich", [("pypi", "flask"), ("pypi", "rich")]),
    ("uv pip install -i https://x.invalid/simple numpy", [("pypi", "numpy")]),
    ("cd app && npm install lodash --save", [("npm", "lodash")]),
    ("yarn add react; ls", [("npm", "react")]),
    ("ls -la && git status", []),
    ("pip list", []),
])
def test_parse_installs(command, expected):
    assert guard.parse_installs(command) == expected


def test_blocks_malicious_package_in_agent_hook(monkeypatch, capsys):
    hook_input = {"tool_name": "Bash", "tool_input": {"command": f"pip install {SAMPLES / 'pypi/mal-setup-exfil'}"}}
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(hook_input)))
    assert guard.main([]) == 2                       # exit 2 = command blocked
    err = capsys.readouterr().err
    assert "blocked" in err and "MALICIOUS" in err


def test_hook_input_with_byte_order_mark_is_still_checked(monkeypatch):
    hook_input = {"tool_input": {"command": f"pip install {SAMPLES / 'pypi/mal-setup-exfil'}"}}
    monkeypatch.setattr("sys.stdin", io.StringIO("﻿" + json.dumps(hook_input)))
    assert guard.main([]) == 2


def test_allows_safe_package(capsys):
    assert guard.main(["--", "pip", "install", str(SAMPLES / "pypi/clean-tidytext")]) == 0


def test_blocks_typosquat_npm(capsys):
    assert guard.main(["--", "npm", "install", str(SAMPLES / "npm/mal-typosquat-lodahs")]) == 2


def test_ignores_non_install_commands(monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"tool_input": {"command": "pytest -q"}})))
    assert guard.main([]) == 0

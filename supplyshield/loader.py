"""Open a package (folder or archive) for static analysis.

SupplyShield never installs, imports or executes package code. Archives are
extracted into a temporary folder with path-traversal and link protection.
"""
from __future__ import annotations

import json
import re
import tarfile
import tempfile
import tomllib
import zipfile
from pathlib import Path

ARCHIVE_SUFFIXES = (".tar.gz", ".tgz", ".tar", ".whl", ".zip")


class LoadError(Exception):
    pass


def _inside(base: Path, target: Path) -> bool:
    try:
        target.resolve().relative_to(base.resolve())
        return True
    except ValueError:
        return False


def _extract(archive: Path, dest: Path) -> None:
    name = archive.name.lower()
    if name.endswith((".whl", ".zip")):
        with zipfile.ZipFile(archive) as zf:
            for member in zf.namelist():
                if not _inside(dest, dest / member):
                    raise LoadError(f"unsafe path in archive: {member}")
            zf.extractall(dest)
    else:
        with tarfile.open(archive) as tf:
            safe = []
            for m in tf.getmembers():
                if m.issym() or m.islnk() or m.isdev():
                    continue  # never follow links or create devices
                if not _inside(dest, dest / m.name):
                    raise LoadError(f"unsafe path in archive: {m.name}")
                safe.append(m)
            tf.extractall(dest, members=safe, filter="data")


def _find_root(base: Path) -> Path:
    """Return the folder that holds package.json / setup.py / pyproject.toml."""
    markers = ("package.json", "setup.py", "pyproject.toml", "setup.cfg", "PKG-INFO")
    candidates = [base] + sorted(p for p in base.rglob("*") if p.is_dir() and "node_modules" not in p.parts)
    for d in candidates:
        if any((d / m).is_file() for m in markers):
            return d
    return base


def detect_ecosystem(root: Path) -> str:
    if (root / "package.json").is_file():
        return "npm"
    return "pypi"


def read_metadata(root: Path, ecosystem: str) -> tuple[str, str, list[str]]:
    """Return (name, version, dependency names)."""
    if ecosystem == "npm":
        try:
            data = json.loads((root / "package.json").read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError):
            return root.name, "?", []
        deps = list((data.get("dependencies") or {}).keys())
        return str(data.get("name", root.name)), str(data.get("version", "?")), deps

    name, version, deps = root.name, "?", []
    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        try:
            proj = tomllib.loads(pyproject.read_text(encoding="utf-8-sig")).get("project", {})
            name = proj.get("name", name)
            version = proj.get("version", version)
            deps = [re.split(r"[<>=!~;\[ ]", d, maxsplit=1)[0] for d in proj.get("dependencies", [])]
        except (OSError, tomllib.TOMLDecodeError):
            pass
    setup_py = root / "setup.py"
    if setup_py.is_file():
        text = setup_py.read_text(encoding="utf-8-sig", errors="replace")
        if m := re.search(r"name\s*=\s*['\"]([^'\"]+)", text):
            name = m.group(1)
        if m := re.search(r"version\s*=\s*['\"]([^'\"]+)", text):
            version = m.group(1)
        if m := re.search(r"install_requires\s*=\s*\[([^\]]*)\]", text):
            deps += [re.split(r"[<>=!~;\[ ]", d.strip(" '\"\n"), maxsplit=1)[0]
                     for d in m.group(1).split(",") if d.strip(" '\"\n")]
    for meta in list(root.glob("PKG-INFO")) + list(root.glob("*.dist-info/METADATA")):
        text = meta.read_text(encoding="utf-8-sig", errors="replace")
        if m := re.search(r"^Name:\s*(.+)$", text, re.M):
            name = m.group(1).strip()
        if m := re.search(r"^Version:\s*(.+)$", text, re.M):
            version = m.group(1).strip()
    return name, version, deps


class OpenedPackage:
    """Context manager giving a folder to analyse, cleaning up temp files after."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._tmp: tempfile.TemporaryDirectory | None = None
        self.root: Path = self.path

    def __enter__(self) -> "OpenedPackage":
        if not self.path.exists():
            raise LoadError(f"not found: {self.path}")
        if self.path.is_dir():
            self.root = _find_root(self.path)
        elif self.path.name.lower().endswith(ARCHIVE_SUFFIXES):
            self._tmp = tempfile.TemporaryDirectory(prefix="supplyshield-")
            dest = Path(self._tmp.name)
            _extract(self.path, dest)
            self.root = _find_root(dest)
        else:
            raise LoadError(f"unsupported file type: {self.path.name}")
        return self

    def __exit__(self, *exc) -> None:
        if self._tmp is not None:
            self._tmp.cleanup()

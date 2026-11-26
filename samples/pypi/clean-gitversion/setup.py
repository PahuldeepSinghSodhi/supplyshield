import subprocess
from setuptools import setup

def version():
    try:
        return subprocess.check_output(["git", "describe", "--tags"], text=True).strip()
    except Exception:
        return "0.0.0"

setup(name="gitversioned-tool", version="2.0.0", packages=["gvtool"])

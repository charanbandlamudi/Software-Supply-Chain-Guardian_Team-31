#!/usr/bin/env python3
"""Seed local npm/Python mirrors with a harmless replacement and a canary malicious fixture."""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path


def run(command: list[str], cwd: Path) -> dict:
    try:
        proc = subprocess.run(command, cwd=cwd, capture_output=True, text=True, timeout=120,
                              stdin=subprocess.DEVNULL)
    except (subprocess.TimeoutExpired, OSError) as exc:
        return {"status": "failed", "reason": f"{type(exc).__name__}: {exc}"}
    return {"status": "ok" if proc.returncode == 0 else "failed",
            "exit_code": proc.returncode, "stdout": proc.stdout[-2000:], "stderr": proc.stderr[-2000:]}


def seed(root: Path) -> dict:
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    npm = root / "npm" / "guardian-canary-legit"
    npm.mkdir(parents=True, exist_ok=True)
    (npm / "package.json").write_text(json.dumps({
        "name": "guardian-canary-legit", "version": "1.0.0",
        "scripts": {"test": "node index.js"}, "main": "index.js",
    }), encoding="utf-8")
    (npm / "index.js").write_text("module.exports = { guardian: 'legit' };\\n", encoding="utf-8")

    malicious = root / "npm" / "guardian-canary-malicious"
    malicious.mkdir(parents=True, exist_ok=True)
    (malicious / "package.json").write_text(json.dumps({
        "name": "guardian-canary-malicious", "version": "1.0.0",
        "scripts": {"postinstall": "node postinstall.js"}, "main": "index.js",
    }), encoding="utf-8")
    (malicious / "index.js").write_text("module.exports = { guardian: 'canary' };\\n", encoding="utf-8")
    (malicious / "postinstall.js").write_text(
        "require('fs').writeFileSync('/tmp/guardian-canary-fired', process.env.GUARDIAN_CANARY || 'canary');\\n",
        encoding="utf-8",
    )

    npm_publish = shutil.which("npm")
    results = {}
    if npm_publish:
        results["legit"] = run([npm_publish, "publish", "--registry", "http://127.0.0.1:4873",
                                "--ignore-scripts"], npm)
        results["malicious"] = run([npm_publish, "publish", "--registry", "http://127.0.0.1:4873",
                                    "--ignore-scripts"], malicious)
    else:
        results["npm"] = {"status": "unavailable", "reason": "npm executable not found"}

    pypi = root / "pypi"
    pypi.mkdir(parents=True, exist_ok=True)
    for name in ("guardian_canary_legit", "guardian_canary_malicious"):
        pkg = pypi / name
        pkg.mkdir(parents=True, exist_ok=True)
        (pkg / "setup.py").write_text(
            "from setuptools import setup\\n"
            f"setup(name='{name}', version='1.0.0', py_modules=['{name}'])\\n",
            encoding="utf-8",
        )
        (pkg / f"{name}.py").write_text("GUARDIAN_CANARY = 'canary'\\n", encoding="utf-8")
    results["python_mirror"] = {"status": "prepared",
                                "path": str(pypi),
                                "note": "build and upload with twine or pypiserver credentials"}
    return results


if __name__ == "__main__":
    print(json.dumps(seed(Path(__file__).resolve().parent.parent / "data" / "mirror-fixtures"), indent=2))

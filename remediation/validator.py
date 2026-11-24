from __future__ import annotations

import json
import subprocess
from pathlib import Path


def run_command(command: list[str], cwd: Path, timeout: int = 900) -> dict:
    result = subprocess.run(
        command,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return {
        "command": command,
        "returncode": result.returncode,
        "stdout": result.stdout[-5000:],
        "stderr": result.stderr[-5000:],
    }


def validate_npm_update(repository: str | Path, run_tests: bool = True) -> dict:
    repo = Path(repository).resolve()
    if not (repo / "package.json").exists():
        raise RuntimeError("package.json not found")

    ls = run_command(["npm", "ls", "--all", "--json"], repo)
    test = None
    if run_tests:
        package = json.loads((repo / "package.json").read_text(encoding="utf-8"))
        scripts = package.get("scripts") or {}
        if "test" in scripts:
            test = run_command(["npm", "test", "--", "--runInBand"], repo)
        else:
            test = {"status": "skipped", "reason": "package.json has no test script"}

    return {
        "dependency_tree": ls,
        "test": test,
        "status": "passed" if ls["returncode"] == 0
                  and (test is None or test.get("returncode") in (None, 0))
                  else "failed",
    }

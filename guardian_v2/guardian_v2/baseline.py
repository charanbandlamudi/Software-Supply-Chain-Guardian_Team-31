"""Run application test baselines and compare remediation outcomes."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path


def run_command(command: list[str], cwd: Path, timeout: int = 600) -> dict:
    try:
        proc = subprocess.run(command, cwd=cwd, capture_output=True, text=True,
                              timeout=timeout, stdin=subprocess.DEVNULL)
    except (subprocess.TimeoutExpired, OSError) as exc:
        return {"status": "failed", "exit_code": None,
                "reason": f"{type(exc).__name__}: {exc}"}
    return {"status": "passed" if proc.returncode == 0 else "failed",
            "exit_code": proc.returncode,
            "stdout": proc.stdout[-8000:], "stderr": proc.stderr[-8000:]}


def compare(before: dict, after: dict) -> dict:
    introduced = after.get("status") == "failed" and before.get("status") == "passed"
    resolved = before.get("status") == "failed" and after.get("status") == "passed"
    return {"introduced_regression": introduced, "resolved_preexisting": resolved,
            "before": before, "after": after}

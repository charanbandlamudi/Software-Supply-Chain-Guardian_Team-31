"""Opt-in dynamic package detonation with gVisor/runsc and network-disabled containers."""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path


def runtime_status() -> dict:
    docker = shutil.which("docker")
    podman = shutil.which("podman")
    runsc = shutil.which("runsc")
    runtime = "docker" if docker else ("podman" if podman else None)
    return {"runtime": runtime, "runsc": bool(runsc),
            "available": bool(runtime and runsc)}


def detonate(work: Path, image: str, command: list[str], canary: str = "GUARDIAN-CANARY") -> dict:
    work = Path(work).resolve()
    status = runtime_status()
    if not status["available"]:
        return {"status": "unavailable", "runtime": status,
                "reason": "gVisor/runsc is not installed or is not registered with Docker/Podman"}

    cli = status["runtime"]
    args = [cli, "run", "--rm", "--runtime=runsc", "--network=none",
            "--read-only", "--tmpfs", "/tmp:rw,nosuid,size=256m",
            "--pids-limit=128", "--memory=512m", "--cpus=1",
            "--cap-drop=ALL", "--security-opt=no-new-privileges",
            "--mount", f"type=bind,src={work},dst=/work,rw",
            "--workdir", "/work", "--env", f"GUARDIAN_CANARY={canary}",
            image, *command]
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=600,
                              stdin=subprocess.DEVNULL)
        stdout, stderr = proc.stdout, proc.stderr
    except (subprocess.TimeoutExpired, OSError) as exc:
        return {"status": "failed", "reason": f"{type(exc).__name__}: {exc}",
                "runtime": status}
    raw = (stdout + "\n" + stderr).encode("utf-8")
    evidence = {
        "status": "completed" if proc.returncode == 0 else "failed",
        "exit_code": proc.returncode,
        "network": "none",
        "runtime": "runsc",
        "canary": canary,
        "canary_observed": canary in (stdout + stderr),
        "stdout_sha256": hashlib.sha256(stdout.encode()).hexdigest(),
        "stderr_sha256": hashlib.sha256(stderr.encode()).hexdigest(),
        "stdout": stdout[-4000:], "stderr": stderr[-4000:],
    }
    evidence["evidence_sha256"] = hashlib.sha256(
        json.dumps(evidence, sort_keys=True).encode()
    ).hexdigest()
    return evidence


def compare_baseline(baseline: dict, upgraded: dict) -> dict:
    keys = ("exit_code", "stdout_sha256", "stderr_sha256", "canary_observed")
    changed = {key: {"baseline": baseline.get(key), "upgraded": upgraded.get(key)}
               for key in keys if baseline.get(key) != upgraded.get(key)}
    return {"changed": bool(changed), "differences": changed,
            "status": "detected_change" if changed else "same_observed_behavior"}

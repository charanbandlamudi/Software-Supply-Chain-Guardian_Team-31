"""Container and package provenance checks for cosign, npm provenance, PEP 740 and Syft."""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path


def command_status(command: str) -> dict:
    executable = shutil.which(command)
    return {"available": bool(executable), "path": executable}


def npm_provenance(packument: dict) -> dict:
    provenance = packument.get("dist", {}).get("provenance")
    if not provenance:
        return {"status": "missing", "verified": False}
    return {"status": "present", "verified": bool(provenance.get("predicateType")),
            "source": provenance}


def pep740(attestation: dict | None) -> dict:
    if not attestation:
        return {"status": "missing", "verified": False}
    return {"status": "present", "verified": bool(attestation.get("predicateType")),
            "attestation": attestation}


def scan_image_syft(image: str) -> dict:
    syft = shutil.which("syft")
    if not syft:
        return {"status": "unavailable", "reason": "syft executable not found"}
    try:
        proc = subprocess.run([syft, image, "-o", "cyclonedx-json"],
                              capture_output=True, text=True, timeout=600,
                              stdin=subprocess.DEVNULL)
    except (subprocess.TimeoutExpired, OSError) as exc:
        return {"status": "failed", "reason": f"{type(exc).__name__}: {exc}"}
    if proc.returncode != 0:
        return {"status": "failed", "reason": proc.stderr[-2000:], "exit_code": proc.returncode}
    try:
        bom = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        return {"status": "failed", "reason": f"invalid Syft JSON: {exc}"}
    return {"status": "ok", "components": len(bom.get("components", []))}


def cosign_signature(image: str) -> dict:
    cosign = shutil.which("cosign")
    if not cosign:
        return {"status": "unavailable", "reason": "cosign executable not found"}
    try:
        proc = subprocess.run([cosign, "verify", "--insecure-ignore-tlog", image],
                              capture_output=True, text=True, timeout=120,
                              stdin=subprocess.DEVNULL)
    except (subprocess.TimeoutExpired, OSError) as exc:
        return {"status": "failed", "reason": f"{type(exc).__name__}: {exc}"}
    return {"status": "verified" if proc.returncode == 0 else "unverified",
            "exit_code": proc.returncode, "output": proc.stdout[-4000:], "stderr": proc.stderr[-2000:]}

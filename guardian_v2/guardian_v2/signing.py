"""In-toto statement generation and optional local cosign signing."""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path


def sha256_file(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def make_in_toto_statement(subjects: list[dict], predicate: dict) -> dict:
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": subjects,
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": predicate,
    }


def sign_statement(statement_path: Path, output_path: Path | None = None) -> dict:
    statement_path = Path(statement_path)
    output_path = output_path or statement_path.with_suffix(".cosign.sig")
    cosign = shutil.which("cosign")
    private_key = __import__("os").getenv("COSIGN_PRIVATE_KEY")
    if not cosign:
        return {"status": "unavailable", "reason": "cosign executable not found"}
    if not private_key:
        return {"status": "unavailable", "reason": "COSIGN_PRIVATE_KEY or key file not configured",
                "statement_sha256": sha256_file(statement_path)}
    key_arg = private_key if private_key.endswith(".key") and Path(private_key).exists() else "-"
    args = [cosign, "sign-blob", "--key", key_arg, "--tlog-upload=false",
            "--output-signature", str(output_path), str(statement_path)]
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=120,
                              input=private_key if key_arg == "-" else None,
                              stdin=subprocess.DEVNULL if key_arg != "-" else None)
    except (subprocess.TimeoutExpired, OSError) as exc:
        return {"status": "failed", "reason": f"{type(exc).__name__}: {exc}"}
    if proc.returncode != 0:
        return {"status": "failed", "reason": proc.stderr[-1000:], "exit_code": proc.returncode}
    fingerprint = hashlib.sha256(
        private_key.encode("utf-8") if key_arg == "-" else Path(key_arg).read_bytes()
    ).hexdigest()
    return {"status": "signed", "signature": str(output_path),
            "key_fingerprint_sha256": fingerprint,
            "statement_sha256": sha256_file(statement_path),
            "rekor_upload": False}

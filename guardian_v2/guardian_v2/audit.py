"""Append-only, hash-chained audit trail for Guardian actions."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def append_entry(entries: list[dict], actor: str, action: str, tool: str,
                 args_redacted: dict, policy_decision: dict,
                 result_ref: str | None = None) -> dict:
    previous = entries[-1]["hash"] if entries else "0" * 64
    entry = {
        "seq": len(entries) + 1,
        "ts": datetime.now(timezone.utc).isoformat(),
        "actor": actor,
        "action": action,
        "tool": tool,
        "args_redacted": args_redacted,
        "policy_decision": policy_decision,
        "result_ref": result_ref,
        "prev_hash": previous,
    }
    entry["hash"] = hashlib.sha256(previous.encode("ascii") + canonical(entry)).hexdigest()
    entries.append(entry)
    return entry


def verify_chain(entries: Iterable[dict]) -> tuple[bool, str | None]:
    previous = "0" * 64
    for expected_seq, entry in enumerate(entries, 1):
        if entry.get("seq") != expected_seq:
            return False, f"sequence mismatch at {expected_seq}"
        if entry.get("prev_hash") != previous:
            return False, f"broken previous hash at sequence {expected_seq}"
        recorded = entry.get("hash")
        body = dict(entry)
        body.pop("hash", None)
        actual = hashlib.sha256(previous.encode("ascii") + canonical(body)).hexdigest()
        if recorded != actual:
            return False, f"hash mismatch at sequence {expected_seq}"
        previous = recorded
    return True, None


def write_audit(path: Path, entries: Iterable[dict]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(e, sort_keys=True) + "\n" for e in entries), encoding="utf-8")
    data = path.read_bytes()
    return hashlib.sha256(data).hexdigest()

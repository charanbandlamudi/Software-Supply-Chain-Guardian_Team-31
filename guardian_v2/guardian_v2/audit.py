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
                 result_ref: str | None = None, tool_version: str | None = None,
                 args_hash: str | None = None) -> dict:
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
    if tool_version:
        entry["tool_version"] = tool_version
    if args_hash:
        entry["args_hash"] = args_hash
    else:
        entry["args_hash"] = hashlib.sha256(canonical(args_redacted)).hexdigest()
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


class EvidenceCAS:
    """Content-addressed evidence blob store, separated from audit metadata."""

    def __init__(self, root: Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def put(self, data: bytes | str, suffix: str = ".blob") -> dict:
        raw = data.encode("utf-8") if isinstance(data, str) else data
        digest = hashlib.sha256(raw).hexdigest()
        path = self.root / digest[:2] / f"{digest}{suffix}"
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.write_bytes(raw)
        return {"sha256": digest, "size": len(raw), "path": str(path)}

    def get(self, digest: str) -> bytes:
        matches = list(self.root.glob(f"{digest[:2]}/*"))
        for path in matches:
            if path.stem == digest:
                return path.read_bytes()
        raise KeyError(digest)

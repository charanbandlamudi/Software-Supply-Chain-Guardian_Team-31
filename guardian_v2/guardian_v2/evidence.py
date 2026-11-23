"""Hashed, append-only evidence records (same shape as the v1 evidence store)."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone


def make_evidence(kind: str, source: str, uri: str, payload) -> tuple[str, dict]:
    raw = payload if isinstance(payload, str) else json.dumps(payload, sort_keys=True, default=str)
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    eid = f"EV-{source}-{digest[:16]}"
    return eid, {
        "id": eid, "kind": kind, "source": source, "uri": uri,
        "retrieved_at": datetime.now(timezone.utc).isoformat(),
        "sha256": digest, "payload": raw,
    }

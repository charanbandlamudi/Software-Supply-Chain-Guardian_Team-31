import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


class EvidenceStore:
    def __init__(self, db_path: str | Path = ":memory:"):
        self.db_path = str(db_path)
        self.connection = sqlite3.connect(self.db_path)
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS evidence (
                id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                source TEXT NOT NULL,
                uri TEXT NOT NULL,
                retrieved_at TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                payload TEXT NOT NULL
            )
            """
        )
        self.connection.commit()

    def add(self, *, kind: str, source: str, uri: str, payload: object) -> dict:
        encoded = json.dumps(payload, sort_keys=True, default=str).encode()
        digest = hashlib.sha256(encoded).hexdigest()
        evidence_id = f"EV-{digest[:16]}"
        retrieved_at = datetime.now(timezone.utc).isoformat()
        self.connection.execute(
            "INSERT OR IGNORE INTO evidence VALUES (?, ?, ?, ?, ?, ?, ?)",
            (evidence_id, kind, source, uri, retrieved_at, digest, encoded.decode()),
        )
        self.connection.commit()
        return {
            "id": evidence_id,
            "kind": kind,
            "source": source,
            "uri": uri,
            "sha256": digest,
            "retrieved_at": retrieved_at,
        }

    def get(self, evidence_id: str) -> dict | None:
        row = self.connection.execute(
            "SELECT id, kind, source, uri, retrieved_at, sha256, payload "
            "FROM evidence WHERE id = ?",
            (evidence_id,),
        ).fetchone()
        if row is None:
            return None
        return dict(zip(("id", "kind", "source", "uri", "retrieved_at", "sha256", "payload"), row))

    def close(self) -> None:
        self.connection.close()

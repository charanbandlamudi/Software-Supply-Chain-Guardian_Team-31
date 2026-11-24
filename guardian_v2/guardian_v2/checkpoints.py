"""SQLite-backed, hash-chained agent snapshots and approval interrupt records."""
from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Iterable


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


class SQLiteCheckpointStore:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(self.path)
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS checkpoints ("
            "run_id TEXT PRIMARY KEY, seq INTEGER NOT NULL, state_json TEXT NOT NULL, "
            "prev_hash TEXT NOT NULL, hash TEXT NOT NULL, interrupted INTEGER NOT NULL)"
        )
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS interrupts ("
            "run_id TEXT NOT NULL, seq INTEGER NOT NULL, payload_json TEXT NOT NULL, "
            "hash TEXT NOT NULL, PRIMARY KEY (run_id, seq))"
        )
        self._db.commit()

    def close(self) -> None:
        self._db.close()

    def save(self, run_id: str, state: dict, interrupted: bool = False) -> dict:
        row = self._db.execute(
            "SELECT seq, hash FROM checkpoints WHERE run_id=?", (run_id,)
        ).fetchone()
        seq = (row[0] + 1) if row else 1
        previous = row[1] if row else "0" * 64
        body = {"run_id": run_id, "seq": seq, "state": state, "prev_hash": previous,
                "interrupted": interrupted}
        digest = hashlib.sha256(previous.encode("ascii") + _canonical(body)).hexdigest()
        self._db.execute(
            "INSERT INTO checkpoints(run_id,seq,state_json,prev_hash,hash,interrupted) "
            "VALUES(?,?,?,?,?,?) "
            "ON CONFLICT(run_id) DO UPDATE SET seq=excluded.seq,state_json=excluded.state_json,"
            "prev_hash=excluded.prev_hash,hash=excluded.hash,interrupted=excluded.interrupted",
            (run_id, seq, json.dumps(state, sort_keys=True, default=str), previous, digest, int(interrupted)),
        )
        self._db.commit()
        return {"run_id": run_id, "seq": seq, "prev_hash": previous, "hash": digest}

    def load(self, run_id: str) -> dict | None:
        row = self._db.execute(
            "SELECT state_json, interrupted FROM checkpoints WHERE run_id=?", (run_id,)
        ).fetchone()
        if not row:
            return None
        return {"state": json.loads(row[0]), "interrupted": bool(row[1])}

    def save_interrupt(self, run_id: str, payload: dict) -> dict:
        seq_row = self._db.execute(
            "SELECT COALESCE(MAX(seq),0) FROM interrupts WHERE run_id=?", (run_id,)
        ).fetchone()
        seq = seq_row[0] + 1
        body = {"run_id": run_id, "seq": seq, "payload": payload}
        digest = hashlib.sha256(_canonical(body)).hexdigest()
        self._db.execute(
            "INSERT INTO interrupts(run_id,seq,payload_json,hash) VALUES(?,?,?,?)",
            (run_id, seq, json.dumps(payload, sort_keys=True, default=str), digest),
        )
        self.save(run_id, payload, interrupted=True)
        self._db.commit()
        return {"seq": seq, "hash": digest}

    def interrupts(self, run_id: str) -> list[dict]:
        rows = self._db.execute(
            "SELECT seq,payload_json,hash FROM interrupts WHERE run_id=? ORDER BY seq",
            (run_id,),
        ).fetchall()
        return [{"seq": seq, "payload": json.loads(payload), "hash": digest}
                for seq, payload, digest in rows]

    def verify(self, run_id: str) -> tuple[bool, str | None]:
        row = self._db.execute(
            "SELECT seq,state_json,prev_hash,hash,interrupted FROM checkpoints WHERE run_id=?", (run_id,)
        ).fetchone()
        if not row:
            return True, None
        seq, state_json, previous, digest, interrupted = row
        body = {"run_id": run_id, "seq": seq, "state": json.loads(state_json),
                "prev_hash": previous, "interrupted": bool(interrupted)}
        actual = hashlib.sha256(previous.encode("ascii") + _canonical(body)).hexdigest()
        if actual != digest:
            return False, "checkpoint hash mismatch"
        return True, None

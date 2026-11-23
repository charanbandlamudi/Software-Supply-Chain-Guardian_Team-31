"""Small cached HTTP client. Raw responses become hashed evidence records."""
from __future__ import annotations

import hashlib
import json
import threading
import urllib.error
import urllib.request
from pathlib import Path

from ..evidence import make_evidence

CACHE_DIR = Path(".guardian_cache")
_LOCK = threading.Lock()
USER_AGENT = "supply-chain-guardian/2.0 (hackathon; read-only)"


class HttpError(RuntimeError):
    def __init__(self, url: str, status: int | None, detail: str):
        super().__init__(f"{status or 'network'} for {url}: {detail[:160]}")
        self.status = status


def _key(method: str, url: str, body: bytes | None) -> Path:
    h = hashlib.sha256(f"{method} {url}".encode() + (body or b"")).hexdigest()[:24]
    return CACHE_DIR / f"{h}.json"


def fetch_json(url: str, source: str, *, method: str = "GET", body=None, headers=None,
               timeout: int = 20, use_cache: bool = True):
    """Returns (data, evidence_id, evidence_record). 404 -> (None, eid, ev)."""
    raw_body = json.dumps(body).encode() if body is not None else None
    path = _key(method, url, raw_body)
    if use_cache and path.exists():
        cached = json.loads(path.read_text())
        status, text = cached["status"], cached["text"]
    else:
        req = urllib.request.Request(url, data=raw_body, method=method, headers={
            "User-Agent": USER_AGENT, "Accept": "application/json",
            **({"Content-Type": "application/json"} if raw_body else {}), **(headers or {})})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                status, text = resp.status, resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            status, text = e.code, e.read().decode("utf-8", "replace")
            if status not in (404,):
                raise HttpError(url, status, text) from None
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            raise HttpError(url, None, str(e)) from None
        if use_cache:
            with _LOCK:
                CACHE_DIR.mkdir(exist_ok=True)
                path.write_text(json.dumps({"status": status, "text": text}))
    eid, ev = make_evidence("api_response", source, url, text)
    return (json.loads(text) if status == 200 else None), eid, ev

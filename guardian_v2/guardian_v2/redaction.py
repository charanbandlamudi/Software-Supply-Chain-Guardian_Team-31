"""Secret redaction for prompts, tool output and evidence pointers."""
from __future__ import annotations

import hashlib
import re


PATTERNS = (
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}", re.I),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}", re.I),
    re.compile(r"AKIA[0-9A-Z]{16}", re.I),
    re.compile(r"(?i)(npm_[A-Za-z0-9]{36,})"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
)


def pointer(value: str) -> dict:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return {"sha256": digest, "redacted": True}


def redact(text: str) -> str:
    result = text
    for pattern in PATTERNS:
        result = pattern.sub("[REDACTED]", result)
    return result

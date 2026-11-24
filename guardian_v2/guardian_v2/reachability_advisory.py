"""Per-advisory reachability evidence for symbol and reflection-aware source checks."""
from __future__ import annotations

import ast
import re
from pathlib import Path


UNKNOWN_PATTERNS = (
    re.compile(r"\beval\s*\(", re.I),
    re.compile(r"\bexec\s*\(", re.I),
    re.compile(r"\bReflection\b", re.I),
    re.compile(r"\bdynamic\s+import\b", re.I),
)


def advisory_state(source_dirs: list[str], symbols: list[str]) -> dict:
    locations = []
    unknown = []
    for source in source_dirs:
        root = Path(source)
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if not path.is_file() or "node_modules" in path.parts:
                continue
            if path.suffix not in {".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"}:
                continue
            try:
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            for line_no, line in enumerate(lines, 1):
                if any(re.search(re.escape(symbol), line) for symbol in symbols if symbol):
                    locations.append(f"{path}:{line_no}")
                if any(pattern.search(line) for pattern in UNKNOWN_PATTERNS):
                    unknown.append(f"{path}:{line_no}")
    if unknown:
        return {"state": "unknown", "reason": "dynamic reflection/eval detected", "locations": locations[:20],
                "unknown_locations": unknown[:20]}
    if locations:
        return {"state": "reachable", "locations": locations[:20], "unknown_locations": []}
    return {"state": "not_reachable", "locations": [], "unknown_locations": []}

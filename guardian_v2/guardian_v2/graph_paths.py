"""Dependency paths from the application root to each component."""
from __future__ import annotations

from collections import defaultdict, deque

ROOT = "app"


def all_paths(components: dict, edges: list, target: str, max_paths: int = 10,
              max_depth: int = 15) -> list[list[str]]:
    """Bounded BFS of root -> ... -> target paths. Direct components hang off ROOT."""
    children: dict[str, list[str]] = defaultdict(list)
    for purl, comp in components.items():
        if comp.get("direct"):
            children[ROOT].append(purl)
    for e in edges:
        children[e["from"]].append(e["to"])

    paths, queue = [], deque([[ROOT]])
    while queue and len(paths) < max_paths:
        path = queue.popleft()
        node = path[-1]
        if node == target and len(path) > 1:
            paths.append(path)
            continue
        if len(path) > max_depth:
            continue
        for nxt in children.get(node, []):
            if nxt not in path:  # cycle guard
                queue.append(path + [nxt])
    return paths


def introducing_direct(paths: list[list[str]]) -> list[str]:
    """Which direct dependencies pull the component in (what a developer changes)."""
    return sorted({p[1] for p in paths if len(p) > 1})

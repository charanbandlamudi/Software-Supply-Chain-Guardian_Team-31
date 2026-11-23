"""Wrap v1 node functions (which take/return the full GuardianState dataclass)
so they return ONLY deltas. Required once branches run in parallel: returning
the full state would make the reducers merge everything twice."""
from __future__ import annotations

import copy
from typing import Callable


def delta(before: dict, after: dict) -> dict:
    out = {}
    for key, new in after.items():
        old = before.get(key)
        if new == old:
            continue
        if isinstance(new, dict) and isinstance(old, dict):
            changed = {k: v for k, v in new.items() if old.get(k) != v}
            if changed:
                out[key] = changed
        elif isinstance(new, list) and isinstance(old, list):
            added = new[len(old):] if new[:len(old)] == old else [x for x in new if x not in old]
            if added:
                out[key] = added
        else:
            out[key] = new
    return out


def adapt(fn: Callable, to_v1: Callable | None = None, from_v1: Callable | None = None) -> Callable:
    """to_v1: dict -> your dataclass (e.g. GuardianState(**d)); from_v1: dataclass -> dict
    (e.g. dataclasses.asdict). Defaults pass dicts straight through."""
    def node(state: dict) -> dict:
        before = copy.deepcopy(dict(state))
        arg = to_v1(copy.deepcopy(dict(state))) if to_v1 else copy.deepcopy(dict(state))
        result = fn(arg)
        after = from_v1(result) if from_v1 else dict(result or {})
        return delta(before, after)
    node.__name__ = getattr(fn, "__name__", "adapted")
    return node

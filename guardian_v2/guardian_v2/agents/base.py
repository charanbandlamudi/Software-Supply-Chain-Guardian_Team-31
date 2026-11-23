"""Agent contract.

An agent owns one responsibility, declares which agents it depends on, and
returns (delta, message). The message is what it tells the supervisor: a
summary, plus optional handoff requests to other agents. Agents never call
each other directly; every handoff goes through the supervisor, which keeps
one auditable decision log.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable


@dataclass
class AgentResult:
    delta: dict = field(default_factory=dict)
    summary: str = ""
    requests: list[dict] = field(default_factory=list)   # [{"to", "task", "reason"}]
    metrics: dict = field(default_factory=dict)


@dataclass
class Agent:
    name: str
    role: str                                  # one line, shown to the LLM planner
    requires: list[str]                        # agents whose output this one consumes
    run: Callable[[dict, dict], AgentResult]   # (state, task) -> AgentResult
    exclusive: bool = False                    # must run alone (human gate)
    condition: Callable[[dict], bool] | None = None  # extra readiness check
    uses_llm: bool = False


def handoff(to: str, reason: str, **task) -> dict:
    return {"to": to, "reason": reason, "task": task}

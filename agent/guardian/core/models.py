from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Evidence:
    id: str
    kind: str
    source: str
    uri: str
    sha256: str
    retrieved_at: str
    excerpt: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Component:
    purl: str
    name: str
    version: str
    ecosystem: str
    scope: str = "runtime"
    direct: bool = False
    hashes: list[str] = field(default_factory=list)
    licenses: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Edge:
    from_purl: str
    to_purl: str
    constraint: str = ""
    scope: str = "runtime"
    source: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    id: str
    type: str
    component_purl: str
    score: float = 0.0
    score_breakdown: dict[str, Any] = field(default_factory=dict)
    confidence: str = "Low"
    verified_evidence: list[str] = field(default_factory=list)
    ai_inferences: list[dict[str, Any]] = field(default_factory=list)
    recommendation: dict[str, Any] = field(default_factory=dict)
    status: str = "open"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class GuardianState:
    run_id: str
    inputs: list[str] = field(default_factory=list)
    components: dict[str, Component] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)
    findings: dict[str, Finding] = field(default_factory=dict)
    evidence: dict[str, Evidence] = field(default_factory=dict)
    coverage: dict[str, str] = field(default_factory=dict)
    remediation_plans: list[dict[str, Any]] = field(default_factory=list)
    approvals: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "inputs": self.inputs,
            "components": {key: value.to_dict() for key, value in self.components.items()},
            "edges": [edge.to_dict() for edge in self.edges],
            "findings": {key: value.to_dict() for key, value in self.findings.items()},
            "evidence": {
                key: (value.to_dict() if hasattr(value, "to_dict") else value)
                for key, value in self.evidence.items()
            },
            "coverage": self.coverage,
            "remediation_plans": self.remediation_plans,
            "approvals": self.approvals,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "GuardianState":
        components = {
            key: Component(**value)
            for key, value in payload.get("components", {}).items()
        }
        edges = [Edge(**value) for value in payload.get("edges", [])]
        findings = {
            key: Finding(**value)
            for key, value in payload.get("findings", {}).items()
        }
        evidence = dict(payload.get("evidence", {}))
        return cls(
            run_id=payload["run_id"],
            inputs=list(payload.get("inputs", [])),
            components=components,
            edges=edges,
            findings=findings,
            evidence=evidence,
            coverage=dict(payload.get("coverage", {})),
            remediation_plans=list(payload.get("remediation_plans", [])),
            approvals=list(payload.get("approvals", [])),
        )

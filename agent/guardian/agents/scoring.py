from guardian.agents.base import BaseAgent
from guardian.core.models import GuardianState


class RiskScoringAgent(BaseAgent):
    name = "risk_scoring"

    @staticmethod
    def _reachability_multiplier(finding, state: GuardianState) -> float:
        for candidate in state.findings.values():
            if candidate.type == "reachability" and candidate.component_purl == finding.component_purl:
                return 1.0
        return finding.score_breakdown.get("reachability", 0.0)

    @staticmethod
    def _scope_multiplier(finding: object, state: GuardianState) -> float:
        component = state.components.get(finding.component_purl)
        if component is None:
            return 1.0
        if component.scope in ("dev", "test", "build"):
            return 0.4
        return 1.0

    def run(self, state: GuardianState) -> GuardianState:
        for finding in state.findings.values():
            if finding.type in ("reachability", "ci", "image"):
                base = 5.0 if finding.type != "reachability" else 3.0
            else:
                base = float(finding.score_breakdown.get("cvss", 0.0))
            reachability = self._reachability_multiplier(finding, state)
            scope = self._scope_multiplier(finding, state)
            exposure = 1.0
            finding.score = round((base + reachability) * scope * exposure, 2)
            finding.score_breakdown = {
                "base": base,
                "reachability": reachability,
                "scope": scope,
                "exposure": exposure,
            }
        return state

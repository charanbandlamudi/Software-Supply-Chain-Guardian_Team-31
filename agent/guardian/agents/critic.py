from guardian.agents.base import BaseAgent
from guardian.core.models import GuardianState


class EvidenceCriticAgent(BaseAgent):
    name = "evidence_critic"

    def run(self, state: GuardianState) -> GuardianState:
        for finding in state.findings.values():
            missing = [evidence_id for evidence_id in finding.verified_evidence
                       if evidence_id not in state.evidence]
            if missing:
                finding.confidence = "Low"
                finding.status = "rejected_missing_evidence"
            elif finding.verified_evidence:
                finding.confidence = "High"
        state.coverage["evidence_critic"] = "complete"
        return state

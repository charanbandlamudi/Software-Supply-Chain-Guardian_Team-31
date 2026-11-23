from guardian.agents.base import BaseAgent
from guardian.core.models import GuardianState


class RemediationAgent(BaseAgent):
    name = "remediation"

    def run(self, state: GuardianState) -> GuardianState:
        for finding in state.findings.values():
            if finding.status == "open":
                state.remediation_plans.append({
                    "finding_id": finding.id,
                    "action": "request_review",
                    "code_changes": False,
                    "merge": False,
                    "human_approval_required": True,
                })
        state.coverage["remediation"] = "gated"
        return state

from guardian.agents.base import BaseAgent
from guardian.core.models import Edge, GuardianState


class DependencyGraphBuilder(BaseAgent):
    name = "dependency_graph"

    def run(self, state: GuardianState) -> GuardianState:
        direct = [component for component in state.components.values() if component.direct]
        for component in direct:
            state.edges.append(
                Edge(
                    from_purl="application",
                    to_purl=component.purl,
                    scope=component.scope,
                    source="input_manifest",
                )
            )
        state.coverage["dependency_graph"] = "complete" if state.components else "no_components"
        return state

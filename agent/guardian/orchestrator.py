from uuid import uuid4

from guardian.agents.ingestion import IngestionAgent
from guardian.agents.graph_builder import DependencyGraphBuilder
from guardian.agents.vuln_intel import VulnerabilityIntelligenceAgent
from guardian.agents.reputation import PackageReputationAgent
from guardian.agents.anomaly import SupplyChainAnomalyAgent
from guardian.agents.cicd_container import ContainerCICDAgent
from guardian.agents.reachability import ReachabilityAgent
from guardian.agents.scoring import RiskScoringAgent
from guardian.agents.remediation import RemediationAgent
from guardian.agents.critic import EvidenceCriticAgent
from guardian.agents.report import ReportAgent
from guardian.agents.inference import GroqInferenceAgent
from guardian.core.models import GuardianState
from langgraph.graph import END, StateGraph
import threading


class Supervisor:
    """LangGraph supervisor pipeline with human-gated remediation."""

    def __init__(self) -> None:
        self.agents = [
            IngestionAgent(),
            DependencyGraphBuilder(),
            VulnerabilityIntelligenceAgent(),
            PackageReputationAgent(),
            SupplyChainAnomalyAgent(),
            ContainerCICDAgent(),
            ReachabilityAgent(),
            RiskScoringAgent(),
            RemediationAgent(),
            EvidenceCriticAgent(),
            GroqInferenceAgent(),
            ReportAgent(),
        ]
        self.graph = self._build_graph()
        self._checkpoint_lock = threading.Lock()

    def _build_graph(self):
        builder = StateGraph(dict)
        for agent in self.agents:
            name = agent.name

            def run_agent(state_payload: dict, selected_agent=agent) -> dict:
                state = GuardianState.from_dict(state_payload)
                result = selected_agent.run(state)
                return result.to_dict()

            builder.add_node(name, run_agent)
        builder.set_entry_point("ingestion")
        for current, following in zip(self.agents, self.agents[1:]):
            builder.add_edge(current.name, following.name)
        builder.add_edge(self.agents[-1].name, END)
        return builder.compile()

    def run(self, inputs: list[str], run_id: str | None = None) -> GuardianState:
        state = GuardianState(run_id=run_id or str(uuid4()), inputs=list(inputs))
        with self._checkpoint_lock:
            payload = self.graph.invoke(state.to_dict())
        return GuardianState.from_dict(payload)

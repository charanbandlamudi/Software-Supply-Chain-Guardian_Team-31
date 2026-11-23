from guardian.agents.base import BaseAgent
from guardian.core.models import Finding, GuardianState
from pathlib import Path
import re


class ContainerCICDAgent(BaseAgent):
    name = "container_cicd"

    def run(self, state: GuardianState) -> GuardianState:
        found = False
        for raw_path in state.inputs:
            path = Path(raw_path)
            if not path.is_file():
                continue
            text = path.read_text(errors="replace")
            if path.name.lower() == "dockerfile" or text.startswith("FROM "):
                found = True
                for line in text.splitlines():
                    if line.strip().upper().startswith("FROM ") and "@sha256:" not in line:
                        image = line.strip().split(maxsplit=1)[1].split()[0]
                        finding_id = f"CONTAINER-{image}-unpinned"
                        state.findings[finding_id] = Finding(
                            id=finding_id,
                            type="image",
                            component_purl=f"container:{image}",
                            confidence="High",
                        )
            if ".github/workflows" in str(path) or path.suffix in (".yml", ".yaml"):
                found = True
                if re.search(r"uses:\s*[^\n]+@v\d", text):
                    state.findings[f"CICD-{path.name}-unpinned-action"] = Finding(
                        id=f"CICD-{path.name}-unpinned-action",
                        type="ci",
                        component_purl=f"workflow:{path.name}",
                        confidence="High",
                    )
                if "pull_request_target" in text and "write-all" in text:
                    state.findings[f"CICD-{path.name}-dangerous-workflow"] = Finding(
                        id=f"CICD-{path.name}-dangerous-workflow",
                        type="ci",
                        component_purl=f"workflow:{path.name}",
                        confidence="High",
                    )
        state.coverage["container_cicd"] = "complete" if found else "no_container_ci_inputs"
        return state

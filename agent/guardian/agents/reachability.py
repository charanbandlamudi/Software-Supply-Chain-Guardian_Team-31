from guardian.agents.base import BaseAgent
from guardian.core.models import Finding, GuardianState
from guardian.core.evidence_store import EvidenceStore
from pathlib import Path
import ast
import re


class ReachabilityAgent(BaseAgent):
    name = "reachability"

    def run(self, state: GuardianState) -> GuardianState:
        store = EvidenceStore(":memory:")
        for raw_path in state.inputs:
            path = Path(raw_path)
            if not path.is_file():
                continue
            text = path.read_text(errors="replace")
            if path.suffix == ".py":
                try:
                    tree = ast.parse(text)
                except SyntaxError:
                    continue
                imported = set()
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        imported.update(alias.name.split(".", 1)[0] for alias in node.names)
                    elif isinstance(node, ast.ImportFrom) and node.module:
                        imported.add(node.module.split(".", 1)[0])
                for component in state.components.values():
                    if component.name.lower() in imported:
                        finding_id = f"REACH-{component.name}-imported"
                        evidence = store.add(
                            kind="tool_output",
                            source="python_ast",
                            uri=f"{path}:{path.name}",
                            payload={"component": component.name, "imports": sorted(imported)},
                        )
                        state.evidence[evidence["id"]] = evidence
                        state.findings[finding_id] = Finding(
                            id=finding_id,
                            type="reachability",
                            component_purl=component.purl,
                            confidence="Medium",
                            verified_evidence=[evidence["id"]],
                            ai_inferences=[{
                                "statement": f"{component.name} is imported in {path.name}",
                                "supporting_evidence_ids": [],
                                "confidence": "Medium",
                            }],
                        )
            elif path.suffix in (".js", ".jsx", ".ts", ".tsx"):
                for component in state.components.values():
                    if re.search(rf"(?:from\s+|require\()['\"]{re.escape(component.name)}", text):
                        finding_id = f"REACH-{component.name}-imported"
                        evidence = store.add(
                            kind="tool_output",
                            source="javascript_import_scan",
                            uri=str(path),
                            payload={"component": component.name},
                        )
                        state.evidence[evidence["id"]] = evidence
                        state.findings.setdefault(
                            finding_id,
                            Finding(
                                id=finding_id,
                                type="reachability",
                                component_purl=component.purl,
                                confidence="Medium",
                                verified_evidence=[evidence["id"]],
                            ),
                        )
        store.close()
        state.coverage["reachability"] = "complete"
        return state

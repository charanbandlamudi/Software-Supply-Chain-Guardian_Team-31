from pathlib import Path
import json

from guardian.core.models import Component, Edge, GuardianState
from guardian.agents.base import BaseAgent


class IngestionAgent(BaseAgent):
    name = "ingestion"

    def run(self, state: GuardianState) -> GuardianState:
        issues = []
        for raw_path in state.inputs:
            path = Path(raw_path)
            if not path.is_file():
                issues.append(f"missing_input:{path}")
                continue
            try:
                if path.suffix.lower() == ".json":
                    payload = self._read_json(path)
                    if payload.get("bomFormat") == "CycloneDX" and "components" in payload:
                        self._load_cyclonedx(payload, state)
                    elif "nodes" in payload and "edges" in payload:
                        self._load_graph(payload, state)
                    elif "matches" in payload:
                        self._load_grype(payload, state)
                    else:
                        issues.append(f"unsupported_json:{path}")
                else:
                    self._load_requirements(path, state)
            except (json.JSONDecodeError, UnicodeDecodeError, OSError):
                issues.append(f"parse_error:{path}")
        if issues:
            state.coverage["ingestion"] = "partial"
            state.coverage["ingestion_issues"] = ";".join(issues)
        else:
            state.coverage["ingestion"] = "complete"
        return state

    @staticmethod
    def _read_json(path: Path) -> dict:
        raw = path.read_bytes()
        if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
            return json.loads(raw.decode("utf-16"))
        return json.loads(raw.decode("utf-8-sig"))

    @staticmethod
    def _load_cyclonedx(payload: dict, state: GuardianState) -> None:
        for item in payload.get("components", []):
            purl = item.get("purl")
            if not purl:
                continue
            name = item.get("name", "")
            version = item.get("version", "")
            ecosystem = purl.split(":", 1)[1].split("/", 1)[0] if purl.startswith("pkg:") else ""
            locations = [prop["value"] for prop in item.get("properties", [])
                         if prop.get("name", "").startswith("syft:location")]
            state.components[purl] = Component(
                purl=purl,
                name=name,
                version=version,
                ecosystem=ecosystem,
                hashes=[h["value"] for h in item.get("hashes", []) if h.get("value")],
                licenses=[entry["license"]["id"] for entry in item.get("licenses", [])
                           if entry.get("license", {}).get("id")],
                sources=["sbom"],
            )

    @staticmethod
    def _load_graph(payload: dict, state: GuardianState) -> None:
        roots = set(payload.get("roots", []))
        for node in payload.get("nodes", []):
            purl = node.get("purl")
            if not purl:
                continue
            current = state.components.get(purl)
            if current is None:
                parts = purl.split("@", 1)
                name = parts[0].removeprefix("pkg:")
                current = Component(
                    purl=purl,
                    name=name.rsplit("/", 1)[-1],
                    version=parts[1] if len(parts) > 1 else "",
                    ecosystem=name.split("/", 1)[0] if "/" in name else "",
                )
            current.direct = node["id"] in roots
            current.sources.append("graph") if "graph" not in current.sources else None
            state.components[purl] = current
        for edge in payload.get("edges", []):
            source = edge.get("source", "")
            target = edge.get("target", "")
            source_purl = next(
                (purl for purl in state.components if source.startswith(purl) or purl in source),
                source,
            )
            target_purl = next(
                (purl for purl in state.components if target.startswith(purl) or purl in target),
                target,
            )
            state.edges.append(Edge(
                from_purl=source_purl,
                to_purl=target_purl,
                source="graph",
            ))
        state.coverage["graph"] = "complete"

    @staticmethod
    def _load_grype(payload: dict, state: GuardianState) -> None:
        state.coverage["grype"] = f"{len(payload.get('matches', []))}_matches"

    @staticmethod
    def _load_requirements(path: Path, state: GuardianState) -> None:
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.upper().startswith(("FROM ", "RUN ", "COPY ", "ADD ", "WORKDIR ", "CMD ", "ENTRYPOINT ")):
                continue
            if "==" in line:
                name, version = line.split("==", 1)
            elif ">=" in line:
                name, version = line.split(">=", 1)
            else:
                name, version = line, "unknown"
            name = name.strip().lower()
            purl = f"pkg:pypi/{name}@{version.strip()}"
            state.components[purl] = Component(
                purl=purl,
                name=name,
                version=version.strip(),
                ecosystem="pypi",
                direct=True,
                sources=["manifest"],
            )

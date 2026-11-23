from guardian.agents.base import BaseAgent
from guardian.core.models import Finding, GuardianState
from guardian.core.evidence_store import EvidenceStore
from pathlib import Path
import json
import re
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class VulnerabilityIntelligenceAgent(BaseAgent):
    name = "vulnerability_intelligence"

    def run(self, state: GuardianState) -> GuardianState:
        grype_paths = []
        for raw in state.inputs:
            path = Path(raw)
            if not path.is_file():
                continue
            try:
                raw_bytes = path.read_bytes()
                payload = json.loads(
                    raw_bytes.decode("utf-16")
                    if raw_bytes.startswith((b"\xff\xfe", b"\xfe\xff"))
                    else raw_bytes.decode("utf-8-sig")
                )
                if isinstance(payload, dict) and "matches" in payload:
                    grype_paths.append(path)
            except (json.JSONDecodeError, UnicodeDecodeError, OSError):
                continue
        matches = 0
        store = EvidenceStore(":memory:")
        for path in grype_paths:
            raw = path.read_bytes()
            payload = json.loads(raw.decode("utf-16") if raw.startswith((b"\xff\xfe", b"\xfe\xff"))
                                else raw.decode("utf-8-sig"))
            for match in payload.get("matches", []):
                vulnerability = match.get("vulnerability", {})
                artifact = match.get("artifact", {})
                purl = artifact.get("purl")
                vuln_id = vulnerability.get("id", "UNKNOWN")
                matches += 1
                evidence = store.add(
                    kind="scanner_match",
                    source="grype",
                    uri=str(path),
                    payload=match,
                )
                package_name = artifact.get("name", "unknown")
                package_version = artifact.get("version", "")
                finding_id = f"{vuln_id}-{package_name}-{package_version}"
                severity = vulnerability.get("severity", "Unknown")
                cvss = vulnerability.get("cvss", [])
                score = max(
                    (entry.get("metrics", {}).get("baseScore", 0) for entry in cvss),
                    default=0,
                )
                fixed = vulnerability.get("fix", {}).get("versions", [])
                finding = Finding(
                    id=finding_id,
                    type="vuln",
                    component_purl=purl or f"pkg:npm/{artifact.get('name','unknown')}@{artifact.get('version','')}",
                    score=float(score),
                    score_breakdown={"cvss": float(score)},
                    confidence="High",
                    verified_evidence=[evidence["id"]],
                )
                finding.recommendation = {
                    "action": "upgrade",
                    "target_version": fixed[0] if fixed else None,
                    "severity": severity,
                }
                related_cves = [
                    item.get("id")
                    for item in vulnerability.get("relatedVulnerabilities", [])
                    if item.get("id", "").startswith("CVE-")
                ]
                related_cves.extend(
                    re.findall(r"CVE-\d{4}-\d{4,}", " ".join(vulnerability.get("urls", [])))
                )
                finding.score_breakdown["cves"] = ",".join(sorted(set(related_cves)))
                state.findings[finding_id] = finding
                state.evidence[evidence["id"]] = evidence
        osv_ids = set()
        queries = []
        for component in state.components.values():
            if component.ecosystem not in ("npm", "pypi"):
                continue
            ecosystem = "npm" if component.ecosystem == "npm" else "PyPI"
            queries.append({"package": {"name": component.name, "ecosystem": ecosystem}, "version": component.version})
        if queries:
            try:
                request = Request(
                    "https://api.osv.dev/v1/querybatch",
                    data=json.dumps({"queries": queries[:100]}).encode(),
                    headers={"Content-Type": "application/json", "User-Agent": "Guardian/0.1"},
                    method="POST",
                )
                with urlopen(request, timeout=10) as response:
                    osv_payload = json.loads(response.read().decode("utf-8"))
                for index, result in enumerate(osv_payload.get("results", [])):
                    for item in result.get("vulns", []):
                        osv_ids.add(item["id"])
                        evidence = store.add(
                            kind="api_response",
                            source="osv",
                            uri="https://api.osv.dev/v1/querybatch",
                            payload=item,
                        )
                        state.evidence[evidence["id"]] = evidence
                state.coverage["osv"] = f"{len(osv_ids)}_advisories"
            except (HTTPError, URLError, TimeoutError, json.JSONDecodeError, OSError):
                state.coverage["osv"] = "unavailable"

        cves = sorted({
            cve
            for finding in state.findings.values()
            for cve in str(finding.score_breakdown.get("cves", "")).split(",")
            if cve.startswith("CVE-")
        })
        if cves:
            try:
                epss_url = "https://api.first.org/data/v1/epss?cve=" + ",".join(cves)
                request = Request(epss_url, headers={"User-Agent": "Guardian/0.1"})
                with urlopen(request, timeout=10) as response:
                    epss_payload = json.loads(response.read().decode("utf-8"))
                evidence = store.add(
                    kind="api_response",
                    source="first_epss",
                    uri=epss_url,
                    payload=epss_payload,
                )
                state.evidence[evidence["id"]] = evidence
                state.coverage["epss"] = f"{len(epss_payload.get('data', []))}_scores"
            except (HTTPError, URLError, TimeoutError, json.JSONDecodeError, OSError):
                state.coverage["epss"] = "unavailable"
        store.close()
        state.coverage["vulnerability_intelligence"] = f"{matches}_matches"
        return state

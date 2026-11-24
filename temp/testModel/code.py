import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MODEL = "qwen3:4b"
DEFAULT_ENDPOINT = "http://localhost:11434/api/chat"


def load_json(path):
    path = path.expanduser()
    if not path.exists():
        raise FileNotFoundError(f"Input file not found: {path}")
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def extract_grype(data):
    findings = []
    for match in data.get("matches", []) if isinstance(data, dict) else []:
        vulnerability = match.get("vulnerability", {})
        artifact = match.get("artifact", {})
        fix = vulnerability.get("fix", {})
        findings.append({
            "source": "grype",
            "id": vulnerability.get("id"),
            "severity": vulnerability.get("severity"),
            "description": vulnerability.get("description"),
            "package": artifact.get("name"),
            "installed_version": artifact.get("version"),
            "ecosystem": artifact.get("type") or artifact.get("language"),
            "fixed_versions": fix.get("versions", []),
            "cwes": [item.get("cwe") for item in vulnerability.get("cwes", [])],
            "risk": vulnerability.get("risk"),
        })
    return findings


def extract_osv(data):
    findings = []
    for result in data.get("results", []) if isinstance(data, dict) else []:
        source = result.get("source", {}).get("path")
        for package_entry in result.get("packages", []):
            package = package_entry.get("package", {})
            for vulnerability in package_entry.get("vulnerabilities", []):
                fixed_versions = []
                for affected in vulnerability.get("affected", []):
                    for range_entry in affected.get("ranges", []):
                        for event in range_entry.get("events", []):
                            if event.get("fixed"):
                                fixed_versions.append(event["fixed"])

                findings.append({
                    "source": "osv",
                    "source_path": source,
                    "id": vulnerability.get("id"),
                    "aliases": vulnerability.get("aliases", []),
                    "severity": vulnerability.get("database_specific", {}).get("severity"),
                    "description": vulnerability.get("details") or vulnerability.get("summary"),
                    "package": package.get("name"),
                    "installed_version": package.get("version"),
                    "ecosystem": package.get("ecosystem"),
                    "fixed_versions": sorted(set(fixed_versions)),
                    "cwes": vulnerability.get("database_specific", {}).get("cwe_ids", []),
                })
    return findings


def deduplicate(findings):
    unique = {}
    for finding in findings:
        key = (
            finding.get("ecosystem"),
            finding.get("package"),
            finding.get("installed_version"),
            finding.get("id"),
        )
        if key not in unique:
            unique[key] = finding
        else:
            existing = unique[key]
            existing_sources = existing.get("sources", [existing["source"]])
            for source in finding.get("sources", [finding["source"]]):
                if source not in existing_sources:
                    existing_sources.append(source)
            existing["sources"] = existing_sources
            for field in ("fixed_versions", "aliases", "cwes"):
                existing[field] = sorted(set(existing.get(field, []) + finding.get(field, [])))
    return list(unique.values())


def add_graph_context(findings, graph):
    nodes = graph.get("nodes", []) if isinstance(graph, dict) else []
    nodes_by_name = {}
    for node in nodes:
        nodes_by_name.setdefault(node.get("name"), []).append(node)

    for finding in findings:
        matches = nodes_by_name.get(finding.get("package"), [])
        contexts = []
        for node in matches[:5]:
            if finding.get("installed_version") not in (None, node.get("version")):
                continue
            contexts.append({
                "name": node.get("name"),
                "version": node.get("version"),
                "direct_or_transitive": node.get("dep_type"),
                "parent_count": len(node.get("parent_ids", [])),
                "child_count": len(node.get("child_ids", [])),
            })
        if contexts:
            finding["dependency_graph"] = contexts


def group_by_package(findings):
    groups = {}
    for finding in findings:
        package = finding.get("package") or "unknown"
        key = (finding.get("ecosystem"), package)
        group = groups.setdefault(key, {
            "package": package,
            "ecosystem": finding.get("ecosystem"),
            "installed_versions": [],
            "findings": [],
        })
        version = finding.get("installed_version")
        if version and version not in group["installed_versions"]:
            group["installed_versions"].append(version)
        group["findings"].append(finding)

    return list(groups.values())


def find_upgrade_via(graph, package, installed_versions):
    nodes = graph.get("nodes", []) if isinstance(graph, dict) else []
    nodes_by_id = {node.get("id"): node for node in nodes}
    vulnerable_nodes = [
        node for node in nodes
        if node.get("name") == package
        and (not installed_versions or node.get("version") in installed_versions)
    ]

    direct_names = set()
    for node in vulnerable_nodes:
        seen = set()
        current = node
        while current and current.get("id") not in seen:
            seen.add(current.get("id"))
            if current.get("dep_type") == "direct":
                direct_names.add(current.get("name"))
                break
            for parent_id in current.get("parent_ids", []):
                parent = nodes_by_id.get(parent_id)
                if parent:
                    current = parent
                    break
            else:
                break
    return sorted(direct_names)


def attach_upgrade_paths(groups, graph):
    for group in groups:
        paths = find_upgrade_via(
            graph,
            group["package"],
            group["installed_versions"],
        )
        group["upgrade_via"] = paths[0] if paths else group["package"]
        group["dependency_paths"] = paths


def chunk_by_budget(groups, max_chars=6000, max_items=6):
    chunk, size = [], 0
    for group in groups:
        size_of_group = len(json.dumps(group, ensure_ascii=False))
        if chunk and (size + size_of_group > max_chars or len(chunk) >= max_items):
            yield chunk
            chunk, size = [], 0
        chunk.append(group)
        size += size_of_group
    if chunk:
        yield chunk


def validate_fix(fix, groups):
    package = fix.get("package")
    target = fix.get("target_version")
    matching_groups = [
        group for group in groups
        if group["package"] == package
        or group["upgrade_via"] == package
    ]

    fixed_versions = set()
    source_packages = set()
    for group in matching_groups:
        source_packages.add(group["package"])
        for finding in group["findings"]:
            fixed_versions.update(finding.get("fixed_versions", []))

    verified = bool(target and target in fixed_versions)
    return {
        **fix,
        "source_packages": sorted(source_packages),
        "verified_fixed_version": verified,
    }


def consolidate(fixes, groups):
    via = {group["package"]: group["upgrade_via"] or group["package"] for group in groups}
    plan = {}
    for raw_fix in fixes:
        package = raw_fix.get("package")
        validated = validate_fix(raw_fix, groups)
        action_package = via.get(package, package)
        plan.setdefault(action_package, []).append(validated)
    return plan


def parse_fix_json(content):
    text = content.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        lines = [line for line in lines if not line.strip().startswith("```")]
        text = "\n".join(lines)
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        start = text.find("[")
        end = text.rfind("]")
        if start >= 0 and end > start:
            parsed = json.loads(text[start:end + 1])
        else:
            raise RuntimeError("Ollama returned a non-JSON fix list.")
    if not isinstance(parsed, list):
        raise RuntimeError("Ollama fix response must be a JSON array.")
    return parsed


def ask_ollama(endpoint, model, groups, graph_stats, timeout, max_chars, max_items):
    fixes = []
    chunks = list(chunk_by_budget(groups, max_chars=max_chars, max_items=max_items))
    for index, chunk in enumerate(chunks, start=1):
        payload = {
            "model": model,
            "stream": False,
            "options": {
                "num_ctx": 8192,
            },
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a software supply-chain security reviewer. Analyze scanner findings "
                        "and dependency graph context. Do not invent vulnerabilities or package versions. "
                        "Prefer fixed versions already present in the findings. Return only a JSON array."
                    ),
                },
                {
                    "role": "user",
                    "content": (
                        f"Dependency graph summary: {json.dumps(graph_stats, ensure_ascii=False)}\n\n"
                        f"Analyze this package group chunk {index} and return only a JSON array.\n"
                        "For each package, use this schema:\n"
                        '[{"package":"package-name","target_version":"fixed-version-or-null",'
                        '"priority":"CRITICAL|HIGH|MEDIUM|LOW",'
                        '"risk":"short reason","action":"upgrade or workaround",'
                        '"testing":"required compatibility check","manual_verification":true_or_false}]\n'
                        "Do not repeat advisory details that are not needed for the fix.\n"
                        f"Groups:\n{json.dumps(chunk, indent=2, ensure_ascii=False)}"
                    ),
                },
            ],
        }
        request = urllib.request.Request(
            endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            print(f"Analyzing chunk {index} of {len(chunks)}...", flush=True)
            with urllib.request.urlopen(request, timeout=timeout) as response:
                result = json.load(response)
        except TimeoutError as error:
            raise RuntimeError(
                f"Ollama timed out while processing chunk {index} "
                f"after {timeout} seconds. Try a smaller chunk size or "
                "increase --timeout."
            ) from error
        except urllib.error.URLError as error:
            raise RuntimeError(
                f"Could not contact Ollama at {endpoint}. "
                "Start Ollama and verify the model is installed."
            ) from error

        content = result.get("message", {}).get("content")
        if not content:
            raise RuntimeError("Ollama returned an empty response.")
        fixes.extend(parse_fix_json(content))

    return fixes


def render_plan(graph_stats, plan):
    lines = [
        "# Software Supply-Chain Remediation Plan",
        "",
        "## Graph summary",
        "",
        "```json",
        json.dumps(graph_stats, indent=2, ensure_ascii=False),
        "```",
        "",
        "## Consolidated fixes",
        "",
    ]
    for action_package, fixes in plan.items():
        source_packages = sorted({
            source
            for fix in fixes
            for source in fix.get("source_packages", [])
        })
        priorities = [fix.get("priority", "MEDIUM") for fix in fixes]
        priority = next(
            (level for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if level in priorities),
            "MEDIUM",
        )
        verified = all(fix.get("verified_fixed_version") for fix in fixes)
        lines.extend([
            f"### {action_package}",
            "",
            f"- **Priority:** {priority}",
            f"- **Verified fixed version:** {'Yes' if verified else 'No'}",
            f"- **Source packages:** {', '.join(source_packages) or 'None'}",
        ])
        for fix in fixes:
            target = fix.get("target_version") or "No scanner-verified target version"
            lines.extend([
                f"- **Target:** `{target}`",
                f"- **Risk:** {fix.get('risk', 'Not provided')}",
                f"- **Action:** {fix.get('action', 'Manual remediation required')}",
                f"- **Testing:** {fix.get('testing', 'Run the relevant test suite')}",
            ])
            if fix.get("manual_verification"):
                lines.append("- **Manual verification required:** Yes")
        lines.append("")
    return "\n".join(lines)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Analyze Grype, OSV-Scanner, and dependency graph JSON with a local Ollama model."
    )
    parser.add_argument("--grype", type=Path, default=REPO_ROOT / "grype.json")
    parser.add_argument("--osv", type=Path, default=REPO_ROOT / "osv.json")
    parser.add_argument("--graph", type=Path, default=REPO_ROOT / "graph.json")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--endpoint", default=DEFAULT_ENDPOINT)
    parser.add_argument(
        "--timeout",
        type=int,
        default=900,
        help="Maximum seconds to wait for each Ollama response.",
    )
    parser.add_argument(
        "--chunk-chars",
        type=int,
        default=6000,
        help="Maximum JSON characters sent in each Ollama request.",
    )
    parser.add_argument(
        "--chunk-items",
        type=int,
        default=6,
        help="Maximum package groups sent in each Ollama request.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=REPO_ROOT / "testModel" / "security-analysis.md",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    grype = load_json(args.grype)
    osv = load_json(args.osv)
    graph = load_json(args.graph)

    findings = deduplicate(extract_grype(grype) + extract_osv(osv))
    add_graph_context(findings, graph)

    graph_stats = graph.get("stats", {}) if isinstance(graph, dict) else {}
    print(
        f"Prepared {len(findings)} unique findings "
        f"({len(extract_grype(grype))} Grype, {len(extract_osv(osv))} OSV)."
    )
    if not findings:
        print("No findings found to analyze.")
        return 0

    groups = group_by_package(findings)
    attach_upgrade_paths(groups, graph)
    serialized_groups = json.dumps(groups, ensure_ascii=False)
    print(
        f"{len(groups)} packages, "
        f"{len(serialized_groups) // 4} approx input tokens "
        f"({len(serialized_groups)} characters)."
    )

    chunks = list(chunk_by_budget(
        groups,
        max_chars=args.chunk_chars,
        max_items=args.chunk_items,
    ))
    fixes = ask_ollama(
        args.endpoint,
        args.model,
        groups,
        graph_stats,
        args.timeout,
        args.chunk_chars,
        args.chunk_items,
    )
    plan = consolidate(fixes, groups)
    report = render_plan(graph_stats, plan)
    plan_json = args.output.with_suffix(".json")
    plan_json.write_text(
        json.dumps(plan, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report, encoding="utf-8")
    print(report)
    print(f"\nReport written to: {args.output}")
    print(f"Structured fixes written to: {plan_json}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (FileNotFoundError, json.JSONDecodeError, RuntimeError) as error:
        print(f"Error: {error}", file=sys.stderr)
        raise SystemExit(1)
"""Deterministic policy checks for agent actions and build outputs."""
from __future__ import annotations

import json
import re

READ_ONLY_TOOLS = {
    "sbom.generate", "osv.scan", "grype.scan", "trivy.image", "epss.get",
    "kev.lookup", "depsdev.versions", "typosquat.check", "guarddog.scan",
    "zizmor.scan", "cosign.verify", "graph.paths", "jelly.callgraph",
}
DENIED_TOOLS = {"git.merge", "git.push_default", "npm.publish", "pypi.upload",
                "docker.push_public", "deploy"}
SECRET_RE = re.compile(r"(ghp_|github_pat_|npm_[A-Za-z0-9]{36}|AKIA[0-9A-Z]{16}|-----BEGIN)")


def evaluate_tool_call(request: dict) -> dict:
    tool = request.get("tool", "")
    args = request.get("args", {})
    reasons = []

    if tool in DENIED_TOOLS:
        reasons.append("merge/deploy/publish is human-only")
    elif tool not in READ_ONLY_TOOLS and tool not in {
        "git.branch", "pkg.apply", "docker.build", "test.run", "git.open_pr",
    }:
        reasons.append(f"tool {tool} is not allow-listed")

    if tool in {"git.branch", "pkg.apply", "docker.build", "test.run"}:
        if not str(args.get("branch", "")).startswith("guardian/"):
            reasons.append("mutation requires a guardian/* branch")
        if not request.get("approval", {}).get("gate1"):
            reasons.append("mutation requires remediation Gate 1")

    if tool == "git.open_pr":
        if args.get("draft") is not True:
            reasons.append("PR must be a draft")
        if not request.get("approval", {}).get("gate2"):
            reasons.append("PR requires publishing Gate 2")

    if request.get("egress_hosts"):
        allowed = {"api.osv.dev", "api.first.org", "www.cisa.gov", "api.deps.dev",
                   "localhost:4873", "llm-gateway.internal"}
        for host in request["egress_hosts"]:
            if host not in allowed:
                reasons.append(f"egress to non-allow-listed host: {host}")

    if SECRET_RE.search(json.dumps(args, sort_keys=True, default=str)):
        reasons.append("secret-like value in tool args")

    return {"allow": not reasons, "deny_reason": reasons}

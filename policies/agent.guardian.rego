package guardian.agent

import rego.v1

default allow := false

read_only_tools := {"sbom.generate", "osv.scan", "grype.scan", "trivy.image",
  "epss.get", "kev.lookup", "depsdev.versions", "typosquat.check",
  "guarddog.scan", "zizmor.scan", "cosign.verify", "graph.paths", "jelly.callgraph"}

allow if {
  input.tool in read_only_tools
  input.target.repo in data.sandbox.repos
}

allow if {
  input.tool == "detonate.run"
  input.args.network == "none"
  input.args.runtime == "runsc"
}

allow if {
  input.tool in {"pkg.apply", "docker.build", "test.run"}
  startswith(input.args.branch, "guardian/")
  input.approval.gate1 == true
}

deny_reason contains "unresolved ACT finding" if {
  input.report.ssvc_decision == "Act"
  input.report.resolution != "validated"
}

deny_reason contains "unpinned GitHub Action" if {
  input.report.unpinned_actions > 0
}

deny_reason contains "unpinned base digest" if {
  input.report.unpinned_base_images > 0
}

deny_reason contains "license policy violation" if {
  input.report.license_violations > 0
}

deny_reason contains "merge/deploy/publish is human-only" if {
  input.tool in {"git.merge", "git.push_default", "npm.publish", "pypi.upload",
                 "docker.push_public", "deploy"}
}

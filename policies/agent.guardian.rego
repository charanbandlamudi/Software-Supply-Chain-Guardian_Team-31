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
  input.tool in {"git.branch", "pkg.apply", "docker.build", "test.run"}
  startswith(input.args.branch, "guardian/")
  input.approval.gate1 == true
}

allow if {
  input.tool == "git.open_pr"
  input.args.draft == true
  input.approval.gate2 == true
}

deny_reason contains "merge/deploy/publish is human-only" if {
  input.tool in {"git.merge", "git.push_default", "npm.publish", "pypi.upload",
                 "docker.push_public", "deploy"}
}

package guardian.build

import rego.v1

deny contains msg if {
  some finding in input.findings
  finding.score.band == "ACT"
  finding.status != "accepted"
  msg := sprintf("ACT-level finding %s is unresolved", [finding.finding_id])
}

deny contains msg if {
  input.image.base_ref
  not contains(input.image.base_ref, "@sha256:")
  msg := "Base image must be pinned by digest"
}

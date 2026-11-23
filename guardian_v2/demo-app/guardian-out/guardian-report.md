# Guardian Report: run b2ae081b

16 components, 12 edges, 44 unique vulnerabilities, 14 non-CVE findings.

## Top findings

| Score | Conf | SSVC | Finding | Component | Reachability | Resolution |
|---|---|---|---|---|---|---|
| 78.0 | High | Act | MALICIOUS_PACKAGE | lodahs@1.0.0 | not_imported | fixed_in_sandbox (awaiting PR merge by a human) |
| 59.0 | High | Attend | INTEGRITY_MISMATCH | minimist@1.2.5 | used_transitively | fixed_in_sandbox (awaiting PR merge by a human) |
| 59.0 | High | Attend | LOCKFILE_TAMPERING | minimist@1.2.5 | used_transitively | fixed_in_sandbox (awaiting PR merge by a human) |
| 47.0 | Medium | Attend | DANGEROUS_WORKFLOW | ci.yml | n/a | plan approved |
| 40.0 | High | Track | UNTRUSTED_RESOLVED_URL | minimist@1.2.5 | used_transitively | fixed_in_sandbox (awaiting PR merge by a human) |
| 38.0 | High | Track | TYPOSQUAT_SUSPECT | lodahs@1.0.0 | not_imported | fixed_in_sandbox (awaiting PR merge by a human) |
| 30.0 | High | Track | INSTALL_SCRIPT | lodahs@1.0.0 | not_imported | fixed_in_sandbox (awaiting PR merge by a human) |
| 29.2 | Medium | Track | GHSA-r5fr-rjxr-66jc | lodash@4.17.15 | imported | fixed_in_sandbox (awaiting PR merge by a human) |
| 28.2 | Medium | Track | GHSA-xvch-5gv4-984h | minimist@1.2.5 | used_transitively | fixed_in_sandbox (awaiting PR merge by a human) |
| 28.0 | Medium | Track | UNPINNED_ACTION | ci.yml | n/a | plan approved |
| 26.6 | Medium | Track | GHSA-p6mc-m468-83gw | lodash@4.17.15 | imported | fixed_in_sandbox (awaiting PR merge by a human) |
| 25.9 | Medium | Track | GHSA-35jh-r3h4-6jhm | lodash@4.17.15 | imported | fixed_in_sandbox (awaiting PR merge by a human) |
| 24.0 | Medium | Track | EXCESSIVE_PERMISSIONS | ci.yml | n/a | plan approved |
| 24.0 | Medium | Track | SUSPICIOUS_UPDATE | certifi@2026.11.20 | used_transitively | plan approved |
| 23.4 | Medium | Track | GHSA-xxjr-mmjv-4gpg | lodash@4.17.15 | imported | fixed_in_sandbox (awaiting PR merge by a human) |
| 23.0 | Medium | Track | CVE-2023-30861 | flask@2.0.1 | imported | fixed_in_sandbox (awaiting PR merge by a human) |
| 23.0 | Medium | Track | CVE-2026-27205 | flask@2.0.1 | imported | fixed_in_sandbox (awaiting PR merge by a human) |
| 23.0 | Medium | Track | CVE-2023-32681 | requests@2.25.1 | imported | fixed_in_sandbox (awaiting PR merge by a human) |
| 23.0 | Medium | Track | CVE-2024-35195 | requests@2.25.1 | imported | fixed_in_sandbox (awaiting PR merge by a human) |
| 23.0 | Medium | Track | CVE-2024-47081 | requests@2.25.1 | imported | fixed_in_sandbox (awaiting PR merge by a human) |

## Remediation plans

| Component | Action | Target | Attempt | Status | Rationale |
|---|---|---|---|---|---|
| Dockerfile | pin |  | 1 | approved | Pin the base image by @sha256 digest (and move off EOL tags). |
| ci.yml | pin |  | 1 | approved | Pin the action to a full 40-character commit SHA. |
| flask@2.0.1 | upgrade | 3.1.3 | 1 | validated | minimal: flask 3.1.3 re-scanned clean on the registry (0 known advisories) |
| jinja2@3.0.1 | upgrade | 3.1.6 | 1 | validated | minimal: jinja2 3.1.6 re-scanned clean on the registry (0 known advisories) |
| werkzeug@2.0.1 | upgrade | 3.1.9 | 1 | validated | minimal: werkzeug 3.1.9 re-scanned clean on the registry (0 known advisories) |
| idna@2.10 | upgrade | 3.15 | 1 | validated | minimal: idna 3.15 re-scanned clean on the registry (0 known advisories) |
| pip@24.0 | upgrade | 26.2 | 1 | approved | minimal: pip 26.2 re-scanned clean on the registry (0 known advisories) |
| requests@2.25.1 | upgrade | 2.33.0 | 1 | validated | minimal: requests 2.33.0 re-scanned clean on the registry (0 known advisories) |
| urllib3@1.26.20 | upgrade | 2.8.0 | 1 | validated | minimal: urllib3 2.8.0 re-scanned clean on the registry (0 known advisories) |
| lodash@4.17.15 | upgrade | 4.18.1 | 1 | validated | minimal: lodash 4.18.1 re-scanned clean on the registry (0 known advisories) |
| minimist@1.2.5 | upgrade | 1.2.6 | 1 | validated | minimal: minimist 1.2.6 re-scanned clean on the registry (0 known advisories) |
| lodahs@1.0.0 | remove |  | 1 | validated | Remove the package; it was taken down as malicious. Source code does not import it, so rem |
| certifi@2026.11.20 | pin |  | 1 | approved | Pin to the previous release until the new one passes the cooling-off window. |

## Validation

- **pypi**: PASS; build ok, tests ok
  - SBOM diff: +8 / -7; residual vulnerable packages: none
- **npm**: PASS; build ok, tests ok
  - SBOM diff: +2 / -3; residual vulnerable packages: none

## Source coverage

- discovery: SBOM CycloneDX 1.6: 12 components; pipdeptree: 12 packages; package-lock v3: 4 packages
- reputation: 16 ok, 0 failed
- source:pypi-osv: ok
- source:npm-audit: ok
- source:osv: failed: network for https://api.osv.dev/v1/querybatch: <urlopen error [Errno -2] Name or service not known>
- source:ghsa: skipped: set GITHUB_TOKEN (unauthenticated limit is 60 req/h)
- source:cisa-kev: ok (1790 entries)
- source:epss: failed: network for https://api.first.org/data/v1/epss?cve=CVE-2022-29361,CVE-2023-23934,CVE-2023-25577,CVE-2023-30861,CVE-2023-
- llm: no LLM key configured; deterministic templates used

## Agent trace

 1. **supervisor** → ['discovery', 'cicd']: policy: ready=['discovery', 'cicd'], handoffs=[]
 1. **cicd** → supervisor: 5 container/CI findings in 2 files
 1. **discovery** → supervisor: 16 components (7 direct), 12 edges; SBOM CycloneDX 1.6: 12 components; pipdeptree: 12 packages; package-lock v3: 4 packages
 2. **supervisor** → ['vuln_intel', 'reputation', 'reachability']: policy: ready=['vuln_intel', 'reputation', 'reachability'], handoffs=[]
 2. **reachability** → supervisor: reachability: {'imported': 4, 'used_transitively': 10, 'not_in_runtime': 1, 'not_imported': 1}
 2. **reputation** → supervisor: registry metadata for 16 packages; security-holding packages: ['pkg:npm/lodahs@1.0.0']
 2. **vuln_intel** → supervisor: 80 raw advisory records from 2/3 sources -> 44 unique vulnerabilities on 10 packages (werkzeug@2.0.1=11, urllib3@1.26.20=7, pip@24.0=6, jinja2@3.0.1=5, lodash@4.17.15=5, requests@2.25.1=4)
 3. **supervisor** → ['exploit_intel', 'anomaly']: policy: ready=['exploit_intel', 'anomaly'], handoffs=[]
 3. **anomaly** → supervisor: 9 non-CVE findings: {'environment_only': 1, 'untrusted_resolved_url': 1, 'integrity_mismatch': 1, 'malicious_package': 1, 'typosquat_suspect': 1, 'install_script': 1, 'suspicious_update': 1, 'lockfile_tampering': 1, 'dependency_added': 1}
 3. **anomaly** → reachability: handoff: suspicious packages found; check whether source code imports them
 3. **exploit_intel** → supervisor: 37 CVEs checked: 0 in CISA KEV, EPSS for 0
 4. **supervisor** → ['reachability']: policy: ready=['scoring'], handoffs=['reachability']
 4. **reachability** → supervisor: reachability: {'imported': 4, 'used_transitively': 10, 'not_in_runtime': 1, 'not_imported': 1}; handoff check on 2 suspicious packages: imported by source = none
 5. **supervisor** → ['scoring']: policy: ready=['scoring'], handoffs=[]
 5. **scoring** → supervisor: scored 58 findings; top: MALICIOUS_PACKAGE on lodahs@1.0.0 = 78.0; INTEGRITY_MISMATCH on minimist@1.2.5 = 59.0; LOCKFILE_TAMPERING on minimist@1.2.5 = 59.0
 6. **supervisor** → ['remediation']: policy: ready=['remediation'], handoffs=[]
 6. **remediation** → supervisor: 13 plans (strategy=minimal): upgrades [flask 2.0.1->3.1.3, jinja2 3.0.1->3.1.6, werkzeug 2.0.1->3.1.9, idna 2.10->3.15, pip 24.0->26.2, requests 2.25.1->2.33.0, urllib3 1.26.20->2.8.0, lodash 4.17.15->4.18.1, minimist 1.2.5->1.2.6]; other actions {'pin': 3, 'remove': 1}
 7. **supervisor** → ['explainer']: policy: ready=['explainer'], handoffs=[]
 7. **explainer** → supervisor: 12 template explanations (no LLM key configured; deterministic templates used)
 8. **supervisor** → ['critic']: policy: ready=['critic'], handoffs=[]
 8. **critic** → supervisor: verified 12 claims; 0 replaced by templates
 9. **supervisor** → ['approval']: policy: ready=['approval'], handoffs=[]
 9. **approval** → supervisor: human reviewer demo-reviewer (simulated): 13 approved, 0 rejected
10. **supervisor** → ['validation']: policy: ready=['validation'], handoffs=[]
10. **validation** → supervisor: pypi: build+tests pass; added 8 / removed 7 packages; residual vulnerable packages after change: 0; npm: build+tests pass; added 2 / removed 3 packages; residual vulnerable packages after change: 0  [6.2s]
11. **supervisor** → report: finish: no agent has new inputs and no handoffs are open
# Security Review

## Summary

Date: 2026-11-23

The Guardian implementation was reviewed for secret handling, command execution,
approval bypass, sandbox isolation, path traversal, and credential exposure.
All findings identified during the first review were fixed and verified by a
second security review.

## Findings

| # | Severity | File | Lines | Vulnerability | Status |
|---|----------|------|-------|---------------|--------|
| 1 | 🔴 CRITICAL | guardian_v2/guardian_v2/agents/gate.py | 47-211 | Host package builds and smoke tests executed untrusted code with host credentials | Fixed |
| 2 | 🟠 HIGH | guardian_v2/run_guardian.py | 43-70 | `--auto-approve` bypassed the human approval boundary | Fixed |
| 3 | 🟡 MEDIUM | guardian_v2/guardian_v2/providers.py | 55-63 | Gemini API key appeared in the request URL | Fixed |
| 4 | 🟡 MEDIUM | guardian_v2/guardian_v2/agents/gate.py | 95-151 | npm copy paths allowed absolute paths and traversal | Fixed |

## Implemented Controls

- Remediation validation runs in Podman or Docker containers.
- Container execution disables network access.
- Container execution is read-only, unprivileged, capability-restricted,
  memory/CPU/PID-limited, and prevents privilege escalation.
- Python and npm smoke files are copied only from validated project paths.
- npm copy entries reject absolute paths and `..` traversal.
- Python package installation uses `--only-binary=:all:`.
- npm installation uses `--ignore-scripts`.
- Host environment variables are not inherited by the sandbox runtime.
- Gemini credentials are sent through `x-goog-api-key`, not the URL.
- The `--auto-approve` CLI bypass was removed; approval uses `interrupt()` and
  interactive approve/reject decisions.
- Generated reports and evidence do not include provider credentials.

## Verification

The first review identified four findings. The fixes were followed by a second
security review, which found no remaining vulnerabilities in the reviewed
changes.

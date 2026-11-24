# 🛡️ Software Supply Chain Guardian — Team 31

Software supply chain security analysis for open-source repositories. Paste a GitHub URL and the
Guardian clones the repository, builds a **CycloneDX SBOM**, scans it with **three
security scanners** (vulnerabilities, misconfigurations and secrets), and renders an **interactive dependency graph** that traces every
vulnerable package back to the application through its real dependency path.

Built for the Amrita BD Hackathon. Primary test target: [OWASP Juice Shop](https://github.com/juice-shop/juice-shop).

> **Design principle — evidence first.** The scanners discover security information; the graph
> only shows what the SBOM and the raw scanner output support. Package versions come from the
> SBOM, dependency paths from the graph, vulnerabilities from scanner output. Missing data is
> shown as *"Evidence unavailable"*, scanner disagreements are shown, not resolved, and the
> absence of a finding is never presented as proof of safety.

---

## Contents

- [Features](#features)
- [How it works](#how-it-works)
- [Quick start](#quick-start)
- [Installation](#installation)
- [Usage](#usage)
- [Outputs](#outputs)
- [The interactive graph](#the-interactive-graph)
- [Project structure](#project-structure)
- [Technology choices](#technology-choices)
- [Security model](#security-model)
- [Understanding the results](#understanding-the-results)
- [Example results](#example-results)
- [Troubleshooting](#troubleshooting)
- [Roadmap](#roadmap)

---

## Features

- **One-click scans from a web UI.** Paste a GitHub URL, press *Run scan*, and watch each step's progress.
- **Background execution.** Scans run on the server, so refreshing or closing the tab doesn't stop them. Scan history is kept in the sidebar.
- **CycloneDX SBOM** generated with OWASP cdxgen, including the full direct and transitive dependency tree.
- **Three scanners in parallel:** Grype, which scans the SBOM, plus OSV-Scanner and Trivy, which scan the repository. Vulnerability findings are merged by shared CVE/GHSA IDs, so each one shows which scanners reported it.
- **Misconfiguration and secret detection** with Trivy: Dockerfiles, CI workflows and Terraform/Kubernetes files are checked as data, never built or run. Secret values are never shown or stored.
- **Interactive dependency graph** built with NetworkX and PyVis:
  - Click a package to see its path to the root, its dependencies and its vulnerability evidence.
  - Search tells apart packages with the same name in different versions.
  - Filter by severity, with each vulnerable package's path kept visible.
  - The layout is still by default, with a toggle to start or stop motion.
- **Machine-readable output:** `graph.json` holds every node, edge, dependency path and merged finding.
- **Reproducible records:** every scan stores its raw scanner output, tool versions, the Grype database build date, the commit scanned, and each step's status and timing.
- **Honest status reporting:** a scan is marked *complete* only when every required step succeeded.

## How it works

```
                ┌───────────────────────── pipeline/scan.py ──────────────────────────┐
GitHub URL ───▶ │ 1. clone        git clone --depth 1 (hooks disabled)                │
                │ 2. lockfile     npm install --package-lock-only --ignore-scripts    │
                │                 (only for npm repos that don't commit a lockfile)   │
                │ 3. SBOM         cdxgen -r --no-install-deps  ──▶ bom.json           │
                │ 4. scan  ┌──▶  grype sbom:bom.json            ──▶ grype.json       │
                │          ├──▶  osv-scanner scan -r --no-ignore ──▶ osv.json        │
                │          └──▶  trivy fs --scanners vuln,misconfig,secret ──▶ trivy.json
                │ 5. graph        graph/build_graph.py                                │
                │                   ├─ NetworkX DiGraph from SBOM dependencies        │
                │                   ├─ merge findings across scanners (by CVE/GHSA)   │
                │                   ├─ direct/transitive, paths to root               │
                │                   └─▶ graph.json + dependency_graph.html (PyVis)    │
                │ 6. agents       pipeline/agents.py → guardian_v2 (LangGraph)        │
                │                   supervisor routes 11 specialist agents; critic    │
                │                   verifies every claim ──▶ agents/guardian-report.* │
                │                   graph re-rendered with the agents' assessment     │
                │ 7. report       reporting/guardian_report.py: Pydantic findings,    │
                │                   evidence validator ──▶ report/guardian-report.    │
                │                   json / html / pdf                                 │
                └─────────────────────────────────────────────────────────────────────┘
                                         │
                                         ▼
                        app.py (Streamlit) shows progress, results and graph
```

| Step | Tool | Why it's needed |
|---|---|---|
| Clone | `git` | Shallow, read-only checkout of the target |
| Lockfile | `npm` | Many npm repos (Juice Shop included) don't commit a lockfile. Without one, only direct dependencies with version ranges are known. This step resolves exact versions from the registry without installing packages or running scripts. |
| SBOM | **cdxgen** | Produces a standard CycloneDX inventory: exact versions, package URLs (purls) and dependency relationships |
| Scan | **Grype** | Matches the SBOM against Anchore's local database (NVD, GitHub advisories, Linux distribution feeds) |
| Scan | **OSV-Scanner** | Looks lockfiles up live on osv.dev: an independent second opinion |
| Scan | **Trivy** | Aqua Security's database for vulnerabilities, plus misconfiguration checks (Dockerfile, Terraform, Kubernetes, CI) and secret detection |
| Graph | **NetworkX + PyVis** | Graph analysis (paths, parents, layout) and interactive HTML rendering |
| Agents | **LangGraph** (`guardian_v2`) | A supervisor decides each turn which specialist agents run (reputation, reachability, exploit intel, anomaly, scoring, remediation, explainer, critic, …) and agents hand work to each other. See [Multi-agent investigation](#multi-agent-investigation). |

## Quick start

```bash
# 1. Python environment (use Python 3.12; see Troubleshooting)
python3.12 -m venv .venv
.venv/bin/pip install -r requirements.txt

# 2. Security tools on PATH (see Installation)
cdxgen --version && grype version && osv-scanner --version

# 3. Download the vulnerability databases (one-time; Grype ~3.6 GB, Trivy ~1.8 GB on disk)
grype db update
trivy fs --download-db-only --timeout 60m

# 4. Start the UI
.venv/bin/streamlit run app.py
```

Open **http://localhost:8501**, keep the default `https://github.com/juice-shop/juice-shop`, and press **Run scan**.

## Installation

### Requirements

| Component | Version tested | Notes |
|---|---|---|
| macOS (Apple Silicon) | Darwin 27 | Homebrew / standalone binaries |
| Windows 10 / 11 | Windows 11 AMD64 | **Fully tested & supported** (WinGet + npm) |
| Linux | Ubuntu 22.04+ | Supported |
| Python | 3.11 / 3.12 | **Not 3.14.1**: networkx fails to import there |
| Node.js / npm | 22.22.3 / 10.9.8 | Needed for cdxgen and lockfile resolution |
| git | 2.44+ | |
| OWASP cdxgen | 12.9.3 | `npm install -g @cyclonedx/cdxgen` |
| Grype | 0.122.1 | Vulnerability database schema v6 |
| OSV-Scanner | 2.7.0 / 2.7.1 | |
| Trivy | 0.76.2 | Vulnerability database schema v2 |

### Installing the scanners

**cdxgen** (via npm):

```bash
npm install -g @cyclonedx/cdxgen
```

**On Windows (via WinGet):**

```powershell
winget install --id Anchore.Grype --accept-source-agreements --accept-package-agreements --silent
winget install --id Google.OSVScanner --accept-source-agreements --accept-package-agreements --silent
winget install --id AquaSecurity.Trivy --accept-source-agreements --accept-package-agreements --silent
```

**On macOS (via Homebrew or binaries):**

```bash
brew install grype osv-scanner trivy
```

On macOS versions without Homebrew bottles (such as macOS 27), download the official release binaries into `~/.local/bin` instead (Trivy: `trivy_<version>_macOS-ARM64.tar.gz` from [aquasecurity/trivy releases](https://github.com/aquasecurity/trivy/releases)):

```bash
mkdir -p ~/.local/bin && cd "$(mktemp -d)"
G=$(curl -s https://api.github.com/repos/anchore/grype/releases/latest | python3 -c "import sys,json;print(json.load(sys.stdin)['tag_name'])")
O=$(curl -s https://api.github.com/repos/google/osv-scanner/releases/latest | python3 -c "import sys,json;print(json.load(sys.stdin)['tag_name'])")
curl -sLo grype.tgz "https://github.com/anchore/grype/releases/download/$G/grype_${G#v}_darwin_arm64.tar.gz" && tar xzf grype.tgz grype
curl -sLo osv-scanner "https://github.com/google/osv-scanner/releases/download/$O/osv-scanner_darwin_arm64"
chmod +x grype osv-scanner && mv grype osv-scanner ~/.local/bin/
```

The pipeline looks for tools in `~/.local/bin`, `/opt/homebrew/bin`, `/usr/local/bin` and your `PATH`.

### Python dependencies

```bash
python3.12 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

### Vulnerability databases

```bash
grype db update   # download or refresh
grype db status   # show build date and validity

trivy fs --download-db-only --timeout 60m   # download or refresh Trivy's DB
trivy version                               # shows the DB's UpdatedAt
```

Trivy's database lives in `~/Library/Caches/trivy/db/` (about 1.8 GB). On slow connections give it a long `--timeout`; the default 5 minutes can expire mid-download.

Grype's is stored in `~/Library/Caches/grype/db/6/vulnerability.db` on macOS. Scans run with auto-update **disabled** for both (`GRYPE_DB_AUTO_UPDATE=false`, `trivy --skip-db-update --skip-check-update`), so a slow download can never stall a scan. Refresh them yourself regularly.

## Usage

### Web UI

```bash
.venv/bin/streamlit run app.py
```

1. Enter a repository URL (`https://github.com/<owner>/<repo>`) or the path to a local folder.
2. Press **Run scan**. A table shows each step's status, result and duration as it runs.
3. When it finishes you get:
   - the status badge (Complete, Incomplete, Failed or Interrupted), the commit scanned, and severity counts;
   - a **Dependency graph** tab with the interactive graph;
   - a **Scan steps & tools** tab with the step results, tool versions and Grype database build date;
   - an **Artifacts** tab with downloads of the SBOM, raw scanner output, `graph.json`, the graph HTML and `scan.json`.
4. Earlier scans are listed in the sidebar; click one to reopen it.

### Command line

The same pipeline without the UI:

```bash
.venv/bin/python -m pipeline.scan https://github.com/juice-shop/juice-shop
```

Rebuild only the graph from an existing SBOM and scanner results:

```bash
.venv/bin/python graph/build_graph.py --repo <repo-dir> \
    --bom <bom.json> --grype <grype.json> --osv <osv.json> \
    --out dependency_graph.html --json graph.json
```

### From Python

```python
from pipeline.scan import run_scan, start_scan, load_scan

meta = run_scan("https://github.com/juice-shop/juice-shop")   # blocking
scan_id = start_scan("https://github.com/owner/repo")         # background thread
print(load_scan(scan_id)["status"])
```

## Outputs

Each scan creates its own folder:

```
data/scans/<owner>__<repo>__<YYYYmmdd-HHMMSS>/
├── scan.json                  # scan record: status, steps, timings, tool versions, DB date, commit
├── repo/                      # the cloned repository (git-ignored)
├── sbom/
│   └── bom.json               # CycloneDX SBOM from cdxgen
├── scanner_results/
│   ├── grype.json             # raw Grype output, unmodified
│   ├── osv.json               # raw OSV-Scanner output, unmodified
│   ├── trivy.json             # raw Trivy output (Trivy masks secret values itself)
│   └── *.stderr / *.stdout    # each tool's log output, kept for debugging
└── graphs/
    ├── graph.json             # machine-readable graph + merged evidence
    └── dependency_graph.html  # interactive graph, self-contained, works offline
├── agents/                    # guardian_v2 output: investigation.json, guardian-report.{json,md}, guardian.sarif
└── report/                    # Final Guardian Report: guardian-report.json / .html / .pdf
```

### `scan.json`

| Field | Meaning |
|---|---|
| `status` | `complete`: every required step succeeded. `incomplete`: the graph was built but a scanner failed or found nothing. `failed`: a fatal step failed. `interrupted`: the server stopped mid-scan. |
| `steps.<name>` | `status` (`ok`, `warn`, `failed`, `skipped`), `detail` and `seconds` for clone, lockfile, sbom, grype, osv, trivy and graph |
| `tools` | Versions of git, npm, cdxgen, grype, osv-scanner and trivy, plus the Grype and Trivy database dates |
| `commit` | Git commit that was scanned |
| `stats` | Package, edge and finding counts, with findings by severity |
| `artifacts` | Paths to every file the scan produced |

### `graph.json` (schema `ssg-dependency-graph/1`)

```jsonc
{
  "schema": "ssg-dependency-graph/1",
  "generated_at": "…", "source": "cdxgen SBOM", "root": "pkg:npm/juice-shop@…",
  "scan":   { "scan_id": "…", "commit": "…", "tools": { … }, "scanner_status": { … } },
  "inputs": { "sbom": "…", "scanner_results": { … }, "scanners_used": ["Grype", "OSV-Scanner", "Trivy"] },
  "stats":  { "nodes": 1134, "edges": 2147, "direct": 98, "transitive": 1010,
              "vulnerable_packages": 20, "findings": 58, "findings_by_severity": { … },
              "misconfigurations": 89, "secrets": 5 },
  "nodes": [{
    "id": "pkg:npm/jsonwebtoken@0.1.0", "name": "jsonwebtoken", "version": "0.1.0",
    "dep_type": "transitive",
    "path_ids": ["pkg:npm/juice-shop@…", "pkg:npm/express-jwt@0.1.3", "pkg:npm/jsonwebtoken@0.1.0"],
    "parent_ids": [ … ], "child_ids": [ … ], "max_sev": "CRITICAL",
    "vulns": [{
      "id": "CVE-2015-9235", "ids": ["CVE-2015-9235", "GHSA-c7hr-j4mj-j2w6"],
      "severity": "CRITICAL", "severity_disagreement": false,
      "source_tools": ["Grype", "OSV-Scanner"],
      "by_tool": {
        "Grype":       { "severity": "CRITICAL", "fixed_versions": ["4.2.2"] },
        "OSV-Scanner": { "severity": "CRITICAL", "fixed_versions": ["4.2.2"] }
      }
    }]
  }],
  "edges": [{ "from": "…", "to": "…" }],
  "unresolved": [ … ],  // components in the SBOM with no dependency link (e.g. CI GitHub Actions)
  "repo_findings": {     // Trivy findings not tied to a package
    "misconfigurations": [{ "id": "DS-0001", "title": "':latest' tag used", "severity": "MEDIUM",
                            "file": "Dockerfile", "start_line": …, "message": "…", "resolution": "…" }],
    "secrets": [{ "rule_id": "private-key", "severity": "HIGH", "file": "lib/insecurity.ts",
                  "start_line": 21, "value": "REDACTED" }]
  }
}
```

## The interactive graph

| Element | Meaning |
|---|---|
| ★ dark star | Root application |
| ● blue | Direct dependency |
| ● grey | Transitive dependency |
| ● purple | In the SBOM but not linked to the tree (for example GitHub Actions from CI workflows) |
| ◆ red, orange, amber, green | Vulnerable package, coloured by worst severity (critical, high, medium, low) |
| amber edges | Path from the root to the focused package |
| teal edges | The focused package's direct dependencies |

**Interactions**
- **Click a package** to highlight its path to the root and its direct dependencies; everything else fades. A detail panel shows:
  - version, ecosystem, purl, and whether the dependency is direct or transitive;
  - the path to the root as clickable steps;
  - every vulnerability with its CVE/GHSA IDs and each scanner's severity and fixed version, flagging single-scanner findings and disagreements;
  - clickable *Depends on* and *Required by* lists.
- **Search** (`/`): ranked results that show name, version, dependency type and severity, so same-named packages in different versions are easy to tell apart. Arrow keys move through results and `Enter` focuses one. A *Vulnerable only* checkbox narrows the list.
- **Severity filter:** shows only critical, high-and-above, and so on, keeping each vulnerable package's path to the root visible.
- **Resume motion / Freeze layout:** the layout is pre-computed and still by default.
- **Fit** resets the view; **`Esc`** clears the focus.

## Project structure

```
.
├── app.py                    # Streamlit UI: start scans, live progress, results, graph, downloads
├── pipeline/
│   ├── scan.py               # pipeline: clone → lockfile → SBOM → scanners → graph → agents; scan.json; background runner
│   ├── agents.py             # bridge: scan folder → guardian_v2 inputs; runs the agents; saves investigation.json
│   └── remediation.py        # Gate 1 → policy → apply → resolve → Docker sandbox (install, test) → re-scan → Gate 2
├── graph/
│   └── build_graph.py        # SBOM + scanner output → NetworkX graph → graph.json + PyVis HTML (+ graph UI)
├── guardian_v2/              # LangGraph multi-agent system (supervisor, agents, critic, CLI with approval gate)
├── agent/                    # earlier agent scaffold (superseded by guardian_v2)
├── data/scans/               # one folder per scan (cloned repos are git-ignored)
├── .streamlit/config.toml    # light theme
├── .claude/launch.json       # dev-server launch config
├── requirements.txt
└── README.md
```

### Key functions

| Function | File | Purpose |
|---|---|---|
| `run_scan(target)` | `pipeline/scan.py` | Runs the whole pipeline and returns the scan record |
| `start_scan(target)` | `pipeline/scan.py` | Same, but in a background thread; returns the `scan_id` |
| `load_scan` / `list_scans` | `pipeline/scan.py` | Read scan records; flag interrupted scans |
| `load_bom` | `graph/build_graph.py` | CycloneDX → `nx.DiGraph`. Never invents nodes or edges. |
| `load_grype` / `load_osv` | `graph/build_graph.py` | Convert raw scanner output into common records |
| `merge_findings` | `graph/build_graph.py` | Match findings across scanners by shared IDs; keep each tool's facts; flag disagreements |
| `annotate` | `graph/build_graph.py` | Direct vs transitive, shortest path to root, parents and children, labels |
| `build` | `graph/build_graph.py` | Writes `graph.json` and the HTML graph |

## Technology choices

| Tool | Why |
|---|---|
| **OWASP cdxgen** | Standard CycloneDX output; covers many ecosystems; lists dependency relationships, not just packages |
| **Grype** | Scans the SBOM itself; offline, versioned database; fast |
| **OSV-Scanner** | Independent data source (osv.dev, live). A second scanner makes it possible to see agreement and disagreement. |
| **NetworkX** | Standard Python graph library: shortest paths, parents and children, ForceAtlas2 layout |
| **PyVis** | Python graph → interactive vis-network HTML with no frontend build step |
| **Streamlit** | Python-only web UI; quick to build, easy to extend into a multi-page dashboard |

Why the layout is computed in Python: laying out about 1,100 nodes in the browser took around 25 seconds on every load and never stopped moving. Python's ForceAtlas2 takes about 10 seconds once, at build time. The vis-network JavaScript is bundled into the HTML so the graph works offline and from `file://`.

## Security model

The target repository is treated as **untrusted input**:

| Risk | Mitigation |
|---|---|
| Malicious install or lifecycle scripts | Nothing from the repo is executed. Lockfiles use `npm --package-lock-only --ignore-scripts`, and cdxgen runs with `--no-install-deps`. |
| Git hooks | Cloned with `-c core.hooksPath=/dev/null`, shallow, no tags, no credential prompts |
| Dockerfiles and CI workflows | Never built or run, only read by cdxgen as data |
| Leaking secrets to tools | Tools run with a minimal environment (`HOME`, `PATH`, `LANG`), so API keys and tokens never reach them |
| Shell injection | All commands use argument lists (`subprocess.run([...])`), never a shell. Only `https://github.com/<owner>/<repo>` URLs or existing folders are accepted. |
| Hung tools | Every step has a timeout (clone 600 s, npm 900 s, cdxgen 900 s, grype 900 s, osv 600 s, trivy 1200 s) |
| Local repos | Copied first, so the generated lockfile never touches your own checkout |
| Unsafe data in the graph page | All package data is HTML-escaped, and embedded JSON is escaped so it can't break out of its script tag |
| Exposing discovered secrets | Secret values are never copied into `graph.json` or shown in the UI (only rule, file and line). Trivy's raw output masks them as well. |
| Misleading "all clear" | A failed or empty scanner step marks the scan *incomplete*; it is never reported as successful |

## Understanding the results

- **Findings are version-specific.** Each advisory lists the versions it affects. A finding means the exact installed version falls in that range, and "fixed in" is where the range ends. Example: `tar` 6.2.1 has 12 findings, while `tar` 7.5.23 in the same tree has none.
- **Results are a snapshot.** They depend on:
  1. the package versions in the repo (and, for repos without a committed lockfile, on the day the lockfile was resolved);
  2. the vulnerability databases at scan time;
  3. the scanner versions.

  `scan.json` records all three so scans can be compared.
- **Scanner disagreement is information.** Examples from Juice Shop:
  - `messageformat@2.3.0` is flagged by OSV-Scanner and Trivy but not Grype. The upstream GitHub advisory gives the affected range as `< 2.3.0` but the first patched version as `3.0.0-beta.0`; Grype follows the range, the other two follow the patched version.
  - `lodash@2.4.2` CVE-2018-3721 is MEDIUM in Grype and OSV-Scanner but LOW in Trivy. The graph shows the worst severity and flags the disagreement.
  - Four findings are Trivy-only `NSWG-ECO-*` IDs (legacy Node Security Working Group advisories). Some likely describe the same flaw as an existing CVE, but no alias links them in the data, so they are kept as separate findings rather than merged on a guess.
  
  The graph never chooses a side: each scanner's verdict is shown.
- **A finding is not proof of exploitability.** It means the version contains a known flaw. Whether the application actually uses the vulnerable code is not determined.
- **No finding is not proof of safety.** It means no known advisory matched in these databases.

## Example results

OWASP Juice Shop, commit `c9f99228d9d5`, scanned 23 Nov 2026 (Grype database built the same day):

| Metric | Value |
|---|---|
| Packages in graph | 1,135 (98 direct, 1,011 transitive, 25 GitHub Actions not linked to the tree) |
| Dependency edges | 2,147 |
| Vulnerable packages | 20 (8 direct, 12 transitive) |
| Vulnerability findings | **58**: 7 critical, 23 high, 26 medium, 2 low |
| Scanner agreement | 53 found by all three · 1 by OSV-Scanner + Trivy (`messageformat`) · 4 Trivy-only (legacy `NSWG-ECO-*` advisories) · 1 severity disagreement (`lodash` CVE-2018-3721: Trivy LOW, others MEDIUM) |
| Misconfigurations | **89** failed checks (20 critical, 22 high), mostly the deliberately insecure Terraform in Juice Shop's challenges, plus the Dockerfile |
| Secrets | **5** (3 private keys, 2 JWTs), values redacted |
| Agent investigation | 11 agents, 9 supervisor turns, 1 handoff; **94** prioritised findings (54 vulnerabilities + 40 non-CVE: deprecated packages, unpinned actions/base images, install scripts, typosquat suspects, suspicious updates); **35** proposed fixes; 12/12 explanations passed the critic |
| Scan time | about 2 min (mostly clone and lockfile resolution; the three scanners together take about 7 s) |

Many of these packages are deliberately outdated, since Juice Shop is an intentionally vulnerable training application.

### Multi-Ecosystem Benchmark Results

The pipeline has been verified across multiple language ecosystems:

| Target Repository | Ecosystem / Manifest | Status | Components | Graph Nodes | Edges | Vulnerabilities Found | Misconfigurations | Secrets |
|---|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **[adeyosemanputra/pygoat](https://github.com/adeyosemanputra/pygoat)** | **Python** (`requirements.txt`, Dockerfile) | `complete` | 62 | 63 | 0 | **369** (29 Crit, 160 High, 144 Med, 32 Low) | 53 | 4 |
| **[praetorian-inc/gokart](https://github.com/praetorian-inc/gokart)** | **Go** (`go.mod`, `go.sum`) | `complete` | 35 | 36 | 9 | **77** (11 Crit, 39 High, 23 Med, 3 Low) | 2 | 0 |
| **[OWASP/wrongsecrets](https://github.com/OWASP/wrongsecrets)** | **Java / Spring Boot** (`pom.xml`) | `complete` | 1,271 | 1,272 | 1,841 | **14** (2 High, 10 Med, 2 Low) | 146 | 12 |
| **[digininja/DVWA](https://github.com/digininja/DVWA)** | **PHP** (`composer.json`) | `complete` | 15 | 16 | 5 | 0 | 4 | 0 |
| **[juice-shop/juice-shop](https://github.com/juice-shop/juice-shop)** | **Node.js / npm** (`package.json`) | `complete` | 1,134 | 1,135 | 2,147 | **58** (7 Crit, 23 High, 26 Med, 2 Low) | 89 | 5 |

## Troubleshooting

| Problem | Cause and fix |
|---|---|
| `AttributeError: 'wrapper_descriptor' object has no attribute '__annotate__'` when importing networkx | Python 3.14.1 incompatibility. Use Python 3.12 for the venv. |
| `brew install grype` → *no bottle available* | No prebuilt Homebrew packages for your macOS version. Use the release binaries ([Installation](#installing-the-scanners)). |
| SBOM has **0 components** | cdxgen needs a lockfile. The pipeline generates one for npm repos; other ecosystems need their lockfile (`poetry.lock`, `go.sum`, …) committed. |
| OSV step says *no lockfiles/packages found* | The repo has no lockfile OSV-Scanner recognises. (Lockfiles excluded by `.gitignore` are already handled with `--no-ignore`.) |
| Grype step fails | The vulnerability database is missing or too old. Run `grype db update`, then check with `grype db status`. |
| Trivy step fails | Its database isn't downloaded (scans skip updates). Run `trivy fs --download-db-only --timeout 60m`. |
| Trivy download fails with *context deadline exceeded* | The default 5-minute timeout expired on a slow connection. Re-run with `--timeout 60m`. |
| `grype db update` or `npm` stalls | Slow or dropped connection. Re-run it; npm caches what it already downloaded, so a retry is faster. |
| cdxgen prints a *SECURE MODE: Environment audit* table | It's warning about secrets in the shell environment. The pipeline already runs cdxgen with a clean environment. |
| Scan shows **Interrupted** | The server restarted mid-scan. Run it again. |
| Groq returns HTTP 403 (error code 1010) | Cloudflare blocks Python's default User-Agent; fixed in `guardian_v2/providers.py`, which now sends one. |
| Groq returns HTTP 404 *model_not_found* | The model was retired; list yours with `GET https://api.groq.com/openai/v1/models` and set `GROQ_MODEL`. |
| Groq returns HTTP 413 / 429 | Request too large or over the tokens-per-minute limit. The explainer batches and retries; a batch that still fails falls back to templates. |
| PDF step says *no Chromium-based browser found* | Install Chrome, or set `GUARDIAN_PDF_BROWSER` to a Chromium-based browser binary. |

## Multi-agent investigation

The last pipeline step hands the finished scan to **`guardian_v2`**, a LangGraph multi-agent system, through
[`pipeline/agents.py`](pipeline/agents.py). It runs unattended in the `analysis` stage: every agent except the human
approval gate and sandbox validation, so a web scan never pauses for input.

**Inputs taken from the scan folder:** the SBOM, the npm lockfile and manifest, `requirements.txt`, Dockerfiles,
`.github/workflows/*`, the source tree (for reachability) and **all three scanners' outputs**:
- `vuln_intel` merges the Grype, OSV-Scanner and Trivy advisories with its own live sources (OSV.dev, npm audit),
  deduplicated by alias.
- `cicd` turns Trivy's misconfigurations and secrets into findings (secret values are never copied).

For Juice Shop, that is 6 of 6 sources and 188 findings.

**How the supervisor works.** Each turn, the supervisor (the head agent) picks which agents run, from:
1. which agents have new inputs to work on;
2. requests agents send each other through the supervisor (for example, anomaly asking reachability whether a suspicious package is imported);
3. optionally, an LLM planner whose choice is checked by guardrails.

Every decision and message is logged.

| Agent | Role |
|---|---|
| discovery | SBOM + lockfiles → inventory and dependency graph |
| cicd | Unpinned base images and GitHub Actions, unsafe workflows, plus Trivy misconfigurations and secrets |
| vuln_intel | Advisories from Grype, OSV-Scanner, Trivy, OSV.dev, npm audit, PyPI (and GHSA with `GITHUB_TOKEN`), deduplicated by alias |
| reputation | Registry metadata: yanked/deprecated versions, maintainers, integrity, install scripts |
| reachability | Is each package imported by the source code? |
| exploit_intel | CISA KEV and FIRST EPSS |
| anomaly | Typosquats (long-established packages are cleared automatically), malicious packages, lockfile tampering, untrusted URLs, dependency confusion |
| scoring | Explainable risk score, confidence and a simplified SSVC decision |
| remediation | Verified safe versions and the other packages that must be upgraded with them (proposed only) |
| explainer | LLM explanations when a key is set (Anthropic → Groq → Gemini), sent in batches of 6 with rate-limit retries. It explains the top 12 findings plus the worst finding of every other type; deterministic templates otherwise. |
| critic | Rejects claims with missing or unlinked evidence, IDs that aren't aliases of the finding, changed CVSS or KEV values, unverified versions, or exploitation claims without KEV evidence |

**In the UI**, the *Agent investigation* tab shows the agent conversation, prioritised findings (score, SSVC,
reachability, KEV, EPSS), the critic-checked explanations and the proposed fixes.

**In the graph**, clicking a package shows an *Agent assessment* section below the scanner evidence: risk score,
SSVC, confidence, reachability, supply-chain signals, the critic-verified LLM explanation (labelled "LLM ·
critic-verified" or "template") and the proposed fix. Packages the agents flag as anomalies get a magenta ring and
their own filter option. Outputs are saved in
`data/scans/<scan>/agents/`: `investigation.json`, `guardian-report.json`, `guardian-report.md`, `guardian.sarif`,
`guardian-sbom.cdx.json` and `dependency-graph.mmd`.

**LLM keys** (optional) come from the environment or a `.env` file: `ANTHROPIC_API_KEY`, `GROQ_API_KEY` or
`GEMINI_API_KEY`. `GITHUB_TOKEN` enables the GHSA source. Without keys, everything still runs, with template
explanations.

Groq's default model is `openai/gpt-oss-120b`; override it with `GROQ_MODEL`. On Groq's free tier (8,000 tokens
per minute) the explainer takes about 80 s for Juice Shop, because it waits between batches as Groq asks.

## Final Guardian Report

The last pipeline step ([`reporting/guardian_report.py`](reporting/guardian_report.py)) turns the scan and the
agents' results into **`report/guardian-report.json`, `.html` and `.pdf`**. The PDF is printed from the HTML by
headless Chrome, Brave, Chromium or Edge; set `GUARDIAN_PDF_BROWSER` to choose one. The UI's *Final report* tab shows
the report with download buttons.

**Every finding is a Pydantic model** with the problem statement's schema (`finding_id`, `category`, `component`,
`installed_version`, `identifier`, `severity`, `source_tool`, `dependency_type`, `dependency_path`,
`evidence_reference`, `fixed_version`, `ai_assessment`, `confidence`, `verification_status`) plus `problem`,
`remediation`, `risk_score`, `ssvc`, `reachability`, `kev`, `epss` and each scanner's view.

**The evidence validator gates every finding.** It rejects any finding whose CVE/GHSA ID isn't in raw scanner output
or an authoritative advisory API, whose version isn't in the SBOM or lockfile, whose dependency path isn't made of
real graph edges, whose fixed version no source reported, or whose secret carries a value. Rejected findings are
listed in the report, not silently dropped (Juice Shop: 188 accepted, 0 rejected).

**Verification status** separates confirmed facts from indicators and hypotheses:

| Status | Meaning |
|---|---|
| `multi_scanner_confirmed` | Two or more scanners agree |
| `scanner_confirmed` | One scanner |
| `authoritative_source` | An advisory API only |
| `registry_confirmed` | Registry metadata, e.g. deprecated |
| `static_check` | A CI/CD or container rule |
| `suspicious_indicator` | A signal worth investigating |
| `potential_risk` | Risky but possibly legitimate, e.g. install scripts |
| `unverified_hypothesis` | A typosquat candidate |

**Report sections:**
1. executive summary (severity counts, findings per category, top risks, AI usage);
2. scope and methodology (every pipeline step and tool version);
3. SBOM statistics;
4. dependency analysis (depth, which direct dependencies pull in vulnerable code, shared vulnerable packages);
5. risk prioritisation;
6. **one section per risk category**: known vulnerabilities, malicious packages, typosquat candidates, lockfile and
   integrity risks, install-time scripts, suspiciously recent releases, deprecated/yanked versions, CI/CD workflow
   risks, container image risks, misconfigurations, exposed secrets. Each section opens with *the problem* in plain
   language, then a card per finding with the problem, dependency path or file location, each scanner's view,
   verification status, the agents' risk score, the LLM analysis (critic-verified) and the agents' remediation;
7. scanner agreement and disagreements;
8. remediation plan;
9. evidence validation;
10. limitations.

**Network use.** The agents query the npm, PyPI and OSV registries plus KEV and EPSS. To keep this practical on slow
links, registry metadata is fetched only for direct dependencies and packages a scanner flagged (98 + about 20 for
Juice Shop, instead of 1,135). Responses are cached in `data/agent_cache/` and reused across scans.

**Governance controls** (merged from `feature/v2-multi-agent-architecture`):
- Every agent turn is sealed into a SHA-256 hash-chained audit trail (`agents/audit.jsonl`). Agents in the same
  turn emit events that the supervisor seals in a fixed order, so the chain stays verifiable when agents run in parallel.
- A deterministic policy firewall (`guardian_v2/policy.py`, mirrored as OPA rules in `policies/`) keeps merge,
  publish and deploy human-only, and only allows changes on `guardian/*` branches with Gate 1 approval.
- The agents' report also includes OpenVEX "not affected" statements and an in-toto statement
  (`guardian.openvex.json`, `guardian.in-toto.json`).

## Human-in-the-loop remediation (sandboxed)

The UI's **Remediation review** tab ([`pipeline/remediation.py`](pipeline/remediation.py)) turns the agents'
proposed fixes into verified changes. Nothing touches your code, gets pushed or gets merged.

1. **Gate 1, human approval.** The reviewer sees every plan (component, action, target version, CVEs it clears,
   blockers, risk) and ticks the ones to approve. Unticked plans are recorded as rejected, under the reviewer's name.
   - *Sandbox* rows are npm package changes the system applies and tests.
   - *Manual* rows (pinning actions or images, rotating secrets, fixing config, transitive removals) become a
     checklist in the draft PR.
2. **Sandbox validation** (runs in the background; the page shows live progress):
   1. **Policy firewall:** `pkg.apply`, `docker.build` and `test.run` must be allowed on a
      `guardian/remediation-*` branch with Gate 1.
   2. **Apply** to a *copy* of `package.json`: direct dependencies get the new version; packages pulled in
      indirectly are forced with npm `overrides`.
   3. **Resolve** the new lockfile with `npm install --package-lock-only --ignore-scripts`. This only reads
      metadata; no package code runs.
   4. **Verify** the target versions are in the new lockfile and the vulnerable versions are gone.
   5. **Sandbox install** in Docker (`node:22-slim`): network on so packages can download, install scripts **off**.
   6. **Sandbox test:** each upgraded package's code is loaded in a container with **no network, a read-only
      filesystem, all capabilities dropped, a non-root user and pid/memory/CPU limits**.
   7. **Re-scan** the new lockfile with OSV-Scanner: vulnerabilities before and after, cleared, remaining and
      newly introduced.
3. **Gate 2, human approval of the validated change.** The firewall must allow a **draft** PR. The system then
   writes `remediation/guardian-remediation.patch`, `package-lock.remediated.json` and `PR_DRAFT.md`, which holds
   the changes, the validation evidence, the manual-task checklist and the audit-chain head. Merging stays
   human-only.

Every human decision, policy verdict and sandbox result is appended to `remediation/audit.jsonl`, a hash chain
whose integrity the tab checks and displays.

Juice Shop example (approving `jsonwebtoken@0.4.0` → 9.0.0, `lodash` → 4.18.1, `moment` → 2.31.0):
- all steps pass, and all 3 packages load in the network-less sandbox;
- known vulnerabilities go from **54 to 43** (11 cleared, 0 newly introduced);
- the whole run takes about 10 s.

**Requires** Docker Desktop (or another Docker engine) running. Without it, the sandbox steps are reported as
skipped and the other steps still run. Only npm changes are executed in the web sandbox; other ecosystems are
handled as manual tasks. The CLI flow (`guardian_v2/run_guardian.py`, which pauses for a reviewer in the terminal)
is still available.

## Roadmap

Done in this version: discovery and cloning, SBOM generation, Grype, OSV-Scanner and Trivy scanning (vulnerabilities, misconfigurations, secrets), dependency graph analysis, the interactive graph, the web UI, and the LangGraph multi-agent investigation (supervisor, specialist agents, evidence critic) connected to the pipeline and fed by all three scanners, the agents' assessment in the graph, the evidence-validated Final Guardian Report (JSON, HTML, PDF), the hash-chained audit trail and policy firewall, and human-in-the-loop remediation with sandboxed validation.

Planned, following the hackathon problem statement:

- [ ] Sandbox execution for PyPI / Go / Maven changes (npm only today)
- [ ] Run the project's own test suite in the sandbox (today: install + load each changed package)
- [ ] **Multi-page dashboard**: overview, SBOM explorer, vulnerabilities, anomalies, agent activity, report
- [ ] **SQLite** storage for scan history

## Agent implementations

- [`guardian_v2/`](guardian_v2/) - LangGraph Day 1 and Day 2 architecture.
- [`agent/`](agent/) - earlier 12-node agent scaffold and verification pipeline.

Run the Day 1 demo:

```bash
cd guardian_v2
PYTHONPATH=. python run_guardian.py --config demo-app/guardian-day1.json --day1
```

#!/usr/bin/env python3
"""
Blast radius + attack path analysis from an ssg-dependency-graph JSON and scanner output.

    python ssg_analysis.py --graph graph.json --grype grype.json --osv osv.json \
        --trivy trivy.json --out reports/

Only --graph is required. Grype / OSV-Scanner / Trivy files enrich findings with
CVSS, EPSS, CWE, descriptions and fix versions; Trivy also supplies secrets and
misconfigurations. Writes blast_radius_report.md and attack_path_report.md.
Standard library only.
"""
import argparse, collections, json, math, os
from collections import defaultdict, deque

SEV_WEIGHT = {"CRITICAL": 1.0, "HIGH": 0.75, "MEDIUM": 0.5, "LOW": 0.25}
SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
# Score = 100 * weighted sum of components in [0,1]; weights are tunable.
W = dict(severity=0.35, exploit=0.25, proximity=0.15, spread=0.15, volume=0.10)
TIERS = [(60, "CRITICAL"), (45, "HIGH"), (30, "MEDIUM"), (0, "LOW")]
EPSS_SATURATION = 0.20  # an EPSS of 20% or more counts as fully exploitable

CWE_CLASS = {
    "Code / command injection": {77, 78, 94, 95},
    "Authentication / authorization bypass": {285, 287, 288, 290, 294, 306, 345, 347, 863, 1259},
    "Weak cryptography": {327, 328, 330, 331, 334, 338, 916},
    "Path traversal / arbitrary file write": {22, 23, 59},
    "Cross-site scripting": {79, 80},
    "Prototype pollution": {1321, 471},
    "Denial of service": {400, 405, 674, 770, 835, 1333, 248, 704},
    "Information exposure": {200, 538},
    "Memory safety": {125, 787, 823},
}


def load(path):
    if path and os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    return None


def short(pid):
    return pid.split("/", 1)[1] if pid.startswith("pkg:") and "/" in pid else pid


def vkey(v):
    out = []
    for part in str(v).replace("-", ".").split("."):
        out.append(int(part) if part.isdigit() else 0)
    return tuple(out)


def cwe_class(cwes):
    for c in cwes or []:
        try:
            n = int(str(c).upper().replace("CWE-", ""))
        except ValueError:
            continue
        for name, ids in CWE_CLASS.items():
            if n in ids:
                return name
    return "Other / unclassified"


def md_table(headers, rows):
    esc = lambda x: str(x).replace("|", "/").replace("\n", " ")
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    lines += ["| " + " | ".join(esc(c) for c in r) + " |" for r in rows]
    return "\n".join(lines)


# ---------------------------------------------------------------- enrichment
def index_grype(g):
    idx = defaultdict(list)
    for m in (g or {}).get("matches", []):
        a, v = m["artifact"], m["vulnerability"]
        rel = m.get("relatedVulnerabilities") or []
        cv = (v.get("cvss") or []) + [c for r in rel for c in (r.get("cvss") or [])]
        best = max(cv, key=lambda c: c["metrics"].get("baseScore", 0)) if cv else None
        ep = (v.get("epss") or [{}])[0]
        idx[(a["name"], a["version"])].append(dict(
            ids={v["id"]} | {r["id"] for r in rel},
            cvss=best["metrics"].get("baseScore") if best else None,
            epss=ep.get("epss"), risk=v.get("risk"),
            cwes=[c.get("cwe") for c in v.get("cwes") or []],
            desc=v.get("description") or next((r.get("description") for r in rel if r.get("description")), "")))
    return idx


def index_trivy(t):
    idx = defaultdict(list)
    for r in (t or {}).get("Results", []):
        for v in r.get("Vulnerabilities") or []:
            scores = [s.get("V3Score") for s in (v.get("CVSS") or {}).values() if s.get("V3Score")]
            idx[(v.get("PkgName"), v.get("InstalledVersion"))].append(dict(
                ids={v.get("VulnerabilityID")}, cvss=max(scores) if scores else None, epss=None, risk=None,
                cwes=v.get("CweIDs") or [], desc=v.get("Title") or v.get("Description") or ""))
    return idx


def index_osv(o):
    idx = defaultdict(list)
    for r in (o or {}).get("results", []):
        for p in r.get("packages", []):
            pk = p.get("package", {})
            for v in p.get("vulnerabilities", []):
                idx[(pk.get("name"), pk.get("version"))].append(dict(
                    ids={v.get("id"), *v.get("aliases", [])}, cvss=None, epss=None, risk=None,
                    cwes=(v.get("database_specific") or {}).get("cwe_ids") or [],
                    desc=v.get("summary") or ""))
    return idx


def enrich(vuln, key, indexes):
    """Merge the first non-empty value per field across Grype > Trivy > OSV."""
    out = dict(cvss=None, epss=None, risk=0.0, cwes=[], desc="")
    ids = set(vuln["ids"])
    for idx in indexes:
        for e in idx.get(key, []):
            if ids & e["ids"]:
                for f in ("cvss", "epss", "desc"):
                    if out[f] in (None, "") and e.get(f) not in (None, ""):
                        out[f] = e[f]
                if not out["cwes"] and e["cwes"]:
                    out["cwes"] = e["cwes"]
                if e.get("risk"):
                    out["risk"] = max(out["risk"], e["risk"])
    return out


def suggest_fix(installed, vuln):
    """Smallest fixed version above the installed one, preferring the same major line."""
    fixes = {f for t in vuln["by_tool"].values() for f in t.get("fixed_versions", [])}
    above = sorted((f for f in fixes if vkey(f) > vkey(installed)), key=vkey)
    same = [f for f in above if vkey(f)[:1] == vkey(installed)[:1]]
    return (same or above or [None])[0]


# ---------------------------------------------------------------- analysis
def analyse(graph, indexes, max_paths):
    nodes = {n["id"]: n for n in graph["nodes"]}
    ch, pa = defaultdict(list), defaultdict(list)
    for e in graph["edges"]:
        ch[e["from"]].append(e["to"])
        pa[e["to"]].append(e["from"])
    root = graph["root"]

    def reach(x, adj):
        seen, q = set(), deque([x])
        while q:
            for nxt in adj[q.popleft()]:
                if nxt not in seen:
                    seen.add(nxt)
                    q.append(nxt)
        return seen

    def paths_to(target):
        out, q, truncated = [], deque([(target, [target])]), False
        while q:
            node, p = q.popleft()
            if node == root:
                out.append(p[::-1])
                if len(out) >= max_paths:
                    truncated = bool(q)
                    break
                continue
            for up in pa[node]:
                if up not in p:
                    q.append((up, p + [up]))
        return out, truncated

    pkgs = []
    for n in graph["nodes"]:
        if not n.get("vulns"):
            continue
        key = (n["name"], n["version"])
        cves = []
        for v in n["vulns"]:
            e = enrich(v, key, indexes)
            cves.append(dict(id=v["id"], sev=v["severity"].upper(), cvss=e["cvss"], epss=e["epss"],
                             risk=e["risk"], cwe=e["cwes"][0] if e["cwes"] else None,
                             cls=cwe_class(e["cwes"]), desc=e["desc"][:120], fix=suggest_fix(n["version"], v)))
        cves.sort(key=lambda c: (-SEV_ORDER[::-1].index(c["sev"]) if c["sev"] in SEV_ORDER else 0, -(c["cvss"] or 0)))
        anc, desc = reach(n["id"], pa), reach(n["id"], ch)
        direct = [a for a in anc if nodes[a]["dep_type"] == "direct"]
        if n["dep_type"] == "direct":
            direct = [n["id"]]
        ps, trunc = paths_to(n["id"])
        pkgs.append(dict(
            id=n["id"], name=n["name"], ver=n["version"], label=f'{n["name"]}@{n["version"]}', sev=n["max_sev"],
            dep_type=n["dep_type"], scope=n.get("scope") or "-", cves=cves, paths=ps, trunc=trunc,
            hops=min(len(p) for p in ps) - 1 if ps else 0, dependents=[short(a) for a in anc if a != root],
            subtree=[short(d) for d in desc], entry=sorted(short(d) for d in direct),
            max_cvss=max([c["cvss"] or 0 for c in cves]), max_epss=max([c["epss"] or 0 for c in cves]),
            grype_risk=max([c["risk"] or 0 for c in cves])))
    top_span = max([len(p["dependents"]) + len(p["subtree"]) for p in pkgs] or [1])
    for p in pkgs:
        sev = max(SEV_WEIGHT.get(p["sev"], 0), p["max_cvss"] / 10)
        comp = dict(severity=sev, exploit=min(1, p["max_epss"] / EPSS_SATURATION),
                    proximity=1 / (1 + 0.1 * max(p["hops"] - 1, 0)),
                    spread=math.log10(1 + len(p["dependents"]) + len(p["subtree"])) / math.log10(1 + top_span),
                    volume=min(1, len(p["cves"]) / 10))
        p["score"] = round(100 * sum(W[k] * comp[k] for k in W), 1)
        p["components"] = {k: round(v, 3) for k, v in comp.items()}   # kept for the UI's score breakdown
        p["tier"] = next(t for lim, t in TIERS if p["score"] >= lim)
    pkgs.sort(key=lambda p: -p["score"])
    return nodes, root, pkgs


def environment(trivy):
    sec, mis, iac = [], [], collections.Counter()
    for r in (trivy or {}).get("Results", []):
        for s in r.get("Secrets") or []:
            sec.append((r["Target"], s.get("Title"), s.get("Severity")))
        for m in r.get("Misconfigurations") or []:
            if r["Target"].lower().endswith(("dockerfile",)):
                mis.append((r["Target"], f'{m.get("ID")}: {m.get("Title")}', m.get("Severity")))
            else:
                iac[m.get("Severity")] += 1
    return sec, mis, iac


def fix_plan(pkgs):
    by = defaultdict(list)
    for p in pkgs:
        for e in p["entry"]:
            by[e].append(p)
    rows = []
    for entry, ps in by.items():
        rank = lambda s_: SEV_ORDER.index(s_) if s_ in SEV_ORDER else len(SEV_ORDER)   # UNKNOWN etc. sort last
        worst = min(ps, key=lambda p: rank(p["sev"]))["sev"]
        rows.append((entry, sum(len(p["cves"]) for p in ps), worst, ps))
    return sorted(rows, key=lambda r: (-r[1], SEV_ORDER.index(r[2]) if r[2] in SEV_ORDER else len(SEV_ORDER)))


# ---------------------------------------------------------------- reports
def header(graph, title):
    st, sc = graph["stats"], graph.get("scan", {})
    tools = ", ".join(graph["inputs"].get("scanners_used", []))
    sevs = ", ".join(f"{v} {k}" for k, v in st.get("findings_by_severity", {}).items())
    return [f"# {title}", "",
            f"**Target:** {short(graph['root'])}" + (f"  \n**Source:** {sc['target']} @ `{sc['commit'][:8]}`" if sc.get("target") else ""),
            f"**Graph generated:** {graph['generated_at'][:10]}  \n**Scanners in graph:** {tools}",
            f"**Scale:** {st['nodes']} packages, {st['edges']} dependency edges "
            f"({st['direct']} direct, {st['transitive']} transitive)  \n"
            f"**Findings:** {st['findings']} across {st['vulnerable_packages']} vulnerable packages ({sevs})", ""]


def blast_report(graph, pkgs, sec, mis, iac, top):
    L = header(graph, "Blast Radius Report")
    crit = [p for p in pkgs if p["tier"] in ("CRITICAL", "HIGH")]
    L += ["## 1. Summary", "",
          f"- {len(crit)} of {len(pkgs)} vulnerable packages score CRITICAL or HIGH on blast radius.",
          f"- Highest scoring: " + ", ".join(f"`{p['label']}` ({p['score']})" for p in pkgs[:3]) + ".",
          f"- Widest reach: `{max(pkgs, key=lambda p: len(p['dependents']) + len(p['subtree']))['label']}` "
          f"({len(max(pkgs, key=lambda p: len(p['dependents']) + len(p['subtree']))['dependents'])} dependents above, "
          f"{len(max(pkgs, key=lambda p: len(p['dependents']) + len(p['subtree']))['subtree'])} packages below).",
          "", "## 2. How the score works", "",
          "Blast radius is a 0-100 score combining five components: "
          + ", ".join(f"{k} ({int(v * 100)}%)" for k, v in W.items()) + ". "
          "*Severity* is the higher of worst CVSS/10 and the severity band; *exploit* is worst EPSS scaled so "
          f"{int(EPSS_SATURATION * 100)}% counts as 1.0; *proximity* decays with hops from the application; "
          "*spread* is the log-scaled count of dependents plus sub-dependencies; *volume* is findings/10 (capped). "
          f"Tiers: CRITICAL >= {TIERS[0][0]}, HIGH >= {TIERS[1][0]}, MEDIUM >= {TIERS[2][0]}.", "",
          "## 3. Ranked packages", ""]
    L.append(md_table(["#", "Package", "Tier", "Score", "Worst sev", "Findings", "Max CVSS", "Max EPSS", "Hops",
                       "Dependents", "Subtree", "Via direct dependency"],
                      [(i + 1, f"`{p['label']}`", p["tier"], p["score"], p["sev"], len(p["cves"]), p["max_cvss"] or "-",
                        f"{p['max_epss'] * 100:.1f}%" if p["max_epss"] else "-", p["hops"], len(p["dependents"]),
                        len(p["subtree"]), ", ".join(p["entry"])) for i, p in enumerate(pkgs)]))
    L += ["", f"## 4. Detail for the top {min(top, len(pkgs))} packages", ""]
    for p in pkgs[:top]:
        classes = sorted({c["cls"] for c in p["cves"]})
        L += [f"### {p['label']} - {p['tier']} ({p['score']})", "",
              f"- **Type:** {p['dep_type']} dependency, cdxgen scope `{p['scope']}`, {p['hops']} hop(s) from the app",
              f"- **Exposure classes:** {', '.join(classes)}",
              f"- **Dependents (blast upward):** {len(p['dependents'])}"
              + (f" - {', '.join(f'`{d}`' for d in p['dependents'][:8])}" + (" ..." if len(p["dependents"]) > 8 else "") if p["dependents"] else ""),
              f"- **Sub-dependencies (blast downward):** {len(p['subtree'])}"
              + (f" - {', '.join(f'`{d}`' for d in p['subtree'][:8])}" + (" ..." if len(p["subtree"]) > 8 else "") if p["subtree"] else ""),
              f"- **Fix:** " + (f"upgrade to at least `{max((c['fix'] for c in p['cves'] if c['fix']), key=vkey)}`"
                                if any(c["fix"] for c in p["cves"]) else "no fixed version reported"), ""]
        L.append(md_table(["Finding", "Severity", "CVSS", "EPSS", "Class", "Fixed in", "Summary"],
                          [(c["id"], c["sev"], c["cvss"] or "-", f"{c['epss'] * 100:.2f}%" if c["epss"] else "-",
                            c["cls"], c["fix"] or "-", c["desc"]) for c in p["cves"]]))
        L.append("")
    L += ["## 5. Fix leverage by direct dependency", "",
          "Upgrading one direct dependency can clear every finding beneath it. Check that the new release actually pins "
          "patched transitive versions, or use package-manager overrides.", ""]
    L.append(md_table(["Direct dependency", "Findings cleared", "Worst", "Vulnerable packages beneath it"],
                      [(f"`{e}`", n, w, ", ".join(f"`{p['label']}`" for p in ps)) for e, n, w, ps in fix_plan(pkgs)]))
    L += ["", "## 6. Environment amplifiers (Trivy)", ""]
    if sec or mis or iac:
        if sec:
            L += ["**Secrets in the repository**", "", md_table(["File", "Type", "Severity"], sec), ""]
        if mis:
            L += ["**Dockerfile misconfigurations**", "", md_table(["File", "Issue", "Severity"], mis), ""]
        if iac:
            L += [f"**Infrastructure-as-code misconfigurations:** " + ", ".join(f"{v} {k}" for k, v in iac.items()), ""]
    else:
        L += ["No Trivy results supplied, or none found.", ""]
    L += ["## 7. Limitations", "",
          "- Blast radius here is dependency-graph impact. It does not prove the vulnerable code is called.",
          "- Missing CVSS/EPSS (for example advisories without a CVE) lowers the score, so check those manually.",
          "- cdxgen `scope` is informational and not used in the score."]
    return "\n".join(L) + "\n"


def attack_report(graph, root, pkgs, sec, top_paths=3):
    L = header(graph, "Attack Path Report")
    total = sum(len(p["paths"]) for p in pkgs)
    L += ["## 1. Summary", "",
          f"- {total} distinct dependency paths lead from `{short(root)}` to {len(pkgs)} vulnerable packages "
          f"(longest shortest-path: {max(p['hops'] for p in pkgs)} hops).",
          f"- {sum(1 for p in pkgs if p['dep_type'] == 'direct')} vulnerable packages are direct dependencies, so there is no "
          "intermediary between them and the application.",
          "- A path shows how a flaw is *reachable in the dependency tree*. Whether it is exploitable depends on how the code uses the package.", "",
          "## 2. Entry points", "",
          "Direct dependencies through which vulnerable code enters the application.", ""]
    L.append(md_table(["Direct dependency", "Vulnerable packages reached", "Findings", "Worst"],
                      [(f"`{e}`", ", ".join(f"`{p['label']}`" for p in ps), n, w) for e, n, w, ps in fix_plan(pkgs)]))
    # chokepoints
    choke = defaultdict(set)
    for p in pkgs:
        for path in p["paths"]:
            for mid in path[1:-1]:
                choke[mid].add(p["id"])
    byid = {p["id"]: p for p in pkgs}
    rows = sorted(((short(m), len(t), sum(len(byid[x]["cves"]) for x in t)) for m, t in choke.items()),
                  key=lambda r: (-r[2], -r[1]))[:10]
    L += ["", "## 3. Chokepoints", "",
          "Intermediate packages that sit on the paths to several vulnerable packages. Fixing or replacing one breaks all of them.", ""]
    L.append(md_table(["Package", "Vulnerable targets behind it", "Findings behind it"], [(f"`{a}`", b, c) for a, b, c in rows]) if rows else "None: every vulnerable package is a direct dependency.")
    # by attack class
    by_cls = defaultdict(list)
    for p in pkgs:
        for cls in {c["cls"] for c in p["cves"]}:
            by_cls[cls].append(p)
    L += ["", "## 4. Attack paths by exposure class", "",
          "Classes come from each finding's CWE. Chains read from the application to the vulnerable package (in bold).", ""]
    for cls, ps in sorted(by_cls.items(), key=lambda kv: -max(p["score"] for p in kv[1])):
        L += [f"### {cls}", ""]
        for p in sorted(ps, key=lambda p: -p["score"]):
            hits = [c for c in p["cves"] if c["cls"] == cls]
            best = max(hits, key=lambda c: c["cvss"] or 0)
            L.append(f"**`{p['label']}`** - {len(hits)} finding(s), worst {best['id']} "
                     f"(CVSS {best['cvss'] or 'n/a'}, EPSS {best['epss'] * 100:.1f}%)" if best["epss"] else
                     f"**`{p['label']}`** - {len(hits)} finding(s), worst {best['id']} (CVSS {best['cvss'] or 'n/a'})")
            L.append("")
            for path in p["paths"][:top_paths]:
                chain = " → ".join(f"`{short(x)}`" for x in path[:-1]) + (" → " if len(path) > 1 else "") + f"**`{short(path[-1])}`**"
                L.append(f"- {chain}")
            more = len(p["paths"]) - top_paths
            if more > 0 or p["trunc"]:
                L.append(f"- ...{max(more, 0)} more path(s){' (path search truncated)' if p['trunc'] else ''}")
            L.append("")
    L += ["## 5. Environment amplifiers", ""]
    if sec:
        L += ["Secrets in the repository can widen the damage once a path is exploited:", "",
              md_table(["File", "Type", "Severity"], sec), ""]
    else:
        L += ["No secrets reported.", ""]
    L += ["## 6. Limitations", "",
          "- Paths are derived from the SBOM graph, not from runtime call analysis.",
          "- Exposure classes depend on CWE data; findings without a CWE appear as unclassified.",
          "- Path enumeration is capped per package; truncation is flagged where it applies."]
    return "\n".join(L) + "\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--graph", required=True)
    ap.add_argument("--grype"); ap.add_argument("--osv"); ap.add_argument("--trivy")
    ap.add_argument("--out", default="reports")
    ap.add_argument("--top", type=int, default=10, help="packages to detail in the blast radius report")
    ap.add_argument("--max-paths", type=int, default=50, help="path cap per vulnerable package")
    a = ap.parse_args()
    graph = load(a.graph)
    trivy = load(a.trivy)
    indexes = [index_grype(load(a.grype)), index_trivy(trivy), index_osv(load(a.osv))]
    nodes, root, pkgs = analyse(graph, indexes, a.max_paths)
    sec, mis, iac = environment(trivy)
    os.makedirs(a.out, exist_ok=True)
    for name, text in (("blast_radius_report.md", blast_report(graph, pkgs, sec, mis, iac, a.top)),
                       ("attack_path_report.md", attack_report(graph, root, pkgs, sec))):
        with open(os.path.join(a.out, name), "w", encoding="utf-8") as f:
            f.write(text)
        print("wrote", os.path.join(a.out, name))


if __name__ == "__main__":
    main()

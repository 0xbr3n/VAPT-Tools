"""Consolidate per-instance findings into one finding per vulnerability.

Fortify-style reporting: a single vulnerability is ONE finding whose affected
files/lines are all listed together — not hundreds of near-identical rows for
the same issue. Grouping rules:

  * Dependency findings  -> one finding per CVE/advisory id (every affected
    manifest/component listed together), because a CVE is the unit you track.
  * Code findings        -> one finding per vulnerability category (e.g. all
    "SQL Injection" locations across the codebase collapse into one finding).

Each consolidated finding carries:
  * locations : every affected "file:line" (deduplicated, sorted)
  * examples  : up to MAX_EXAMPLES locations that include a code snippet, so
                the report shows a couple of representative samples rather than
                every single occurrence.

The per-instance findings are still written to findings.json / findings.csv as
working-paper evidence — only the human-facing HTML/PDF report is consolidated.
"""
from __future__ import annotations

from collections import defaultdict

from .dedupe import CVE_RE
from .model import Finding, SEVERITIES

MAX_EXAMPLES = 3


def _sev_rank(s: str) -> int:
    return SEVERITIES.index(s) if s in SEVERITIES else 2


def _group_key(f: Finding):
    """Return the consolidation key for a finding.

    Dependency findings collapse by CVE (one CVE across every affected file is
    ONE finding). Code findings collapse by category + rule, so the SAME issue
    spread across many files becomes one finding, but two genuinely different
    checks that merely share a category stay as separate findings (otherwise
    their individual titles/details would be lost)."""
    cve = CVE_RE.search(f.rule_id + " " + f.title)
    if f.category == "Vulnerable Dependency":
        if cve:
            return ("cve", cve.group(1).upper())
        # component without a parsed CVE id — group by the manifest/component
        return ("dep", f.file.lower())
    return ("cat", f.category, f.rule_id or f.title)


def _ref_links(cwes, cve_ids, extra_refs):
    """Build clickable reference links for the report: authoritative CWE (MITRE)
    and CVE/GHSA (NVD / GitHub Advisory) pages, plus any tool-supplied URLs."""
    links = []
    for c in cwes:
        links.append({"label": f"CWE-{c}",
                      "url": f"https://cwe.mitre.org/data/definitions/{c}.html"})
    for cid in cve_ids:
        if cid.upper().startswith("CVE-"):
            links.append({"label": cid,
                          "url": f"https://nvd.nist.gov/vuln/detail/{cid}"})
        elif cid.upper().startswith("GHSA-"):
            links.append({"label": cid,
                          "url": f"https://github.com/advisories/{cid}"})
    # tool-supplied http(s) references not already covered
    for r in extra_refs:
        for tok in str(r).replace(",", " ").split():
            if tok.startswith("http") and not any(tok == l["url"] for l in links):
                links.append({"label": tok, "url": tok})
    return links


def _dedup_keep_order(items):
    seen, out = set(), []
    for it in items:
        if it not in seen:
            seen.add(it)
            out.append(it)
    return out


def _pick_examples(members: list[Finding]):
    """Up to MAX_EXAMPLES representative snippets, preferring distinct files and
    the most severe / highest-confidence instances first."""
    ranked = sorted(
        members,
        key=lambda f: (_sev_rank(f.severity),
                       0 if f.confidence == "high" else 1,
                       f.file, f.line),
    )
    examples, seen_files = [], set()
    for f in ranked:
        if not f.snippet:
            continue
        if f.file in seen_files:
            continue
        seen_files.add(f.file)
        examples.append({"file": f.file, "line": f.line,
                         "end_line": f.end_line or f.line, "snippet": f.snippet})
        if len(examples) >= MAX_EXAMPLES:
            break
    # if not enough distinct-file snippets, top up allowing repeats
    if len(examples) < MAX_EXAMPLES:
        for f in ranked:
            if not f.snippet:
                continue
            entry = {"file": f.file, "line": f.line,
                     "end_line": f.end_line or f.line, "snippet": f.snippet}
            if entry not in examples:
                examples.append(entry)
            if len(examples) >= MAX_EXAMPLES:
                break
    return examples


def _rollup_dependencies(dep_findings: list[dict]) -> dict:
    """Merge every per-CVE dependency finding into ONE collapsible finding:
    'Vulnerable and Outdated Components'. The summary then shows a single row;
    expanding it reveals the full per-library / per-CVE breakdown table."""
    # gather every component row across all dependency findings
    rows, seen = [], set()
    for d in dep_findings:
        for c in d.get("components", []):
            k = (c["component"], c["version"], c["file"], c.get("cve", ""))
            if k in seen:
                continue
            seen.add(k)
            rows.append(c)
    rows.sort(key=lambda c: (_sev_rank_none, c["component"].lower(), c["version"]))

    severity = min((d["severity"] for d in dep_findings), key=_sev_rank)
    n_comp = len({(c["component"], c["version"]) for c in rows}) or len(rows)
    n_cve = len({c.get("cve", "") for c in rows if c.get("cve")})
    tools = _dedup_keep_order([t for d in dep_findings for t in d["tools"]])
    locations = _dedup_keep_order(sorted(
        {loc for d in dep_findings for loc in d["locations"]}, key=str.lower))
    best_conf = min((d["confidence"] for d in dep_findings),
                    key=lambda c: {"high": 0, "medium": 1, "low": 2}.get(c, 1))
    best_fp = min((d["fp_likelihood"] for d in dep_findings),
                  key=lambda c: {"low": 0, "medium": 1, "high": 2}.get(c, 1))
    ref_links, seen_ref = [], set()
    for d in dep_findings:
        for r in d.get("ref_links", []):
            if r["url"] not in seen_ref:
                seen_ref.add(r["url"])
                ref_links.append(r)

    return {
        "fid": "dep-rollup",
        "severity": severity,
        "title": f"Vulnerable and Outdated Components "
                 f"({n_comp} component{'s' if n_comp != 1 else ''}, {n_cve} CVE{'s' if n_cve != 1 else ''})",
        "category": "Vulnerable Dependency",
        "owasp": "A06:2021 Vulnerable and Outdated Components",
        "cwe_display": "CWE-1104",
        "cwe_ids": [1104],
        "cve_ids": _dedup_keep_order([c["cve"] for c in rows if c.get("cve", "").upper().startswith("CVE-")]),
        "ref_links": ref_links,
        "rule_id": f"{n_cve} CVEs across {n_comp} components",
        "tools": tools,
        "confidence": best_conf,
        "fp_likelihood": best_fp,
        "description": (f"{n_comp} third-party component version(s) in use are affected by "
                        f"{n_cve} known vulnerabilit{'y' if n_cve == 1 else 'ies'}. Each affected "
                        f"library, the version found, the fixed version, and the location are listed "
                        f"in the breakdown below. Upgrade each component to (at least) its fixed version."),
        "remediation": ("Upgrade every listed component to the 'Fixed in' version (or later). Where no "
                        "fixed version is listed, assess exposure and consider replacing the component. "
                        "Re-scan after upgrading to confirm the vulnerabilities are resolved."),
        "reference": "",
        "verification": ("For each component, confirm the vulnerable version is the one actually deployed "
                         "(check the lockfile/manifest) and whether the vulnerable feature is reachable by the app."),
        "triage_notes": [],
        "location_count": len(rows),
        "locations": locations,
        "components": rows,
        "examples": [],
    }


# components are pre-sorted per-finding; keep a stable primary sort weight
_sev_rank_none = 0


def consolidate(findings: list[Finding], group_dependencies: bool = True) -> list[dict]:
    """Collapse per-instance findings into consolidated finding dicts ready for
    the report template.

    When group_dependencies is True (default) every vulnerable-dependency
    finding is further rolled up into a SINGLE 'Vulnerable and Outdated
    Components' finding, so the summary stays short; the full per-library
    breakdown is revealed when the consultant expands it."""
    groups: dict = defaultdict(list)
    for f in findings:
        groups[_group_key(f)].append(f)

    out: list[dict] = []
    for key, members in groups.items():
        members.sort(key=lambda f: (_sev_rank(f.severity), f.file, f.line))
        primary = members[0]  # most severe
        kind = key[0]

        # aggregate metadata across every instance in the group
        tools = sorted({t for m in members for t in m.tools})
        cwes = sorted({m.cwe for m in members if m.cwe})
        rules = _dedup_keep_order([m.rule_id for m in members if m.rule_id])
        cve_ids = _dedup_keep_order(
            [CVE_RE.search(m.rule_id + " " + m.title).group(1).upper()
             for m in members if CVE_RE.search(m.rule_id + " " + m.title)])
        extra_refs = _dedup_keep_order([m.reference for m in members if m.reference])
        # confidence: best across the group (any solid instance lifts the group)
        best_conf = min((m.confidence for m in members),
                        key=lambda c: {"high": 0, "medium": 1, "low": 2}.get(c, 1))
        # fp_likelihood: keep the group visible unless EVERY instance is a likely FP
        best_fp = min((m.fp_likelihood for m in members),
                      key=lambda c: {"low": 0, "medium": 1, "high": 2}.get(c, 1))

        locations = _dedup_keep_order(
            sorted((f"{m.file}:{m.line}" for m in members),
                   key=lambda s: s.lower()))
        notes = _dedup_keep_order([n for m in members for n in m.triage_notes])

        # per-affected-component version detail (for dependency findings)
        components = []
        seen_comp = set()
        for m in members:
            if not (m.component or m.version):
                continue
            mcve = CVE_RE.search(m.rule_id + " " + m.title)
            k = (m.component, m.version, m.file)
            if k in seen_comp:
                continue
            seen_comp.add(k)
            components.append({
                "component": m.component or "(unknown)",
                "version": m.version or "(unknown)",
                "fixed_version": m.fixed_version or "",
                "file": m.file,
                "cve": mcve.group(1).upper() if mcve else (m.rule_id or ""),
            })
        components.sort(key=lambda c: (c["component"].lower(), c["version"]))

        if kind == "cve":
            libs = _dedup_keep_order(
                [m.file.split("/")[-1].split("\\")[-1] or m.file for m in members])
            cve_id = key[1]
            title = f"{cve_id} — Vulnerable Component"
            if libs:
                title += f" ({', '.join(libs[:3])}{', +more' if len(libs) > 3 else ''})"
            rule_display = cve_id
        elif kind == "dep":
            title = f"Vulnerable/Outdated Component: {primary.file.split('/')[-1] or primary.file}"
            rule_display = ", ".join(rules[:3]) + (" …" if len(rules) > 3 else "")
        else:
            base = (primary.title or primary.category).strip()
            title = base if len(locations) == 1 \
                else f"{base} ({len(locations)} locations)"
            rule_display = ", ".join(rules[:3]) + (" …" if len(rules) > 3 else "")

        out.append({
            "fid": primary.fid,
            "severity": primary.severity,
            "title": title,
            "category": primary.category,
            "owasp": primary.owasp,
            "cwe_display": ", ".join(f"CWE-{c}" for c in cwes) if cwes else "",
            "cwe_ids": cwes,
            "cve_ids": cve_ids,
            "ref_links": _ref_links(cwes, cve_ids, extra_refs),
            "rule_id": rule_display,
            "tools": tools,
            "confidence": best_conf,
            "fp_likelihood": best_fp,
            "description": primary.description,
            "remediation": primary.remediation,
            "reference": "; ".join(_dedup_keep_order(
                [m.reference for m in members if m.reference]))[:1200],
            "verification": primary.verification,
            "triage_notes": notes,
            "location_count": len(locations),
            "locations": locations,
            "components": components,
            "examples": _pick_examples(members),
            # primary file/line retained for the collapsed-header summary + search
            "file": primary.file,
            "line": primary.line,
        })

    if group_dependencies:
        deps = [d for d in out if d["category"] == "Vulnerable Dependency"]
        if deps:
            others = [d for d in out if d["category"] != "Vulnerable Dependency"]
            out = others + [_rollup_dependencies(deps)]

    out.sort(key=lambda d: (_sev_rank(d["severity"]), d["category"], d["title"]))
    return out

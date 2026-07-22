"""DRG export — turn SCR findings into a CSV the VAPT Report Generator (DRG)
imports directly under its new 'Source Code Review' template.

Two shapes:
  * grouped (default): one row per vulnerability TYPE, with every affected
    file:line aggregated into the Affected Assets column — how an SCR report
    actually reads ("SQL Injection — 6 locations").
  * per-instance: one row per individual finding (file:line).

By default only the actionable set is exported (likely false positives dropped,
info severity optional) so the report doesn't drown in tool noise. Columns map
onto DRG's Observation / Implication / Recommendation house format.
"""
from __future__ import annotations

import csv
import re
from collections import defaultdict
from pathlib import Path

from .model import Finding, SEVERITIES

# Only real CVE ids — GHSA / advisory ids are intentionally dropped from the
# DRG export (the consultant fills in a CVE manually if one is warranted).
CVE_ONLY_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)

# Per-category business-impact statement (DRG "Implication" field).
IMPLICATION = {
    "Cross-Site Scripting (XSS)": "An attacker can execute arbitrary JavaScript in a victim's browser session, enabling session/cookie theft, credential harvesting, keylogging, defacement, or actions performed as the victim.",
    "SQL Injection": "An attacker can read, modify, or delete arbitrary database records, bypass authentication, and in some configurations execute operating-system commands on the database server — leading to full compromise of application data.",
    "NoSQL / Query Injection": "An attacker can manipulate database queries to bypass authentication or read/alter data they should not have access to.",
    "Command Injection": "An attacker can execute arbitrary operating-system commands on the host with the privileges of the application, typically resulting in full server compromise.",
    "Code Injection": "An attacker can execute arbitrary application code, leading to data compromise or full control of the application process.",
    "Code Injection (eval)": "Untrusted input reaching a dynamic evaluation (eval) construct allows an attacker to execute arbitrary code within the application.",
    "Server-Side Template Injection (SSTI)": "An attacker can inject template directives that execute server-side, frequently escalating to remote code execution.",
    "Path Traversal": "An attacker can read or write files outside the intended directory, exposing sensitive files (configuration, credentials, source) or overwriting critical files.",
    "XML External Entity (XXE)": "An attacker can read local files, perform server-side request forgery, or cause denial of service by supplying crafted XML with external entity declarations.",
    "Insecure Deserialization": "An attacker who controls serialized input can manipulate application logic or achieve remote code execution during object reconstruction.",
    "Broken Access Control": "A user can access functionality or data beyond their authorisation level, breaching confidentiality and integrity of other users' or the system's data.",
    "Broken Access Control (Missing AuthZ)": "Endpoints lacking authorisation checks allow any user to invoke privileged functionality or access restricted data.",
    "IDOR (Insecure Direct Object Reference)": "By manipulating an object identifier, an attacker can access or modify records belonging to other users, breaching data confidentiality and integrity.",
    "Broken Authentication": "Weaknesses in the authentication flow allow an attacker to impersonate legitimate users or bypass login controls.",
    "Broken Authentication (Missing AuthN)": "Unauthenticated access to protected functionality allows anyone to use privileged features without credentials.",
    "Cross-Site Request Forgery (CSRF)": "An attacker can trick an authenticated user's browser into performing unintended state-changing actions on the application.",
    "Cookie Security": "Session cookies without Secure/HttpOnly/SameSite protections can be stolen via network interception or client-side scripts, enabling session hijacking.",
    "Missing Security Headers / Protection": "Absent HTTP security headers increase exposure to clickjacking, MIME sniffing, protocol downgrade, and cross-site scripting attacks.",
    "Security Misconfiguration": "Insecure configuration weakens the application's security posture and may expose sensitive functionality or information to attackers.",
    "Security Misconfiguration (CORS)": "An overly permissive cross-origin policy allows malicious sites to read authenticated responses, exposing user data.",
    "Hardcoded Credentials / Secrets": "Credentials embedded in source code are available to anyone with repository or binary access and cannot be rotated easily, providing a direct path to the protected system if leaked.",
    "Weak Cryptography": "Use of weak or broken cryptographic algorithms allows an attacker to decrypt, forge, or tamper with data that was assumed to be protected.",
    "Weak Hashing": "Weak hashing (e.g. MD5/SHA-1) for passwords or integrity allows attackers to crack credentials or forge values, undermining the protection it was meant to provide.",
    "Insecure Randomness": "Predictable random values used for security tokens, session IDs, or passwords can be guessed by an attacker, defeating the control they underpin.",
    "Improper Certificate Validation": "Disabled or improper TLS certificate validation allows man-in-the-middle attackers to intercept and modify supposedly encrypted traffic.",
    "Cleartext Transmission": "Sensitive data transmitted over unencrypted channels can be intercepted and read by attackers on the network path.",
    "Server-Side Request Forgery (SSRF)": "An attacker can coerce the server into making requests to internal systems or cloud metadata endpoints, exposing internal services and credentials.",
    "Open Redirect": "An attacker can craft links that redirect users to malicious sites while appearing to originate from the trusted application, aiding phishing.",
    "Unrestricted File Upload": "An attacker can upload malicious files (e.g. web shells) that may be executed on the server, leading to remote code execution.",
    "Vulnerable Dependency": "A third-party component with known vulnerabilities exposes the application to publicly documented exploits until the component is updated.",
    "Information Exposure": "Sensitive information disclosed in the application or source can assist an attacker in profiling and further attacking the system.",
    "Information Exposure (Error Details)": "Detailed error messages or stack traces returned to users reveal internal implementation details that facilitate targeted attacks.",
    "Information Exposure (Comments)": "Comments in source or delivered code may disclose credentials, internal URLs, TODOs, or disabled security controls useful to an attacker.",
    "Information Exposure (Logs)": "Sensitive data written to logs may be exposed to unauthorised parties with log access.",
    "Hardcoded Path / Environment": "Hardcoded absolute paths expose deployment details and reduce portability, and may reveal directory structure useful to an attacker.",
    "Regex Denial of Service (ReDoS)": "A crafted input can cause catastrophic regular-expression backtracking, consuming CPU and rendering the service unavailable.",
    "Denial of Service": "An attacker can exhaust resources to render the application unavailable to legitimate users.",
    "Improper Output Encoding": "Output rendered without proper context-aware encoding may allow cross-site scripting or content injection in the client.",
    "Session Management": "Weak session handling can allow session hijacking or fixation, letting an attacker take over authenticated sessions.",
    "Incorrect Permissions": "Overly broad file or resource permissions may allow unauthorised access or modification.",
}
DEFAULT_IMPLICATION = ("The identified weakness may be leveraged by an attacker to compromise the "
                       "confidentiality, integrity, or availability of the application or its data.")

# DRG-facing column order. The DRG importer maps these headers onto ReportFinding.
DRG_COLUMNS = [
    "Title", "Severity", "Confidence", "Category", "OWASP", "CWE",
    "Affected Assets", "Location Count", "Observation", "Implication",
    "Recommendation", "Verification", "References", "Detected By",
    "FP Likelihood", "Status",
]


def _sev_rank(s: str) -> int:
    return SEVERITIES.index(s) if s in SEVERITIES else 2


def _implication(category: str) -> str:
    return IMPLICATION.get(category, DEFAULT_IMPLICATION)


def _select(findings, include_info: bool, include_fp: bool):
    out = []
    for f in findings:
        if not include_fp and f.fp_likelihood == "high":
            continue
        if not include_info and f.severity == "info":
            continue
        out.append(f)
    return out


def _observation(f: Finding, locations=None) -> str:
    obs = f.description.strip()
    if locations:
        shown = locations[:25]
        loc_txt = "; ".join(shown)
        if len(locations) > len(shown):
            loc_txt += f"; (+{len(locations) - len(shown)} more)"
        obs += f"\n\nAffected location(s): {loc_txt}"
    else:
        obs += f"\n\nAffected location: {f.file}:{f.line}"
    return obs


def _recommendation(f: Finding) -> str:
    parts = []
    if f.remediation:
        parts.append(f.remediation.strip())
    if f.verification:
        parts.append("Verification: " + f.verification.strip())
    if not parts:
        parts.append("Review the flagged code and apply the appropriate secure-coding control "
                     "for this weakness (input validation, output encoding, parameterisation, "
                     "or use of a vetted security library).")
    return "\n\n".join(parts)


def _dependency_rollup_row(deps: list[Finding]) -> dict:
    """Collapse every vulnerable/outdated dependency into ONE DRG finding.

    Affected Assets lists each outdated library (component version + file).
    CVE numbers are gathered into the References column; GHSA/advisory ids are
    dropped (left blank) so the consultant can add the correct CVE in DRG."""
    deps = sorted(deps, key=lambda f: (_sev_rank(f.severity), (f.component or "").lower(), f.version))
    severity = deps[0].severity  # most severe (sorted ascending by rank)

    comp_rows, seen, cves = [], set(), []
    for f in deps:
        m = CVE_ONLY_RE.search(f.rule_id + " " + f.title)
        cve = m.group(0).upper() if m else ""
        comp = f.component or (f.file.split("/")[-1] or f.file)
        key = (comp, f.version, f.file, cve)
        if key in seen:
            continue
        seen.add(key)
        comp_rows.append((comp, f.version, f.fixed_version, cve, f.file))
        if cve:
            cves.append(cve)
    cves = sorted(set(cves))
    n_comp = len({(c[0], c[1]) for c in comp_rows})

    # Affected Assets: one line per outdated library + the file it lives in
    affected = "\n".join(
        f"{c[0]} {c[1]}".strip() + f"  ({c[4]})" for c in comp_rows)

    # Observation: full breakdown — component, version found, fix, CVE, file
    obs_lines = []
    for comp, ver, fix, cve, file in comp_rows:
        seg = f"{comp} {ver}".strip()
        if fix:
            seg += f"  ->  upgrade to {fix}"
        if cve:
            seg += f"  [{cve}]"
        seg += f"  ({file})"
        obs_lines.append("  - " + seg)
    obs = (f"{n_comp} third-party component version(s) in use are outdated / affected by known "
           f"vulnerabilities. Affected libraries, the version found, the fixed version, and the "
           f"file each was detected in:\n" + "\n".join(obs_lines))

    tools = sorted({t for f in deps for t in f.tools})
    best_conf = min((f.confidence for f in deps),
                    key=lambda c: {"high": 0, "medium": 1, "low": 2}.get(c, 1))
    worst_fp = min((f.fp_likelihood for f in deps),
                   key=lambda c: {"low": 0, "medium": 1, "high": 2}.get(c, 1))

    title = f"Vulnerable and Outdated Components ({n_comp} component{'s' if n_comp != 1 else ''}"
    title += f", {len(cves)} CVEs)" if cves else ")"

    return {
        "Title": title,
        "Severity": severity.capitalize(),
        "Confidence": best_conf.capitalize(),
        "Category": "Vulnerable Dependency",
        "OWASP": "A06:2021 Vulnerable and Outdated Components",
        "CWE": "CWE-1104",
        "Affected Assets": affected,
        "Location Count": len(comp_rows),
        "Observation": obs,
        "Implication": _implication("Vulnerable Dependency"),
        "Recommendation": ("Upgrade each listed component to its 'upgrade to' version (or later). "
                           "Where no fixed version is listed, assess exposure and consider replacing "
                           "the component. Re-scan after upgrading to confirm resolution."),
        "Verification": ("For each component, confirm the vulnerable version is the one actually "
                         "deployed (check the lockfile/manifest) and whether the vulnerable feature "
                         "is reachable by the application."),
        "References": ", ".join(cves),   # CVE numbers only; GHSA ids dropped
        "Detected By": ", ".join(tools),
        "FP Likelihood": worst_fp.capitalize(),
        "Status": "Open",
    }


def write_drg_csv(findings: list[Finding], path: Path, grouped: bool = True,
                  include_info: bool = False, include_fp: bool = False) -> int:
    """Write a DRG-import CSV. Returns the number of rows written."""
    selected = _select(findings, include_info, include_fp)
    rows = []

    if grouped:
        # Non-dependency findings: one row per vulnerability category.
        # Dependency findings: ALL rolled up into a single 'Vulnerable and
        # Outdated Components' row (mirrors the HTML/PDF report).
        deps = [f for f in selected if f.category == "Vulnerable Dependency"]
        non_deps = [f for f in selected if f.category != "Vulnerable Dependency"]

        groups: dict = defaultdict(list)
        for f in non_deps:
            groups[(f.category,)].append(f)
        for key, members in groups.items():
            category = key[0]
            members.sort(key=lambda f: (_sev_rank(f.severity), f.file, f.line))
            primary = members[0]
            tools = sorted({t for m in members for t in m.tools})
            cwes = sorted({m.cwe for m in members if m.cwe})
            best_conf = min((m.confidence for m in members),
                            key=lambda c: {"high": 0, "medium": 1, "low": 2}.get(c, 1))
            worst_fp = min((m.fp_likelihood for m in members),
                           key=lambda c: {"low": 0, "medium": 1, "high": 2}.get(c, 1))
            locations = [f"{m.file}:{m.line}" for m in members]
            rows.append({
                "Title": category if len(members) == 1 else f"{category} ({len(members)} locations)",
                "Severity": primary.severity.capitalize(),
                "Confidence": best_conf.capitalize(),
                "Category": category,
                "OWASP": primary.owasp,
                "CWE": ", ".join(f"CWE-{c}" for c in cwes),
                "Affected Assets": "\n".join(locations),
                "Location Count": len(locations),
                "Observation": _observation(primary, locations),
                "Implication": _implication(category),
                "Recommendation": _recommendation(primary),
                "Verification": primary.verification,
                "References": primary.reference,
                "Detected By": ", ".join(tools),
                "FP Likelihood": worst_fp.capitalize(),
                "Status": "Open",
            })

        if deps:
            rows.append(_dependency_rollup_row(deps))
        rows.sort(key=lambda r: (_sev_rank(r["Severity"].lower()), r["Category"], r["Title"]))
    else:
        for f in selected:
            rows.append({
                "Title": f.title,
                "Severity": f.severity.capitalize(),
                "Confidence": f.confidence.capitalize(),
                "Category": f.category,
                "OWASP": f.owasp,
                "CWE": f"CWE-{f.cwe}" if f.cwe else "",
                "Affected Assets": f"{f.file}:{f.line}",
                "Location Count": 1,
                "Observation": _observation(f),
                "Implication": _implication(f.category),
                "Recommendation": _recommendation(f),
                "Verification": f.verification,
                "References": f.reference,
                "Detected By": ", ".join(f.tools),
                "FP Likelihood": f.fp_likelihood.capitalize(),
                "Status": "Open",
            })
        rows.sort(key=lambda r: (_sev_rank(r["Severity"].lower()), r["Category"]))

    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.DictWriter(fh, fieldnames=DRG_COLUMNS)
        w.writeheader()
        w.writerows(rows)
    return len(rows)

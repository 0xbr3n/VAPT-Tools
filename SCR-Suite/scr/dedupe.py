"""Cross-tool deduplication.

Two findings are considered the same issue when they share the same file and
the same vulnerability category (or the same CVE id for dependency findings)
and their lines are within LINE_TOLERANCE of each other. Merged findings keep
the highest severity and remember every tool that reported them — multi-tool
agreement feeds the confidence score in triage.
"""
from __future__ import annotations

import re

from .model import Finding, SEVERITIES

LINE_TOLERANCE = 3
CVE_RE = re.compile(r"(CVE-\d{4}-\d+|GHSA-[\w-]+)", re.IGNORECASE)


def _sev_rank(s: str) -> int:
    return SEVERITIES.index(s) if s in SEVERITIES else 2


def _key(f: Finding):
    cve = CVE_RE.search(f.rule_id + " " + f.title)
    if cve:
        # dependency findings: same CVE + same file == same finding regardless of tool
        return ("cve", f.file.lower(), cve.group(1).upper())
    return ("code", f.file.lower(), f.category)


def dedupe(findings: list[Finding]) -> list[Finding]:
    groups: dict = {}
    for f in findings:
        groups.setdefault(_key(f), []).append(f)

    merged: list[Finding] = []
    for key, group in groups.items():
        if key[0] == "cve":
            merged.append(_merge(group))
            continue
        # cluster by line proximity within (file, category)
        group.sort(key=lambda f: f.line)
        cluster = [group[0]]
        for f in group[1:]:
            if f.line - cluster[-1].line <= LINE_TOLERANCE:
                cluster.append(f)
            else:
                merged.append(_merge(cluster))
                cluster = [f]
        merged.append(_merge(cluster))

    merged.sort(key=lambda f: (_sev_rank(f.severity), f.category, f.file, f.line))
    return merged


def _merge(cluster: list[Finding]) -> Finding:
    # keep the most severe / most descriptive finding as the primary record
    cluster.sort(key=lambda f: (_sev_rank(f.severity), -len(f.description)))
    primary = cluster[0]
    tools = sorted({f.tool for f in cluster})
    primary.tools = tools
    primary.duplicates = len(cluster) - 1
    if len(tools) > 1:
        primary.triage_notes.append(
            f"Corroborated by {len(tools)} independent tools: {', '.join(tools)}")
    # adopt any extra context from siblings
    for f in cluster[1:]:
        if not primary.cwe and f.cwe:
            primary.cwe = f.cwe
        if not primary.remediation and f.remediation:
            primary.remediation = f.remediation
        if not primary.reference and f.reference:
            primary.reference = f.reference
    return primary

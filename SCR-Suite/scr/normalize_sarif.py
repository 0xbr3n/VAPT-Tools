"""Generic SARIF 2.1.0 -> Finding conversion (used by opengrep/semgrep and any
other SARIF-emitting tool you plug in later)."""
from __future__ import annotations

import json
import re
from pathlib import Path

from .model import Finding, normalize_severity
from .util import rel_to_target

CWE_RE = re.compile(r"cwe[-/ ]?(\d+)", re.IGNORECASE)
OWASP_RE = re.compile(r"owasp[-/ ]?(a\d{1,2}:?\d{0,4})", re.IGNORECASE)

LEVEL_SEV = {"error": "high", "warning": "medium", "note": "low", "none": "info"}


def _rule_index(run: dict) -> dict:
    idx = {}
    driver = (run.get("tool") or {}).get("driver") or {}
    for rule in driver.get("rules") or []:
        idx[rule.get("id", "")] = rule
    for ext in run.get("tool", {}).get("extensions") or []:
        for rule in ext.get("rules") or []:
            idx.setdefault(rule.get("id", ""), rule)
    return idx


def _extract_cwe_owasp(rule: dict, text: str):
    cwe, owasp = None, ""
    props = rule.get("properties") or {}
    tags = props.get("tags") or []
    hay = " ".join(str(t) for t in tags) + " " + json.dumps(props.get("cwe", "")) + " " + text
    m = CWE_RE.search(hay)
    if m:
        try:
            cwe = int(m.group(1))
        except ValueError:
            pass
    m2 = OWASP_RE.search(hay)
    if m2:
        owasp = m2.group(1).upper()
    return cwe, owasp


def _severity_for(result: dict, rule: dict) -> str:
    props = (rule.get("properties") or {})
    # semgrep/opengrep put security-severity or severity in rule properties
    ss = props.get("security-severity")
    if ss:
        return normalize_severity(None, cvss=ss)
    for key in ("severity", "problem.severity"):
        if props.get(key):
            return normalize_severity(props[key])
    return LEVEL_SEV.get(result.get("level", ""), "medium")


def parse_sarif(path: Path, tool_name: str, target: Path) -> list[Finding]:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        doc = json.load(f)
    findings = []
    for run in doc.get("runs") or []:
        rules = _rule_index(run)
        for res in run.get("results") or []:
            if res.get("suppressions"):
                continue
            rule_id = res.get("ruleId", "") or ""
            rule = rules.get(rule_id, {})
            msg = ((res.get("message") or {}).get("text") or "").strip()
            locs = res.get("locations") or [{}]
            phys = (locs[0].get("physicalLocation") or {})
            uri = ((phys.get("artifactLocation") or {}).get("uri") or "")
            region = phys.get("region") or {}
            line = int(region.get("startLine") or 1)
            end_line = int(region.get("endLine") or line)
            short = ((rule.get("shortDescription") or {}).get("text")
                     or rule_id.split(".")[-1].replace("-", " ").title())
            full = ((rule.get("fullDescription") or {}).get("text") or "")
            cwe, owasp = _extract_cwe_owasp(rule, msg + " " + full)
            props = rule.get("properties") or {}
            conf = str(props.get("confidence", "") or "")
            help_uri = rule.get("helpUri", "") or ""
            fix = ""
            if res.get("fixes"):
                fix = ((res["fixes"][0].get("description") or {}).get("text") or "")
            findings.append(Finding(
                tool=tool_name, rule_id=rule_id, title=short,
                description=msg or full, severity=_severity_for(res, rule),
                file=rel_to_target(uri, target), line=line, end_line=end_line,
                cwe=cwe, owasp=owasp, tool_confidence=conf.lower(),
                remediation=fix, reference=help_uri,
            ).finalize())
    return findings

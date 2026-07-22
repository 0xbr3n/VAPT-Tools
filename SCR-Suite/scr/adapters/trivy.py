"""Trivy adapter — second opinion on dependencies + secrets + IaC misconfigs.

Offline via a pre-downloaded vulnerability DB in tools/trivy-cache
(setup_tools.ps1 handles the download) and --skip-*-update flags.
"""
from __future__ import annotations

import json
from pathlib import Path

from ..model import Finding, normalize_severity
from ..util import find_tool, log, run_cmd, rel_to_target, tools_dir

NAME = "trivy"


def applicable(profile: dict, cfg: dict) -> bool:
    return True


def run(target: Path, cfg: dict, workdir: Path) -> list[Finding]:
    exe = find_tool(cfg, ["trivy"])
    if not exe:
        log("trivy not found - skipping")
        return None
    cache = tools_dir(cfg) / "trivy-cache"
    out = workdir / "trivy.json"
    base = [exe, "fs", "--scanners", "vuln,secret,misconfig",
            "--format", "json", "--output", str(out),
            "--cache-dir", str(cache), "--skip-db-update"]
    skips = []
    for d in cfg.get("exclude_dirs", []):
        skips += ["--skip-dirs", d]
    cmd = base + ["--skip-check-update"] + skips + [str(target)]
    rc, _so, se = run_cmd(cmd, cfg, timeout=3600)
    if rc != 0 and "unknown flag" in (se or "").lower():
        cmd = base + ["--skip-policy-update"] + skips + [str(target)]
        rc, _so, se = run_cmd(cmd, cfg, timeout=3600)
    if not out.exists():
        log(f"trivy produced no output (rc={rc}): {se[-400:]}")
        return None
    with open(out, "r", encoding="utf-8", errors="replace") as f:
        data = json.load(f)
    findings = []
    for res in data.get("Results") or []:
        tfile = rel_to_target(res.get("Target", ""), target)
        for v in res.get("Vulnerabilities") or []:
            findings.append(Finding(
                tool=NAME, rule_id=v.get("VulnerabilityID", "CVE"),
                title=f"{v.get('VulnerabilityID', '')} in {v.get('PkgName', '')} {v.get('InstalledVersion', '')}",
                description=(v.get("Title", "") + ". " + (v.get("Description", "") or ""))[:800],
                severity=normalize_severity(v.get("Severity")),
                file=tfile, line=1, cwe=1104, category="Vulnerable Dependency",
                component=v.get("PkgName", ""), version=v.get("InstalledVersion", ""),
                fixed_version=v.get("FixedVersion", ""),
                reference=v.get("PrimaryURL", ""),
                remediation=(f"Upgrade {v.get('PkgName', '')} from {v.get('InstalledVersion', '')} to {v.get('FixedVersion')}"
                             if v.get("FixedVersion") else
                             f"No fixed version listed for {v.get('PkgName', '')} {v.get('InstalledVersion', '')}; assess exposure."),
            ).finalize())
        for s in res.get("Secrets") or []:
            findings.append(Finding(
                tool=NAME, rule_id=s.get("RuleID", "secret"),
                title=f"Hardcoded Secret: {s.get('Title', s.get('RuleID', ''))}",
                description=f"Secret matched rule {s.get('RuleID', '')} (match masked by trivy).",
                severity=normalize_severity(s.get("Severity", "high")),
                file=tfile, line=int(s.get("StartLine") or 1),
                end_line=int(s.get("EndLine") or 1), cwe=798,
            ).finalize())
        for m in res.get("Misconfigurations") or []:
            if m.get("Status") and m["Status"] != "FAIL":
                continue
            findings.append(Finding(
                tool=NAME, rule_id=m.get("ID", "misconfig"),
                title=m.get("Title", "Misconfiguration"),
                description=(m.get("Description", "") + " " + m.get("Message", ""))[:800],
                severity=normalize_severity(m.get("Severity")),
                file=tfile,
                line=int(((m.get("CauseMetadata") or {}).get("StartLine")) or 1),
                category="Security Misconfiguration",
                reference=m.get("PrimaryURL", ""),
                remediation=m.get("Resolution", ""),
            ).finalize())
    log(f"trivy: {len(findings)} findings")
    return findings

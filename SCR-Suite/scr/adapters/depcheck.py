"""OWASP Dependency-Check adapter — vulnerable third-party components.

Runs strictly offline: the NVD database is pre-downloaded by setup_tools.ps1
(`--updateonly`), scans always use --noupdate and disable every online analyzer.
Requires the bundled JRE (setup script downloads Temurin) or a system Java.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from ..model import Finding, normalize_severity
from ..util import find_tool, log, run_cmd, rel_to_target, tools_dir

NAME = "depcheck"


def applicable(profile: dict, cfg: dict) -> bool:
    # Runs when there is a source manifest OR bundled library binaries
    # (.jar/.war/.dll/…) — Dependency-Check fingerprints those against the NVD
    # directly, so a JAR-only app with no pom.xml is still fully scannable.
    return (bool(profile.get("manifests"))
            or profile.get("dotnet", False)
            or profile.get("lib_binaries", 0) > 0)


def _java_home(cfg) -> str | None:
    td = tools_dir(cfg)
    for p in td.glob("jre*/"):
        if (p / "bin" / "java.exe").exists():
            return str(p)
    for p in td.glob("jdk*/"):
        if (p / "bin" / "java.exe").exists():
            return str(p)
    return None


def _component_version(dep: dict, pkg: str):
    """Best-effort (component, version) for a Dependency-Check dependency.

    Prefers the Package-URL identifier (pkg:npm/lodash@4.17.0), then any
    version-bearing evidence, then a 'name:version' fileName."""
    for p in dep.get("packages") or []:
        pid = p.get("id", "")
        if pid.startswith("pkg:") and "@" in pid:
            body, ver = pid.rsplit("@", 1)
            name = body.split("/")[-1]
            return name, ver
    for sid in dep.get("softwareIdentifiers") or []:
        pid = sid.get("id", "")
        if pid.startswith("pkg:") and "@" in pid:
            body, ver = pid.rsplit("@", 1)
            return body.split("/")[-1], ver
    # fall back to fileName forms like "lodash:4.17.0" or "log4j-core-2.14.1.jar"
    if ":" in pkg:
        name, _, ver = pkg.partition(":")
        return name, ver
    return pkg, ""


def run(target: Path, cfg: dict, workdir: Path) -> list[Finding]:
    exe = find_tool(cfg, ["dependency-check"], subdirs=["dependency-check", "dependency-check/bin"], cfg_key=NAME)
    if not exe:
        log("dependency-check not found - skipping")
        return None
    outdir = workdir / "depcheck"
    outdir.mkdir(exist_ok=True)
    extra_env = {}
    jh = _java_home(cfg)
    if jh:
        extra_env["JAVA_HOME"] = jh
    # Emit the human-readable HTML + CSV reports (evidence that the OWASP
    # Dependency-Check scan ran) alongside the JSON we parse programmatically.
    cmd = [exe, "--scan", str(target),
           "--format", "HTML", "--format", "CSV", "--format", "JSON",
           "--out", str(outdir),
           "--noupdate", "--disableOssIndex", "--disableCentral",
           "--disableRetireJS", "--project", "SCR-Scan",
           "--nvdValidForHours", "999999"]
    rc, _so, se = run_cmd(cmd, cfg, timeout=3600, extra_env=extra_env)
    report = outdir / "dependency-check-report.json"
    if not report.exists():
        log(f"dependency-check produced no output (rc={rc}): {se[-400:]}")
        return None
    with open(report, "r", encoding="utf-8", errors="replace") as f:
        data = json.load(f)
    findings = []
    for dep in data.get("dependencies", []):
        vulns = dep.get("vulnerabilities") or []
        if not vulns:
            continue
        fpath = rel_to_target(dep.get("filePath", dep.get("fileName", "")), target)
        pkg = dep.get("fileName", "")
        comp, ver = _component_version(dep, pkg)
        for v in vulns:
            cvss = None
            for key in ("cvssv3", "cvssv2"):
                block = v.get(key) or {}
                cvss = block.get("baseScore", cvss)
            label = f"{comp} {ver}".strip() or pkg
            findings.append(Finding(
                tool=NAME, rule_id=v.get("name", "CVE"),
                title=f"{v.get('name', 'CVE')} in {label}",
                description=(v.get("description", "") or "")[:800],
                severity=normalize_severity(v.get("severity"), cvss=cvss),
                file=fpath, line=1, cwe=1104,
                category="Vulnerable Dependency",
                component=comp, version=ver,
                reference=f"https://nvd.nist.gov/vuln/detail/{v.get('name', '')}",
                remediation=(f"Upgrade {label} to a version not affected by "
                             f"{v.get('name', '')}."),
            ).finalize())
    log(f"dependency-check: {len(findings)} findings")
    return findings

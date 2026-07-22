"""Grype adapter — vulnerable third-party libraries (Software Composition Analysis).

This is the PRIMARY dependency-CVE scanner. Unlike OWASP Dependency-Check
(whose NVD-API download paginates 180+ times and frequently hangs on a stalled
socket), Grype ships its whole vulnerability database as a SINGLE archive that
is downloaded once at setup — reliable and fully offline at scan time.

Grype's Java cataloger identifies bundled JARs by their filename+manifest even
when they have no embedded pom.properties, so it catches loose WEB-INF/lib JARs
that Trivy misses. Scans directories directly (dir:<path>).
"""
from __future__ import annotations

import json
from pathlib import Path

from ..model import Finding, normalize_severity
from ..util import find_tool, log, run_cmd, rel_to_target, tools_dir

NAME = "grype"


def applicable(profile: dict, cfg: dict) -> bool:
    # Any manifest, .NET project, or bundled library binaries (.jar/.dll/…)
    return (bool(profile.get("manifests"))
            or profile.get("dotnet", False)
            or profile.get("lib_binaries", 0) > 0)


def _db_dir(cfg: dict) -> Path:
    override = cfg.get("adapters", {}).get(NAME, {}).get("db_dir")
    if override and Path(override).exists():
        return Path(override)
    return tools_dir(cfg) / "grype-db"


def run(target: Path, cfg: dict, workdir: Path) -> list[Finding]:
    exe = find_tool(cfg, ["grype"])
    if not exe:
        log("grype not found - skipping (run setup\\setup_tools.ps1)")
        return None
    db = _db_dir(cfg)
    if not db.exists():
        log(f"grype DB not found at {db} - skipping (run update_databases.ps1 -Only grype)")
        return None
    out = workdir / "grype.json"
    # Offline: point at the local DB, never auto-update or check for app updates.
    extra_env = {
        "GRYPE_DB_CACHE_DIR": str(db),
        "GRYPE_DB_AUTO_UPDATE": "false",
        "GRYPE_DB_VALIDATE_AGE": "false",
        "GRYPE_CHECK_FOR_APP_UPDATE": "false",
    }
    cmd = [exe, f"dir:{target}", "-o", "json", "-q"]
    rc, so, se = run_cmd(cmd, cfg, timeout=int(cfg.get("adapters", {}).get(NAME, {}).get("timeout", 1800)),
                         extra_env=extra_env)
    # grype writes JSON to stdout with -o json (no file), so capture stdout
    data = None
    if so and so.strip().startswith("{"):
        try:
            data = json.loads(so)
        except json.JSONDecodeError:
            data = None
    if data is None and out.exists():
        try:
            data = json.loads(out.read_text(encoding="utf-8", errors="replace"))
        except json.JSONDecodeError:
            data = None
    if data is None:
        log(f"grype produced no parseable output (rc={rc}): {se[-300:] if se else so[:200]}")
        return None

    findings = []
    for m in data.get("matches") or []:
        v = m.get("vulnerability") or {}
        a = m.get("artifact") or {}
        vid = v.get("id", "CVE")
        pkg = a.get("name", "")
        ver = a.get("version", "")
        locs = a.get("locations") or []
        fpath = rel_to_target(locs[0].get("path", ""), target) if locs else pkg
        fix = (v.get("fix") or {}).get("versions") or []
        urls = v.get("urls") or ([v.get("dataSource")] if v.get("dataSource") else [])
        # grype severity: Critical/High/Medium/Low/Negligible/Unknown
        sev = v.get("severity", "")
        cvss = None
        for c in v.get("cvss") or []:
            metrics = c.get("metrics") or {}
            if metrics.get("baseScore"):
                cvss = metrics["baseScore"]
        findings.append(Finding(
            tool=NAME, rule_id=vid,
            title=f"{vid} in {pkg} {ver}",
            description=(v.get("description") or
                        f"{pkg} {ver} is affected by {vid}.")[:800],
            severity=normalize_severity("low" if sev.lower() == "negligible" else sev, cvss=cvss),
            file=fpath, line=1, cwe=1104,
            category="Vulnerable Dependency",
            component=pkg, version=ver, fixed_version=", ".join(fix),
            reference="; ".join(u for u in urls if u)[:500],
            remediation=(f"Upgrade {pkg} from {ver} to {', '.join(fix)} (or later)."
                         if fix else
                         f"No fixed version is listed for {vid}; assess exposure and consider replacing {pkg}."),
            tool_confidence="high",
        ).finalize())
    log(f"grype: {len(findings)} dependency CVEs")
    return findings

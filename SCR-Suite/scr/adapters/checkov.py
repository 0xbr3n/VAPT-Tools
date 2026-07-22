"""Checkov adapter — IaC misconfigurations (Terraform / Dockerfile / K8s / CFN).
Policies ship inside the pip package, so it is offline by nature."""
from __future__ import annotations

import json
from pathlib import Path

from ..model import Finding, normalize_severity
from ..util import find_tool, log, run_cmd, rel_to_target, BASE_DIR

NAME = "checkov"


def applicable(profile: dict, cfg: dict) -> bool:
    return profile.get("iac", False)


def _exe(cfg):
    venv = BASE_DIR / ".venv" / "Scripts" / "checkov.cmd"
    if venv.exists():
        return str(venv)
    venv2 = BASE_DIR / ".venv" / "Scripts" / "checkov.exe"
    if venv2.exists():
        return str(venv2)
    return find_tool(cfg, ["checkov"])


def run(target: Path, cfg: dict, workdir: Path) -> list[Finding]:
    exe = _exe(cfg)
    if not exe:
        log("checkov not found - skipping")
        return None
    out = workdir / "checkov"
    out.mkdir(exist_ok=True)
    skips = []
    for d in cfg.get("exclude_dirs", []):
        skips += ["--skip-path", d]
    cmd = [exe, "-d", str(target), "-o", "json", "--output-file-path", str(out),
           "--quiet", "--compact", "--download-external-modules", "false"] + skips
    rc, _so, se = run_cmd(cmd, cfg, timeout=1800)
    report = out / "results_json.json"
    if not report.exists():
        log(f"checkov produced no output (rc={rc}): {se[-300:]}")
        return None
    with open(report, "r", encoding="utf-8", errors="replace") as f:
        data = json.load(f)
    if isinstance(data, dict):
        data = [data]
    findings = []
    for block in data:
        for chk in ((block.get("results") or {}).get("failed_checks") or []):
            rng = chk.get("file_line_range") or [1, 1]
            findings.append(Finding(
                tool=NAME, rule_id=chk.get("check_id", ""),
                title=chk.get("check_name", "IaC misconfiguration"),
                description=f"{chk.get('check_name', '')} — resource: {chk.get('resource', '')}",
                severity=normalize_severity(chk.get("severity") or "medium"),
                file=rel_to_target(chk.get("file_path", "").lstrip("/\\"), target),
                line=int(rng[0] or 1), end_line=int(rng[-1] or 1),
                category="Security Misconfiguration",
                reference=chk.get("guideline", "") or "",
            ).finalize())
    log(f"checkov: {len(findings)} findings")
    return findings

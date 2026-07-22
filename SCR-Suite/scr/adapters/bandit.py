"""Bandit adapter — Python-specific SAST (runs from the local venv, offline)."""
from __future__ import annotations

import json
from pathlib import Path

from ..model import Finding
from ..util import find_tool, log, run_cmd, rel_to_target, BASE_DIR

NAME = "bandit"


def applicable(profile: dict, cfg: dict) -> bool:
    return "python" in profile.get("languages", [])


def _exe(cfg):
    venv = BASE_DIR / ".venv" / "Scripts" / "bandit.exe"
    if venv.exists():
        return str(venv)
    return find_tool(cfg, ["bandit"])


def run(target: Path, cfg: dict, workdir: Path) -> list[Finding]:
    exe = _exe(cfg)
    if not exe:
        log("bandit not found - skipping")
        return None
    out = workdir / "bandit.json"
    skips = ",".join(cfg.get("exclude_dirs", []))
    cmd = [exe, "-r", str(target), "-f", "json", "-o", str(out), "-q"]
    if skips:
        cmd += ["-x", skips]
    rc, _so, se = run_cmd(cmd, cfg, timeout=1800)
    if not out.exists():
        log(f"bandit produced no output (rc={rc}): {se[-300:]}")
        return None
    with open(out, "r", encoding="utf-8", errors="replace") as f:
        data = json.load(f)
    findings = []
    for r in data.get("results", []):
        cwe = None
        c = r.get("issue_cwe") or {}
        if isinstance(c, dict) and c.get("id"):
            cwe = int(c["id"])
        findings.append(Finding(
            tool=NAME, rule_id=r.get("test_id", ""),
            title=r.get("test_name", "").replace("_", " ").title(),
            description=r.get("issue_text", ""),
            severity=str(r.get("issue_severity", "medium")).lower(),
            file=rel_to_target(r.get("filename", ""), target),
            line=int(r.get("line_number") or 1),
            end_line=int((r.get("line_range") or [r.get("line_number", 1)])[-1]),
            cwe=cwe,
            tool_confidence=str(r.get("issue_confidence", "")).lower(),
            reference=r.get("more_info", ""),
        ).finalize())
    log(f"bandit: {len(findings)} findings")
    return findings

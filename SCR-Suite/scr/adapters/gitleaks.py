"""Gitleaks adapter — hardcoded secrets / credentials (single offline binary).

Secrets are ALWAYS redacted before they reach any report file.
"""
from __future__ import annotations

import json
from pathlib import Path

from ..model import Finding
from ..util import find_tool, log, run_cmd, rel_to_target

NAME = "gitleaks"


def applicable(profile: dict, cfg: dict) -> bool:
    return True


def _redact(secret: str) -> str:
    if not secret:
        return ""
    s = str(secret)
    if len(s) <= 8:
        return s[:2] + "*" * (len(s) - 2)
    return s[:4] + "*" * min(len(s) - 8, 24) + s[-4:]


def run(target: Path, cfg: dict, workdir: Path) -> list[Finding]:
    exe = find_tool(cfg, ["gitleaks"])
    if not exe:
        log("gitleaks not found - skipping")
        return None
    out = workdir / "gitleaks.json"
    # `detect --no-git` scans the working tree as plain files (works on any folder)
    cmd = [exe, "detect", "--source", str(target), "--no-git",
           "--report-format", "json", "--report-path", str(out),
           "--exit-code", "0"]
    rc, _so, se = run_cmd(cmd, cfg, timeout=1800)
    if rc != 0 and not out.exists():
        # newer gitleaks (>=8.19) prefers the `dir` command
        cmd = [exe, "dir", str(target), "--report-format", "json",
               "--report-path", str(out), "--exit-code", "0"]
        rc, _so, se = run_cmd(cmd, cfg, timeout=1800)
    if not out.exists():
        log(f"gitleaks produced no output (rc={rc}): {se[-300:]}")
        return None
    try:
        with open(out, "r", encoding="utf-8", errors="replace") as f:
            data = json.load(f) or []
    except json.JSONDecodeError:
        data = []
    ex_dirs = [d.lower() for d in cfg.get("exclude_dirs", [])]
    findings = []
    for r in data:
        file = rel_to_target(r.get("File", ""), target)
        parts = file.lower().split("/")
        if any(d in parts for d in ex_dirs):
            continue
        secret_preview = _redact(r.get("Secret", ""))
        findings.append(Finding(
            tool=NAME, rule_id=r.get("RuleID", "secret"),
            title=f"Hardcoded Secret: {r.get('RuleID', 'generic')}",
            description=(f"{r.get('Description', 'Potential secret detected')}. "
                         f"Matched value (masked): {secret_preview}. "
                         f"Entropy: {round(float(r.get('Entropy') or 0), 2)}"),
            severity="high", cwe=798,
            file=file, line=int(r.get("StartLine") or 1),
            end_line=int(r.get("EndLine") or r.get("StartLine") or 1),
            tool_confidence="high" if float(r.get("Entropy") or 0) >= 3.5 else "medium",
        ).finalize())
    log(f"gitleaks: {len(findings)} findings")
    return findings

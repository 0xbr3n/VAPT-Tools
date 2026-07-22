"""Opengrep / Semgrep adapter — the main multi-language SAST engine.

Prefers the opengrep binary (native Windows support, Semgrep fork) and falls
back to semgrep if that's what is installed. Rules come from the locally
downloaded semgrep-rules / opengrep-rules pack, so no network is ever needed.
"""
from __future__ import annotations

from pathlib import Path

from ..model import Finding
from ..normalize_sarif import parse_sarif
from ..util import find_tool, log, run_cmd, tools_dir

NAME = "semgrep"


def applicable(profile: dict, cfg: dict) -> bool:
    return True  # multi-language; always worth running


def _rules_path(cfg: dict) -> Path | None:
    conf = cfg.get("adapters", {}).get(NAME, {})
    rules = conf.get("rules_dir")
    if rules and Path(rules).exists():
        return Path(rules)
    td = tools_dir(cfg)
    for cand in ("semgrep-rules", "opengrep-rules", "rules"):
        p = td / cand
        if p.exists():
            # the repo zip may have unpacked to a single nested folder
            subs = [c for c in p.iterdir() if c.is_dir()]
            if not any(p.glob("*.yaml")) and not any(p.glob("*.yml")) and len(subs) == 1:
                return subs[0]
            return p
    return None


def run(target: Path, cfg: dict, workdir: Path) -> list[Finding]:
    exe = find_tool(cfg, ["opengrep", "semgrep"])
    if not exe:
        log("semgrep/opengrep not found - skipping (run setup\\setup_tools.ps1)")
        return None
    rules = _rules_path(cfg)
    if not rules:
        log("semgrep rules pack not found in tools/ - skipping")
        return None
    out = workdir / "semgrep.sarif"
    excludes = []
    for d in cfg.get("exclude_dirs", []):
        excludes += ["--exclude", d]
    for g in cfg.get("exclude_globs", []):
        excludes += ["--exclude", g]
    is_opengrep = "opengrep" in Path(exe).name.lower()
    cmd = [exe, "scan", "--config", str(rules), "--disable-version-check",
           "--timeout=30", "--timeout-threshold=5", "--max-target-bytes=2000000"]
    if is_opengrep:
        cmd += ["--sarif-output", str(out)]
    else:  # real semgrep: has telemetry that must be forced off
        cmd += ["--sarif", "--output", str(out), "--metrics", "off", "--quiet"]
    cmd += excludes + [str(target)]
    rc, _so, se = run_cmd(cmd, cfg, timeout=int(cfg.get("adapters", {}).get(NAME, {}).get("timeout", 5400)))
    if not out.exists():
        log(f"semgrep produced no output (rc={rc}): {se[:400] if se else 'no stderr'}")
        return None
    findings = parse_sarif(out, NAME, target)
    # keep only security-relevant results; the rules repo also carries
    # correctness/best-practice rules that add noise to a VAPT report
    sec = [f for f in findings if _is_security(f)]
    log(f"semgrep: {len(sec)} security findings ({len(findings)} raw)")
    return sec


def _is_security(f: Finding) -> bool:
    if f.cwe:
        return True
    hay = (f.rule_id + " " + f.title + " " + f.owasp).lower()
    return any(k in hay for k in (
        "security", "owasp", "injection", "sqli", "xss", "csrf", "crypto",
        "secret", "auth", "authz", "authoriz", "access-control", "idor",
        "traversal", "path-travers", "ssrf", "deserial", "pickle", "xxe",
        "xml", "cookie", "header", "hsts", "csp", "redirect", "open-redirect",
        "ssti", "template-injection", "cors", "clickjack", "frame",
        "upload", "file-upload", "rce", "command", "exec", "eval",
        "prototype", "dangerous", "unsafe", "hardcoded", "insecure",
        "tls", "ssl", "certificate", "sensitive", "taint"))

"""Optional SonarQube adapter (disabled by default).

Only talks to a LOCAL SonarQube server (localhost) — still fully offline from
the internet's point of view. To use it:
  1. Run SonarQube Community locally (e.g. `docker run -p 9000:9000 sonarqube:community`)
  2. Create a user token in the local UI
  3. Set adapters.sonarqube.enabled=true, token, and sonar_scanner path in config.json
The adapter runs sonar-scanner on the target, then pulls VULNERABILITY /
SECURITY_HOTSPOT issues from the local API.
"""
from __future__ import annotations

import base64
import json
import time
import urllib.request
from pathlib import Path

from ..model import Finding, normalize_severity
from ..util import find_tool, log, run_cmd

NAME = "sonarqube"


def applicable(profile: dict, cfg: dict) -> bool:
    return bool(cfg.get("adapters", {}).get(NAME, {}).get("enabled", False))


def _api(url_base: str, token: str, path: str) -> dict:
    req = urllib.request.Request(url_base.rstrip("/") + path)
    auth = base64.b64encode(f"{token}:".encode()).decode()
    req.add_header("Authorization", f"Basic {auth}")
    # localhost only — refuse anything else so client code can't leak out
    if not any(h in url_base for h in ("localhost", "127.0.0.1")):
        raise RuntimeError("sonarqube adapter refuses non-localhost servers")
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode("utf-8", "replace"))


def run(target: Path, cfg: dict, workdir: Path) -> list[Finding]:
    conf = cfg.get("adapters", {}).get(NAME, {})
    url = conf.get("url", "http://localhost:9000")
    token = conf.get("token", "")
    project_key = conf.get("project_key", "scr-scan")
    if not token:
        log("sonarqube enabled but no token configured - skipping")
        return None
    scanner = find_tool(cfg, ["sonar-scanner"], subdirs=["sonar-scanner/bin"], cfg_key=NAME)
    if not scanner:
        log("sonar-scanner not found - skipping")
        return None
    cmd = [scanner,
           f"-Dsonar.projectKey={project_key}",
           f"-Dsonar.sources={target}",
           f"-Dsonar.host.url={url}",
           f"-Dsonar.token={token}",
           "-Dsonar.scm.disabled=true",
           f"-Dsonar.exclusions=" + ",".join(f"**/{d}/**" for d in cfg.get("exclude_dirs", []))]
    rc, _so, se = run_cmd(cmd, cfg, timeout=5400, allow_network=True)  # localhost only
    if rc != 0:
        log(f"sonar-scanner failed (rc={rc}): {se[-300:]}")
        return None
    time.sleep(10)  # let the server finish background processing
    findings = []
    page = 1
    while True:
        data = _api(url, token,
                    f"/api/issues/search?componentKeys={project_key}"
                    f"&types=VULNERABILITY&ps=500&p={page}")
        for issue in data.get("issues", []):
            comp = issue.get("component", "")
            file = comp.split(":", 1)[1] if ":" in comp else comp
            findings.append(Finding(
                tool=NAME, rule_id=issue.get("rule", ""),
                title=issue.get("message", "")[:120],
                description=issue.get("message", ""),
                severity=normalize_severity(issue.get("severity")),
                file=file, line=int(issue.get("line") or 1),
            ).finalize())
        if page * 500 >= min(int(data.get("total", 0)), 10000) or not data.get("issues"):
            break
        page += 1
    log(f"sonarqube: {len(findings)} findings")
    return findings

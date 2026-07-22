"""Adapter registry. Each adapter module exposes:
    NAME: str
    applicable(profile: dict, cfg: dict) -> bool
    run(target: Path, cfg: dict, workdir: Path) -> list[Finding]
Adapters must degrade gracefully (return [] with a log line) when their tool
is not installed.
"""
from . import (semgrep, bandit, gitleaks, grype, depcheck, trivy, checkov,
               sonarqube, manualscan)

ALL = [semgrep, bandit, gitleaks, grype, depcheck, trivy, checkov,
       sonarqube, manualscan]

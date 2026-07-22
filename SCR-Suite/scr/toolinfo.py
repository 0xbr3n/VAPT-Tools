"""Collect the version of every scanning tool used, for the report + evidence.

Records what actually ran (binary path + reported version) so a reviewer can
reproduce the scan and prove which engine/rule versions produced the findings.
Binaries are asked with their own --version/version flag; Python-packaged tools
(bandit, checkov) are read from installed package metadata.
"""
from __future__ import annotations

from pathlib import Path

from .util import find_tool, run_cmd, tools_dir

# (display name, [exe candidates], version-subcommand, find_tool subdirs)
_BINARY_TOOLS = [
    ("opengrep", ["opengrep"], ["--version"], []),
    ("semgrep", ["semgrep"], ["--version"], []),
    ("gitleaks", ["gitleaks"], ["version"], []),
    ("grype", ["grype"], ["version"], []),
    ("trivy", ["trivy"], ["--version"], []),
    ("dependency-check", ["dependency-check"], ["--version"],
     ["dependency-check", "dependency-check/bin"]),
    ("sonar-scanner", ["sonar-scanner"], ["--version"],
     ["sonar-scanner", "sonar-scanner/bin"]),
]

# Python-packaged tools: read version from installed metadata
_PY_TOOLS = ["bandit", "checkov", "semgrep"]


def _first_line_version(text: str) -> str:
    for ln in (text or "").splitlines():
        ln = ln.strip()
        if ln:
            return ln[:120]
    return ""


def _py_version(pkg: str) -> str:
    try:
        from importlib.metadata import version, PackageNotFoundError
    except ImportError:
        return ""
    try:
        return version(pkg)
    except Exception:
        return ""


def collect_versions(cfg: dict) -> list[dict]:
    """Return [{tool, version, path}] for every tool that is present."""
    out: list[dict] = []
    seen = set()

    for name, cands, verargs, subdirs in _BINARY_TOOLS:
        exe = find_tool(cfg, cands, subdirs=subdirs, cfg_key=name)
        if not exe:
            continue
        rc, so, se = run_cmd([exe] + verargs, cfg, timeout=60)
        ver = _first_line_version(so) or _first_line_version(se) or "(unknown)"
        out.append({"tool": name, "version": ver, "path": exe})
        seen.add(name)

    for pkg in _PY_TOOLS:
        ver = _py_version(pkg)
        if ver:
            out.append({"tool": pkg, "version": ver, "path": "(python package)"})

    # note the vulnerability-database freshness where we can
    gdb = tools_dir(cfg) / "grype-db"
    if gdb.exists():
        out.append({"tool": "grype-db", "version": "present", "path": str(gdb)})
    tdb = tools_dir(cfg) / "trivy-cache"
    if tdb.exists():
        out.append({"tool": "trivy-db", "version": "present", "path": str(tdb)})

    out.sort(key=lambda d: d["tool"].lower())
    return out


def write_versions_file(versions: list[dict], path: Path):
    lines = ["SCR Automater — scanning tool versions", "=" * 42, ""]
    width = max((len(v["tool"]) for v in versions), default=10)
    for v in versions:
        lines.append(f"{v['tool']:<{width}}  {v['version']}")
        lines.append(f"{'':<{width}}  ({v['path']})")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

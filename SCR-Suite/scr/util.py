"""Shared helpers: tool resolution, contained subprocess execution, language detection."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent   # the "SCR Automater" folder

_LOG_FH = None


def set_log_file(path):
    """Tee everything log() prints into a scan.log file kept as scan evidence."""
    global _LOG_FH
    try:
        _LOG_FH = open(path, "a", encoding="utf-8")
    except OSError:
        _LOG_FH = None


def log(msg: str):
    line = f"[scr] {msg}"
    print(line, flush=True)
    if _LOG_FH is not None:
        try:
            _LOG_FH.write(line + "\n")
            _LOG_FH.flush()
        except OSError:
            pass


def load_config(path: str | None = None) -> dict:
    cfg_path = Path(path) if path else BASE_DIR / "config.json"
    if not cfg_path.exists():
        cfg_path = BASE_DIR / "config.default.json"
    with open(cfg_path, "r", encoding="utf-8") as f:
        return json.load(f)


def tools_dir(cfg: dict) -> Path:
    d = Path(cfg.get("tools_dir", "tools"))
    return d if d.is_absolute() else BASE_DIR / d


def find_tool(cfg: dict, names, subdirs=(), cfg_key: str | None = None) -> str | None:
    """Resolve a tool executable: explicit config path -> tools/ dir -> PATH."""
    if isinstance(names, str):
        names = [names]
    td = tools_dir(cfg)
    for key in [cfg_key] + names:
        if not key:
            continue
        override = cfg.get("adapters", {}).get(key, {}).get("path")
        if override and Path(override).exists():
            return str(override)
    exts = ["", ".exe", ".cmd", ".bat"]
    search_dirs = [td] + [td / s for s in subdirs]
    # also scan one level of subdirectories under tools/
    if td.exists():
        search_dirs += [p for p in td.iterdir() if p.is_dir()]
        for p in list(search_dirs):
            if isinstance(p, Path) and p.is_dir():
                search_dirs += [c / "bin" for c in [p] if (c / "bin").is_dir()]
    for name in names:
        for d in search_dirs:
            for ext in exts:
                cand = Path(d) / f"{name}{ext}"
                if cand.is_file():
                    return str(cand)
        w = shutil.which(name)
        if w:
            return w
    return None


def blackhole_env(cfg: dict) -> dict:
    """Environment for child processes that blocks outbound HTTP(S) via an
    unroutable proxy — defence in depth on top of each tool's offline flags."""
    env = os.environ.copy()
    if not cfg.get("network_blackhole", True):
        return env
    dead = "http://127.0.0.1:1"
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy",
                "ALL_PROXY", "all_proxy"):
        env[var] = dead
    env["NO_PROXY"] = env["no_proxy"] = "localhost,127.0.0.1"
    # JVM tools (Dependency-Check) don't honour HTTP_PROXY — force via JAVA_TOOL_OPTIONS
    env["JAVA_TOOL_OPTIONS"] = (
        "-Dhttp.proxyHost=127.0.0.1 -Dhttp.proxyPort=1 "
        "-Dhttps.proxyHost=127.0.0.1 -Dhttps.proxyPort=1 "
        "-Dhttp.nonProxyHosts=localhost|127.0.0.1"
    )
    env["SEMGREP_SEND_METRICS"] = "off"
    return env


_RAW_DIR = None


def set_raw_dir(path):
    """Directory where each tool's full stdout/stderr is written as a .log file."""
    global _RAW_DIR
    _RAW_DIR = Path(path)


def _write_tool_log(cmd, rc, out, se):
    if _RAW_DIR is None:
        return
    try:
        name = Path(str(cmd[0])).stem or "tool"
        with open(_RAW_DIR / f"{name}.log", "a", encoding="utf-8") as fh:
            fh.write("$ " + " ".join(str(c) for c in cmd) + "\n")
            fh.write(f"[return code] {rc}\n")
            if out:
                fh.write("[stdout]\n" + out + "\n")
            if se:
                fh.write("[stderr]\n" + se + "\n")
            fh.write("\n" + "=" * 72 + "\n")
    except OSError:
        pass


def run_cmd(cmd, cfg, cwd=None, timeout=3600, extra_env=None, allow_network=False):
    """Run a tool. Returns (returncode, stdout, stderr). Never raises on non-zero exit."""
    env = os.environ.copy() if allow_network else blackhole_env(cfg)
    if extra_env:
        env.update(extra_env)
    log("  $ " + " ".join(str(c) for c in cmd))
    try:
        p = subprocess.run(
            [str(c) for c in cmd], cwd=cwd, env=env, timeout=timeout,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        rc = p.returncode
        out = p.stdout.decode("utf-8", "replace")
        se = p.stderr.decode("utf-8", "replace")
    except subprocess.TimeoutExpired:
        rc, out, se = -1, "", f"timeout after {timeout}s"
    except FileNotFoundError as e:
        rc, out, se = -2, "", str(e)
    _write_tool_log(cmd, rc, out, se)
    return rc, out, se


LANG_EXT = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".java": "java", ".jsp": "java",
    ".cs": "csharp", ".cshtml": "csharp", ".go": "go", ".rb": "ruby",
    ".php": "php", ".phtml": "php", ".c": "c", ".cpp": "cpp", ".h": "c",
    ".hpp": "cpp", ".kt": "kotlin", ".kts": "kotlin", ".swift": "swift",
    ".scala": "scala", ".rs": "rust", ".html": "html", ".htm": "html",
    ".vue": "javascript", ".sql": "sql", ".sh": "shell", ".ps1": "powershell",
    ".tf": "terraform", ".yml": "yaml", ".yaml": "yaml", ".json": "json",
    ".xml": "xml", ".properties": "config", ".ini": "config", ".cfg": "config",
    ".pl": "perl", ".lua": "lua", ".dart": "dart", ".m": "objc",
}

DEP_MANIFESTS = {
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "requirements.txt", "pipfile", "pipfile.lock", "poetry.lock", "pyproject.toml",
    "pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile",
    "packages.config", "composer.json", "composer.lock", "gemfile", "gemfile.lock",
    "go.mod", "go.sum", "cargo.toml", "cargo.lock",
}

IAC_MARKERS = {".tf", ".tfvars"}
IAC_FILES = {"dockerfile", "docker-compose.yml", "docker-compose.yaml"}

# Compiled / bundled dependency artifacts that Dependency-Check and Trivy can
# fingerprint against the NVD even when there is no source manifest (pom.xml,
# package.json, …). A JAR-only Java web app is the classic case.
BINARY_LIBS = {
    ".jar", ".war", ".ear", ".aar",          # Java
    ".dll", ".exe", ".nupkg",                # .NET
    ".whl", ".egg",                          # Python
    ".gem",                                  # Ruby
    ".apk", ".ipa",                          # mobile
    ".zip", ".tar", ".tgz", ".gz",           # generic archives DC unpacks
    ".node",                                 # native node addons
    ".so", ".dylib",                         # native libs
}


def detect_profile(target: Path, exclude_dirs) -> dict:
    """Walk the target once and figure out languages / manifests / IaC presence."""
    langs, manifests, iac = set(), set(), False
    ex = {e.lower() for e in exclude_dirs}
    csproj = False
    lib_count = 0
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d.lower() not in ex and not d.startswith(".git")]
        for f in files:
            fl = f.lower()
            ext = os.path.splitext(fl)[1]
            if ext in LANG_EXT:
                langs.add(LANG_EXT[ext])
            if fl in DEP_MANIFESTS or fl.endswith(".csproj") or fl.endswith(".sln"):
                manifests.add(fl)
                if fl.endswith((".csproj", ".sln")):
                    csproj = True
            # Bundled library binaries — Dependency-Check / Trivy fingerprint
            # these directly (a JAR-only app with no pom.xml still has real,
            # CVE-checkable dependencies, e.g. WEB-INF/lib/*.jar).
            if ext in BINARY_LIBS:
                lib_count += 1
            if ext in IAC_MARKERS or fl in IAC_FILES or fl.startswith("dockerfile"):
                iac = True
            if ext in (".yml", ".yaml") and ("k8s" in root.lower() or "kubernetes" in root.lower()):
                iac = True
    return {"languages": sorted(langs), "manifests": sorted(manifests),
            "iac": iac, "dotnet": csproj, "lib_binaries": lib_count}


def rel_to_target(path: str, target: Path) -> str:
    """Best-effort relative path for report display."""
    try:
        p = Path(path)
        if not p.is_absolute():
            return str(p).replace("\\", "/")
        return str(p.resolve().relative_to(target.resolve())).replace("\\", "/")
    except (ValueError, OSError):
        return str(path).replace("\\", "/")

"""Manual-checks adapter — encodes Brendon's hand-run SCR grep/regex searches
(Pentesting Notes/Source Code Review/Manual Testing) so they run automatically
after the tool-based scanners.

Pure standard-library regex over the source tree — needs no external tool, so
it works even on a fully air-gapped machine with nothing else installed. Rules
live in manual_rules.json (editable) and flow through the same dedupe + triage
+ report pipeline as every other adapter.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from ..model import Finding
from ..util import BASE_DIR, LANG_EXT, log, rel_to_target

NAME = "manual"

# file-group scopes used by rules
CODE_EXTS = {".py", ".js", ".jsx", ".mjs", ".ts", ".tsx", ".java", ".jsp",
             ".cs", ".cshtml", ".go", ".rb", ".php", ".phtml", ".c", ".cpp",
             ".h", ".hpp", ".kt", ".kts", ".swift", ".scala", ".rs", ".vue",
             ".pl", ".lua", ".dart", ".m", ".groovy", ".sh", ".ps1"}
WEB_EXTS = {".html", ".htm", ".jsp", ".php", ".vue", ".js", ".jsx", ".ts", ".tsx"}
CONFIG_EXTS = {".xml", ".properties", ".ini", ".cfg", ".yml", ".yaml", ".json",
               ".env", ".conf", ".toml", ".config"}

TEXT_EXTS = set(LANG_EXT) | CONFIG_EXTS | {".txt", ".md", ".env", ".conf",
                                           ".gradle", ".tf", ".tfvars"}

MAX_FILE_BYTES = 3 * 1024 * 1024
MAX_HITS_PER_RULE_PER_FILE = 50
MAX_TOTAL_PER_RULE = 500


def applicable(profile: dict, cfg: dict) -> bool:
    return cfg.get("adapters", {}).get(NAME, {}).get("enabled", True)


def _rules_file(cfg: dict) -> Path:
    override = cfg.get("adapters", {}).get(NAME, {}).get("rules_file")
    if override and Path(override).exists():
        return Path(override)
    return BASE_DIR / "manual_rules.json"


def _scope_exts(scope: str):
    return {"code": CODE_EXTS, "web": WEB_EXTS, "config": CONFIG_EXTS}.get(scope)


def _compile(rule: dict):
    kind = rule.get("kind", "regex")
    pat = rule["pattern"]
    flags = 0
    fl = rule.get("flags", "")
    if "i" in fl:
        flags |= re.IGNORECASE
    if "m" in fl:
        flags |= re.DOTALL
    if kind == "literal":
        return re.compile(re.escape(pat), flags), True
    return re.compile(pat, flags), False


def _redact(s: str) -> str:
    s = s.strip()
    if len(s) <= 8:
        return s[:2] + "*" * max(0, len(s) - 2)
    return s[:4] + "*" * min(len(s) - 8, 20) + s[-4:]


def _iter_files(target: Path, cfg: dict):
    import os
    ex_dirs = {d.lower() for d in cfg.get("exclude_dirs", [])}
    ex_globs = cfg.get("exclude_globs", [])
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d.lower() not in ex_dirs and not d.startswith(".git")]
        for f in files:
            ext = Path(f).suffix.lower()
            if ext not in TEXT_EXTS:
                continue
            if any(Path(f).match(g) for g in ex_globs):
                continue
            p = Path(root) / f
            try:
                if p.stat().st_size > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            yield p, ext


def run(target: Path, cfg: dict, workdir: Path) -> list[Finding]:
    rules_path = _rules_file(cfg)
    if not rules_path.exists():
        log(f"manual: rules file not found ({rules_path}) - skipping")
        return None
    try:
        rules = json.loads(rules_path.read_text(encoding="utf-8")).get("rules", [])
    except (json.JSONDecodeError, OSError) as e:
        log(f"manual: bad rules file: {e} - skipping")
        return None

    compiled = []
    for r in rules:
        try:
            rx, _lit = _compile(r)
            compiled.append((r, rx, _scope_exts(r.get("scope", "all"))))
        except re.error as e:
            log(f"manual: skipping rule {r.get('id')}: bad regex ({e})")

    counts = {r["id"]: 0 for r in rules}
    findings: list[Finding] = []

    for p, ext in _iter_files(target, cfg):
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = rel_to_target(str(p), target)
        line_starts = None  # lazy offset->line index

        for rule, rx, scope_exts in compiled:
            if scope_exts is not None and ext not in scope_exts:
                continue
            if counts[rule["id"]] >= MAX_TOTAL_PER_RULE:
                continue
            per_file = 0
            multiline = "m" in rule.get("flags", "")
            for m in rx.finditer(text):
                if per_file >= MAX_HITS_PER_RULE_PER_FILE or counts[rule["id"]] >= MAX_TOTAL_PER_RULE:
                    break
                if line_starts is None:
                    line_starts = _build_line_index(text)
                start_line = _offset_to_line(line_starts, m.start())
                end_line = _offset_to_line(line_starts, m.end()) if multiline else start_line
                matched = m.group(0)
                desc = rule["description"]
                if rule.get("redact"):
                    desc += f"  Matched value (masked): {_redact(matched)}"
                elif not multiline:
                    desc += f"  Matched: {matched[:120]}"
                findings.append(Finding(
                    tool=NAME, rule_id=rule["id"],
                    title=rule["title"], description=desc,
                    severity=rule.get("severity", "low"),
                    file=rel, line=start_line,
                    end_line=min(end_line, start_line + 30),
                    cwe=rule.get("cwe"),
                    category=rule.get("category", "Other"),
                    tool_confidence=rule.get("confidence", "low"),
                    reference=f"Manual SCR check ({rule.get('note', rules_path.name)})",
                ).finalize())
                per_file += 1
                counts[rule["id"]] += 1

    capped = [rid for rid, c in counts.items() if c >= MAX_TOTAL_PER_RULE]
    if capped:
        log(f"manual: NOTE - these rules hit the {MAX_TOTAL_PER_RULE}-match cap "
            f"(results truncated): {', '.join(capped)}")
    log(f"manual: {len(findings)} findings across {sum(1 for c in counts.values() if c)} active checks")
    return findings


def _build_line_index(text: str):
    idx = [0]
    for i, ch in enumerate(text):
        if ch == "\n":
            idx.append(i + 1)
    return idx


def _offset_to_line(line_starts, off: int) -> int:
    import bisect
    return bisect.bisect_right(line_starts, off)

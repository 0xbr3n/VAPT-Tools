"""Prune the semgrep-rules checkout down to actual rule files.

The repo contains pre-commit configs, CI files, and *.test.yaml fixtures that
make opengrep abort with 'Invalid rule schema' when the repo root is passed as
--config. Keep only YAML files whose top level declares `rules:`; delete
everything else. Run automatically by setup_tools.ps1; safe to re-run.

Usage: python setup/clean_rules.py [rules_dir]
"""
import os
import re
import sys
from pathlib import Path

RULES_RE = re.compile(r"^rules\s*:", re.MULTILINE)


def is_rule_file(p: Path) -> bool:
    if p.suffix.lower() not in (".yaml", ".yml"):
        return False
    if p.name.startswith(".") or p.name.endswith((".test.yaml", ".test.yml")):
        return False
    try:
        head = p.read_text(encoding="utf-8", errors="replace")[:20000]
    except OSError:
        return False
    return bool(RULES_RE.search(head))


def main():
    base = Path(sys.argv[1]) if len(sys.argv) > 1 else (
        Path(__file__).resolve().parent.parent / "tools" / "semgrep-rules")
    if not base.exists():
        print(f"rules dir not found: {base}")
        return 1
    kept = removed = 0
    for root, dirs, files in os.walk(base, topdown=False):
        for f in files:
            p = Path(root) / f
            if is_rule_file(p):
                kept += 1
            else:
                p.unlink(missing_ok=True)
                removed += 1
        for d in dirs:
            dp = Path(root) / d
            try:
                dp.rmdir()  # only removes if now empty
            except OSError:
                pass
    print(f"rules pack cleaned: kept {kept} rule files, removed {removed} others")
    return 0


if __name__ == "__main__":
    sys.exit(main())

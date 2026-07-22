"""Report generation: self-contained HTML (offline, filterable), JSON, CSV,
and optional PDF via Edge/Chrome headless (both already present on Windows)."""
from __future__ import annotations

import csv
import json
import shutil
import subprocess
import time
from pathlib import Path

from .consolidate import consolidate
from .model import Finding, SEVERITIES
from .util import log

TEMPLATE = Path(__file__).resolve().parent / "report_template.html"
SNIPPET_CONTEXT = 3
MAX_SNIPPET_FILE = 5 * 1024 * 1024


def make_snippet_reader(target: Path):
    cache: dict = {}

    def read_snippet(f: Finding) -> str:
        try:
            p = target / f.file
            if not p.exists() or p.stat().st_size > MAX_SNIPPET_FILE:
                return ""
            if f.file not in cache:
                with open(p, "r", encoding="utf-8", errors="replace") as fh:
                    cache[f.file] = fh.readlines()
                if len(cache) > 200:
                    cache.clear()
                    with open(p, "r", encoding="utf-8", errors="replace") as fh:
                        cache[f.file] = fh.readlines()
            lines = cache[f.file]
            start = max(0, f.line - 1 - SNIPPET_CONTEXT)
            end = min(len(lines), (f.end_line or f.line) + SNIPPET_CONTEXT)
            out = []
            for i in range(start, end):
                marker = ">>" if (f.line - 1) <= i <= (f.end_line - 1) else "  "
                out.append(f"{marker}{i + 1:5d} | {lines[i].rstrip()}"[:400])
            return "\n".join(out[:40])
        except (OSError, UnicodeError):
            return ""
    return read_snippet


def write_reports(findings: list[Finding], meta: dict, outdir: Path, want_pdf: bool) -> dict:
    outdir.mkdir(parents=True, exist_ok=True)
    data = [f.to_dict() for f in findings]           # raw per-instance (evidence)
    grouped = consolidate(findings)                  # consolidated for the report
    meta = dict(meta, consolidated_findings=len(grouped))

    json_path = outdir / "findings.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({"meta": meta, "consolidated": grouped, "findings": data},
                  f, indent=1)

    csv_path = outdir / "findings.csv"
    cols = ["fid", "severity", "confidence", "fp_likelihood", "category", "owasp",
            "cwe", "title", "file", "line", "tools", "rule_id", "description",
            "remediation", "verification"]
    with open(csv_path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(cols)
        for d in data:
            row = dict(d)
            row["tools"] = ", ".join(d["tools"])
            w.writerow([row.get(c, "") for c in cols])

    html_path = outdir / "report.html"
    tpl = TEMPLATE.read_text(encoding="utf-8")
    tpl = tpl.replace("__SCR_META__", json.dumps(meta))
    tpl = tpl.replace("__SCR_DATA__", json.dumps(grouped).replace("</", "<\\/"))
    html_path.write_text(tpl, encoding="utf-8")

    result = {"html": str(html_path), "json": str(json_path), "csv": str(csv_path)}
    if want_pdf:
        pdf = _html_to_pdf(html_path, outdir / "report.pdf")
        if pdf:
            result["pdf"] = pdf
    return result


def _html_to_pdf(html_path: Path, pdf_path: Path) -> str | None:
    candidates = [
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        shutil.which("msedge"), shutil.which("chrome"), shutil.which("chromium"),
    ]
    browser = next((c for c in candidates if c and Path(c).exists()), None)
    if not browser:
        log("no Edge/Chrome found for PDF export - HTML report only")
        return None
    try:
        subprocess.run(
            [browser, "--headless", "--disable-gpu", "--no-pdf-header-footer",
             f"--print-to-pdf={pdf_path}", html_path.resolve().as_uri()],
            timeout=180, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # Edge can return before the file is flushed to disk — poll briefly
        for _ in range(30):
            if pdf_path.exists() and pdf_path.stat().st_size > 0:
                return str(pdf_path)
            time.sleep(0.5)
    except (subprocess.TimeoutExpired, OSError) as e:
        log(f"pdf export failed: {e}")
    return None

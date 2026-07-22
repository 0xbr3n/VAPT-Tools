# SCR-Suite

> **Fully Offline Source Code Review Automation for VAPT Engagements**

A standalone, air-gap-friendly replacement for Fortify-style automated source code review. Runs eight open-source SAST/SCA tools over a client codebase in parallel, merges and dedupes their findings, scores every result through a false-positive triage pass, and emits a filterable HTML report plus PDF/JSON/CSV — **without a single byte of client code ever leaving the machine**.

```
 ____   ____ ____       ____        _ _
/ ___| / ___|  _ \     / ___| _   _(_) |_ ___
\___ \| |   | |_) |____\___ \| | | | | __/ _ \
 ___) | |___|  _ <_____|__) | |_| | | ||  __/
|____/ \____|_| \_\    |____/ \__,_|_|\__\___|

           Bren's Source Code Review Automater
```

---

## ⚠️ Legal Disclaimer

This tool is for **authorised source code review engagements only**. Client source code is confidential material — only run it against codebases you have explicit written permission to assess, and follow your organisation's data-handling policy for the resulting reports. Scan outputs contain code snippets from the reviewed application and must be treated as client-confidential.

---

## What It Does

Commercial SAST tooling is expensive, licence-locked, and usually cloud-backed — which is a non-starter when the client's contract says their code never leaves their premises. Running the open-source equivalents by hand means invoking eight different tools with eight different flag sets, then manually reconciling eight incompatible output formats, then wading through thousands of duplicated and false-positive findings.

This framework does the whole pipeline in one command:

```
detect languages → run tools in parallel → normalise to a common model
   → dedupe across tools → triage false positives → report
```

**1. Runs the whole toolchain from one command**
Point it at a source directory. It fingerprints the languages and frameworks present, decides which scanners are relevant, and runs them with the correct offline flags — no per-tool configuration.

**2. Never touches the network**
Every tool is launched with its no-update/no-telemetry flags, *and* every child process is spawned with `HTTP_PROXY`/`HTTPS_PROXY`/`JAVA_TOOL_OPTIONS` pointed at an unroutable proxy (`127.0.0.1:1`). Even a misbehaving scanner physically cannot phone home. All downloads happen once, during setup, on a separate machine — before any client code is involved.

**3. Merges eight output formats into one**
SARIF, JSON, CSV and bespoke formats are normalised into a single finding model. Findings from different tools describing the same issue (same file + category within 3 lines, or the same CVE) are merged, and multi-tool agreement raises the confidence score.

**4. Triages the noise instead of dumping it on you**
Every finding is scored on tool-reported confidence, taint-vs-pattern rule type, test/vendored/minified/generated paths, placeholder secrets, and known-noisy rule families. The result is a `confidence` and `fp_likelihood` rating. **Nothing is ever deleted** — likely false positives are flagged and hidden behind a report toggle, but remain in the JSON/CSV for audit.

**5. Produces a report you can hand over**
A self-contained HTML report (works with no internet) with severity cards, category charts, live filters, expandable code snippets, and per-category *"how to verify"* and remediation guidance — plus PDF, JSON and CSV exports.

On a large Java codebase this pipeline reduced **7,202 raw tool findings to 9 grouped, report-ready rows** (257 per-instance) after dedupe and triage.

---

## Tools Orchestrated

| Tool | What it finds | How it runs offline |
|---|---|---|
| **Opengrep** (Semgrep fork) | XSS incl. DOM-based, SQLi, command injection, SSTI, XXE, SSRF, path traversal, IDOR/access-control, cookie flags, weak crypto — ~30 languages | Local `semgrep-rules` pack, `--metrics off` |
| **Bandit** | Python-specific SAST | pip package, offline by nature |
| **Gitleaks** | Hardcoded secrets and credentials (values redacted in reports) | Single binary |
| **Grype** | **Primary dependency/library CVE scanner** — fingerprints bundled JARs/DLLs/wheels, even loose `WEB-INF/lib/*.jar` with no manifest | Single-archive DB, `GRYPE_DB_AUTO_UPDATE=false` |
| **Trivy** | Second opinion: dependency CVEs, secrets, IaC misconfigurations | DB pre-cached, `--skip-db-update` |
| **Checkov** | Terraform / Dockerfile / Kubernetes / CloudFormation misconfigs | Policies ship in the package |
| **OWASP Dependency-Check** | *(optional, off by default)* alternative dependency CVE scanner | Its NVD API download is slow and paginates 180+ times — Grype is preferred |
| **SonarQube** | *(optional, off by default)* code quality + security hotspots | Local server only — the adapter **refuses any non-localhost URL** by design |
| **Manual checks** | Hand-run SCR greps: `eval()` injection, AWS keys, JWTs, hardcoded passwords, dev comments, MD5, insecure `random()`, TLS versions, cleartext `http://`, stack traces | Pure-Python regex — needs no external tool at all |

Adapters are ~60 lines each, so adding SpotBugs/FindSecBugs, PMD, cppcheck, gosec, KICS or Syft is straightforward.

---

## Data Containment Guarantees

1. **Two-phase design** — all downloads (tool binaries, rule packs, vulnerability databases) happen once during setup on a machine *with* internet, **before** any client code is involved. Scanning is 100% local.
2. **Offline flags** — every tool is invoked with its no-update/no-telemetry switches (`--metrics off`, `--noupdate`, `--skip-db-update`, `--disableOssIndex`, …).
3. **Network black-hole** — every child process is launched behind an unroutable proxy so a tool cannot exfiltrate even if it tries.
4. **No API keys needed to scan.** An NVD API key is *optional* and only speeds up the one-time database download during setup.
5. For belt-and-braces on a client site: pull the network cable. The scan needs no connectivity at all.

---

## Manual Checks

The `manual` adapter encodes the regex and keyword searches you'd otherwise run by hand after the automated scans, so they flow through the same dedupe → triage → report pipeline. Rules live in **`manual_rules.json`** — edit that file to add, remove or retune a check with no code change. Each rule carries its own category, CWE, severity and base confidence; deliberately broad checks (`password` keyword, TLS strings, emails, comments) are given low severity and confidence so triage flags them for a quick confirm rather than flooding the report.

---

## Requirements

- **Python 3.9+** on PATH (the orchestrator is pure standard library)
- **Windows** for the one-click `.cmd` launchers; the Python package itself is portable
- Roughly **2–4 GB** of disk for `tools\` after setup (mostly vulnerability databases)
- Optional: **Docker** for the local SonarQube server, **Ollama** for the LLM triage layer

No pip packages are required for the orchestrator itself — the scanners are fetched by the setup script.

---

## Setup

### Phase 1 — one time, on a machine WITH internet (no client code involved)

```powershell
cd SCR-Suite
powershell -ExecutionPolicy Bypass -File setup\setup_tools.ps1

# optional: a free NVD API key speeds up the database download
powershell -ExecutionPolicy Bypass -File setup\setup_tools.ps1 -NvdApiKey "your-free-nvd-key"
```

This fills `tools\` with every scanner, rule pack and database.

### Phase 2 — on the offline machine

Copy the **entire folder** across, then run once:

```
setup\setup_offline.cmd
```

### Keeping databases current

Run periodically on the online machine, then re-copy `tools\`:

```powershell
powershell -ExecutionPolicy Bypass -File setup\update_databases.ps1 -NvdApiKey "your-key"
powershell -ExecutionPolicy Bypass -File setup\update_databases.ps1 -Only trivy,rules,sonar
```

> **Never commit your NVD API key.** `setup/nvd_api_key.txt` is gitignored — keep it that way, and pass the key as a parameter instead of hardcoding it.

---

## Scanning

```
run_scan.cmd "C:\path\to\client\source"
```

Or directly:

```bash
python -m scr --target "C:\path\to\client\source" --pdf
python -m scr --target ... --only semgrep,gitleaks      # subset of tools
python -m scr --target ... --skip depcheck              # skip slow tools
```

### Output

Results land in `reports\<project>_<timestamp>\`:

| File | Contents |
|---|---|
| `report.html` | Self-contained report — severity cards, category chart, filters (severity/category/tool/confidence/search/hide-likely-FPs), expandable findings with code snippets, triage notes, verification steps and remediation |
| `report.pdf` | Print of the HTML via headless Edge (`--pdf`) |
| `findings.json` / `findings.csv` | Full raw finding set, including flagged false positives |
| `drg_import.csv` | Ready to import into the VAPT report generator |

---

## Report-Generator Import

Every scan writes a **`drg_import.csv`** shaped for the VAPT Report Generator. By default it contains the *actionable* set: grouped by vulnerability type (one row per issue, e.g. "SQL Injection (6 locations)" with all affected `file:line` locations aggregated), with likely false positives dropped. Columns map onto the Observation / Implication / Recommendation house format, plus Severity, OWASP, CWE and detecting tools.

Flags to change what goes in:

- `--drg-per-instance` — one row per individual finding instead of grouping
- `--drg-include-info` — also include info-severity findings
- `--drg-include-fp` — also include findings flagged as likely false positives

---

## Optional LLM Triage Layer

An optional reasoning pass reviews each finding for false positives and suggests exploitation vectors, using a **local Ollama model** — no data egress. See **[LLM_LAYER.md](LLM_LAYER.md)** for the full design.

```
run_scan_llm.cmd "C:\path\to\client\source"
```

Backends: `poc` (offline deterministic reasoning, no model call), `onprem` (an internal OpenAI-compatible endpoint), or `disabled`. By default the LLM is **advisory only** — it annotates findings but does not change ranking unless `influence_ranking` is enabled.

---

## Configuration

Copy `config.default.json` to `config.json` to override: excluded directories and globs, per-adapter enable/disable, explicit tool paths, timeouts, SonarQube settings, and the LLM backend. `config.json` is gitignored so your local settings never get committed.

---

## Folder Layout

```
SCR-Suite\
├── run_scan.cmd              one-click scan
├── run_scan_llm.cmd          scan with the local LLM triage pass
├── config.default.json       defaults (copy to config.json to override)
├── manual_rules.json         manual-check regexes (editable, no code change)
├── scr\                      orchestrator (pure stdlib Python)
│   ├── __main__.py           pipeline: detect → run → dedupe → triage → report
│   ├── adapters\             one module per tool (incl. manualscan.py)
│   ├── dedupe.py triage.py consolidate.py drg_export.py llm_triage.py
│   └── report.py report_template.html
├── setup\
│   ├── setup_tools.ps1       one-time online download of tools/DBs/rules
│   ├── update_databases.ps1  refresh DBs/rules/scanner
│   ├── clean_rules.py        prunes the semgrep-rules pack to valid rules
│   ├── run_sonarqube.cmd     start a local SonarQube server (optional)
│   └── setup_offline.cmd     one-time venv creation on the offline machine
├── tools\                    binaries, rules, CVE databases  (gitignored)
└── reports\                  scan outputs                    (gitignored)
```

> `tools\`, `reports\`, `config.json` and `setup/nvd_api_key.txt` are gitignored by design — they hold downloaded binaries, client scan output, and secrets respectively.

---

<div align="center">
  <sub>Built by a pentester, for pentesters · Singapore 🇸🇬</sub>
</div>

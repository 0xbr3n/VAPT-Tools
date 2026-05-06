# VA Automater

> **Vulnerability Assessment Report Automation for InfraVA / VAPT Engagements**

A terminal-driven Python tool that automates the tedious manual work in VA reporting — removing previously risk-accepted findings, bucketing findings by category, detecting outdated software, reassessing CVSS scores, and closing remediated findings in your tracking spreadsheet. Built to speed up quarterly VAPT reporting cycles.

```
 ____                  _       ____                       _     _             
| __ ) _ __ ___ _ __  ( )___  |  _ \ ___ _ __   ___  _ __| |_  | |__   ___    
|  _ \| '__/ _ \ '_ \ |// __| | |_) / _ \ '_ \ / _ \| '__| __| | '_ \ / _ \   
| |_) | | |  __/ | | |  \__ \ |  _ <  __/ |_) | (_) | |  | |_  | | | |  __/   
|____/|_|  \___|_| |_|  |___/ |_| \_\___| .__/ \___/|_|   \__| |_| |_|\___|   
                                        |_|                                    
              Bren's Report Automater
```

---

## ⚠️ Legal Disclaimer

This tool processes vulnerability scan data from authorised assessments only. Ensure all scan data handled by this tool was collected with appropriate written permission from the asset owner.

---

## What It Does

Manual VA reporting involves hours of repetitive work every quarter: cross-referencing accepted risks from last quarter, separating SSL findings from the main list, identifying outdated software findings, and manually marking remediated items as closed in a tracker spreadsheet. This script automates all of it.

**Option 1 — InfraVA Automation (New Scan)**
Process a fresh set of Nessus CSV exports with no prior scan to compare against. Buckets findings into categories and outputs ready-to-use Excel files.

**Option 2 — InfraVA Automation (Recurring / Rescan)**
Compares the current scan against last quarter's risk-accepted findings and removes already-accepted items automatically. Same bucketing workflow as Option 1, plus a diff output showing what was removed.

**Option 3 — Tracker Closure (Image-Safe)**
Opens your previous quarter's Excel tracker via Excel COM (so images and formatting are preserved), compares each open finding against the current scan, and marks anything no longer appearing as Closed — with an optional comment fill. No reformatting, no broken images.

---

## Features

- **Multi-file Nessus CSV ingestion** — loads an entire folder of CSV exports and merges them automatically
- **Flexible column detection** — handles different column naming conventions across Nessus versions and custom exports (`Plugin Name`, `Finding Name`, `IP Address`, `Severity`, etc.)
- **Name + Host matching** — normalises finding names (strips punctuation, case, whitespace) and extracts IPs from mixed-format host cells for robust cross-scan matching
- **Multi-IP host support** — a single tracker row listing multiple IPs is expanded correctly during matching
- **Risk-accepted removal** — removes findings that were accepted last quarter by matching on normalised Name + Host pairs across all sheets of the previous file
- **Finding bucketing** — automatically separates SSL/TLS findings, information disclosure findings, and outdated software/patch findings into separate output files
- **Outdated software detection** — keyword and pattern matching across name, solution and plugin output fields with a refined exclusion list to reduce false positives
- **CVSS 3.1 bulk reassessment** — optional interactive CVSS re-scoring per unique finding name, with per-finding or batch vector entry
- **Image-safe tracker closure** — uses Excel COM (not openpyxl) so charts, logos and formatting in the tracker are never touched
- **Auto port-mode detection** — detects whether tracker host cells embed port numbers (e.g. `10.0.0.1 (443)`) and adjusts matching logic automatically
- **Quick match tester** — before closing anything, run a single-row test to verify your column mapping is correct
- **Low match-rate safety guard** — warns and confirms before saving if fewer than 20% of rows matched (catches wrong sheet/column selections)

---

## Requirements

### Python
Python 3.10+ (uses `list[str]` and `str | None` type hints)

### Dependencies

```bash
pip install pandas openpyxl cvss pywin32
```

| Package | Purpose | Required? |
|---|---|---|
| `pandas` | Data loading and manipulation | **Yes** |
| `openpyxl` | Excel file writing (`.xlsx` output) | **Yes** |
| `cvss` | CVSS 3.1 score calculation | Optional — CVSS reassessment skipped if absent |
| `pywin32` | Excel COM for image-safe tracker update | Optional — Option 3 only, Windows only |

### Platform Note

- **Options 1 and 2** work on any OS (Windows, macOS, Linux)
- **Option 3** requires **Windows** with **Microsoft Excel installed** (uses COM automation)

---

## Installation

```bash
git clone https://github.com/yourusername/va-automater.git
cd va-automater
pip install pandas openpyxl cvss pywin32
python VA-Automater.py
```

---

## Usage

```bash
python VA-Automater.py
```

You will be prompted to choose an option:

```
  1) InfraVA report automation (Options 1/2 workflow)
  2) Option 3: Compare old tracker vs current scan and close missing (image-safe)
```

---

## Workflow Guides

### Option 1 — New VA Scan (First-Time)

Use this when there is no previous scan to compare against, such as a first-ever assessment of a new client.

```
Prompt: current Nessus CSV folder path
Prompt: output folder path

Output files produced:
  remaining_findings.xlsx       ← main findings list after bucketing
  removed_findings.xlsx         ← empty (no removal in new scan mode)
  SSL_findings.xlsx             ← SSL/TLS-related findings
  Info_Disclosure_Findings.xlsx ← information disclosure findings
  outdated_patches_versions.xlsx← outdated software / missing patches
```

### Option 2 — Recurring VA Scan (Rescan)

Use this every subsequent quarter. Requires last quarter's risk-accepted file and open findings file.

```
Prompt: current Nessus CSV folder path
Prompt: previous risk-accepted findings file (xlsx/xls/csv)
Prompt: previous open findings file (xlsx)
Prompt: output folder path

Steps performed automatically:
  1. Load all current CSVs from folder
  2. Load all sheets from previous risk-accepted file
  3. Normalise names and extract IPs from host cells
  4. Remove previously accepted findings (Name + Host match)
  5. Bucket remaining into SSL, Info Disclosure, Outdated
  6. Optional CVSS 3.1 reassessment per unique finding name
  7. Write all output Excel files
```

### Option 3 — Tracker Closure (Image-Safe)

Use this to update your tracker spreadsheet after a rescan. Opens the file through Excel COM so images, charts and formatting are untouched.

```
Prompt: old tracker Excel path (previous quarter)
Prompt: new scan file path (current quarter xlsx/csv)

Interactive steps:
  1. Select the correct sheet from both files
  2. Map column names (Name, Host, Port, Status)
  3. Choose port matching mode (auto-detected)
  4. Optionally run a quick single-row test match
  5. Review match statistics before saving
  6. Save in-place or as a new timestamped file

For each Open row in the tracker:
  - If the finding+host is STILL in the current scan → leave as Open
  - If NOT found in current scan → mark as Closed (optionally fill comment)
```

---

## Input File Formats

### Nessus CSV Exports

Standard Nessus CSV exports. The script auto-detects column names from a list of known variants:

| Standard Name | Also Recognised As |
|---|---|
| `Name` | `Plugin Name`, `Plugin`, `Finding Name` |
| `Host` | `IP Address`, `IP` |
| `Port` | `Service Port` |
| `Risk` | `Severity` |
| `Description` | `Plugin Description`, `Synopsis` |
| `Solution` | `Remediation`, `Recommendations`, `Recommendation` |
| `Plugin Output` | `Output`, `Plugin output` |
| `CVSS Version 2.0 Base Score` | `CVSS v2.0 Base Score`, `CVSSv2 Base Score` |

Place all CSV files for the current quarter in a single folder. The script loads and merges them all automatically.

### Previous Risk-Accepted File

Any `.xlsx`, `.xls` or `.csv` file. For Excel files, **all sheets** are read. Each row must have at minimum a Name column and a Host column (any of the recognised variants above). Multiple IPs in a single host cell are all extracted and matched individually.

### Tracker File (Option 3)

Any Excel file (`.xlsx`/`.xls`). Must contain at minimum:
- A Name column
- A Host/IP column
- A Status column (values like `Open`, `Closed`, `Risk Accepted`)

---

## Output Files

| File | Description |
|---|---|
| `remaining_findings.xlsx` | All findings after risk-accepted removal and bucketing |
| `removed_findings.xlsx` | Findings removed (matched previous risk-accepted list) |
| `SSL_findings.xlsx` | SSL/TLS, cipher, certificate findings |
| `Info_Disclosure_Findings.xlsx` | Information disclosure, banner, version findings |
| `outdated_patches_versions.xlsx` | Missing patches, outdated software, EOL versions |

All output files include `Comments` and `Status` columns pre-added for manual annotation.

---

## SSL / Info Disclosure Keywords

The bucketing is keyword-driven against the finding Name field.

**SSL / TLS findings matched on:**
`ssl`, `tls`, `cipher`, `cbc`, `weak cipher`, `weak encryption`, `dhe`, `rsa key`, `modulus`, `diffie-hellman`, `sweet32`, `certificate`, `cert`, `expiry`, `expiration`

**Information Disclosure findings matched on:**
`information disclosure`, `info disclosure`, `http server`, `http version`, `banner`, `snmp`, `ldap`, `kerberos`, `version disclosure`, `server header`

---

## Outdated Software Detection

The outdated detection logic uses three signals across the Name, Solution and Plugin Output fields:

**Strong solution hints** — phrases like `upgrade to`, `apply the latest`, `apply a security update`, `fixed version`, `cumulative update`, `hotfix`, `firmware`

**Strong name hints** — phrases like `less than`, `prior to`, `outdated`, `unsupported`, `end of life`, `EOL`

**KB article context** — presence of a KB number (`kb1234567`) combined with patch-related language (`missing`, `security update`, `cumulative update`)

A refined exclusion list prevents false positives from detection/enumeration plugins (OS version info, CPE listings, file history, registry scans, etc.).

---

## Matching Logic

### Name Normalisation
Finding names are normalised aggressively before comparison:
- Lowercased
- All non-alphanumeric characters removed
- Whitespace and NBSP collapsed

This means `"SSL Certificate Cannot Be Trusted"` and `"ssl certificate cannot be trusted"` and `"SSL Certificate Cannot Be Trusted  "` all match correctly.

### Host Normalisation
- IP addresses are extracted from the host cell using regex
- Multi-IP cells are expanded (each IP matched independently)
- Normalised to lowercase, stripped of whitespace

### Port Matching (Option 3)
- **Auto-detection** checks a sample of host cells for embedded port patterns like `10.0.0.1 (443)`, `10.0.0.1:443`, `10.0.0.1 [443]`
- If more than 15% of sampled rows contain embedded ports, port mode 1 (embedded) is recommended
- When matching with port: tries strict match (Name + Host + Port) first, then falls back to loose match (Name + Host) if no strict hit
- When matching without port: always uses loose match (Name + Host)

---

## CVSS 3.1 Reassessment

After bucketing, you are offered optional CVSS 3.1 re-scoring for SSL and Info Disclosure findings.

```
Requires:  pip install cvss   (python-cvss)

Workflow:
  1. Unique finding names are listed (no row counts shown)
  2. You can exclude specific findings from reassessment
  3. Choose: apply ONE vector to all, or skip
  4. Enter each CVSS 3.1 metric interactively:
       AV (N/A/L/P)   AC (L/H)   PR (N/L/H)
       UI (N/R)       S (U/C)    C/I/A (N/L/H)
  5. Score and severity label are calculated and applied
```

If `python-cvss` is not installed, this step is silently skipped.

---

## Option 3 — Safety Features

Before any changes are written to the tracker, the following safeguards run:

**Quick match tester** — enter a single finding name and IP to verify the column mapping and sheet selection are correct before processing all rows.

**Low match-rate warning** — if fewer than 20% of open rows are found in the current scan, you are warned and must explicitly confirm before saving. This catches the most common mistake of selecting the wrong sheet or wrong column.

**Save confirmation** — choose to overwrite the original file or save to a new timestamped copy (e.g. `tracker__updated_20250507_143022.xlsx`).

**Sample of unmatched rows** — after processing, up to 10 rows that were not found in the current scan are printed for manual review.

---

## Common Issues

**No CSV files found in folder**
Make sure the folder path points to a directory containing `.csv` files, not a single file path. All `.csv` files in the folder are loaded and merged.

**Column not found / empty output**
Run the tool and check the column detection output. If your Nessus export uses a non-standard column name, check the `ALT_COL_*` lists at the top of the script and add your column name there.

**Option 3: found-rate is 0% or very low**
Most commonly caused by selecting the wrong sheet from either file, or the wrong Name/Host column. Use the quick match tester (prompted before processing) to verify with a known finding before running the full comparison.

**Option 3: not available / COM error**
Option 3 requires Windows with Microsoft Excel installed. On non-Windows systems, export the tracker to CSV, make edits via Options 1/2 outputs, then re-import.

**CVSS reassessment skipped automatically**
Install the `cvss` package: `pip install cvss`

**Port matching not working as expected**
Check the auto-detected port mode printed during Option 3 setup. If your tracker uses `10.0.0.1 (443)` format, mode 1 should be selected. Use the quick match tester to verify a specific host+port combination before proceeding.

---

## File Structure

```
va-automater/
├── VA-Automater.py     # Main script — single file
└── README.md           # This file
```

---

## Changelog

| Version | Notes |
|---|---|
| Current | Image-safe Option 3 via Excel COM. Auto port-mode detection. Low match-rate safety guard. Quick match tester. Multi-IP host expansion. Refined outdated detection with exclusion list. CVSS 3.1 bulk reassessment. |

---

## Dependencies Reference

```bash
# Minimum install (Options 1 and 2 only)
pip install pandas openpyxl

# Full install (all features)
pip install pandas openpyxl cvss pywin32
```

---

## Licence

MIT Licence — free to use, modify and distribute. Attribution appreciated.

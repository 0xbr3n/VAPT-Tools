# VA Remediation Validator

> Automate the manual screenshot-vs-finding check after a vulnerability assessment.

After a Nessus scan, clients typically remediate the findings and send back screenshots as proof. Validating these manually — opening Excel, eyeballing each screenshot, comparing the IP and version against the corresponding row, finding-by-finding across hundreds of hosts — is a slow, error-prone slog.

This tool reads your VA report (`.xlsx` with screenshots embedded in an Evidence column), runs OCR on every screenshot, and flags whether the expected **Host/IP** and **fixed version** actually appear in the image. You only manually review the rows it can't auto-classify.

---

## Table of Contents

- [What it does](#what-it-does)
- [Example output](#example-output)
- [Installation](#installation)
- [Usage](#usage)
- [How it works](#how-it-works)
- [Output columns](#output-columns)
- [Validation logic](#validation-logic)
- [Limitations](#limitations)
- [Roadmap](#roadmap)
- [License](#license)

---

## What it does

For each row in the report, the script:

1. Pulls the embedded screenshot(s) from the row's Evidence cell.
2. Runs OCR (Tesseract) to extract the text from each screenshot.
3. Checks whether the **Host/IP** in that row appears in the OCR text.
4. (Optional) Checks whether the version in the screenshot is **`>=`** the required fixed version.
5. Writes a colour-coded verdict back into the spreadsheet.

You go from manually checking thousands of findings to manually checking only the few dozen that legitimately need a human eye.

---

## Example output

The script appends three columns to your input spreadsheet and colour-codes each row:

| Host | Fixed Version | Validation_Status | Validation_Notes |
|---|---|---|---|
| 10.0.0.5 | 8.9p1 | **PASS** | IP 10.0.0.5 found; Version '8.9p1' confirmed |
| 10.0.0.12 | 10.0.19041.4170 | **PASS** | IP 10.0.0.12 found; Version '10.0.19041.4170' confirmed |
| 10.0.0.20 | 2.4.58 | **FAIL** | IP mismatch: expected 10.0.0.20, screenshot shows ['10.0.0.99'] |
| 10.0.0.33 | 1.25.3 | **FAIL** | IP 10.0.0.33 found; Version too old: required >= 1.25.3 (screenshot shows ['1.18.0']) |
| 10.0.0.41 | 17.0.10 | **REVIEW** | No IP detected in screenshot; Version '17.0.10' confirmed |
| 10.0.0.55 | 8.0.36 | **NO_EVIDENCE** | No screenshot in evidence cell |
| 10.0.0.60 | 1.25.3 | **PASS** | IP 10.0.0.60 found; Version OK: screenshot shows 1.27.1 (>= required 1.25.3) |

Sort by `Validation_Status` and you can blow through the `PASS` rows, focus your manual effort on `REVIEW` and `FAIL`, and chase the client for any `NO_EVIDENCE`.

---

## Installation

### Prerequisites

- Python 3.8+
- Tesseract OCR engine

### Install Python dependencies

```bash
pip install openpyxl Pillow pytesseract
```

### Install Tesseract

| OS | Command |
|---|---|
| macOS | `brew install tesseract` |
| Ubuntu / Debian | `sudo apt-get install tesseract-ocr` |
| RHEL / CentOS | `sudo yum install tesseract` |
| Windows | Download from [UB-Mannheim/tesseract](https://github.com/UB-Mannheim/tesseract/wiki), then add the install directory to `PATH` |

### Verify

```bash
tesseract --version
python -c "import pytesseract, openpyxl, PIL; print('OK')"
```

---

## Usage

### Basic

```bash
python va_validator.py findings.xlsx \
    --ip-col       "Host" \
    --evidence-col "Evidence"
```

### With version checking (recommended)

```bash
python va_validator.py findings.xlsx \
    --ip-col       "Host" \
    --evidence-col "Evidence" \
    --version-col  "Fixed Version"
```

### All options

```
positional arguments:
  input                 Path to the input xlsx

options:
  -o, --output OUTPUT   Output xlsx path (default: <input>_validated.xlsx)
  --ip-col       NAME   Header name of the Host/IP column (required)
  --evidence-col NAME   Header name of the Evidence column (required)
  --version-col  NAME   Header name of the expected fixed-version column (optional)
  --sheet        NAME   Sheet name (default: active sheet)
  --dump-ocr            Print raw OCR text per row (debug mode)
```

Column names are matched **case-insensitively** against row 1 headers, so the script adapts to whatever naming convention the client used. Common variations like `Host`, `IP`, `IP Address`, `Asset`, `Evidence`, `Remediation Evidence`, `Screenshot`, `Proof`, `Fixed Version`, `Patched Version`, `Resolution` all work — just pass whatever the actual header text is.

### Example session

```
$ python va_validator.py client_report.xlsx \
    --ip-col "Host" --evidence-col "Evidence" --version-col "Fixed Version"

[1/4] Loading client_report.xlsx ...
      Sheet: Findings, rows: 1247, cols: 12
      IP col: Host (#3)
      Evidence col: Evidence (#11)
      Version col: Fixed Version (#7)
[2/4] Extracting embedded images ...
      Found 1198 image(s) across 1198 row(s)
[3/4] OCR + validation ...
[4/4] Saving client_report_validated.xlsx ...

==================================================
Done. 1246 row(s) processed.
  PASS           987  ( 79.2%)
  FAIL            42  (  3.4%)
  REVIEW         169  ( 13.6%)
  NO_EVIDENCE     48  (  3.9%)
==================================================
```

---

## How it works

```
   ┌─────────────────────┐
   │  findings.xlsx      │
   │  (Nessus + client   │
   │   screenshots)      │
   └──────────┬──────────┘
              │
              ▼
   ┌─────────────────────┐      Parses xl/drawings/*.xml
   │  Image extraction   │ ──── from the xlsx package
   │                     │      directly. No filename
   └──────────┬──────────┘      conventions needed.
              │
              ▼
   ┌─────────────────────┐      Upscales small images,
   │  Tesseract OCR      │ ──── handles dark/light themes.
   └──────────┬──────────┘
              │
              ▼
   ┌─────────────────────┐      IP regex with octet validation.
   │  IP + version       │ ──── Semver-aware version comparison
   │  matching           │      (accepts >= required version).
   └──────────┬──────────┘
              │
              ▼
   ┌─────────────────────┐
   │  validated.xlsx     │
   │  (PASS/FAIL/REVIEW/ │
   │   NO_EVIDENCE,      │
   │   colour-coded)     │
   └─────────────────────┘
```

---

## Output columns

The script appends three columns to the right of your existing data:

| Column | Description |
|---|---|
| `Validation_Status` | Verdict: `PASS`, `FAIL`, `REVIEW`, or `NO_EVIDENCE`. Colour-coded green/red/amber/grey. |
| `OCR_Found_IPs` | All IP-like strings the OCR detected, comma-separated. |
| `Validation_Notes` | Human-readable explanation of the verdict. |

### Status meanings

| Status | Meaning | Suggested action |
|---|---|---|
| `PASS` | Expected IP found in screenshot. Version (if checked) is `>=` required. | Trust + spot-check a sample. |
| `FAIL` | IP mismatch, OR IP matches but the version shown is still old. | Reject remediation, ask client to redo. |
| `REVIEW` | OCR couldn't extract an IP, or OCR failed entirely. | Eyeball it manually. |
| `NO_EVIDENCE` | Evidence cell has no embedded image. | Chase the client for a screenshot. |

---

## Validation logic

### IP matching

The expected IP from the row is checked against every IPv4-shaped string in the OCR text. Each candidate's octets are validated to be `0–255`. `0.0.0.0` is filtered out as noise.

### Version matching

This is the part that matters most for real-world reports — clients rarely patch to *exactly* the minimum required version. Instead, they typically jump to whatever's current.

The script does proper semver-style comparison: any version `>=` the required version passes.

| Required | Screenshot shows | Result |
|---|---|---|
| `1.25.3` | `1.25.3` | PASS (exact) |
| `1.25.3` | `1.25.10` | PASS (newer patch, two-digit) |
| `1.25.3` | `1.27.1` | PASS (newer minor) |
| `1.25.3` | `2.0.0` | PASS (newer major) |
| `1.25.3` | `1.25.2` | FAIL (older patch) |
| `1.25.3` | `1.18.0` | FAIL (older minor) |
| `8.9p1` | `9.6p1` | PASS (OpenSSH-style suffix) |
| `8.9p1` | `8.4p1` | FAIL (older with suffix) |
| `10.0.19041.4170` | `10.0.19041.5500` | PASS (Windows build) |
| `10.0.19041.4170` | `10.0.19041.3000` | FAIL (older Windows build) |
| `2.4.58` | `2.4.58-rc1` | FAIL (release candidate is technically pre-release) |

The notes column always tells you *which* version was detected, so you can see exactly why the script accepted or rejected it.

---

## Limitations

- **Image format**: Handles classic floating images (the default when you paste a screenshot into a cell). Excel's newer "Insert Picture **in Cell**" feature stores images differently and isn't yet supported — ask clients to use plain paste.
- **OCR quality**: Tesseract is decent but not perfect. Realistic accuracy:
  - Clean terminal output, `ipconfig`, Programs and Features → **80–90% auto-classified correctly**.
  - Heavily compressed phone photos of monitors, dark themes with thin fonts, screenshots cropped so the IP is off-frame → land in `REVIEW`. This is intentional — the script is conservative and won't `PASS` something it can't actually read.
- **Pre-release versions**: A screenshot showing `2.4.58-rc1` will NOT auto-pass a required `2.4.58`, because RCs are technically pre-release. These land in `FAIL` and you can manually override.
- **Hostname-only screenshots**: If the client's evidence shows only a hostname (e.g. `web-srv-01`) without an IP, the script can't validate. These land in `REVIEW`.

---

## Roadmap

Ideas for extending if you want to push accuracy higher:

- **Pre-process for dark themes**: invert + threshold dark-mode terminals before OCR.
- **Per-vulnerability keyword check**: for an "OpenSSH" finding, additionally assert `OpenSSH` appears in the OCR text.
- **MAC / hostname matching**: useful in environments where IPs rotate or aren't shown.
- **PaddleOCR backend**: noticeably better than Tesseract on noisy screenshots; heavier install.
- **"Insert Picture in Cell" support**: parse the `xr:absoluteAnchor` / cell-image dispimg references introduced in newer Excel versions.
- **HTML/PDF report output**: in addition to the xlsx, generate a stakeholder-friendly summary report.

---

## License

MIT — do whatever you want with it. Pull requests welcome.

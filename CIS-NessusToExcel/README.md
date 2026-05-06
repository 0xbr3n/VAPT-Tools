# Nessus Compliance to Excel

Convert Nessus **Policy Compliance** / **CIS Host Configuration Review (HCR)** scan results (`.nessus` XML) into a clean, styled Excel workbook that's easier to review, filter, and report on.

This is a purpose-built Python replacement for the compliance-related parts of the legacy `parse_nessus_xml.v24.pl` Perl script. It focuses specifically on Policy Compliance / CIS benchmark data rather than attempting to port the entire legacy parser 1:1.

---

## Features

- Accepts a **single** `.nessus` file or a **directory** containing multiple `.nessus` / `.xml` files
- Extracts Policy Compliance / audit results per host
- Auto-detects benchmark level (**L1 / L2**) where possible
- Auto-detects benchmark profile (e.g. *CIS Microsoft Windows Server 2022 Benchmark*)
- Produces a styled `.xlsx` workbook containing:
  - **Summary** — overall metrics, result counts, benchmark level breakdown
  - **All Compliance** — every check across every host in one table
  - **Host Summary** — per-host pass/fail/warning counts
  - **One worksheet per policy / plugin family**
- Preserves leading `=` characters in values so Excel does **not** treat them as formulas
- Adds Excel tables, frozen header rows, auto-filters, and tuned column widths
- Tolerates the unbound `cm:` prefix often seen in Nessus compliance XML

---

## Requirements

- **Python 3.9+**
- **openpyxl**

Install the dependency:

```bash
pip install openpyxl
```

Or, if you prefer a `requirements.txt`:

```text
openpyxl>=3.1
```

```bash
pip install -r requirements.txt
```

---

## Installation

Clone the repository:

```bash
git clone https://github.com/<your-username>/<your-repo>.git
cd <your-repo>
pip install -r requirements.txt
```

No further setup is required — the script is a single self-contained file.

---

## Usage

### Parse a single `.nessus` file

```bash
python nessus_compliance_to_excel.py -f scan.nessus
```

### Parse every `.nessus` / `.xml` file in a directory

```bash
python nessus_compliance_to_excel.py -d /path/to/scans
```

### Specify an output workbook path

```bash
python nessus_compliance_to_excel.py -d /path/to/scans -o WDN_CIS_Report.xlsx
```

### Command-line options

| Flag | Description |
|------|-------------|
| `-f`, `--file` | Single `.nessus` / `.xml` file to parse |
| `-d`, `--directory` | Directory containing `.nessus` / `.xml` files |
| `-o`, `--output` | Output `.xlsx` path (optional). Defaults to a timestamped filename next to the input |

> Use **either** `-f` **or** `-d`, not both.

If `-o` is not supplied, the workbook is written next to the input as:

- `<input-name>_compliance_<YYYYMMDD_HHMMSS>.xlsx` (single-file mode), or
- `nessus_compliance_<YYYYMMDD_HHMMSS>.xlsx` inside the input directory (directory mode).

---

## Output workbook structure

| Sheet | Purpose |
|-------|---------|
| **Summary** | Generation timestamp, total rows, unique hosts/policies, result counts (FAILED / PASSED / WARNING / ERROR / INFO / UNKNOWN), benchmark-level distribution |
| **All Compliance** | Every compliance check, with host details, plugin metadata, requirement, system value, severity, result, etc. |
| **Host Summary** | One row per host with PASS / FAIL / WARNING / ERROR / INFO / UNKNOWN totals |
| **\<Policy Name\>** | One sheet per policy/plugin family (e.g. *CIS Microsoft Windows Server 2022 Benchmark v2.0.0 L1 Member Server*) |

### Columns in the All Compliance / per-policy sheets

`source_file`, `host_name`, `ip_address`, `fqdn`, `operating_system`, `policy_name`, `plugin_id`, `plugin_name`, `benchmark_level`, `benchmark_profile`, `policy_setting`, `description_of_requirement`, `solution`, `result`, `system_value_or_error`, `compliance_requirement`, `severity`, `service_name`, `port`, `protocol`, `see_also`, `synopsis`, `description`.

---

## Example output

```text
[*] Parsing: /scans/win2022-host01.nessus
    -> extracted 412 compliance rows
[*] Parsing: /scans/win2022-host02.nessus
    -> extracted 412 compliance rows
[+] Excel workbook written to: /scans/nessus_compliance_20260507_142231.xlsx
[+] Total compliance rows: 824
```

---

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Bad arguments, missing input, or XML parse error |
| `2` | No Policy Compliance / CIS rows were found in the supplied input |

---

## Notes & limitations

- The script targets **Policy Compliance / Host Configuration Review** plugins. Standard vulnerability findings are **not** exported.
- A `ReportItem` is treated as a compliance item if its `pluginFamily` is `Policy Compliance` **or** if it contains any `compliance-*` / `cm:compliance-*` child element.
- Nessus compliance XML often uses an undeclared `cm:` namespace prefix. The parser rewrites `<cm:` → `<cm_` before parsing so Python's `ElementTree` can read it.
- Benchmark level detection looks for `L1` / `L2` / `Level 1` / `Level 2` substrings in the plugin name, check name, info, and description fields. When none of these are present, the level is reported as `Unknown`.
- Sheet names are sanitized to comply with Excel's 31-character limit and forbidden-character rules; duplicates are suffixed (`_2`, `_3`, …).

---

## Contributing

Issues and pull requests are welcome. If you hit a `.nessus` file the parser doesn't handle well, please attach a sanitized snippet (or describe the structure) so the issue can be reproduced.

---

## License

Add your preferred license here (MIT, Apache-2.0, GPL-3.0, etc.) and include a corresponding `LICENSE` file in the repository root.

---

## Acknowledgements

- Inspired by the compliance-parsing logic in the legacy `parse_nessus_xml.v24.pl`.
- Built with [openpyxl](https://openpyxl.readthedocs.io/).

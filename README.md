# 🛠️ VAPT-Tools

> A personal collection of open-source tools built to automate, streamline, and supercharge penetration testing and vulnerability assessment workflows.

[![My Website](https://img.shields.io/badge/🌐_My_Website-0xbr3n.com-8b5cf6?style=for-the-badge&labelColor=0d1117)](https://0xbren.com)

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-0077b5?style=for-the-badge&logo=linkedin&labelColor=0d1117)](https://www.linkedin.com/in/brendon-teo-195971152/)
[![Tools](https://img.shields.io/badge/Tools-4-00d4ff?style=for-the-badge&labelColor=0d1117)](#tools)
[![Language](https://img.shields.io/badge/Language-Python-3776ab?style=for-the-badge&logo=python&labelColor=0d1117)](https://www.python.org/)

---

## 📦 Tools Overview

| Tool | Category | Description |
|---|---|---|
| [BT-WebSuite](#-bt-websuite) | Web VAPT | Automated web recon, fuzzing & vulnerability discovery |
| [CIS-NessusToExcel](#-cis-nessustoexcel) | Reporting | Converts Nessus CIS scans into client-ready Excel reports |
| [Infra-VA (VA-Automater)](#-infra-va--va-automater) | Infra VAPT | Automates VA report processing and tracking |
| [OSED-Automation](#-osed-automation) | Exploit Dev | Exploit development scaffolding and automation |

---

## 🌐 BT-WebSuite

**Category:** Web VAPT | **Language:** Python

A custom web security testing suite built for Web Application VAPT engagements. Automates the tedious early-phase recon work so you can focus on actual exploitation. Designed to work alongside Burp Suite Professional durign Web VAPT engagements, semni-automating tedious or repetive checks.

**Features:**
- Full interactive prompt driven style 
- Automated endpoint enumeration and directory fuzzing
- Parameter discovery and injection point mapping
- Custom fingerprinting for common web vulnerabilities
- Modular design — run individual modules or chain them into a full pipeline

**Use case:** Speeds up the recon and discovery phase of web application penetration tests, particularly useful for large-scope assessments with many subdomains or endpoints.

```bash
cd BT-WebSuite
python3 bt_websuite.py
```

---

## 📊 CIS-NessusToExcel

**Category:** Reporting / Compliance | **Language:** Python

Eliminates hours of manual post-scan formatting. Takes raw Nessus CIS compliance scan output and transforms it into a clean, structured, client-ready Excel workbook — complete with comply/non-comply summaries, finding categorisation, and remediation tracking.

**Features:**
- Parses `.nessus` CIS benchmark scan files automatically
- Generates Excel reports with comply / non-comply breakdown
- Summary dashboard tab for executive reporting
- Colour-coded findings by compliance status
- Allows clients to track and prioritise remediation with ease

**Use case:** Every infrastructure engagement that includes a CIS benchmark assessment. Saves significant post-engagement time and ensures consistent report formatting across all clients.

```bash
cd CIS-NessusToExcel
python3 nessus_compliance_to_excel.py -f Linux_HCR.nessus
```
OR
```bash
cd CIS-NessusToExcel
python3 nessus_compliance_to_excel.py -d Nessus_CIS_Scans
```

---

## 🔍 Infra-VA / VA-Automater

**Category:** Infrastructure VAPT | **Language:** Python

A terminal-driven automation tool that handles the most repetitive and time-consuming parts of VA reporting cycles. Built specifically for teams running recurring quarterly or annual vulnerability assessments.

**Features:**
- Full interactive prompt driven style 
- Removes previously risk-accepted findings automatically from new scan results
- Buckets findings by vulnerability category for structured reporting
- Detects outdated/EOL software versions and flags them
- Reassesses and validates CVSS scores against current NVD data
- Closes remediated findings in your tracking spreadsheet
- Generates delta reports showing what's new, fixed, and outstanding

**Use case:** Quarterly VAPT reporting cycles where you need to reconcile new scan results against historical findings, risk acceptances, and remediation tracking sheets — without doing it manually every time.

```bash
cd Infra-VA
python3 va_automater.py
```

---

## 💥 OSED-Automation

**Category:** Exploit Development | **Language:** Python

A set of automation scripts built during OSED (Offensive Security Exploit Developer) exam preparation. Reduces the repetitive manual setup involved in exploit development workflows so you can iterate faster.

**Features:**
- Full interactive prompt driven style 
- Bad character analysis — automated identification of bad chars in shellcode buffers
- Shellcode generation helpers and integration scaffolding
- Skeleton exploit script generation for common vulnerability classes (SEH, stack BOF, etc.)
- Offset calculation and EIP/RIP control verification helpers
- Pattern generation and cyclic offset detection
- ROP/ASLR Bypass with command prompts to run in Target machine

**Use case:** Buffer overflow and exploit development engagements, CTF prep, and OSED/OSCE3 exam preparation. Also useful as a teaching aid for understanding exploit development fundamentals.

```bash
cd OSED-Automation
python3 bof_toolkit.py
```

---

## 🚀 Getting Started

**Prerequisites:**
```bash
Python 3.8+
pip install -r requirements.txt   # inside each tool's folder
```

**Clone the repo:**
```bash
git clone https://github.com/brendontkl/VAPT-Tools.git
cd VAPT-Tools
```

Each tool lives in its own subdirectory with its own `README.md` and `requirements.txt`. Navigate into the relevant folder and follow the tool-specific instructions.

---

## ⚠️ Legal Disclaimer

> All tools in this repository are developed for **authorised security testing, research, and educational purposes only**. Use of these tools against systems without explicit written authorisation is illegal and unethical. The author accepts no liability for misuse. Always obtain proper permission before conducting any security assessment.

---

## 📬 Contact

| Platform | Link |
|---|---|
| Email | [btkl123@gmail.com](mailto:btkl123@gmail.com) |
| LinkedIn | [linkedin.com/in/brendon-teo-195971152](https://www.linkedin.com/in/brendon-teo-195971152/) |
| GitHub | [github.com/brendontkl](https://github.com/brendontkl) |
| Medium | [medium.com/@btkl123](https://medium.com/@btkl123) |
| Portfolio | [0xbren.com](https://brendontkl.github.io) |

---

<div align="center">
  <sub>Built by a pentester, for pentesters · Singapore 🇸🇬</sub>
</div>

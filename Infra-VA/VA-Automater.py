import os
import re
import sys
import platform
from glob import glob
from datetime import datetime

import pandas as pd

# Optional dependency for CVSS (python-cvss)
try:
    from cvss import CVSS3
    HAS_CVSS = True
except Exception:
    HAS_CVSS = False

# Excel COM (image-safe edits) for Option 3
try:
    import win32com.client as win32
    HAS_WIN32COM = True
except Exception:
    HAS_WIN32COM = False


ASCII_ART = r"""
 ____                  _       ____                       _     _             
| __ ) _ __ ___ _ __  ( )___  |  _ \ ___ _ __   ___  _ __| |_  | |__   ___    
|  _ \| '__/ _ \ '_ \ |// __| | |_) / _ \ '_ \ / _ \| '__| __| | '_ \ / _ \   
| |_) | | |  __/ | | |  \__ \ |  _ <  __/ |_) | (_) | |  | |_  | | | |  __/   
|____/|_|  \___|_| |_|  |___/ |_| \_\___| .__/ \___/|_|   \__| |_| |_|\___|   
                                        |_|                                    
              Bren's Report Automater
"""


# -------------------------
# Common column names
# -------------------------
COL_NAME = "Name"
COL_HOST = "Host"
COL_PORT = "Port"
COL_RISK = "Risk"
COL_DESC = "Description"
COL_SOLUTION = "Solution"
COL_PLUGIN_OUTPUT = "Plugin Output"
COL_CVSS2 = "CVSS Version 2.0 Base Score"

ALT_COL_NAME = ["Plugin Name", "Plugin", "Finding Name"]
ALT_COL_HOST = ["Host", "IP Address", "IP"]
ALT_COL_PORT = ["Port", "Service Port"]
ALT_COL_RISK = ["Risk", "Severity"]
ALT_COL_DESC = ["Description", "Plugin Description", "Synopsis"]
ALT_COL_SOLUTION = ["Solution", "Remediation", "Recommendations", "Recommendation"]
ALT_COL_PLUGIN_OUTPUT = ["Plugin Output", "Output", "Plugin output"]
ALT_COL_CVSS2 = ["CVSS Version 2.0 Base Score", "CVSS v2.0 Base Score", "CVSS Base Score", "CVSSv2 Base Score"]

OUT_REMAINING = "remaining_findings.xlsx"
OUT_REMOVED = "removed_findings.xlsx"
OUT_CH4_REMEDIATED = "chapter4_remediated.xlsx"
OUT_SSL = "SSL_findings.xlsx"
OUT_INFO = "Info_Disclosure_Findings.xlsx"
OUT_OUTDATED = "outdated_patches_versions.xlsx"
OUT_SUMMARY = "summary_report.txt"

SSL_KEYWORDS = [
    "ssl", "tls", "cipher", "cbc", "weak cipher", "weak encryption",
    "dhe", "rsa key", "modulus", "diffie-hellman", "sweet32",
    "certificate", "cert", "expiry", "expiration"
]
INFO_KEYWORDS = [
    "information disclosure", "info disclosure", "http server", "http version",
    "banner", "snmp", "ldap", "kerberos", "version disclosure", "server header"
]

# -------------------------
# Helpers
# -------------------------
def yn(prompt: str, default: str = "n") -> bool:
    default = default.lower().strip()
    while True:
        x = input(prompt).strip().lower()
        if not x:
            x = default
        if x in ("y", "yes"):
            return True
        if x in ("n", "no"):
            return False
        print("Please enter y/n.")

def pick_first_existing(df: pd.DataFrame, candidates: list[str]) -> str | None:
    df.columns = df.columns.str.strip()
    cols = set(df.columns.tolist())
    for c in candidates:
        if c in cols:
            return c
    return None

def ensure_cols(df: pd.DataFrame, needed: list[str]) -> pd.DataFrame:
    for c in needed:
        if c not in df.columns:
            df[c] = ""
    return df

def normalize_text(s: str) -> str:
    s = "" if s is None else str(s)
    s = s.replace("\u00A0", " ")  # NBSP
    s = s.strip().lower()
    s = re.sub(r"\s+", " ", s)
    return s

def normalize_key_alnum(s: str) -> str:
    """Strong key: remove ALL non-alphanumeric."""
    s = "" if s is None else str(s)
    s = s.replace("\u00A0", " ")
    s = s.lower()
    return re.sub(r"[^a-z0-9]+", "", s)

_ip_regex = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

def extract_ips(cell: str) -> list[str]:
    text = "" if cell is None else str(cell)
    found = _ip_regex.findall(text)
    out, seen = [], set()
    for ip in found:
        ipn = ip.strip()
        if ipn and ipn not in seen:
            seen.add(ipn)
            out.append(ipn)
    return out

def extract_first_ip(cell: str) -> str:
    ips = extract_ips(cell)
    return ips[0] if ips else ""

def safe_port_norm(p):
    """Normalize port: 0/blank => '' (host-level)."""
    if p is None:
        return ""
    s = str(p).strip()
    if s == "" or s.lower() == "nan":
        return ""
    try:
        f = float(s)
        if int(f) == 0:
            return ""
        return str(int(f))
    except:
        pass
    if s == "0":
        return ""
    return s

def keyword_mask(series: pd.Series, keywords: list[str]) -> pd.Series:
    patt = "|".join([re.escape(k.lower()) for k in keywords])
    return series.astype(str).str.lower().str.contains(patt, na=False)

# detect ports embedded in tracker host cells
_PORT_EMBED_PAT = re.compile(r"(\(\s*\d{1,5}\s*\)|\[\s*\d{1,5}\s*\]|:\s*\d{1,5}\b)")

def detect_tracker_port_mode(host_series: pd.Series) -> int:
    """
    Return recommended port mode:
      1 if many rows contain embedded port patterns
      2 otherwise
    """
    sample = host_series.astype(str).head(300).tolist()
    if not sample:
        return 2
    hits = sum(1 for x in sample if _PORT_EMBED_PAT.search(x or ""))
    ratio = hits / max(1, len(sample))
    return 1 if ratio >= 0.15 else 2  # >=15% implies embedded is common

def parse_tracker_host_ip_port(host_cell: str, port_mode: int):
    raw = "" if host_cell is None else str(host_cell)
    ip = extract_first_ip(raw)
    ipn = normalize_text(ip)

    if port_mode != 1:
        return ipn, ""

    m = re.search(r"[\(\[\{]\s*(\d{1,5})\s*[\)\]\}]", raw)
    if m:
        return ipn, safe_port_norm(m.group(1))
    m = re.search(r":\s*(\d{1,5})\b", raw)
    if m:
        return ipn, safe_port_norm(m.group(1))
    return ipn, ""


# -------------------------
# Load Nessus CSV folder
# -------------------------
def load_current_scans(current_folder: str) -> pd.DataFrame:
    csv_files = sorted(glob(os.path.join(current_folder, "*.csv")))
    if not csv_files:
        raise FileNotFoundError(f"No CSV files found in: {current_folder}")

    frames = []
    for fp in csv_files:
        df = pd.read_csv(fp, encoding="utf-8", dtype=str, on_bad_lines="skip")
        df.columns = df.columns.str.strip()

        name_col = pick_first_existing(df, [COL_NAME] + ALT_COL_NAME)
        host_col = pick_first_existing(df, [COL_HOST] + ALT_COL_HOST)
        port_col = pick_first_existing(df, [COL_PORT] + ALT_COL_PORT)
        risk_col = pick_first_existing(df, [COL_RISK] + ALT_COL_RISK)
        desc_col = pick_first_existing(df, [COL_DESC] + ALT_COL_DESC)
        sol_col  = pick_first_existing(df, [COL_SOLUTION] + ALT_COL_SOLUTION)
        out_col  = pick_first_existing(df, [COL_PLUGIN_OUTPUT] + ALT_COL_PLUGIN_OUTPUT)
        cvss2_col= pick_first_existing(df, [COL_CVSS2] + ALT_COL_CVSS2)

        out = pd.DataFrame()
        out[COL_NAME] = df[name_col] if name_col else ""
        out[COL_HOST] = df[host_col] if host_col else ""
        out[COL_PORT] = df[port_col] if port_col else ""
        out[COL_RISK] = df[risk_col] if risk_col else ""
        out[COL_DESC] = df[desc_col] if desc_col else ""
        out[COL_SOLUTION] = df[sol_col] if sol_col else ""
        out[COL_PLUGIN_OUTPUT] = df[out_col] if out_col else ""
        out[COL_CVSS2] = df[cvss2_col] if cvss2_col else ""
        out = out.astype(object).fillna("")
        out[COL_PORT] = out[COL_PORT].apply(safe_port_norm)
        frames.append(out)

    current = pd.concat(frames, ignore_index=True)
    for c in [COL_NAME, COL_HOST, COL_PORT, COL_RISK]:
        current[c] = current[c].astype(str).str.strip()
    return current


# -------------------------
# Risk accepted removal (Option 2 recurring)
# -------------------------
def load_prev_risk_accepted_pairs(prev_path: str) -> pd.DataFrame:
    all_pairs = []
    if prev_path.lower().endswith((".xlsx", ".xls")):
        xls = pd.ExcelFile(prev_path)
        for sheet in xls.sheet_names:
            df = xls.parse(sheet, dtype=str).fillna("")
            df.columns = df.columns.str.strip()
            name_col = pick_first_existing(df, [COL_NAME] + ALT_COL_NAME)
            host_col = pick_first_existing(df, [COL_HOST] + ALT_COL_HOST)
            if not name_col or not host_col:
                continue
            for _, r in df.iterrows():
                nm = normalize_key_alnum(r.get(name_col, ""))
                if not nm:
                    continue
                ips = extract_ips(r.get(host_col, ""))
                for ip in ips:
                    all_pairs.append((nm, normalize_text(ip)))
    elif prev_path.lower().endswith(".csv"):
        df = pd.read_csv(prev_path, encoding="utf-8", dtype=str, on_bad_lines="skip").fillna("")
        df.columns = df.columns.str.strip()
        name_col = pick_first_existing(df, [COL_NAME] + ALT_COL_NAME)
        host_col = pick_first_existing(df, [COL_HOST] + ALT_COL_HOST)
        if name_col and host_col:
            for _, r in df.iterrows():
                nm = normalize_key_alnum(r.get(name_col, ""))
                if not nm:
                    continue
                ips = extract_ips(r.get(host_col, ""))
                for ip in ips:
                    all_pairs.append((nm, normalize_text(ip)))
    else:
        raise ValueError("Unsupported previous risk accepted file type. Use .xlsx/.xls/.csv")
    return pd.DataFrame(all_pairs, columns=["name_norm", "host_norm"]).drop_duplicates()

def remove_risk_accepted(current: pd.DataFrame, prev_pairs: pd.DataFrame):
    cur = current.copy()
    cur["name_norm"] = cur[COL_NAME].apply(normalize_key_alnum)
    cur["host_norm"] = cur[COL_HOST].apply(lambda x: normalize_text(extract_first_ip(x) or x))
    merged = cur.merge(prev_pairs, on=["name_norm", "host_norm"], how="left", indicator=True)
    removed = merged[merged["_merge"] == "both"].copy()
    remaining = merged[merged["_merge"] == "left_only"].copy()
    diag = {
        "current_rows": len(cur),
        "prev_pairs": len(prev_pairs),
        "removed": len(removed),
        "remaining": len(remaining),
        "host_overlap": len(set(cur["host_norm"]).intersection(set(prev_pairs["host_norm"]))),
        "name_overlap": len(set(cur["name_norm"]).intersection(set(prev_pairs["name_norm"]))),
    }
    remaining.drop(columns=["_merge", "name_norm", "host_norm"], inplace=True, errors="ignore")
    removed.drop(columns=["_merge", "name_norm", "host_norm"], inplace=True, errors="ignore")
    remaining.reset_index(drop=True, inplace=True)
    removed.reset_index(drop=True, inplace=True)
    return remaining, removed, diag


# -------------------------
# Bucketing
# -------------------------
def extract_ssl(df: pd.DataFrame) -> pd.DataFrame:
    return df[keyword_mask(df[COL_NAME], SSL_KEYWORDS)].copy()

def extract_info(df: pd.DataFrame) -> pd.DataFrame:
    return df[keyword_mask(df[COL_NAME], INFO_KEYWORDS)].copy()


# -------------------------
# Outdated extraction (kept)
# -------------------------
_STRONG_SOLUTION_HINTS = re.compile(
    r"(?:upgrade|update|apply (?:the )?latest|install (?:the )?latest|"
    r"download (?:and )?install|fixed version|patched version|"
    r"upgrade to|update to|vendor (?:advises|recommends) upgrading|"
    r"apply (?:a )?patch|apply (?:a )?security update|"
    r"cumulative update|security update|hotfix|firmware)",
    re.I
)
_STRONG_NAME_HINTS = re.compile(r"(?:less than|prior to|before|outdated|unsupported|end of life|end-of-life|\beol\b)", re.I)
_KB_CONTEXT = re.compile(r"\bkb\d{4,8}\b", re.I)
_KB_VULN_WORDS = re.compile(r"(?:missing|not installed|security update|cumulative update|hotfix)", re.I)
_EXCLUDE_OUTDATED_NAME = re.compile(
    r"(?:bios info|dce service enumeration|service enumeration|common platform enumeration|\bcpe\b|"
    r"dism package list|enumerate local group|active directory configuration|internet explorer typed urls|"
    r"microsoft office detection|file history|recent file history|microsoft sql server detection|start tls success|"
    r"dns cache|installed software|nessus scan information|netbios.*enumeration|os security patch assessment|"
    r"patch report|recycle bin|registry.*last access|user download folder files|execution history|recently executed|"
    r"prefetch|windows store application enumeration|system drive enumeration|wmi quick fix engineering|\bqfe\b|"
    r"wordpad history|target credentials by authentication|credentials.*authentication|"
    r"ssl cert expiry|certificate expiration|cert(?:ificate)? expiry|"
    r"microsoft windows smb shares access|microsoft windows smb share hosting office files|"
    r"windows defender installed|microsoft windows process information)",
    re.I
)

def extract_outdated_refined(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    df2 = df.copy()
    df2 = ensure_cols(df2, [COL_NAME, COL_SOLUTION, COL_PLUGIN_OUTPUT, COL_RISK])
    name_s = df2[COL_NAME].astype(str)
    sol_s = df2[COL_SOLUTION].astype(str)
    out_s = df2[COL_PLUGIN_OUTPUT].astype(str)

    exclude_mask = name_s.str.contains(_EXCLUDE_OUTDATED_NAME, na=False)
    strong_solution = sol_s.str.contains(_STRONG_SOLUTION_HINTS, na=False) | out_s.str.contains(_STRONG_SOLUTION_HINTS, na=False)
    strong_name = name_s.str.contains(_STRONG_NAME_HINTS, na=False)

    kb_present = name_s.str.contains(_KB_CONTEXT, na=False) | sol_s.str.contains(_KB_CONTEXT, na=False) | out_s.str.contains(_KB_CONTEXT, na=False)
    kb_vuln_context = name_s.str.contains(_KB_VULN_WORDS, na=False) | sol_s.str.contains(_KB_VULN_WORDS, na=False) | out_s.str.contains(_KB_VULN_WORDS, na=False)
    kb_outdated = kb_present & kb_vuln_context

    include_mask = (strong_solution | strong_name | kb_outdated) & (~exclude_mask)
    return df2[include_mask].copy(), df2[~include_mask].copy()


# -------------------------
# CVSS reassessment (kept)
# -------------------------
def prompt_metric(prompt: str, allowed: set[str], default: str) -> str:
    while True:
        v = input(prompt).strip().upper()
        if not v:
            v = default
        if v in allowed:
            return v
        print(f"Invalid input. Allowed: {sorted(allowed)} (default={default})")

def cvss_bulk_reassess_unique_names(df_min: pd.DataFrame, label: str) -> pd.DataFrame:
    if df_min.empty:
        print(f"▶ No {label} findings to reassess.")
        return df_min
    if not HAS_CVSS:
        print("⚠ CVSS library not available (python-cvss). Skipping reassessment.")
        return df_min
    if yn(f"\n▶ Skip CVSS 3.1 reassessment for {label}? (y/n) [default=y]: ", default="y"):
        return df_min

    df_work = df_min.copy()
    df_work = ensure_cols(df_work, [COL_NAME, COL_RISK])

    uniq_names = (
        df_work[COL_NAME].astype(str).str.strip()
        .replace("", pd.NA)
        .dropna()
        .drop_duplicates()
        .tolist()
    )
    if not uniq_names:
        return df_min

    print("\nUnique findings list (no counts):")
    for i, nm in enumerate(uniq_names, start=1):
        print(f"{i}. {nm}")

    exclude = parse_exclude_indices(input("\nEnter numbers to EXCLUDE (e.g., 1,3,5-10) or press Enter for none: "))
    include_nums = [i for i in range(1, len(uniq_names) + 1) if i not in exclude]
    if not include_nums:
        return df_min

    if yn("Use ONE CVSS vector for ALL included unique findings? (y/n) [default=y]: ", default="y"):
        av = prompt_metric("AV (N/A/L/P) [default=N]: ", {"N", "A", "L", "P"}, "N")
        ac = prompt_metric("AC (L/H) [default=L]: ", {"L", "H"}, "L")
        pr = prompt_metric("PR (N/L/H) [default=N]: ", {"N", "L", "H"}, "N")
        ui = prompt_metric("UI (N/R) [default=N]: ", {"N", "R"}, "N")
        s  = prompt_metric("S (U/C) [default=U]: ", {"U", "C"}, "U")
        c  = prompt_metric("C (N/L/H) [default=N]: ", {"N", "L", "H"}, "N")
        i_ = prompt_metric("I (N/L/H) [default=N]: ", {"N", "L", "H"}, "N")
        a  = prompt_metric("A (N/L/H) [default=N]: ", {"N", "L", "H"}, "N")

        vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i_}/A:{a}"
        try:
            score = float(CVSS3(vector).scores()[0])
        except Exception as e:
            print(f"⚠ Error calculating CVSS from vector: {e}. Skipping reassessment.")
            return df_min

        sev = "Informational"
        if score >= 9.0:
            sev = "Critical"
        elif score >= 7.0:
            sev = "High"
        elif score >= 4.0:
            sev = "Medium"
        elif score > 0.0:
            sev = "Low"

        included_names = {uniq_names[i - 1] for i in include_nums}
        mask_apply = df_work[COL_NAME].astype(str).str.strip().isin(included_names)
        df_work.loc[mask_apply, COL_RISK] = sev
        print(f"▶ Applied CVSS vector. BaseScore={score}, Risk={sev}")
        return df_work

    return df_work


# -------------------------
# Option 3 (IMAGE SAFE) - Improved Matching + Auto Port Mode
# -------------------------
def build_new_scan_indices(new_df: pd.DataFrame, name_col: str, host_col: str, port_col: str | None, match_on_port: bool):
    df = new_df.copy().fillna("")
    df.columns = df.columns.str.strip()

    name_s = df[name_col].astype(str).apply(normalize_key_alnum)
    host_s = df[host_col].astype(str).apply(lambda x: normalize_text(extract_first_ip(x) or x))
    if match_on_port and port_col and port_col in df.columns:
        port_s = df[port_col].apply(safe_port_norm)
    else:
        port_s = pd.Series([""] * len(df), index=df.index)

    strict_set = set()
    loose_set = set()
    for n, h, p in zip(name_s, host_s, port_s):
        if not n or not h:
            continue
        p = safe_port_norm(p)
        strict_set.add((n, h, p))
        loose_set.add((n, h))

    diag = {
        "new_rows": len(df),
        "strict_keys": len(strict_set),
        "loose_keys": len(loose_set),
        "new_unique_hosts": len(set(host_s)),
        "new_unique_names": len(set(name_s)),
        "new_unique_ports": len(set(port_s)),
    }
    return strict_set, loose_set, diag


def option3_update_tracker_status_inplace():
    if platform.system().lower() != "windows":
        print("ERROR: Option 3 requires Windows + Excel (COM).")
        return
    if not HAS_WIN32COM:
        print("ERROR: pywin32 not installed. Install: pip install pywin32")
        return

    print("\n=== Option 3: Compare OLD tracker vs NEW scan and close missing (image-safe) ===\n")
    tracker_path = input("Enter OLD tracker Excel path (previous quarter): ").strip()
    new_path = input("Enter NEW scan file path (current quarter) (xlsx/xls/csv): ").strip()

    if not os.path.exists(tracker_path):
        print("ERROR: tracker file not found.")
        return
    if not os.path.exists(new_path):
        print("ERROR: new scan file not found.")
        return

    # Load NEW scan into pandas
    if new_path.lower().endswith((".xlsx", ".xls")):
        new_xls = pd.ExcelFile(new_path)
        if len(new_xls.sheet_names) > 1:
            print("\nSheets in NEW scan file:")
            for i, s in enumerate(new_xls.sheet_names, 1):
                print(f"  {i}) {s}")
            si = input("Choose NEW scan sheet number [default=1]: ").strip() or "1"
            try:
                si = int(si)
            except:
                si = 1
            si = max(1, min(si, len(new_xls.sheet_names)))
            new_df = new_xls.parse(new_xls.sheet_names[si-1], dtype=str).fillna("")
        else:
            new_df = new_xls.parse(new_xls.sheet_names[0], dtype=str).fillna("")
    else:
        new_df = pd.read_csv(new_path, dtype=str, on_bad_lines="skip").fillna("")

    new_df.columns = new_df.columns.str.strip()
    print("\nNEW scan columns:")
    print(", ".join(new_df.columns.tolist()))

    new_name_col = input("New file: column for Name [default=Name]: ").strip() or "Name"
    new_host_col = input("New file: column for Host/IP [default=Host]: ").strip() or "Host"
    new_port_col = input("New file: column for Port (blank if none) [default=Port]: ").strip() or "Port"
    match_on_port = yn("Match on Port? (y/n) [default=y]: ", default="y")

    if new_name_col not in new_df.columns or new_host_col not in new_df.columns:
        print("ERROR: New file missing Name/Host columns.")
        return
    if match_on_port and new_port_col not in new_df.columns:
        print("WARNING: New file missing Port column; disabling port match.")
        match_on_port = False

    strict_set, loose_set, new_diag = build_new_scan_indices(
        new_df, new_name_col, new_host_col, new_port_col if match_on_port else None, match_on_port
    )
    print("\nBuilt new-scan indices:")
    for k, v in new_diag.items():
        print(f"- {k}: {v}")

    # Open tracker via Excel COM
    excel = win32.DispatchEx("Excel.Application")
    excel.Visible = False
    excel.DisplayAlerts = False
    wb = None

    try:
        wb = excel.Workbooks.Open(os.path.abspath(tracker_path))

        print("\nSheets in TRACKER file:")
        for i in range(1, wb.Worksheets.Count + 1):
            print(f"  {i}) {wb.Worksheets(i).Name}")

        tsi = input("Choose tracker sheet number [default=1]: ").strip() or "1"
        try:
            tsi = int(tsi)
        except:
            tsi = 1
        tsi = max(1, min(tsi, wb.Worksheets.Count))
        ws = wb.Worksheets(tsi)

        used = ws.UsedRange
        values = used.Value
        if not values or len(values) < 2:
            print("ERROR: Tracker sheet appears empty.")
            return

        headers = [str(h).strip() if h is not None else "" for h in values[0]]
        data_rows = values[1:]
        tracker_df = pd.DataFrame(list(data_rows), columns=headers).fillna("")
        tracker_df.columns = tracker_df.columns.str.strip()

        print("\nTracker columns:")
        print(", ".join(tracker_df.columns.tolist()))

        tr_name_col = input("Tracker: column for Name [default=Name]: ").strip() or "Name"
        tr_host_col = input("Tracker: column for Host [default=Host]: ").strip() or "Host"
        tr_status_col = input("Tracker: column for Status [default=Status]: ").strip() or "Status"

        if tr_name_col not in tracker_df.columns or tr_host_col not in tracker_df.columns or tr_status_col not in tracker_df.columns:
            print("ERROR: Tracker missing Name/Host/Status columns.")
            return

        # Auto-detect port mode from tracker host values
        recommended_mode = detect_tracker_port_mode(tracker_df[tr_host_col])
        print("\nHow is port represented in tracker Host?")
        print("  1) Embedded (e.g., 10.0.0.1 (443) / 10.0.0.1:443 / 10.0.0.1 [443])")
        print("  2) No port in host")
        port_mode_in = input(f"Choose 1/2 [default={recommended_mode}]: ").strip()
        if port_mode_in not in ("1", "2", ""):
            port_mode_in = ""
        if port_mode_in == "":
            port_mode = recommended_mode
        else:
            port_mode = 1 if port_mode_in == "1" else 2

        # If user chose embedded but detection says no, warn strongly
        if port_mode == 1 and recommended_mode == 2:
            print("\n⚠ It looks like your tracker Host column rarely contains ports.")
            if not yn("Are you SURE you want embedded-port mode anyway? (y/n) [default=n]: ", default="n"):
                port_mode = 2
                print("Switched to port mode 2 (no port in host).")

        only_open = yn("Only process rows where Status is 'Open'? (y/n) [default=y]: ", default="y")
        mark_closed = yn("Mark NOT-found rows as Closed? (y/n) [default=y]: ", default="y")

        fill_comment = yn("Fill reviewer comments column for CLOSED rows? (y/n) [default=y]: ", default="y")
        comment_col_name = ""
        comment_fill_text = ""
        if fill_comment:
            comment_col_name = input("Enter comment column name (e.g., Reviewer Comments): ").strip()
            comment_fill_text = input("Enter text to fill for CLOSED rows: ").strip()

        def find_col_index_ci(header_name: str) -> int:
            target = normalize_text(header_name)
            for idx, h in enumerate(headers, start=1):
                if normalize_text(h) == target:
                    return idx
            return 0

        status_col_idx = find_col_index_ci(tr_status_col)
        if status_col_idx == 0:
            print(f"ERROR: Could not find Status header '{tr_status_col}' in row 1.")
            return

        comment_col_idx = 0
        if fill_comment and comment_col_name:
            comment_col_idx = find_col_index_ci(comment_col_name)
            if comment_col_idx == 0:
                print(f"WARNING: Could not find comment header '{comment_col_name}'. Comments will not be filled.")
                fill_comment = False

        # Quick match tester before closing anything
        if yn("\nRun a quick TEST match (recommended)? (y/n) [default=y]: ", default="y"):
            t_host = input("Test Host IP (e.g., 10.45.243.200): ").strip()
            t_name = input("Test Finding Name (exact as in tracker): ").strip()
            t_ip = normalize_text(extract_first_ip(t_host) or t_host)
            t_key = normalize_key_alnum(t_name)
            print("Checking in NEW scan index...")
            print(" - loose (Name+Host):", (t_key, t_ip) in loose_set)
            if match_on_port:
                t_port = input("Test Port (blank if none/0): ").strip()
                t_port = safe_port_norm(t_port)
                print(" - strict (Name+Host+Port):", (t_key, t_ip, t_port) in strict_set)
            print("If loose=False, you're likely using the wrong NEW scan sheet/file or Host column.")

        rows_checked = 0
        rows_considered = 0
        rows_found = 0
        rows_closed = 0
        samples = []

        for i, r in tracker_df.iterrows():
            rows_checked += 1
            excel_row = 2 + i  # header row = 1

            status_val = str(r.get(tr_status_col, "")).strip()
            if only_open and status_val.lower() != "open":
                continue

            rows_considered += 1
            name_val = str(r.get(tr_name_col, "")).strip()
            host_val = str(r.get(tr_host_col, "")).strip()
            if not name_val or not host_val:
                continue

            ip_norm, port_norm = parse_tracker_host_ip_port(host_val, port_mode)
            port_norm = safe_port_norm(port_norm)
            name_key = normalize_key_alnum(name_val)

            # Matching logic:
            # If tracker has no port, ALWAYS match using loose (Name+Host).
            # If tracker has port, try strict then fallback to loose.
            found = False
            if (not match_on_port) or port_norm == "":
                found = (name_key, ip_norm) in loose_set
            else:
                found = (name_key, ip_norm, port_norm) in strict_set
                if not found:
                    found = (name_key, ip_norm) in loose_set

            if found:
                rows_found += 1
                continue

            if len(samples) < 10:
                samples.append((name_val, ip_norm, port_norm))

            if mark_closed:
                ws.Cells(excel_row, status_col_idx).Value = "Closed"
                rows_closed += 1
                if fill_comment and comment_col_idx and comment_fill_text:
                    ws.Cells(excel_row, comment_col_idx).Value = comment_fill_text

        found_rate = (rows_found / rows_considered) if rows_considered else 0.0
        print(f"\nMatch stats: considered={rows_considered}, found={rows_found}, found_rate={found_rate:.2%}")

        if found_rate < 0.20:
            print("\n⚠ WARNING: Found-rate is very low (<20%). Usually wrong NEW scan sheet/file or wrong Host/Name columns.")
            if not yn("Proceed to SAVE these changes anyway? (y/n) [default=n]: ", default="n"):
                print("Aborted save. No changes written.")
                return

        out_same = yn("\nWrite changes back into the SAME tracker file? (y/n) [default=n]: ", default="n")
        if out_same:
            wb.Save()
            out_path = os.path.abspath(tracker_path)
        else:
            base, ext = os.path.splitext(os.path.abspath(tracker_path))
            out_path = f"{base}__updated_{datetime.now().strftime('%Y%m%d_%H%M%S')}{ext}"
            wb.SaveAs(out_path)

        print("\n▶ Done (Option 3, image-safe via Excel)")
        print(f"Rows checked: {rows_checked}")
        print(f"Rows considered: {rows_considered}")
        print(f"Rows found in current: {rows_found}")
        print(f"Rows marked Closed: {rows_closed}")
        print(f"Updated file: {out_path}")

        if samples:
            print("\nSample rows NOT matched (first 10):")
            for nm, ipn, pn in samples:
                print(f"- Name='{nm}' | Host='{ipn}' | Port='{pn or '(none)'}'")

    finally:
        try:
            if wb is not None:
                wb.Close(SaveChanges=False)
        except Exception:
            pass
        excel.Quit()


# -------------------------
# InfraVA automation (Option 1/2) - kept
# -------------------------
def run_infrava_automation():
    print("=== InfraVA VAPT Automation ===\n")

    print("Select scan mode:")
    print("  1) New VA scan (first time) - no comparison with previous risk accepted findings")
    print("  2) Recurring VA scan (rescan) - compare with previous risk accepted findings\n")
    mode = input("Enter 1 or 2 [default=2]: ").strip() or "2"
    if mode not in ("1", "2"):
        mode = "2"

    current_folder = input("\nEnter folder path for CURRENT Nessus CSV scans (this quarter): ").strip()

    prev_open_path = ""
    prev_accepted_path = ""
    if mode == "2":
        prev_accepted_path = input("Enter path to PREVIOUS risk accepted findings file (xlsx/xls/csv): ").strip()
        prev_open_path = input("Enter path to PREVIOUS open findings file (xlsx) (used to detect any new 'risk accepted' rows): ").strip()

    output_folder = input("Enter output folder path: ").strip()

    if not current_folder:
        print("ERROR: current scans folder is required.")
        return
    if mode == "2" and not prev_accepted_path:
        print("ERROR: previous risk accepted file is required for recurring scan mode.")
        return
    if not output_folder:
        print("ERROR: output folder is required.")
        return

    os.makedirs(output_folder, exist_ok=True)

    print("\n▶ Loading current Nessus scans...")
    current = load_current_scans(current_folder)
    current = ensure_cols(current, [COL_NAME, COL_HOST, COL_PORT, COL_RISK, COL_DESC, COL_SOLUTION, COL_PLUGIN_OUTPUT, COL_CVSS2])
    total_current = len(current)
    print(f"Loaded current findings: {total_current}")

    removed = pd.DataFrame()
    diag = {}

    if mode == "2":
        print("▶ Loading previous risk accepted findings (all sheets if Excel)...")
        prev_pairs = load_prev_risk_accepted_pairs(prev_accepted_path)
        print(f"Built previous accepted pairs: {len(prev_pairs)} (expanded per-IP)")

        print("▶ Removing previously risk-accepted findings from current scans (Name+Host match, multi-IP aware)...")
        remaining, removed, diag = remove_risk_accepted(current, prev_pairs)
    else:
        print("▶ New scan mode: skipping previous risk accepted removal.")
        remaining = current.copy()

    removed_path = os.path.join(output_folder, OUT_REMOVED)
    removed.to_excel(removed_path, index=False)

    print("▶ Extracting SSL findings...")
    ssl_df = extract_ssl(remaining)
    print("▶ Extracting Info Disclosure findings...")
    info_df = extract_info(remaining)

    remaining_after_si = remaining.copy()
    if not ssl_df.empty:
        remaining_after_si = remaining_after_si.merge(
            ssl_df[[COL_NAME, COL_HOST, COL_PORT]].assign(_is_ssl=1),
            on=[COL_NAME, COL_HOST, COL_PORT],
            how="left"
        )
        remaining_after_si = remaining_after_si[remaining_after_si["_is_ssl"].isna()].drop(columns=["_is_ssl"])
    if not info_df.empty:
        remaining_after_si = remaining_after_si.merge(
            info_df[[COL_NAME, COL_HOST, COL_PORT]].assign(_is_info=1),
            on=[COL_NAME, COL_HOST, COL_PORT],
            how="left"
        )
        remaining_after_si = remaining_after_si[remaining_after_si["_is_info"].isna()].drop(columns=["_is_info"])

    print("▶ Detecting Outdated patches / versions (refined)...")
    outdated, remaining2 = extract_outdated_refined(remaining_after_si)

    ssl_out = ssl_df[[COL_HOST, COL_PORT, COL_NAME, COL_RISK, COL_SOLUTION, COL_DESC, COL_PLUGIN_OUTPUT]].copy()
    ssl_out["Comments"] = ""
    ssl_out["Status"] = ""

    info_out = info_df[[COL_HOST, COL_PORT, COL_NAME, COL_RISK, COL_SOLUTION, COL_DESC, COL_PLUGIN_OUTPUT]].copy()
    info_out["Comments"] = ""
    info_out["Status"] = ""

    outdated_out = outdated.copy()
    outdated_out["Comments"] = ""
    outdated_out["Status"] = ""

    ssl_path = os.path.join(output_folder, OUT_SSL)
    info_path = os.path.join(output_folder, OUT_INFO)
    outdated_path = os.path.join(output_folder, OUT_OUTDATED)
    remaining_path = os.path.join(output_folder, OUT_REMAINING)

    ssl_out.to_excel(ssl_path, index=False)
    info_out.to_excel(info_path, index=False)
    outdated_out.to_excel(outdated_path, index=False)
    remaining2.to_excel(remaining_path, index=False)

    print("\n▶ Bulk CVSS 3.1 reassessment (optional, UNIQUE finding names list)...")
    ssl_out2 = cvss_bulk_reassess_unique_names(ssl_out, "SSL findings")
    info_out2 = cvss_bulk_reassess_unique_names(info_out, "Info Disclosure findings")
    ssl_out2.to_excel(ssl_path, index=False)
    info_out2.to_excel(info_path, index=False)

    print("\n▶ Done.")
    print(f"Output folder: {output_folder}")
    print(f"- {OUT_REMAINING}")
    print(f"- {OUT_REMOVED}")
    print(f"- {OUT_SSL}")
    print(f"- {OUT_INFO}")
    print(f"- {OUT_OUTDATED}")


def main():
    print(ASCII_ART)
    print("\nSelect an option:")
    print("  1) InfraVA report automation (Options 1/2 workflow)")
    print("  2) Option 3: Compare old tracker vs current scan and close missing (image-safe)")
    choice = input("Enter 1 or 2 [default=1]: ").strip() or "1"

    if choice == "2":
        option3_update_tracker_status_inplace()
    else:
        run_infrava_automation()


if __name__ == "__main__":
    main()

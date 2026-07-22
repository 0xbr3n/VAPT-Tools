#!/usr/bin/env python3
"""
wifi_recon.py — Stage 1 of the WiFi audit suite (Windows, built-in adapter).

Passive reconnaissance of nearby WiFi networks using Windows' native `netsh`.
Works on ANY Windows adapter (including Intel AX211) — no monitor mode or
injection required. This is the "pick your target SSID" front-end of the
pipeline: it enumerates every visible network, classifies its security,
flags weak configurations, and (when you select a target) writes a capture
manifest that Stage 2 (deauth + handshake capture on a monitor/injection
capable adapter) consumes.

Usage:
    python wifi_recon.py                 # scan + print audit table
    python wifi_recon.py --json out.json # also write full results as JSON
    python wifi_recon.py --select        # scan, then interactively pick a
                                         # target SSID -> writes capture_manifest.json
    python wifi_recon.py --html report.html

Authorization: only audit networks you have written permission to test.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
@dataclass
class BSS:
    """A single BSSID (radio) belonging to an SSID."""
    bssid: str = ""
    signal_pct: int | None = None
    radio_type: str = ""
    band: str = ""
    channel: int | None = None


@dataclass
class Network:
    ssid: str = ""
    authentication: str = ""
    encryption: str = ""
    network_type: str = ""
    bsses: list[BSS] = field(default_factory=list)
    # audit fields (filled by classify)
    risk: str = ""            # HIGH / MEDIUM / LOW / INFO
    findings: list[str] = field(default_factory=list)
    wpa2_psk_crackable: bool = False

    @property
    def best_signal(self) -> int:
        return max((b.signal_pct or 0 for b in self.bsses), default=0)

    @property
    def primary_bss(self) -> BSS | None:
        if not self.bsses:
            return None
        return max(self.bsses, key=lambda b: b.signal_pct or 0)


# ---------------------------------------------------------------------------
# netsh execution + parsing
# ---------------------------------------------------------------------------
def run_netsh(args: list[str]) -> str:
    try:
        proc = subprocess.run(
            ["netsh", *args],
            capture_output=True, text=True, timeout=30,
        )
    except FileNotFoundError:
        sys.exit("ERROR: `netsh` not found — this tool only runs on Windows.")
    except subprocess.TimeoutExpired:
        sys.exit("ERROR: netsh timed out.")
    return proc.stdout


def _int_or_none(s: str) -> int | None:
    m = re.search(r"-?\d+", s)
    return int(m.group()) if m else None


def parse_networks(text: str) -> list[Network]:
    """Parse `netsh wlan show networks mode=bssid` output (English locale)."""
    networks: list[Network] = []
    current: Network | None = None
    current_bss: BSS | None = None

    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue

        # "SSID 3 : MyNetwork"  (index then colon)
        m = re.match(r"^SSID\s+\d+\s*:\s*(.*)$", line)
        if m:
            if current is not None:
                networks.append(current)
            current = Network(ssid=m.group(1).strip())
            current_bss = None
            continue

        if current is None:
            continue

        m = re.match(r"^Network type\s*:\s*(.*)$", line, re.I)
        if m:
            current.network_type = m.group(1).strip()
            continue
        m = re.match(r"^Authentication\s*:\s*(.*)$", line, re.I)
        if m:
            current.authentication = m.group(1).strip()
            continue
        m = re.match(r"^Encryption\s*:\s*(.*)$", line, re.I)
        if m:
            current.encryption = m.group(1).strip()
            continue

        m = re.match(r"^BSSID\s+\d+\s*:\s*(.*)$", line, re.I)
        if m:
            current_bss = BSS(bssid=m.group(1).strip())
            current.bsses.append(current_bss)
            continue

        if current_bss is not None:
            m = re.match(r"^Signal\s*:\s*(.*)$", line, re.I)
            if m:
                current_bss.signal_pct = _int_or_none(m.group(1))
                continue
            m = re.match(r"^Radio type\s*:\s*(.*)$", line, re.I)
            if m:
                current_bss.radio_type = m.group(1).strip()
                continue
            m = re.match(r"^Band\s*:\s*(.*)$", line, re.I)
            if m:
                current_bss.band = m.group(1).strip()
                continue
            m = re.match(r"^Channel\s*:\s*(.*)$", line, re.I)
            if m:
                current_bss.channel = _int_or_none(m.group(1))
                continue

    if current is not None:
        networks.append(current)
    return networks


# ---------------------------------------------------------------------------
# Security classification
# ---------------------------------------------------------------------------
def classify(net: Network) -> None:
    auth = net.authentication.lower()
    enc = net.encryption.lower()
    findings: list[str] = []
    risk = "LOW"

    if "open" in auth or enc in ("", "none"):
        risk = "HIGH"
        findings.append("Open network — no encryption; all traffic in the clear.")
    elif "wep" in auth or "wep" in enc:
        risk = "HIGH"
        findings.append("WEP — trivially crackable in minutes; effectively no protection.")
    elif "wpa3" in auth or "sae" in auth:
        risk = "INFO"
        findings.append("WPA3-SAE — strong; not offline-crackable like WPA2-PSK.")
    elif "wpa2" in auth:
        if "psk" in auth or "personal" in auth:
            net.wpa2_psk_crackable = True
            risk = "MEDIUM"
            findings.append("WPA2-Personal (PSK) — handshake is offline-crackable if the "
                            "passphrase is weak. Target for Stage 2 capture.")
        else:
            risk = "LOW"
            findings.append("WPA2-Enterprise (802.1X) — not PSK; standard handshake cracking N/A.")
        if "tkip" in enc:
            risk = "MEDIUM" if risk == "LOW" else risk
            findings.append("TKIP cipher in use — deprecated; should be CCMP/AES only.")
    elif "wpa" in auth:  # WPA1
        risk = "MEDIUM"
        findings.append("WPA (v1) — deprecated; upgrade to WPA2/WPA3.")
        if "psk" in auth:
            net.wpa2_psk_crackable = True
    else:
        risk = "INFO"
        findings.append(f"Unrecognized auth/enc: {net.authentication} / {net.encryption}")

    net.risk = risk
    net.findings = findings


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
RISK_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}


def print_table(nets: list[Network]) -> None:
    nets_sorted = sorted(nets, key=lambda n: (RISK_ORDER.get(n.risk, 9), -n.best_signal))
    print()
    print(f"{'#':>2}  {'RISK':<7} {'SSID':<28} {'AUTH':<22} {'SIG':>4} {'CH':>4} {'BAND':<6}")
    print("-" * 82)
    for i, n in enumerate(nets_sorted, 1):
        pb = n.primary_bss
        ssid = (n.ssid or "<hidden>")[:28]
        auth = (n.authentication or "?")[:22]
        sig = f"{n.best_signal}%" if pb else "-"
        ch = str(pb.channel) if pb and pb.channel else "-"
        band = (pb.band if pb else "") or "-"
        print(f"{i:>2}  {n.risk:<7} {ssid:<28} {auth:<22} {sig:>4} {ch:>4} {band:<6}")
    print("-" * 82)
    highs = [n for n in nets if n.risk == "HIGH"]
    crackable = [n for n in nets if n.wpa2_psk_crackable]
    print(f"{len(nets)} networks | {len(highs)} HIGH-risk | "
          f"{len(crackable)} WPA2-PSK (Stage-2 crack candidates)")
    return nets_sorted


def write_json(nets: list[Network], path: Path) -> None:
    payload = {
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "network_count": len(nets),
        "networks": [asdict(n) | {"best_signal": n.best_signal} for n in nets],
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"[+] JSON written: {path}")


def write_html(nets: list[Network], path: Path) -> None:
    rows = []
    for n in sorted(nets, key=lambda x: (RISK_ORDER.get(x.risk, 9), -x.best_signal)):
        pb = n.primary_bss
        color = {"HIGH": "#c0392b", "MEDIUM": "#e67e22",
                 "LOW": "#27ae60", "INFO": "#7f8c8d"}.get(n.risk, "#555")
        findings = "<br>".join(n.findings)
        rows.append(
            f"<tr><td style='color:{color};font-weight:bold'>{n.risk}</td>"
            f"<td>{(n.ssid or '&lt;hidden&gt;')}</td>"
            f"<td>{n.authentication}</td><td>{n.encryption}</td>"
            f"<td>{pb.channel if pb else ''}</td><td>{n.best_signal}%</td>"
            f"<td>{pb.bssid if pb else ''}</td><td>{findings}</td></tr>"
        )
    html = f"""<!doctype html><html><head><meta charset="utf-8">
<title>WiFi Audit</title><style>
body{{font-family:Segoe UI,Arial,sans-serif;margin:24px;background:#1e1e1e;color:#eee}}
table{{border-collapse:collapse;width:100%}}
th,td{{border:1px solid #444;padding:6px 10px;text-align:left;font-size:13px}}
th{{background:#333}}tr:nth-child(even){{background:#282828}}
</style></head><body>
<h2>WiFi Passive Audit</h2>
<p>Scanned: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} — {len(nets)} networks</p>
<table><tr><th>Risk</th><th>SSID</th><th>Auth</th><th>Enc</th><th>Ch</th>
<th>Signal</th><th>BSSID</th><th>Findings</th></tr>
{''.join(rows)}</table></body></html>"""
    path.write_text(html, encoding="utf-8")
    print(f"[+] HTML report written: {path}")


def write_manifest(net: Network, path: Path) -> None:
    pb = net.primary_bss
    manifest = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "target_ssid": net.ssid,
        "authentication": net.authentication,
        "encryption": net.encryption,
        "wpa2_psk_crackable": net.wpa2_psk_crackable,
        "bssid": pb.bssid if pb else None,
        "channel": pb.channel if pb else None,
        "band": pb.band if pb else None,
        "all_bssids": [{"bssid": b.bssid, "channel": b.channel,
                        "signal_pct": b.signal_pct} for b in net.bsses],
        "capture_hint": (
            "Feed this to Stage 2 (capture.sh) on a monitor/injection-capable "
            "adapter. Lock airodump-ng to the channel above and target the BSSID."
        ),
    }
    path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"[+] Capture manifest written: {path}")
    if not net.wpa2_psk_crackable:
        print("[!] NOTE: target is not WPA2-PSK — standard handshake cracking may not apply.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    ap = argparse.ArgumentParser(description="Stage 1 passive WiFi recon (Windows).")
    ap.add_argument("--json", metavar="PATH", help="write full results to JSON")
    ap.add_argument("--html", metavar="PATH", help="write an HTML audit report")
    ap.add_argument("--select", action="store_true",
                    help="interactively select a target SSID and write capture_manifest.json")
    ap.add_argument("--manifest", metavar="PATH", default="capture_manifest.json",
                    help="path for the capture manifest (with --select)")
    args = ap.parse_args()

    print("[*] Scanning nearby WiFi (netsh wlan show networks mode=bssid)...")
    raw = run_netsh(["wlan", "show", "networks", "mode=bssid"])
    nets = parse_networks(raw)
    if not nets:
        print("[!] No networks parsed. Is WiFi enabled? (Try: netsh wlan show networks)")
        print("    Note: on non-English Windows the netsh labels differ; tell me and")
        print("    I'll add your locale's field names.")
        return

    for n in nets:
        classify(n)

    ordered = print_table(nets)

    if args.json:
        write_json(nets, Path(args.json))
    if args.html:
        write_html(nets, Path(args.html))

    if args.select:
        print()
        try:
            choice = input("Select target # (or blank to skip): ").strip()
        except EOFError:
            choice = ""
        if choice.isdigit() and 1 <= int(choice) <= len(ordered):
            target = ordered[int(choice) - 1]
            print(f"[*] Target: {target.ssid} ({target.authentication})")
            write_manifest(target, Path(args.manifest))
        else:
            print("[*] No target selected.")


if __name__ == "__main__":
    main()

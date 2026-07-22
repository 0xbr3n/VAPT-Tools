# Wifi-Auditor

> **Three-Stage Automated WiFi Auditing Pipeline for Wireless VAPT**

A three-stage, mostly-automated WiFi auditing pipeline for **authorized**
penetration testing — recon on Windows, deauth/capture in a Kali VM with a USB
injection adapter, and offline handshake/PMKID cracking, with an auto-generated
client report at the end.

> **AUTHORIZED USE ONLY.** Only audit, deauth, capture, or crack networks you
> have **written permission** to test. Deauthentication is an active attack on a
> live network. Unauthorized use is illegal in most jurisdictions.

---

## The hardware reality (read this first)

Your laptop's built-in adapter is an **Intel Wi-Fi 6E AX211**. Intel WiFi chips
**do not support monitor mode or packet injection** — not on Windows, not on
Linux, and **not even when passed through to a VM**. There is no software
workaround; the firmware doesn't expose those capabilities.

Consequences:

| Stage | Needs | Runs on AX211? |
|-------|-------|----------------|
| 1. Recon (enumerate SSIDs, classify security) | ordinary WiFi | ✅ yes, today |
| 2. Capture (deauth + handshake/PMKID) | monitor mode **+ injection** | ❌ no |
| 3. Crack (hashcat / John) | CPU/GPU only | ✅ yes (no WiFi needed) |

**To do Stage 2 you need a cheap USB adapter with an injection-capable chipset**
(~US$15–35), e.g. **Alfa AWUS036ACH (RTL8812AU)**, TP-Link TL-WN722N **v1**
(Atheros AR9271), or any RTL8812AU/RT3070 board. You pass *that USB device*
through to the Kali VM — not the built-in card.

---

## Pipeline overview

```
[Windows laptop]                    [Kali VM on this laptop, USB adapter attached]
  wifi_recon.py                          wifi_audit.py  <-- the orchestrator
  scan + classify  --manifest.json-->    auto monitor mode → recon → decision
  pick target SSID                       engine → guided attacks → HTML/PDF report
```

Everything hands off through small JSON files, so the stages are decoupled — you
can capture on one machine and crack on another (e.g. your colleague's GPU rig).

---

## `wifi_audit.py` — the automated orchestrator (recommended)

This is the main tool. It implements the **WiFi VAPT & Wireless Security Audit
field guide** end-to-end and runs entirely inside your Kali VM:

```bash
./setup.sh                          # one-time: copies to ~, chmods, installs everything
sudo python3 wifi_audit.py          # full interactive run
sudo python3 wifi_audit.py -i wlan1 --recon-time 45 --reg SG
```

`setup.sh` is the one-liner bootstrap: run it from the shared/USB copy and it moves
the suite into `~/Wifi-Auditor`, makes the scripts executable, runs `install_deps.sh`,
unzips rockyou, and lists your wireless interfaces. (Or do it by hand with
`chmod +x *.sh && sudo ./install_deps.sh`.)

### Fully automated mode (no prompts)

```bash
sudo python3 wifi_audit.py --auto -i wlan1               # safe: recon + clientless
                                                         # PMKID + config checks + auto-crack
sudo python3 wifi_audit.py --auto --aggressive -i wlan1  # + handshake/deauth, WPS Pixie, WEP
sudo python3 wifi_audit.py --auto -i wlan1 --client "Acme Corp" --assessor "J. Doe"
```

`--auto` runs the whole engagement without asking anything: monitor mode → recon →
per-target attacks → auto-crack captured hashes → `audit_run/wifi_report.html`.

- **`--auto` (SAFE, default):** only non-disruptive steps — clientless **PMKID**
  on WPA2-PSK/transition, WPA3/transition config detection, open-network notes.
  No deauth. WEP and Enterprise are skipped (they need disruptive/confirmed steps).
- **`--auto --aggressive`:** additionally runs **targeted-deauth handshake capture**,
  **WPS Pixie Dust** (only where WPS is unlocked), and **WEP** ARP-replay — still
  fully unattended. Confirm this is within your RoE first.

Never auto-run in either mode (they always require an interactive `y`): Enterprise
evil-twin, WPS **PIN brute**, DoS flood, and all three OPT-IN modules. Use the
interactive run (no `--auto`) for those.

Pass `-i <iface>` in `--auto` when more than one wireless interface is present
(so it doesn't have to ask which). Client/assessor default to sensible values;
override with `--client` / `--assessor` for the report header.

### Scoping to ONE target (don't touch everything)

By default a run considers every AP in range. Lock it to a single target with
`--ssid` and/or `--bssid` — this applies in **both** auto and interactive mode:

```bash
# only the network named "ClientCorp" (all its radios/BSSIDs)
sudo python3 wifi_audit.py --auto -i wlan1 --ssid "ClientCorp"

# only one specific access point (one radio)
sudo python3 wifi_audit.py --auto -i wlan1 --bssid AA:BB:CC:DD:EE:FF

# pin exactly one radio of a multi-AP SSID
sudo python3 wifi_audit.py --auto -i wlan1 --ssid "ClientCorp" --bssid AA:BB:CC:DD:EE:FF
```

- `--ssid` is an **exact, case-insensitive** name match (returns all BSSIDs using it).
- `--bssid` is the AP's MAC (returns just that radio).
- **Fail-safe:** if the filter matches nothing, the run attacks **nothing** and
  prints the SSIDs it saw — it never falls back to hitting everything.

Recon is always a passive full sweep (needed to find and fingerprint your target),
but only the matched AP(s) are ever deauthed / attacked. Tip: do a first plain run
(or `wifi_recon.py` on Windows) to copy the exact SSID/BSSID before scoping.

What it does, in order:

1. **Auto adapter + monitor mode** — lists wireless interfaces, lets you pick one
   (or `-i`), kills interfering services, runs `airmon-ng start`, sets the
   regulatory domain, and runs an injection self-test. No manual `airmon-ng`.
2. **Recon** — sweeps 2.4 + 5 GHz with `airodump-ng`, parses the CSV, then runs
   `wash` to flag WPS-enabled/locked APs. Merges clients to each AP.
3. **Decision engine** — for every SSID it prints a **recommended attack path**
   ordered by likelihood + least disruption, chosen from the encryption type,
   WPS state, and whether clients are present.
4. **Guided attacks** — you pick from a per-target menu; it runs the tool, detects
   success, and records a structured finding. Attacks:

   | Phase | Attacks | Guide? |
   |-------|---------|--------|
   | WPA2-Personal | PMKID (clientless) → 4-way handshake + targeted deauth | ✅ |
   | WPS | Pixie Dust → PIN brute (reaver/bully) | ✅ |
   | WPA3 | transition-mode downgrade detection + config guidance | ✅ |
   | Enterprise 802.1X | evil-twin cred harvest (eaphammer/hostapd-wpe) | ✅ |
   | **WEP** | ARP-replay + aircrack | ➕ **GAP-ADD** |
   | **Open** | exposure / client-isolation guidance | ➕ **GAP-ADD** |
   | **DoS** | deauth/beacon-flood resilience (mdk4, PMF check) | ➕ **GAP-ADD** |

5. **Cracking** — any captured PMKID/handshake can be cracked inline with
   **hashcat** (`-m 22000`, or `-m 5500` for Enterprise), auto-falling back to
   **John**. Cracked passphrases upgrade the finding to Critical.
6. **Client report** — writes a self-contained, presentable **HTML report**
   (exec summary, severity counts, findings-at-a-glance, detailed findings with
   evidence + remediation) and a **PDF** if `wkhtmltopdf`/`weasyprint` is present.
   **Recovered secrets are redacted** in the report (kept only in evidence files).

Everything lands in `./audit_run/` — capture files, `findings.json` (re-runnable
with `--report-only`), and `wifi_report.html` / `.pdf`.

### What the field guide missed (and this suite adds)

- **WEP** — the guide has zero WEP coverage; still found in legacy/OT/printer
  networks. Added full ARP-replay + statistical key recovery.
- **Open networks** — added exposure + client-isolation checks and reporting.
- **DoS / resilience** — added a controlled `mdk4` deauth-flood test and an
  explicit **802.11w (PMF)** remediation, which the guide never mentions.
- **Auto monitor mode + injection self-test** — the guide has you do this by
  hand; the orchestrator automates and verifies it.
- **Structured findings + auto client report** — the guide lists *what to record*
  but ships no generator; this produces the deliverable.

### Opt-in modules (separate authorization)

Three additional modules are built in but **never auto-run** — each is tagged
`[OPT-IN]`, appears last in a target's recommended path, and requires an explicit
runtime `y` confirmation, because each is usually a *separate authorization* from
the core wireless test:

| Module | What it does | Applies to |
|--------|--------------|-----------|
| **Post-association segmentation + Responder** | From an already-associated managed interface, runs `nmap -sn`/`-sV` to test whether the wireless segment can reach production/management VLANs, plus optional `Responder` (LLMNR/NBT-NS) — gated separately | any (after access) |
| **WPA3 Dragonblood SAE PoCs** | Offers to clone `vanhoefm/dragondrain-and-time`; runs the SAE commit-flood/timing test if built, else records a firmware-version readiness finding (CVE-2019-9494…9499) | WPA3 / transition |
| **Captive-portal evil-twin (wifiphisher)** | Stands up a rogue AP + captive-portal phishing page to harvest the PSK from users when offline cracking fails — social-engineering test | WPA2-PSK / transition / open |

Tip: run the post-association module with the **built-in AX211 connected normally
(managed) to the target network** while the USB adapter stays in monitor mode for
the rest of the audit — two interfaces, no mode juggling.

---

## Stage 1 — Recon (Windows, works now)

```powershell
cd "VAPT Scripts\Wifi-Auditor"
python wifi_recon.py                 # print an audit table of nearby networks
python wifi_recon.py --html audit.html
python wifi_recon.py --select        # pick a target -> writes capture_manifest.json
```

- Classifies each network: **HIGH** (Open/WEP), **MEDIUM** (WPA/WPA2-PSK, TKIP),
  **LOW** (WPA2-Enterprise), **INFO** (WPA3).
- Flags **WPA2-PSK** networks as Stage-2 crack candidates.
- `--select` writes `capture_manifest.json` (target SSID, BSSID, channel) — copy
  it into the Kali VM for Stage 2.

Non-English Windows: `netsh` field labels differ — if parsing returns 0
networks, tell me your locale and I'll add the field names.

## Stage 2 — Capture (Kali VM + USB injection adapter)

```bash
sudo apt install aircrack-ng hcxdumptool hcxtools jq   # one-time
chmod +x kali/*.sh                                     # one-time

sudo ./kali/capture.sh -i wlan1 -m capture_manifest.json
# options: -M handshake|pmkid|both  -t <timeout s>  -d <deauth bursts>  -o <outdir>
```

- Puts `wlan1` (the USB adapter) into monitor mode, locks to the target
  BSSID/channel.
- Grabs a **PMKID** (often no client/deauth needed) *and* attempts a **4-way
  handshake**, sending deauth bursts to nudge connected clients.
- Verifies the handshake with `aircrack-ng`, writes `.cap`/`.pcapng` +
  a `*.capture.json` for Stage 3, and restores managed mode on exit.

## Stage 3 — Crack (Kali VM, or colleague's GPU rig)

```bash
sudo apt install hcxtools hashcat john   # one-time
sudo gunzip /usr/share/wordlists/rockyou.txt.gz   # if needed

./kali/crack.sh -c captures/<file>-01.cap -w /usr/share/wordlists/rockyou.txt
# -e auto|hashcat|john   -r <rules file>   -o <outdir>
```

- Converts to hashcat **22000** format with `hcxpcapngtool`.
- **hashcat** primary (`-m 22000`, GPU). **Auto-falls back to John the Ripper**
  when no hashcat compute device is present.
- Writes `<file>.result.json` — `cracked: true/false`, engine, and the
  recovered passphrase if found.

### One-shot chain

```bash
sudo ./kali/run_pipeline.sh -i wlan1 -m capture_manifest.json \
     -w /usr/share/wordlists/rockyou.txt
```

---

## USB adapter passthrough into the Kali VM

**VirtualBox:** install the *Extension Pack*, VM → Settings → USB → enable
USB 3.0 (xHCI) → add a filter for your adapter → boot Kali → `ip link` /
`iw dev` should list `wlan1`.

**VMware Workstation:** VM → Removable Devices → your adapter → Connect.

Confirm inside Kali:
```bash
iw dev                              # should show the USB interface (e.g. wlan1)
sudo airmon-ng                      # lists it as a wifi device
sudo aireplay-ng --test wlan1mon    # "Injection is working!" = good to go
```

If `iw dev` only shows the built-in card, the USB adapter isn't passed through —
fix passthrough before running Stage 2. Remember: **the built-in AX211 will never
show injection support**, which is expected.

---

## Notes & limitations

- **WPA3-SAE** and **WPA2-Enterprise** are not offline-crackable the way
  WPA2-PSK is; the pipeline flags this and the crack stage will report no hash.
- Cracking success depends entirely on the **wordlist** — a strong random
  passphrase won't be in `rockyou.txt`. Add targeted wordlists / hashcat rules.
- Deauth requires at least one connected client (for the 4-way handshake); PMKID
  can sometimes be pulled from the AP with no client at all.

---

<div align="center">
  <sub>Built by a pentester, for pentesters · Singapore 🇸🇬</sub>
</div>

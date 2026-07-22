# Ping-Sweeper

> **Categorised Host Discovery & Master-Sheet Mapping for Infrastructure VAPT**

A zero-dependency Bash tool that takes the client's scope — text lists, CSV exports, or the **original Excel tracker** — sweeps every IP with both `fping` and `nmap`, and hands back live-host lists **grouped by device category** plus a **LIVE/DEAD mapping sheet** you can paste straight back into the client's master IP list. No more ticking off hosts one by one.

```
  ____  _              ____
 |  _ \(_)_ __   __ _ / ___|_      _____  ___ _ __
 | |_) | | '_ \ / _` |\___ \ \ /\ / / _ \/ _ \ '_ \
 |  __/| | | | | (_| | ___) \ V  V /  __/  __/ |_) |
 |_|   |_|_| |_|\__, ||____/ \_/\_/ \___|\___| .__/
                |___/                        |_|
             Bren's Host Discovery Automater
```

---

## ⚠️ Legal Disclaimer

This tool performs active network host discovery. Only run it against IP ranges you have **explicit written authorisation** to test. Sweeping a client network is an intrusive action that will appear in their IDS/IPS and SIEM — confirm your scope and testing window before you start.

---

## What It Does

Every infrastructure engagement starts the same way: the client sends a master Excel tracker with a few hundred (or few thousand) IPs, split across columns like `IP`, `Subnet`, `Device Type`, `Hostname`, `Location`. Before you can scan anything, you need to know **which of those hosts are actually alive** — and then you need to feed that answer *back* into the tracker so the report reflects what was really in scope.

Done manually that's hours of work: clean the sheet into IP lists, ping each group, eyeball the output, then hand-flag every row in Excel as live or dead. This script does the whole loop.

**1. Ingests the scope in whatever format you were given**
Drop the client's files into `input/`. Plain `.txt` lists, `.csv` exports, or the **untouched `.xlsx` tracker** all work. IPs and CIDR ranges are extracted from *any* column, so a sheet with `IP,Subnet,Device Type,Owner` needs no cleanup. Subnet-mask columns (`255.255.255.0`), headers, hostnames and other noise are filtered out automatically.

**2. Sweeps with two complementary methods**
An `fping` ICMP sweep catches everything that answers ping. An `nmap -sn` pass (`-PE` ICMP echo + `-PS`/`-PA` TCP SYN/ACK on your chosen ports, plus ARP on local subnets) catches the hosts that **silently drop ICMP** — the Windows boxes and hardened appliances a ping-only sweep misses entirely. The two result sets are unioned, so a host only has to answer *one* of them to be marked live.

**3. Categorises the findings**
One input file = one category. `windows_hosts.csv` produces `alive_windows_hosts.txt`, `cctv_ips.txt` produces `alive_cctv_ips.txt`, and so on. You get each device group's live hosts separately **and** a single deduplicated `alive_all.txt` for the whole engagement — so you can scan Windows separately from CCTV, or blast the lot in one go.

**4. Maps the results back to the master sheet — the part that saves the most time**
`results_all.csv` contains **every scoped IP**, not just the live ones, with its category, its `LIVE`/`DEAD` status, and which method detected it:

```csv
ip,category,status,detected_by
10.10.5.21,windows_hosts,DEAD,
10.10.5.22,windows_hosts,LIVE,icmp
10.20.1.8,linux_hosts,LIVE,icmp+nmap
192.168.50.7,cctv_ips,LIVE,nmap
```

Open the client's master tracker, add a `Status` column, and `VLOOKUP` / `XLOOKUP` against this file. Every row is flagged in one action — no manual reconciliation, and you have documented evidence of *how* each host was detected (useful when a client asks why a host was declared dead).

---

## Features

- **Any input format** — `.txt`, `.csv`, `.lst`, `.xlsx`, `.xlsm`; mixed formats in the same run
- **Reads Excel with no dependencies** — `.xlsx` is unzipped and parsed straight from the workbook XML using only `unzip`. No Python, no `openpyxl`, no LibreOffice, no internet
- **Column-agnostic extraction** — pulls IPs and CIDR ranges out of any column layout; ignores headers, hostnames, device types
- **Netmask filtering** — subnet columns like `255.255.255.0` are dropped instead of being swept as bogus hosts, and every octet is validated (`192.168.1.300` is rejected)
- **Dual-method discovery** — `fping` ICMP + `nmap -sn` (`-PE -PS -PA` / ARP), results unioned so ICMP-blocking hosts are still found
- **Custom discovery ports** — `22,80,443,3389` always probed; you're prompted to add any others (`8080`, `8443`, `445`, …)
- **Per-category *and* combined output** — grouped live-host lists plus one deduplicated master list
- **Master-sheet mapping** — `results_all.csv` gives LIVE/DEAD status + detection method for every scoped IP
- **Timestamped run folders** — engagements and re-runs never overwrite each other
- **Bounded scans** — `--host-timeout` and `--max-retries` are configurable so dead ranges can never stall the run
- **Live progress ticker** — a running elapsed-time indicator during quiet scans, plus `-v` for full nmap output; a long sweep never looks frozen
- **Offline by design** — pure Bash over tools already present on Kali. Copy one folder to an air-gapped client laptop and run

---

## Requirements

Everything is stock on Kali Linux:

```bash
sudo apt install fping nmap unzip     # only if a minimal image is missing them
```

| Tool | Purpose |
|---|---|
| `fping` | Fast ICMP sweep |
| `nmap` | ICMP/TCP/ARP discovery sweep |
| `unzip` | Reading `.xlsx` workbooks offline |
| `awk`, `grep`, `sort` | Parsing and filtering (coreutils) |

**No Python. No pip. No internet.** Run as **root** (`sudo`) so nmap can send raw `-PE`/`-PS`/`-PA` probes — without it nmap silently downgrades to TCP-connect and results will be less reliable.

---

## Usage

```bash
git clone https://github.com/0xbr3n/VAPT-Tools.git
cd VAPT-Tools/Ping-Sweeper
chmod +x pingsweep.sh
```

**1. Drop the scope into `input/`** — one file per device category. The **filename becomes the category name**, so name them however you want the output labelled:

```
input/
  windows_hosts.csv
  linux_hosts.txt
  cctv_ips.txt
  master_tracker.xlsx
```

**2. Run it**

```bash
sudo ./pingsweep.sh
```

It shows the default discovery ports, asks if you want to add any, sweeps each category, then offers to run a full service scan on the live hosts.

**3. Collect the results**

```
output/run_20260623_142530/
├── _parsed/                        # cleaned target list per category
├── windows_hosts/
│   ├── alive_icmp.txt              # fping hits
│   ├── alive_nmap.txt              # nmap -sn hits
│   ├── nmap_sn.gnmap               # raw nmap greppable output
│   └── alive_windows_hosts.txt     # ← category live hosts (union)
├── linux_hosts/…
├── cctv_ips/…
├── alive_all.txt                   # ← all live hosts, deduped (for nmap -iL)
├── alive_all.csv                   # ← ip,category
├── results_all.csv                 # ← ip,category,status,detected_by  (master-sheet map)
├── summary.txt                     # counts table
└── sweep.log                       # full run transcript
```

**4. Scan only what's alive**

```bash
nmap -sS -sV -n -T4 --top-ports 1000 -iL output/run_*/alive_all.txt -oA nmap_services
```

Or let the script do it for you with `-s`.

---

## Options

| Flag | Meaning |
|---|---|
| `-i DIR` | Input directory (default: `./input`) |
| `-o DIR` | Output directory (default: `./output`) |
| `-p LIST` | Extra discovery ports, comma-separated (skips the prompt) |
| `-t TIME` | Per-host timeout (default `20s`) — e.g. `10s`, `30s`, `1m` |
| `-r NUM` | nmap max-retries (default `1`; `0` = fastest) |
| `-y` | Non-interactive: accept defaults, no prompts |
| `-s` | After the sweep, run the full nmap service scan on `alive_all.txt` |
| `-v` | Verbose: echo every command and show live nmap progress |
| `-h` | Help |

### Examples

```bash
sudo ./pingsweep.sh                              # interactive, default folders
sudo ./pingsweep.sh -p 8080,8443,445             # add extra discovery ports
sudo ./pingsweep.sh -y -s                        # fully automated + service scan
sudo ./pingsweep.sh -i /root/engmt/scope -o /root/engmt/results
sudo ./pingsweep.sh -v                           # watch live progress
sudo ./pingsweep.sh -r 0 -t 10s                  # fastest sweep over dead ranges
sudo ./pingsweep.sh -r 3 -t 60s                  # thorough sweep on a lossy network
```

---

## Notes & Troubleshooting

**"It looks stuck on one category."**
That's nmap working through unresponsive hosts — dead IPs, off-subnet addresses, or a CIDR range like `172.16.0.0/24` that expands to 254 hosts. The run is bounded by `--host-timeout` / `--max-retries` so it always finishes, and a live elapsed-time ticker shows it's still moving. Use `-v` to watch nmap directly, or `-r 0 -t 10s` to speed through dead space.

**Categories.** One file = one category. If you drop a single master `.xlsx` containing every device type, all its IPs land under one category named after the file — still correct, just not split. To keep Windows/Linux/CCTV separate, give each its own file.

**Legacy `.xls`.** The old binary format isn't supported offline — re-save as `.xlsx` or `.csv`.

**CIDR ranges.** Passed through to `fping`/`nmap` and expanded by them. In `results_all.csv` the range itself isn't given a status (a range has no single state), but every live host discovered inside it appears as its own row.

**Duplicates across categories.** A host listed in two input files appears once per category in `results_all.csv` and `alive_all.csv` (so you can see every group it belongs to), but only once in `alive_all.txt`.

---

## Why Two Discovery Methods?

| Pass | Catches |
|---|---|
| `fping` ICMP | Hosts that answer ping — fast, low noise |
| `nmap -sn` | Hosts that **block ICMP** but expose TCP (`-PS`/`-PA` on your ports), plus ARP on local subnets |

Windows hosts with the default firewall, hardened Linux servers, and most network appliances drop ICMP entirely. A ping-only sweep reports them dead and they get silently dropped from scope — the classic way live hosts go untested. Running both and taking the union closes that gap.

---

<div align="center">
  <sub>Built by a pentester, for pentesters · Singapore 🇸🇬</sub>
</div>

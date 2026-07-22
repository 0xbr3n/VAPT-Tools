#!/usr/bin/env bash
#
# pingsweep.sh - Categorised host-discovery sweep for infra VAPT
# ---------------------------------------------------------------
# Runs an fping ICMP sweep + an nmap -sn (ICMP/TCP-SYN/TCP-ACK/ARP) sweep
# against one or more category files, then emits per-category AND a single
# combined live-hosts list.
#
# Designed to run OFFLINE, out-of-the-box on Kali (no pip / no internet).
# Dependencies (all stock on Kali): fping, nmap, awk, grep, sort, comm.
#
# WORKFLOW
#   1. Drop one file per category into ./input/  (e.g. linux_hosts.txt,
#      windows_hosts.csv, cctv_ips.txt). The FILENAME becomes the category.
#      Files may be .txt or .csv with any columns - IPs/CIDR are auto-extracted.
#   2. ./pingsweep.sh
#   3. Collect results from ./output/run_<timestamp>/
#
# USAGE
#   ./pingsweep.sh [options]
#     -i DIR    input directory          (default: ./input)
#     -o DIR    output directory         (default: ./output)
#     -p LIST   extra discovery ports, comma-sep (skips the prompt)
#     -y        non-interactive: accept all defaults, no prompts
#     -s        after the sweep, run the full nmap service scan on alive_all
#     -v        verbose: echo each command + show live nmap progress
#     -t TIME   per-host timeout (default: 20s) e.g. 10s, 30s, 1m
#     -r NUM    nmap max-retries / probe retransmissions (default: 1; 0 = fastest)
#     -h        show this help
#
# EXAMPLES
#   ./pingsweep.sh                       # interactive, default folders
#   ./pingsweep.sh -i /root/engmt/ips -p 8080,8443,445 -y
#   ./pingsweep.sh -y -s                 # fully automated incl. service scan
#   ./pingsweep.sh -v                    # watch live progress (debug a "hang")
#   ./pingsweep.sh -t 10s                # tighter per-host cap on dead ranges
#
set -u

# ----------------------------------------------------------------------------
# Defaults / config
# ----------------------------------------------------------------------------
# Anchor default folders to the SCRIPT's location, not the caller's CWD, so
# `./pingsweep.sh` works no matter where it's launched from. (-i/-o override.)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
INPUT_DIR="$SCRIPT_DIR/input"
OUTPUT_BASE="$SCRIPT_DIR/output"
DEFAULT_PORTS="22,80,443,3389"     # the "usual" PE/PS/PA discovery ports
EXTRA_PORTS=""
NONINTERACTIVE=0
RUN_SERVICE_SCAN=0
VERBOSE=0
HOST_TIMEOUT="20s"          # hard cap per host so dead/off-subnet IPs can't stall
MAX_RETRIES=1               # nmap probe retransmissions per host (higher = more thorough but slower)

# fping tuning (from the playbook): 1 retry, 500ms timeout
FPING_OPTS="-a -q -r1 -t500"

# nmap tuning: -sn = ping scan (no port scan), -n = no reverse DNS,
# -T4 = fast timing. --max-retries and --host-timeout (added per-run below)
# bound the time spent on hosts that never answer (otherwise the run *looks*
# hung on dead ranges).
NMAP_BASE="-sn -n -T4"

# ----------------------------------------------------------------------------
# Colours (degrade gracefully if not a TTY)
# ----------------------------------------------------------------------------
if [ -t 1 ]; then
  C_RST=$'\e[0m'; C_BOLD=$'\e[1m'; C_GRN=$'\e[32m'; C_YEL=$'\e[33m'
  C_RED=$'\e[31m'; C_CYN=$'\e[36m'; C_DIM=$'\e[2m'
else
  C_RST=""; C_BOLD=""; C_GRN=""; C_YEL=""; C_RED=""; C_CYN=""; C_DIM=""
fi

info()  { printf '%s[*]%s %s\n' "$C_CYN"  "$C_RST" "$*"; }
ok()    { printf '%s[+]%s %s\n' "$C_GRN"  "$C_RST" "$*"; }
warn()  { printf '%s[!]%s %s\n' "$C_YEL"  "$C_RST" "$*"; }
err()   { printf '%s[x]%s %s\n' "$C_RED"  "$C_RST" "$*" >&2; }
hdr()   { printf '\n%s%s== %s ==%s\n' "$C_BOLD" "$C_CYN" "$*" "$C_RST"; }

usage() { sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }

# heartbeat PID LABEL START
#   While background process PID runs, print a live "Ns elapsed" line to the
#   terminal so a quiet long-running scan never looks frozen. Writes only to
#   /dev/tty (keeps the spinner out of the log) and no-ops if there's no TTY.
heartbeat() {
  local pid="$1" label="$2" start="$3"
  # Only animate if /dev/tty can actually be opened for writing; otherwise
  # just wait quietly for the background job to finish.
  if ! { true >/dev/tty; } 2>/dev/null; then
    wait "$pid" 2>/dev/null; return 0
  fi
  while kill -0 "$pid" 2>/dev/null; do
    printf '\r    %s%s ... %ss elapsed%s ' \
      "$C_DIM" "$label" "$((SECONDS - start))" "$C_RST" > /dev/tty
    sleep 2
  done
  printf '\r%*s\r' 64 '' > /dev/tty       # clear the line
}

# ----------------------------------------------------------------------------
# Arg parsing
# ----------------------------------------------------------------------------
while getopts ":i:o:p:t:r:ysvh" opt; do
  case "$opt" in
    i) INPUT_DIR="$OPTARG" ;;
    o) OUTPUT_BASE="$OPTARG" ;;
    p) EXTRA_PORTS="$OPTARG" ;;
    t) HOST_TIMEOUT="$OPTARG" ;;
    r) MAX_RETRIES="$OPTARG" ;;
    y) NONINTERACTIVE=1 ;;
    s) RUN_SERVICE_SCAN=1 ;;
    v) VERBOSE=1 ;;
    h) usage ;;
    \?) err "Unknown option: -$OPTARG"; exit 2 ;;
    :)  err "Option -$OPTARG requires an argument"; exit 2 ;;
  esac
done

# -r must be a non-negative integer (0 = no retries, fastest).
if ! printf '%s' "$MAX_RETRIES" | grep -qE '^[0-9]+$'; then
  err "Invalid -r value '$MAX_RETRIES' (must be a whole number, e.g. 0, 1, 3)."
  exit 2
fi

# ----------------------------------------------------------------------------
# Pre-flight checks
# ----------------------------------------------------------------------------
hdr "Pre-flight"

missing=0
for bin in fping nmap awk grep sort comm unzip; do
  if command -v "$bin" >/dev/null 2>&1; then
    printf '    %s%-7s%s found\n' "$C_GRN" "$bin" "$C_RST"
  else
    printf '    %s%-7s%s MISSING\n' "$C_RED" "$bin" "$C_RST"
    missing=1
  fi
done
if [ "$missing" -ne 0 ]; then
  err "Install missing tools (Kali: 'apt install fping nmap'). Aborting."
  exit 1
fi

# Root check - nmap's -PE/-PS/-PA raw probes and fast fping need raw sockets.
if [ "$(id -u)" -ne 0 ]; then
  warn "Not running as root. nmap will fall back to TCP-connect probes and"
  warn "ICMP (-PE) discovery may be limited. Re-run with sudo for best results."
fi

if [ ! -d "$INPUT_DIR" ]; then
  warn "Input dir not found - creating it: $INPUT_DIR"
  mkdir -p "$INPUT_DIR" || { err "Could not create '$INPUT_DIR'."; exit 1; }
  info "Drop one file per category into it, then re-run. e.g.:"
  info "    cp linux_hosts.txt windows_hosts.csv cctv_ips.txt master.xlsx '$INPUT_DIR/'"
  exit 1
fi

# Gather category files (.txt / .csv / .lst / .xlsx / .xlsm), ignore the rest.
shopt -s nullglob nocaseglob
CAT_FILES=( "$INPUT_DIR"/*.txt "$INPUT_DIR"/*.csv "$INPUT_DIR"/*.lst \
            "$INPUT_DIR"/*.xlsx "$INPUT_DIR"/*.xlsm )
shopt -u nullglob nocaseglob

if [ "${#CAT_FILES[@]}" -eq 0 ]; then
  err "No .txt/.csv/.lst/.xlsx/.xlsm files in '$INPUT_DIR'."
  exit 1
fi

ok "Found ${#CAT_FILES[@]} category file(s):"
for f in "${CAT_FILES[@]}"; do printf '    %s\n' "$(basename "$f")"; done

# ----------------------------------------------------------------------------
# Port selection
# ----------------------------------------------------------------------------
hdr "Discovery ports"
info "These ports are ALWAYS probed via nmap -PS (SYN) and -PA (ACK):"
printf '    %s%s%s\n' "$C_BOLD" "$DEFAULT_PORTS" "$C_RST"

if [ "$NONINTERACTIVE" -eq 0 ] && [ -z "$EXTRA_PORTS" ]; then
  printf '%sAdd any extra ports? (comma-separated, blank = none): %s' "$C_YEL" "$C_RST"
  read -r EXTRA_PORTS </dev/tty || EXTRA_PORTS=""
fi

# Sanitise + merge port lists -> unique, numeric only.
PORTS="$DEFAULT_PORTS"
if [ -n "$EXTRA_PORTS" ]; then
  clean_extra=$(printf '%s' "$EXTRA_PORTS" | tr ' ' ',' | tr -s ',' \
                | grep -oE '[0-9]+' | paste -sd, -)
  [ -n "$clean_extra" ] && PORTS="$DEFAULT_PORTS,$clean_extra"
fi
# Dedupe ports while preserving order-ish (sort numeric unique).
PORTS=$(printf '%s' "$PORTS" | tr ',' '\n' | grep -oE '[0-9]+' \
        | sort -n -u | paste -sd, -)
ok "Final discovery port set: $PORTS"

# ----------------------------------------------------------------------------
# Run directory
# ----------------------------------------------------------------------------
TS=$(date +%Y%m%d_%H%M%S)
RUN_DIR="$OUTPUT_BASE/run_$TS"
PARSED_DIR="$RUN_DIR/_parsed"
LOG="$RUN_DIR/sweep.log"
COMBINED="$RUN_DIR/alive_all.txt"
COMBINED_CSV="$RUN_DIR/alive_all.csv"
STATUS_CSV="$RUN_DIR/results_all.csv"
SUMMARY="$RUN_DIR/summary.txt"
mkdir -p "$PARSED_DIR"
: > "$COMBINED"
printf 'ip,category\n' > "$COMBINED_CSV"
printf 'ip,category,status,detected_by\n' > "$STATUS_CSV"

# Mirror everything to the log as well.
exec > >(tee -a "$LOG") 2>&1

hdr "Run $TS"
info "Output: $RUN_DIR"
info "Ports : $PORTS"
info "Limits: max-retries $MAX_RETRIES  |  host-timeout $HOST_TIMEOUT  |  verbose: $([ "$VERBOSE" -eq 1 ] && echo on || echo off)"
echo

# Regex for an IPv4 address with optional /CIDR.
IP_RE='([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?'

# ip_filter
#   stdin -> valid IPv4 (optionally /CIDR) targets:
#     - validates each octet is 0-255 (drops garbage like 192.168.1.300)
#     - drops 255.0.0.0/8 (standard subnet masks) and 0.0.0.0
#     - sorts numerically, de-dupes
ip_filter() {
  grep -oE "$IP_RE" \
    | awk -F'[./]' '{ok=1; for(i=1;i<=4;i++) if($i>255) ok=0; if(ok) print}' \
    | grep -vE '^(255\.|0\.0\.0\.0)' \
    | sort -V -u
}

# extract_ips FILE
#   Pull targets from any supported file/column layout:
#     - .txt / .csv / .lst  : grab IPs from every column
#     - .xlsx / .xlsm       : unzip the workbook XML (text cells live in
#                             xl/sharedStrings.xml) and grab IPs - fully
#                             offline, only needs `unzip`. No pip/LibreOffice.
extract_ips() {
  local file="$1" ext
  ext="$(printf '%s' "${file##*.}" | tr 'A-Z' 'a-z')"
  case "$ext" in
    xlsx|xlsm|xltx)
      # sharedStrings holds string cells; worksheets cover any inline strings.
      unzip -p "$file" 'xl/sharedStrings.xml' 'xl/worksheets/*.xml' 2>/dev/null \
        | ip_filter
      ;;
    xls)
      warn "Legacy .xls (binary) not supported offline - re-save as .xlsx or .csv. Skipping '$file'." >&2
      ;;
    *)
      ip_filter < "$file"
      ;;
  esac
}

# ----------------------------------------------------------------------------
# Per-category sweep
# ----------------------------------------------------------------------------
declare -a SUM_CAT SUM_IN SUM_ICMP SUM_NMAP SUM_LIVE

for f in "${CAT_FILES[@]}"; do
  base=$(basename "$f")
  cat="${base%.*}"                       # strip extension -> category name
  cat=$(printf '%s' "$cat" | tr ' /' '__')   # filesystem-safe

  hdr "Category: $cat"
  cdir="$RUN_DIR/$cat"
  mkdir -p "$cdir"

  parsed="$PARSED_DIR/$cat.txt"
  # Extract IPs/CIDR from any column, validate, drop masks/dupes, sort.
  extract_ips "$f" > "$parsed"
  n_in=$(wc -l < "$parsed" | tr -d ' ')

  if [ "$n_in" -eq 0 ]; then
    warn "No IPs found in $base - skipping."
    continue
  fi
  info "$n_in unique target(s) parsed -> $parsed"
  n_cidr=$(grep -c '/' "$parsed")
  if [ "$n_cidr" -gt 0 ]; then
    warn "$n_cidr CIDR range(s) here - nmap/fping expand these to many hosts, so this category can take a while. Watch the live timer; use -v for full detail."
  fi

  icmp="$cdir/alive_icmp.txt"
  nmapg="$cdir/nmap_sn.gnmap"
  nmaplive="$cdir/alive_nmap.txt"
  live="$cdir/alive_${cat}.txt"

  # --- 1) fping ICMP sweep --------------------------------------------------
  t0=$SECONDS
  info "fping ICMP sweep ($n_in host(s))..."
  [ "$VERBOSE" -eq 1 ] && info "CMD: fping $FPING_OPTS -f $parsed"
  # shellcheck disable=SC2086
  fping $FPING_OPTS -f "$parsed" 2>/dev/null | sort -V -u > "$icmp"
  n_icmp=$(wc -l < "$icmp" | tr -d ' ')
  ok "fping: $n_icmp alive ($((SECONDS - t0))s)"

  # --- 2) nmap -sn discovery (ICMP + TCP SYN/ACK on chosen ports) -----------
  # --host-timeout caps each host so unresponsive IPs can't stall the run.
  t0=$SECONDS
  nmap_to="--max-retries $MAX_RETRIES --host-timeout $HOST_TIMEOUT"
  info "nmap -sn discovery (PE + PS/PA on $PORTS, max-retries $MAX_RETRIES, host-timeout $HOST_TIMEOUT)..."
  if [ "$VERBOSE" -eq 1 ]; then
    # Verbose: show nmap's own live progress (--stats-every), no heartbeat.
    info "CMD: nmap $NMAP_BASE $nmap_to -v --stats-every 5s -PE -PS$PORTS -PA$PORTS -iL $parsed -oG $nmapg"
    # shellcheck disable=SC2086
    nmap $NMAP_BASE $nmap_to -v --stats-every 5s -PE -PS"$PORTS" -PA"$PORTS" -iL "$parsed" -oG "$nmapg"
  else
    # Quiet: run nmap in the background + a heartbeat so it never looks frozen.
    # shellcheck disable=SC2086
    nmap $NMAP_BASE $nmap_to -PE -PS"$PORTS" -PA"$PORTS" -iL "$parsed" -oG "$nmapg" >/dev/null 2>&1 &
    heartbeat "$!" "nmap scanning $n_in target(s)" "$t0"
  fi
  awk '/Status: Up/{print $2}' "$nmapg" | sort -V -u > "$nmaplive"
  n_nmap=$(wc -l < "$nmaplive" | tr -d ' ')
  ok "nmap : $n_nmap alive ($((SECONDS - t0))s)"

  # --- 3) combine this category --------------------------------------------
  cat "$icmp" "$nmaplive" | grep -oE "$IP_RE" | sort -V -u > "$live"
  n_live=$(wc -l < "$live" | tr -d ' ')
  ok "Category live total: $n_live  -> $live"

  # feed the global combined list (plain) + the labelled CSV (ip,category)
  cat "$live" >> "$COMBINED"
  awk -v c="$cat" '{print $1","c}' "$live" >> "$COMBINED_CSV"

  # --- 4) master-sheet mapping: EVERY scoped IP with LIVE/DEAD + method -----
  # Lets you VLOOKUP results straight back into the client's master IP sheet
  # instead of flagging hosts one by one. CIDR entries are skipped as rows
  # (a range has no single status) but any live host found inside one appears.
  awk -v c="$cat" -v icmpf="$icmp" -v nmapf="$nmaplive" '
    FILENAME == icmpf { i[$0]=1; hosts[$0]=1; next }
    FILENAME == nmapf { n[$0]=1; hosts[$0]=1; next }
                      { hosts[$0]=1 }
    END {
      for (h in hosts) {
        if (h == "" || h ~ /\//) continue
        by = ""
        if ((h in i) && (h in n)) by = "icmp+nmap"
        else if (h in i)          by = "icmp"
        else if (h in n)          by = "nmap"
        printf "%s,%s,%s,%s\n", h, c, (by == "" ? "DEAD" : "LIVE"), by
      }
    }' "$icmp" "$nmaplive" "$parsed" >> "$STATUS_CSV"

  SUM_CAT+=("$cat"); SUM_IN+=("$n_in"); SUM_ICMP+=("$n_icmp")
  SUM_NMAP+=("$n_nmap"); SUM_LIVE+=("$n_live")
done

# ----------------------------------------------------------------------------
# Combined list
# ----------------------------------------------------------------------------
sort -V -u "$COMBINED" -o "$COMBINED"
n_all=$(wc -l < "$COMBINED" | tr -d ' ')

# Sort the labelled CSV by IP, keeping the header row on top. A host that
# belongs to >1 category intentionally keeps one row per category.
if [ -s "$COMBINED_CSV" ]; then
  { head -n1 "$COMBINED_CSV"; tail -n +2 "$COMBINED_CSV" | sort -V -u; } \
    > "$COMBINED_CSV.tmp" && mv "$COMBINED_CSV.tmp" "$COMBINED_CSV"
fi

# Same for the full LIVE/DEAD mapping sheet.
if [ -s "$STATUS_CSV" ]; then
  { head -n1 "$STATUS_CSV"; tail -n +2 "$STATUS_CSV" | sort -V -u; } \
    > "$STATUS_CSV.tmp" && mv "$STATUS_CSV.tmp" "$STATUS_CSV"
fi
n_scoped=$(($(wc -l < "$STATUS_CSV" | tr -d ' ') - 1))
n_dead=$(( n_scoped - $(grep -c ',LIVE,' "$STATUS_CSV") ))

# ----------------------------------------------------------------------------
# Summary
# ----------------------------------------------------------------------------
hdr "Summary"
{
  printf '%-22s %8s %8s %8s %8s\n' "CATEGORY" "TARGETS" "ICMP" "NMAP" "LIVE"
  printf '%-22s %8s %8s %8s %8s\n' "----------------------" "-------" "----" "----" "----"
  for i in "${!SUM_CAT[@]}"; do
    printf '%-22s %8s %8s %8s %8s\n' \
      "${SUM_CAT[$i]}" "${SUM_IN[$i]}" "${SUM_ICMP[$i]}" "${SUM_NMAP[$i]}" "${SUM_LIVE[$i]}"
  done
  printf '%-22s %8s %8s %8s %8s\n' "----------------------" "-------" "----" "----" "----"
  printf '%-22s %8s %8s %8s %8s\n' "COMBINED (dedup)" "" "" "" "$n_all"
} | tee "$SUMMARY"

echo
ok "Per-category lists : $RUN_DIR/<category>/alive_<category>.txt"
ok "Combined live list : $COMBINED  ($n_all hosts)"
ok "Combined labelled  : $COMBINED_CSV  (ip,category)"
ok "Master-sheet map   : $STATUS_CSV  ($n_scoped scoped: $n_all live / $n_dead dead)"
ok "Log                : $LOG"

# ----------------------------------------------------------------------------
# Optional: full nmap service scan on the combined live list
# ----------------------------------------------------------------------------
if [ "$NONINTERACTIVE" -eq 0 ] && [ "$RUN_SERVICE_SCAN" -eq 0 ] && [ "$n_all" -gt 0 ]; then
  printf '%sRun full nmap service scan (-sS -sV --top-ports 1000) on the %s live hosts now? [y/N]: %s' \
    "$C_YEL" "$n_all" "$C_RST"
  read -r ans </dev/tty || ans=""
  case "$ans" in [Yy]*) RUN_SERVICE_SCAN=1 ;; esac
fi

if [ "$RUN_SERVICE_SCAN" -eq 1 ] && [ "$n_all" -gt 0 ]; then
  hdr "Service scan"
  out="$RUN_DIR/nmap_services"
  info "nmap -sS -sV -n -T4 --top-ports 1000 -iL $COMBINED -oA $out"
  nmap -sS -sV -n -T4 --top-ports 1000 -iL "$COMBINED" -oA "$out"
  ok "Service scan output: ${out}.{nmap,gnmap,xml}"
fi

echo
ok "Done."

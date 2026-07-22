#!/usr/bin/env bash
#
# crack.sh — Stage 3 of the WiFi audit suite (Kali/Linux).
#
# Takes a captured handshake/PMKID (.cap / .pcap / .pcapng), converts it to the
# hashcat 22000 format, and attempts to recover the WPA2-PSK passphrase.
# Primary engine: hashcat (-m 22000, GPU). Automatic fallback: John the Ripper
# (CPU) when no usable hashcat compute device is present.
#
# ===========================================================================
#  AUTHORIZED USE ONLY. Crack only handshakes you captured with permission.
# ===========================================================================
#
# Usage:
#   ./crack.sh -c capture-01.cap -w /usr/share/wordlists/rockyou.txt [options]
#
# Options:
#   -c CAPTURE    capture file (.cap/.pcap/.pcapng)                    [required]
#   -w WORDLIST   wordlist path (default: /usr/share/wordlists/rockyou.txt)
#   -r RULES      hashcat rules file (optional, e.g. best64.rule)
#   -e ENGINE     auto | hashcat | john   (default: auto)
#   -o OUTDIR     output directory (default: ./cracked)
#   -h            help
#
set -uo pipefail

CAPTURE=""
WORDLIST="/usr/share/wordlists/rockyou.txt"
RULES=""
ENGINE="auto"
OUTDIR="./cracked"

log()  { echo -e "[\e[36m*\e[0m] $*"; }
ok()   { echo -e "[\e[32m+\e[0m] $*"; }
warn() { echo -e "[\e[33m!\e[0m] $*"; }
err()  { echo -e "[\e[31mx\e[0m] $*" >&2; }
usage(){ grep '^#' "$0" | sed 's/^#//' | head -30; exit "${1:-0}"; }

while getopts "c:w:r:e:o:h" opt; do
  case "$opt" in
    c) CAPTURE="$OPTARG" ;;
    w) WORDLIST="$OPTARG" ;;
    r) RULES="$OPTARG" ;;
    e) ENGINE="$OPTARG" ;;
    o) OUTDIR="$OPTARG" ;;
    h) usage 0 ;;
    *) usage 1 ;;
  esac
done

[[ -n "$CAPTURE" ]]  || { err "Missing -c CAPTURE."; usage 1; }
[[ -f "$CAPTURE" ]]  || { err "Capture not found: $CAPTURE"; exit 1; }
if [[ ! -f "$WORDLIST" ]]; then
  err "Wordlist not found: $WORDLIST"
  [[ -f /usr/share/wordlists/rockyou.txt.gz ]] && \
    warn "Found rockyou.txt.gz — run: sudo gunzip /usr/share/wordlists/rockyou.txt.gz"
  exit 1
fi

mkdir -p "$OUTDIR"
BASE="$OUTDIR/$(basename "${CAPTURE%.*}")"
HASH_22000="$BASE.22000"
POTFILE="$BASE.potfile"
RESULT_JSON="$BASE.result.json"

# ---- convert capture -> 22000 ---------------------------------------------
command -v hcxpcapngtool >/dev/null 2>&1 || {
  err "hcxpcapngtool missing. Install: sudo apt install hcxtools"; exit 1; }

log "Converting $CAPTURE -> $HASH_22000 (hashcat 22000 format)..."
hcxpcapngtool -o "$HASH_22000" "$CAPTURE" > "$BASE.convert.log" 2>&1

if [[ ! -s "$HASH_22000" ]]; then
  err "No crackable EAPOL/PMKID hashes extracted from $CAPTURE."
  warn "The capture likely has no complete 4-way handshake or PMKID."
  warn "See $BASE.convert.log. Re-run Stage 2 (ensure a client is connected)."
  jq -n --arg cap "$CAPTURE" \
    '{status:"no_hash", capture:$cap, cracked:false}' > "$RESULT_JSON"
  exit 2
fi
HASH_COUNT=$(wc -l < "$HASH_22000")
ok "Extracted $HASH_COUNT hash line(s)."

# ---- engine selection ------------------------------------------------------
have_hashcat_device() {
  command -v hashcat >/dev/null 2>&1 || return 1
  # returns 0 if hashcat reports at least one backend device
  hashcat -I 2>/dev/null | grep -qiE "Backend Device ID|Type\.*:" && return 0
  # even CPU-only OpenCL counts; if -I lists nothing usable, fail
  return 1
}

run_hashcat() {
  log "Engine: hashcat -m 22000 (GPU/OpenCL)..."
  local args=(-m 22000 -a 0 "$HASH_22000" "$WORDLIST"
              --potfile-path "$POTFILE" --status --status-timer 10)
  [[ -n "$RULES" ]] && args+=(-r "$RULES")
  hashcat "${args[@]}"
  local rc=$?
  # rc: 0 = cracked, 1 = exhausted (not cracked). Both are "ran ok".
  hashcat -m 22000 "$HASH_22000" --potfile-path "$POTFILE" --show 2>/dev/null \
    > "$BASE.hashcat.show"
  if [[ -s "$BASE.hashcat.show" ]]; then
    # 22000 --show format: HASH:...:MAC_AP:MAC_CL:ESSID:PASSWORD
    local pw ess
    pw=$(awk -F: '{print $NF}' "$BASE.hashcat.show" | head -1)
    ess=$(awk -F: '{print $(NF-1)}' "$BASE.hashcat.show" | head -1)
    ok "CRACKED! SSID='$ess'  PASSWORD='$pw'"
    jq -n --arg e hashcat --arg ess "$ess" --arg pw "$pw" --arg cap "$CAPTURE" \
      '{status:"cracked", engine:$e, capture:$cap, ssid:$ess, password:$pw, cracked:true}' \
      > "$RESULT_JSON"
    return 0
  fi
  warn "hashcat exhausted the wordlist without cracking (rc=$rc)."
  jq -n --arg e hashcat --arg cap "$CAPTURE" --arg w "$WORDLIST" \
    '{status:"not_cracked", engine:$e, capture:$cap, wordlist:$w, cracked:false}' \
    > "$RESULT_JSON"
  return 1
}

run_john() {
  command -v john >/dev/null 2>&1 || { err "John the Ripper not installed."; return 3; }
  log "Engine: John the Ripper (CPU fallback)..."
  # John reads the hashcat 22000 format via the wpapsk-pmk / 22000 formats in
  # recent Jumbo builds. Try 22000 directly; fall back to wpapcap2john on .cap.
  local jhash="$BASE.john"
  cp "$HASH_22000" "$jhash"
  john --wordlist="$WORDLIST" --format=wpapsk-pmkid "$jhash" >/dev/null 2>&1 \
    || john --wordlist="$WORDLIST" "$jhash" >/dev/null 2>&1
  local shown
  shown=$(john --show "$jhash" 2>/dev/null | grep -v "password hash" | head -1)
  if [[ -n "$shown" && "$shown" != *"0 password"* ]]; then
    local pw
    pw=$(echo "$shown" | awk -F: '{print $2}')
    ok "CRACKED (John)! PASSWORD='$pw'"
    jq -n --arg e john --arg pw "$pw" --arg cap "$CAPTURE" \
      '{status:"cracked", engine:$e, capture:$cap, password:$pw, cracked:true}' \
      > "$RESULT_JSON"
    return 0
  fi
  warn "John exhausted the wordlist without cracking."
  jq -n --arg e john --arg cap "$CAPTURE" --arg w "$WORDLIST" \
    '{status:"not_cracked", engine:$e, capture:$cap, wordlist:$w, cracked:false}' \
    > "$RESULT_JSON"
  return 1
}

# ---- run -------------------------------------------------------------------
case "$ENGINE" in
  hashcat) run_hashcat ;;
  john)    run_john ;;
  auto)
    if have_hashcat_device; then
      run_hashcat || { warn "Falling back to John..."; run_john; }
    else
      warn "No usable hashcat compute device detected — using John the Ripper."
      run_john
    fi
    ;;
  *) err "Unknown engine: $ENGINE"; exit 1 ;;
esac

echo
ok "Result written: $RESULT_JSON"
cat "$RESULT_JSON" 2>/dev/null

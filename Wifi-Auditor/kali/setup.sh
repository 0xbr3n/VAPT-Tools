#!/usr/bin/env bash
#
# setup.sh — one-shot bootstrap for the WiFi Audit Suite on Kali/Linux.
#
# Copies the suite off a read-only shared mount into your home (if needed),
# makes the scripts executable, installs every dependency, decompresses the
# rockyou wordlist, and prints the wireless interfaces it can see.
#
# Run as your NORMAL user (it calls sudo only for the package install, so the
# copied files stay owned by you):
#
#     ./setup.sh
#
set -e

SRC_KALI="$(cd "$(dirname "$0")" && pwd)"       # .../Wifi-Auditor/kali
SRC_ROOT="$(dirname "$SRC_KALI")"               # .../Wifi-Auditor
DEST="$HOME/Wifi-Auditor"

echo "[*] Suite source: $SRC_ROOT"

# If we're on a shared/removable/read-only mount, copy into home first.
if [[ "$SRC_ROOT" == /mnt/* || "$SRC_ROOT" == /media/* || ! -w "$SRC_ROOT" ]]; then
  echo "[*] Read-only/shared location detected — copying to $DEST ..."
  mkdir -p "$DEST"
  cp -r "$SRC_ROOT"/. "$DEST"/
  WORK="$DEST/kali"
else
  WORK="$SRC_KALI"
fi

cd "$WORK"
echo "[*] Working directory: $WORK"

echo "[*] Making scripts executable..."
chmod +x ./*.sh 2>/dev/null || true

echo "[*] Installing dependencies (needs sudo)..."
sudo ./install_deps.sh

echo
echo "[*] Wireless interfaces currently visible:"
if command -v iw >/dev/null 2>&1; then
  iw dev | awk '/Interface/{print "      - " $2}'
else
  echo "      (iw not found — check the install step above)"
fi

echo
echo "==========================================================================="
echo "[+] Setup complete. Files are in: $WORK"
echo "[+] Next:"
echo "      1. Plug in your USB injection adapter (RTL8812AU / Alfa)."
echo "      2. VMware -> Removable Devices -> your adapter -> Connect to the VM."
echo "      3. Confirm it appears above (e.g. wlan1), then run:"
echo
echo "         cd $WORK && sudo python3 wifi_audit.py"
echo "==========================================================================="

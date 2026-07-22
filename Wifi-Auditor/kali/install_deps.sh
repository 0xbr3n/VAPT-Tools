#!/usr/bin/env bash
#
# install_deps.sh — one-shot dependency setup for the WiFi Audit Suite on Kali.
#
# Installs every tool the orchestrator can use across all phases (recon, PMKID,
# handshake, WPS, WPA3, Enterprise, DoS, cracking, reporting). Safe to re-run.
#
# Robust by design: core attack tools install atomically; optional/report tools
# install separately and NEVER abort the run if a package is missing from your
# Kali mirror (package availability drifts on rolling).
#
set -u
[[ $EUID -eq 0 ]] || { echo "Run as root: sudo ./install_deps.sh"; exit 1; }

# Non-interactive so the Wireshark "allow non-root capture?" dialog can't hang us.
export DEBIAN_FRONTEND=noninteractive

echo "[*] apt update..."
apt update || true

# --- core attack + cracking tools (these all exist in kali-rolling) ----------
# NOTE: hcxdumptool is intentionally NOT installed from apt here. Kali rolling
# now ships hcxdumptool 7.x, whose rewritten interface "arm" step is incompatible
# with out-of-tree Realtek drivers (Alfa 8812AU/8814AU) and fails with
# "failed to arm interface -driver does not support monitor mode". We build the
# last Realtek-friendly release (6.2.7) from source below instead. hcxtools
# (the hcxpcapngtool hash converter) stays on the apt version — it's unaffected.
echo "[*] Installing core wireless + cracking tools..."
apt install -y --no-install-recommends \
  aircrack-ng \
  hcxtools \
  reaver bully \
  hashcat john \
  mdk4 \
  nmap \
  jq git python3 make gcc pkg-config libssl-dev \
  || { echo "[x] Core install failed — fix the error above and re-run."; exit 1; }

# --- hcxdumptool 6.2.7 from source (Realtek-compatible) ----------------------
HCX_WANT="6.2.7"
hcx_have="$(hcxdumptool --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
if [[ "$hcx_have" != "$HCX_WANT" ]]; then
  echo "[*] Installing hcxdumptool $HCX_WANT from source (found: ${hcx_have:-none})..."
  apt remove -y hcxdumptool 2>/dev/null || true   # drop any apt 7.x build
  _hcxsrc="$(mktemp -d)"
  if git clone --quiet https://github.com/ZerBea/hcxdumptool.git "$_hcxsrc" \
     && ( cd "$_hcxsrc" && git checkout --quiet "$HCX_WANT" && make && make install ); then
    echo "    hcxdumptool $HCX_WANT installed: $(command -v hcxdumptool)"
  else
    echo "    [x] hcxdumptool $HCX_WANT build FAILED — PMKID capture on Realtek adapters"
    echo "        will not work until this is resolved. Build manually:"
    echo "        git clone https://github.com/ZerBea/hcxdumptool && cd hcxdumptool \\"
    echo "          && git checkout $HCX_WANT && make && sudo make install"
  fi
  rm -rf "$_hcxsrc"
else
  echo "[*] hcxdumptool $HCX_WANT already installed — skipping source build."
fi

# --- optional tools: never abort the whole script if one is unavailable ------
opt_install() {
  echo "[*] (optional) $*"
  apt install -y --no-install-recommends "$@" 2>/dev/null \
    || echo "    [!] skipped (not in your mirror): $*"
}

opt_install kismet
opt_install wireshark tshark
opt_install responder
opt_install wifiphisher
opt_install hostapd-wpe asleap        # Enterprise (802.1X) evil-twin (apt alt to eaphammer)
opt_install realtek-rtl88xxau-dkms    # common Alfa dual-band chipset driver

# --- eaphammer: not in apt; clone + expose on PATH (non-fatal) ---------------
# Only needed for Enterprise (802.1X / MGT) evil-twin testing.
if ! command -v eaphammer >/dev/null 2>&1; then
  echo "[*] (optional) Installing eaphammer from GitHub for Enterprise testing..."
  if command -v git >/dev/null 2>&1 && \
     git clone https://github.com/s0lst1c3/eaphammer /opt/eaphammer 2>/dev/null; then
    ( cd /opt/eaphammer && ./kali-setup ) 2>/dev/null || \
      echo "    [!] eaphammer kali-setup needs a manual run: cd /opt/eaphammer && ./kali-setup"
    cat > /usr/local/bin/eaphammer <<'EOF'
#!/bin/bash
cd /opt/eaphammer && exec python3 ./eaphammer "$@"
EOF
    chmod +x /usr/local/bin/eaphammer
    echo "    eaphammer exposed at /usr/local/bin/eaphammer"
  else
    echo "    [!] eaphammer skipped — install manually if you test 802.1X networks."
  fi
fi

# --- PDF report engine: wkhtmltopdf was removed from Debian/Kali -------------
# The report generator prefers wkhtmltopdf, then falls back to WeasyPrint,
# then to HTML-only. Install WeasyPrint so you still get a PDF.
echo "[*] Installing WeasyPrint for PDF reports (wkhtmltopdf is gone from Kali)..."
apt install -y --no-install-recommends python3-weasyprint 2>/dev/null \
  || pip3 install --break-system-packages weasyprint 2>/dev/null \
  || echo "    [!] WeasyPrint not installed — reports will be HTML-only (still fine)."

# --- rockyou wordlist --------------------------------------------------------
echo "[*] Decompressing rockyou wordlist if present..."
if [[ -f /usr/share/wordlists/rockyou.txt.gz ]]; then
  gunzip -k /usr/share/wordlists/rockyou.txt.gz 2>/dev/null && echo "    rockyou.txt ready."
elif [[ -f /usr/share/wordlists/rockyou.txt ]]; then
  echo "    rockyou.txt already present."
else
  echo "    [!] rockyou not found — install with: sudo apt install wordlists"
fi

echo "[*] Opt-in module note: WPA3 Dragonblood PoCs are built manually —"
echo "    the suite offers to 'git clone vanhoefm/dragondrain-and-time' at runtime;"
echo "    you then run 'make' in that repo (needs libpcap/openssl dev headers)."

echo
echo "[+] Done. Verify your adapter:  iw dev   &&   sudo airmon-ng"
echo "[+] Then run:  sudo python3 wifi_audit.py"

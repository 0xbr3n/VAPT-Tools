#!/usr/bin/env bash
# Build a standalone, single-file binary of vapt_toolkit.py
#
# Run this ONCE on a build machine that DOES have internet (to install
# PyInstaller and the third-party libs). The resulting binary in dist/
# is fully self-contained and needs zero internet / zero Python on the
# target machine.
#
# Build host must match the target OS+arch:
#   - Linux  build host -> Linux  binary (no Windows/Mac binary)
#   - Windows build host -> Windows .exe
#   - macOS  build host -> macOS binary
# There is no cross-compilation. Build on each OS you want to ship to.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PY="${PYTHON:-python3}"
NAME="vapt_toolkit"

echo "[1/4] Creating clean virtualenv (./.buildvenv)..."
"$PY" -m venv .buildvenv
# shellcheck disable=SC1091
source .buildvenv/bin/activate

echo "[2/4] Installing runtime deps + PyInstaller..."
pip install --upgrade pip wheel >/dev/null
pip install -r requirements.txt
pip install pyinstaller

echo "[3/4] Building single-file binary with PyInstaller..."
# --onefile         : produce one self-contained executable
# --clean           : wipe PyInstaller cache before build
# --name            : final binary name
# --collect-all     : ensure all sub-modules are bundled (cryptography is fussy)
pyinstaller \
  --onefile \
  --clean \
  --name "$NAME" \
  --collect-all cryptography \
  --collect-all certifi \
  vapt_toolkit.py

echo "[4/4] Done."
echo
echo "Binary location: $SCRIPT_DIR/dist/$NAME"
echo
echo "Quick test:"
echo "  ./dist/$NAME            # interactive menu"
echo "  ./dist/$NAME 4          # jump straight to tool 4 (SSL audit)"
echo
echo "The binary in dist/ is self-contained. Copy it to any target machine"
echo "with the SAME OS+arch and it will run with no Python and no internet."

deactivate

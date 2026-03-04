#!/usr/bin/env bash
# IR Sinkhole — one-liner install (run with curl -sSL ... | sudo bash)
# Use only on the affected host or a dedicated IR/test machine. Requires root for capture/contain.

set -e
GITHUB_REPO="${GITHUB_REPO:-https://github.com/Leviticus-Triage/ir-sinkhole}"
INSTALL_DIR="${INSTALL_DIR:-/opt/ir-sinkhole}"
VENV="${INSTALL_DIR}/venv"
BIN_LINK="/usr/local/bin/ir-sinkhole"

echo "IR Sinkhole installer"
echo "  Install dir: $INSTALL_DIR"
echo "  Requires: Python 3.10+, nftables, tshark (optional), root for capture/contain"
echo ""

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root: curl -sSL <url> | sudo bash"
  exit 1
fi

apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-pip nftables tshark 2>/dev/null || true

mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

if [ -d ".git" ]; then
  git pull --quiet 2>/dev/null || true
else
  if command -v git &>/dev/null; then
    git clone --depth 1 "$GITHUB_REPO" . 2>/dev/null || true
  fi
  if [ ! -f "pyproject.toml" ]; then
    echo "Not a git clone. Copy ir-sinkhole source to $INSTALL_DIR (e.g. from release tarball)."
    exit 1
  fi
fi

python3 -m venv "$VENV"
"$VENV/bin/pip" install --quiet --upgrade pip
"$VENV/bin/pip" install --quiet -e ".[dev]" 2>/dev/null || "$VENV/bin/pip" install --quiet .
"$VENV/bin/pip" install --quiet scapy 2>/dev/null || true

ln -sf "$VENV/bin/ir-sinkhole" "$BIN_LINK" 2>/dev/null || true
mkdir -p /var/lib/ir-sinkhole /var/run

echo "Installed. Usage:"
echo "  sudo ir-sinkhole status"
echo "  sudo ir-sinkhole capture -d 15m -o /var/lib/ir-sinkhole"
echo "  sudo ir-sinkhole contain -o /var/lib/ir-sinkhole   # Ctrl+C to stop"
echo "  sudo ir-sinkhole stop"
echo ""
echo "See README for incident response workflow."

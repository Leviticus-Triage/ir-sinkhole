#!/usr/bin/env bash
# IR Sinkhole ASCII menu launcher
# Intended to be usable via: curl -sSL <raw-url> | sudo bash

set -euo pipefail

GITHUB_REPO="${GITHUB_REPO:-https://github.com/Leviticus-Triage/ir-sinkhole}"
INSTALL_DIR="${INSTALL_DIR:-/opt/ir-sinkhole}"
VENV_DIR="$INSTALL_DIR/venv"
IR_BIN_LINK="/usr/local/bin/ir-sinkhole"
DEFAULT_OUT="/var/lib/ir-sinkhole"

banner() {
  clear
  cat <<'BANNER'
  ___ ____    ____ _       _           _      _
 |_ _|  _ \  / ___(_)_ __ | |__   ___ | | ___| | ___   _
  | || |_) | \___ \ | '_ \| '_ \ / _ \| |/ _ \ |/ / | | |
  | ||  __/   ___) | | | | | | | (_) | |  __/   <| |_| |
 |___|_|     |____/|_| |_|_| |_|\___/|_|\___|_|\_\\__, |
                                                  |___/
        Incident Response Sinkhole — ASCII Menu
BANNER
}

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "[!] This script must run as root (sudo)." >&2
    exit 1
  fi
}

ensure_dependencies() {
  echo "[+] Installing base dependencies (python3, venv, pip, nftables, tshark) if needed..."
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq || true
    apt-get install -y -qq python3 python3-venv python3-pip nftables tshark git || true
  else
    echo "[!] Non-Debian system detected. Please ensure python3, python3-venv, python3-pip, nftables, tshark, and git are installed." >&2
  fi
}

ensure_install() {
  mkdir -p "$INSTALL_DIR"
  cd "$INSTALL_DIR"

  if [ -d .git ]; then
    echo "[+] Updating existing ir-sinkhole clone in $INSTALL_DIR..."
    git pull --quiet || true
  else
    if [ ! -f pyproject.toml ]; then
      echo "[+] Cloning ir-sinkhole from $GITHUB_REPO into $INSTALL_DIR..."
      if ! command -v git >/dev/null 2>&1; then
        echo "[!] git not available. Install git or pre-populate $INSTALL_DIR with the source tree." >&2
        exit 1
      fi
      git clone --depth 1 "$GITHUB_REPO" . || {
        echo "[!] git clone failed. Check GITHUB_REPO or network." >&2
        exit 1
      }
    fi
  fi

  echo "[+] Setting up Python virtualenv in $VENV_DIR..."
  python3 -m venv "$VENV_DIR"
  "$VENV_DIR/bin/pip" install --quiet --upgrade pip
  # Try dev extras first (for pytest etc.), fall back to normal install
  "$VENV_DIR/bin/pip" install --quiet -e ".[dev]" 2>/dev/null || "$VENV_DIR/bin/pip" install --quiet .
  "$VENV_DIR/bin/pip" install --quiet scapy 2>/dev/null || true

  ln -sf "$VENV_DIR/bin/ir-sinkhole" "$IR_BIN_LINK" 2>/dev/null || true
  mkdir -p "$DEFAULT_OUT" /var/run

  echo "[+] ir-sinkhole installed. Binary: $VENV_DIR/bin/ir-sinkhole"
}

ir() {
  "$VENV_DIR/bin/ir-sinkhole" "$@"
}

menu_main() {
  local choice
  while true; do
    banner
    echo "Install dir : $INSTALL_DIR"
    echo "Output dir  : $DEFAULT_OUT"
    echo
    echo "[1] Status"
    echo "[2] Capture (start recording)"
    echo "[3] Contain (start sinkhole & firewall)"
    echo "[4] Stop containment (remove firewall)"
    echo "[5] Quit"
    echo
    read -rp "Select option [1-5]: " choice || exit 0
    case "$choice" in
      1) do_status ; read -rp "Press Enter to continue..." _ ;;
      2) do_capture ; read -rp "Press Enter to continue..." _ ;;
      3) do_contain ; read -rp "Press Enter to continue..." _ ;;
      4) do_stop ; read -rp "Press Enter to continue..." _ ;;
      5) echo "Bye." ; exit 0 ;;
      *) echo "Invalid choice." ; sleep 1 ;;
    esac
  done
}

do_status() {
  echo
  ir status || echo "[!] ir-sinkhole status failed."
}

do_capture() {
  echo
  read -rp "Capture duration (e.g. 15m, 60, 1h) [15m]: " dur
  dur=${dur:-15m}
  read -rp "Output directory [$DEFAULT_OUT]: " out
  out=${out:-$DEFAULT_OUT}
  read -rp "Interface for tshark [any]: " iface
  iface=${iface:-any}
  read -rp "Run tshark (PCAP) ? [Y/n]: " usecap
  usecap=${usecap:-Y}

  local args=(capture -d "$dur" -o "$out" -i "$iface")
  if [[ "$usecap" =~ ^[Nn]$ ]]; then
    args+=(--no-tshark)
  fi

  echo "[+] Running: ir-sinkhole ${args[*]}"
  ir "${args[@]}" || echo "[!] capture failed."
}

do_contain() {
  echo
  read -rp "Output directory with capture [$DEFAULT_OUT]: " out
  out=${out:-$DEFAULT_OUT}
  read -rp "First sinkhole port [19000]: " pstart
  pstart=${pstart:-19000}
  read -rp "Drop all other egress? [Y/n]: " drop
  drop=${drop:-Y}
  read -rp "Record containment PCAP on loopback? (PATH or empty to skip): " rec

  local args=(contain -o "$out" --port-start "$pstart")
  if [[ "$drop" =~ ^[Nn]$ ]]; then
    args+=(--no-drop-egress)
  fi
  if [[ -n "$rec" ]]; then
    args+=(--record-pcap "$rec")
  fi

  echo
  echo "[+] Starting containment. Press Ctrl+C in that session to stop."
  echo "[!] Containment will run in the foreground now."
  echo
  ir "${args[@]}" || echo "[!] contain failed."
}

do_stop() {
  echo
  ir stop || echo "[!] stop failed (firewall may already be removed)."
}

main() {
  require_root
  ensure_dependencies
  ensure_install
  menu_main
}

main "$@"

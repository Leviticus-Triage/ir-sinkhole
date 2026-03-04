#!/usr/bin/env bash
# IR Sinkhole — Interactive ASCII Menu
# Download-then-run: curl -sSL <url>/run.sh | bash
set -e

GITHUB_REPO="${GITHUB_REPO:-https://github.com/Leviticus-Triage/ir-sinkhole}"
INSTALL_DIR="${INSTALL_DIR:-/opt/ir-sinkhole}"
VENV_DIR="$INSTALL_DIR/venv"
IR_BIN_LINK="/usr/local/bin/ir-sinkhole"
DEFAULT_OUT="/var/lib/ir-sinkhole"

RED=$'\033[0;31m'
GRN=$'\033[0;32m'
YLW=$'\033[1;33m'
CYN=$'\033[0;36m'
BLD=$'\033[1m'
DIM=$'\033[2m'
RST=$'\033[0m'

line()  { printf "${DIM}────────────────────────────────────────────${RST}\n"; }
info()  { printf "${CYN}[*]${RST} %s\n" "$*"; }
ok()    { printf "${GRN}[+]${RST} %s\n" "$*"; }
warn()  { printf "${YLW}[!]${RST} %s\n" "$*"; }
err()   { printf "${RED}[✗]${RST} %s\n" "$*"; }
ask()   { printf "${BLD}$1${RST} "; read -r "$2"; }

pause_menu() {
  echo ""
  line
  printf "${DIM}Press Enter to return to menu...${RST}"
  read -r _
}

banner() {
  clear
  local W=66
  local border
  border=$(printf '═%.0s' $(seq 1 $W))
  _bx() { printf "${BLD}${CYN}  ║${RST}${BLD}${CYN}%-${W}s${RST}${BLD}${CYN}║${RST}\n" "$1"; }

  printf "${BLD}${CYN}  ╔%s╗${RST}\n" "$border"
  _bx '    ________     _____ _____   ____ __ __  ______  __    ______'
  _bx '   /  _/ __ \   / ___//  _/ | / / //_// / / / __ \/ /   / ____/'
  _bx '   / // /_/ /   \__ \ / //  |/ / ,<  / /_/ / / / / /   / __/'
  _bx ' _/ // _, _/   ___/ // // /|  / /| |/ __  / /_/ / /___/ /___'
  _bx '/___/_/ |_|   /____/___/_/ |_/_/ |_/_/ /_/\____/_____/_____/'
  _bx ''
  _bx '         Incident Response Containment  v1.0.0'
  _bx '         By Leviticus-Triage'
  printf "${BLD}${CYN}  ╚%s╝${RST}\n" "$border"

  echo ""
  printf "  ${DIM}Install dir :${RST} %s\n" "$INSTALL_DIR"
  printf "  ${DIM}Output dir  :${RST} %s\n" "$DEFAULT_OUT"
  echo ""
  line
}

ir() {
  "$VENV_DIR/bin/ir-sinkhole" "$@"
}

# ── Setup ─────────────────────────────────────────

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    err "This script must run as root (sudo)."
    exit 1
  fi
}

ensure_dependencies() {
  info "Checking system dependencies..."
  local missing=()
  command -v python3  >/dev/null 2>&1 || missing+=(python3)
  command -v git      >/dev/null 2>&1 || missing+=(git)
  dpkg -s python3-venv >/dev/null 2>&1 || missing+=(python3-venv)

  if [ ${#missing[@]} -gt 0 ]; then
    info "Installing: ${missing[*]} + nftables, tshark ..."
    apt-get update -qq 2>/dev/null || true
    apt-get install -y -qq python3 python3-venv python3-pip nftables tshark git 2>/dev/null || true
    ok "System packages installed."
  else
    ok "System dependencies present."
  fi
}

ensure_install() {
  mkdir -p "$INSTALL_DIR"
  cd "$INSTALL_DIR"

  if [ -d .git ]; then
    info "Updating existing clone in $INSTALL_DIR ..."
    git pull --quiet 2>/dev/null || true
    ok "Repository updated."
  elif [ ! -f pyproject.toml ]; then
    info "Cloning $GITHUB_REPO ..."
    git clone --depth 1 "$GITHUB_REPO" . || { err "git clone failed."; exit 1; }
    ok "Repository cloned."
  else
    ok "Source already present."
  fi

  if [ ! -f "$VENV_DIR/bin/ir-sinkhole" ]; then
    info "Creating Python virtualenv ..."
    python3 -m venv "$VENV_DIR"
    "$VENV_DIR/bin/pip" install --quiet --upgrade pip
    "$VENV_DIR/bin/pip" install --quiet -e ".[dev]" 2>/dev/null || "$VENV_DIR/bin/pip" install --quiet .
    "$VENV_DIR/bin/pip" install --quiet scapy 2>/dev/null || true
    ok "Python environment ready."
  else
    ok "Python environment already set up."
  fi

  ln -sf "$VENV_DIR/bin/ir-sinkhole" "$IR_BIN_LINK" 2>/dev/null || true
  mkdir -p "$DEFAULT_OUT" /var/run
}

# ── Menu actions ──────────────────────────────────

do_status() {
  banner
  printf "${BLD}  ── STATUS ──${RST}\n\n"
  info "Querying active TCP connections and containment state ...\n"
  line
  ir status 2>&1 || warn "ir-sinkhole status returned an error."
  line
  pause_menu
}

do_capture() {
  banner
  printf "${BLD}  ── CAPTURE ──${RST}\n\n"
  info "Configure the capture phase. Press Enter for defaults."
  line

  ask "  Duration (e.g. 60s, 15m, 1h, 2h) [15m]:" dur
  dur=${dur:-15m}

  ask "  Output directory [${DEFAULT_OUT}]:" out
  out=${out:-$DEFAULT_OUT}

  ask "  Network interface for tshark [any]:" iface
  iface=${iface:-any}

  ask "  Enable tshark PCAP recording? (Y/n) [Y]:" usecap
  usecap=${usecap:-Y}

  echo ""
  line

  local args=(capture -d "$dur" -o "$out" -i "$iface")
  if [[ "$usecap" =~ ^[Nn]$ ]]; then
    args+=(--no-tshark)
    warn "tshark disabled — replay will use stubs only."
  else
    ok "tshark enabled — PCAP will be written to ${out}/capture.pcap"
  fi

  echo ""
  info "Starting capture with: ir-sinkhole ${args[*]}"
  info "Duration: $dur | Interface: $iface | Output: $out"
  echo ""
  line

  ir "${args[@]}" 2>&1 && ok "Capture completed successfully." || err "Capture failed."

  echo ""
  info "Output files:"
  ls -lh "$out"/connections.jsonl "$out"/remote_endpoints.json "$out"/capture.pcap 2>/dev/null | while read -r l; do
    printf "  ${DIM}%s${RST}\n" "$l"
  done

  echo ""
  if [ -f "$out/remote_endpoints.json" ]; then
    local count
    count=$(python3 -c "import json; print(len(json.load(open('$out/remote_endpoints.json'))))" 2>/dev/null || echo "?")
    ok "Remote endpoints captured: ${BLD}${count}${RST}"
  fi

  pause_menu
}

do_contain() {
  banner
  printf "${BLD}  ── CONTAIN ──${RST}\n\n"

  local out="$DEFAULT_OUT"
  if [ ! -f "$out/remote_endpoints.json" ]; then
    err "No capture data found at $out/remote_endpoints.json"
    warn "Run [2] Capture first before starting containment."
    pause_menu
    return
  fi

  local count
  count=$(python3 -c "import json; print(len(json.load(open('$out/remote_endpoints.json'))))" 2>/dev/null || echo "?")
  ok "Found ${BLD}${count}${RST} remote endpoint(s) from previous capture."
  echo ""
  line

  ask "  Output directory with capture [$DEFAULT_OUT]:" cdir
  cdir=${cdir:-$DEFAULT_OUT}

  ask "  First sinkhole port [19000]:" pstart
  pstart=${pstart:-19000}

  ask "  Drop ALL other egress traffic? (Y/n) [Y]:" drop
  drop=${drop:-Y}

  ask "  Enable DNS sinkhole (block DNS tunneling)? (Y/n) [Y]:" usedns
  usedns=${usedns:-Y}

  ask "  Flush established connections (force through DNAT)? (Y/n) [Y]:" useflush
  useflush=${useflush:-Y}

  ask "  Whitelist management IPs (comma-separated, or empty):" wl_ips
  ask "  Record containment PCAP? Enter path or leave empty:" rec

  echo ""
  line

  local args=(contain -o "$cdir" --port-start "$pstart")
  if [[ "$drop" =~ ^[Nn]$ ]]; then
    args+=(--no-drop-egress)
    warn "Egress NOT blocked — only redirecting captured endpoints."
  else
    ok "Full containment — all egress will be blocked except sinkhole."
  fi
  if [[ "$usedns" =~ ^[Nn]$ ]]; then
    args+=(--no-dns-sinkhole)
    warn "DNS sinkhole disabled — DNS tunneling NOT blocked."
  else
    ok "DNS sinkhole enabled — all DNS queries redirected to 127.0.0.1"
  fi
  if [[ "$useflush" =~ ^[Nn]$ ]]; then
    args+=(--no-conntrack-flush)
    warn "Conntrack flush disabled — established connections stay alive."
  else
    ok "Conntrack flush enabled — established C2 connections will be killed."
  fi
  if [[ -n "$wl_ips" ]]; then
    IFS=',' read -ra ips <<< "$wl_ips"
    for ip in "${ips[@]}"; do
      ip=$(echo "$ip" | xargs)
      if [[ -n "$ip" ]]; then
        args+=(--allow-ip "$ip")
        ok "Whitelisted: $ip"
      fi
    done
  fi
  if [[ -n "$rec" ]]; then
    args+=(--record-pcap "$rec")
    ok "Recording containment PCAP to: $rec"
  fi

  echo ""
  info "Starting containment: ir-sinkhole ${args[*]}"
  warn "Containment runs in foreground. Press Ctrl+C to stop and remove firewall."
  echo ""
  line
  echo ""

  ir "${args[@]}" 2>&1 || err "Containment ended with error."

  ok "Containment stopped. Firewall rules removed."
  pause_menu
}

do_stop() {
  banner
  printf "${BLD}  ── STOP ──${RST}\n\n"
  info "Removing nftables rules and PID file ..."
  line
  ir stop 2>&1 && ok "Firewall removed, containment stopped." || warn "Stop returned error (firewall may already be removed)."
  line
  pause_menu
}

# ── Main menu ─────────────────────────────────────

menu_main() {
  while true; do
    banner
    printf "  ${BLD}[1]${RST}  Status          ${DIM}— show connections & containment state${RST}\n"
    printf "  ${BLD}[2]${RST}  Capture         ${DIM}— record connections + PCAP${RST}\n"
    printf "  ${BLD}[3]${RST}  Contain         ${DIM}— start sinkhole & apply firewall${RST}\n"
    printf "  ${BLD}[4]${RST}  Stop            ${DIM}— remove firewall rules${RST}\n"
    printf "  ${BLD}[5]${RST}  Quit\n"
    echo ""
    line
    ask "  Select [1-5]:" choice
    echo ""

    case "$choice" in
      1) do_status ;;
      2) do_capture ;;
      3) do_contain ;;
      4) do_stop ;;
      5) echo ""; ok "Bye."; exit 0 ;;
      *) warn "Invalid option: '$choice'. Enter 1-5."; sleep 1 ;;
    esac
  done
}

# ── Entry point ───────────────────────────────────

main() {
  require_root
  echo ""
  line
  info "IR Sinkhole — Setup"
  line
  echo ""
  ensure_dependencies
  ensure_install
  echo ""
  ok "Ready. Launching menu ..."
  sleep 1

  exec 0</dev/tty 2>/dev/null || true
  menu_main
}

main "$@"

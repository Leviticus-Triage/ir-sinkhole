#!/usr/bin/env bash
# Bootstrap: download menu script and run with terminal stdin (fixes "curl | bash" pipe issue)
# One-liner: curl -sSL https://raw.githubusercontent.com/Leviticus-Triage/ir-sinkhole/main/scripts/run.sh | bash
set -e
URL="${IR_SINKHOLE_URL:-https://raw.githubusercontent.com/Leviticus-Triage/ir-sinkhole/main/scripts/ir-sinkhole-menu.sh}"
TMP=$(mktemp)
curl -sSL "$URL" -o "$TMP"
exec sudo bash "$TMP" < /dev/tty

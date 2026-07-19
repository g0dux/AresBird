#!/bin/sh
# Cross-platform echo for pack smoke on Linux CI.
set -eu
MSG="echo-open pack targets=${ARES_TARGETS:-} ports=${ARES_PORTS:-} open_ports=${ARES_OPEN_PORTS:-}"
MSG_ESC=$(printf '%s' "$MSG" | sed 's/\\/\\\\/g; s/"/\\"/g')
printf '{"type":"log","level":"info","message":"%s"}\n' "$MSG_ESC"

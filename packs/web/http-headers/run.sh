#!/bin/sh
# Light HTTP GET / — emit interesting response headers as NDJSON (Linux/macOS).
set -eu
TARGET=$(printf '%s' "${ARES_TARGETS:-127.0.0.1}" | cut -d, -f1)
PORTS=${ARES_PORTS:-80}

IFS=,
for p in $PORTS; do
  [ -z "$p" ] && continue
  case "$p" in
    443|8443) SCHEME=https ;;
    *) SCHEME=http ;;
  esac
  URI="${SCHEME}://${TARGET}:${p}/"
  HDR=$(curl -skI --max-time 5 -A "AresBird-http-headers/0.1" "$URI" 2>/dev/null || true)
  if [ -z "$HDR" ]; then
    printf '{"type":"log","level":"info","message":"http-headers %s:%s — no response"}\n' "$TARGET" "$p"
    continue
  fi
  CODE=$(printf '%s' "$HDR" | head -n1 | awk '{print $2}')
  SERVER=$(printf '%s' "$HDR" | awk -F': ' 'BEGIN{IGNORECASE=1} /^Server:/{print $2; exit}' | tr -d '\r')
  POWERED=$(printf '%s' "$HDR" | awk -F': ' 'BEGIN{IGNORECASE=1} /^X-Powered-By:/{print $2; exit}' | tr -d '\r')
  VIA=$(printf '%s' "$HDR" | awk -F': ' 'BEGIN{IGNORECASE=1} /^Via:/{print $2; exit}' | tr -d '\r')
  DETAIL=$(printf 'HTTP %s Server=%s X-Powered-By=%s Via=%s' "${CODE:-?}" "$SERVER" "$POWERED" "$VIA")
  # Escape minimal JSON string chars
  DETAIL_ESC=$(printf '%s' "$DETAIL" | sed 's/\\/\\\\/g; s/"/\\"/g')
  printf '{"type":"probe_result","addr":"%s","port":%s,"probe":"http-headers","detail":"%s","confidence":0.7}\n' \
    "$TARGET" "$p" "$DETAIL_ESC"
done

#!/bin/sh
# Probe a few well-known control-plane HTTP paths (observe-only).
set -eu
TARGET=$(printf '%s' "${ARES_TARGETS:-127.0.0.1}" | cut -d, -f1)
PORTS=${ARES_PORTS:-2375,2379,8500,9000,9090,3000}

OLDIFS=$IFS
IFS=,
# shellcheck disable=SC2086
set -- $PORTS
IFS=$OLDIFS

for p in "$@"; do
  [ -z "$p" ] && continue
  case "$p" in
    443|6443|8443) SCHEME=https ;;
    *) SCHEME=http ;;
  esac
  for path in /version /v1/agent/self /-/healthy /minio/health/live /api/health; do
    URI="${SCHEME}://${TARGET}:${p}${path}"
    CODE=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 3 -A "AresBird-control-plane/0.1" "$URI" 2>/dev/null || echo 000)
    case "$CODE" in
      000|404|502|503|504) continue ;;
    esac
    detail=$(printf 'GET %s → HTTP %s' "$path" "$CODE")
    detail_esc=$(printf '%s' "$detail" | sed 's/\\/\\\\/g; s/"/\\"/g')
    printf '{"type":"probe_result","addr":"%s","port":%s,"probe":"control-plane-hint","detail":"%s","confidence":0.55}\n' \
      "$TARGET" "$p" "$detail_esc"
    if [ "$CODE" = "200" ]; then
      msg=$(printf 'Control-plane path %s reachable on :%s (HTTP %s) — verify auth' "$path" "$p" "$CODE")
      msg_esc=$(printf '%s' "$msg" | sed 's/\\/\\\\/g; s/"/\\"/g')
      sev=medium
      case "$p" in
        2375|2379|6443) sev=high ;;
      esac
      printf '{"type":"misconfig_finding","addr":"%s","port":%s,"finding":"%s","severity":"%s"}\n' \
        "$TARGET" "$p" "$msg_esc" "$sev"
    fi
  done
done

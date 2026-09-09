#!/bin/sh
# Emit misconfig_finding for commonly abused open ports (from ARES_OPEN_PORTS / ARES_PORTS).
set -eu
TARGETS=${ARES_TARGETS:-}
PORTS=${ARES_PORTS:-}
OPEN=${ARES_OPEN_PORTS:-}

list="$PORTS"
[ -n "$OPEN" ] && list="$OPEN"

# port|label|severity
RISKS="6379|Redis|high
9200|Elasticsearch|high
11211|Memcached|high
27017|MongoDB|medium
2375|Docker API|high
2379|etcd|high
8500|Consul|high
5984|CouchDB|high
2181|ZooKeeper|high
9090|Prometheus|high
8080|HTTP alt / Jenkins-ish|low
3389|RDP|medium
5900|VNC|medium"

TARGET=$(printf '%s' "$TARGETS" | cut -d, -f1)
OLDIFS=$IFS
IFS=,
# shellcheck disable=SC2086
set -- $list
IFS=$OLDIFS
for entry in "$@"; do
  [ -z "$entry" ] && continue
  # entry may be "ip:port/tcp" or bare port
  port=$(printf '%s' "$entry" | sed -E 's/.*:([0-9]+).*/\1/; t; s/[^0-9]//g')
  [ -z "$port" ] && continue
  addr="$TARGET"
  case "$entry" in
    *:*) addr=$(printf '%s' "$entry" | cut -d: -f1) ;;
  esac
  printf '%s\n' "$RISKS" | while IFS='|' read -r rp label sev; do
    [ "$port" = "$rp" ] || continue
    msg=$(printf '%s port %s open — verify auth and network exposure' "$label" "$port")
    msg_esc=$(printf '%s' "$msg" | sed 's/\\/\\\\/g; s/"/\\"/g')
    printf '{"type":"misconfig_finding","addr":"%s","port":%s,"finding":"%s","severity":"%s"}\n' \
      "$addr" "$port" "$msg_esc" "$sev"
  done
done

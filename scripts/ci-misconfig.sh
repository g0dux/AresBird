#!/usr/bin/env bash
# Local / CI helper: seed baseline then fail on NEW medium+ findings.
# Usage:
#   TARGET=example.com ./scripts/ci-misconfig.sh
#   TARGET=10.0.0.5 PORTS=apps MIN_SEV=high ./scripts/ci-misconfig.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TARGET="${TARGET:-127.0.0.1}"
PORTS="${PORTS:-web}"
MIN_SEV="${MIN_SEV:-medium}"
export ARES_DATA_DIR="${ARES_DATA_DIR:-$ROOT/.ares-data}"
export ARES_QUIET="${ARES_QUIET:-1}"
mkdir -p "$ARES_DATA_DIR"

if [[ -x "$ROOT/target/release/ares" ]]; then
  BIN="$ROOT/target/release/ares"
elif [[ -x "$ROOT/target/debug/ares" ]]; then
  BIN="$ROOT/target/debug/ares"
else
  echo "building ares-cli…"
  cargo build -p ares-cli --release
  BIN="$ROOT/target/release/ares"
fi

echo "==> seed/compare store: $ARES_DATA_DIR"
"$BIN" test "$TARGET" -p "$PORTS" --no-path-probes --save -q --format csv || true

ARGS=(test "$TARGET" -p "$PORTS" --no-path-probes --save
      --fail-on-new --min-severity "$MIN_SEV" -q --format csv)
if [[ -n "${ARES_NOTIFY_URL:-}" ]]; then
  ARGS+=(--notify "$ARES_NOTIFY_URL" --notify-on new)
fi

set +e
"$BIN" "${ARGS[@]}"
code=$?
set -e
echo "ares exit=$code (2 => new findings)"
exit "$code"

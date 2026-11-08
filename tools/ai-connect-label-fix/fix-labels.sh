#!/usr/bin/env bash
# Fix ai-connect peer labels: drop the per-peer "name_mode: per-project" override
# so the Bridge server assigns unique labels. Idempotent. Backs up before editing.
# Usage: fix-labels.sh [--dry-run] [--config PATH]
set -euo pipefail

CONFIG="${AI_CONNECT_CONFIG:-$HOME/.config/ai-connect/config.yaml}"
DRY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY=1 ;;
    --config) CONFIG="${2:?--config needs a path}"; shift ;;
    -h|--help) sed -n '2,4p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

PATTERN='^[[:space:]]*name_mode[[:space:]]*:[[:space:]]*per-project[[:space:]]*(#.*)?$'

echo "config: $CONFIG"
[ -f "$CONFIG" ] || { echo "ERROR: config not found; is this the ai-connect peer host?" >&2; exit 1; }

echo "--- before (name / name_mode lines) ---"
grep -E '^[[:space:]]*(name|name_mode)[[:space:]]*:' "$CONFIG" || echo "(none)"

if [ -n "${AI_CONNECT_PEER_NAME:-}" ] || [ -n "${AI_CONNECT_PEER_SUFFIX:-}" ]; then
  echo "NOTE: env override set in this shell (AI_CONNECT_PEER_NAME='${AI_CONNECT_PEER_NAME:-}' SUFFIX='${AI_CONNECT_PEER_SUFFIX:-}')."
  echo "      Remove it from your shell profile / service unit, then run: unset AI_CONNECT_PEER_NAME AI_CONNECT_PEER_SUFFIX"
fi

if ! grep -Eq "$PATTERN" "$CONFIG"; then
  echo "OK: no 'name_mode: per-project' line. Nothing to change."
  exit 0
fi

if [ "$DRY" -eq 1 ]; then
  echo "DRY RUN: would delete these lines:"
  grep -En "$PATTERN" "$CONFIG"
  exit 0
fi

BACKUP="$CONFIG.bak.$(date +%Y%m%d%H%M%S)"
cp -p "$CONFIG" "$BACKUP"
TMP="$(mktemp "$CONFIG.XXXXXX")"
grep -Ev "$PATTERN" "$CONFIG" > "$TMP" || true
cat "$TMP" > "$CONFIG"   # keep the original file's mode and owner
rm -f "$TMP"

if grep -Eq "$PATTERN" "$CONFIG"; then
  echo "ERROR: verify failed, restoring backup" >&2
  cp -p "$BACKUP" "$CONFIG"
  exit 1
fi

echo "--- after ---"
grep -E '^[[:space:]]*(name|name_mode)[[:space:]]*:' "$CONFIG" || echo "(none)"
echo "VERIFIED: name_mode per-project removed."
echo "Rollback:  cp -p '$BACKUP' '$CONFIG'"
echo "Next: restart the ai-connect MCP service or the Claude session so the peer re-registers,"
echo "      e.g. 'systemctl restart ai-connect-mcp.service' (add --user if it is a user unit)."

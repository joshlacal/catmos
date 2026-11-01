#!/usr/bin/env bash
# Regenerates catmos/src/lib/brand/tokens.json from
# ../docs/brand/tokens/Catbird.pkl. Called automatically by npm
# `predev` and `prebuild` hooks; run directly via `npm run brand:gen`.
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORKSPACE_ROOT="$(cd "$PROJECT_ROOT/.." && pwd)"
DEFAULT_TOKENS="$WORKSPACE_ROOT/docs/brand/tokens/Catbird.pkl"
if [[ ! -f "$DEFAULT_TOKENS" && -f "$WORKSPACE_ROOT/workspace-root/docs/brand/tokens/Catbird.pkl" ]]; then
  DEFAULT_TOKENS="$WORKSPACE_ROOT/workspace-root/docs/brand/tokens/Catbird.pkl"
fi
TOKENS="${CATBIRD_BRAND_TOKENS:-$DEFAULT_TOKENS}"
OUT="$PROJECT_ROOT/src/lib/brand/tokens.json"

if ! command -v pkl > /dev/null 2>&1; then
  echo "Warning: pkl not on PATH — using existing $OUT if present" >&2
  if [[ ! -f "$OUT" ]]; then
    echo "Error: $OUT not present and pkl unavailable" >&2
    exit 1
  fi
  exit 0
fi

mkdir -p "$(dirname "$OUT")"
pkl eval "$TOKENS" --format json | jq -S . > "$OUT"
echo "Wrote $OUT ($(wc -c < "$OUT") bytes)"

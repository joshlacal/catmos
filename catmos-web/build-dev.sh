#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/../src/lib/wasm-pkg"

echo "Building catmos-web WASM package (dev mode)..."

if ! command -v wasm-pack &>/dev/null; then
    echo "Error: wasm-pack not found."
    exit 1
fi

cd "$SCRIPT_DIR"
wasm-pack build \
    --target web \
    --out-dir "$OUTPUT_DIR" \
    --dev

echo "Dev WASM package built at: $OUTPUT_DIR"

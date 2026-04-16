#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/../src/lib/wasm-pkg"

echo "Building catmos-web WASM package..."

# Check for wasm-pack
if ! command -v wasm-pack &>/dev/null; then
    echo "Error: wasm-pack not found. Install with:"
    echo "  curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh"
    echo "  # or: cargo install wasm-pack"
    exit 1
fi

# Build WASM package targeting web (ESM output)
cd "$SCRIPT_DIR"
wasm-pack build \
    --target web \
    --out-dir "$OUTPUT_DIR" \
    --release

echo "WASM package built at: $OUTPUT_DIR"

# Optional: optimize with wasm-opt if available
if command -v wasm-opt &>/dev/null; then
    WASM_FILE="$OUTPUT_DIR/catmos_web_bg.wasm"
    if [[ -f "$WASM_FILE" ]]; then
        echo "Running wasm-opt for size optimization..."
        wasm-opt -Os "$WASM_FILE" -o "$WASM_FILE"
        echo "wasm-opt complete"
    fi
else
    echo "Note: wasm-opt not found (optional). Install binaryen for smaller WASM output."
fi

echo "Done!"

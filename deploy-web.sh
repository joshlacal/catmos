#!/usr/bin/env bash
set -euo pipefail

EXPECTED_WEB_REV="1731490b2be2dd94e69c889512d0cc9ba8fa5ee8"
EXPECTED_WASM_SHA256="45cefe98834b47bacda1b54b051ed04698e90e1b753842d6de63442713448a0c"
PAGES_BRANCH="${1:-main}"

# Vite cannot handle special characters (+, #, etc.) in the project path.
# Catbird+Petrel contains a "+" which Vite URL-encodes and then misresolves.
# Workaround: create a temporary symlink with a safe path and build from there.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARENT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SAFE_LINK="/tmp/catmos-build"
SAFE_PARENT_LINK="/tmp/catbird-petrel-build"

# Clean up on exit
cleanup() {
    rm -f "$SAFE_LINK"
    rm -f "$SAFE_PARENT_LINK"
}
trap cleanup EXIT

# Create symlinks with paths that have no special characters
rm -f "$SAFE_LINK"
rm -f "$SAFE_PARENT_LINK"
ln -s "$SCRIPT_DIR" "$SAFE_LINK"
ln -s "$PARENT_DIR" "$SAFE_PARENT_LINK"

echo "==> Building catbird-mls-web WASM..."
cd "$SAFE_PARENT_LINK/catbird-mls-web"
bash build.sh

ACTUAL_WEB_REV="$(git rev-parse main^{commit})"
if [[ "$ACTUAL_WEB_REV" != "$EXPECTED_WEB_REV" ]]; then
    echo "catbird-mls-web revision mismatch: expected $EXPECTED_WEB_REV, got $ACTUAL_WEB_REV" >&2
    exit 1
fi

ACTUAL_WASM_SHA256="$(shasum -a 256 pkg/catbird_mls_web_bg.wasm | cut -d' ' -f1)"
if [[ "$ACTUAL_WASM_SHA256" != "$EXPECTED_WASM_SHA256" ]]; then
    echo "WASM artifact mismatch: expected $EXPECTED_WASM_SHA256, got $ACTUAL_WASM_SHA256" >&2
    exit 1
fi

echo "==> Building SvelteKit..."
cd "$SAFE_LINK"
npm run build

echo "==> Deploying to Cloudflare Pages..."
cd "$SAFE_LINK"
npx wrangler pages deploy build/ --project-name=catmos --branch="$PAGES_BRANCH" --commit-dirty=true

echo "==> Done!"

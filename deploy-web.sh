#!/usr/bin/env bash
set -euo pipefail

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

echo "==> Building catmos-web WASM..."
cd "$SAFE_LINK"
bash catmos-web/build.sh

echo "==> Building SvelteKit..."
cd "$SAFE_LINK"
npm run build

echo "==> Deploying to Cloudflare Pages..."
cd "$SAFE_LINK"
npx wrangler pages deploy build/ --project-name=catmos

echo "==> Done!"

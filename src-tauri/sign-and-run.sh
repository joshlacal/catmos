#!/bin/bash
# Auto-sign and run: signs the binary with Apple Development cert + entitlements before executing.
# Prevents macOS keychain prompts on every rebuild during development.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
codesign -s "Apple Development" -f --entitlements "$SCRIPT_DIR/Entitlements.plist" "$1" || echo "warning: codesign failed; keychain prompts may reappear" >&2
exec "$@"

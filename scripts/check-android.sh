#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

SDK_ROOT="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-$HOME/Library/Android/sdk}}"
if [[ ! -d "$SDK_ROOT" ]]; then
	echo "Android SDK not found at: $SDK_ROOT" >&2
	echo "Set ANDROID_SDK_ROOT or ANDROID_HOME to your SDK path." >&2
	exit 1
fi

NDK_DIR="${ANDROID_NDK_HOME:-${NDK_HOME:-}}"
if [[ -z "$NDK_DIR" ]]; then
	if [[ -d "$SDK_ROOT/ndk" ]]; then
		NDK_DIR="$(find "$SDK_ROOT/ndk" -mindepth 1 -maxdepth 1 -type d | sort | tail -n 1)"
	fi
fi

if [[ -z "${NDK_DIR:-}" || ! -d "$NDK_DIR" ]]; then
	echo "Android NDK not found under $SDK_ROOT/ndk." >&2
	echo "Install NDK and/or set ANDROID_NDK_HOME (or NDK_HOME)." >&2
	exit 1
fi

TOOLCHAIN_BIN="$(find "$NDK_DIR/toolchains/llvm/prebuilt" -mindepth 2 -maxdepth 2 -type d -name bin | head -n 1)"
if [[ -z "${TOOLCHAIN_BIN:-}" || ! -d "$TOOLCHAIN_BIN" ]]; then
	echo "Android NDK LLVM toolchain bin directory not found in: $NDK_DIR" >&2
	exit 1
fi

export ANDROID_SDK_ROOT="$SDK_ROOT"
export ANDROID_HOME="${ANDROID_HOME:-$SDK_ROOT}"
export ANDROID_NDK_HOME="$NDK_DIR"
export NDK_HOME="${NDK_HOME:-$NDK_DIR}"
export PATH="$TOOLCHAIN_BIN:$PATH"

cd "$ROOT_DIR/src-tauri"
cargo check --target aarch64-linux-android "$@"

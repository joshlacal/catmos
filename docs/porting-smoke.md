# Catmos Porting Smoke Matrix

Date: 2026-02-14

## Scope
- Validate portability baseline changes for Android, Linux, and Windows.
- Record exact commands, outcomes, and environment blockers.

## Command Matrix

| Command | Result | Notes |
| --- | --- | --- |
| `npm run check:rust` | PASS | Host `cargo check` succeeds after TLS/keyring changes (script runs from `src-tauri` so local Cargo target config is applied). |
| `npm run check:android` | BLOCKED | Fails before compile due missing Android NDK toolchain (`aarch64-linux-android21-clang` not found). No longer fails on `openssl-sys`. |
| `npm run check:linux` | BLOCKED | Cross-compile from macOS requires Linux sysroot/pkg-config cross setup for GTK/WebKit dependencies. |
| `npm run check:windows` | BLOCKED | Cross-compile from macOS to `x86_64-pc-windows-msvc` needs Windows C toolchain/sysroot (C headers missing for `ring`). |
| `npm run check` | PASS (warnings only) | Svelte type check passes with existing pre-existing a11y warnings. |
| `npm run build` | PASS (warnings only) | Production build completes with same pre-existing a11y warnings. |
| `npm run tauri -- --version` | PASS | `tauri-cli 2.10.0`. |
| `npm run tauri -- android init --ci` | BLOCKED | Android SDK found, but NDK missing (`failed to ensure Android environment`). |

## Android Boot Smoke
- Status: BLOCKED in this environment.
- Required to proceed:
  - Install Android NDK (and expose toolchain binaries in `PATH`), or set `NDK_HOME`.
  - Re-run `npm run tauri -- android init --ci`.
  - Run `npm run tauri -- android dev`.

## Environment Blockers Observed
- `ANDROID_NDK_HOME`, `ANDROID_HOME`, and `ANDROID_SDK_ROOT` were not set in shell.
- Android SDK auto-discovered at `/Users/joshlacalamito/Library/Android/sdk`, but NDK was absent.
- Linux/Windows checks are blocked by missing cross-compilation sysroots/toolchains, not by Catmos source code.

## Portability Acceptance Summary
- Completed:
  - Rust TLS stack moved to rustls-based features.
  - Windows-native keyring feature enabled.
  - Hardcoded `/tmp/catmos.log` removed.
  - Mobile viewport usability baseline added (narrow-screen navigation and layout behavior).
  - Build scripts/tooling added for repeatable checks.
- Pending external setup:
  - Android NDK/toolchain.
  - Linux and Windows cross toolchain/sysroot setup (or native CI/runners).

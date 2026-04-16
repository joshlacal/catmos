# catmos - Desktop & Web MLS Messaging

## Overview

Catmos is an E2EE group messaging app on AT Protocol, available as both a Tauri desktop app and a browser web app. Both targets share the same SvelteKit frontend and the same `catbird-mls` MLS orchestrator crate. The desktop version uses Tauri IPC; the web version compiles the orchestrator to WASM.

## Build & Development

### Desktop (Tauri)

```bash
# Install dependencies
cd catmos && npm install

# Development (frontend + Rust backend)
npm run tauri dev

# Build release
npm run tauri build

# Frontend only (no Tauri)
npm run dev

# Type check
npm run check

# Rust backend only
cd src-tauri && cargo build
cd src-tauri && cargo test
cd src-tauri && cargo fmt && cargo clippy
```

### Web (WASM)

Requires: `wasm-pack` (install via `cargo install wasm-pack` or the official installer).

```bash
# Build WASM package (release, with wasm-opt if available)
cd catmos/catmos-web && ./build.sh

# Build WASM package (dev mode, faster, debug symbols)
cd catmos/catmos-web && ./build-dev.sh

# Run SvelteKit frontend pointing at WASM backend
cd catmos && npm run dev
```

The build scripts output to `src/lib/wasm-pkg/` which is gitignored. The SvelteKit frontend auto-detects Tauri vs browser at runtime via `$lib/wasm.ts`.

## Architecture

### Desktop Rust Backend (`src-tauri/`)

```
src-tauri/src/
├── main.rs          # Tauri app entry point
├── lib.rs           # Library with IPC command registration
├── commands.rs      # IPC commands (create_group, send_message, etc.)
├── storage.rs       # SQLCipher local storage
├── credentials.rs   # AT Protocol credential management
├── keychain.rs      # OS keychain integration
├── api_client.rs    # AT Protocol API client
├── websocket.rs     # Real-time message delivery
├── blue.rs          # Blue namespace types
├── blue/            # AT Protocol lexicon types
└── catbird/         # Catbird-specific types
```

### Web WASM Backend (`catmos-web/`)

Compiles the `catbird-mls` orchestrator to WebAssembly. Implements the same three orchestrator traits using browser-native APIs instead of OS services.

```
catmos-web/
├── Cargo.toml           # cdylib crate targeting wasm32-unknown-unknown
├── rust-toolchain.toml  # Pins stable + wasm32 target
├── build.sh             # Release build (wasm-pack + wasm-opt)
├── build-dev.sh         # Dev build (faster, debug symbols)
└── src/
    ├── lib.rs           # Module root + wasm_bindgen(start) panic hook
    ├── api_client.rs    # WasmApiClient (MLSAPIClient via reqwest/fetch)
    ├── storage.rs       # WasmStorageBackend (MLSStorageBackend via IndexedDB)
    ├── credentials.rs   # IndexedDbCredentialStore (CredentialStore via IndexedDB)
    └── websocket.rs     # Browser WebSocket via web-sys
```

Platform trait mapping:

| Orchestrator Trait | Desktop (Tauri) | Web (WASM) |
|--------------------|----------------|------------|
| `MLSAPIClient` | `ReqwestApiClient` (reqwest/native) | `WasmApiClient` (reqwest/fetch) |
| `MLSStorageBackend` | SQLCipher via `rusqlite` | IndexedDB via `web-sys` |
| `CredentialStore` | OS keychain via `keyring` | IndexedDB via `web-sys` |
| WebSocket | `tokio-tungstenite` | `web-sys::WebSocket` |

All trait impls use `#[async_trait(?Send)]` because WASM is single-threaded.

### SvelteKit Frontend (`src/`)

Shared between desktop and web. The `wasm.ts` bridge auto-detects the runtime.

```
src/
├── routes/
│   ├── +layout.svelte   # App shell layout
│   ├── +layout.ts       # SSR disabled (ssr = false)
│   └── +page.svelte     # Main page
├── catmos-web.d.ts      # Type declarations for WASM package
└── lib/
    ├── components/
    │   ├── Sidebar.svelte       # Conversation list
    │   ├── MessageList.svelte   # Message display
    │   ├── MessageBubble.svelte # Individual message
    │   ├── Composer.svelte      # Message input
    │   └── MemberList.svelte    # Group members
    ├── stores/
    │   ├── auth.ts              # Authentication state
    │   ├── conversations.ts     # Conversation list state
    │   ├── messages.ts          # Message state
    │   └── profiles.ts          # Profile cache with batching
    ├── tauri.ts                 # Tauri IPC types + invoke wrappers
    ├── wasm.ts                  # Unified bridge (Tauri ↔ WASM)
    └── wasm-pkg/                # WASM build output (gitignored)
```

### Runtime Detection

`src/lib/wasm.ts` provides a unified API surface:
- Detects `window.__TAURI_INTERNALS__` at module load
- **Tauri**: lazy-imports `@tauri-apps/api/core` invoke()
- **Browser**: lazy-imports + caches the `catmos-web` WASM module
- Stores should import from `$lib/wasm` instead of `$lib/tauri`

### IPC Commands

Frontend calls backend via the unified bridge (17 commands):
- **Auth**: `startLogin`, `completeLogin`, `tryRestoreSession`, `logout`
- **Conversations**: `getConversations`, `createGroup`, `subscribeConversation`, `unsubscribeConversation`
- **Messages**: `sendMessage`, `getMessages`, `fetchNewMessages`, `sendReaction`, `markAsRead`
- **Members**: `getGroupMembers`, `promoteMember`, `demoteMember`, `removeGroupMember`
- **Profiles**: `getProfiles`, `searchUsers`, `checkOptInStatus`

## Key Dependencies

### Rust (Desktop — `src-tauri/`)
- **tauri** 2 - Desktop app framework
- **catbird_mls** - Shared MLS orchestrator (path dependency: `../../catbird-mls`)
- **rusqlite** with `bundled-sqlcipher` - Encrypted local storage
- **atrium-api** - AT Protocol SDK
- **keyring** - OS-native credential storage
- **tokio-tungstenite** - WebSocket for real-time delivery

### Rust (Web — `catmos-web/`)
- **catbird_mls** with `browser` feature - Same orchestrator, WASM-compatible mode
- **wasm-bindgen** / **js-sys** / **web-sys** - WASM ↔ JS interop
- **reqwest** (default-features off) - HTTP via browser fetch
- **getrandom** with `js` feature - Crypto RNG in WASM
- **chrono** with `wasmbind` - Date/time in WASM
- **console-error-panic-hook** - Better panic messages in browser console

### Frontend
- **SvelteKit** + Svelte 5 - UI framework
- **@tauri-apps/api** - Tauri IPC bridge (lazy-loaded, desktop only)
- **@tauri-apps/plugin-shell** - Shell integration (desktop only)
- **@sveltejs/adapter-static** - Static SPA output for both Tauri and web

## Relationship to catbird-mls

Both targets use `catbird_mls` directly as a Rust dependency (no UniFFI). The same `mls-orchestrator` crate powers all three:
- **Catmos Desktop**: Direct Rust API via Tauri IPC
- **Catmos Web**: Same Rust crate compiled to WASM via `wasm-pack`
- **Catbird iOS**: Via UniFFI Swift bindings

The `browser` feature flag in `catbird-mls/Cargo.toml` gates WASM-incompatible code (e.g., SQLCipher, tokio multi-thread). Source-level `cfg(target_arch = "wasm32")` handles the rest.

## Known Issues

- SQLCipher requires `PRAGMA key` after opening connection (StorageFailed panic if missing)
- IPC commands are currently stubs pending Phase 3 implementation
- catmos-web trait impls are stubs — build compiles but methods return `not yet implemented`
- Stores still import from `$lib/tauri` — migration to `$lib/wasm` pending

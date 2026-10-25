# catmos - Desktop & Web MLS Messaging

## Overview

Catmos is an E2EE group messaging app on AT Protocol, available as both a Tauri desktop app and a browser web app. Both targets share the same SvelteKit frontend and the same `catbird-mls` MLS orchestrator crate. The desktop version uses Tauri IPC; the web version compiles the orchestrator to WASM.

## Build & Development

Use Node 24.22.1 LTS and npm 12.2.1 (see `.node-version` and `packageManager`). SvelteKit 3 configuration lives in `vite.config.ts`; `#lib/*` imports are declared in `package.json`. TypeScript stays on 6.0.3 because the current Svelte tooling declares support through version 6.

For an isolated sibling workspace whose brand docs live elsewhere, set `CATBIRD_BRAND_TOKENS` to the absolute `Catbird.pkl` path before running build/dev commands.

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

The WASM backend is `catbird-mls-web`, which lives in its own sibling repo at the workspace root (not under `catmos/`). It is a standalone crate consumed by catmos, catbird-mls-web's own web demo, and any future browser clients.

```bash
# Build WASM package (release, with wasm-opt if available)
cd ../catbird-mls-web && ./build.sh

# Build WASM package (dev mode, faster, debug symbols)
cd ../catbird-mls-web && ./build-dev.sh

# Run the SvelteKit frontend pointing at the WASM backend
cd catmos && npm run dev
```

Build output lives in `catbird-mls-web/pkg/` (gitignored). catmos resolves `import … from 'catbird-mls-web'` through `vite.config.ts` (bundling) + the generated TypeScript config (type-checking), both pointing at that `pkg/` directory. There is no hand-declared `.d.ts` shim — the wasm-pack-generated `catbird_mls_web.d.ts` is the single source of truth for the WASM contract.

The SvelteKit frontend auto-detects Tauri vs browser at runtime via `$lib/wasm.ts`.

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

### Web WASM Backend (`../catbird-mls-web/`)

Single-crate WASM wrapper exposing `#[wasm_bindgen]` entry points directly, compiled to WebAssembly via wasm-pack. catmos consumes the generated `pkg/` output via a Vite alias + SvelteKit `kit.alias`; no hand-declared shim is needed.

Storage model is a unified encrypted SQLite database (OPFS-backed via `wa-sqlite`), shared across credentials, conversation state, and MLS group state — there's no separate IndexedDB layer.

| Feature | Desktop (Tauri) | Web (catbird-mls-web) |
|---------|----------------|------------------------|
| Client construction | Direct Rust via `MLSOrchestrator` | `catbird_mls_init({ baseUrl, storagePrefix?, dbPrefix? })` |
| Auth | `keyring` → OS keychain | `catbird_mls_set_auth(did, token)` → localStorage |
| Storage | SQLCipher via `rusqlite` | OPFS SQLite (wa-sqlite) |
| WebSocket | `tokio-tungstenite` | `catbird_mls_subscribe` → browser WebSocket via `web-sys` |
| HTTP | `reqwest` (native) | `reqwest` (browser fetch backend) |

### SvelteKit Frontend (`src/`)

Shared between desktop and web. The `wasm.ts` bridge auto-detects the runtime.

```
src/
├── routes/
│   ├── +layout.svelte   # App shell layout
│   ├── +layout.ts       # SSR disabled (ssr = false)
│   └── +page.svelte     # Main page
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
    ├── wasm.ts                  # Unified bridge (Tauri ↔ catbird-mls-web)
    └── mls-worker.ts            # Dedicated Worker that owns the WASM instance
```

WASM types come from `../catbird-mls-web/pkg/catbird_mls_web.d.ts` via the `kit.alias` in `tsconfig.json`.

### Runtime Detection

`src/lib/wasm.ts` provides a unified API surface:
- Detects `window.__TAURI_INTERNALS__` at module load
- **Tauri**: lazy-imports `@tauri-apps/api/core` invoke()
- **Browser**: spawns `mls-worker.ts` (Comlink-wrapped) that loads the `catbird-mls-web` WASM module from OPFS-backed SQLite storage
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

### Rust (Web — `../catbird-mls-web/`)

Lives in its own sibling repo. catmos does not take a Rust dependency on it — it consumes the wasm-pack-generated JS/TS artifacts at `../catbird-mls-web/pkg/`.

Notable crate-level pieces (see catbird-mls-web's own AGENTS.md for detail):
- **wasm-bindgen** / **js-sys** / **web-sys** — WASM ↔ JS interop
- **wa-sqlite** — OPFS-backed synchronous SQLite for unified encrypted storage (credentials + conversation state + MLS groups in one DB)
- **reqwest** (default-features off) — HTTP via browser fetch
- **console-error-panic-hook** — better panic messages in the browser console

### Frontend
- **SvelteKit** + Svelte 5 - UI framework
- **@tauri-apps/api** - Tauri IPC bridge (lazy-loaded, desktop only)
- **@tauri-apps/plugin-shell** - Shell integration (desktop only)
- **@sveltejs/adapter-static** - Static SPA output for both Tauri and web

## Relationship to catbird-mls

- **Catmos Desktop**: depends on `catbird-mls` directly as a Rust path dep (`src-tauri/Cargo.toml` → `../../catbird-mls`). The orchestrator + MLSContext are linked into the Tauri binary; no UniFFI.
- **Catmos Web**: does *not* depend on `catbird-mls` directly. The WASM work lives in the sibling `catbird-mls-web` crate, which owns its own `wasm_bindgen` surface and its own adapted storage/network layers. catmos only consumes the generated `pkg/` artifacts.
- **Catbird iOS**: bridges to `catbird-mls` via UniFFI Swift bindings (outside catmos's scope).

## Known Issues

- SQLCipher requires `PRAGMA key` after opening connection (StorageFailed panic if missing)
- Stores still import from `$lib/tauri` — migration to `$lib/wasm` pending

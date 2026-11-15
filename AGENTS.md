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
cd ../catbird-mls-web && ./build.sh        # or: npm run build:wasm

# Build WASM package (dev mode, faster, debug symbols)
cd ../catbird-mls-web && ./build-dev.sh    # or: npm run build:wasm:dev

# Run the SvelteKit frontend pointing at the WASM backend
cd catmos && npm run dev

# Frontend unit tests (Node test runner over tests/*.spec.ts)
cd catmos && npm test
```

Build output lives in `catbird-mls-web/pkg/` (gitignored). catmos resolves `import … from 'catbird-mls-web'` through the `resolve.alias` in `vite.config.ts` (bundling) and the `paths` entry in `tsconfig.json` (type-checking), both pointing at that `pkg/` directory. There is no hand-declared `.d.ts` shim — the wasm-pack-generated `catbird_mls_web.d.ts` is the single source of truth for the WASM contract. The current unsealed Task 4 R4 candidate consumes `pkg/` cut as `catbird-mls-web` revision `7f300356f6f9ebb794f5cb4ed52293029ad52bac` (WASM SHA-256 `81d2455449b8d12e8284c56715312c41dbc737a8d0eec2aa0504c91dd3092f55`), rebuilt from exact `catbird-mls` revision `085e8a7435c2b1c61189040e626b680f7572559f` (R4 signed Space denial) with `catbird-atproto` `49c6fdb00671ffe96e58e3b5ebec7d5e6532f51f` and `labyrinth` `f771b9c26558ce6a39ed87c657dc8bd6e331d94a`; rebuild `pkg/` and rerun `npm run check` after any source change. This is not a published or release-qualified artifact.

The SvelteKit frontend auto-detects Tauri vs browser at runtime via `$lib/wasm.ts`.

## Architecture

### Desktop Rust Backend (`src-tauri/`)

```
src-tauri/src/
├── main.rs              # Tauri app entry point
├── lib.rs               # IPC command registration; MLSOrchestrator wiring
├── commands.rs          # IPC commands (create_group, send_message, etc.)
├── mls.rs               # Clean-slate CatbirdMlsClient + Labyrinth 1.1 manager (TauriTransport, TauriKeyStore, ctl #2 opt-in gate)
├── mls_proxy.rs         # atproto-proxy header value (ATPROTO_PROXY_HEADER / ATPROTO_PROXY_DID, default did:web:chat.catbird.blue#atproto_mls)
├── storage.rs           # SQLCipher local storage
├── credentials.rs       # AT Protocol credential management
├── keychain.rs          # OS keychain integration
├── native_keyring.rs    # Maintained keyring backends (pre-upgrade identifiers)
├── keys.rs              # Per-DID content-root keys for field-level encryption
├── api_client.rs        # AT Protocol API client
├── websocket.rs         # Real-time message delivery
├── quarantine_observer.rs # MLS quarantine event observer
├── recovery.rs          # Shared recovery categories (transport ↔ UI)
└── session_restore.rs   # Session-restore failure classification
```

### Web WASM Backend (`../catbird-mls-web/`)

Single-crate WASM wrapper exposing `#[wasm_bindgen]` entry points directly, compiled to WebAssembly via wasm-pack. catmos consumes the generated `pkg/` output through the Vite `resolve.alias` in `vite.config.ts` (bundling) and the `paths` entry in `tsconfig.json` (type-checking); no hand-declared shim is needed.

Storage model is one encrypted SQLite database (`sqlite-wasm-rs` with `sqlite3mc`, on the OPFS SyncAccessHandle-pool VFS), shared across credentials, conversation state, and MLS group state — there's no separate IndexedDB layer.

| Feature | Desktop (Tauri) | Web (catbird-mls-web) |
|---------|----------------|------------------------|
| Client construction | `MLSOrchestrator` (`lib.rs`) plus `CatbirdMlsClient` per account (`mls.rs`) | `catbird_mls_init({ baseUrl, storagePrefix?, dbPrefix? })`, or `WasmMlsClient` for the clean-slate client |
| Auth | `keyring` → OS keychain | `catbird_mls_set_auth(did, token)` → localStorage |
| Storage | SQLCipher via `rusqlite` | OPFS SQLite (`sqlite-wasm-rs` + `sqlite3mc`) |
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

WASM types come from `../catbird-mls-web/pkg/catbird_mls_web.d.ts` via the `paths` entry in `tsconfig.json`.

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
- **catbird_mls** - Shared MLS core (path dependency: `../../catbird-mls`); `mls.rs` wraps its `CatbirdMlsClient`
- **catbird-atproto** - Generated AT Protocol / Catbird lexicon types (path dependency: `../../catbird-atproto`)
- **rusqlite** with `bundled-sqlcipher` - Encrypted local storage
- **keyring-core** (as `keyring`) - OS-native credential storage
- **tokio-tungstenite** - WebSocket for real-time delivery

### Rust (Web — `../catbird-mls-web/`)

Lives in its own sibling repo. catmos does not take a Rust dependency on it — it consumes the wasm-pack-generated JS/TS artifacts at `../catbird-mls-web/pkg/`.

Notable crate-level pieces (see catbird-mls-web's own AGENTS.md for detail):
- **wasm-bindgen** / **js-sys** / **web-sys** — WASM ↔ JS interop
- **sqlite-wasm-rs** (`sqlite3mc`) on the OPFS SyncAccessHandle-pool VFS — unified encrypted storage (credentials + conversation state + MLS groups in one DB)
- **reqwest** (default-features off) — HTTP via browser fetch
- **console-error-panic-hook** — better panic messages in the browser console

### Frontend
- **SvelteKit** + Svelte 5 - UI framework
- **@tauri-apps/api** - Tauri IPC bridge (lazy-loaded, desktop only)
- **@tauri-apps/plugin-shell** - Shell integration (desktop only)
- **@sveltejs/adapter-static** - Static SPA output for both Tauri and web

## Relationship to catbird-mls

- **Catmos Desktop**: depends on `catbird-mls` directly as a Rust path dep (`src-tauri/Cargo.toml` → `../../y9b-catbird-mls`). The unified `CatbirdMlsClient` is linked into the Tauri binary; no UniFFI.
- **Catmos Web**: does *not* depend on `catbird-mls` directly. The WASM work lives in the sibling `catbird-mls-web` crate, which owns its own `wasm_bindgen` surface and its own adapted storage/network layers. catmos only consumes the generated `pkg/` artifacts.
- **Catbird iOS**: bridges to `catbird-mls` via UniFFI Swift bindings (outside catmos's scope).

## Labyrinth and Spaces gate

- MLS chat is default-off per account (`ctl #2`). The frontend records the opt-in with `isMlsOptedInForDid` / `setMlsOptedInForDid` (`src/lib/labyrinth-ui.ts`); the desktop gate is `<data_dir>/mls-opt-in/<sha256(normalized_did)>.enabled` (`src-tauri/src/mls.rs`), and before opt-in a desktop sign-in opens no MLS database, uploads no KeyPackages and probes no PDS/DS endpoint.
- `REQUIRED_LABYRINTH_OAUTH_SCOPES` in `src/lib/labyrinth-ui.ts` mirrors the 7 allowlisted `nest` + `catbird_mls` Labyrinth/device scopes: `atproto`, `blob:*/*`, `repo:blue.catbird.labyrinth.mailboxKeys`, `repo:blue.catbird.chat.device?action=create`, `repo:blue.catbird.chat.deviceRevocation?action=create`, and the two explicit Labyrinth Space scopes (`space:blue.catbird.labyrinth.mailbox?action=…&manage=delete` including `circleOwnerState` + `readState`, and `space:blue.catbird.labyrinth.conversation?action=…&collection=blue.catbird.labyrinth.mek` including `authorRedaction`; exact strings in the file).
- `evaluateSpacesGateForUi(pdsSupportsSpaces, grantedScopes)` returns `missingScopes` and a user message. A session granted only the retired `space:blue.catbird.labyrinth.mailbox?manage=create&manage=delete` and `space:blue.catbird.labyrinth.conversation?authority=*` forms reports both Space scopes missing and must re-authorize; `tests/labyrinth-ui.spec.ts` pins this. Change the strings only together with `catbird-mls`, CatbirdMLSCore, Android and nest.

## Known Issues

- SQLCipher requires `PRAGMA key` after opening connection (StorageFailed panic if missing)
- Stores still import from `$lib/tauri` — migration to `$lib/wasm` pending

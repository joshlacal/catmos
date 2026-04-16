# Catmos Compatibility Report (2026-02-16)

## Scope
- Validate Catmos against current local changes in:
  - `/Users/joshlacalamito/Developer/Catbird+Petrel/catbird-mls`
  - `/Users/joshlacalamito/Developer/Catbird+Petrel/mls-ds`
- Build, test, capture logs, and track integration issues.

## Log Sets
- Initial run logs: `/Users/joshlacalamito/Developer/Catbird+Petrel/catmos/docs/compat-runs/20260216-103344`
- Post-fix run logs: `/Users/joshlacalamito/Developer/Catbird+Petrel/catmos/docs/compat-runs/20260216-104007-post-fixes`
- mlsChat v2 remap logs: `/Users/joshlacalamito/Developer/Catbird+Petrel/catmos/docs/compat-runs/20260216-112506-mlschat-v2-remap`
- atproto-proxy header wiring logs: `/Users/joshlacalamito/Developer/Catbird+Petrel/catmos/docs/compat-runs/20260217-083222-atproto-proxy-header`
- atproto-proxy validation logs: `/Users/joshlacalamito/Developer/Catbird+Petrel/catmos/docs/compat-runs/20260217-083343-atproto-proxy-validation`

## Command Summary
- `catmos`:
  - `npm run check`: pass
  - `npm run build`: pass
  - `cargo check` (`src-tauri`): pass
  - `cargo build` (`src-tauri`): pass
  - `cargo test` (`src-tauri`): pass (0 tests)
  - Latest revalidation (2026-02-17): pass (`cargo check`, `cargo test`, `npm run check`, `npm run build`)
- `catbird-mls`:
  - `cargo check`: pass
  - `cargo test`: pass
- `mls-ds/server`:
  - `cargo check`: pass
  - `cargo test`: fail
  - `SQLX_OFFLINE=true cargo test`: fail

## Issue Tracker

### CATMOS-INT-001 (Fixed)
- Title: Catmos reaction/read endpoints drifted from mls-ds v2 routes.
- Symptom:
  - Catmos called `blue.catbird.mlsChat.addReaction`
  - Catmos called `blue.catbird.mlsChat.removeReaction`
  - Catmos called `blue.catbird.mlsChat.updateRead`
  - Current mls-ds routes consolidate these into `sendMessage` (ephemeral actions) and `updateCursor`.
- Fix:
  - Updated `/Users/joshlacalamito/Developer/Catbird+Petrel/catmos/src-tauri/src/commands.rs`:
    - `send_reaction()` now calls `blue.catbird.mlsChat.sendMessage` with ephemeral reaction payload.
    - `mark_as_read()` now calls `blue.catbird.mlsChat.updateCursor` with `markRead`.
- Verification:
  - Explicit Catmos XRPC calls now match mls-ds known routes:
    - `blue.catbird.mlsChat.getSubscriptionTicket`
    - `blue.catbird.mlsChat.sendMessage`
    - `blue.catbird.mlsChat.updateCursor`
  - Missing explicit endpoints after patch: 0.

### CATMOS-INT-002 (Fixed)
- Title: Catmos API client still used pre-consolidation `mlsChat` methods, causing 501 MethodNotImplemented responses.
- Symptom:
  - Runtime error: `ServerError { status: 501, body: "{\"error\":\"MethodNotImplemented\",\"message\":\"Method Not Implemented\"}" }`.
  - API client called old methods that are not routed by current mls-ds v2:
    - `getWelcome`, `getGroupInfo`, `addMembers`, `processExternalCommit`, `publishKeyPackage`, `getKeyPackageStats`, `getOptInStatus`, `deleteDevice`, `removeMember`.
- Fix:
  - Updated `/Users/joshlacalamito/Developer/Catbird+Petrel/catmos/src-tauri/src/api_client.rs` to use consolidated v2 endpoints/actions:
    - `optIn` (`action: getStatus/optIn`)
    - `commitGroupChange` (`addMembers`, `externalCommit`, `updateGroupInfo`)
    - `getGroupState` (`groupInfo`, `welcome`)
    - `publishKeyPackages` (`action: publish`)
    - `getKeyPackageStatus` (`include=stats`)
    - `registerDevice` (`action: delete`)
    - `leaveConvo` with `targetDid` (for member removal)
- Verification:
  - Catmos compiles/tests after remap:
    - `/Users/joshlacalamito/Developer/Catbird+Petrel/catmos/docs/compat-runs/20260216-112506-mlschat-v2-remap/catmos-cargo-check-after-remove-members-remap.log`
    - `/Users/joshlacalamito/Developer/Catbird+Petrel/catmos/docs/compat-runs/20260216-112506-mlschat-v2-remap/catmos-cargo-test-after-remove-members-remap.log`
    - `/Users/joshlacalamito/Developer/Catbird+Petrel/catmos/docs/compat-runs/20260216-112506-mlschat-v2-remap/catmos-npm-check.log`
    - `/Users/joshlacalamito/Developer/Catbird+Petrel/catmos/docs/compat-runs/20260216-112506-mlschat-v2-remap/catmos-npm-build.log`
  - Audit grep in `api_client.rs` shows no remaining calls to removed endpoints above.

### CATMOS-INT-003 (Fixed)
- Title: Catmos MLS calls were not explicitly setting `atproto-proxy` for mlsChat DID routing.
- Symptom:
  - Required proxy target is `did:web:mlschat.catbird.blue#atproto_mls`.
  - Catmos did not set `atproto-proxy` on MLS direct request callsites.
- Fix:
  - Added `/Users/joshlacalamito/Developer/Catbird+Petrel/catmos/src-tauri/src/mls_proxy.rs`:
    - Default header target: `did:web:mlschat.catbird.blue#atproto_mls`.
    - Env override support: `ATPROTO_PROXY_HEADER` then `ATPROTO_PROXY_DID`.
    - Shared helpers for per-request and default-client header injection.
  - Updated `/Users/joshlacalamito/Developer/Catbird+Petrel/catmos/src-tauri/src/api_client.rs`:
    - `ReqwestApiClient::new()` now sets default headers via `mls_default_headers()`.
  - Updated `/Users/joshlacalamito/Developer/Catbird+Petrel/catmos/src-tauri/src/commands.rs`:
    - MLS direct calls (`sendMessage`, `updateCursor`, `getOptInStatus`, `promoteAdmin`, `demoteAdmin`) now use `with_mls_proxy_header(...)`.
  - Updated `/Users/joshlacalamito/Developer/Catbird+Petrel/catmos/src-tauri/src/websocket.rs`:
    - `getSubscriptionTicket` request now uses `with_mls_proxy_header(...)`.
- Verification:
  - Compile check after wiring:
    - `/Users/joshlacalamito/Developer/Catbird+Petrel/catmos/docs/compat-runs/20260217-083222-atproto-proxy-header/catmos-cargo-check.log`
  - Full Catmos revalidation pass:
    - `/Users/joshlacalamito/Developer/Catbird+Petrel/catmos/docs/compat-runs/20260217-083343-atproto-proxy-validation/catmos-cargo-check.log`
    - `/Users/joshlacalamito/Developer/Catbird+Petrel/catmos/docs/compat-runs/20260217-083343-atproto-proxy-validation/catmos-cargo-test.log`
    - `/Users/joshlacalamito/Developer/Catbird+Petrel/catmos/docs/compat-runs/20260217-083343-atproto-proxy-validation/catmos-npm-check.log`
    - `/Users/joshlacalamito/Developer/Catbird+Petrel/catmos/docs/compat-runs/20260217-083343-atproto-proxy-validation/catmos-npm-build.log`
- Notes:
  - Non-MLS calls intentionally remain unchanged (`/auth/session`, `public.api.bsky.app`).

### MLSDS-TEST-001 (Open)
- Title: mls-ds test suite is out of sync with server API/type changes.
- Symptom:
  - `SQLX_OFFLINE=true cargo test` fails in test targets (`stress`, `race_conditions`, `db_tests`) due stale callsites and model assumptions.
- Evidence:
  - `/Users/joshlacalamito/Developer/Catbird+Petrel/catmos/docs/compat-runs/20260216-104007-post-fixes/mls-ds_server_sqlx_offline_cargo_test.log`
- Key failures:
  - `ActorRegistry::new` now needs 3 args (tests still pass 1).
  - `ConvoMessage::SendMessage` now requires additional fields.
  - `db` helper signatures changed (`create_message`, `list_messages`, `list_messages_since*`).
  - `Conversation.title` references in tests no longer match model.

### MLSDS-ENV-001 (Open)
- Title: online `mls-ds` tests require a working DB auth context.
- Symptom:
  - `cargo test` (without `SQLX_OFFLINE=true`) fails during SQLx macro expansion with:
    - `password authentication failed for user "catbird"`
- Evidence:
  - `/Users/joshlacalamito/Developer/Catbird+Petrel/catmos/docs/compat-runs/20260216-103344/mls-ds_server_cargo_test.log`
- Notes:
  - This can mask code-level test errors; offline mode reveals true compile/test drift.

### MLSDS-TEST-002 (Fixed)
- Title: `send_ephemeral` handler unit test deserialization lifetime mismatch.
- Symptom:
  - `SendEphemeral<'_>` deserialization from `serde_json::Value` failed with non-general `Deserialize` lifetime.
- Fix:
  - Updated `/Users/joshlacalamito/Developer/Catbird+Petrel/mls-ds/server/src/handlers/mls_chat/send_ephemeral.rs` test to deserialize from JSON string (`from_str`) into `SendEphemeral<'_>`.
- Verification:
  - Previous lifetime error no longer appears in offline test run logs.

## Warnings Observed
- Catmos:
  - Svelte a11y warnings in:
    - `/Users/joshlacalamito/Developer/Catbird+Petrel/catmos/src/lib/components/Sidebar.svelte`
    - `/Users/joshlacalamito/Developer/Catbird+Petrel/catmos/src/lib/components/MemberList.svelte`
  - Rust warns heavily (`dead_code` and generated lexicon unused symbols), but no compile failures.

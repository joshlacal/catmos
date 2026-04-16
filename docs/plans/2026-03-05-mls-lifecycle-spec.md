# MLS Lifecycle Flow Specification

## Problem Statement

The WASM client (`catbird-mls-web`) reimplements MLS lifecycle logic ad-hoc instead
of using the shared `catbird-mls` orchestrator. The orchestrator has the correct,
complete lifecycle but is excluded from WASM builds via `#[cfg(not(target_arch = "wasm32"))]`.

This causes:
- Key packages never refilled → Welcome joins always fail
- GroupInfo never published → External Commit joins fail for other clients
- No sync loop → stale epoch state
- Self-echo dedup is fragile
- Different behavior between iOS, desktop, and web

## Canonical MLS Lifecycle (What Should Happen Everywhere)

### Phase 1: Device Bootstrap (once per device)

```
1. Generate device UUID
2. Create initial key package (Ed25519 signing key + credential)
3. Register device with server (POST publishKeyPackages action:"publish")
4. Store credentials (MLS DID, device UUID, signing key ref)
5. Upload batch of key packages (target: 20-50)
```

**Who does this correctly:** iOS (MLSKeyPackageManager), Orchestrator (devices.rs)
**WASM gap:** Does steps 1-5 in setup(), but only uploads 10 KPs, never refills

### Phase 2: Key Package Management (ongoing)

```
On every app launch / session start:
  1. Check server inventory: GET getKeyPackageStatus
  2. If available < threshold (10): generate + upload to target (50)

After every send_message:
  1. Check if KP consumption warrants refill
  2. If so, async refill

Periodically (every 4 hours or on push notification):
  1. Smart refresh: check inventory, refill if needed
  2. Sync hashes: clean up expired/orphaned packages
```

**Who does this correctly:** iOS (smartRefreshKeyPackages, background refresh)
**WASM gap:** Never checks inventory after setup. KPs deplete and are never refilled.

### Phase 3: Group Creation

```
1. Ensure local key packages available (replenish if empty)
2. Create MLS group locally (FFI → OpenMLS)
3. Store conversation record (groupIdHex as canonical ID)
4. If initial members:
   a. Fetch their key packages from server
   b. Add members locally (generates Commit + Welcome)
   c. Track own commit hash (SHA256 for dedup)
   d. Send to server: createConvo(groupId, commit, welcome, members)
   e. Merge pending commit locally
5. Get authoritative epoch from FFI (not server)
6. Export + publish GroupInfo to server ← CRITICAL
7. Track KP consumption, trigger refill if needed
```

**Who does this correctly:** iOS, Orchestrator (groups.rs)
**WASM gap:** Steps 1 (no replenish), 6 (no GroupInfo publish), 7 (no refill)

### Phase 4: Joining a Group

```
Path A — Welcome (preferred, preserves message history):
  1. Receive Welcome bytes (from server or push)
  2. Process Welcome locally (FFI → OpenMLS)
  3. If NoMatchingKeyPackage → fall through to Path B
  4. Store group state, fetch conversation metadata from server

Path B — External Commit (fallback, no history before join epoch):
  1. Fetch GroupInfo from server: GET getGroupState?include=groupInfo
  2. If 404 GroupInfoUnavailable → JOIN FAILS (server has no GroupInfo)
  3. Create external commit locally (FFI → OpenMLS)
  4. Send commit to server: commitGroupChange(action: "externalCommit")
  5. Merge pending commit locally
  6. Export + publish updated GroupInfo ← CRITICAL (enables next joiner)
  7. Can only decrypt messages from this epoch onwards
```

**Who does this correctly:** iOS, Orchestrator (recovery.rs)
**WASM gap:** Step 6 in Path B (never publishes GroupInfo after external commit)

### Phase 5: Sending Messages

```
1. Encode as MLSMessagePayload JSON: {"version":1,"messageType":"text","text":"..."}
2. Pre-send sync: fetch pending messages (catch up on missed commits)
3. Encrypt via MLS (FFI → OpenMLS)
   - If GroupNotFound: run Phase 4 (join), then retry
4. Track own commit hash (SHA256 of ciphertext)
5. Get epoch from FFI (authoritative, not cache)
6. Send to server with epoch + message_id
   - If 409 (epoch mismatch): return error, do NOT auto-rejoin
   - If timeout: track for failover
7. Track message_id as pending (for self-echo dedup)
8. Store locally
```

**Who does this correctly:** Orchestrator (messaging.rs)
**WASM gap:** No pre-send sync, no commit hash tracking, no pending message tracking

### Phase 6: Receiving Messages

```
1. Dedup check: skip if message_id already stored
2. Own-commit check: skip if SHA256(ciphertext) matches own_commits set
3. Decrypt via MLS (FFI → OpenMLS)
   - If GroupNotFound: run Phase 4 (join), then retry
4. Extract sender DID from credential
5. Self-echo check: skip if sender matches self AND message_id in pending set
6. Empty plaintext → commit/control message, update epoch, skip
7. Extract text via MLSMessagePayload::extract_text()
8. Store message locally
```

**Who does this correctly:** Orchestrator (messaging.rs)
**WASM gap:** Steps 1-2 (no dedup), step 5 (sender_did check only, no pending tracking)

### Phase 7: Sync Loop (ongoing)

```
Every N seconds (or on WebSocket event):
  1. Fetch conversations from server
  2. Reconcile: remove stale local groups, add new ones
  3. For each conversation:
     a. If group not found locally: run Phase 4 (join)
     b. If server epoch >> local epoch: mark for rejoin
  4. Fetch new messages for active conversations
  5. Circuit breaker: pause on 5+ consecutive failures
```

**Who does this correctly:** Orchestrator (sync.rs)
**WASM gap:** No sync loop at all

## Root Cause: Why the Orchestrator is Excluded from WASM

The orchestrator uses:
- `tokio::sync::Mutex` (requires `Send`)
- `Arc<dyn Trait + Send + Sync>` bounds
- `#[async_trait]` (default: requires `Send`)

WASM is single-threaded — there's no `Send`/`Sync` requirement, but the trait
bounds prevent compilation.

## Proposed Fix: Make Orchestrator WASM-Compatible

### Option A: Conditional compilation on trait bounds (Recommended)

```rust
// In orchestrator traits:
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait MLSStorageBackend { ... }

// In orchestrator struct:
#[cfg(not(target_arch = "wasm32"))]
type SharedMutex<T> = tokio::sync::Mutex<T>;
#[cfg(target_arch = "wasm32")]
type SharedMutex<T> = std::cell::RefCell<T>; // or futures::lock::Mutex

// Remove Send + Sync + 'static bounds for WASM
```

**Pros:** One codebase, consistent behavior across all targets
**Cons:** cfg attrs everywhere, some complexity

### Option B: Feature-gated orchestrator facade for WASM

Create a thin WASM wrapper that calls the same orchestrator logic but with
`?Send` traits:

```rust
// catbird-mls/src/orchestrator/wasm_facade.rs
// Wraps orchestrator methods with WASM-compatible async_trait(?Send)
```

**Pros:** Cleaner separation
**Cons:** Still need to make core logic Send-agnostic

### Option C: Keep WASM separate, but call orchestrator functions

Extract the pure logic (no async, no mutexes) into free functions that both the
orchestrator and WASM client can call. The orchestrator wraps them with
tokio::Mutex; WASM wraps them with RefCell.

**Pros:** Maximum code reuse without trait bound changes
**Cons:** Large refactor to extract pure functions

## Recommended Approach: Option A

1. Replace `#[cfg(not(target_arch = "wasm32"))]` gates with conditional trait bounds
2. Use `#[cfg_attr(...)]` for `async_trait(?Send)` vs `async_trait`
3. Use a `SharedMutex<T>` type alias that maps to `tokio::Mutex` on native and
   `RefCell<T>` (or `Rc<RefCell<T>>`) on WASM
4. Remove `Send + Sync + 'static` bounds from trait generics for WASM
5. Have `catbird-mls-web` use `MLSOrchestrator` directly instead of reimplementing

## Migration Plan

### Step 1: Make traits WASM-compatible
- Add `#[cfg_attr]` to `MLSStorageBackend`, `MLSAPIClient`, `CredentialStore`
- Remove `Send + Sync` bounds conditionally

### Step 2: Make MLSOrchestrator WASM-compatible
- Replace `tokio::sync::Mutex` with `SharedMutex<T>` type alias
- Replace `Arc<dyn Trait>` with `Rc<dyn Trait>` on WASM
- Gate `tokio`-specific code (multi-thread runtime, spawn)

### Step 3: Remove `#[cfg(not(wasm32))]` gates from orchestrator modules
- Expose all modules for all targets
- Fix any remaining compilation issues

### Step 4: Rewrite catbird-mls-web to use MLSOrchestrator
- Replace ad-hoc `try_join_group_internal` with orchestrator's `join_or_rejoin`
- Replace ad-hoc `send_message` with orchestrator's `send_message`
- Replace ad-hoc `fetch_new_messages` with orchestrator's `fetch_messages`
- Add `replenish_if_needed()` to init flow
- GroupInfo auto-published after commits (built into orchestrator)

### Step 5: Delete dead code
- Remove `catmos/catmos-web/` crate (unused, user approved)
- Remove ad-hoc implementations from `catbird-mls-web/src/lib.rs`

## Immediate Fixes (Before Full Migration)

While the full migration is in progress, these fixes will unblock the current flow:

1. **Publish GroupInfo after external commit** in `try_join_group_internal()`
2. **Refill key packages** in `catbird_mls_setup()` and after sends
3. **Call getKeyPackageStatus** on init to check inventory

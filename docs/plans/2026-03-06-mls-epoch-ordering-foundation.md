# MLS Epoch, Ordering & Integrity Foundation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix the entire MLS epoch tracking, message ordering, and group persistence stack across server, Rust orchestrator, and iOS client — no bandaids.

**Architecture:** Bottom-up: fix the server's epoch CAS first (source of truth), then fix the orchestrator's epoch persistence and message sequence propagation (shared by all clients), then fix iOS-specific ordering bugs. Each layer depends on the one below it.

**Tech Stack:** Rust (catbird-mls orchestrator, mls-ds server), Swift (CatbirdMLSCore, Catbird iOS), PostgreSQL, GRDB, OpenMLS

---

## Context for Implementers

### The Problem

Six interconnected bugs cause epoch inflation, message misordering, and unnecessary external commits:

1. **Server: No CAS on epoch advancement** — Concurrent commits both succeed, double-advancing the epoch. A CAS function (`try_advance_conversation_epoch_tx`) exists in `db.rs` but is only used in federation handlers, not client-facing ones.

2. **Server: Messages stored with client epoch, not validated** — `send_message.rs` logs a warning on epoch mismatch but stores the client's (potentially stale) epoch anyway, corrupting ordering.

3. **Orchestrator: `send_message_with_id` returns `()`, discards server seq** — The server returns `{ seq, epoch }` in `SendMessageOutput` but the API client trait returns `Result<()>`. Sent messages are stored locally with `sequence_number: 0`.

4. **Orchestrator: Epoch not persisted after merges** — `add_members`, `remove_members`, `process_incoming` (commit handling), and `join_or_rejoin` (Welcome path) all update in-memory `group_states` but never call `storage().set_group_state()`. On restart, epochs revert to stale values.

5. **Orchestrator: `join_or_rejoin` Welcome path doesn't insert GroupState** — It only calls `states.get_mut(convo_id)` which returns `None` for new groups, silently dropping the epoch update.

6. **iOS: Sent messages sort wrong** — Messages stored with seq=0 sort to the beginning of their epoch. The (epoch, seq) comparator in `MLSConversationDataSource` puts them before all other messages in that epoch.

### File Map

| File | Role |
|------|------|
| `mls-ds/server/src/handlers/mls_chat/commit_group_change.rs` | Server epoch advancement (addMembers, externalCommit) |
| `mls-ds/server/src/handlers/mls_chat/send_message.rs` | Server message storage with epoch |
| `mls-ds/server/src/db.rs:192-215` | `try_advance_conversation_epoch_tx` (CAS function) |
| `catbird-mls/src/orchestrator/api_client.rs:81-90` | `send_message_with_id` trait (returns `()`) |
| `catbird-mls/src/orchestrator/messaging.rs:92-224` | `send_message` + `process_incoming` |
| `catbird-mls/src/orchestrator/groups.rs:319-470` | `add_members` + `remove_members` |
| `catbird-mls/src/orchestrator/recovery.rs:420-535` | `join_or_rejoin` Welcome path |
| `catbird-mls/src/orchestrator/storage.rs:100` | `set_group_state` trait method |
| `CatbirdMLSCore/.../MLSConversationManager+Messaging.swift` | iOS epoch tracking |
| `Catbird/.../MLSConversationDataSource.swift:546-600` | iOS message sorting |
| `Catbird/.../MLSConversationDetailViewModel.swift:42-53` | iOS displayMessages |

---

## Task 1: Server — CAS Epoch Advancement in commit_group_change

**Why first:** The server is the source of truth. Without CAS, concurrent commits corrupt the epoch for everyone.

**Files:**
- Modify: `mls-ds/server/src/handlers/mls_chat/commit_group_change.rs:184-194` (addMembers epoch advance)
- Modify: `mls-ds/server/src/handlers/mls_chat/commit_group_change.rs:360-370` (externalCommit epoch advance)
- Reference: `mls-ds/server/src/db.rs:192-215` (existing CAS function)
- Test: `mls-ds/server/tests/` (new integration test)

**Step 1: Write a failing test for CAS epoch advancement**

Create `mls-ds/server/tests/epoch_cas_test.rs` (or add to existing test file):

```rust
// Test that concurrent epoch advances result in one success and one conflict
#[tokio::test]
async fn test_concurrent_epoch_advance_cas() {
    // Setup: create a conversation with epoch=5
    // Action: two concurrent try_advance_conversation_epoch_tx calls with expected_epoch=5
    // Assert: exactly one returns Some(6), the other returns None
}
```

**Step 2: Run test to verify it fails**

Run: `cd mls-ds/server && cargo test test_concurrent_epoch_advance_cas -- --nocapture`
Expected: FAIL (test doesn't exist yet or assertion fails)

**Step 3: Replace unconditional epoch increment with CAS in addMembers**

In `commit_group_change.rs`, replace lines 184-194:

```rust
// BEFORE (broken):
let new_epoch: i32 = sqlx::query_scalar(
    "UPDATE conversations SET current_epoch = current_epoch + 1, updated_at = NOW() WHERE id = $1 RETURNING current_epoch",
)
.bind(&convo_id)
.fetch_one(&pool)
.await
.map_err(|e| {
    error!("addMembers: failed to advance epoch: {}", e);
    StatusCode::INTERNAL_SERVER_ERROR
})?;
```

WITH a transactional CAS approach:

```rust
// Fetch current epoch
let current_epoch: i32 = sqlx::query_scalar(
    "SELECT current_epoch FROM conversations WHERE id = $1",
)
.bind(&convo_id)
.fetch_one(&pool)
.await
.map_err(|e| {
    error!("addMembers: failed to fetch epoch: {}", e);
    StatusCode::INTERNAL_SERVER_ERROR
})?;

// CAS: only advance if epoch hasn't changed
let mut tx = pool.begin().await.map_err(|e| {
    error!("addMembers: failed to begin tx: {}", e);
    StatusCode::INTERNAL_SERVER_ERROR
})?;

let new_epoch = crate::db::try_advance_conversation_epoch_tx(&mut tx, &convo_id, current_epoch)
    .await
    .map_err(|e| {
        error!("addMembers: CAS epoch advance failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

let new_epoch = match new_epoch {
    Some(epoch) => epoch,
    None => {
        tx.rollback().await.ok();
        warn!("addMembers: epoch conflict (CAS failed), client should retry");
        return Err(StatusCode::CONFLICT);
    }
};

// Move all subsequent inserts (commit message, welcome, idempotency) into the same tx
// ... (use &mut *tx instead of &pool for all queries until tx.commit())

tx.commit().await.map_err(|e| {
    error!("addMembers: commit failed: {}", e);
    StatusCode::INTERNAL_SERVER_ERROR
})?;
```

**Step 4: Apply same CAS pattern to externalCommit**

Replace lines 360-370 in the `"externalCommit"` branch with the same CAS pattern. Return 409 CONFLICT on CAS failure.

**Step 5: Run tests**

Run: `cd mls-ds/server && cargo test -- --nocapture`
Expected: All tests PASS

**Step 6: Commit**

```bash
cd mls-ds/server
git add src/handlers/mls_chat/commit_group_change.rs tests/
git commit -m "mls-ds: use CAS for epoch advancement in addMembers and externalCommit

Replaces unconditional epoch increment with try_advance_conversation_epoch_tx.
Returns 409 CONFLICT when concurrent commits race, preventing double epoch advance."
```

---

## Task 2: Server — Validate Message Epoch on Send

**Why:** Messages stored with stale/future epochs corrupt the ordering for all clients.

**Files:**
- Modify: `mls-ds/server/src/handlers/mls_chat/send_message.rs:214-224`

**Step 1: Write failing test**

Test that a message with epoch != server epoch is stored with the *server's* epoch (not the client's stale value).

**Step 2: Replace warn-and-accept with server epoch override**

In `send_message.rs`, replace lines 214-224:

```rust
// BEFORE: logs warning, stores client_epoch
let client_epoch = input.epoch;
if client_epoch != server_epoch {
    tracing::warn!(...);
}
// line 310: .bind(client_epoch)  // stores stale value
```

WITH:

```rust
let client_epoch = input.epoch;
let store_epoch = if client_epoch != server_epoch {
    tracing::warn!(
        target: "mls_epoch",
        convo_id = %crate::crypto::redact_for_log(&convo_id),
        server_epoch, client_epoch,
        "overriding client epoch with server epoch (client={}, server={})",
        client_epoch, server_epoch
    );
    server_epoch
} else {
    client_epoch
};
```

Then on line 310, change `.bind(client_epoch)` to `.bind(store_epoch)`.

Also update the response to return `store_epoch`:

```rust
// In SendMessageOutput, use store_epoch instead of client_epoch
epoch: store_epoch,
```

**Step 3: Run tests**

Run: `cd mls-ds/server && cargo test -- --nocapture`
Expected: PASS

**Step 4: Commit**

```bash
cd mls-ds/server
git add src/handlers/mls_chat/send_message.rs
git commit -m "mls-ds: override client epoch with server epoch on send_message

Messages are now always stored with the server's authoritative epoch.
Stale client epochs are logged but corrected server-side."
```

---

## Task 3: Orchestrator — Return SendMessageResponse from API Client

**Why:** The orchestrator needs the server's `seq` and `epoch` to store messages correctly. Currently `send_message_with_id` returns `()`.

**Files:**
- Create: `catbird-mls/src/orchestrator/types.rs` (add `SendMessageResponse` struct, or add to existing types)
- Modify: `catbird-mls/src/orchestrator/api_client.rs:75-90` (change return type)
- Modify: `catbird-mls/src/orchestrator/messaging.rs:116-124` (use response)
- Modify: All implementations of `ApiClient` trait (update to return new type)

**Step 1: Add SendMessageResponse type**

In the orchestrator types file (wherever `Message`, `GroupState` etc. are defined):

```rust
/// Response from the delivery service after sending a message.
#[derive(Debug, Clone)]
pub struct SendMessageResponse {
    pub message_id: String,
    pub seq: u64,
    pub epoch: u64,
}
```

**Step 2: Update ApiClient trait**

In `api_client.rs`:

```rust
// BEFORE:
async fn send_message(&self, convo_id: &str, ciphertext: &[u8], epoch: u64) -> Result<()>;
async fn send_message_with_id(...) -> Result<()> { ... }

// AFTER:
async fn send_message(&self, convo_id: &str, ciphertext: &[u8], epoch: u64) -> Result<SendMessageResponse>;
async fn send_message_with_id(
    &self,
    convo_id: &str,
    ciphertext: &[u8],
    epoch: u64,
    msg_id: &str,
) -> Result<SendMessageResponse> {
    let _ = msg_id;
    self.send_message(convo_id, ciphertext, epoch).await
}
```

**Step 3: Update all ApiClient implementations**

Find all `impl ApiClient` blocks and update `send_message` to parse the server's JSON response and return `SendMessageResponse`. The server returns:

```json
{ "message_id": "...", "seq": 42, "epoch": 5, "received_at": "..." }
```

**Step 4: Use response in messaging.rs**

In `messaging.rs`, update the send call (lines 116-124):

```rust
let send_response = self
    .api_client()
    .send_message_with_id(
        conversation_id,
        &encrypt_result.ciphertext,
        epoch,
        &message_id,
    )
    .await;

// ... (existing match on Ok/Err)

// After successful send, use server's seq and epoch:
let mut message = Message {
    id: message_id,
    conversation_id: conversation_id.to_string(),
    sender_did: user_did,
    text: text.to_string(),
    timestamp: Utc::now(),
    epoch: send_response.epoch,           // was: epoch (local, potentially stale)
    sequence_number: send_response.seq,    // was: 0
    is_own: true,
    delivery_status: None,
};
```

**Step 5: Run tests**

Run: `cd catbird-mls && cargo test -- --nocapture`
Expected: PASS (update test mocks to return `SendMessageResponse`)

**Step 6: Commit**

```bash
cd catbird-mls
git add src/orchestrator/api_client.rs src/orchestrator/messaging.rs src/orchestrator/types.rs
git commit -m "orchestrator: propagate server seq/epoch from send_message response

send_message_with_id now returns SendMessageResponse with the server's
authoritative seq and epoch. Sent messages are stored with correct ordering
values instead of sequence_number=0."
```

---

## Task 4: Orchestrator — Persist Epoch After Every Merge

**Why:** Without persistence, epoch reverts to stale values on restart, causing unnecessary external commits and epoch inflation.

**Files:**
- Modify: `catbird-mls/src/orchestrator/groups.rs:387-394` (add_members merge)
- Modify: `catbird-mls/src/orchestrator/groups.rs:448-456` (remove_members merge)
- Modify: `catbird-mls/src/orchestrator/messaging.rs:342-351` (process_incoming commit)
- Modify: `catbird-mls/src/orchestrator/recovery.rs:474-493` (join_or_rejoin Welcome path)

**Step 1: Fix add_members — persist after merge**

In `groups.rs`, after line 394 (after updating in-memory group state), add storage persistence:

```rust
// BEFORE (lines 387-394):
if let Some(gs) = self.group_states().lock().await.get_mut(group_id) {
    gs.epoch = merged_epoch;
    for did in member_dids {
        if !gs.members.contains(did) {
            gs.members.push(did.clone());
        }
    }
}

// AFTER: also persist to storage
{
    let mut states = self.group_states().lock().await;
    if let Some(gs) = states.get_mut(group_id) {
        gs.epoch = merged_epoch;
        for did in member_dids {
            if !gs.members.contains(did) {
                gs.members.push(did.clone());
            }
        }
        let state_clone = gs.clone();
        drop(states);
        if let Err(e) = self.storage().set_group_state(&state_clone).await {
            tracing::warn!(error = %e, group_id, "Failed to persist group state after add_members");
        }
    }
}
```

**Step 2: Fix remove_members — persist after merge**

Same pattern in `groups.rs` lines 453-456:

```rust
{
    let mut states = self.group_states().lock().await;
    if let Some(gs) = states.get_mut(group_id) {
        gs.epoch = merged_epoch;
        gs.members.retain(|m| !member_dids.contains(m));
        let state_clone = gs.clone();
        drop(states);
        if let Err(e) = self.storage().set_group_state(&state_clone).await {
            tracing::warn!(error = %e, group_id, "Failed to persist group state after remove_members");
        }
    }
}
```

**Step 3: Fix process_incoming — persist after commit message**

In `messaging.rs` lines 342-351, after updating the in-memory epoch for commit messages:

```rust
// After: "Still update cached group state epoch"
{
    let mut states = self.group_states().lock().await;
    if let Some(gs) = states.get_mut(&envelope.conversation_id) {
        if decrypt_result.epoch > gs.epoch {
            gs.epoch = decrypt_result.epoch;
            let state_clone = gs.clone();
            drop(states);
            if let Err(e) = self.storage().set_group_state(&state_clone).await {
                tracing::warn!(error = %e, "Failed to persist epoch after commit");
            }
        }
    }
}
```

**Step 4: Fix join_or_rejoin Welcome path — INSERT (not just update) GroupState**

In `recovery.rs` lines 480-486, the code only updates existing entries:

```rust
// BEFORE:
{
    let mut states = self.group_states().lock().await;
    if let Some(gs) = states.get_mut(convo_id) {
        gs.epoch = epoch;
    }
}

// AFTER: insert or update, and persist
{
    let mut states = self.group_states().lock().await;
    let state = states.entry(convo_id.to_string()).or_insert_with(|| GroupState {
        group_id: convo_id.to_string(),
        conversation_id: convo_id.to_string(),
        epoch: 0,
        members: vec![],
    });
    state.epoch = epoch;
    let state_clone = state.clone();
    drop(states);
    if let Err(e) = self.storage().set_group_state(&state_clone).await {
        tracing::warn!(error = %e, convo_id, "Failed to persist group state after Welcome join");
    }
}
```

**Step 5: Run tests**

Run: `cd catbird-mls && cargo test -- --nocapture`
Expected: PASS

**Step 6: Commit**

```bash
cd catbird-mls
git add src/orchestrator/groups.rs src/orchestrator/messaging.rs src/orchestrator/recovery.rs
git commit -m "orchestrator: persist group state after every epoch-advancing operation

Calls storage().set_group_state() after add_members, remove_members,
process_incoming commits, and join_or_rejoin via Welcome. Also fixes
join_or_rejoin to INSERT (not just update) group state for new groups."
```

---

## Task 5: iOS — Fix Sent Message Ordering

**Why:** Even after the orchestrator returns correct seq/epoch, iOS needs to use them properly. The GRDB model and UI sorting need to handle the transition.

**Files:**
- Modify: `CatbirdMLSCore/.../MLSConversationManager+Messaging.swift` (use FFI-returned epoch/seq)
- Modify: `Catbird/.../MLSConversationDetailViewModel.swift:42-53` (fix displayMessages sorting)

**Step 1: Verify the FFI layer propagates seq from SendMessageResponse**

Check that the Swift-side `sendMessage` call receives the server's `seq` and `epoch` after Task 3 changes. The CatbirdMLSCore FFI bridge needs to return these values to the iOS layer.

If the FFI `send_message` currently returns just a message ID, update it to return `(message_id, epoch, seq)`.

**Step 2: Update MLSConversationManager to store correct epoch/seq**

In `MLSConversationManager+Messaging.swift`, after sending a message, ensure the GRDB `MLSMessageModel` is created with the server's `epoch` and `sequenceNumber`, not 0 or the local stale epoch.

```swift
// After FFI send succeeds:
let model = MLSMessageModel(
    messageID: response.messageId,
    conversationID: conversationId,
    senderID: currentUserDID,
    epoch: response.epoch,           // NOT local epoch
    sequenceNumber: response.seq,    // NOT 0
    // ...
)
try await storage.storeMessage(model, database: database)
```

**Step 3: Fix displayMessages sort to handle optimistic messages**

In `MLSConversationDetailViewModel.swift`, ensure optimistic messages (with `Int.max` epoch/seq) sort AFTER all confirmed messages:

```swift
var displayMessages: [DisplayMessage] {
    let optimistic = optimisticMessages.map { DisplayMessage.optimistic($0) }
    let confirmed = messages.map { DisplayMessage.confirmed($0) }
    return (optimistic + confirmed).sorted {
        // Optimistic messages (Int.max) always sort last
        if $0.epoch != $1.epoch {
            return $0.epoch < $1.epoch
        }
        if $0.sequenceNumber != $1.sequenceNumber {
            return $0.sequenceNumber < $1.sequenceNumber
        }
        return $0.sentAt < $1.sentAt
    }
}
```

This should already work correctly since `Int.max > any real epoch`, but verify the optimistic message epoch/seq values are indeed `Int.max`.

**Step 4: Build and test**

Run: `cd Catbird && xcodebuild -project Catbird.xcodeproj -scheme Catbird -destination 'platform=iOS Simulator,name=iPhone 16' build`
Expected: BUILD SUCCEEDED

**Step 5: Commit**

```bash
cd Catbird
git add .
git commit -m "Catbird: use server-assigned epoch/seq for sent messages

Sent messages now store the server's authoritative epoch and sequence
number instead of 0, fixing messages appearing in wrong position."
```

---

## Task 6: iOS — Update GRDB Epoch After Commits

**Why:** `MLSConversationModel.epoch` in GRDB is never updated after commits, causing stale epoch values in the database.

**Files:**
- Modify: `CatbirdMLSCore/.../MLSConversationManager+Messaging.swift:411-471` (epoch update after send)
- Modify: `CatbirdMLSCore/.../MLSConversationManager+Messaging.swift:4573-4620` (updateGroupStateAfterJoin)

**Step 1: Find where GRDB epoch should be updated**

After every commit merge (send, add_members, remove_members, incoming commit), the GRDB `MLSConversationModel.epoch` should be updated. Currently only `joinEpoch` is persisted.

**Step 2: Add epoch update after FFI operations**

After each operation that advances the epoch:

```swift
// After successful send/commit:
let newEpoch = try mlsContext.getEpoch(groupId: groupIdBytes)
try await database.write { db in
    try MLSConversationModel
        .filter(Column("conversationID") == conversationId)
        .updateAll(db, Column("epoch").set(to: newEpoch))
}
```

**Step 3: Build and test**

Run: `cd Catbird && xcodebuild -project Catbird.xcodeproj -scheme Catbird -destination 'platform=iOS Simulator,name=iPhone 16' build`
Expected: BUILD SUCCEEDED

**Step 4: Commit**

```bash
cd CatbirdMLSCore
git add .
git commit -m "CatbirdMLSCore: persist epoch to GRDB after every commit merge

Updates MLSConversationModel.epoch after send, add_members,
remove_members, and incoming commit processing."
```

---

## Task 7: Server — Invalidate GroupInfo Cache on Epoch Advance

**Why:** Stale GroupInfo with old epoch causes external commits to fail or create invalid state.

**Files:**
- Modify: `mls-ds/server/src/handlers/mls_chat/commit_group_change.rs` (clear cached GroupInfo after epoch advance)
- Reference: `mls-ds/server/src/handlers/mls_chat/get_group_state.rs:172-193` (current GroupInfo serving)

**Step 1: After CAS epoch advance succeeds, delete stale GroupInfo**

In the `addMembers` and `externalCommit` branches, after the epoch advances successfully, clear the cached GroupInfo so that the next `getGroupState` call forces clients to upload fresh GroupInfo:

```rust
// After successful epoch advance in addMembers/externalCommit:
sqlx::query("DELETE FROM group_info WHERE convo_id = $1")
    .bind(&convo_id)
    .execute(&mut *tx)  // within the same transaction
    .await
    .map_err(|e| {
        error!("Failed to clear stale GroupInfo: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
```

If GroupInfo is stored in a different table or as a blob, adapt the query accordingly. The key is: after any epoch-advancing commit, the old GroupInfo is invalid and must be purged.

**Step 2: Run tests**

Run: `cd mls-ds/server && cargo test -- --nocapture`
Expected: PASS

**Step 3: Commit**

```bash
cd mls-ds/server
git add src/handlers/mls_chat/commit_group_change.rs
git commit -m "mls-ds: invalidate GroupInfo cache after epoch advance

Deletes stale GroupInfo when epoch advances, preventing external commits
against outdated group state."
```

---

## Dependency Graph

```
Task 1 (Server CAS)  ←──  Task 2 (Server epoch override)  [independent of each other]
        ↓                          ↓
Task 3 (Orchestrator SendMessageResponse)  ←── depends on Task 2 for correct epoch
        ↓
Task 4 (Orchestrator epoch persistence)    [independent of Task 3]
        ↓
Task 5 (iOS sent message ordering)         ←── depends on Task 3
        ↓
Task 6 (iOS GRDB epoch updates)            [independent of Task 5]
Task 7 (Server GroupInfo invalidation)     [independent, can parallel with Task 3+]
```

**Parallel execution opportunities:**
- Tasks 1 + 2 can run in parallel (both server, different files)
- Task 7 can run in parallel with Tasks 3-6 (server, different concern)
- Tasks 4 + 5 can run in parallel after Task 3 (different repos)

---

## Verification Plan

After all tasks complete:

1. **Server:** Deploy to staging, send concurrent addMembers from two clients → only one should succeed (other gets 409)
2. **Orchestrator:** Restart orchestrator, verify `group_states` storage has correct epochs
3. **iOS:** Send a message, verify it appears at the BOTTOM of the conversation (not slotted in the middle)
4. **End-to-end:** Two clients chatting — epochs should advance by exactly 1 per commit, no inflation

## Deploy Order

1. Deploy server changes (Tasks 1, 2, 7) first
2. Build and distribute orchestrator changes (Tasks 3, 4)
3. Build iOS (Tasks 5, 6)
4. All clients will handle 409 CONFLICT gracefully (existing retry logic)

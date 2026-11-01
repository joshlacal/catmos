#![allow(dead_code)]

use std::io::Cursor;
use std::sync::Arc;

use base64::Engine;
use ciborium::Value as CborValue;
use serde::Deserialize;
use tauri::{AppHandle, Emitter};

use catbird_mls::orchestrator::types::IncomingEnvelope;

use crate::api_client::ReqwestApiClient;
use crate::recovery::{actionable_error, classify_error, RecoveryCategory};
use crate::{commands, CatmosOrchestrator};

macro_rules! log_ws {
    ($($arg:tt)*) => {{
        let msg = format!($($arg)*);
        let ts = chrono::Local::now().format("%H:%M:%S%.3f");
        let line = format!("[catmos {}] [WS] {}\n", ts, msg);
        commands::append_log_line(&line);
    }};
}

/// DAG-CBOR WebSocket frame header (matches mls-ds MessageHeader)
#[derive(Debug, Deserialize)]
struct FrameHeader {
    op: i32,
    t: Option<String>,
}

/// Extract a string from a CBOR map
fn cbor_str(map: &[(CborValue, CborValue)], key: &str) -> Option<String> {
    map.iter().find_map(|(k, v)| match (k, v) {
        (CborValue::Text(k), CborValue::Text(v)) if k == key => Some(v.clone()),
        _ => None,
    })
}

/// Extract an integer from a CBOR map
fn cbor_int(map: &[(CborValue, CborValue)], key: &str) -> Option<i64> {
    map.iter().find_map(|(k, v)| match (k, v) {
        (CborValue::Text(k), CborValue::Integer(v)) if k == key => {
            let n: i128 = (*v).into();
            Some(n as i64)
        }
        _ => None,
    })
}

/// Extract a boolean from a CBOR map
fn cbor_bool(map: &[(CborValue, CborValue)], key: &str) -> Option<bool> {
    map.iter().find_map(|(k, v)| match (k, v) {
        (CborValue::Text(k), CborValue::Bool(v)) if k == key => Some(*v),
        _ => None,
    })
}

#[derive(Debug, PartialEq, Eq)]
struct ValidatedGroupReset {
    conversation_id: String,
    new_group_id_hex: String,
    new_group_id: Vec<u8>,
    reset_generation: i32,
}

fn strict_uuid_v4(value: &str) -> bool {
    let Ok(parsed) = uuid::Uuid::parse_str(value) else {
        return false;
    };
    parsed.get_version() == Some(uuid::Version::Random)
        && parsed.get_variant() == uuid::Variant::RFC4122
        && parsed.to_string() == value
}

/// Validate all authority coordinates before the reset event can mutate local
/// lifecycle state. A global (`*`) WebSocket subscription may carry events for
/// any stable UUID, but `*` is never itself accepted as a payload conversation
/// ID. A conversation-scoped subscription requires an exact payload match.
fn validate_group_reset_authority(
    top: &[(CborValue, CborValue)],
    subscribed_conversation_id: &str,
) -> Result<ValidatedGroupReset, String> {
    let conversation_id =
        cbor_str(top, "convoId").ok_or_else(|| "groupResetEvent is missing convoId".to_string())?;
    if !strict_uuid_v4(&conversation_id) {
        return Err(format!(
            "groupResetEvent has invalid canonical convoId: {conversation_id}"
        ));
    }
    if subscribed_conversation_id != "*" && subscribed_conversation_id != conversation_id {
        return Err(format!(
            "groupResetEvent convoId {conversation_id} does not match subscription {subscribed_conversation_id}"
        ));
    }

    let new_group_id_hex = cbor_str(top, "newGroupId")
        .ok_or_else(|| "groupResetEvent is missing newGroupId".to_string())?;
    let new_group_id = hex::decode(&new_group_id_hex)
        .map_err(|_| "groupResetEvent newGroupId is not valid hex".to_string())?;
    if new_group_id.is_empty() || hex::encode(&new_group_id) != new_group_id_hex {
        return Err(
            "groupResetEvent newGroupId must be nonempty canonical lowercase hex".to_string(),
        );
    }

    let reset_generation_raw = cbor_int(top, "resetGeneration")
        .ok_or_else(|| "groupResetEvent is missing resetGeneration".to_string())?;
    let reset_generation = i32::try_from(reset_generation_raw)
        .ok()
        .filter(|generation| *generation >= 0)
        .ok_or_else(|| "groupResetEvent resetGeneration is out of range".to_string())?;

    Ok(ValidatedGroupReset {
        conversation_id,
        new_group_id_hex,
        new_group_id,
        reset_generation,
    })
}

/// Extract bytes from a CBOR map.
/// Handles three formats:
/// - CBOR byte string (major type 2) — raw bytes
/// - ATProto `{"$bytes": "base64..."}` map — base64-decoded
/// - CBOR array of integers — each int as u8
fn cbor_bytes(map: &[(CborValue, CborValue)], key: &str) -> Option<Vec<u8>> {
    map.iter().find_map(|(k, v)| {
        let CborValue::Text(k) = k else { return None };
        if k != key {
            return None;
        }
        extract_bytes(v)
    })
}

/// Extract bytes from a CBOR value regardless of encoding format.
fn extract_bytes(v: &CborValue) -> Option<Vec<u8>> {
    match v {
        CborValue::Bytes(b) => Some(b.clone()),
        // ATProto {"$bytes": "base64..."} format
        CborValue::Map(entries) => cbor_str(entries, "$bytes")
            .and_then(|b64| base64::engine::general_purpose::STANDARD.decode(&b64).ok()),
        CborValue::Array(arr) => arr
            .iter()
            .map(|item| match item {
                CborValue::Integer(i) => {
                    let n: i128 = (*i).into();
                    u8::try_from(n).ok()
                }
                _ => None,
            })
            .collect(),
        _ => None,
    }
}

/// Extract a nested CBOR map from a parent map
fn cbor_map<'a>(
    map: &'a [(CborValue, CborValue)],
    key: &str,
) -> Option<&'a [(CborValue, CborValue)]> {
    map.iter().find_map(|(k, v)| match (k, v) {
        (CborValue::Text(k), CborValue::Map(m)) if k == key => Some(m.as_slice()),
        _ => None,
    })
}

/// Decode a DAG-CBOR WebSocket frame. Returns header and remaining payload bytes.
/// The frame contains two concatenated CBOR items: header + payload.
fn split_frame(data: &[u8]) -> Option<(FrameHeader, &[u8])> {
    let mut cursor = Cursor::new(data);
    let header: FrameHeader = ciborium::from_reader(&mut cursor).ok()?;
    let consumed = cursor.position() as usize;
    Some((header, &data[consumed..]))
}

/// Subscribe to a conversation via WebSocket and process incoming messages.
pub async fn subscribe_conversation(
    app: AppHandle,
    orchestrator: Arc<CatmosOrchestrator>,
    api_client: Arc<ReqwestApiClient>,
    api_base_url: String,
    auth_token: String,
    conversation_id: String,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let convo_id = conversation_id.clone();
    // Load persisted cursor from storage (spec §7.1)
    let mut last_cursor: Option<String> = orchestrator.storage().get_ws_cursor(&convo_id);
    if last_cursor.is_some() {
        log_ws!("Loaded persisted cursor for {}", convo_id);
    }
    let mut attempt = 0u32;

    loop {
        if *shutdown.borrow() {
            log_ws!("Shutdown detected for convo {}", convo_id);
            break;
        }

        attempt += 1;
        log_ws!("Connecting attempt {} for convo {}", attempt, convo_id);

        match do_subscribe(
            &app,
            &orchestrator,
            &api_client,
            &api_base_url,
            &auth_token,
            Some(&convo_id),
            last_cursor.as_deref(),
            &mut shutdown,
        )
        .await
        {
            Ok(cursor) => {
                last_cursor = cursor;
                attempt = 0;
            }
            Err(e) => {
                log_ws!("Error for convo {}: {}", convo_id, e);
                let category = classify_error(&e);
                let _ = app.emit("mls-ws-recovery", actionable_error(&e));
                if category != RecoveryCategory::Retry {
                    log_ws!(
                        "Stopping reconnect loop for convo {} after {} recovery classification",
                        convo_id,
                        category
                    );
                    break;
                }
            }
        }

        if *shutdown.borrow() {
            log_ws!("Shutdown detected after disconnect for convo {}", convo_id);
            break;
        }

        // Exponential backoff: 1s, 2s, 4s, 8s, 16s, max 30s (spec §10)
        let delay = std::cmp::min(1 << attempt.min(5), 30);
        log_ws!("Reconnecting in {}s for convo {}", delay, convo_id);
        tokio::select! {
            _ = tokio::time::sleep(std::time::Duration::from_secs(delay)) => {},
            _ = shutdown.changed() => {
                log_ws!("Shutdown during backoff for convo {}", convo_id);
                break;
            },
        }
    }
}

/// Subscribe globally (across all the user's conversations). Matches the
/// iOS/Android/CLI wiring — omitting convoId gives a single connection that
/// receives every event the server would fan out to this user. The per-convo
/// subscribe_conversation path stayed working for a single selected convo,
/// but any message landing in a convo the user wasn't currently viewing got
/// dropped because no subscription existed for it.
pub async fn subscribe_all(
    app: AppHandle,
    orchestrator: Arc<CatmosOrchestrator>,
    api_client: Arc<ReqwestApiClient>,
    api_base_url: String,
    auth_token: String,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    const GLOBAL_CURSOR_KEY: &str = "__global__";
    let mut last_cursor: Option<String> = orchestrator.storage().get_ws_cursor(GLOBAL_CURSOR_KEY);
    if last_cursor.is_some() {
        log_ws!("Loaded persisted global cursor");
    }
    let mut attempt = 0u32;

    loop {
        if *shutdown.borrow() {
            log_ws!("Shutdown detected (global)");
            break;
        }

        attempt += 1;
        log_ws!("Connecting attempt {} (global)", attempt);

        match do_subscribe(
            &app,
            &orchestrator,
            &api_client,
            &api_base_url,
            &auth_token,
            None,
            last_cursor.as_deref(),
            &mut shutdown,
        )
        .await
        {
            Ok(cursor) => {
                last_cursor = cursor;
                attempt = 0;
            }
            Err(e) => {
                log_ws!("Error (global): {}", e);
                let category = classify_error(&e);
                let _ = app.emit("mls-ws-recovery", actionable_error(&e));
                if category != RecoveryCategory::Retry {
                    log_ws!(
                        "Stopping global reconnect loop after {} recovery classification",
                        category
                    );
                    break;
                }
            }
        }

        if *shutdown.borrow() {
            log_ws!("Shutdown detected after disconnect (global)");
            break;
        }

        let delay = std::cmp::min(1 << attempt.min(5), 30);
        log_ws!("Reconnecting in {}s (global)", delay);
        tokio::select! {
            _ = tokio::time::sleep(std::time::Duration::from_secs(delay)) => {},
            _ = shutdown.changed() => {
                log_ws!("Shutdown during backoff (global)");
                break;
            },
        }
    }
}

/// Single WebSocket connection session. Returns the last cursor on clean disconnect.
/// `convo_id` = Some(id) subscribes to a single conversation; `None` subscribes
/// globally to every event the server fans out to the authenticated user.
#[allow(clippy::too_many_arguments)]
async fn do_subscribe(
    app: &AppHandle,
    orchestrator: &Arc<CatmosOrchestrator>,
    api_client: &Arc<ReqwestApiClient>,
    api_base_url: &str,
    auth_token: &str,
    convo_id: Option<&str>,
    cursor: Option<&str>,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
) -> Result<Option<String>, String> {
    // The old mlsChat ticket endpoint accepted a bearer token and a local
    // conversation identifier. It is not a valid clean-chat subscription
    // authority. The generated canonical ticket also requires an
    // inventory-session capability supplied by the platform admission flow;
    // catmos must not invent one or silently fall back to the legacy route.
    api_client
        .require_canonical_admission()
        .map_err(actionable_error)?;

    let _ = (
        app,
        orchestrator,
        api_base_url,
        auth_token,
        convo_id,
        cursor,
        shutdown,
    );
    // Keep the unsupported path explicit at the function boundary. Once the
    // platform supplies an inventory-session capability, this function will
    // call the generated `blue.catbird.chat.getSubscriptionTicket` route and
    // then connect to its returned endpoint; it must never revive the legacy
    // mlsChat ticket request.
    Err(actionable_error(
        "canonical subscription ticket transport is unavailable until the platform supplies an admitted inventory session",
    ))
}

/// Handle a binary DAG-CBOR WebSocket frame.
async fn handle_binary_frame(
    app: &AppHandle,
    orchestrator: &Arc<CatmosOrchestrator>,
    api_client: &Arc<ReqwestApiClient>,
    data: &[u8],
    convo_id: &str,
) -> Result<Option<String>, String> {
    let (header, payload_bytes) =
        split_frame(data).ok_or_else(|| "Failed to decode DAG-CBOR frame header".to_string())?;

    if header.op == -1 {
        log_ws!("Server error frame for {}", convo_id);
        return Err("Server error frame".to_string());
    }

    let event_type = header.t.as_deref().unwrap_or("");

    match event_type {
        "#messageEvent" => {
            // Decode payload as generic CBOR value to handle atproto_bytes format
            let payload: CborValue = ciborium::from_reader(Cursor::new(payload_bytes))
                .map_err(|e| format!("Failed to decode messageEvent CBOR: {}", e))?;

            let CborValue::Map(ref top) = payload else {
                return Err("messageEvent payload is not a CBOR map".into());
            };

            let cursor = cbor_str(top, "cursor");
            let msg_map =
                cbor_map(top, "message").ok_or("Missing 'message' field in messageEvent")?;

            let id = cbor_str(msg_map, "id").ok_or("Missing message.id")?;
            let msg_convo_id = cbor_str(msg_map, "convoId").ok_or("Missing message.convoId")?;
            let created_at = cbor_str(msg_map, "createdAt").ok_or("Missing message.createdAt")?;
            let epoch = cbor_int(msg_map, "epoch").unwrap_or(0);
            let ciphertext =
                cbor_bytes(msg_map, "ciphertext").ok_or("Missing or invalid message.ciphertext")?;

            // Diagnostic: first 8 bytes + predicted strip_padding decision. A valid
            // MlsMessage starts with `0x00 0x01 0x00 0x0[1-5]` (version 1, wire
            // format Public/Private/Welcome/GroupInfo/KeyPackage). Anything else
            // means this payload was never wrapped as an MlsMessage, and the MLS
            // layer will bail with `SerializationError`. We also predict what
            // `strip_padding` (in catbird-mls/src/api.rs) will do by mirroring
            // its check: claimed_len > 0 && ≤ len-4 && first body byte 0x00..=0x04.
            let head_hex: String = ciphertext
                .iter()
                .take(8)
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(" ");
            let strip_decision: &'static str = if ciphertext.len() >= 5 {
                let claimed_len = u32::from_be_bytes([
                    ciphertext[0],
                    ciphertext[1],
                    ciphertext[2],
                    ciphertext[3],
                ]) as usize;
                if claimed_len > 0
                    && claimed_len <= ciphertext.len().saturating_sub(4)
                    && matches!(ciphertext[4], 0x00..=0x04)
                {
                    "STRIP"
                } else {
                    "PASS"
                }
            } else {
                "TOOSMALL"
            };
            log_ws!(
                "Parsed message {} epoch={} ct_len={} head={} strip={}",
                id,
                epoch,
                ciphertext.len(),
                head_hex,
                strip_decision
            );

            // Build envelope for orchestrator
            let timestamp = created_at.parse().unwrap_or_else(|_| chrono::Utc::now());

            // Keep an owned copy of the message's convoId (the stable
            // conversation_id) for downstream metadata bootstrap. The
            // websocket-handler `convo_id` parameter is the subscription
            // label (group_id-shaped pre-reset; "*" in global mode) and is
            // not safe to use as the storage key after a reset has remapped
            // the conversation to a new group_id.
            let msg_convo_id_owned = msg_convo_id.clone();

            let envelope = IncomingEnvelope {
                // Legacy CBOR frames carry no signed canonical append-log row.
                // Shared verification must obtain canonical proof for controls.
                canonical_entry_json: None,
                conversation_id: msg_convo_id,
                sender_did: String::new(),
                ciphertext,
                timestamp,
                server_message_id: Some(id.clone()),
                server_epoch: None,
                server_sequence: None,
            };

            // Decrypt via orchestrator. `decrypt_message` (task #33) no longer
            // auto-merges incoming commits — it stages them in
            // `pending_incoming_merges` keyed by `(group_id, target_epoch)`.
            // We must explicitly call `merge_incoming_commit` after
            // `process_incoming` so the local MLS group actually advances.
            let process_result = orchestrator.process_incoming(&envelope).await;

            // Merge any staged incoming commit for this (group, epoch). The
            // key in `pending_incoming_merges` is the target (post-merge)
            // epoch, which the server records as `message.epoch`. Returns an
            // error for app messages / dedup / own-echoes (no staged entry);
            // treat that as a no-op.
            let mut commit_did_merge = false;
            if epoch >= 0 {
                if let Ok(gid_bytes) = hex::decode(convo_id) {
                    match orchestrator
                        .mls_context()
                        .merge_incoming_commit(gid_bytes, epoch as u64)
                    {
                        Ok(_) => {
                            commit_did_merge = true;
                        }
                        Err(e) => {
                            log_ws!(
                                "merge_incoming_commit no-op for {} epoch {}: {}",
                                id,
                                epoch,
                                e
                            );
                        }
                    }
                }
            }

            // Encrypted-metadata cutover: any commit can update the
            // `MetadataReference` in AppDataDictionary 0x8001. We don't have
            // a per-commit "metadata changed" signal at this layer, so we
            // opportunistically re-run the bootstrap whenever a merge
            // succeeded. The bootstrap short-circuits when the local cache
            // is already in sync (matching `metadata_version` + locator), so
            // the cost is one cheap SQLite read for unrelated commits.
            if commit_did_merge {
                let stable_convo_id = msg_convo_id_owned.as_str();
                if let Err(e) = commands::bootstrap_group_metadata_for_ws(
                    orchestrator,
                    api_client,
                    convo_id,
                    stable_convo_id,
                )
                .await
                {
                    log_ws!(
                        "bootstrap_group_metadata after merge failed for convo={} (gid={}): {}",
                        stable_convo_id,
                        convo_id,
                        e
                    );
                } else {
                    log_ws!(
                        "bootstrap_group_metadata refreshed for convo={} after merge to epoch {}",
                        stable_convo_id,
                        epoch
                    );
                }
            }

            match process_result {
                Ok(Some(decrypted)) => {
                    if !decrypted.has_displayable_body() {
                        log_ws!(
                            "Skipping non-displayable decrypted payload {} in {}",
                            id,
                            convo_id
                        );
                        return Ok(cursor);
                    }

                    log_ws!("Decrypted message {} in {}", id, convo_id);
                    let ui_msg = commands::ui_message_from_orchestrator(decrypted);
                    let _ = app.emit("mls-incoming-message", &ui_msg);
                    log_ws!("Emitted mls-incoming-message event for {}", id);
                }
                Ok(None) => {
                    log_ws!("Message {} deduplicated/own-echo", id);
                }
                Err(e) => {
                    log_ws!("Decrypt failed for {} in {}: {}", id, convo_id, e);
                }
            }

            Ok(cursor)
        }
        "#membershipChangeEvent" => {
            log_ws!("Membership change event for {}", convo_id);
            let payload: CborValue = ciborium::from_reader(Cursor::new(payload_bytes))
                .map_err(|e| format!("Failed to decode membershipChangeEvent CBOR: {}", e))?;

            let CborValue::Map(ref top) = payload else {
                return Ok(cbor_str_from_cbor(&payload, "cursor"));
            };

            let cursor = cbor_str(top, "cursor");
            let member_did = cbor_str(top, "memberDid").unwrap_or_default();
            let action = cbor_str(top, "action").unwrap_or_else(|| "changed".to_string());

            let content = match action.as_str() {
                "join" | "added" => format!("{} joined the group", short_id(&member_did)),
                "leave" | "left" => format!("{} left the group", short_id(&member_did)),
                "removed" => format!("{} was removed from the group", short_id(&member_did)),
                _ => format!("Membership updated: {}", short_id(&member_did)),
            };

            let ui_msg = commands::Message {
                id: format!("sys-{}", uuid::Uuid::new_v4()),
                conversation_id: convo_id.to_string(),
                sender_did: String::new(),
                sender_handle: String::new(),
                content,
                timestamp: chrono::Utc::now().to_rfc3339(),
                sequence_number: 0,
                status: "delivered".to_string(),
                message_type: "system".to_string(),
                image: None,
            };
            let _ = app.emit("mls-incoming-message", &ui_msg);

            Ok(cursor)
        }
        "#infoEvent" => {
            log_ws!("Info event for {}", convo_id);
            let payload: CborValue = ciborium::from_reader(Cursor::new(payload_bytes))
                .map_err(|e| format!("Failed to decode infoEvent CBOR: {}", e))?;

            let CborValue::Map(ref top) = payload else {
                return Ok(cbor_str_from_cbor(&payload, "cursor"));
            };

            let cursor = cbor_str(top, "cursor");
            let info_text = cbor_str(top, "message")
                .or_else(|| cbor_str(top, "info"))
                .unwrap_or_else(|| "Group info updated".to_string());

            let ui_msg = commands::Message {
                id: format!("sys-{}", uuid::Uuid::new_v4()),
                conversation_id: convo_id.to_string(),
                sender_did: String::new(),
                sender_handle: String::new(),
                content: info_text,
                timestamp: chrono::Utc::now().to_rfc3339(),
                sequence_number: 0,
                status: "delivered".to_string(),
                message_type: "system".to_string(),
                image: None,
            };
            let _ = app.emit("mls-incoming-message", &ui_msg);

            Ok(cursor)
        }
        "#newDeviceEvent" => {
            log_ws!("New device event for {}", convo_id);
            let payload: CborValue = ciborium::from_reader(Cursor::new(payload_bytes))
                .map_err(|e| format!("Failed to decode newDeviceEvent CBOR: {}", e))?;

            let CborValue::Map(ref top) = payload else {
                return Ok(cbor_str_from_cbor(&payload, "cursor"));
            };

            let cursor = cbor_str(top, "cursor");
            let member_did = cbor_str(top, "memberDid").unwrap_or_default();

            let ui_msg = commands::Message {
                id: format!("sys-{}", uuid::Uuid::new_v4()),
                conversation_id: convo_id.to_string(),
                sender_did: String::new(),
                sender_handle: String::new(),
                content: format!("{} added a new device", short_id(&member_did)),
                timestamp: chrono::Utc::now().to_rfc3339(),
                sequence_number: 0,
                status: "delivered".to_string(),
                message_type: "system".to_string(),
                image: None,
            };
            let _ = app.emit("mls-incoming-message", &ui_msg);

            Ok(cursor)
        }
        // Silent events — process but don't create visible messages
        "#groupInfoRefreshRequestedEvent" => {
            log_ws!("Group info refresh requested for {}", convo_id);
            let _ = app.emit("mls-refresh-group", convo_id);
            Ok(None)
        }
        "#readditionRequestedEvent" => {
            log_ws!("Readdition requested for {}", convo_id);
            Ok(None)
        }
        "#groupResetEvent" => {
            log_ws!("Group reset event for {}", convo_id);
            let payload: CborValue = ciborium::from_reader(Cursor::new(payload_bytes))
                .map_err(|e| format!("Failed to decode groupResetEvent CBOR: {}", e))?;

            let CborValue::Map(ref top) = payload else {
                return Err("groupResetEvent payload must be a CBOR map".to_string());
            };

            let cursor = cbor_str(top, "cursor");
            let authority = validate_group_reset_authority(top, convo_id)?;
            let payload_conversation_id = authority.conversation_id;
            let new_group_id = authority.new_group_id_hex;
            let reset_generation = authority.reset_generation;
            let reset_by = cbor_str(top, "resetBy").unwrap_or_default();
            let reason = cbor_str(top, "reason");

            log_ws!(
                "Group reset: convo={} newGroupId={} gen={} by={}",
                payload_conversation_id,
                new_group_id,
                reset_generation,
                short_id(&reset_by)
            );

            // The orchestrator owns the reset transition. Its storage callback
            // persists the complete ResetPending authority in one transaction;
            // this handler must not issue split state/rejoin/group-id writes or
            // replace the current group before target adoption succeeds.
            orchestrator
                .record_group_reset(
                    &payload_conversation_id,
                    authority.new_group_id,
                    reset_generation,
                )
                .await
                .map_err(|error| {
                    format!("Failed to record group reset for {payload_conversation_id}: {error:?}")
                })?;

            // Emit event to frontend
            let _ = app.emit(
                "mls:group-reset",
                serde_json::json!({
                    "convoId": payload_conversation_id,
                    "newGroupId": new_group_id,
                    "resetGeneration": reset_generation,
                    "resetBy": reset_by,
                    "reason": reason,
                }),
            );

            // Also emit a system message so the user sees the reset in chat
            let reason_text = reason
                .map(|r| format!(" (reason: {})", r))
                .unwrap_or_default();
            let ui_msg = commands::Message {
                id: format!("sys-{}", uuid::Uuid::new_v4()),
                conversation_id: payload_conversation_id,
                sender_did: String::new(),
                sender_handle: String::new(),
                content: format!("Group was reset by {}{}", short_id(&reset_by), reason_text),
                timestamp: chrono::Utc::now().to_rfc3339(),
                sequence_number: 0,
                status: "delivered".to_string(),
                message_type: "system".to_string(),
                image: None,
            };
            let _ = app.emit("mls-incoming-message", &ui_msg);

            Ok(cursor)
        }
        "#reactionEvent" => {
            log_ws!("Reaction event for {}", convo_id);
            let payload: CborValue = ciborium::from_reader(Cursor::new(payload_bytes))
                .map_err(|e| format!("Failed to decode reactionEvent CBOR: {}", e))?;

            let CborValue::Map(ref top) = payload else {
                return Ok(cbor_str_from_cbor(&payload, "cursor"));
            };

            let cursor = cbor_str(top, "cursor");
            let reaction_data = commands::ReactionEvent {
                conversation_id: cbor_str(top, "convoId").unwrap_or_else(|| convo_id.to_string()),
                message_id: cbor_str(top, "messageId").unwrap_or_default(),
                sender_did: cbor_str(top, "did").unwrap_or_default(),
                emoji: cbor_str(top, "reaction").unwrap_or_default(),
                action: cbor_str(top, "action").unwrap_or_else(|| "add".to_string()),
            };
            let _ = app.emit("mls-reaction-event", &reaction_data);
            log_ws!(
                "Emitted mls-reaction-event: {} {} on {}",
                reaction_data.emoji,
                reaction_data.action,
                reaction_data.message_id
            );

            Ok(cursor)
        }
        "#typingEvent" => {
            log_ws!("Typing event for {}", convo_id);
            let payload: CborValue = ciborium::from_reader(Cursor::new(payload_bytes))
                .map_err(|e| format!("Failed to decode typingEvent CBOR: {}", e))?;

            let CborValue::Map(ref top) = payload else {
                return Ok(cbor_str_from_cbor(&payload, "cursor"));
            };

            let cursor = cbor_str(top, "cursor");
            let typing_data = commands::TypingEvent {
                conversation_id: cbor_str(top, "convoId").unwrap_or_else(|| convo_id.to_string()),
                sender_did: cbor_str(top, "did").unwrap_or_default(),
                is_typing: cbor_bool(top, "isTyping")
                    .or_else(|| cbor_bool(top, "typing"))
                    .unwrap_or(true),
            };
            let _ = app.emit("mls-typing-event", &typing_data);
            log_ws!(
                "Emitted mls-typing-event: {} typing={} in {}",
                typing_data.sender_did,
                typing_data.is_typing,
                typing_data.conversation_id
            );

            Ok(cursor)
        }
        "#treeChanged" => {
            // Server signals the canonical MLS tree has moved forward. Payload is
            // metadata-only (cursor, convoId, confirmationTag, epoch); the actual
            // commit arrives either as a separate #messageEvent (messageType=commit)
            // or is fetched by the HTTP sync path. Trust the HTTP path — the WS
            // commit payload is currently unreliable (orphan/malformed bytes delivered
            // by the server for heavily-inflated groups). Kick an async sync so the
            // orchestrator walks commits from its local epoch forward.
            let payload: CborValue = ciborium::from_reader(Cursor::new(payload_bytes))
                .map_err(|e| format!("Failed to decode treeChanged CBOR: {}", e))?;
            let CborValue::Map(ref top) = payload else {
                return Ok(cbor_str_from_cbor(&payload, "cursor"));
            };
            let cursor = cbor_str(top, "cursor");
            let server_epoch = cbor_int(top, "epoch").unwrap_or(0);
            log_ws!(
                "Tree changed for {} — server epoch {}, scheduling sync",
                convo_id,
                server_epoch
            );
            let orch = Arc::clone(orchestrator);
            let app_clone = app.clone();
            let convo_id_owned = convo_id.to_string();
            tokio::spawn(async move {
                if let Err(e) = orch.sync_with_server(false).await {
                    let line = format!(
                        "[catmos {}] [WS] treeChanged sync failed for {}: {:?}\n",
                        chrono::Local::now().format("%H:%M:%S%.3f"),
                        convo_id_owned,
                        e
                    );
                    commands::append_log_line(&line);
                } else {
                    let _ = app_clone.emit("mls-tree-changed", &convo_id_owned);
                }
            });
            Ok(cursor)
        }
        _ => {
            log_ws!(
                "Ignoring unknown event type '{}' for {}",
                event_type,
                convo_id
            );
            Ok(None)
        }
    }
}

/// Shorten a DID for display (e.g., "did:plc:abc123" → "abc123")
fn short_id(did: &str) -> &str {
    did.rsplit(':').next().unwrap_or(did)
}

/// Extract cursor string from a CBOR value (helper for non-map payloads)
fn cbor_str_from_cbor(val: &CborValue, key: &str) -> Option<String> {
    match val {
        CborValue::Map(ref entries) => cbor_str(entries, key),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{validate_group_reset_authority, CborValue};

    fn reset_map(conversation_id: Option<&str>) -> Vec<(CborValue, CborValue)> {
        let mut values = vec![
            (
                CborValue::Text("newGroupId".to_string()),
                CborValue::Text("deadbeef".to_string()),
            ),
            (
                CborValue::Text("resetGeneration".to_string()),
                CborValue::Integer(7_i64.into()),
            ),
        ];
        if let Some(conversation_id) = conversation_id {
            values.push((
                CborValue::Text("convoId".to_string()),
                CborValue::Text(conversation_id.to_string()),
            ));
        }
        values
    }

    #[test]
    fn reset_payload_requires_stable_conversation_id_even_on_global_socket() {
        let stable = "00000000-0000-4000-8000-000000000001";
        let authority = validate_group_reset_authority(&reset_map(Some(stable)), "*")
            .expect("global socket should admit a stable payload UUID");
        assert_eq!(authority.conversation_id, stable);
        assert_eq!(authority.new_group_id, vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(authority.reset_generation, 7);

        assert!(validate_group_reset_authority(&reset_map(None), "*").is_err());
        assert!(validate_group_reset_authority(&reset_map(Some("*")), "*").is_err());
        assert!(validate_group_reset_authority(&reset_map(Some("deadbeef")), "*").is_err());
    }

    #[test]
    fn scoped_reset_payload_must_match_subscription_exactly() {
        let subscribed = "00000000-0000-4000-8000-000000000001";
        let other = "00000000-0000-4000-8000-000000000002";
        assert!(validate_group_reset_authority(&reset_map(Some(subscribed)), subscribed).is_ok());
        assert!(validate_group_reset_authority(&reset_map(Some(other)), subscribed).is_err());
    }

    #[test]
    fn reset_payload_requires_complete_canonical_target_authority() {
        let stable = "00000000-0000-4000-8000-000000000001";
        let mut missing_generation = reset_map(Some(stable));
        missing_generation.retain(
            |(key, _)| !matches!(key, CborValue::Text(value) if value == "resetGeneration"),
        );
        assert!(validate_group_reset_authority(&missing_generation, "*").is_err());

        let mut uppercase_group = reset_map(Some(stable));
        for (key, value) in &mut uppercase_group {
            if matches!(key, CborValue::Text(name) if name == "newGroupId") {
                *value = CborValue::Text("DEADBEEF".to_string());
            }
        }
        assert!(validate_group_reset_authority(&uppercase_group, "*").is_err());
    }
}

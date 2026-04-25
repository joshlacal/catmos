use std::io::Cursor;
use std::sync::Arc;

use base64::Engine;
use ciborium::Value as CborValue;
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use tauri::{AppHandle, Emitter};
use tokio_tungstenite::{connect_async, tungstenite::Message as WsMessage};

use catbird_mls::orchestrator::types::IncomingEnvelope;
use catbird_mls::orchestrator::MLSStorageBackend;

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
async fn do_subscribe(
    app: &AppHandle,
    orchestrator: &Arc<CatmosOrchestrator>,
    api_base_url: &str,
    auth_token: &str,
    convo_id: Option<&str>,
    cursor: Option<&str>,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
) -> Result<Option<String>, String> {
    const GLOBAL_CURSOR_KEY: &str = "__global__";
    let cursor_key = convo_id.unwrap_or(GLOBAL_CURSOR_KEY);
    let label_owned: String = convo_id
        .map(|c| c.to_string())
        .unwrap_or_else(|| "*".to_string());
    let label: &str = &label_owned;

    // 1. Get subscription ticket
    let client = reqwest::Client::new();
    let ticket_body = match convo_id {
        Some(c) => serde_json::json!({ "convoId": c }),
        None => serde_json::json!({}),
    };
    let ticket_resp = crate::mls_proxy::with_mls_proxy_header(client.post(format!(
        "{}/xrpc/blue.catbird.mlsChat.getSubscriptionTicket",
        api_base_url
    )))
    .bearer_auth(auth_token)
    .json(&ticket_body)
    .send()
    .await
    .map_err(|e| format!("Ticket request failed: {}", e))?;

    if !ticket_resp.status().is_success() {
        return Err(format!("Ticket request failed: {}", ticket_resp.status()));
    }

    let ticket_data: serde_json::Value = ticket_resp
        .json()
        .await
        .map_err(|e| format!("Ticket parse failed: {}", e))?;

    let ticket = ticket_data["ticket"]
        .as_str()
        .ok_or("No ticket in response")?;
    let ws_endpoint = ticket_data["endpoint"]
        .as_str()
        .ok_or("No endpoint in response")?;

    // 2. Connect to WebSocket. Omit convoId in global mode so the server sends
    //    events from every conversation the user is a member of on one stream.
    let mut ws_url = match convo_id {
        Some(c) => format!("{}?convoId={}&ticket={}", ws_endpoint, c, ticket),
        None => format!("{}?ticket={}", ws_endpoint, ticket),
    };
    if let Some(cur) = cursor {
        ws_url.push_str(&format!("&cursor={}", cur));
    }

    let (mut ws_stream, _) = connect_async(&ws_url)
        .await
        .map_err(|e| format!("WebSocket connect failed: {}", e))?;

    log_ws!("Connected to {}", label);
    let _ = app.emit("mls-ws-connected", label);

    let mut last_cursor: Option<String> = cursor.map(String::from);

    loop {
        tokio::select! {
            msg = ws_stream.next() => {
                match msg {
                    Some(Ok(WsMessage::Binary(data))) => {
                        log_ws!("Received binary frame: {} bytes ({})", data.len(), label);
                        match handle_binary_frame(app, orchestrator, &data, label).await {
                            Ok(Some(cur)) => {
                                orchestrator.storage().set_ws_cursor(cursor_key, &cur);
                                last_cursor = Some(cur);
                            }
                            Ok(None) => {},
                            Err(e) => log_ws!("Frame error: {}", e),
                        }
                    }
                    Some(Ok(WsMessage::Ping(data))) => {
                        let _ = ws_stream.send(WsMessage::Pong(data)).await;
                    }
                    Some(Ok(WsMessage::Close(_))) => {
                        log_ws!("Closed by server for {}", label);
                        break;
                    }
                    Some(Err(e)) => {
                        return Err(format!("WebSocket error: {}", e));
                    }
                    None => break,
                    _ => {}
                }
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    let _ = ws_stream.close(None).await;
                    return Ok(last_cursor);
                }
            }
        }
    }

    let _ = app.emit("mls-ws-disconnected", label);
    Ok(last_cursor)
}

/// Handle a binary DAG-CBOR WebSocket frame.
async fn handle_binary_frame(
    app: &AppHandle,
    orchestrator: &Arc<CatmosOrchestrator>,
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

            let envelope = IncomingEnvelope {
                conversation_id: msg_convo_id,
                sender_did: String::new(),
                ciphertext,
                timestamp,
                server_message_id: Some(id.clone()),
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
            if epoch >= 0 {
                if let Ok(gid_bytes) = hex::decode(convo_id) {
                    if let Err(e) = orchestrator
                        .mls_context()
                        .merge_incoming_commit(gid_bytes, epoch as u64)
                    {
                        log_ws!(
                            "merge_incoming_commit no-op for {} epoch {}: {}",
                            id,
                            epoch,
                            e
                        );
                    }
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
                return Ok(cbor_str_from_cbor(&payload, "cursor"));
            };

            let cursor = cbor_str(top, "cursor");
            let new_group_id = cbor_str(top, "newGroupId").unwrap_or_default();
            let reset_generation = cbor_int(top, "resetGeneration").unwrap_or(0) as i32;
            let reset_by = cbor_str(top, "resetBy").unwrap_or_default();
            let reason = cbor_str(top, "reason");

            log_ws!(
                "Group reset: convo={} newGroupId={} gen={} by={}",
                convo_id,
                new_group_id,
                reset_generation,
                short_id(&reset_by)
            );

            // Spec §8.5: groupReset is a RESET_PENDING trigger — reset the
            // recovery tracker's attempt counter to 0 so the deferred recovery
            // treats this as a fresh attempt (no accumulated backoff/cooldown).
            orchestrator
                .recovery_tracker()
                .lock()
                .await
                .clear(convo_id);
            log_ws!(
                "Reset recovery tracker for {} (groupReset → fresh attempt)",
                convo_id
            );

            // Flag for deferred recovery — External Commits only in deferred
            // recovery, never inline in event handlers. Recovery dispatch
            // reads the `needs_rejoin` boolean (recovery.rs), so we keep
            // marking it; in addition we persist the RESET_PENDING payload
            // (spec §8.5) so the new group id + reset generation survive a
            // restart even if the orchestrator's in-memory
            // `conversation_states` map is empty on next boot.
            if let Err(e) = orchestrator
                .storage()
                .mark_needs_rejoin(convo_id)
                .await
            {
                log_ws!("Failed to mark_needs_rejoin for {}: {:?}", convo_id, e);
            }

            let notified_at_ms = chrono::Utc::now().timestamp_millis();
            if !new_group_id.is_empty() {
                if let Err(e) = orchestrator
                    .storage()
                    .set_conversation_state(
                        convo_id,
                        catbird_mls::orchestrator::types::ConversationState::ResetPending {
                            new_group_id: new_group_id.clone(),
                            reset_generation,
                            notified_at_ms,
                        },
                    )
                    .await
                {
                    log_ws!(
                        "Failed to set ResetPending state for {}: {:?}",
                        convo_id,
                        e
                    );
                }
                if let Err(e) = orchestrator
                    .storage()
                    .mark_reset_pending(
                        convo_id,
                        &new_group_id,
                        reset_generation,
                        notified_at_ms,
                    )
                    .await
                {
                    log_ws!(
                        "Failed to persist ResetPending payload for {}: {:?}",
                        convo_id,
                        e
                    );
                } else {
                    log_ws!(
                        "Flagged {} for deferred rejoin after group reset (newGroupId={}, gen={})",
                        convo_id,
                        new_group_id,
                        reset_generation
                    );
                }
            } else {
                // Server didn't send a new group id; fall back to NeedsRejoin
                // state so the recovery loop still picks this up via the
                // pre-reset lookup-by-conversation-id heuristic.
                if let Err(e) = orchestrator
                    .storage()
                    .set_conversation_state(
                        convo_id,
                        catbird_mls::orchestrator::types::ConversationState::NeedsRejoin,
                    )
                    .await
                {
                    log_ws!("Failed to set NeedsRejoin state for {}: {:?}", convo_id, e);
                } else {
                    log_ws!(
                        "Flagged {} for deferred rejoin after group reset (no newGroupId in payload)",
                        convo_id
                    );
                }
            }

            // Adopt the new group id locally so the deferred rejoin targets
            // the post-reset MLS group. Empty = server didn't send one; fall
            // back to the pre-reset lookup-by-conversation-id heuristic.
            if !new_group_id.is_empty() {
                if let Err(e) = orchestrator
                    .storage()
                    .update_conversation_group_id(convo_id, &new_group_id)
                {
                    log_ws!(
                        "Failed to update group_id for {} to {}: {:?}",
                        convo_id,
                        new_group_id,
                        e
                    );
                } else {
                    log_ws!(
                        "Adopted new group_id {} for convo {}",
                        new_group_id,
                        convo_id
                    );
                }
            }

            // Emit event to frontend
            let _ = app.emit(
                "mls:group-reset",
                serde_json::json!({
                    "convoId": convo_id,
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
                conversation_id: convo_id.to_string(),
                sender_did: String::new(),
                sender_handle: String::new(),
                content: format!(
                    "Group was reset by {}{}",
                    short_id(&reset_by),
                    reason_text
                ),
                timestamp: chrono::Utc::now().to_rfc3339(),
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

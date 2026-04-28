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

/// Fields extracted from a `#resetRequestedEvent` CBOR payload (Phase 2.5).
/// Matches the lexicon-generated `ResetRequestedEvent` shape (camelCase wire
/// fields → snake_case Rust). See plan §2 for the wire schema and
/// `catbird-mls/src/orchestrator/recovery.rs::record_reset_requested` for
/// the consumer signature.
#[derive(Debug, PartialEq, Eq)]
struct ResetRequestedPayload {
    cursor: Option<String>,
    crypto_session_id: String,
    reset_generation: i32,
    trigger: String,
    request_event_id: String,
    expected_new_mls_group_id: Option<String>,
    reason: Option<String>,
}

/// Decode a `#resetRequestedEvent` CBOR payload into the
/// `ResetRequestedPayload` projection consumed by the SSE dispatcher and
/// shared Rust core.
///
/// Returns `None` if the payload isn't a CBOR map (caller falls back to
/// `cbor_str_from_cbor` for cursor extraction). Missing optional fields
/// default per the orchestrator contract:
///   - `cryptoSessionId`, `trigger`, `requestEventId` → `""`
///   - `generation` → `0` (saturated to `i32::MAX` on overflow; the
///     lexicon types `generation: i64` while the orchestrator stores
///     `reset_generation: i32`)
///   - `expectedNewMlsGroupId`, `reason` → `None`
///
/// Idempotency on the orchestrator side is keyed on
/// `(convoId, generation)`; duplicate deliveries via SSE reconnect or
/// `event_stream` cursor replay collapse there.
fn parse_reset_requested_payload(payload: &CborValue) -> Option<ResetRequestedPayload> {
    let CborValue::Map(ref top) = payload else {
        return None;
    };
    let generation = cbor_int(top, "generation").unwrap_or(0);
    Some(ResetRequestedPayload {
        cursor: cbor_str(top, "cursor"),
        crypto_session_id: cbor_str(top, "cryptoSessionId").unwrap_or_default(),
        reset_generation: i32::try_from(generation).unwrap_or(i32::MAX),
        trigger: cbor_str(top, "trigger").unwrap_or_default(),
        request_event_id: cbor_str(top, "requestEventId").unwrap_or_default(),
        expected_new_mls_group_id: cbor_str(top, "expectedNewMlsGroupId"),
        reason: cbor_str(top, "reason"),
    })
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
        // Phase 2.5 (`docs/plans/phase-2-5-indirect-funneling.md` §2 / §4):
        // server-emitted indirect-trigger reset. Server hands us
        // `cryptoSessionId`, `generation`, `trigger`, `requestEventId`, and
        // (usually null) `expectedNewMlsGroupId`. We hand the whole bundle to
        // `record_reset_requested`, which mirrors `GroupResetEvent` handling
        // (ResetPending state, group-state rebinding, recovery-tracker reset,
        // `mark_needs_rejoin`). The deferred-recovery sync loop then drives
        // first-responder bootstrap via `join_or_rejoin`. This is *silent*
        // recovery infra — no UI surface beyond the structured log line and
        // whatever the eventual rejoin emits.
        "#resetRequestedEvent" => {
            log_ws!("Reset requested event for {}", convo_id);
            let payload: CborValue = ciborium::from_reader(Cursor::new(payload_bytes))
                .map_err(|e| format!("Failed to decode resetRequestedEvent CBOR: {}", e))?;

            let parsed = match parse_reset_requested_payload(&payload) {
                Some(p) => p,
                None => return Ok(cbor_str_from_cbor(&payload, "cursor")),
            };

            log_ws!(
                "resetRequested: convo={} cryptoSession={} gen={} trigger={} requestEventId={} expectedNewGroupId={} reason={}",
                convo_id,
                short_id(&parsed.crypto_session_id),
                parsed.reset_generation,
                parsed.trigger,
                short_id(&parsed.request_event_id),
                parsed.expected_new_mls_group_id.as_deref().unwrap_or("<none>"),
                parsed.reason.as_deref().unwrap_or("<none>")
            );

            // Hand to the shared Rust core. `record_reset_requested` is
            // idempotent against (convo_id, reset_generation) so duplicate
            // SSE deliveries (reconnect / cursor replay) collapse to a
            // single state transition. The orchestrator (a) writes
            // ResetPending state, (b) deletes the old MLS group, (c)
            // resets the recovery tracker, (d) rebinds `group_states`
            // and `mark_needs_rejoin`, and (e) persists the new group
            // id (server-supplied OR orchestrator-minted for indirect
            // triggers per Phase 2.5 §1) into the reset_pending payload
            // via `mark_reset_pending`.
            if let Err(e) = orchestrator
                .record_reset_requested(
                    convo_id,
                    &parsed.crypto_session_id,
                    parsed.reset_generation,
                    &parsed.trigger,
                    &parsed.request_event_id,
                    parsed.expected_new_mls_group_id.clone(),
                )
                .await
            {
                log_ws!(
                    "record_reset_requested failed for {} (gen={} trigger={}): {:?}",
                    convo_id,
                    parsed.reset_generation,
                    parsed.trigger,
                    e
                );
                // Don't proceed with the local mirror — leave
                // `conversations.group_id` pointing at the pre-reset
                // value so a retry on the next delivery has consistent
                // state to overwrite.
                return Ok(parsed.cursor);
            }

            // Mirror the new group id into `conversations.group_id`
            // (catmos-specific table; not in the orchestrator's
            // `MLSStorageBackend` trait surface). The existing
            // `#groupResetEvent` handler does the same via
            // `update_conversation_group_id`. Without this mirror,
            // `get_conversation`/`list_conversations` would return the
            // pre-reset group_id while `group_states` already holds the
            // new one — divergence between the two tables that
            // surfaces as wrong group ids in any UI / sync path that
            // joins on `conversations`.
            //
            // We read the authoritative value back from
            // `get_reset_pending` because for indirect-trigger paths
            // (`expectedNewMlsGroupId == null`) the orchestrator mints
            // the id internally and doesn't return it. For
            // server-supplied paths the SSE field and the persisted
            // value are identical.
            let new_group_id_for_mirror = orchestrator
                .storage()
                .get_reset_pending(convo_id)
                .and_then(|state| match state {
                    catbird_mls::orchestrator::types::ConversationState::ResetPending {
                        new_group_id,
                        ..
                    } => Some(new_group_id),
                    _ => None,
                })
                .or_else(|| parsed.expected_new_mls_group_id.clone());

            if let Some(ref new_group_id) = new_group_id_for_mirror {
                if !new_group_id.is_empty() {
                    if let Err(e) = orchestrator
                        .storage()
                        .update_conversation_group_id(convo_id, new_group_id)
                    {
                        log_ws!(
                            "Failed to update conversations.group_id for {} to {}: {:?}",
                            convo_id,
                            new_group_id,
                            e
                        );
                    } else {
                        log_ws!(
                            "Adopted new group_id {} for convo {} (Phase 2.5 indirect)",
                            new_group_id,
                            convo_id
                        );
                    }
                }
            } else {
                // Should not happen — `record_reset_requested` always
                // persists ResetPending unless it short-circuited on
                // idempotency, in which case the existing row already
                // has the right group id and we don't need to touch
                // `conversations`. Log so we notice if this assumption
                // ever breaks.
                log_ws!(
                    "resetRequested: no ResetPending payload after record_reset_requested for {} \
                     (idempotent dup or storage gap?) — skipping conversations.group_id mirror",
                    convo_id
                );
            }

            Ok(parsed.cursor)
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
    //! Wire-format coverage for `#resetRequestedEvent` (Phase 2.5,
    //! `docs/plans/phase-2-5-indirect-funneling.md` §2 / §4).
    //!
    //! These tests pin the CBOR → `ResetRequestedPayload` projection that
    //! feeds `MLSOrchestrator::record_reset_requested`. The orchestrator
    //! itself is exercised by `catbird-mls` tests; here we only assert that
    //! catmos's SSE handler reads the lexicon-defined fields correctly.
    //!
    //! If the lexicon (`blue.catbird.mlsChat.subscribeEvents#resetRequestedEvent`)
    //! changes shape, these tests should be the first thing that fails.
    use super::*;

    /// Build a minimal CBOR map for a reset_requested_event payload. Only
    /// fields we want under test are passed; everything else is omitted to
    /// match the optional-field behavior of the real wire format.
    fn cbor_map_payload(entries: Vec<(&str, CborValue)>) -> CborValue {
        CborValue::Map(
            entries
                .into_iter()
                .map(|(k, v)| (CborValue::Text(k.into()), v))
                .collect(),
        )
    }

    #[test]
    fn parse_reset_requested_full_payload() {
        // Server emits all required fields plus optional reason +
        // expectedNewMlsGroupId set (admin / direct-flow path). Verify
        // every field plumbs through.
        let payload = cbor_map_payload(vec![
            ("cursor", CborValue::Text("seq-000123".into())),
            ("convoId", CborValue::Text("c-abc".into())),
            (
                "cryptoSessionId",
                CborValue::Text("did:plc:foo:cs-9".into()),
            ),
            ("generation", CborValue::Integer(17.into())),
            ("trigger", CborValue::Text("inlineGroupInfo404".into())),
            (
                "requestEventId",
                CborValue::Text("req-inline-404:c-abc:5:42".into()),
            ),
            (
                "expectedNewMlsGroupId",
                CborValue::Text("deadbeefcafebabe".into()),
            ),
            ("reason", CborValue::Text("groupinfo 404 threshold".into())),
        ]);

        let parsed = parse_reset_requested_payload(&payload).expect("payload is a CBOR map");

        assert_eq!(parsed.cursor.as_deref(), Some("seq-000123"));
        assert_eq!(parsed.crypto_session_id, "did:plc:foo:cs-9");
        assert_eq!(parsed.reset_generation, 17);
        assert_eq!(parsed.trigger, "inlineGroupInfo404");
        assert_eq!(parsed.request_event_id, "req-inline-404:c-abc:5:42");
        assert_eq!(
            parsed.expected_new_mls_group_id.as_deref(),
            Some("deadbeefcafebabe")
        );
        assert_eq!(parsed.reason.as_deref(), Some("groupinfo 404 threshold"));
    }

    #[test]
    fn parse_reset_requested_indirect_trigger_no_group_id() {
        // The Phase 2.5 indirect path: server does NOT mint a group id, so
        // `expectedNewMlsGroupId` is absent. `record_reset_requested` then
        // mints a client-side candidate. This is the dominant case in
        // production once Phase 2.5 ships.
        let payload = cbor_map_payload(vec![
            ("cursor", CborValue::Text("seq-000124".into())),
            ("convoId", CborValue::Text("c-xyz".into())),
            ("cryptoSessionId", CborValue::Text("cs-prior".into())),
            ("generation", CborValue::Integer(3.into())),
            ("trigger", CborValue::Text("quorumVote".into())),
            (
                "requestEventId",
                CborValue::Text("req-quorum:c-xyz:vote-7".into()),
            ),
        ]);

        let parsed = parse_reset_requested_payload(&payload).expect("payload is a CBOR map");

        assert!(parsed.expected_new_mls_group_id.is_none());
        assert!(parsed.reason.is_none());
        assert_eq!(parsed.reset_generation, 3);
        assert_eq!(parsed.trigger, "quorumVote");
        assert_eq!(parsed.request_event_id, "req-quorum:c-xyz:vote-7");
    }

    #[test]
    fn parse_reset_requested_missing_required_fields_default_safely() {
        // Defense in depth: if the server sends a malformed payload, we
        // don't want to panic. Required strings default to "" and the
        // orchestrator's idempotency check still functions on
        // (convo_id, generation).
        let payload = cbor_map_payload(vec![
            ("cursor", CborValue::Text("seq-broken".into())),
            ("generation", CborValue::Integer(5.into())),
        ]);

        let parsed = parse_reset_requested_payload(&payload).expect("payload is a CBOR map");

        assert_eq!(parsed.crypto_session_id, "");
        assert_eq!(parsed.trigger, "");
        assert_eq!(parsed.request_event_id, "");
        assert_eq!(parsed.reset_generation, 5);
        assert!(parsed.expected_new_mls_group_id.is_none());
    }

    #[test]
    fn parse_reset_requested_generation_overflow_saturates() {
        // Lexicon types `generation: i64`; we saturate to `i32::MAX` rather
        // than wrap or panic. In production generations are tiny but a
        // server bug or attacker-supplied value should not crash the
        // dispatcher.
        let payload = cbor_map_payload(vec![
            ("cursor", CborValue::Text("seq-x".into())),
            ("generation", CborValue::Integer(i64::MAX.into())),
            ("trigger", CborValue::Text("systemSweep".into())),
            ("cryptoSessionId", CborValue::Text("cs".into())),
            ("requestEventId", CborValue::Text("req".into())),
        ]);

        let parsed = parse_reset_requested_payload(&payload).expect("payload is a CBOR map");

        assert_eq!(parsed.reset_generation, i32::MAX);
    }

    #[test]
    fn parse_reset_requested_non_map_returns_none() {
        // Non-map payloads can't be parsed; the dispatcher falls back to
        // `cbor_str_from_cbor` for cursor extraction. Verify the helper
        // signals that path correctly rather than producing a default
        // payload that would still try to invoke `record_reset_requested`.
        let payload = CborValue::Text("not a map".into());
        assert!(parse_reset_requested_payload(&payload).is_none());

        let payload = CborValue::Array(vec![]);
        assert!(parse_reset_requested_payload(&payload).is_none());
    }

    #[test]
    fn parse_reset_requested_round_trip_via_ciborium_serde() {
        // Mirror the dispatcher's actual decode path: bytes → ciborium →
        // CborValue → parse. This guards against subtle CBOR encoding
        // mismatches between the test fixture (built by hand) and the
        // server's serializer.
        let payload = cbor_map_payload(vec![
            ("cursor", CborValue::Text("seq-rt".into())),
            ("convoId", CborValue::Text("c-rt".into())),
            ("cryptoSessionId", CborValue::Text("cs-rt".into())),
            ("generation", CborValue::Integer(42.into())),
            ("trigger", CborValue::Text("inlineCommit409".into())),
            (
                "requestEventId",
                CborValue::Text("req-inline-409:c-rt:9:11".into()),
            ),
        ]);

        let mut buf = Vec::new();
        ciborium::into_writer(&payload, &mut buf).expect("encode CBOR fixture");
        let decoded: CborValue =
            ciborium::from_reader(Cursor::new(&buf[..])).expect("decode CBOR fixture");

        let parsed = parse_reset_requested_payload(&decoded).expect("payload is a CBOR map");
        assert_eq!(parsed.cursor.as_deref(), Some("seq-rt"));
        assert_eq!(parsed.crypto_session_id, "cs-rt");
        assert_eq!(parsed.reset_generation, 42);
        assert_eq!(parsed.trigger, "inlineCommit409");
        assert_eq!(parsed.request_event_id, "req-inline-409:c-rt:9:11");
        assert!(parsed.expected_new_mls_group_id.is_none());
    }
}

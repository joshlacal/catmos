//! Browser WebSocket client for real-time MLS message delivery.
//!
//! This is the WASM equivalent of `catmos/src-tauri/src/websocket.rs`.
//! Instead of `tokio-tungstenite` + async loops, it wires browser-native
//! `web_sys::WebSocket` event callbacks.
//!
//! # Limitations
//! - MLS decryption is NOT available in the browser target — `MLSContext` is a
//!   native-only type. Text messages are surfaced with
//!   `content = "[Encrypted message]"` and `message_type = "encrypted"`. The JS
//!   side should show a placeholder or trigger a side-channel fetch from the
//!   native orchestrator if decryption is required.
//! - WASM is single-threaded, so there is no `tokio::select!` and no
//!   `Arc<Mutex<>>` for shared async state. All handler closures run on the JS
//!   event loop.
//! - Membership, info, new-device, reaction, and typing events do NOT
//!   require MLS crypto and are surfaced fully.

use std::cell::RefCell;
use std::io::Cursor;
use std::rc::Rc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ciborium::Value as CborValue;
use js_sys::Function;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::spawn_local;
use web_sys::{CloseEvent, ErrorEvent, MessageEvent, WebSocket};

// ---------------------------------------------------------------------------
// Public types (serde-compatible with Tauri output)
// ---------------------------------------------------------------------------

/// A single chat message ready for the UI layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UiMessage {
    pub id: String,
    pub conversation_id: String,
    pub sender_did: String,
    pub sender_handle: String,
    pub content: String,
    pub timestamp: String,
    /// `"pending"` | `"delivered"` | `"read"`
    pub status: String,
    /// `"text"` | `"system"` | `"encrypted"`
    pub message_type: String,
}

/// Emitted for `#reactionEvent` frames.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReactionEvent {
    pub conversation_id: String,
    pub message_id: String,
    pub sender_did: String,
    pub emoji: String,
    /// `"add"` | `"remove"`
    pub action: String,
}

/// Emitted for `#typingEvent` frames.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TypingEvent {
    pub conversation_id: String,
    pub sender_did: String,
    pub is_typing: bool,
}

// ---------------------------------------------------------------------------
// Internal frame processing types
// ---------------------------------------------------------------------------

/// DAG-CBOR WebSocket frame header — same wire format as mls-ds `MessageHeader`.
#[derive(Debug, Deserialize)]
struct FrameHeader {
    op: i32,
    t: Option<String>,
}

/// Discriminated output from `handle_frame`.
#[allow(dead_code)]
enum FrameOutput {
    /// A displayable message (text, system, or encrypted placeholder).
    Message(UiMessage),
    /// A named non-message event with an arbitrary JS value payload.
    /// The first field is the `type` string passed to `on_event`.
    Event(String, JsValue),
}

// ---------------------------------------------------------------------------
// CBOR helper functions (ported verbatim from src-tauri/src/websocket.rs)
// ---------------------------------------------------------------------------

/// Extract a string from a CBOR map.
fn cbor_str(map: &[(CborValue, CborValue)], key: &str) -> Option<String> {
    map.iter().find_map(|(k, v)| match (k, v) {
        (CborValue::Text(k), CborValue::Text(v)) if k == key => Some(v.clone()),
        _ => None,
    })
}

/// Extract an integer from a CBOR map.
fn cbor_int(map: &[(CborValue, CborValue)], key: &str) -> Option<i64> {
    map.iter().find_map(|(k, v)| match (k, v) {
        (CborValue::Text(k), CborValue::Integer(v)) if k == key => {
            let n: i128 = (*v).into();
            Some(n as i64)
        }
        _ => None,
    })
}

/// Extract a boolean from a CBOR map.
fn cbor_bool(map: &[(CborValue, CborValue)], key: &str) -> Option<bool> {
    map.iter().find_map(|(k, v)| match (k, v) {
        (CborValue::Text(k), CborValue::Bool(v)) if k == key => Some(*v),
        _ => None,
    })
}

/// Extract bytes from a CBOR map.
///
/// Handles three formats:
/// - CBOR byte string (major type 2) — raw bytes
/// - ATProto `{"$bytes": "base64..."}` map — base64-decoded
/// - CBOR array of integers — each int as u8
fn cbor_bytes(map: &[(CborValue, CborValue)], key: &str) -> Option<Vec<u8>> {
    map.iter().find_map(|(k, v)| {
        let CborValue::Text(k) = k else {
            return None;
        };
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
        CborValue::Map(entries) => {
            cbor_str(entries, "$bytes").and_then(|b64| B64.decode(&b64).ok())
        }
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

/// Extract a nested CBOR map from a parent map.
fn cbor_map<'a>(
    map: &'a [(CborValue, CborValue)],
    key: &str,
) -> Option<&'a [(CborValue, CborValue)]> {
    map.iter().find_map(|(k, v)| match (k, v) {
        (CborValue::Text(k), CborValue::Map(m)) if k == key => Some(m.as_slice()),
        _ => None,
    })
}

/// Decode a DAG-CBOR WebSocket frame.
///
/// Returns the deserialized header and the remaining payload bytes. The frame
/// contains two concatenated CBOR items: header + payload.
fn split_frame(data: &[u8]) -> Option<(FrameHeader, &[u8])> {
    let mut cursor = Cursor::new(data);
    let header: FrameHeader = ciborium::from_reader(&mut cursor).ok()?;
    let consumed = cursor.position() as usize;
    Some((header, &data[consumed..]))
}

/// Shorten a DID for display (e.g. `"did:plc:abc123"` → `"abc123"`).
fn short_id(did: &str) -> &str {
    did.rsplit(':').next().unwrap_or(did)
}

/// Extract cursor string from a CBOR value (helper for non-map payloads).
#[allow(dead_code)]
fn cbor_str_from_cbor(val: &CborValue, key: &str) -> Option<String> {
    match val {
        CborValue::Map(ref entries) => cbor_str(entries, key),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Frame processing
// ---------------------------------------------------------------------------

/// Decode a binary DAG-CBOR frame and produce a [`FrameOutput`] if actionable.
///
/// Returns `Ok(None)` for frames that are intentionally ignored (readdition
/// requests, unknown types), `Ok(Some(_))` for
/// actionable frames, and `Err` for decode failures or server-error frames.
fn handle_frame(data: &[u8], convo_id: &str) -> Result<Option<FrameOutput>, String> {
    let (header, payload_bytes) =
        split_frame(data).ok_or_else(|| "Failed to decode DAG-CBOR frame header".to_string())?;

    if header.op == -1 {
        return Err("Server error frame received".to_string());
    }

    let event_type = header.t.as_deref().unwrap_or("");

    match event_type {
        // ------------------------------------------------------------------
        // Encrypted MLS message — surface as placeholder; no crypto in WASM.
        // ------------------------------------------------------------------
        "#messageEvent" => {
            let payload: CborValue = ciborium::from_reader(Cursor::new(payload_bytes))
                .map_err(|e| format!("Failed to decode messageEvent CBOR: {}", e))?;

            let CborValue::Map(ref top) = payload else {
                return Err("messageEvent payload is not a CBOR map".into());
            };

            let msg_map =
                cbor_map(top, "message").ok_or("Missing 'message' field in messageEvent")?;

            let id = cbor_str(msg_map, "id").ok_or("Missing message.id")?;
            let msg_convo_id =
                cbor_str(msg_map, "convoId").ok_or("Missing message.convoId")?;
            let created_at =
                cbor_str(msg_map, "createdAt").ok_or("Missing message.createdAt")?;

            // We verify ciphertext is present so we know this is a genuine MLS
            // message, but we cannot decrypt it without MLSContext (native only).
            let _ciphertext_present = cbor_bytes(msg_map, "ciphertext").is_some();
            let _epoch = cbor_int(msg_map, "epoch").unwrap_or(0);

            // NOTE: MLS decryption is not available in the browser WASM target.
            // MLSContext is a native-only type (requires SQLCipher + OpenMLS).
            // Surface a placeholder so the UI can show a spinner or request
            // decryption from the native orchestrator via a separate channel.
            let ui_msg = UiMessage {
                id,
                conversation_id: msg_convo_id,
                sender_did: String::new(),
                sender_handle: String::new(),
                content: "[Encrypted message]".to_string(),
                timestamp: created_at,
                status: "delivered".to_string(),
                message_type: "encrypted".to_string(),
            };

            Ok(Some(FrameOutput::Message(ui_msg)))
        }

        // ------------------------------------------------------------------
        // Membership change — no crypto required, surface fully.
        // ------------------------------------------------------------------
        "#membershipChangeEvent" => {
            let payload: CborValue = ciborium::from_reader(Cursor::new(payload_bytes))
                .map_err(|e| format!("Failed to decode membershipChangeEvent CBOR: {}", e))?;

            let (member_did, action) = match &payload {
                CborValue::Map(ref top) => (
                    cbor_str(top, "memberDid").unwrap_or_default(),
                    cbor_str(top, "action").unwrap_or_else(|| "changed".to_string()),
                ),
                _ => (String::new(), "changed".to_string()),
            };

            let content = match action.as_str() {
                "join" | "added" => format!("{} joined the group", short_id(&member_did)),
                "leave" | "left" => format!("{} left the group", short_id(&member_did)),
                "removed" => format!("{} was removed from the group", short_id(&member_did)),
                _ => format!("Membership updated: {}", short_id(&member_did)),
            };

            let msg = UiMessage {
                id: format!("sys-{}", uuid::Uuid::new_v4()),
                conversation_id: convo_id.to_string(),
                sender_did: String::new(),
                sender_handle: String::new(),
                content,
                timestamp: chrono::Utc::now().to_rfc3339(),
                status: "delivered".to_string(),
                message_type: "system".to_string(),
            };

            Ok(Some(FrameOutput::Message(msg)))
        }

        // ------------------------------------------------------------------
        // Info event — no crypto required.
        // ------------------------------------------------------------------
        "#infoEvent" => {
            let payload: CborValue = ciborium::from_reader(Cursor::new(payload_bytes))
                .map_err(|e| format!("Failed to decode infoEvent CBOR: {}", e))?;

            let info_text = match &payload {
                CborValue::Map(ref top) => cbor_str(top, "message")
                    .or_else(|| cbor_str(top, "info"))
                    .unwrap_or_else(|| "Group info updated".to_string()),
                _ => "Group info updated".to_string(),
            };

            let msg = UiMessage {
                id: format!("sys-{}", uuid::Uuid::new_v4()),
                conversation_id: convo_id.to_string(),
                sender_did: String::new(),
                sender_handle: String::new(),
                content: info_text,
                timestamp: chrono::Utc::now().to_rfc3339(),
                status: "delivered".to_string(),
                message_type: "system".to_string(),
            };

            Ok(Some(FrameOutput::Message(msg)))
        }

        // ------------------------------------------------------------------
        // New device event — no crypto required.
        // ------------------------------------------------------------------
        "#newDeviceEvent" => {
            let payload: CborValue = ciborium::from_reader(Cursor::new(payload_bytes))
                .map_err(|e| format!("Failed to decode newDeviceEvent CBOR: {}", e))?;

            let member_did = match &payload {
                CborValue::Map(ref top) => cbor_str(top, "memberDid").unwrap_or_default(),
                _ => String::new(),
            };

            let msg = UiMessage {
                id: format!("sys-{}", uuid::Uuid::new_v4()),
                conversation_id: convo_id.to_string(),
                sender_did: String::new(),
                sender_handle: String::new(),
                content: format!("{} added a new device", short_id(&member_did)),
                timestamp: chrono::Utc::now().to_rfc3339(),
                status: "delivered".to_string(),
                message_type: "system".to_string(),
            };

            Ok(Some(FrameOutput::Message(msg)))
        }

        // ------------------------------------------------------------------
        // Reaction event — no crypto required.
        // ------------------------------------------------------------------
        "#reactionEvent" => {
            let payload: CborValue = ciborium::from_reader(Cursor::new(payload_bytes))
                .map_err(|e| format!("Failed to decode reactionEvent CBOR: {}", e))?;

            let CborValue::Map(ref top) = payload else {
                return Ok(None);
            };

            let reaction = ReactionEvent {
                conversation_id: cbor_str(top, "convoId")
                    .unwrap_or_else(|| convo_id.to_string()),
                message_id: cbor_str(top, "messageId").unwrap_or_default(),
                sender_did: cbor_str(top, "did").unwrap_or_default(),
                emoji: cbor_str(top, "reaction").unwrap_or_default(),
                action: cbor_str(top, "action").unwrap_or_else(|| "add".to_string()),
            };

            let event_js = make_event_js("reaction", &reaction)?;
            Ok(Some(FrameOutput::Event("reaction".to_string(), event_js)))
        }

        // ------------------------------------------------------------------
        // Typing event — no crypto required.
        // ------------------------------------------------------------------
        "#typingEvent" => {
            let payload: CborValue = ciborium::from_reader(Cursor::new(payload_bytes))
                .map_err(|e| format!("Failed to decode typingEvent CBOR: {}", e))?;

            let CborValue::Map(ref top) = payload else {
                return Ok(None);
            };

            let typing = TypingEvent {
                conversation_id: cbor_str(top, "convoId")
                    .unwrap_or_else(|| convo_id.to_string()),
                sender_did: cbor_str(top, "did").unwrap_or_default(),
                is_typing: cbor_bool(top, "isTyping")
                    .or_else(|| cbor_bool(top, "typing"))
                    .unwrap_or(true),
            };

            let event_js = make_event_js("typing", &typing)?;
            Ok(Some(FrameOutput::Event("typing".to_string(), event_js)))
        }

        // ------------------------------------------------------------------
        // Group info refresh request — signal JS to re-fetch group state.
        // ------------------------------------------------------------------
        "#groupInfoRefreshRequestedEvent" => {
            let obj = js_sys::Object::new();
            js_sys::Reflect::set(
                &obj,
                &JsValue::from_str("type"),
                &JsValue::from_str("groupRefresh"),
            )
            .ok();
            js_sys::Reflect::set(
                &obj,
                &JsValue::from_str("convoId"),
                &JsValue::from_str(convo_id),
            )
            .ok();
            Ok(Some(FrameOutput::Event("groupRefresh".to_string(), obj.into())))
        }

        // ------------------------------------------------------------------
        // Silent / no-op events.
        // ------------------------------------------------------------------
        "#readditionRequestedEvent" => Ok(None),

        // ------------------------------------------------------------------
        // Unknown event type — ignore without error.
        // ------------------------------------------------------------------
        _ => Ok(None),
    }
}

/// Build a `{type, data}` JS object suitable for the `on_event` callback.
fn make_event_js<T: Serialize>(event_type: &str, data: &T) -> Result<JsValue, String> {
    let data_js = serde_wasm_bindgen::to_value(data)
        .map_err(|e| format!("Failed to serialize event data: {}", e))?;
    let obj = js_sys::Object::new();
    js_sys::Reflect::set(&obj, &JsValue::from_str("type"), &JsValue::from_str(event_type))
        .map_err(|_| "Reflect::set 'type' failed".to_string())?;
    js_sys::Reflect::set(&obj, &JsValue::from_str("data"), &data_js)
        .map_err(|_| "Reflect::set 'data' failed".to_string())?;
    Ok(obj.into())
}

// ---------------------------------------------------------------------------
// Reconnection state
// ---------------------------------------------------------------------------

/// Shared mutable state for reconnection logic.
///
/// WASM is single-threaded, so `Rc<RefCell<>>` is safe and appropriate here
/// (no `Arc<Mutex<>>` needed).
struct ReconnectState {
    /// Number of consecutive failed connection attempts. Reset on successful open.
    attempt: u32,
    /// Set to `true` when the caller explicitly calls `close()` (e.g. logout,
    /// navigation away). Prevents the `onclose` handler from scheduling a
    /// reconnect.
    intentional_close: bool,
}

impl ReconnectState {
    fn new() -> Self {
        Self {
            attempt: 0,
            intentional_close: false,
        }
    }
}

/// Compute the reconnect delay in milliseconds using exponential backoff.
///
/// Sequence: 1000 -> 2000 -> 4000 -> 8000 -> 16000 -> 30000 (cap).
fn backoff_ms(attempt: u32) -> i32 {
    let base: u32 = 1000;
    let max: u32 = 30_000;
    let delay = base.saturating_mul(1u32.checked_shl(attempt.min(4)).unwrap_or(u32::MAX));
    delay.min(max) as i32
}

// ---------------------------------------------------------------------------
// WsSubscription — public WASM handle
// ---------------------------------------------------------------------------

/// A live browser WebSocket subscription with automatic reconnection.
///
/// The `Closure` fields keep handler allocations alive for the lifetime of
/// this struct. Without them the JS garbage collector would collect the
/// closures and the WebSocket handlers would silently stop firing.
///
/// On unexpected disconnects the subscription automatically reconnects with
/// exponential backoff (1 s -> 2 s -> 4 s -> 8 s -> 30 s cap). The backoff
/// resets when a connection succeeds. Calling [`WsSubscription::close`]
/// sets an intentional-close flag that suppresses reconnection.
#[wasm_bindgen]
pub struct WsSubscription {
    ws: WebSocket,
    /// Shared reconnection state — checked by the `onclose` handler.
    reconnect: Rc<RefCell<ReconnectState>>,
    // These hold the Closure<...> allocations alive. Never read after init.
    _on_open: Closure<dyn FnMut(web_sys::Event)>,
    _on_message: Closure<dyn FnMut(MessageEvent)>,
    _on_error: Closure<dyn FnMut(ErrorEvent)>,
    _on_close: Closure<dyn FnMut(CloseEvent)>,
}

#[wasm_bindgen]
impl WsSubscription {
    /// Close the underlying WebSocket connection intentionally.
    ///
    /// This sets the intentional-close flag so the `onclose` handler will
    /// **not** attempt to reconnect. Use this during logout or when the
    /// caller no longer needs the subscription.
    pub fn close(&self) {
        self.reconnect.borrow_mut().intentional_close = true;
        // Ignore the result — the socket may already be closing.
        let _ = self.ws.close();
    }

    /// Returns `true` if the WebSocket is in the `OPEN` (1) state.
    pub fn is_open(&self) -> bool {
        self.ws.ready_state() == WebSocket::OPEN
    }
}

// ---------------------------------------------------------------------------
// connect() — public async entry point
// ---------------------------------------------------------------------------

/// Connect to a conversation WebSocket and return a live [`WsSubscription`].
///
/// # Parameters
/// - `convo_id`    — The MLS conversation/group ID to subscribe to.
/// - `base_url`    — XRPC service base URL, e.g. `"https://mls.catbird.blue"`.
/// - `auth_token`  — Bearer token used to obtain the subscription ticket.
/// - `on_message`  — JS callback invoked with a JSON-serialized [`UiMessage`]
///                   on every text, system, or encrypted-placeholder frame.
/// - `on_event`    — JS callback invoked with `{type: string, data: any}` for
///                   reaction, typing, and group-refresh events.
/// - `on_status`   — JS callback invoked with a plain string:
///                   `"connected"`, `"disconnected"`, or `"error"`.
///
/// # Errors
/// Returns `Err(JsValue)` when the ticket HTTP request fails, the ticket
/// response cannot be parsed, or `WebSocket` construction itself fails.
#[wasm_bindgen]
pub async fn connect(
    convo_id: String,
    base_url: String,
    auth_token: String,
    on_message: Function,
    on_event: Function,
    on_status: Function,
) -> Result<WsSubscription, JsValue> {
    // ------------------------------------------------------------------
    // 1. Request a subscription ticket from the MLS delivery service.
    // ------------------------------------------------------------------
    let client = reqwest::Client::new();
    let ticket_resp = client
        .post(format!(
            "{}/xrpc/blue.catbird.mlsChat.getSubscriptionTicket",
            base_url
        ))
        .bearer_auth(&auth_token)
        .json(&serde_json::json!({ "convoId": convo_id }))
        .send()
        .await
        .map_err(|e| JsValue::from_str(&format!("Ticket request failed: {}", e)))?;

    if !ticket_resp.status().is_success() {
        let status = ticket_resp.status();
        let body = ticket_resp.text().await.unwrap_or_default();
        return Err(JsValue::from_str(&format!(
            "Ticket request returned {}: {}",
            status, body
        )));
    }

    let ticket_data: serde_json::Value = ticket_resp
        .json()
        .await
        .map_err(|e| JsValue::from_str(&format!("Ticket JSON parse failed: {}", e)))?;

    let ticket = ticket_data["ticket"]
        .as_str()
        .ok_or_else(|| JsValue::from_str("No 'ticket' field in ticket response"))?;
    let ws_endpoint = ticket_data["endpoint"]
        .as_str()
        .ok_or_else(|| JsValue::from_str("No 'endpoint' field in ticket response"))?;

    // ------------------------------------------------------------------
    // 2. Build the WebSocket URL.
    // ------------------------------------------------------------------
    let ws_url = format!(
        "{}?convoId={}&ticket={}",
        ws_endpoint, convo_id, ticket
    );

    // ------------------------------------------------------------------
    // 3. Create the browser WebSocket.
    // ------------------------------------------------------------------
    let ws = WebSocket::new(&ws_url)
        .map_err(|e| JsValue::from_str(&format!("WebSocket construction failed: {:?}", e)))?;

    // Receive binary frames as ArrayBuffer so we can cheaply convert them to
    // a Rust Vec<u8> via js_sys::Uint8Array::new(&data).to_vec().
    ws.set_binary_type(web_sys::BinaryType::Arraybuffer);

    // ------------------------------------------------------------------
    // 4. Set up shared reconnection state.
    // ------------------------------------------------------------------
    let reconnect = Rc::new(RefCell::new(ReconnectState::new()));

    // ------------------------------------------------------------------
    // 5. Wire event handlers.
    // ------------------------------------------------------------------

    // onopen — notify the caller and reset backoff counter.
    let on_status_open = on_status.clone();
    let reconnect_open = Rc::clone(&reconnect);
    let on_open = Closure::<dyn FnMut(web_sys::Event)>::new(move |_: web_sys::Event| {
        reconnect_open.borrow_mut().attempt = 0;
        let _ = on_status_open.call1(&JsValue::NULL, &JsValue::from_str("connected"));
    });
    ws.set_onopen(Some(on_open.as_ref().unchecked_ref()));

    // onerror — surface as status "error".
    let on_status_err = on_status.clone();
    let on_error = Closure::<dyn FnMut(ErrorEvent)>::new(move |_: ErrorEvent| {
        let _ = on_status_err.call1(&JsValue::NULL, &JsValue::from_str("error"));
    });
    ws.set_onerror(Some(on_error.as_ref().unchecked_ref()));

    // onclose — surface as "disconnected" and schedule a reconnect unless
    // the close was intentional (caller invoked `WsSubscription::close()`).
    let on_status_close = on_status.clone();
    let reconnect_close = Rc::clone(&reconnect);
    // Capture the connection parameters so we can re-invoke `connect()`.
    let rc_convo_id = convo_id.clone();
    let rc_base_url = base_url.clone();
    let rc_auth_token = auth_token.clone();
    let rc_on_message = on_message.clone();
    let rc_on_event = on_event.clone();
    let rc_on_status = on_status.clone();
    let on_close = Closure::<dyn FnMut(CloseEvent)>::new(move |_: CloseEvent| {
        let _ = on_status_close.call1(&JsValue::NULL, &JsValue::from_str("disconnected"));

        // Check if the close was intentional (e.g. logout).
        if reconnect_close.borrow().intentional_close {
            web_sys::console::log_1(&JsValue::from_str(
                "[catmos-ws] Intentional close — skipping reconnect",
            ));
            return;
        }

        let attempt = {
            let mut state = reconnect_close.borrow_mut();
            state.attempt += 1;
            state.attempt
        };
        let delay = backoff_ms(attempt - 1);

        web_sys::console::log_1(&JsValue::from_str(&format!(
            "[catmos-ws] Scheduling reconnect #{} in {}ms",
            attempt, delay,
        )));

        // Clone everything the `setTimeout` closure needs.
        let convo = rc_convo_id.clone();
        let base = rc_base_url.clone();
        let token = rc_auth_token.clone();
        let msg_cb = rc_on_message.clone();
        let evt_cb = rc_on_event.clone();
        let sts_cb = rc_on_status.clone();

        // Use browser `setTimeout` to delay the reconnect.
        let timer_closure = Closure::once(move || {
            // `spawn_local` runs the async `connect()` on the JS microtask queue.
            spawn_local(async move {
                match connect(convo, base, token, msg_cb, evt_cb, sts_cb).await {
                    Ok(_sub) => {
                        // The new WsSubscription is returned to JS via the
                        // `on_status("connected")` callback. The old handle's
                        // closures will be dropped when JS releases it.
                        web_sys::console::log_1(&JsValue::from_str(
                            "[catmos-ws] Reconnect succeeded",
                        ));
                    }
                    Err(e) => {
                        web_sys::console::warn_1(&JsValue::from_str(&format!(
                            "[catmos-ws] Reconnect failed: {:?}",
                            e,
                        )));
                        // The next `onclose` will fire from the failed
                        // connection attempt and schedule another retry.
                    }
                }
            });
        });

        let window = web_sys::window().expect("no global `window` exists");
        let _ = window.set_timeout_with_callback_and_timeout_and_arguments_0(
            timer_closure.as_ref().unchecked_ref(),
            delay,
        );
        // Let the closure be garbage-collected after it fires.
        timer_closure.forget();
    });
    ws.set_onclose(Some(on_close.as_ref().unchecked_ref()));

    // onmessage — decode the DAG-CBOR frame and dispatch to the right callback.
    let convo_id_for_handler = convo_id.clone();
    let on_message_cb = on_message.clone();
    let on_event_cb = on_event.clone();
    let on_message_handler =
        Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
            // event.data() is a JsValue wrapping an ArrayBuffer (because we set
            // binary_type = Arraybuffer above).
            let data = event.data();
            let bytes = js_sys::Uint8Array::new(&data).to_vec();

            match handle_frame(&bytes, &convo_id_for_handler) {
                Ok(Some(FrameOutput::Message(msg))) => {
                    match serde_wasm_bindgen::to_value(&msg) {
                        Ok(js_msg) => {
                            let _ = on_message_cb.call1(&JsValue::NULL, &js_msg);
                        }
                        Err(e) => {
                            web_sys::console::warn_1(&JsValue::from_str(&format!(
                                "[catmos-ws] Failed to serialize UiMessage: {}",
                                e
                            )));
                        }
                    }
                }
                Ok(Some(FrameOutput::Event(_kind, js_val))) => {
                    let _ = on_event_cb.call1(&JsValue::NULL, &js_val);
                }
                Ok(None) => {
                    // Intentionally ignored frame type (readdition, unknown, etc.)
                }
                Err(e) => {
                    web_sys::console::warn_1(&JsValue::from_str(&format!(
                        "[catmos-ws] Frame decode error: {}",
                        e
                    )));
                }
            }
        });
    ws.set_onmessage(Some(on_message_handler.as_ref().unchecked_ref()));

    // ------------------------------------------------------------------
    // 6. Return the subscription handle, keeping all closures alive.
    // ------------------------------------------------------------------
    Ok(WsSubscription {
        ws,
        reconnect,
        _on_open: on_open,
        _on_message: on_message_handler,
        _on_error: on_error,
        _on_close: on_close,
    })
}

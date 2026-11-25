use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use catbird_mls::payload_types::{MLSMessagePayload, MLSMessageType};
use petrel::xrpc::{CallOptions, XrpcBody, XrpcClient};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tauri::{Emitter, Manager, State};
use tauri_plugin_shell::ShellExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::auth::{AuthFailure, DesktopAuth, SessionSigner, SignedIn};
use crate::recovery::actionable_error;
use crate::{AppState, WsHandle};

fn log_file_path() -> std::path::PathBuf {
    let base = dirs::cache_dir()
        .or_else(dirs::data_local_dir)
        .unwrap_or_else(std::env::temp_dir);
    base.join("catmos").join("catmos.log")
}

async fn cleanup_ws_handle(
    handles: &Arc<tokio::sync::Mutex<std::collections::HashMap<String, WsHandle>>>,
    key: &str,
    owner: &tokio::sync::watch::Sender<bool>,
) {
    let mut handles = handles.lock().await;
    if handles.get(key).is_some_and(|handle| handle.owns(owner)) {
        handles.remove(key);
    }
}

pub(crate) fn append_log_line(line: &str) {
    eprint!("{}", line);
    let path = log_file_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        use std::io::Write;
        let _ = f.write_all(line.as_bytes());
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileView {
    pub did: String,
    pub handle: String,
    pub display_name: Option<String>,
    pub avatar: Option<String>,
}

macro_rules! log_catmos {
    ($($arg:tt)*) => {
        let msg = format!($($arg)*);
        let ts = chrono::Local::now().format("%H:%M:%S%.3f");
        let line = format!("[catmos {}] {}\n", ts, msg);
        crate::commands::append_log_line(&line);
    };
}

fn spawn_unified_kp_monitor(
    mgr: Arc<crate::mls::TauriMlsManager>,
    did: String,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            let mgr_tick = mgr.clone();
            let did_tick = did.clone();
            let _ = tokio::task::spawn_blocking(move || {
                if let Err(e) = mgr_tick.replenish_key_packages(&did_tick, 10) {
                    log_catmos!("Unified key package replenishment warning: {}", e);
                }
                let _ = mgr_tick.flush_labyrinth_queue(&did_tick);
            })
            .await;
        }
    })
}

async fn start_kp_monitor(state: &AppState, did: String) {
    let mut guard = state.kp_monitor.lock().await;
    if let Some(handle) = guard.take() {
        handle.abort();
    }
    *guard = Some(spawn_unified_kp_monitor(state.mls_manager.clone(), did));
}

fn spawn_unified_sync_loop(
    mgr: Arc<crate::mls::TauriMlsManager>,
    did: String,
) -> tokio::task::JoinHandle<()> {
    use catbird_mls::constants::SYNC_INTERVAL_SECS;
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(SYNC_INTERVAL_SECS)).await;
            let mgr_tick = mgr.clone();
            let did_tick = did.clone();
            let _ = tokio::task::spawn_blocking(move || {
                if let Err(e) = mgr_tick.sync(&did_tick) {
                    tracing::debug!("Unified sync cycle warning: {}", e);
                }
            })
            .await;
        }
    })
}

async fn start_sync_loop(state: &AppState, did: String) {
    let mut guard = state.sync_loop.lock().await;
    if let Some(handle) = guard.take() {
        handle.abort();
    }
    *guard = Some(spawn_unified_sync_loop(state.mls_manager.clone(), did));
}

async fn stop_background_tasks_and_subscriptions(state: &AppState) {
    if let Some(handle) = state.kp_monitor.lock().await.take() {
        handle.abort();
    }
    if let Some(handle) = state.sync_loop.lock().await.take() {
        handle.abort();
    }
    let mut handles = state.ws_handles.lock().await;
    for (_, handle) in handles.drain() {
        let _ = handle.shutdown.send(true);
    }
}

fn require_authenticated_did(state: &AppState) -> Result<String, String> {
    if let Some(did) = state.current_did() {
        if !did.trim().is_empty() {
            return Ok(did);
        }
    }
    crate::native_keyring::entry("catmos", "user_did")
        .and_then(|e| e.get_password())
        .map_err(|_| "Not authenticated".to_string())
        .and_then(|d| {
            if d.trim().is_empty() {
                Err("Not authenticated".to_string())
            } else {
                Ok(d)
            }
        })
}

/// The OAuth client and the DID of the account signed in to it.
fn require_session(state: &AppState) -> Result<(Arc<DesktopAuth>, String), String> {
    let did = state
        .current_did()
        .filter(|did| !did.trim().is_empty())
        .ok_or_else(|| "Not authenticated".to_string())?;
    Ok((state.auth()?, did))
}

fn extract_message_text_and_type(plaintext_json: &str) -> (String, String) {
    if let Ok(payload) = serde_json::from_str::<MLSMessagePayload>(plaintext_json) {
        if payload.message_type == MLSMessageType::System {
            let display_text = match payload.text.as_deref() {
                Some("history_boundary.new_member") => "You joined this conversation".to_string(),
                Some("history_boundary.device_rejoined") => {
                    "Messages before this point aren't available on this device".to_string()
                }
                Some(other) => other.to_string(),
                None => String::new(),
            };
            return ("system".to_string(), display_text);
        }
        if let Some(embed) = payload.embed.as_ref() {
            if embed.as_image().is_some() {
                return ("image".to_string(), payload.text.unwrap_or_default());
            }
            if embed.as_audio().is_some() {
                return (
                    "voice".to_string(),
                    payload.text.unwrap_or_else(|| "Voice message".to_string()),
                );
            }
        }
        return ("text".to_string(), payload.text.unwrap_or_default());
    }
    if let Ok(val) = serde_json::from_str::<serde_json::Value>(plaintext_json) {
        let msg_type = val
            .get("messageType")
            .or_else(|| val.get("type"))
            .and_then(|v| v.as_str())
            .unwrap_or("text")
            .to_string();
        let text = val
            .get("text")
            .or_else(|| val.get("content"))
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .unwrap_or_else(|| plaintext_json.to_string());
        return (msg_type, text);
    }
    ("text".to_string(), plaintext_json.to_string())
}

fn rfc3339_from_ms(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms)
        .unwrap_or_else(chrono::Utc::now)
        .to_rfc3339()
}

pub(crate) fn ui_message_from_row(row: catbird_mls::storage::MessageRow) -> Message {
    let mut image: Option<ImageAttachment> = None;
    let mut audio: Option<AudioAttachment> = None;
    let mut display_embed: Option<serde_json::Value> = None;
    let mut message_type = "text".to_string();
    let content: String;

    if let Ok(payload) = serde_json::from_str::<MLSMessagePayload>(&row.plaintext_json) {
        if payload.message_type == MLSMessageType::System {
            message_type = "system".to_string();
            content = match payload.text.as_deref() {
                Some("history_boundary.new_member") => "You joined this conversation".to_string(),
                Some("history_boundary.device_rejoined") => {
                    "Messages before this point aren't available on this device".to_string()
                }
                Some(other) => other.to_string(),
                None => String::new(),
            };
        } else if let Some(embed) = payload.embed {
            if let Some(img) = embed.as_image() {
                message_type = "image".to_string();
                content = payload.text.unwrap_or_default();
                image = Some(ImageAttachment {
                    blob_id: img.blob_id,
                    key_b64: B64.encode(&img.key),
                    iv_b64: B64.encode(&img.iv),
                    sha256: img.sha256,
                    content_type: img.content_type,
                    size: img.size,
                    width: img.width,
                    height: img.height,
                    alt_text: img.alt_text,
                    blurhash: img.blurhash,
                });
            } else if let Some(aud) = embed.as_audio() {
                message_type = "voice".to_string();
                content = payload.text.unwrap_or_default();
                let key_b64 = B64.encode(&aud.key);
                let iv_b64 = B64.encode(&aud.iv);
                audio = Some(AudioAttachment {
                    blob_id: aud.blob_id,
                    key: aud.key,
                    iv: aud.iv,
                    key_b64,
                    iv_b64,
                    sha256: aud.sha256,
                    content_type: aud.content_type,
                    size: aud.size,
                    duration_ms: aud.duration_ms,
                    waveform: aud.waveform,
                    transcript: aud.transcript,
                });
            } else {
                display_embed = display_embed_json(&embed);
                content = payload.text.unwrap_or_default();
            }
        } else {
            content = payload.text.unwrap_or_default();
        }
    } else {
        let (mt, txt) = extract_message_text_and_type(&row.plaintext_json);
        message_type = mt;
        content = txt;
    }

    let audio_attachment = audio.clone();
    Message {
        id: row.message_id,
        conversation_id: row.conversation_id,
        sender_did: row.sender_did,
        sender_handle: String::new(),
        content,
        timestamp: rfc3339_from_ms(row.created_at_ms),
        sequence_number: row.seq.max(0) as u64,
        status: if row.is_own {
            "sent".to_string()
        } else {
            "delivered".to_string()
        },
        is_own: Some(row.is_own),
        message_type,
        image,
        audio,
        audio_attachment,
        embed: display_embed,
    }
}

/// Embed kinds the UI renders as cards. Everything else (images, audio,
/// group invitations) has a dedicated projection or none.
const DISPLAY_EMBED_KINDS: [&str; 3] = ["post", "link", "gif"];

fn display_embed_json(
    embed: &catbird_mls::payload_types::MLSEmbedData,
) -> Option<serde_json::Value> {
    if !DISPLAY_EMBED_KINDS.contains(&embed.kind.as_str()) || !embed.data.is_object() {
        return None;
    }
    Some(serde_json::json!({ "type": embed.kind, "data": embed.data }))
}

fn ui_conversation_from_row(
    row: catbird_mls::storage::ConversationRow,
    members: Vec<String>,
    meta: Option<catbird_mls::storage::GroupMetadataRow>,
    last_msg: Option<catbird_mls::storage::MessageRow>,
) -> Conversation {
    let meta_title = meta
        .as_ref()
        .and_then(|m| m.title.clone())
        .filter(|s| !s.trim().is_empty());
    let row_title = row.title.filter(|s| !s.trim().is_empty());
    let display_name = meta_title.or(row_title).unwrap_or_else(|| {
        if members.is_empty() {
            row.conversation_id.clone()
        } else {
            members.join(", ")
        }
    });
    let description = meta
        .as_ref()
        .and_then(|m| m.description.clone())
        .filter(|s| !s.trim().is_empty());
    let (last_message, last_message_at) = match last_msg {
        Some(m) => {
            let (_mt, txt) = extract_message_text_and_type(&m.plaintext_json);
            (Some(txt), Some(rfc3339_from_ms(m.created_at_ms)))
        }
        None => (None, None),
    };
    let is_group = members.len() > 2 || meta.is_some();
    Conversation {
        id: row.conversation_id,
        group_id: hex::encode(&row.group_id),
        display_name,
        description,
        members,
        last_message,
        last_message_at,
        unread_count: row.unread_count.max(0) as u32,
        is_group,
        avatar_data_url: None,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthResponse {
    pub did: String,
    pub handle: String,
    pub display_name: Option<String>,
    pub avatar: Option<String>,
    #[serde(default)]
    pub granted_scopes: Vec<String>,
}

fn clear_saved_session_credentials() {
    for key in ["session_id", "user_did", "chat_dpop_jkt"] {
        if let Ok(entry) = crate::native_keyring::entry("catmos", key) {
            let _ = entry.delete_credential();
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Conversation {
    pub id: String,
    pub group_id: String,
    pub display_name: String,
    pub description: Option<String>,
    pub members: Vec<String>,
    pub last_message: Option<String>,
    pub last_message_at: Option<String>,
    pub unread_count: u32,
    pub is_group: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_data_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Message {
    pub id: String,
    pub conversation_id: String,
    pub sender_did: String,
    pub sender_handle: String,
    pub content: String,
    pub timestamp: String,
    #[serde(default)]
    pub sequence_number: u64,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_own: Option<bool>,
    #[serde(default = "default_message_type")]
    pub message_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<ImageAttachment>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audio: Option<AudioAttachment>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audio_attachment: Option<AudioAttachment>,
    /// Display-only rich embed (`post`, `link`, `gif`) in the Catbird wire
    /// shape `{"type": kind, "data": {...snake_case...}}`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embed: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageAttachment {
    pub blob_id: String,
    pub key_b64: String,
    pub iv_b64: String,
    pub sha256: String,
    pub content_type: String,
    pub size: usize,
    pub width: u32,
    pub height: u32,
    pub alt_text: Option<String>,
    pub blurhash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AudioAttachment {
    pub blob_id: String,
    pub key: Vec<u8>,
    pub iv: Vec<u8>,
    pub key_b64: String,
    pub iv_b64: String,
    pub sha256: String,
    pub content_type: String,
    pub size: u64,
    pub duration_ms: u64,
    pub waveform: Vec<f32>,
    pub transcript: Option<String>,
}

fn default_message_type() -> String {
    "text".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupMember {
    pub did: String,
    pub handle: String,
    pub display_name: Option<String>,
    pub role: String,
}

fn classify_pds_spaces_probe_response(status: u16, body: &[u8]) -> bool {
    let err_code = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_owned));
    if matches!(
        err_code.as_deref(),
        Some("XRPCNotSupported" | "MethodNotImplemented")
    ) {
        return false;
    }
    status == 200 || status == 400
}

const CALLBACK_PAGE_SIGNED_IN: &str = r#"<!DOCTYPE html><html><body style="font-family:system-ui;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#1a1a2e;color:#e0e0e0"><div style="text-align:center"><h1>Almost there</h1><p>You can close this tab and return to Catmos.</p></div></body></html>"#;
const CALLBACK_PAGE_CANCELLED: &str = r#"<!DOCTYPE html><html><body style="font-family:system-ui;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#1a1a2e;color:#e0e0e0"><div style="text-align:center"><h1>Sign-in cancelled</h1><p>You can close this tab and return to Catmos.</p></div></body></html>"#;

/// What the callback listener makes of one request line's query string.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CallbackQuery {
    /// Not an answer to this sign-in: keep listening.
    Ignore,
    /// The authorization server's answer, to hand to the OAuth client.
    Answer { denied: bool },
}

/// Accepts only a callback that names this sign-in's `state`. Anything else
/// on the loopback port (another local process, a stale tab) is ignored, so
/// it cannot end the wait.
pub(crate) fn classify_callback_query(query: &str, expected_state: &str) -> CallbackQuery {
    let mut state_matches = false;
    let mut has_code = false;
    let mut has_error = false;
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        match key.as_ref() {
            "state" => state_matches = value == expected_state,
            "code" => has_code = !value.is_empty(),
            "error" => has_error = !value.is_empty(),
            _ => {}
        }
    }
    if !state_matches || !(has_code || has_error) {
        return CallbackQuery::Ignore;
    }
    CallbackQuery::Answer { denied: has_error }
}

/// Waits for the browser to deliver the authorization server's answer and
/// returns its query string unchanged.
async fn wait_for_callback(listener: TcpListener, expected_state: &str) -> Result<String, String> {
    const MAX_REQUEST_SIZE: usize = 8192;

    loop {
        let (mut stream, _) = listener
            .accept()
            .await
            .map_err(|e| format!("Accept failed: {}", e))?;

        let mut buf = vec![0u8; MAX_REQUEST_SIZE];
        let mut total = 0;
        let complete = loop {
            if total >= MAX_REQUEST_SIZE {
                break false;
            }
            match stream.read(&mut buf[total..]).await {
                Ok(0) | Err(_) => break false,
                Ok(n) => total += n,
            }
            if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
                break true;
            }
        };

        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut req = httparse::Request::new(&mut headers);
        let answer = if complete && req.parse(&buf[..total]).is_ok() {
            req.path
                .and_then(|path| path.split_once('?'))
                .filter(|(route, _)| *route == "/callback")
                .map(|(_, query)| {
                    (
                        query.to_string(),
                        classify_callback_query(query, expected_state),
                    )
                })
        } else {
            None
        };

        let Some((query, CallbackQuery::Answer { denied })) = answer else {
            let not_found =
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            let _ = stream.write_all(not_found.as_bytes()).await;
            let _ = stream.flush().await;
            continue;
        };

        let html = if denied {
            CALLBACK_PAGE_CANCELLED
        } else {
            CALLBACK_PAGE_SIGNED_IN
        };
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nReferrer-Policy: no-referrer\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            html.len(),
            html
        );
        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.flush().await;
        return Ok(query);
    }
}

/// Opens the account's sign-in page in the browser and finishes the flow in
/// the background. The UI hears the result as `oauth-signed-in` or
/// `oauth-error`. Starting another sign-in, [`cancel_login`] or [`logout`]
/// makes this flow stale: it then stops waiting, emits nothing and never
/// activates its account, even if the browser tab is still completed.
#[tauri::command]
pub async fn start_login(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    identifier: String,
) -> Result<(), String> {
    let auth = state.auth().map_err(actionable_error)?;

    let generation = {
        let _gate = state.login_gate.lock().await;
        state.invalidate_pending_login()
    };
    let mut current = state.login_generation.subscribe();

    let bind_port = auth.fixed_callback_port().unwrap_or(0);
    let listener = bind_callback_listener(bind_port).await?;
    let port = listener
        .local_addr()
        .map_err(|e| format!("Failed to get port: {}", e))?
        .port();

    let flow = auth
        .begin_login(&identifier, port)
        .await
        .map_err(actionable_error)?;

    #[allow(deprecated)]
    {
        if let Err(e) = app.shell().open(flow.authorize_url.as_str(), None) {
            auth.cancel_login(&flow.state).await;
            return Err(e.to_string());
        }
    }

    let app_handle = app.clone();
    tokio::spawn(async move {
        let waited = tokio::select! {
            waited = tokio::time::timeout(
                std::time::Duration::from_secs(300),
                wait_for_callback(listener, &flow.state),
            ) => waited,
            () = async { let _ = current.wait_for(|latest| *latest != generation).await; } => {
                auth.cancel_login(&flow.state).await;
                return;
            }
        };
        let is_current =
            |current: &tokio::sync::watch::Receiver<u64>| *current.borrow() == generation;
        let outcome = match waited {
            Ok(Ok(query)) if is_current(&current) => auth.finish_login(&query).await,
            Ok(Ok(_)) => {
                auth.cancel_login(&flow.state).await;
                return;
            }
            Ok(Err(e)) => {
                auth.cancel_login(&flow.state).await;
                Err(e)
            }
            Err(_) => {
                auth.cancel_login(&flow.state).await;
                Err("Login timed out".to_string())
            }
        };
        let state = app_handle.state::<AppState>();
        let _gate = state.login_gate.lock().await;
        if !is_current(&current) {
            // Cancelled while the authorization was being completed: drop the
            // session it just stored rather than leave it for the next launch.
            if let Ok(signed_in) = &outcome {
                if let Err(e) = auth.logout(&signed_in.did).await {
                    log_catmos!("A cancelled sign-in could not clear its session: {}", e);
                }
            }
            return;
        }
        match outcome {
            Ok(signed_in) => {
                let response = activate_session(&state, &auth, signed_in).await;
                let _ = app_handle.emit("oauth-signed-in", &response);
            }
            Err(e) => {
                log_catmos!("OAuth sign-in error: {}", e);
                let _ = app_handle.emit("oauth-error", &actionable_error(e));
            }
        }
    });

    Ok(())
}

/// Binds the loopback callback listener. A fixed port can still be held for a
/// moment by the sign-in this one replaced, which releases it as soon as it
/// sees that it is stale.
async fn bind_callback_listener(port: u16) -> Result<TcpListener, String> {
    let mut attempts = 0;
    loop {
        match TcpListener::bind(("127.0.0.1", port)).await {
            Ok(listener) => return Ok(listener),
            Err(e) if port != 0 && e.kind() == std::io::ErrorKind::AddrInUse && attempts < 20 => {
                attempts += 1;
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            Err(e) => return Err(format!("Failed to bind callback server: {}", e)),
        }
    }
}

/// Abandons the pending desktop sign-in, if any. A browser tab that is still
/// completed afterwards signs no one in.
#[tauri::command]
pub async fn cancel_login(state: State<'_, AppState>) -> Result<(), String> {
    let _gate = state.login_gate.lock().await;
    state.invalidate_pending_login();
    Ok(())
}

/// Whether the account's server implements Spaces. A server that does
/// answers a request with no `space` parameter with 400, not "not supported".
#[tauri::command]
pub async fn labyrinth_probe_pds_spaces(state: State<'_, AppState>) -> Result<bool, String> {
    let Ok((auth, did)) = require_session(&state) else {
        return Ok(false);
    };
    let response = match auth
        .pds_exchange(
            &did,
            http::Method::GET,
            "com.atproto.space.getSpace",
            Vec::new(),
            http::HeaderMap::new(),
            None,
        )
        .await
    {
        Ok(response) => response,
        Err(_) => return Ok(false),
    };
    Ok(classify_pds_spaces_probe_response(
        response.status().as_u16(),
        response.body(),
    ))
}

#[tauri::command]
pub async fn labyrinth_sync_backfill(
    state: State<'_, AppState>,
    did: String,
) -> Result<Option<catbird_mls::client::LabyrinthBackupStatus>, String> {
    let mgr = state.mls_manager.clone();
    tokio::task::spawn_blocking(move || {
        match mgr.restore_archived_conversations(&did) {
            Ok(summary) => {
                log_catmos!(
                    "labyrinth_sync_backfill: discovered={}, restored_convos={}, restored_msgs={}, errors={:?}",
                    summary.conversations_discovered,
                    summary.conversations_restored,
                    summary.messages_restored,
                    summary.errors
                );
            }
            Err(e) => {
                log_catmos!("labyrinth_sync_backfill archive restore warning: {e}");
            }
        }
        if let Err(e) = mgr.flush_labyrinth_queue(&did) {
            log_catmos!("labyrinth_sync_backfill flush warning: {e}");
        }
        mgr.status(&did)
    })
    .await
    .map_err(|e| format!("task join error: {e}"))?
}

#[tauri::command]
pub async fn labyrinth_restore_archived_conversations(
    state: State<'_, AppState>,
    did: String,
) -> Result<crate::mls::LabyrinthArchiveRestoreSummary, String> {
    let mgr = state.mls_manager.clone();
    let summary = tokio::task::spawn_blocking(move || mgr.restore_archived_conversations(&did))
        .await
        .map_err(|e| format!("task join error: {e}"))??;
    log_catmos!(
        "labyrinth_restore_archived_conversations: discovered={}, restored_convos={}, restored_msgs={}, errors={:?}",
        summary.conversations_discovered,
        summary.conversations_restored,
        summary.messages_restored,
        summary.errors
    );
    Ok(summary)
}

#[tauri::command]
pub async fn labyrinth_restore_conversation_history(
    state: State<'_, AppState>,
    did: String,
    conversation_id: String,
) -> Result<u32, String> {
    let mgr = state.mls_manager.clone();
    let cid = conversation_id.trim().to_string();
    let count = tokio::task::spawn_blocking(move || {
        mgr.restore_conversation_from_owner_mailbox(&did, &cid)
    })
    .await
    .map_err(|e| format!("task join error: {e}"))??;
    log_catmos!(
        "labyrinth_restore_conversation_history: convo={}, restored_msgs={}",
        conversation_id.trim(),
        count
    );
    Ok(count)
}

/// Binds the app to a signed-in account: the transport signs with its
/// session, and background sync starts if the account has opted in.
async fn activate_session(
    state: &AppState,
    auth: &Arc<DesktopAuth>,
    signed_in: SignedIn,
) -> AuthResponse {
    state.set_session_did(signed_in.did.clone());
    state
        .mls_manager
        .set_account_did(Some(signed_in.did.clone()));
    state.mls_manager.set_account_auth(Some((
        signed_in.pds.clone(),
        Arc::new(SessionSigner::new(Arc::clone(auth), signed_in.did.clone())),
    )));

    // ctl #2: Chat/Spaces is strictly OFF by default on fresh sign-ins.
    if state.mls_manager.is_opted_in(&signed_in.did) {
        let mgr = state.mls_manager.clone();
        let did_for_sync = signed_in.did.clone();
        let _ = tokio::task::spawn_blocking(move || {
            if let Err(e) = mgr.sync(&did_for_sync) {
                log_catmos!("Initial unified MLS sync warning: {}", e);
            }
        })
        .await;
        start_kp_monitor(state, signed_in.did.clone()).await;
        start_sync_loop(state, signed_in.did.clone()).await;
    }

    if let Ok(entry) = crate::native_keyring::entry("catmos", "user_did") {
        let _ = entry.set_password(&signed_in.did);
    }

    AuthResponse {
        did: signed_in.did,
        handle: signed_in.handle,
        display_name: None,
        avatar: None,
        granted_scopes: signed_in.granted_scopes,
    }
}

fn sign_out_locally(state: &AppState) {
    state.mls_manager.set_account_did(None);
    state.mls_manager.set_account_auth(None);
    state.clear_session_auth();
    clear_saved_session_credentials();
}

#[tauri::command]
pub async fn try_restore_session(
    state: State<'_, AppState>,
) -> Result<Option<AuthResponse>, String> {
    // A session id from the gateway this app used to sign in through is of
    // no use to the direct client. Dropping it means one more sign-in.
    if let Ok(entry) = crate::native_keyring::entry("catmos", "session_id") {
        let _ = entry.delete_credential();
    }

    let auth = state.auth().map_err(actionable_error)?;
    match auth.restore().await {
        Ok(Some(signed_in)) => {
            log_catmos!("Restoring session for DID: {}", signed_in.did);
            let response = activate_session(&state, &auth, signed_in).await;
            log_catmos!("Session restored: handle={}", response.handle);
            Ok(Some(response))
        }
        Ok(None) => Ok(None),
        Err(AuthFailure::SignedOut(reason)) => {
            log_catmos!(
                "Stored session is no longer usable; clearing saved login: {}",
                reason
            );
            sign_out_locally(&state);
            Ok(None)
        }
        Err(AuthFailure::Retryable(reason)) => {
            log_catmos!(
                "Stored session could not be restored yet; keeping saved login: {}",
                reason
            );
            Err(actionable_error(reason))
        }
    }
}

#[tauri::command]
pub async fn logout(state: State<'_, AppState>) -> Result<(), String> {
    {
        let _gate = state.login_gate.lock().await;
        state.invalidate_pending_login();
    }
    stop_background_tasks_and_subscriptions(&state).await;
    if let Ok(did) = require_authenticated_did(&state) {
        let mgr = state.mls_manager.clone();
        let did_for_wipe = did.clone();
        let _ = tokio::task::spawn_blocking(move || {
            let _ = mgr.sign_out_and_wipe(&did_for_wipe);
        })
        .await;
        if let Ok(auth) = state.auth() {
            if let Err(e) = auth.logout(&did).await {
                log_catmos!("Sign-out could not clear the saved session: {}", e);
            }
        }
    }
    sign_out_locally(&state);
    Ok(())
}

#[tauri::command]
pub async fn retire_current_device(
    state: State<'_, AppState>,
    did: Option<String>,
) -> Result<(), String> {
    let target_did = match did.filter(|d| !d.trim().is_empty()) {
        Some(d) => d,
        None => require_authenticated_did(&state)?,
    };
    if !state.mls_manager.is_opted_in(&target_did) {
        return Ok(());
    }
    let mgr = state.mls_manager.clone();
    tokio::task::spawn_blocking(move || mgr.retire_current_device(&target_did))
        .await
        .map_err(|e| format!("task join error: {e}"))?
        .map_err(actionable_error)
}

/// Fail-closed account deletion (`D-3`): executes remote Space/PDS/DS deletion FIRST.
/// If any remote delete fails, returns `Err` BEFORE tearing down background tasks,
/// session credentials, OS keyring entries, or local encrypted SQLite state.
#[tauri::command]
pub async fn delete_account_data(
    state: State<'_, AppState>,
    did: Option<String>,
) -> Result<(), String> {
    let target_did = match did.filter(|d| !d.trim().is_empty()) {
        Some(d) => d,
        None => require_authenticated_did(&state)?,
    };
    if state.mls_manager.is_opted_in(&target_did) {
        let mgr = state.mls_manager.clone();
        let did_for_delete = target_did.clone();
        tokio::task::spawn_blocking(move || mgr.delete_account_data(&did_for_delete))
            .await
            .map_err(|e| format!("task join error: {e}"))?
            .map_err(actionable_error)?;
    }

    stop_background_tasks_and_subscriptions(&state).await;
    if let Ok(auth) = state.auth() {
        if let Err(e) = auth.logout(&target_did).await {
            log_catmos!("Account deletion could not clear the saved session: {}", e);
        }
    }
    sign_out_locally(&state);
    Ok(())
}

#[tauri::command]
pub async fn get_conversations(state: State<'_, AppState>) -> Result<Vec<Conversation>, String> {
    let did = require_authenticated_did(&state)?;
    if !state.mls_manager.is_opted_in(&did) {
        return Ok(vec![]);
    }

    let mgr = state.mls_manager.clone();
    let rows = tokio::task::spawn_blocking(move || {
        if let Err(e) = mgr.sync(&did) {
            log_catmos!(" unified sync warning in get_conversations: {}", e);
        }
        mgr.list_conversations_detailed(&did, 100)
    })
    .await
    .map_err(|e| format!("task join error: {e}"))??;

    Ok(rows
        .into_iter()
        .map(|(row, members, meta, last_msg)| {
            ui_conversation_from_row(row, members, meta, last_msg)
        })
        .collect())
}

#[tauri::command]
pub async fn create_group(
    state: State<'_, AppState>,
    name: String,
    member_dids: Vec<String>,
    description: Option<String>,
) -> Result<Conversation, String> {
    let did = require_authenticated_did(&state)?;
    log_catmos!(
        " create_group called: name={}, members={:?}, description={:?}",
        name,
        member_dids,
        description
    );

    let mgr = state.mls_manager.clone();
    let (row, members, meta) = tokio::task::spawn_blocking(move || {
        mgr.create_group_detailed(&did, name, member_dids, description)
    })
    .await
    .map_err(|e| format!("task join error: {e}"))?
    .map_err(|e| {
        log_catmos!(" create_group error: {}", e);
        actionable_error(e)
    })?;

    log_catmos!(
        " create_group success: convo_id={} group_id={}",
        row.conversation_id,
        hex::encode(&row.group_id)
    );
    Ok(ui_conversation_from_row(row, members, meta, None))
}

#[tauri::command]
pub async fn send_message(
    state: State<'_, AppState>,
    conversation_id: String,
    content: String,
) -> Result<Message, String> {
    let did = require_authenticated_did(&state)?;
    log_catmos!(" send_message: convo={}", conversation_id);

    let mgr = state.mls_manager.clone();
    let convo_id = conversation_id.clone();
    let row = tokio::task::spawn_blocking(move || mgr.send_message(&did, &convo_id, &content))
        .await
        .map_err(|e| format!("task join error: {e}"))?
        .map_err(|e| {
            log_catmos!(" send_message error: {}", e);
            actionable_error(e)
        })?;

    Ok(ui_message_from_row(row))
}

#[allow(clippy::too_many_arguments)]
#[tauri::command]
pub async fn send_image(
    state: State<'_, AppState>,
    conversation_id: String,
    content: String,
    data: Vec<u8>,
    content_type: String,
    width: u32,
    height: u32,
    alt_text: Option<String>,
) -> Result<Message, String> {
    let did = require_authenticated_did(&state)?;
    if !content_type.starts_with("image/") {
        return Err(format!("Unsupported image content type: {content_type}"));
    }
    if data.len() > 10 * 1024 * 1024 {
        return Err("Image too large (max 10MB)".to_string());
    }
    log_catmos!(
        " send_image (Space attachment): convo={} bytes={} type={} dims={}x{}",
        conversation_id,
        data.len(),
        content_type,
        width,
        height
    );

    let mgr = state.mls_manager.clone();
    let convo_id = conversation_id.clone();
    let row = tokio::task::spawn_blocking(move || {
        mgr.send_image_message(
            &did,
            &convo_id,
            &content,
            data,
            content_type,
            width,
            height,
            alt_text,
        )
    })
    .await
    .map_err(|e| format!("task join error: {e}"))?
    .map_err(actionable_error)?;

    Ok(ui_message_from_row(row))
}

#[tauri::command]
pub async fn send_voice(
    state: State<'_, AppState>,
    conversation_id: String,
    audio_data: Vec<u8>,
    duration_ms: u64,
    waveform: Vec<f32>,
    content_type: Option<String>,
    transcript: Option<String>,
) -> Result<Message, String> {
    let did = require_authenticated_did(&state)?;
    let _ = transcript;
    if audio_data.is_empty() {
        return Err("Voice recording is empty".to_string());
    }
    if audio_data.len() > 15 * 1024 * 1024 {
        return Err("Voice message too large (max 15MB)".to_string());
    }
    let mime = content_type
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "audio/webm;codecs=opus".to_string());
    log_catmos!(
        " send_voice (Space attachment): convo={} bytes={} duration_ms={} type={}",
        conversation_id,
        audio_data.len(),
        duration_ms,
        mime
    );

    let mgr = state.mls_manager.clone();
    let convo_id = conversation_id.clone();
    let row = tokio::task::spawn_blocking(move || {
        mgr.send_voice_message(&did, &convo_id, audio_data, duration_ms, waveform, mime)
    })
    .await
    .map_err(|e| format!("task join error: {e}"))?
    .map_err(actionable_error)?;

    Ok(ui_message_from_row(row))
}

#[tauri::command]
pub async fn get_image_attachment(
    state: State<'_, AppState>,
    blob_id: String,
    key_b64: String,
    iv_b64: String,
    sha256: String,
    content_type: String,
) -> Result<String, String> {
    let did = require_authenticated_did(&state)?;
    let key = B64
        .decode(key_b64)
        .map_err(|e| format!("Invalid image key: {e}"))?;
    let iv = B64
        .decode(iv_b64)
        .map_err(|e| format!("Invalid image IV: {e}"))?;
    let mgr = state.mls_manager.clone();
    let plaintext = tokio::task::spawn_blocking(move || {
        mgr.download_conversation_attachment(&did, &blob_id, &key, &iv, &sha256)
    })
    .await
    .map_err(|e| format!("task join error: {e}"))?
    .map_err(actionable_error)?;

    Ok(format!(
        "data:{};base64,{}",
        content_type,
        B64.encode(plaintext)
    ))
}

#[tauri::command]
pub async fn fetch_and_decrypt_blob(
    state: State<'_, AppState>,
    blob_id: String,
    key: Option<Vec<u8>>,
    iv: Option<Vec<u8>>,
    key_b64: Option<String>,
    iv_b64: Option<String>,
    sha256: String,
) -> Result<Vec<u8>, String> {
    let did = require_authenticated_did(&state)?;
    let key_bytes = match (key, key_b64) {
        (Some(k), _) => k,
        (None, Some(b64)) => B64
            .decode(b64)
            .map_err(|e| format!("Invalid attachment key base64: {e}"))?,
        (None, None) => return Err("Missing attachment decryption key".to_string()),
    };
    let iv_bytes = match (iv, iv_b64) {
        (Some(v), _) => v,
        (None, Some(b64)) => B64
            .decode(b64)
            .map_err(|e| format!("Invalid attachment IV base64: {e}"))?,
        (None, None) => return Err("Missing attachment decryption IV".to_string()),
    };
    let mgr = state.mls_manager.clone();
    tokio::task::spawn_blocking(move || {
        mgr.download_conversation_attachment(&did, &blob_id, &key_bytes, &iv_bytes, &sha256)
    })
    .await
    .map_err(|e| format!("task join error: {e}"))?
    .map_err(actionable_error)
}

#[tauri::command]
pub async fn get_messages(
    state: State<'_, AppState>,
    conversation_id: String,
    before: Option<String>,
    mark_read: Option<bool>,
) -> Result<Vec<Message>, String> {
    let did = require_authenticated_did(&state)?;
    if !state.mls_manager.is_opted_in(&did) {
        return Ok(vec![]);
    }
    let before_seq = before.and_then(|b| b.parse::<i64>().ok());
    let mgr = state.mls_manager.clone();
    let convo_id = conversation_id.clone();
    let rows = tokio::task::spawn_blocking(move || {
        let listed = mgr.list_messages(&did, &convo_id, before_seq, 50)?;
        if before_seq.is_none() && mark_read.unwrap_or(true) {
            if let Some(max_seq) = listed.iter().map(|r| r.seq).max().filter(|s| *s > 0) {
                let _ = mgr.advance_read_state(&did, &convo_id, max_seq as u64);
            }
        }
        Ok::<_, String>(listed)
    })
    .await
    .map_err(|e| format!("task join error: {e}"))??;

    let mut messages: Vec<Message> = rows.into_iter().map(ui_message_from_row).collect();
    messages.sort_by_key(|m| m.sequence_number);
    Ok(messages)
}

#[tauri::command]
pub async fn get_group_members(
    state: State<'_, AppState>,
    conversation_id: String,
) -> Result<Vec<GroupMember>, String> {
    let did = require_authenticated_did(&state)?;
    if !state.mls_manager.is_opted_in(&did) {
        return Ok(vec![]);
    }
    let mgr = state.mls_manager.clone();
    let members = tokio::task::spawn_blocking(move || mgr.list_members(&did, &conversation_id))
        .await
        .map_err(|e| format!("task join error: {e}"))??;

    Ok(members
        .into_iter()
        .map(|member_did| GroupMember {
            did: member_did,
            handle: String::new(),
            display_name: None,
            role: "member".to_string(),
        })
        .collect())
}

async fn run_unified_sync_subscription(
    app: tauri::AppHandle,
    mgr: std::sync::Arc<crate::mls::TauriMlsManager>,
    did: String,
    target_convo: Option<String>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let mut seen_ids = std::collections::HashSet::<(String, String)>::new();
    {
        let mgr_seed = mgr.clone();
        let did_seed = did.clone();
        let target_seed = target_convo.clone();
        if let Ok(Ok(seeded)) =
            tokio::task::spawn_blocking(move || -> Result<Vec<(String, String)>, String> {
                let mut pairs = Vec::new();
                let convos: Vec<String> = match target_seed {
                    Some(cid) => vec![cid],
                    None => mgr_seed
                        .list_conversations_detailed(&did_seed, 100)?
                        .into_iter()
                        .map(|(row, _, _, _)| row.conversation_id)
                        .collect(),
                };
                for cid in convos {
                    if let Ok(msgs) = mgr_seed.list_messages(&did_seed, &cid, None, 50) {
                        for m in msgs {
                            pairs.push((cid.clone(), m.message_id));
                        }
                    }
                }
                Ok(pairs)
            })
            .await
        {
            seen_ids.extend(seeded);
        }
    }

    loop {
        if *shutdown.borrow() {
            break;
        }
        tokio::select! {
            _ = tokio::time::sleep(std::time::Duration::from_secs(3)) => {},
            _ = shutdown.changed() => {
                break;
            }
        }
        if *shutdown.borrow() {
            break;
        }

        let mgr_tick = mgr.clone();
        let did_tick = did.clone();
        let target_tick = target_convo.clone();
        let sync_res = tokio::task::spawn_blocking(
            move || -> Result<Vec<catbird_mls::storage::MessageRow>, String> {
                let _ = mgr_tick.sync(&did_tick)?;
                let convos: Vec<String> = match target_tick {
                    Some(cid) => vec![cid],
                    None => mgr_tick
                        .list_conversations_detailed(&did_tick, 100)?
                        .into_iter()
                        .map(|(row, _, _, _)| row.conversation_id)
                        .collect(),
                };
                let mut rows = Vec::new();
                for cid in convos {
                    if let Ok(mut msgs) = mgr_tick.list_messages(&did_tick, &cid, None, 20) {
                        msgs.sort_by_key(|m| m.seq);
                        rows.extend(msgs);
                    }
                }
                Ok(rows)
            },
        )
        .await;

        if let Ok(Ok(rows)) = sync_res {
            for row in rows {
                let key = (row.conversation_id.clone(), row.message_id.clone());
                if seen_ids.insert(key) {
                    let cid = row.conversation_id.clone();
                    let ui_msg = ui_message_from_row(row);
                    let _ = app.emit("mls-incoming-message", &ui_msg);
                    let _ = app.emit("mls-refresh-group", &cid);
                }
            }
        }
    }
}

#[tauri::command]
pub async fn subscribe_conversation(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    conversation_id: String,
) -> Result<(), String> {
    {
        let handles = state.ws_handles.lock().await;
        if handles.contains_key(&conversation_id) {
            return Ok(());
        }
    }

    let did = require_authenticated_did(&state)?;
    if !state.mls_manager.is_opted_in(&did) {
        return Ok(());
    }

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let owner = shutdown_tx.clone();
    state.ws_handles.lock().await.insert(
        conversation_id.clone(),
        WsHandle {
            shutdown: shutdown_tx,
        },
    );
    let mgr = state.mls_manager.clone();
    let ws_handles = state.ws_handles.clone();
    let convo_id = conversation_id.clone();
    let task_convo_id = convo_id.clone();
    tokio::spawn(async move {
        run_unified_sync_subscription(app, mgr, did, Some(task_convo_id), shutdown_rx).await;
        cleanup_ws_handle(&ws_handles, &convo_id, &owner).await;
    });
    log_catmos!(
        " subscribe_conversation (unified): convo={}",
        conversation_id
    );
    Ok(())
}

#[tauri::command]
pub async fn unsubscribe_conversation(
    state: State<'_, AppState>,
    conversation_id: String,
) -> Result<(), String> {
    if let Some(handle) = state.ws_handles.lock().await.remove(&conversation_id) {
        let _ = handle.shutdown.send(true);
        log_catmos!(" unsubscribe_conversation: convo={}", conversation_id);
    }
    Ok(())
}

#[tauri::command]
pub async fn subscribe_all_events(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<(), String> {
    const GLOBAL_KEY: &str = "__global__";

    {
        let handles = state.ws_handles.lock().await;
        if handles.contains_key(GLOBAL_KEY) {
            return Ok(());
        }
    }

    let did = require_authenticated_did(&state)?;
    if !state.mls_manager.is_opted_in(&did) {
        return Ok(());
    }

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let owner = shutdown_tx.clone();
    state.ws_handles.lock().await.insert(
        GLOBAL_KEY.to_string(),
        WsHandle {
            shutdown: shutdown_tx,
        },
    );
    let mgr = state.mls_manager.clone();
    let ws_handles = state.ws_handles.clone();
    tokio::spawn(async move {
        run_unified_sync_subscription(app, mgr, did, None, shutdown_rx).await;
        cleanup_ws_handle(&ws_handles, GLOBAL_KEY, &owner).await;
    });
    log_catmos!(" subscribe_all_events (unified): global sync loop opened");
    Ok(())
}

#[tauri::command]
pub async fn unsubscribe_all_events(state: State<'_, AppState>) -> Result<(), String> {
    if let Some(handle) = state.ws_handles.lock().await.remove("__global__") {
        let _ = handle.shutdown.send(true);
        log_catmos!(" unsubscribe_all_events: global sync loop torn down");
    }
    Ok(())
}

#[tauri::command]
pub async fn fetch_new_messages(
    state: State<'_, AppState>,
    conversation_id: String,
) -> Result<Vec<Message>, String> {
    let did = require_authenticated_did(&state)?;
    if !state.mls_manager.is_opted_in(&did) {
        return Ok(vec![]);
    }
    let mgr = state.mls_manager.clone();
    let convo_id = conversation_id.clone();
    let rows = tokio::task::spawn_blocking(move || {
        if let Err(e) = mgr.sync(&did) {
            log_catmos!(" unified sync warning in fetch_new_messages: {}", e);
        }
        let listed = mgr.list_messages(&did, &convo_id, None, 50)?;
        if let Some(max_seq) = listed.iter().map(|r| r.seq).max().filter(|s| *s > 0) {
            let _ = mgr.advance_read_state(&did, &convo_id, max_seq as u64);
        }
        Ok::<_, String>(listed)
    })
    .await
    .map_err(|e| format!("task join error: {e}"))??;

    let mut messages: Vec<Message> = rows.into_iter().map(ui_message_from_row).collect();
    messages.sort_by_key(|m| m.sequence_number);
    Ok(messages)
}

const PUBLIC_APPVIEW: &str = "https://public.api.bsky.app";
/// `app.bsky.actor.getProfiles` accepts at most this many actors per call.
const PROFILES_PER_REQUEST: usize = 25;

#[tauri::command]
pub async fn get_profiles(
    state: State<'_, AppState>,
    dids: Vec<String>,
) -> Result<Vec<ProfileView>, String> {
    use petrel_api::generated::app::bsky::actor::get_profiles::{GetProfiles, Parameters};

    if dids.is_empty() {
        return Ok(vec![]);
    }
    let (auth, _) = require_session(&state)?;
    // Public profile data: sent without the account's credentials.
    let client = auth.public_client(PUBLIC_APPVIEW)?;
    let mut profiles = Vec::with_capacity(dids.len());
    for chunk in dids.chunks(PROFILES_PER_REQUEST) {
        let actors = chunk
            .iter()
            .map(|did| {
                petrel_core::AtIdentifier::parse(did.as_str())
                    .map_err(|e| format!("invalid actor `{did}`: {e}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let output = client
            .send::<GetProfiles>(Parameters::new(actors), (), &CallOptions::default())
            .await
            .map_err(|e| format!("Profile fetch failed: {e}"))?;
        profiles.extend(output.profiles.into_iter().map(|p| ProfileView {
            did: p.did.to_string(),
            handle: p.handle.to_string(),
            display_name: p.display_name,
            avatar: p.avatar.map(|uri| uri.to_string()),
        }));
    }
    Ok(profiles)
}

#[tauri::command]
pub async fn send_reaction(
    state: State<'_, AppState>,
    conversation_id: String,
    message_id: String,
    emoji: String,
    action: String,
) -> Result<(), String> {
    let did = require_authenticated_did(&state)?;
    if !state.mls_manager.is_opted_in(&did) {
        return Err(actionable_error(
            "Enable encrypted chat before sending reactions",
        ));
    }
    log_catmos!(
        " send_reaction (unified): convo={}, msg={}, emoji={}, action={}",
        conversation_id,
        message_id,
        emoji,
        action
    );
    let reaction_action = if action == "remove" {
        catbird_mls::payload_types::ReactionAction::Remove
    } else {
        catbird_mls::payload_types::ReactionAction::Add
    };
    let payload = MLSMessagePayload::reaction(&message_id, &emoji, reaction_action);
    let payload_json = serde_json::to_string(&payload).map_err(|e| e.to_string())?;
    let mgr = state.mls_manager.clone();
    tokio::task::spawn_blocking(move || mgr.send_message(&did, &conversation_id, &payload_json))
        .await
        .map_err(|e| format!("task join error: {e}"))?
        .map(|_| ())
        .map_err(actionable_error)
}

#[tauri::command]
pub async fn send_typing(
    _state: State<'_, AppState>,
    conversation_id: String,
    is_typing: bool,
) -> Result<(), String> {
    let _ = (conversation_id, is_typing);
    Err(actionable_error(
        "Typing is temporarily unavailable: canonical signed typing transport is not wired",
    ))
}

#[tauri::command]
pub async fn update_cursor(
    state: State<'_, AppState>,
    conversation_id: String,
    cursor: String,
) -> Result<(), String> {
    let did = require_authenticated_did(&state)?;
    if !state.mls_manager.is_opted_in(&did) {
        return Ok(());
    }
    log_catmos!(
        " update_cursor: convo={}, cursor={}",
        conversation_id,
        cursor
    );

    if let Ok(seq) = cursor.parse::<i64>() {
        let mgr = state.mls_manager.clone();
        tokio::task::spawn_blocking(move || -> Result<(), String> {
            mgr.acknowledge_entries_up_to(&did, &conversation_id, seq)?;
            if seq > 0 {
                let _ = mgr.advance_read_state(&did, &conversation_id, seq as u64);
            }
            Ok(())
        })
        .await
        .map_err(|e| format!("task join error: {e}"))?
        .map_err(actionable_error)?;
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchResult {
    pub did: String,
    pub handle: String,
    pub display_name: Option<String>,
    pub avatar: Option<String>,
}

#[tauri::command]
pub async fn search_users(
    state: State<'_, AppState>,
    query: String,
) -> Result<Vec<SearchResult>, String> {
    use petrel_api::generated::app::bsky::actor::search_actors_typeahead::{
        Parameters, SearchActorsTypeahead,
    };

    if query.trim().is_empty() {
        return Ok(vec![]);
    }
    let (auth, _) = require_session(&state)?;
    let client = auth.public_client(PUBLIC_APPVIEW)?;
    let mut parameters = Parameters::new();
    parameters.q = Some(query);
    parameters.limit = 10;
    let output = client
        .send::<SearchActorsTypeahead>(parameters, (), &CallOptions::default())
        .await
        .map_err(|e| format!("Search failed: {e}"))?;
    Ok(output
        .actors
        .into_iter()
        .map(|a| SearchResult {
            did: a.did.to_string(),
            handle: a.handle.to_string(),
            display_name: a.display_name,
            avatar: a.avatar.map(|uri| uri.to_string()),
        })
        .collect())
}

/// An XRPC client for the delivery service and the options that carry a
/// token the account's server minted for `method`.
async fn delivery_service_call(
    auth: &DesktopAuth,
    did: &str,
    method: &str,
) -> Result<(XrpcClient, CallOptions), String> {
    let audience = format!(
        "{}#{}",
        crate::mls::TauriMlsManager::home_ds_did(),
        crate::auth::DELIVERY_SERVICE_ID
    );
    let token = auth.service_token(did, &audience, method).await?;
    let mut bearer = http::HeaderValue::from_str(&format!("Bearer {token}"))
        .map_err(|_| "service token is not a valid header value".to_string())?;
    bearer.set_sensitive(true);
    let mut options = CallOptions::default();
    options.headers.insert(http::header::AUTHORIZATION, bearer);
    let client = auth.public_client(&crate::mls::TauriMlsManager::home_ds_endpoint())?;
    Ok((client, options))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OptInStatusResult {
    pub did: String,
    pub opted_in: bool,
}

#[tauri::command]
pub async fn check_opt_in_status(
    state: State<'_, AppState>,
    dids: Vec<String>,
) -> Result<Vec<OptInStatusResult>, String> {
    use petrel_api::generated::com::atproto::repo::list_records::{ListRecords, Parameters};
    use petrel_catbird::generated::blue::catbird::chat::get_devices;

    if dids.is_empty() {
        return Ok(vec![]);
    }
    let (auth, own_did) = require_session(&state)?;
    let parsed_dids = dids
        .iter()
        .map(|did| crate::auth::parse_did(did))
        .collect::<Result<Vec<_>, _>>()?;

    let (ds, options) = delivery_service_call(&auth, &own_did, get_devices::NSID).await?;
    let response = ds
        .query(
            get_devices::NSID,
            parsed_dids.iter().map(|did| ("userDids", did.as_str())),
            &options,
        )
        .await
        .map_err(|e| format!("Opt-in check failed: {e}"))?;
    let output: get_devices::Output =
        petrel_core::from_json(&response.body).map_err(|e| e.to_string())?;

    let mut active_dids: std::collections::HashSet<String> = output
        .devices
        .iter()
        .map(|d| d.user_did.as_str().to_string())
        .collect();

    let pds = auth.pds_client(&own_did)?;
    let collection: petrel_core::Nsid = "blue.catbird.chat.device"
        .parse()
        .map_err(|_| "invalid collection".to_string())?;
    for did in &parsed_dids {
        if active_dids.contains(did.as_str()) {
            continue;
        }
        let mut parameters = Parameters::new(
            petrel_core::AtIdentifier::Did(did.clone()),
            collection.clone(),
        );
        parameters.limit = 1;
        if let Ok(page) = pds
            .send::<ListRecords>(parameters, (), &CallOptions::default())
            .await
        {
            if !page.records.is_empty() {
                active_dids.insert(did.as_str().to_string());
            }
        }
    }

    Ok(dids
        .into_iter()
        .map(|did| {
            let opted_in = active_dids.contains(did.as_str());
            OptInStatusResult { did, opted_in }
        })
        .collect())
}

#[tauri::command]
pub async fn promote_member(
    _state: State<'_, AppState>,
    conversation_id: String,
    target_did: String,
) -> Result<(), String> {
    let _ = (&conversation_id, &target_did);
    Err(actionable_error(
        "Admin role mutation is not supported in clean-slate MLS v1",
    ))
}

#[tauri::command]
pub async fn demote_member(
    _state: State<'_, AppState>,
    conversation_id: String,
    target_did: String,
) -> Result<(), String> {
    let _ = (&conversation_id, &target_did);
    Err(actionable_error(
        "Admin role mutation is not supported in clean-slate MLS v1",
    ))
}

#[tauri::command]
pub async fn remove_group_member(
    state: State<'_, AppState>,
    conversation_id: String,
    target_did: String,
) -> Result<(), String> {
    let did = require_authenticated_did(&state)?;
    log_catmos!(
        "remove_group_member: convo={}, target={}",
        conversation_id,
        target_did
    );

    let mgr = state.mls_manager.clone();
    tokio::task::spawn_blocking(move || {
        mgr.remove_group_member(&did, &conversation_id, &target_did)
    })
    .await
    .map_err(|e| format!("task join error: {e}"))?
    .map_err(actionable_error)
}

#[tauri::command]
pub async fn get_group_metadata(
    state: State<'_, AppState>,
    conversation_id: String,
) -> Result<Option<serde_json::Value>, String> {
    let did = require_authenticated_did(&state)?;
    if !state.mls_manager.is_opted_in(&did) {
        return Ok(None);
    }
    let mgr = state.mls_manager.clone();
    let row = tokio::task::spawn_blocking(move || mgr.get_group_metadata(&did, &conversation_id))
        .await
        .map_err(|e| format!("task join error: {e}"))??;

    Ok(row.map(|m| {
        serde_json::json!({
            "conversationId": m.conversation_id,
            "name": m.title,
            "title": m.title,
            "description": m.description,
            "avatarBlobCid": m.avatar_blob_cid,
            "epoch": m.epoch,
            "updatedAtMs": m.updated_at_ms,
        })
    }))
}

#[tauri::command]
pub async fn update_group_metadata(
    state: State<'_, AppState>,
    conversation_id: String,
    name: Option<String>,
    description: Option<String>,
    avatar_blob_locator: Option<String>,
    avatar_content_type: Option<String>,
) -> Result<(), String> {
    let did = require_authenticated_did(&state)?;
    let _ = (&avatar_blob_locator, &avatar_content_type);
    log_catmos!(
        "update_group_metadata: convo={}, name={:?}, description={:?}",
        conversation_id,
        name,
        description
    );

    let mgr = state.mls_manager.clone();
    tokio::task::spawn_blocking(move || {
        let existing = mgr.get_group_metadata(&did, &conversation_id)?;
        let next_title = name
            .or_else(|| existing.as_ref().and_then(|e| e.title.clone()))
            .unwrap_or_default();
        let next_desc = description
            .or_else(|| existing.as_ref().and_then(|e| e.description.clone()))
            .unwrap_or_default();
        mgr.update_group_metadata(&did, &conversation_id, next_title, next_desc)
            .map(|_| ())
    })
    .await
    .map_err(|e| format!("task join error: {e}"))?
    .map_err(actionable_error)
}

#[tauri::command]
pub async fn add_group_members(
    state: State<'_, AppState>,
    conversation_id: String,
    member_dids: Vec<String>,
) -> Result<(), String> {
    let did = require_authenticated_did(&state)?;
    log_catmos!(
        "add_group_members: convo={}, members={:?}",
        conversation_id,
        member_dids
    );

    let mgr = state.mls_manager.clone();
    tokio::task::spawn_blocking(move || {
        mgr.add_group_members(&did, &conversation_id, member_dids)
            .map(|_| ())
    })
    .await
    .map_err(|e| format!("task join error: {e}"))?
    .map_err(actionable_error)
}

#[tauri::command]
pub async fn leave_conversation(
    state: State<'_, AppState>,
    conversation_id: String,
) -> Result<(), String> {
    let did = require_authenticated_did(&state)?;
    log_catmos!("leave_conversation: convo={}", conversation_id);

    let mgr = state.mls_manager.clone();
    tokio::task::spawn_blocking(move || mgr.leave_conversation(&did, &conversation_id).map(|_| ()))
        .await
        .map_err(|e| format!("task join error: {e}"))?
        .map_err(actionable_error)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchHit {
    pub message_id: String,
    pub conversation_id: String,
    pub conversation_name: String,
    pub sender_did: String,
    pub content: String,
    pub timestamp: String,
}

#[tauri::command]
pub async fn search_messages(
    state: State<'_, AppState>,
    query: String,
) -> Result<Vec<SearchHit>, String> {
    log_catmos!("search_messages: query={}", query);

    if query.trim().is_empty() {
        return Ok(vec![]);
    }

    let did = require_authenticated_did(&state)?;
    if !state.mls_manager.is_opted_in(&did) {
        return Ok(vec![]);
    }

    let mgr = state.mls_manager.clone();
    let lower_query = query.to_lowercase();
    tokio::task::spawn_blocking(move || {
        let convos = mgr.list_conversations_detailed(&did, 200)?;
        let mut hits = Vec::new();
        for (row, members, meta, _) in convos {
            let convo_name = meta
                .as_ref()
                .and_then(|m| m.title.clone())
                .filter(|t| !t.trim().is_empty())
                .or_else(|| row.title.clone().filter(|t| !t.trim().is_empty()))
                .unwrap_or_else(|| {
                    if members.is_empty() {
                        row.conversation_id.clone()
                    } else {
                        members.join(", ")
                    }
                });
            if let Ok(msgs) = mgr.list_messages(&did, &row.conversation_id, None, 500) {
                for msg in msgs {
                    let (_mt, content) = extract_message_text_and_type(&msg.plaintext_json);
                    if content.to_lowercase().contains(&lower_query) {
                        hits.push(SearchHit {
                            message_id: msg.message_id,
                            conversation_id: msg.conversation_id,
                            conversation_name: convo_name.clone(),
                            sender_did: msg.sender_did,
                            content,
                            timestamp: rfc3339_from_ms(msg.created_at_ms),
                        });
                    }
                }
            }
        }
        hits.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        hits.truncate(100);
        Ok(hits)
    })
    .await
    .map_err(|e| format!("task join error: {e}"))?
}

#[tauri::command]
pub async fn report_spam(
    state: State<'_, AppState>,
    conversation_id: String,
    reported_did: String,
    reason: Option<String>,
) -> Result<(), String> {
    const METHOD: &str = "blue.catbird.chat.reportSpam";
    let (auth, did) = require_session(&state)?;

    let mut body = serde_json::json!({
        "convoId": conversation_id,
        "reportedDid": reported_did,
    });
    if let Some(r) = reason {
        body["reason"] = serde_json::Value::String(r);
    }
    let body = serde_json::to_vec(&body).map_err(|e| e.to_string())?;

    let (ds, options) = delivery_service_call(&auth, &did, METHOD).await?;
    ds.procedure(
        METHOD,
        std::iter::empty::<(&str, &str)>(),
        Some(XrpcBody::json(body)),
        &options,
    )
    .await
    .map_err(|e| format!("reportSpam failed: {e}"))?;
    Ok(())
}

#[tauri::command]
pub async fn reset_group(
    _state: State<'_, AppState>,
    conversation_id: String,
    reason: Option<String>,
) -> Result<serde_json::Value, String> {
    let _ = (&conversation_id, &reason);
    Err(actionable_error(
        "Manual group reset is replaced by Labyrinth Space history re-indexing in clean-slate MLS",
    ))
}

#[tauri::command]
pub async fn republish_group_metadata(
    _state: State<'_, AppState>,
    conversation_id: String,
    new_group_id: String,
    new_reset_generation: i64,
) -> Result<(), String> {
    let _ = (&conversation_id, &new_group_id, new_reset_generation);
    Ok(())
}

const BLOCK_COLLECTION: &str = "app.bsky.graph.block";

#[tauri::command]
pub async fn create_block(
    state: State<'_, AppState>,
    subject_did: String,
) -> Result<String, String> {
    use petrel_api::generated::app::bsky::graph::block::Block;
    use petrel_api::generated::com::atproto::repo::create_record::{CreateRecord, Input};
    use petrel_core::ToValue;

    let (auth, did) = require_session(&state)?;
    let record = Block::new(
        crate::auth::parse_did(&subject_did)?,
        petrel_core::Datetime::now().map_err(|e| e.to_string())?,
    )
    .to_value()
    .map_err(|e| e.to_string())?;
    let input = Input::new(
        petrel_core::AtIdentifier::Did(crate::auth::parse_did(&did)?),
        BLOCK_COLLECTION
            .parse()
            .map_err(|_| "invalid collection".to_string())?,
        record,
    );
    let output = auth
        .pds_client(&did)?
        .send::<CreateRecord>((), input, &CallOptions::default())
        .await
        .map_err(|e| format!("createBlock failed: {e}"))?;
    Ok(output.uri.to_string())
}

#[tauri::command]
pub async fn list_own_blocks(state: State<'_, AppState>) -> Result<Vec<String>, String> {
    use petrel_api::generated::com::atproto::repo::list_records::{ListRecords, Parameters};

    let (auth, did) = require_session(&state)?;
    let client = auth.pds_client(&did)?;
    let repo = petrel_core::AtIdentifier::Did(crate::auth::parse_did(&did)?);
    let collection: petrel_core::Nsid = BLOCK_COLLECTION
        .parse()
        .map_err(|_| "invalid collection".to_string())?;

    let mut blocked: Vec<String> = Vec::new();
    let mut cursor: Option<String> = None;
    for _page in 0..1000 {
        let mut parameters = Parameters::new(repo.clone(), collection.clone());
        parameters.limit = 100;
        parameters.cursor = cursor.clone();
        let page = client
            .send::<ListRecords>(parameters, (), &CallOptions::default())
            .await
            .map_err(|e| format!("listOwnBlocks failed: {e}"))?;

        let record_count = page.records.len();
        for record in page.records {
            if let petrel_core::Value::Object(mut fields) = record.value {
                if let Some(petrel_core::Value::String(subject)) = fields.remove("subject") {
                    blocked.push(subject);
                }
            }
        }
        if page.cursor.is_none() || record_count == 0 || page.cursor == cursor {
            break;
        }
        cursor = page.cursor;
    }

    Ok(blocked)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QuarantineStateView {
    pub reason_tag: String,
    pub since_ms: i64,
    pub suspected_dids: Vec<String>,
}

#[tauri::command]
pub async fn get_quarantine_state(
    _state: State<'_, AppState>,
    conversation_id: String,
) -> Result<Option<QuarantineStateView>, String> {
    let _ = conversation_id;
    Ok(None)
}

#[tauri::command]
pub async fn confirm_manual_reset(
    _state: State<'_, AppState>,
    conversation_id: String,
) -> Result<(), String> {
    let _ = conversation_id;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Unified Clean-Slate Labyrinth 1.1 & Spaces Commands
// ─────────────────────────────────────────────────────────────────────────────

#[tauri::command]
pub async fn labyrinth_enable_and_enroll(
    state: State<'_, AppState>,
    did: String,
    pds_supports_spaces: Option<bool>,
    granted_scopes: Option<Vec<String>>,
) -> Result<catbird_mls::client::LabyrinthBackupStatus, String> {
    let mgr = state.mls_manager.clone();
    let did_for_enroll = did.clone();
    let status = tokio::task::spawn_blocking(move || {
        mgr.enable_and_enroll(&did_for_enroll, pds_supports_spaces, granted_scopes)
    })
    .await
    .map_err(|e| format!("task join error: {e}"))??;

    start_kp_monitor(&state, did.clone()).await;
    start_sync_loop(&state, did).await;
    Ok(status)
}

#[tauri::command]
pub async fn labyrinth_status(
    state: State<'_, AppState>,
    did: String,
) -> Result<Option<catbird_mls::client::LabyrinthBackupStatus>, String> {
    let mgr = state.mls_manager.clone();
    tokio::task::spawn_blocking(move || mgr.status(&did))
        .await
        .map_err(|e| format!("task join error: {e}"))?
}

#[tauri::command]
pub async fn labyrinth_current_device_id(
    state: State<'_, AppState>,
    did: String,
) -> Result<Option<String>, String> {
    let mgr = state.mls_manager.clone();
    tokio::task::spawn_blocking(move || mgr.current_device_id(&did))
        .await
        .map_err(|e| format!("task join error: {e}"))?
}

#[tauri::command]
pub async fn labyrinth_setup_recovery_code(
    state: State<'_, AppState>,
    did: String,
) -> Result<String, String> {
    let mgr = state.mls_manager.clone();
    tokio::task::spawn_blocking(move || mgr.setup_recovery_code(&did))
        .await
        .map_err(|e| format!("task join error: {e}"))?
}

#[tauri::command]
pub async fn labyrinth_restore_recovery_code(
    state: State<'_, AppState>,
    did: String,
    recovery_code_input: String,
) -> Result<catbird_mls::client::LabyrinthBackupStatus, String> {
    let mgr = state.mls_manager.clone();
    let did_for_restore = did.clone();
    let status = tokio::task::spawn_blocking(move || {
        let status = mgr.restore_recovery_code(&did_for_restore, &recovery_code_input)?;
        let _ = mgr.set_opted_in(&did_for_restore, true);
        match mgr.restore_archived_conversations(&did_for_restore) {
            Ok(summary) => {
                log_catmos!(
                    "post-recovery-code archive restore: discovered={}, restored_convos={}, restored_msgs={}, errors={:?}",
                    summary.conversations_discovered,
                    summary.conversations_restored,
                    summary.messages_restored,
                    summary.errors
                );
            }
            Err(e) => {
                log_catmos!("post-recovery-code archive restore warning: {e}");
            }
        }
        Ok::<_, String>(status)
    })
    .await
    .map_err(|e| format!("task join error: {e}"))??;
    start_kp_monitor(&state, did.clone()).await;
    start_sync_loop(&state, did).await;
    Ok(status)
}

#[tauri::command]
pub async fn labyrinth_register_passkey_prf(
    state: State<'_, AppState>,
    did: String,
    credential_id: Vec<u8>,
    prf_output32: Vec<u8>,
) -> Result<catbird_mls::client::LabyrinthBackupStatus, String> {
    let mgr = state.mls_manager.clone();
    tokio::task::spawn_blocking(move || mgr.register_passkey_prf(&did, credential_id, prf_output32))
        .await
        .map_err(|e| format!("task join error: {e}"))?
}

#[tauri::command]
pub async fn labyrinth_restore_passkey_prf(
    state: State<'_, AppState>,
    did: String,
    credential_id: Vec<u8>,
    prf_output32: Vec<u8>,
) -> Result<catbird_mls::client::LabyrinthBackupStatus, String> {
    let mgr = state.mls_manager.clone();
    let did_for_restore = did.clone();
    let status = tokio::task::spawn_blocking(move || {
        let status = mgr.restore_passkey_prf(&did_for_restore, credential_id, prf_output32)?;
        let _ = mgr.set_opted_in(&did_for_restore, true);
        match mgr.restore_archived_conversations(&did_for_restore) {
            Ok(summary) => {
                log_catmos!(
                    "post-passkey archive restore: discovered={}, restored_convos={}, restored_msgs={}, errors={:?}",
                    summary.conversations_discovered,
                    summary.conversations_restored,
                    summary.messages_restored,
                    summary.errors
                );
            }
            Err(e) => {
                log_catmos!("post-passkey archive restore warning: {e}");
            }
        }
        Ok::<_, String>(status)
    })
    .await
    .map_err(|e| format!("task join error: {e}"))??;
    start_kp_monitor(&state, did.clone()).await;
    start_sync_loop(&state, did).await;
    Ok(status)
}

#[tauri::command]
pub async fn labyrinth_is_device_pending_approval(
    state: State<'_, AppState>,
    did: String,
) -> Result<bool, String> {
    let mgr = state.mls_manager.clone();
    tokio::task::spawn_blocking(move || mgr.is_device_pending_approval(&did))
        .await
        .map_err(|e| format!("task join error: {e}"))?
}

#[tauri::command]
pub async fn labyrinth_approve_device(
    state: State<'_, AppState>,
    did: String,
    target_device_id: String,
) -> Result<catbird_mls::client::LabyrinthBackupStatus, String> {
    let mgr = state.mls_manager.clone();
    tokio::task::spawn_blocking(move || {
        mgr.approve_device(&did, &target_device_id)?;
        mgr.status(&did)?
            .ok_or_else(|| "Labyrinth status unavailable after device approval".to_string())
    })
    .await
    .map_err(|e| format!("task join error: {e}"))?
}

#[tauri::command]
pub async fn labyrinth_list_devices(
    state: State<'_, AppState>,
    did: String,
) -> Result<Vec<catbird_mls::client::RegisteredDeviceInfo>, String> {
    let mgr = state.mls_manager.clone();
    tokio::task::spawn_blocking(move || mgr.list_devices(&did))
        .await
        .map_err(|e| format!("task join error: {e}"))?
}

#[tauri::command]
pub async fn labyrinth_revoke_device(
    state: State<'_, AppState>,
    did: String,
    target_device_id: String,
) -> Result<catbird_mls::client::LabyrinthRevocationOutcome, String> {
    let mgr = state.mls_manager.clone();
    tokio::task::spawn_blocking(move || mgr.revoke_device(&did, &target_device_id))
        .await
        .map_err(|e| format!("task join error: {e}"))?
}

#[tauri::command]
pub async fn labyrinth_revoke_device_live(
    state: State<'_, AppState>,
    did: String,
    target_device_id: String,
) -> Result<catbird_mls::client::DeviceRevocationReport, String> {
    let mgr = state.mls_manager.clone();
    tokio::task::spawn_blocking(move || mgr.revoke_device_live(&did, &target_device_id))
        .await
        .map_err(|e| format!("task join error: {e}"))?
}

#[tauri::command]
pub async fn labyrinth_initiate_otc(
    state: State<'_, AppState>,
    did: String,
) -> Result<catbird_mls::client::OtcPairingOffer, String> {
    let mgr = state.mls_manager.clone();
    tokio::task::spawn_blocking(move || mgr.initiate_otc(&did))
        .await
        .map_err(|e| format!("task join error: {e}"))?
}

#[tauri::command]
pub async fn labyrinth_start_otc(
    state: State<'_, AppState>,
    did: String,
    six_digit_code: String,
) -> Result<catbird_mls::client::OtcInitiatedSession, String> {
    let mgr = state.mls_manager.clone();
    tokio::task::spawn_blocking(move || mgr.start_otc(&did, &six_digit_code))
        .await
        .map_err(|e| format!("task join error: {e}"))?
}

#[tauri::command]
pub async fn labyrinth_respond_otc(
    state: State<'_, AppState>,
    did: String,
    session_id_hex: String,
    six_digit_code: Option<String>,
) -> Result<(), String> {
    let mgr = state.mls_manager.clone();
    tokio::task::spawn_blocking(move || {
        mgr.respond_otc(&did, &session_id_hex, six_digit_code.as_deref())
    })
    .await
    .map_err(|e| format!("task join error: {e}"))?
}

#[tauri::command]
pub async fn labyrinth_complete_otc(
    state: State<'_, AppState>,
    did: String,
    six_digit_code: String,
) -> Result<catbird_mls::client::OtcPairingCompletion, String> {
    let mgr = state.mls_manager.clone();
    let did_for_otc = did.clone();
    let completion = tokio::task::spawn_blocking(move || {
        let res = mgr.complete_otc(&did_for_otc, &six_digit_code)?;
        let _ = mgr.set_opted_in(&did_for_otc, true);
        match mgr.restore_archived_conversations(&did_for_otc) {
            Ok(summary) => {
                log_catmos!(
                    "post-otc archive restore: discovered={}, restored_convos={}, restored_msgs={}, errors={:?}",
                    summary.conversations_discovered,
                    summary.conversations_restored,
                    summary.messages_restored,
                    summary.errors
                );
            }
            Err(e) => {
                log_catmos!("post-otc archive restore warning: {e}");
            }
        }
        Ok::<_, String>(res)
    })
    .await
    .map_err(|e| format!("task join error: {e}"))??;
    start_kp_monitor(&state, did.clone()).await;
    start_sync_loop(&state, did).await;
    Ok(completion)
}

#[tauri::command]
pub async fn labyrinth_verify_and_reindex_history(
    state: State<'_, AppState>,
    did: String,
    conversation_id: String,
) -> Result<u32, String> {
    let mgr = state.mls_manager.clone();
    tokio::task::spawn_blocking(move || mgr.verify_and_reindex_history(&did, &conversation_id))
        .await
        .map_err(|e| format!("task join error: {e}"))?
}

#[tauri::command]
pub async fn labyrinth_get_read_state(
    state: State<'_, AppState>,
    did: String,
    conversation_id: String,
) -> Result<Option<catbird_mls::client::MailboxReadStateRecord>, String> {
    let mgr = state.mls_manager.clone();
    tokio::task::spawn_blocking(move || mgr.get_read_state(&did, &conversation_id))
        .await
        .map_err(|e| format!("task join error: {e}"))?
}

#[tauri::command]
pub async fn labyrinth_advance_read_state(
    state: State<'_, AppState>,
    did: String,
    conversation_id: String,
    candidate_seq: u64,
) -> Result<catbird_mls::client::MailboxReadStateRecord, String> {
    let mgr = state.mls_manager.clone();
    tokio::task::spawn_blocking(move || {
        mgr.advance_read_state(&did, &conversation_id, candidate_seq)
    })
    .await
    .map_err(|e| format!("task join error: {e}"))?
}

#[tauri::command]
pub async fn labyrinth_list_read_states(
    state: State<'_, AppState>,
    did: String,
) -> Result<Vec<catbird_mls::client::MailboxReadStateRecord>, String> {
    let mgr = state.mls_manager.clone();
    tokio::task::spawn_blocking(move || mgr.list_read_states(&did))
        .await
        .map_err(|e| format!("task join error: {e}"))?
}

#[tauri::command]
pub async fn labyrinth_get_circle_owner_state(
    state: State<'_, AppState>,
    did: String,
    circle_id: String,
) -> Result<Option<catbird_mls::client::CircleOwnerStateDto>, String> {
    let mgr = state.mls_manager.clone();
    tokio::task::spawn_blocking(move || mgr.get_circle_owner_state(&did, &circle_id))
        .await
        .map_err(|e| format!("task join error: {e}"))?
}

#[tauri::command]
pub async fn labyrinth_put_circle_owner_state(
    state: State<'_, AppState>,
    did: String,
    state_dto: catbird_mls::client::CircleOwnerStateDto,
    swap_record_cid: Option<String>,
) -> Result<String, String> {
    let mgr = state.mls_manager.clone();
    tokio::task::spawn_blocking(move || {
        mgr.put_circle_owner_state(&did, state_dto, swap_record_cid)
    })
    .await
    .map_err(|e| format!("task join error: {e}"))?
}

#[tauri::command]
pub async fn labyrinth_merge_circle_owner_state(
    state: State<'_, AppState>,
    did: String,
    update: catbird_mls::client::CircleOwnerStateDto,
) -> Result<catbird_mls::client::CircleOwnerStateDto, String> {
    let mgr = state.mls_manager.clone();
    tokio::task::spawn_blocking(move || mgr.merge_circle_owner_state(&did, update))
        .await
        .map_err(|e| format!("task join error: {e}"))?
}

#[tauri::command]
pub async fn labyrinth_clear_circle_acl_tombstone(
    state: State<'_, AppState>,
    did: String,
    circle_id: String,
    member_did: String,
) -> Result<Option<catbird_mls::client::CircleOwnerStateDto>, String> {
    let mgr = state.mls_manager.clone();
    tokio::task::spawn_blocking(move || {
        mgr.clear_circle_acl_tombstone(&did, &circle_id, &member_did)
    })
    .await
    .map_err(|e| format!("task join error: {e}"))?
}

#[tauri::command]
pub async fn labyrinth_list_circle_owner_states(
    state: State<'_, AppState>,
    did: String,
) -> Result<Vec<catbird_mls::client::CircleOwnerStateDto>, String> {
    let mgr = state.mls_manager.clone();
    tokio::task::spawn_blocking(move || mgr.list_circle_owner_states(&did))
        .await
        .map_err(|e| format!("task join error: {e}"))?
}

#[cfg(test)]
mod tests {
    use super::{
        classify_callback_query, classify_pds_spaces_probe_response, cleanup_ws_handle,
        ui_message_from_row, wait_for_callback, CallbackQuery,
    };
    use catbird_mls::payload_types::{
        MLSAudioEmbed, MLSEmbedData, MLSImageEmbed, MLSMessagePayload,
    };
    use catbird_mls::storage::MessageRow;
    use std::collections::HashMap;
    use std::sync::Arc;

    fn row_with_payload(payload_json: String) -> MessageRow {
        MessageRow {
            message_id: "msg-embed-1".to_string(),
            conversation_id: "01900000-0000-7000-8000-000000000001".to_string(),
            group_id: vec![1, 2, 3, 4],
            seq: 3,
            epoch: 1,
            sender_did: "did:plc:bob".to_string(),
            sender_device_id: "00000000-0000-4000-8000-000000000002".to_string(),
            plaintext_json: payload_json,
            created_at_ms: 1_763_120_000_000,
            is_own: false,
        }
    }

    #[test]
    fn ui_message_from_row_projects_post_link_and_gif_embeds() {
        // Shape Catbird iOS sends for a quoted Bluesky post with no text.
        let post = MLSEmbedData {
            kind: "post".to_string(),
            data: serde_json::json!({
                "uri": "at://did:plc:carol/app.bsky.feed.post/3kabc",
                "cid": "bafyreipost",
                "author_did": "did:plc:carol",
            }),
        };
        let msg = ui_message_from_row(row_with_payload(
            serde_json::to_string(&MLSMessagePayload::text_with_embed("", post)).unwrap(),
        ));
        assert_eq!(msg.message_type, "text");
        let embed = msg.embed.expect("post embed projected");
        assert_eq!(embed["type"], "post");
        assert_eq!(
            embed["data"]["uri"],
            "at://did:plc:carol/app.bsky.feed.post/3kabc"
        );
        // Serialized for the Svelte side under the camelCase `embed` key.
        let wire = serde_json::to_value(ui_message_from_row(row_with_payload(
            serde_json::to_string(&MLSMessagePayload::text_with_embed(
                "see",
                MLSEmbedData {
                    kind: "link".to_string(),
                    data: serde_json::json!({ "url": "https://example.com", "title": "Ex" }),
                },
            ))
            .unwrap(),
        )))
        .unwrap();
        assert_eq!(wire["embed"]["type"], "link");
        assert_eq!(wire["embed"]["data"]["url"], "https://example.com");

        let gif = ui_message_from_row(row_with_payload(
            serde_json::to_string(&MLSMessagePayload::text_with_embed(
                "",
                MLSEmbedData {
                    kind: "gif".to_string(),
                    data: serde_json::json!({
                        "tenor_url": "https://tenor.com/x",
                        "mp4_url": "https://media.tenor.com/x.mp4"
                    }),
                },
            ))
            .unwrap(),
        ));
        assert_eq!(
            gif.embed.expect("gif embed")["data"]["mp4_url"],
            "https://media.tenor.com/x.mp4"
        );

        // Kinds without a card are not projected.
        let invite = ui_message_from_row(row_with_payload(
            serde_json::to_string(&MLSMessagePayload::text_with_embed(
                "hi",
                MLSEmbedData {
                    kind: "groupInvitation".to_string(),
                    data: serde_json::json!({}),
                },
            ))
            .unwrap(),
        ));
        assert!(invite.embed.is_none());
    }

    #[test]
    fn ui_message_from_row_projects_space_image_and_voice_embeds() {
        let img_embed = MLSEmbedData::image(MLSImageEmbed {
            blob_id: "at://did:plc:alice/blue.catbird.labyrinth.conversation/tid1|did:plc:alice|bafyreiimg".to_string(),
            key: vec![0x11; 32],
            iv: vec![0x22; 12],
            sha256: "aa".repeat(32),
            content_type: "image/png".to_string(),
            size: 1024,
            width: 640,
            height: 480,
            alt_text: Some("sunset".to_string()),
            blurhash: None,
        })
        .expect("image embed");
        let img_json =
            serde_json::to_string(&MLSMessagePayload::text_with_embed("Look!", img_embed))
                .expect("serialize image payload");
        let img_msg = ui_message_from_row(MessageRow {
            message_id: "msg-img-1".to_string(),
            conversation_id: "01900000-0000-7000-8000-000000000001".to_string(),
            group_id: vec![1, 2, 3, 4],
            seq: 7,
            epoch: 1,
            sender_did: "did:plc:alice".to_string(),
            sender_device_id: "00000000-0000-4000-8000-000000000001".to_string(),
            plaintext_json: img_json,
            created_at_ms: 1_763_120_000_000,
            is_own: true,
        });
        assert_eq!(img_msg.message_type, "image");
        assert_eq!(img_msg.content, "Look!");
        assert_eq!(img_msg.sequence_number, 7);
        let img = img_msg.image.expect("image attachment");
        assert!(img.blob_id.contains("|did:plc:alice|bafyreiimg"));
        assert_eq!(img.width, 640);
        assert_eq!(img.height, 480);

        let aud_embed = MLSEmbedData::audio(MLSAudioEmbed {
            blob_id: "at://did:plc:alice/blue.catbird.labyrinth.conversation/tid1|did:plc:alice|bafyreiaud".to_string(),
            key: vec![0x33; 32],
            iv: vec![0x44; 12],
            sha256: "bb".repeat(32),
            content_type: "audio/webm;codecs=opus".to_string(),
            size: 4096,
            duration_ms: 3250,
            waveform: vec![0.1, 0.5, 0.9],
            transcript: Some("hello world".to_string()),
        })
        .expect("audio embed");
        let aud_json = serde_json::to_string(&MLSMessagePayload::text_with_embed("", aud_embed))
            .expect("serialize audio payload");
        let aud_msg = ui_message_from_row(MessageRow {
            message_id: "msg-aud-1".to_string(),
            conversation_id: "01900000-0000-7000-8000-000000000001".to_string(),
            group_id: vec![1, 2, 3, 4],
            seq: 8,
            epoch: 1,
            sender_did: "did:plc:alice".to_string(),
            sender_device_id: "00000000-0000-4000-8000-000000000001".to_string(),
            plaintext_json: aud_json,
            created_at_ms: 1_763_120_005_000,
            is_own: false,
        });
        assert_eq!(aud_msg.message_type, "voice");
        let aud = aud_msg.audio.expect("audio attachment");
        assert!(aud.blob_id.contains("|did:plc:alice|bafyreiaud"));
        assert_eq!(aud.duration_ms, 3250);
        assert_eq!(aud.waveform.len(), 3);
        assert!(aud_msg.audio_attachment.is_some());
    }

    #[tokio::test]
    async fn websocket_exit_only_removes_its_current_handle() {
        let handles = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
        let (old_owner, _old_rx) = tokio::sync::watch::channel(false);
        let (new_owner, _new_rx) = tokio::sync::watch::channel(false);
        handles.lock().await.insert(
            "conversation".to_string(),
            crate::WsHandle {
                shutdown: new_owner.clone(),
            },
        );

        cleanup_ws_handle(&handles, "conversation", &old_owner).await;
        assert!(handles.lock().await.contains_key("conversation"));
        cleanup_ws_handle(&handles, "conversation", &new_owner).await;
        assert!(!handles.lock().await.contains_key("conversation"));
    }

    #[test]
    fn callback_listener_accepts_only_this_sign_ins_state() {
        let state = "49152.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert_eq!(
            classify_callback_query(
                &format!("code=abc&state={state}&iss=https%3A%2F%2Fas"),
                state
            ),
            CallbackQuery::Answer { denied: false }
        );
        assert_eq!(
            classify_callback_query(&format!("error=access_denied&state={state}"), state),
            CallbackQuery::Answer { denied: true }
        );
        assert_eq!(
            classify_callback_query("code=abc&state=49152.someone-elses", state),
            CallbackQuery::Ignore
        );
        assert_eq!(
            classify_callback_query(&format!("state={state}"), state),
            CallbackQuery::Ignore
        );
        assert_eq!(
            classify_callback_query("code=abc", state),
            CallbackQuery::Ignore
        );
    }

    #[tokio::test]
    async fn callback_listener_ignores_strangers_and_returns_the_query_unchanged() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};

        let state = "49152.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let waiting = tokio::spawn(async move { wait_for_callback(listener, state).await });

        async fn get(addr: std::net::SocketAddr, path: &str) -> String {
            let mut socket = TcpStream::connect(addr).await.unwrap();
            socket
                .write_all(format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").as_bytes())
                .await
                .unwrap();
            let mut response = String::new();
            socket.read_to_string(&mut response).await.unwrap();
            response
        }

        assert!(get(addr, "/favicon.ico").await.starts_with("HTTP/1.1 404"));
        assert!(get(addr, "/callback?code=forged&state=1.forged")
            .await
            .starts_with("HTTP/1.1 404"));
        let query = format!("code=real&state={state}&iss=https%3A%2F%2Fas.example");
        assert!(get(addr, &format!("/callback?{query}"))
            .await
            .starts_with("HTTP/1.1 200"));
        assert_eq!(waiting.await.unwrap(), Ok(query));
    }

    #[test]
    fn spaces_probe_classifier_fails_closed_on_401_404_501_and_accepts_400_invalid_request() {
        assert!(classify_pds_spaces_probe_response(
            400,
            br#"{"error":"InvalidRequest","message":"Missing required key space"}"#
        ));
        assert!(classify_pds_spaces_probe_response(200, b"{}"));
        assert!(!classify_pds_spaces_probe_response(
            401,
            br#"{"error":"AuthRequired"}"#
        ));
        assert!(!classify_pds_spaces_probe_response(
            404,
            br#"{"error":"XRPCNotSupported"}"#
        ));
        assert!(!classify_pds_spaces_probe_response(
            501,
            br#"{"error":"MethodNotImplemented"}"#
        ));
        assert!(!classify_pds_spaces_probe_response(
            400,
            br#"{"error":"XRPCNotSupported"}"#
        ));
        assert!(!classify_pds_spaces_probe_response(500, b""));
    }
}

#[cfg(test)]
mod login_flow_tests {
    use super::bind_callback_listener;

    #[tokio::test]
    async fn a_fixed_callback_port_is_rebound_once_the_stale_flow_releases_it() {
        let held = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = held.local_addr().unwrap().port();
        let release = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(120)).await;
            drop(held);
        });
        let rebound = bind_callback_listener(port).await.unwrap();
        assert_eq!(rebound.local_addr().unwrap().port(), port);
        release.await.unwrap();
    }

    #[tokio::test]
    async fn a_stale_flow_sees_its_generation_end() {
        let (generation, _) = tokio::sync::watch::channel(0u64);
        let started = *generation.borrow();
        let mut current = generation.subscribe();
        generation.send_modify(|g| *g += 1);
        let ended = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            current.wait_for(|latest| *latest != started),
        )
        .await;
        assert!(matches!(ended, Ok(Ok(_))));
    }
}

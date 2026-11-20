use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL};
use base64::Engine;
use catbird_atproto::jacquard_common::IntoStatic;
use catbird_mls::payload_types::{MLSMessagePayload, MLSMessageType};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tauri::{Emitter, State, WebviewUrl, WebviewWindowBuilder, WindowEvent};
use tauri_plugin_shell::ShellExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::recovery::actionable_error;
use crate::types::string::Did;
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

fn require_auth_token(state: &AppState) -> Result<String, String> {
    state
        .current_token()
        .ok_or_else(|| "Not authenticated".to_string())
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
    }
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

#[derive(Debug, Clone)]
struct SessionInfo {
    did: String,
    handle: String,
    granted_scopes: Vec<String>,
}

fn clear_saved_session_credentials() {
    for key in ["session_id", "user_did", "chat_dpop_jkt"] {
        if let Ok(entry) = crate::native_keyring::entry("catmos", key) {
            let _ = entry.delete_credential();
        }
    }
}

async fn fetch_session_info(session_id: &str) -> Result<SessionInfo, String> {
    let nest_url = crate::nest_url();

    let resp = reqwest::Client::new()
        .get(format!("{}/auth/session", nest_url))
        .bearer_auth(session_id)
        .send()
        .await
        .map_err(|e| format!("Failed to fetch session info: {}", e))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("Session rejected by nest ({}): {}", status, body));
    }

    let info: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("Failed to decode session info: {}", e))?;
    let did = info["did"]
        .as_str()
        .filter(|did| !did.is_empty())
        .ok_or_else(|| "Session response missing DID".to_string())?
        .to_string();
    let handle = info["handle"].as_str().unwrap_or(&did).to_string();
    let granted_scopes = info["granted_scopes"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();

    Ok(SessionInfo {
        did,
        handle,
        granted_scopes,
    })
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

const FIXED_UPGRADE_CALLBACK_HOST: &str = "catbird.blue";
const FIXED_UPGRADE_CALLBACK_PATH: &str = "/oauth/permission-callback";

fn generate_browser_nonce() -> Result<String, String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|e| format!("Failed to generate browser nonce: {e}"))?;
    Ok(B64URL.encode(bytes))
}

fn build_desktop_login_url(
    nest_url: &str,
    identifier: &str,
    redirect_to: &str,
    browser_nonce: &str,
    client_override: Option<&str>,
) -> String {
    let mut url = format!(
        "{}/auth/login?identifier={}&redirect_to={}&browser_nonce={}",
        nest_url.trim_end_matches('/'),
        urlencoding::encode(identifier),
        urlencoding::encode(redirect_to),
        urlencoding::encode(browser_nonce),
    );
    if let Some(client) = client_override.map(str::trim).filter(|c| !c.is_empty()) {
        url.push_str("&client=");
        url.push_str(&urlencoding::encode(client));
    }
    url
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

fn parse_permission_callback_url(url: &reqwest::Url) -> Option<Result<String, String>> {
    if url.scheme() != "https"
        || url.host_str() != Some(FIXED_UPGRADE_CALLBACK_HOST)
        || url.path() != FIXED_UPGRADE_CALLBACK_PATH
    {
        return None;
    }
    let mut code: Option<String> = None;
    let mut error: Option<String> = None;
    let mut error_description: Option<String> = None;
    for (k, v) in url.query_pairs() {
        match k.as_ref() {
            "code" if !v.is_empty() => code = Some(v.into_owned()),
            "error" if !v.is_empty() => error = Some(v.into_owned()),
            "error_description" if !v.is_empty() => error_description = Some(v.into_owned()),
            _ => {}
        }
    }
    if let Some(err) = error {
        let msg = match error_description {
            Some(desc) => format!("{err}: {desc}"),
            None => err,
        };
        return Some(Err(msg));
    }
    match code {
        Some(c) => Some(Ok(c)),
        None => Some(Err(
            "Permission upgrade callback missing authorization code".to_string(),
        )),
    }
}

async fn exchange_oauth_code(
    nest_url: &str,
    code: &str,
    browser_nonce: &str,
    callback_origin: &str,
) -> Result<String, String> {
    let resp = reqwest::Client::new()
        .post(format!("{}/auth/exchange", nest_url.trim_end_matches('/')))
        .header("Origin", callback_origin)
        .json(&serde_json::json!({
            "code": code,
            "browser_nonce": browser_nonce,
        }))
        .send()
        .await
        .map_err(|e| format!("Authentication exchange request failed: {e}"))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("Authentication exchange failed ({status}): {body}"));
    }
    let data: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("Failed to decode authentication exchange response: {e}"))?;
    data["session_id"]
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| "Authentication exchange response missing session_id".to_string())
}

enum CallbackOutcome {
    Code(String),
    SessionId(String),
}

#[tauri::command]
pub async fn start_login(app: tauri::AppHandle, identifier: String) -> Result<(), String> {
    let nest_url = crate::nest_url();
    let browser_nonce = generate_browser_nonce()?;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("Failed to bind callback server: {}", e))?;
    let port = listener
        .local_addr()
        .map_err(|e| format!("Failed to get port: {}", e))?
        .port();

    let callback_origin = format!("http://127.0.0.1:{}", port);
    let redirect_to = format!("{}/callback", callback_origin);
    // Default to the `catbird` OAuth client profile (which already declares all 6 Labyrinth/Spaces
    // scopes on prod nest) unless `CATMOS_OAUTH_CLIENT` explicitly overrides it.
    let client_override = std::env::var("CATMOS_OAUTH_CLIENT").ok();
    let login_url = build_desktop_login_url(
        &nest_url,
        &identifier,
        &redirect_to,
        &browser_nonce,
        client_override.as_deref(),
    );

    #[allow(deprecated)]
    {
        app.shell()
            .open(&login_url, None)
            .map_err(|e| e.to_string())?;
    }

    let app_handle = app.clone();
    tokio::spawn(async move {
        match tokio::time::timeout(
            std::time::Duration::from_secs(300),
            wait_for_callback(listener),
        )
        .await
        {
            Ok(Ok(CallbackOutcome::Code(code))) => {
                match exchange_oauth_code(&nest_url, &code, &browser_nonce, &callback_origin).await
                {
                    Ok(session_id) => {
                        let _ = app_handle.emit("oauth-callback", &session_id);
                    }
                    Err(e) => {
                        log_catmos!("OAuth code exchange error: {}", e);
                        let _ = app_handle.emit("oauth-error", &e);
                    }
                }
            }
            Ok(Ok(CallbackOutcome::SessionId(session_id))) => {
                let _ = app_handle.emit("oauth-callback", &session_id);
            }
            Ok(Err(e)) => {
                log_catmos!("OAuth callback error: {}", e);
                let _ = app_handle.emit("oauth-error", &e);
            }
            Err(_) => {
                log_catmos!("OAuth callback timed out");
                let _ = app_handle.emit("oauth-error", "Login timed out");
            }
        }
    });

    Ok(())
}

async fn wait_for_callback(listener: TcpListener) -> Result<CallbackOutcome, String> {
    const MAX_REQUEST_SIZE: usize = 8192;

    loop {
        let (mut stream, _) = listener
            .accept()
            .await
            .map_err(|e| format!("Accept failed: {}", e))?;

        let mut buf = vec![0u8; MAX_REQUEST_SIZE];
        let mut total = 0;
        loop {
            if total >= MAX_REQUEST_SIZE {
                return Err("OAuth callback request too large".to_string());
            }
            let n = stream
                .read(&mut buf[total..])
                .await
                .map_err(|e| format!("Read failed: {}", e))?;
            if n == 0 {
                break;
            }
            total += n;
            if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }

        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut req = httparse::Request::new(&mut headers);
        if req.parse(&buf[..total]).is_err() {
            continue;
        }

        let path = match req.path {
            Some(p) => p,
            None => continue,
        };
        let (route, query) = match path.split_once('?') {
            Some((r, q)) => (r, Some(q)),
            None => (path, None),
        };
        if route != "/callback" {
            let not_found =
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            let _ = stream.write_all(not_found.as_bytes()).await;
            let _ = stream.flush().await;
            continue;
        }

        let query = query.ok_or("No query string in callback URL")?;
        let mut code: Option<String> = None;
        let mut session_id: Option<String> = None;
        let mut error: Option<String> = None;
        let mut error_description: Option<String> = None;
        for param in query.split('&') {
            if let Some(v) = param.strip_prefix("code=") {
                let decoded = urlencoding::decode(v)
                    .unwrap_or_else(|_| v.into())
                    .into_owned();
                if !decoded.is_empty() {
                    code = Some(decoded);
                }
            } else if let Some(v) = param.strip_prefix("session_id=") {
                let decoded = urlencoding::decode(v)
                    .unwrap_or_else(|_| v.into())
                    .into_owned();
                if !decoded.is_empty() {
                    session_id = Some(decoded);
                }
            } else if let Some(v) = param.strip_prefix("error=") {
                let decoded = urlencoding::decode(v)
                    .unwrap_or_else(|_| v.into())
                    .into_owned();
                if !decoded.is_empty() {
                    error = Some(decoded);
                }
            } else if let Some(v) = param.strip_prefix("error_description=") {
                let decoded = urlencoding::decode(v)
                    .unwrap_or_else(|_| v.into())
                    .into_owned();
                if !decoded.is_empty() {
                    error_description = Some(decoded);
                }
            }
        }

        let (html, outcome) = if let Some(err) = error {
            let detail = match error_description {
                Some(desc) => format!("{err}: {desc}"),
                None => err,
            };
            (
                r#"<!DOCTYPE html><html><body style="font-family:system-ui;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#1a1a2e;color:#e0e0e0"><div style="text-align:center"><h1>Sign-in cancelled</h1><p>You can close this tab and return to Catmos.</p></div></body></html>"#,
                Err(detail),
            )
        } else if let Some(c) = code {
            (
                r#"<!DOCTYPE html><html><body style="font-family:system-ui;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#1a1a2e;color:#e0e0e0"><div style="text-align:center"><h1>Signed in</h1><p>You can close this tab and return to Catmos.</p></div></body></html>"#,
                Ok(CallbackOutcome::Code(c)),
            )
        } else if let Some(sid) = session_id {
            (
                r#"<!DOCTYPE html><html><body style="font-family:system-ui;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#1a1a2e;color:#e0e0e0"><div style="text-align:center"><h1>Signed in</h1><p>You can close this tab and return to Catmos.</p></div></body></html>"#,
                Ok(CallbackOutcome::SessionId(sid)),
            )
        } else {
            (
                r#"<!DOCTYPE html><html><body style="font-family:system-ui;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#1a1a2e;color:#e0e0e0"><div style="text-align:center"><h1>Sign-in failed</h1><p>Missing authorization code. Return to Catmos to retry.</p></div></body></html>"#,
                Err("No authorization code or session_id in callback".to_string()),
            )
        };

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            html.len(),
            html
        );
        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.flush().await;
        return outcome;
    }
}

#[tauri::command]
pub async fn upgrade_oauth_scopes(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    additional_scopes: Vec<String>,
) -> Result<AuthResponse, String> {
    let current_did = require_authenticated_did(&state)?;
    let current_session_id = require_auth_token(&state)?;
    let nest_url = crate::nest_url();

    let mut deduped: Vec<String> = Vec::new();
    for raw in additional_scopes {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed == "atproto" || deduped.iter().any(|s| s == trimmed) {
            continue;
        }
        deduped.push(trimmed.to_string());
    }
    if deduped.is_empty() {
        return Err("No additional OAuth scopes requested for upgrade.".to_string());
    }

    let browser_nonce = generate_browser_nonce()?;
    let http = reqwest::Client::new();
    let start_resp = http
        .post(format!("{}/auth/upgrade", nest_url.trim_end_matches('/')))
        .bearer_auth(&current_session_id)
        .json(&serde_json::json!({
            "additional_scopes": deduped,
            "browser_nonce": browser_nonce,
        }))
        .send()
        .await
        .map_err(|e| format!("Permission upgrade initiation failed: {e}"))?;

    if !start_resp.status().is_success() {
        let status = start_resp.status();
        let body = start_resp.text().await.unwrap_or_default();
        return Err(format!(
            "Permission upgrade initiation failed ({status}): {body}"
        ));
    }

    let start_json: serde_json::Value = start_resp
        .json()
        .await
        .map_err(|e| format!("Decode /auth/upgrade response failed: {e}"))?;
    let raw_auth_url = start_json["authorization_url"]
        .as_str()
        .map(str::trim)
        .filter(|u| !u.is_empty() && !u.bytes().any(|b| b < 0x20 || b == 0x7f))
        .ok_or_else(|| "Invalid authorization_url returned from /auth/upgrade".to_string())?;
    let parsed_auth_url = reqwest::Url::parse(raw_auth_url)
        .map_err(|e| format!("Malformed authorization_url from /auth/upgrade: {e}"))?;
    if parsed_auth_url.scheme() != "https"
        || !parsed_auth_url.username().is_empty()
        || parsed_auth_url.password().is_some()
    {
        return Err("Insecure authorization_url returned from /auth/upgrade".to_string());
    }

    let (tx, rx) = tokio::sync::oneshot::channel::<Result<String, String>>();
    let tx_nav = Arc::new(std::sync::Mutex::new(Some(tx)));
    let tx_close = Arc::clone(&tx_nav);
    let label = format!("oauth-upgrade-{}", uuid::Uuid::new_v4());

    let popup = WebviewWindowBuilder::new(&app, &label, WebviewUrl::External(parsed_auth_url))
        .title("Grant Spaces Permissions")
        .inner_size(540.0, 760.0)
        .resizable(true)
        .on_navigation(move |url| {
            if let Some(result) = parse_permission_callback_url(url) {
                if let Some(sender) = tx_nav.lock().ok().and_then(|mut g| g.take()) {
                    let _ = sender.send(result);
                }
                return false;
            }
            true
        })
        .build()
        .map_err(|e| format!("Failed to open permission upgrade window: {e}"))?;

    popup.on_window_event(move |event| {
        if matches!(event, WindowEvent::Destroyed) {
            if let Some(sender) = tx_close.lock().ok().and_then(|mut g| g.take()) {
                let _ = sender.send(Err("Permission upgrade cancelled.".to_string()));
            }
        }
    });

    let code_result = tokio::time::timeout(std::time::Duration::from_secs(300), rx).await;
    if let Some(win) = tauri::Manager::get_webview_window(&app, &label) {
        let _ = win.close();
    }
    let code = code_result
        .map_err(|_| "Permission upgrade timed out".to_string())?
        .map_err(|_| "Permission upgrade cancelled.".to_string())??;

    // Exchange authorization code for candidate session
    // nest's POST /auth/upgrade/exchange requires Origin: https://catbird.blue matching the fixed
    // permission callback URL.
    let ex_resp = http
        .post(format!(
            "{}/auth/upgrade/exchange",
            nest_url.trim_end_matches('/')
        ))
        .header("Origin", "https://catbird.blue")
        .bearer_auth(&current_session_id)
        .json(&serde_json::json!({
            "code": code,
            "browser_nonce": browser_nonce,
        }))
        .send()
        .await
        .map_err(|e| format!("Permission upgrade exchange failed: {e}"))?;
    if !ex_resp.status().is_success() {
        let status = ex_resp.status();
        let body = ex_resp.text().await.unwrap_or_default();
        return Err(format!(
            "Permission upgrade exchange failed ({status}): {body}"
        ));
    }
    let ex_json: serde_json::Value = ex_resp
        .json()
        .await
        .map_err(|e| format!("Decode /auth/upgrade/exchange failed: {e}"))?;
    let candidate_session_id = ex_json["candidate_session_id"]
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "Permission upgrade exchange missing candidate_session_id".to_string())?
        .to_string();
    let ex_did = ex_json["did"].as_str().unwrap_or_default();
    if !ex_did.eq_ignore_ascii_case(&current_did) {
        return Err("Permission upgrade exchange DID mismatch.".to_string());
    }

    // Commit candidate session (with one retry on 5xx per nest contract)
    let commit_url = format!("{}/auth/upgrade/commit", nest_url.trim_end_matches('/'));
    let mut commit_resp = http
        .post(&commit_url)
        .bearer_auth(&candidate_session_id)
        .send()
        .await
        .map_err(|e| format!("Permission upgrade commit failed: {e}"))?;
    if commit_resp.status().is_server_error() {
        commit_resp = http
            .post(&commit_url)
            .bearer_auth(&candidate_session_id)
            .send()
            .await
            .map_err(|e| format!("Permission upgrade commit retry failed: {e}"))?;
    }
    if !commit_resp.status().is_success() {
        let status = commit_resp.status();
        let body = commit_resp.text().await.unwrap_or_default();
        return Err(format!(
            "Permission upgrade commit failed ({status}): {body}"
        ));
    }
    let commit_json: serde_json::Value = commit_resp
        .json()
        .await
        .map_err(|e| format!("Decode /auth/upgrade/commit failed: {e}"))?;
    if commit_json["status"].as_str() != Some("committed") {
        return Err("Permission upgrade commit returned unexpected status.".to_string());
    }
    let committed_session_id = commit_json["session_id"]
        .as_str()
        .map(str::trim)
        .filter(|s| *s == candidate_session_id)
        .ok_or_else(|| "Committed session_id did not match candidate_session_id.".to_string())?
        .to_string();
    let commit_did = commit_json["did"].as_str().unwrap_or_default();
    if !commit_did.eq_ignore_ascii_case(&current_did) {
        return Err("Committed session DID mismatch.".to_string());
    }

    // Fetch authoritative upgraded session info once
    let session = fetch_session_info(&committed_session_id)
        .await
        .map_err(actionable_error)?;
    state.set_session_auth(session.did.clone(), committed_session_id.clone());
    state.mls_manager.set_account_did(Some(session.did.clone()));
    state
        .mls_manager
        .set_session_token(Some(committed_session_id.clone()));

    if let Ok(entry) = crate::native_keyring::entry("catmos", "session_id") {
        let _ = entry.set_password(&committed_session_id);
    }
    if let Ok(entry) = crate::native_keyring::entry("catmos", "user_did") {
        let _ = entry.set_password(&session.did);
    }

    Ok(AuthResponse {
        did: session.did,
        handle: session.handle,
        display_name: None,
        avatar: None,
        granted_scopes: session.granted_scopes,
    })
}

#[tauri::command]
pub async fn labyrinth_probe_pds_spaces(state: State<'_, AppState>) -> Result<bool, String> {
    let session_id = match state.current_token() {
        Some(tok) if !tok.trim().is_empty() => tok,
        _ => return Ok(false),
    };
    let nest_url = crate::nest_url();
    let resp = match reqwest::Client::new()
        .get(format!(
            "{}/xrpc/com.atproto.space.getSpace",
            nest_url.trim_end_matches('/')
        ))
        .bearer_auth(&session_id)
        .send()
        .await
    {
        Ok(r) => r,
        Err(_) => return Ok(false),
    };
    let status = resp.status().as_u16();
    let body = resp.bytes().await.unwrap_or_default();
    Ok(classify_pds_spaces_probe_response(status, &body))
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

#[tauri::command]
pub async fn complete_login(
    state: State<'_, AppState>,
    session_id: String,
) -> Result<AuthResponse, String> {
    let session = fetch_session_info(&session_id)
        .await
        .map_err(actionable_error)?;

    state.set_session_auth(session.did.clone(), session_id.clone());
    state.mls_manager.set_account_did(Some(session.did.clone()));
    state
        .mls_manager
        .set_session_token(Some(session_id.clone()));

    // ctl #2: Chat/Spaces is strictly OFF by default on fresh sign-ins.
    if state.mls_manager.is_opted_in(&session.did) {
        let mgr = state.mls_manager.clone();
        let did_for_sync = session.did.clone();
        let _ = tokio::task::spawn_blocking(move || {
            if let Err(e) = mgr.sync(&did_for_sync) {
                log_catmos!("Initial unified MLS sync warning: {}", e);
            }
        })
        .await;
        start_kp_monitor(&state, session.did.clone()).await;
        start_sync_loop(&state, session.did.clone()).await;
    }

    if let Ok(entry) = crate::native_keyring::entry("catmos", "session_id") {
        let _ = entry.set_password(&session_id);
    }
    if let Ok(entry) = crate::native_keyring::entry("catmos", "user_did") {
        let _ = entry.set_password(&session.did);
    }

    Ok(AuthResponse {
        did: session.did,
        handle: session.handle,
        display_name: None,
        avatar: None,
        granted_scopes: session.granted_scopes,
    })
}

#[tauri::command]
pub async fn try_restore_session(
    state: State<'_, AppState>,
) -> Result<Option<AuthResponse>, String> {
    let session_id = crate::native_keyring::entry("catmos", "session_id")
        .and_then(|e| e.get_password())
        .ok();
    let did = crate::native_keyring::entry("catmos", "user_did")
        .and_then(|e| e.get_password())
        .ok();

    match (session_id, did) {
        (Some(sid), stored_did) => {
            let session = match fetch_session_info(&sid).await {
                Ok(session) => session,
                Err(e) => {
                    if crate::session_restore::session_error_invalidates_credentials(&e) {
                        log_catmos!("Stored session was rejected; clearing saved login: {}", e);
                        clear_saved_session_credentials();
                        state.clear_session_auth();
                        state.mls_manager.set_account_did(None);
                        state.mls_manager.set_session_token(None);
                        return Ok(None);
                    }
                    log_catmos!(
                        "Stored session could not be restored yet; keeping saved login: {}",
                        e
                    );
                    return Err(actionable_error(e));
                }
            };

            if let Some(ref d) = stored_did {
                if d != &session.did {
                    log_catmos!(
                        "Saved DID {} did not match nest session DID {}; using nest session DID",
                        d,
                        session.did
                    );
                }
            }
            log_catmos!("Restoring session for DID: {}", session.did);
            state.set_session_auth(session.did.clone(), sid.clone());
            state.mls_manager.set_account_did(Some(session.did.clone()));
            state.mls_manager.set_session_token(Some(sid.clone()));

            // ctl #2: Only initialize MLS runtime + background sync if explicitly opted in.
            if state.mls_manager.is_opted_in(&session.did) {
                let mgr = state.mls_manager.clone();
                let did_for_sync = session.did.clone();
                let _ = tokio::task::spawn_blocking(move || {
                    if let Err(e) = mgr.sync(&did_for_sync) {
                        log_catmos!("Restored unified MLS sync warning: {}", e);
                    }
                })
                .await;
                start_kp_monitor(&state, session.did.clone()).await;
                start_sync_loop(&state, session.did.clone()).await;
            }

            if let Ok(entry) = crate::native_keyring::entry("catmos", "user_did") {
                let _ = entry.set_password(&session.did);
            }
            log_catmos!("Session restored: handle={}", session.handle);

            Ok(Some(AuthResponse {
                did: session.did,
                handle: session.handle,
                display_name: None,
                avatar: None,
                granted_scopes: session.granted_scopes,
            }))
        }
        _ => Ok(None),
    }
}

#[tauri::command]
pub async fn logout(state: State<'_, AppState>) -> Result<(), String> {
    stop_background_tasks_and_subscriptions(&state).await;
    if let Ok(did) = require_authenticated_did(&state) {
        let mgr = state.mls_manager.clone();
        let _ = tokio::task::spawn_blocking(move || {
            let _ = mgr.sign_out_and_wipe(&did);
        })
        .await;
    }
    state.mls_manager.set_account_did(None);
    state.mls_manager.set_session_token(None);
    state.clear_session_auth();
    clear_saved_session_credentials();
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
    state.mls_manager.set_account_did(None);
    state.mls_manager.set_session_token(None);
    state.clear_session_auth();
    clear_saved_session_credentials();
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

#[tauri::command]
pub async fn get_profiles(
    state: State<'_, AppState>,
    dids: Vec<String>,
) -> Result<Vec<ProfileView>, String> {
    if dids.is_empty() {
        return Ok(vec![]);
    }

    let token = require_auth_token(&state)?;
    let client = reqwest::Client::new();
    let mut url =
        reqwest::Url::parse("https://public.api.bsky.app/xrpc/app.bsky.actor.getProfiles")
            .map_err(|e| e.to_string())?;

    for did in &dids {
        url.query_pairs_mut().append_pair("actors", did);
    }

    let resp = client
        .get(url)
        .bearer_auth(&token)
        .send()
        .await
        .map_err(|e| format!("Profile fetch failed: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("Profile fetch failed: {}", resp.status()));
    }

    let data: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
    let profiles = data["profiles"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .map(|p| ProfileView {
                    did: p["did"].as_str().unwrap_or("").to_string(),
                    handle: p["handle"].as_str().unwrap_or("").to_string(),
                    display_name: p["displayName"].as_str().map(|s| s.to_string()),
                    avatar: p["avatar"].as_str().map(|s| s.to_string()),
                })
                .collect()
        })
        .unwrap_or_default();

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

fn parse_did(s: &str) -> Result<Did, String> {
    Did::new_owned(s).map_err(|e| format!("invalid DID `{s}`: {e}"))
}

fn parse_lexicon_json<'de, T>(body: &'de [u8]) -> std::result::Result<T::Output, String>
where
    T: serde::Deserialize<'de> + IntoStatic,
{
    let parsed: T = serde_json::from_slice(body).map_err(|e| e.to_string())?;
    Ok(parsed.into_static())
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
    if query.trim().is_empty() {
        return Ok(vec![]);
    }

    let token = require_auth_token(&state)?;
    let client = reqwest::Client::new();
    let url = reqwest::Url::parse_with_params(
        "https://public.api.bsky.app/xrpc/app.bsky.actor.searchActorsTypeahead",
        &[("q", query.as_str()), ("limit", "10")],
    )
    .map_err(|e| e.to_string())?;

    let resp = client
        .get(url)
        .bearer_auth(&token)
        .send()
        .await
        .map_err(|e| format!("Search failed: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("Search failed: {}", resp.status()));
    }

    let data: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
    let results = data["actors"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .map(|a| SearchResult {
                    did: a["did"].as_str().unwrap_or("").to_string(),
                    handle: a["handle"].as_str().unwrap_or("").to_string(),
                    display_name: a["displayName"].as_str().map(|s| s.to_string()),
                    avatar: a["avatar"].as_str().map(|s| s.to_string()),
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(results)
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
    if dids.is_empty() {
        return Ok(vec![]);
    }

    let token = require_auth_token(&state)?;
    let client = reqwest::Client::new();
    let home_ds_did = crate::mls::TauriMlsManager::home_ds_did();
    let home_ds_url = crate::mls::TauriMlsManager::home_ds_endpoint();
    let sa_resp = client
        .get(format!(
            "{}/xrpc/com.atproto.server.getServiceAuth",
            crate::nest_url().trim_end_matches('/')
        ))
        .query(&[
            ("aud", home_ds_did.as_str()),
            ("lxm", "blue.catbird.chat.getDevices"),
        ])
        .bearer_auth(&token)
        .send()
        .await
        .map_err(|e| format!("getServiceAuth for getDevices failed: {e}"))?;

    if !sa_resp.status().is_success() {
        return Err(format!(
            "getServiceAuth for getDevices failed: {}",
            sa_resp.status()
        ));
    }
    let sa_json: serde_json::Value = sa_resp.json().await.map_err(|e| e.to_string())?;
    let service_jwt = sa_json
        .get("token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "getServiceAuth missing token".to_string())?;

    let url = format!(
        "{}/xrpc/blue.catbird.chat.getDevices",
        home_ds_url.trim_end_matches('/')
    );
    let parsed_dids: Vec<Did> = dids
        .iter()
        .map(|did| parse_did(did))
        .collect::<Result<Vec<_>, _>>()?;
    let query_params: Vec<(&str, &str)> = parsed_dids
        .iter()
        .map(|d| ("userDids", d.as_str()))
        .collect();

    let resp = client
        .get(&url)
        .query(&query_params)
        .bearer_auth(service_jwt)
        .send()
        .await
        .map_err(|e| format!("Opt-in check failed: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("Opt-in check failed: {}", resp.status()));
    }

    let body = resp.bytes().await.map_err(|e| e.to_string())?;
    let output = parse_lexicon_json::<
        catbird_atproto::blue_catbird::chat::get_devices::GetDevicesOutput<String>,
    >(body.as_ref())?;

    let mut active_dids: std::collections::HashSet<String> = output
        .devices
        .iter()
        .map(|d| d.user_did.as_str().to_string())
        .collect();

    for did in &dids {
        if active_dids.contains(did.as_str()) {
            continue;
        }
        if let Ok(pds_resp) = client
            .get(format!(
                "{}/xrpc/com.atproto.repo.listRecords",
                crate::nest_url().trim_end_matches('/')
            ))
            .query(&[
                ("repo", did.as_str()),
                ("collection", "blue.catbird.chat.device"),
                ("limit", "1"),
            ])
            .bearer_auth(&token)
            .send()
            .await
        {
            if pds_resp.status().is_success() {
                if let Ok(json) = pds_resp.json::<serde_json::Value>().await {
                    if json
                        .get("records")
                        .and_then(|r| r.as_array())
                        .is_some_and(|arr| !arr.is_empty())
                    {
                        active_dids.insert(did.clone());
                    }
                }
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
    let token = require_auth_token(&state)?;
    let client = reqwest::Client::new();
    let home_ds_did = crate::mls::TauriMlsManager::home_ds_did();
    let home_ds_url = crate::mls::TauriMlsManager::home_ds_endpoint();
    let sa_resp = client
        .get(format!(
            "{}/xrpc/com.atproto.server.getServiceAuth",
            crate::nest_url().trim_end_matches('/')
        ))
        .query(&[
            ("aud", home_ds_did.as_str()),
            ("lxm", "blue.catbird.chat.reportSpam"),
        ])
        .bearer_auth(&token)
        .send()
        .await
        .map_err(|e| format!("getServiceAuth for reportSpam failed: {e}"))?;
    if !sa_resp.status().is_success() {
        return Err(format!(
            "getServiceAuth for reportSpam failed: {}",
            sa_resp.status()
        ));
    }
    let sa_json: serde_json::Value = sa_resp.json().await.map_err(|e| e.to_string())?;
    let service_jwt = sa_json["token"]
        .as_str()
        .ok_or_else(|| "getServiceAuth missing token".to_string())?;

    let mut body = serde_json::json!({
        "convoId": conversation_id,
        "reportedDid": reported_did,
    });
    if let Some(r) = reason {
        body["reason"] = serde_json::Value::String(r);
    }

    let resp = client
        .post(format!(
            "{}/xrpc/blue.catbird.chat.reportSpam",
            home_ds_url.trim_end_matches('/')
        ))
        .bearer_auth(service_jwt)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("reportSpam failed: {e}"))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(format!("reportSpam failed ({status}): {text}"));
    }
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

#[tauri::command]
pub async fn create_block(
    state: State<'_, AppState>,
    subject_did: String,
) -> Result<String, String> {
    let token = require_auth_token(&state)?;
    let did = require_authenticated_did(&state)?;
    let nest_url = crate::nest_url();

    let body = serde_json::json!({
        "repo": did,
        "collection": "app.bsky.graph.block",
        "record": {
            "$type": "app.bsky.graph.block",
            "subject": subject_did,
            "createdAt": chrono::Utc::now().to_rfc3339(),
        },
    });

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/xrpc/com.atproto.repo.createRecord", nest_url))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("createBlock request failed: {}", e))?;

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("createBlock failed: {} {}", status, body));
    }

    let result: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse createBlock response: {}", e))?;

    let uri = result
        .get("uri")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "createBlock response missing `uri`".to_string())?
        .to_string();

    Ok(uri)
}

#[tauri::command]
pub async fn list_own_blocks(state: State<'_, AppState>) -> Result<Vec<String>, String> {
    let token = require_auth_token(&state)?;
    let did = require_authenticated_did(&state)?;
    let nest_url = crate::nest_url();

    let client = reqwest::Client::new();
    let mut blocked: Vec<String> = Vec::new();
    let mut cursor: Option<String> = None;

    for _page in 0..1000 {
        let mut req = client
            .get(format!("{}/xrpc/com.atproto.repo.listRecords", nest_url))
            .bearer_auth(&token)
            .query(&[
                ("repo", did.as_str()),
                ("collection", "app.bsky.graph.block"),
                ("limit", "100"),
            ]);
        if let Some(c) = cursor.as_deref() {
            req = req.query(&[("cursor", c)]);
        }

        let resp = req
            .send()
            .await
            .map_err(|e| format!("listOwnBlocks request failed: {}", e))?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("listOwnBlocks failed: {} {}", status, body));
        }

        let page: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| format!("Failed to parse listRecords page: {}", e))?;

        let records = page.get("records").and_then(|v| v.as_array());
        let record_count = records.map(|r| r.len()).unwrap_or(0);
        if let Some(recs) = records {
            for rec in recs {
                if let Some(subject) = rec
                    .get("value")
                    .and_then(|v| v.get("subject"))
                    .and_then(|v| v.as_str())
                {
                    blocked.push(subject.to_string());
                }
            }
        }

        let next = page
            .get("cursor")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        if next.is_none() || record_count == 0 {
            break;
        }
        cursor = next;
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
        build_desktop_login_url, classify_pds_spaces_probe_response, cleanup_ws_handle,
        generate_browser_nonce, parse_permission_callback_url, ui_message_from_row,
    };
    use catbird_mls::payload_types::{
        MLSAudioEmbed, MLSEmbedData, MLSImageEmbed, MLSMessagePayload,
    };
    use catbird_mls::storage::MessageRow;
    use std::collections::HashMap;
    use std::sync::Arc;

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
    fn desktop_login_url_includes_43_char_browser_nonce_and_omits_client_by_default() {
        let nonce = generate_browser_nonce().expect("browser nonce");
        assert_eq!(nonce.len(), 43);
        let default_url = build_desktop_login_url(
            "https://api.catbird.blue",
            "swan.place",
            "http://127.0.0.1:43210/callback",
            &nonce,
            None,
        );
        assert!(default_url.contains("browser_nonce="));
        assert!(!default_url.contains("client=catmos"));

        let override_url = build_desktop_login_url(
            "https://api.catbird.blue",
            "swan.place",
            "http://127.0.0.1:43210/callback",
            &nonce,
            Some("catmos"),
        );
        assert!(override_url.contains("&client=catmos"));
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

    #[test]
    fn permission_callback_parser_matches_fixed_catbird_blue_callback_only() {
        let ok_url =
            reqwest::Url::parse("https://catbird.blue/oauth/permission-callback?code=abc123")
                .unwrap();
        assert_eq!(
            parse_permission_callback_url(&ok_url),
            Some(Ok("abc123".to_string()))
        );

        let err_url = reqwest::Url::parse(
            "https://catbird.blue/oauth/permission-callback?error=access_denied&error_description=User%20cancelled",
        )
        .unwrap();
        assert_eq!(
            parse_permission_callback_url(&err_url),
            Some(Err("access_denied: User cancelled".to_string()))
        );

        let other_url = reqwest::Url::parse("https://swan.place/oauth/authorize?foo=bar").unwrap();
        assert_eq!(parse_permission_callback_url(&other_url), None);
    }

    #[tokio::test]
    async fn exchange_oauth_code_sends_matching_origin_header() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let expected_origin = "http://127.0.0.1:42424";
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let n = socket.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            let resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 31\r\nConnection: close\r\n\r\n{\"session_id\":\"sess-ok-123456\"}";
            socket.write_all(resp.as_bytes()).await.unwrap();
            req
        });

        let session_id = super::exchange_oauth_code(
            &format!("http://{}", addr),
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
            expected_origin,
        )
        .await
        .expect("exchange should succeed");
        assert_eq!(session_id, "sess-ok-123456");

        let raw_req = server.await.unwrap();
        assert!(
            raw_req
                .lines()
                .any(|l| l.eq_ignore_ascii_case(&format!("origin: {expected_origin}"))),
            "POST /auth/exchange must send Origin header matching callback origin; got:\n{raw_req}"
        );
    }
}

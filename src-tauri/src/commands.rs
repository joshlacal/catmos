use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use catbird_atproto::blue_catbird;
use catbird_atproto::jacquard_common::IntoStatic;
use catbird_mls::blob_crypto::{decrypt_blob, encrypt_blob};
use catbird_mls::orchestrator::types::{DeliveryStatus, Message as OrchestratorMessage};
use catbird_mls::orchestrator::MLSAPIClient;
use catbird_mls::orchestrator::MLSStorageBackend;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tauri::{Emitter, State};
use tauri_plugin_shell::ShellExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::catbird::mls_chat as lexicon;
use crate::types::string::Did;

use crate::{AppState, CatmosOrchestrator, WsHandle};

fn log_file_path() -> std::path::PathBuf {
    let base = dirs::cache_dir()
        .or_else(dirs::data_local_dir)
        .unwrap_or_else(std::env::temp_dir);
    base.join("catmos").join("catmos.log")
}

/// Resolve the per-DID content-root key from disk and install it on the
/// shared `MLSContext`. Best-effort: any error is logged and the storage
/// layer keeps writing legacy plaintext columns until the next attempt.
/// Idempotent — re-running with the same DID is a no-op once the in-memory
/// key matches the file on disk.
fn install_content_root_key(state: &AppState, user_did: &str) {
    match crate::keys::load_or_create_content_root_key(&state.data_dir, user_did) {
        Ok(root_key) => {
            if let Err(err) = state
                .orchestrator
                .mls_context()
                .set_content_root_key(root_key)
            {
                tracing::warn!(
                    user_did = %user_did,
                    error = ?err,
                    "install_content_root_key: set_content_root_key failed"
                );
            } else {
                tracing::info!(
                    user_did = %user_did,
                    "install_content_root_key: field-level encryption key installed"
                );
            }
        }
        Err(err) => {
            tracing::warn!(
                user_did = %user_did,
                error = %err,
                "install_content_root_key: load_or_create_content_root_key failed; storage will fall back to plaintext columns"
            );
        }
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

pub fn spawn_key_package_monitor(
    orchestrator: Arc<CatmosOrchestrator>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            match orchestrator.replenish_if_needed().await {
                Ok(()) => {}
                Err(e) => {
                    log_catmos!("Key package replenishment failed: {:?}", e);
                }
            }
        }
    })
}

/// Ensure the user is opted into MLS. Checks status first, then opts in if needed.
/// Failures are logged but never propagated — opt-in should not block login.
async fn ensure_opted_in(state: &AppState) {
    let did = match state.orchestrator.api_client().current_did().await {
        Some(d) => d,
        None => return,
    };

    // Check current status
    match state.api_client.get_opt_in_status(&did).await {
        Ok(true) => {
            log_catmos!("Already opted into MLS");
            return;
        }
        Ok(false) => {
            log_catmos!("Not yet opted in — opting in automatically");
        }
        Err(e) => {
            log_catmos!(
                "Failed to check opt-in status: {:?} — attempting opt-in anyway",
                e
            );
        }
    }

    // Attempt opt-in with a single retry
    for attempt in 1..=2 {
        match state.api_client.opt_in(None).await {
            Ok(()) => {
                log_catmos!("MLS opt-in succeeded (attempt {})", attempt);
                return;
            }
            Err(e) => {
                log_catmos!("MLS opt-in failed (attempt {}): {:?}", attempt, e);
                if attempt < 2 {
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                }
            }
        }
    }
}

async fn start_kp_monitor(state: &AppState) {
    let mut guard = state.kp_monitor.lock().await;
    if let Some(handle) = guard.take() {
        handle.abort();
    }
    *guard = Some(spawn_key_package_monitor(state.orchestrator.clone()));
}

/// Periodic sync loop — calls sync_with_server every SYNC_INTERVAL_SECS (spec §6.1).
fn spawn_sync_loop(orchestrator: Arc<CatmosOrchestrator>) -> tokio::task::JoinHandle<()> {
    use catbird_mls::orchestrator::constants::SYNC_INTERVAL_SECS;
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(SYNC_INTERVAL_SECS)).await;
            if let Err(e) = orchestrator.sync_with_server(false).await {
                tracing::debug!("Sync cycle error: {:?}", e);
            }
        }
    })
}

async fn start_sync_loop(state: &AppState) {
    let mut guard = state.sync_loop.lock().await;
    if let Some(handle) = guard.take() {
        handle.abort();
    }
    *guard = Some(spawn_sync_loop(state.orchestrator.clone()));
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthResponse {
    pub did: String,
    pub handle: String,
    pub display_name: Option<String>,
    pub avatar: Option<String>,
}

#[derive(Debug, Clone)]
struct SessionInfo {
    did: String,
    handle: String,
}

fn clear_saved_session_credentials() {
    if let Ok(entry) = keyring::Entry::new("catmos", "session_id") {
        let _ = entry.delete_credential();
    }
    if let Ok(entry) = keyring::Entry::new("catmos", "user_did") {
        let _ = entry.delete_credential();
    }
}

async fn fetch_session_info(session_id: &str) -> Result<SessionInfo, String> {
    let nest_url =
        std::env::var("NEST_URL").unwrap_or_else(|_| "https://api.catbird.blue".to_string());

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

    Ok(SessionInfo { did, handle })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Conversation {
    /// Stable conversation identifier (survives group resets). Use for API calls and storage.
    pub id: String,
    /// Current MLS group identifier (hex). Changes on group reset. For display/debug only.
    pub group_id: String,
    pub display_name: String,
    pub description: Option<String>,
    pub members: Vec<String>,
    pub last_message: Option<String>,
    pub last_message_at: Option<String>,
    pub unread_count: u32,
    pub is_group: bool,
    /// Decrypted avatar rendered as a `data:` URL. Populated from the
    /// `avatar_bytes` column when the encrypted-metadata bootstrap fetched
    /// + decrypted an avatar blob; `None` otherwise. Frontend renders this
    /// directly into an `<img src>` slot.
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
    pub status: String,
    #[serde(default = "default_message_type")]
    pub message_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<ImageAttachment>,
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

fn default_message_type() -> String {
    "text".to_string()
}

fn image_attachment_from_message(message: &OrchestratorMessage) -> Option<ImageAttachment> {
    let embed = message.image_embed()?;
    Some(ImageAttachment {
        blob_id: embed.blob_id,
        key_b64: B64.encode(embed.key),
        iv_b64: B64.encode(embed.iv),
        sha256: embed.sha256,
        content_type: embed.content_type,
        size: embed.size,
        width: embed.width,
        height: embed.height,
        alt_text: embed.alt_text,
        blurhash: embed.blurhash,
    })
}

pub(crate) fn ui_message_from_orchestrator(message: OrchestratorMessage) -> Message {
    use catbird_mls::orchestrator::types::MLSMessageType;

    let image = image_attachment_from_message(&message);

    // Detect system messages from payload
    let (message_type, content) = if let Some(payload) = message.payload() {
        if payload.message_type == MLSMessageType::System {
            let display_text = match payload.text.as_deref() {
                Some("history_boundary.new_member") => "You joined this conversation".to_string(),
                Some("history_boundary.device_rejoined") => {
                    "Messages before this point aren't available on this device".to_string()
                }
                Some(other) => other.to_string(),
                None => message.text.clone(),
            };
            ("system".to_string(), display_text)
        } else if image.is_some() {
            ("image".to_string(), message.text.clone())
        } else {
            ("text".to_string(), message.text.clone())
        }
    } else if image.is_some() {
        ("image".to_string(), message.text.clone())
    } else {
        ("text".to_string(), message.text.clone())
    };

    Message {
        id: message.id,
        conversation_id: message.conversation_id,
        sender_did: message.sender_did,
        sender_handle: String::new(),
        content,
        timestamp: message.timestamp.to_rfc3339(),
        status: ui_status_for_delivery(message.is_own, message.delivery_status.as_ref()),
        message_type,
        image,
    }
}

pub(crate) fn ui_status_for_delivery(
    is_own: bool,
    delivery_status: Option<&DeliveryStatus>,
) -> String {
    if !is_own {
        return "delivered".to_string();
    }

    match delivery_status {
        Some(DeliveryStatus::DeliveredToAll) | Some(DeliveryStatus::LocalOnly) => {
            "delivered".to_string()
        }
        Some(DeliveryStatus::Partial { .. }) | Some(DeliveryStatus::Pending) | None => {
            "sent".to_string()
        }
    }
}

async fn refresh_message_delivery_statuses(
    state: &AppState,
    conversation_id: &str,
    messages: &mut [OrchestratorMessage],
) {
    let own_ids: Vec<String> = messages
        .iter()
        .filter(|m| m.is_own)
        .map(|m| m.id.clone())
        .collect();
    if own_ids.is_empty() {
        return;
    }

    let mut status_by_id = std::collections::HashMap::<String, DeliveryStatus>::new();
    for chunk in own_ids.chunks(50) {
        match state
            .orchestrator
            .api_client()
            .get_delivery_status(conversation_id, chunk)
            .await
        {
            Ok(statuses) => {
                for (message_id, status) in statuses {
                    status_by_id.insert(message_id, status);
                }
            }
            Err(e) => {
                log_catmos!(
                    " refresh delivery status failed: convo={} count={} err={:?}",
                    conversation_id,
                    chunk.len(),
                    e
                );
            }
        }
    }

    for message in messages.iter_mut() {
        let Some(status) = status_by_id.get(&message.id) else {
            continue;
        };
        if message.delivery_status.as_ref() == Some(status) {
            continue;
        }
        message.delivery_status = Some(status.clone());
        if let Err(e) = state.orchestrator.storage().store_message(message).await {
            log_catmos!(
                " persist delivery status failed: convo={} msg={} err={:?}",
                conversation_id,
                message.id,
                e
            );
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReactionEvent {
    pub conversation_id: String,
    pub message_id: String,
    pub sender_did: String,
    pub emoji: String,
    pub action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TypingEvent {
    pub conversation_id: String,
    pub sender_did: String,
    pub is_typing: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupMember {
    pub did: String,
    pub handle: String,
    pub display_name: Option<String>,
    pub role: String,
}

#[tauri::command]
pub async fn start_login(app: tauri::AppHandle, identifier: String) -> Result<(), String> {
    let nest_url =
        std::env::var("NEST_URL").unwrap_or_else(|_| "https://api.catbird.blue".to_string());

    // Bind a temporary HTTP server on a random localhost port
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("Failed to bind callback server: {}", e))?;
    let port = listener
        .local_addr()
        .map_err(|e| format!("Failed to get port: {}", e))?
        .port();

    let redirect_to = format!("http://127.0.0.1:{}/callback", port);
    let login_url = format!(
        "{}/auth/login?identifier={}&client=catmos&redirect_to={}",
        nest_url,
        urlencoding::encode(&identifier),
        urlencoding::encode(&redirect_to)
    );

    // Open system browser
    #[allow(deprecated)]
    {
        app.shell()
            .open(&login_url, None)
            .map_err(|e| e.to_string())?;
    }

    // Spawn async task to wait for the OAuth callback
    let app_handle = app.clone();
    tokio::spawn(async move {
        match tokio::time::timeout(
            std::time::Duration::from_secs(300),
            wait_for_callback(listener),
        )
        .await
        {
            Ok(Ok(session_id)) => {
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

async fn wait_for_callback(listener: TcpListener) -> Result<String, String> {
    const MAX_REQUEST_SIZE: usize = 8192;

    let (mut stream, _) = listener
        .accept()
        .await
        .map_err(|e| format!("Accept failed: {}", e))?;

    // Read in a loop up to MAX_REQUEST_SIZE, stop when we see the end of headers
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
        // We only need headers (GET request has no body), so stop once we see \r\n\r\n
        if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }

    // Parse the HTTP request line with httparse
    let mut headers = [httparse::EMPTY_HEADER; 16];
    let mut req = httparse::Request::new(&mut headers);
    req.parse(&buf[..total])
        .map_err(|e| format!("HTTP parse error: {}", e))?;

    let path = req.path.ok_or("No path in HTTP request")?;

    // Extract query string from the path
    let query = path
        .split_once('?')
        .map(|(_, q)| q)
        .ok_or("No query string in callback URL")?;

    // Find session_id parameter and URL-decode its value
    let session_id = query
        .split('&')
        .find_map(|param| {
            param.strip_prefix("session_id=").map(|v| {
                urlencoding::decode(v)
                    .unwrap_or_else(|_| v.into())
                    .into_owned()
            })
        })
        .ok_or_else(|| "No session_id in callback".to_string())?;

    // Send HTML response telling user to close the tab
    let html = r#"<!DOCTYPE html><html><body style="font-family:system-ui;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#1a1a2e;color:#e0e0e0"><div style="text-align:center"><h1>✅ Signed in!</h1><p>You can close this tab and return to Catmos.</p></div></body></html>"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        html.len(),
        html
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.flush().await;

    Ok(session_id)
}

#[tauri::command]
pub async fn complete_login(
    state: State<'_, AppState>,
    session_id: String,
) -> Result<AuthResponse, String> {
    let session = fetch_session_info(&session_id).await?;

    // Initialize orchestrator for this user
    state
        .orchestrator
        .initialize(&session.did)
        .await
        .map_err(|e| format!("{:?}", e))?;

    // Install the per-DID content-root key so the field-level (envelope)
    // encryption layer can encrypt subsequent message inserts. Best-effort:
    // a failure here downgrades to legacy plaintext writes with a warning
    // rather than blocking login.
    install_content_root_key(&state, &session.did);

    // Set auth on API client (before device registration and opt-in, which need auth)
    state
        .api_client
        .set_auth(session.did.clone(), session_id.clone());

    // Ensure device is registered with MLS service (generates keys, publishes key packages)
    state
        .orchestrator
        .ensure_device_registered()
        .await
        .map_err(|e| format!("{:?}", e))?;

    // Auto opt-in to MLS (non-blocking — failures are logged only)
    ensure_opted_in(&state).await;

    // Start background key package replenishment
    start_kp_monitor(&state).await;

    // Start periodic sync loop (spec §6.1)
    start_sync_loop(&state).await;

    // Persist session to keyring
    if let Ok(entry) = keyring::Entry::new("catmos", "session_id") {
        let _ = entry.set_password(&session_id);
    }
    if let Ok(entry) = keyring::Entry::new("catmos", "user_did") {
        let _ = entry.set_password(&session.did);
    }

    Ok(AuthResponse {
        did: session.did,
        handle: session.handle,
        display_name: None,
        avatar: None,
    })
}

#[tauri::command]
pub async fn try_restore_session(
    state: State<'_, AppState>,
) -> Result<Option<AuthResponse>, String> {
    let session_id = keyring::Entry::new("catmos", "session_id")
        .and_then(|e| e.get_password())
        .ok();
    let did = keyring::Entry::new("catmos", "user_did")
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
                        state.api_client.clear_auth();
                        return Ok(None);
                    }
                    log_catmos!(
                        "Stored session could not be restored yet; keeping saved login: {}",
                        e
                    );
                    return Err(e);
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
            state
                .orchestrator
                .initialize(&session.did)
                .await
                .map_err(|e| format!("{:?}", e))?;
            // Install the per-DID content-root key for the field-level
            // encryption layer; see `complete_login` for rationale.
            install_content_root_key(&state, &session.did);
            state.api_client.set_auth(session.did.clone(), sid.clone());

            // Ensure device is registered (idempotent — skips if already done)
            state
                .orchestrator
                .ensure_device_registered()
                .await
                .map_err(|e| format!("{:?}", e))?;

            // Auto opt-in to MLS (non-blocking — failures are logged only)
            ensure_opted_in(&state).await;

            // Start background key package replenishment
            start_kp_monitor(&state).await;

            // Start periodic sync loop (spec §6.1)
            start_sync_loop(&state).await;

            if let Ok(entry) = keyring::Entry::new("catmos", "user_did") {
                let _ = entry.set_password(&session.did);
            }
            log_catmos!("Session restored: handle={}", session.handle);

            Ok(Some(AuthResponse {
                did: session.did,
                handle: session.handle,
                display_name: None,
                avatar: None,
            }))
        }
        _ => Ok(None),
    }
}

#[tauri::command]
pub async fn logout(state: State<'_, AppState>) -> Result<(), String> {
    // Stop key package monitor
    if let Some(handle) = state.kp_monitor.lock().await.take() {
        handle.abort();
    }
    // Stop sync loop
    if let Some(handle) = state.sync_loop.lock().await.take() {
        handle.abort();
    }
    // Drop the in-memory content-root key. The file on disk is preserved so
    // re-login on the same machine resumes the same chain seed; an explicit
    // wipe path (account removal) would also call `keys::delete_content_root_key`.
    state.orchestrator.mls_context().clear_content_root_key();
    state.orchestrator.shutdown().await;
    state.api_client.clear_auth();
    clear_saved_session_credentials();
    Ok(())
}

#[tauri::command]
pub async fn get_conversations(state: State<'_, AppState>) -> Result<Vec<Conversation>, String> {
    // Sync with server first — joins any groups we were added to
    if let Err(e) = state.orchestrator.sync_with_server(false).await {
        log_catmos!(" sync_with_server warning: {}", e);
    }

    let page = state
        .orchestrator
        .api_client()
        .get_conversations(50, None)
        .await
        .map_err(|e| e.to_string())?;

    // Encrypted-metadata cutover: titles/descriptions/avatars come from the
    // local SQLite cache populated by `bootstrap_group_metadata` after every
    // Welcome / commit-merge that touches metadata. The server no longer
    // exposes plaintext title (post-Phase-E), and the plaintext 0xff00
    // extension is gone (Wave 1). For any row where the bootstrap has not
    // yet run (first observation post-restart or a freshly-joined group
    // whose Welcome arrived during this same tick), opportunistically
    // bootstrap inline so the very next render has a real title.
    let mut convos: Vec<Conversation> = Vec::with_capacity(page.conversations.len());
    for c in page.conversations.into_iter() {
        let member_dids: Vec<String> = c.members.iter().map(|m| m.did.clone()).collect();

        // Lazy bootstrap on miss. Best-effort; failure leaves the snapshot
        // empty and we fall back to a member-DID join below.
        let mut snapshot = state
            .orchestrator
            .storage()
            .get_metadata_snapshot(&c.conversation_id);
        let needs_bootstrap = snapshot
            .as_ref()
            .map(|s| s.metadata_json.is_none())
            .unwrap_or(true);
        if needs_bootstrap {
            if let Err(e) = bootstrap_group_metadata(&state, &c.group_id, &c.conversation_id).await
            {
                log_catmos!(
                    "get_conversations: lazy bootstrap failed for {}: {}",
                    c.conversation_id,
                    e
                );
            }
            snapshot = state
                .orchestrator
                .storage()
                .get_metadata_snapshot(&c.conversation_id);
        }

        let payload: Option<catbird_mls::metadata::GroupMetadataV1> = snapshot
            .as_ref()
            .and_then(|s| s.metadata_json.as_deref())
            .and_then(|j| serde_json::from_str(j).ok());

        let display_name = payload
            .as_ref()
            .map(|p| p.title.clone())
            .filter(|t| !t.is_empty())
            .unwrap_or_else(|| member_dids.join(", "));
        let description = payload
            .as_ref()
            .map(|p| p.description.clone())
            .filter(|d| !d.is_empty());

        let avatar_data_url = state
            .orchestrator
            .storage()
            .get_avatar(&c.conversation_id)
            .map(|(bytes, ct)| {
                let mime = ct.unwrap_or_else(|| "image/jpeg".to_string());
                format!("data:{};base64,{}", mime, B64.encode(&bytes))
            });

        convos.push(Conversation {
            id: c.conversation_id.clone(),
            group_id: c.group_id,
            display_name,
            description,
            members: member_dids.clone(),
            last_message: None,
            last_message_at: None,
            unread_count: 0,
            is_group: member_dids.len() > 2,
            avatar_data_url,
        });
    }

    Ok(convos)
}

#[tauri::command]
pub async fn create_group(
    state: State<'_, AppState>,
    name: String,
    member_dids: Vec<String>,
    description: Option<String>,
) -> Result<Conversation, String> {
    log_catmos!(
        " create_group called: name={}, members={:?}, description={:?}",
        name,
        member_dids,
        description
    );

    let members = if member_dids.is_empty() {
        None
    } else {
        Some(member_dids.as_slice())
    };

    let convo = state
        .orchestrator
        .create_group(&name, members, description.as_deref())
        .await
        .map_err(|e| {
            log_catmos!(" create_group error: {:?}", e);
            format!("{:?}", e)
        })?;

    log_catmos!(" create_group success: group_id={}", convo.group_id);

    let member_list: Vec<String> = convo.members.iter().map(|m| m.did.clone()).collect();

    // Encrypted-metadata cutover: server-plaintext `convo.metadata` is gone
    // post-cutover. The orchestrator's create flow has already produced an
    // epoch-0 group with a `MetadataReference` in AppDataDictionary 0x8001
    // (when name/description were supplied). Run the bootstrap to fetch +
    // decrypt the freshly-uploaded blob so the local SQLite cache has the
    // title/description before the Tauri command returns to the UI.
    if let Err(e) = bootstrap_group_metadata(&state, &convo.group_id, &convo.conversation_id).await
    {
        log_catmos!(
            " create_group: bootstrap_group_metadata failed for {}: {}",
            convo.conversation_id,
            e
        );
    }

    let snapshot = state
        .orchestrator
        .storage()
        .get_metadata_snapshot(&convo.conversation_id);
    let payload: Option<catbird_mls::metadata::GroupMetadataV1> = snapshot
        .as_ref()
        .and_then(|s| s.metadata_json.as_deref())
        .and_then(|j| serde_json::from_str(j).ok());

    let display_name = payload
        .as_ref()
        .map(|p| p.title.clone())
        .filter(|t| !t.is_empty())
        .unwrap_or_else(|| {
            // Fall back to the requested name (the bootstrap may not have
            // run yet if the orchestrator hasn't uploaded the blob in this
            // build) — never expose the server's plaintext field.
            if !name.is_empty() {
                name.clone()
            } else {
                member_list.join(", ")
            }
        });
    let desc = payload
        .as_ref()
        .map(|p| p.description.clone())
        .filter(|d| !d.is_empty())
        .or_else(|| description.clone());

    let avatar_data_url = state
        .orchestrator
        .storage()
        .get_avatar(&convo.conversation_id)
        .map(|(bytes, ct)| {
            let mime = ct.unwrap_or_else(|| "image/jpeg".to_string());
            format!("data:{};base64,{}", mime, B64.encode(&bytes))
        });

    Ok(Conversation {
        id: convo.conversation_id.clone(),
        group_id: convo.group_id,
        display_name,
        description: desc,
        members: member_list.clone(),
        last_message: None,
        last_message_at: None,
        unread_count: 0,
        is_group: member_list.len() > 2,
        avatar_data_url,
    })
}

#[tauri::command]
pub async fn send_message(
    state: State<'_, AppState>,
    conversation_id: String,
    content: String,
) -> Result<Message, String> {
    log_catmos!(" send_message: convo={}", conversation_id);

    let msg = state
        .orchestrator
        .send_message(&conversation_id, &content)
        .await
        .map_err(|e| {
            log_catmos!(" send_message error: {:?}", e);
            format!("{:?}", e)
        })?;

    Ok(ui_message_from_orchestrator(msg))
}

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
    log_catmos!(
        " send_image: convo={} bytes={} type={} dims={}x{}",
        conversation_id,
        data.len(),
        content_type,
        width,
        height
    );

    if !content_type.starts_with("image/") {
        return Err(format!("Unsupported image content type: {content_type}"));
    }
    if data.len() > 10 * 1024 * 1024 {
        return Err("Image too large (max 10MB)".to_string());
    }

    let encrypted = encrypt_blob(&data).map_err(|e| e.to_string())?;
    let (blob_id, _uploaded_size) = state
        .api_client
        .upload_blob(&encrypted.ciphertext, &conversation_id)
        .await
        .map_err(|e| format!("{:?}", e))?;

    let embed = catbird_mls::orchestrator::types::MLSEmbedData::image(
        catbird_mls::orchestrator::types::MLSImageEmbed {
            blob_id,
            key: encrypted.key,
            iv: encrypted.iv,
            sha256: encrypted.sha256,
            content_type,
            size: data.len(),
            width,
            height,
            alt_text,
            blurhash: None,
        },
    )
    .map_err(|e| e.to_string())?;

    let msg = state
        .orchestrator
        .send_message_with_embed(&conversation_id, &content, embed)
        .await
        .map_err(|e| {
            log_catmos!(" send_image error: {:?}", e);
            format!("{:?}", e)
        })?;

    Ok(ui_message_from_orchestrator(msg))
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
    let key = B64
        .decode(key_b64)
        .map_err(|e| format!("Invalid image key: {e}"))?;
    let iv = B64
        .decode(iv_b64)
        .map_err(|e| format!("Invalid image IV: {e}"))?;
    let ciphertext = state
        .api_client
        .get_blob(&blob_id)
        .await
        .map_err(|e| format!("{:?}", e))?;
    let plaintext = decrypt_blob(&ciphertext, &key, &iv, &sha256).map_err(|e| e.to_string())?;

    Ok(format!(
        "data:{};base64,{}",
        content_type,
        B64.encode(plaintext)
    ))
}

#[tauri::command]
pub async fn get_messages(
    state: State<'_, AppState>,
    conversation_id: String,
    before: Option<String>,
) -> Result<Vec<Message>, String> {
    // Try local storage first
    let before_seq = before.and_then(|b| b.parse::<u64>().ok());
    let mut stored = state
        .orchestrator
        .storage()
        .get_messages(&conversation_id, 50, before_seq)
        .await
        .map_err(|e| format!("{:?}", e))?;

    refresh_message_delivery_statuses(&state, &conversation_id, &mut stored).await;

    let messages = stored
        .into_iter()
        .filter(|m| m.has_displayable_body())
        .map(ui_message_from_orchestrator)
        .collect();

    Ok(messages)
}

#[tauri::command]
pub async fn get_group_members(
    state: State<'_, AppState>,
    conversation_id: String,
) -> Result<Vec<GroupMember>, String> {
    let user_did = state
        .orchestrator
        .api_client()
        .current_did()
        .await
        .unwrap_or_default();

    let convo = state
        .orchestrator
        .storage()
        .get_conversation(&user_did, &conversation_id)
        .await
        .map_err(|e| e.to_string())?;

    match convo {
        Some(c) => Ok(c
            .members
            .into_iter()
            .map(|m| GroupMember {
                did: m.did.clone(),
                handle: String::new(),
                display_name: None,
                role: format!("{:?}", m.role),
            })
            .collect()),
        None => Ok(vec![]),
    }
}

#[tauri::command]
pub async fn subscribe_conversation(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    conversation_id: String,
) -> Result<(), String> {
    // Don't subscribe twice
    {
        let handles = state.ws_handles.lock().await;
        if handles.contains_key(&conversation_id) {
            return Ok(());
        }
    }

    let token = state
        .api_client
        .get_auth_token()
        .ok_or("Not authenticated")?;

    let base_url =
        std::env::var("NEST_URL").unwrap_or_else(|_| "https://api.catbird.blue".to_string());

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let orchestrator = state.orchestrator.clone();

    let handle = WsHandle {
        shutdown: shutdown_tx,
    };

    state
        .ws_handles
        .lock()
        .await
        .insert(conversation_id.clone(), handle);

    let convo_id = conversation_id.clone();
    let api_client = state.api_client.clone();
    tokio::spawn(async move {
        crate::websocket::subscribe_conversation(
            app,
            orchestrator,
            api_client,
            base_url,
            token,
            convo_id,
            shutdown_rx,
        )
        .await;
    });

    log_catmos!(" subscribe_conversation: convo={}", conversation_id);
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

/// Open a single WebSocket that receives events for EVERY conversation the
/// authenticated user is a member of. This is the preferred wiring — it
/// matches iOS/Android/CLI and ensures messages in background conversations
/// aren't dropped waiting for the user to navigate into them. Per-convo
/// subscribe_conversation remains available for targeted re-subscription.
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

    let token = state
        .api_client
        .get_auth_token()
        .ok_or("Not authenticated")?;

    let base_url =
        std::env::var("NEST_URL").unwrap_or_else(|_| "https://api.catbird.blue".to_string());

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let orchestrator = state.orchestrator.clone();

    state.ws_handles.lock().await.insert(
        GLOBAL_KEY.to_string(),
        WsHandle {
            shutdown: shutdown_tx,
        },
    );

    let api_client = state.api_client.clone();
    tokio::spawn(async move {
        crate::websocket::subscribe_all(
            app,
            orchestrator,
            api_client,
            base_url,
            token,
            shutdown_rx,
        )
        .await;
    });

    log_catmos!(" subscribe_all_events: global WS opened");
    Ok(())
}

/// Tear down the global WebSocket started by `subscribe_all_events`.
/// Call on logout; leaving it running after auth teardown leaks the stream.
#[tauri::command]
pub async fn unsubscribe_all_events(state: State<'_, AppState>) -> Result<(), String> {
    if let Some(handle) = state.ws_handles.lock().await.remove("__global__") {
        let _ = handle.shutdown.send(true);
        log_catmos!(" unsubscribe_all_events: global WS torn down");
    }
    Ok(())
}

#[tauri::command]
pub async fn fetch_new_messages(
    state: State<'_, AppState>,
    conversation_id: String,
) -> Result<Vec<Message>, String> {
    let (msgs, _cursor) = state
        .orchestrator
        .fetch_messages(&conversation_id, None, 50, Some("app"), None, None)
        .await
        .map_err(|e| format!("{:?}", e))?;

    Ok(msgs.into_iter().map(ui_message_from_orchestrator).collect())
}

#[tauri::command]
pub async fn get_profiles(
    state: State<'_, AppState>,
    dids: Vec<String>,
) -> Result<Vec<ProfileView>, String> {
    if dids.is_empty() {
        return Ok(vec![]);
    }

    let token = state
        .api_client
        .get_auth_token()
        .ok_or("Not authenticated")?;

    // Use Bluesky public API to fetch profiles
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
    log_catmos!(
        " send_reaction: convo={}, msg={}, emoji={}, action={}",
        conversation_id,
        message_id,
        emoji,
        action
    );

    let reaction_action = if action == "remove" {
        catbird_mls::orchestrator::types::ReactionAction::Remove
    } else {
        catbird_mls::orchestrator::types::ReactionAction::Add
    };

    state
        .orchestrator
        .send_reaction(&conversation_id, &message_id, &emoji, reaction_action)
        .await
        .map_err(|e| {
            log_catmos!(" send_reaction error: {:?}", e);
            format!("{:?}", e)
        })?;

    Ok(())
}

#[tauri::command]
pub async fn send_typing(
    state: State<'_, AppState>,
    conversation_id: String,
    is_typing: bool,
) -> Result<(), String> {
    log_catmos!(
        " send_typing: convo={}, is_typing={}",
        conversation_id,
        is_typing
    );

    // The canonical blue.catbird.chat.publishTyping endpoint requires a
    // signed request (device identity, DPoP binding, and typing body). The
    // old mlsChat.sendMessage/ephemeral shim fabricated ciphertext and is not
    // a valid substitute. Do not emit a misleading network request until the
    // catmos signing adapter is available.
    let _ = (conversation_id, is_typing);
    Err("Typing is temporarily unavailable: canonical signed typing transport is not wired".into())
}

#[tauri::command]
pub async fn update_cursor(
    state: State<'_, AppState>,
    conversation_id: String,
    cursor: String,
) -> Result<(), String> {
    log_catmos!(
        " update_cursor: convo={}, cursor={}",
        conversation_id,
        cursor
    );

    state
        .api_client
        .update_cursor(&conversation_id, &cursor)
        .await
        .map_err(|e| format!("Update cursor failed: {e:?}"))
}

fn parse_did(s: &str) -> Did {
    Did::new_owned(s.to_string()).unwrap_or_else(|_| panic!("invalid DID: {}", s))
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

    let token = state
        .api_client
        .get_auth_token()
        .ok_or("Not authenticated")?;

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

    let token = state
        .api_client
        .get_auth_token()
        .ok_or("Not authenticated")?;

    let url = format!(
        "{}/xrpc/{}",
        std::env::var("NEST_URL").unwrap_or_else(|_| "https://api.catbird.blue".to_string()),
        lexicon::get_opt_in_status::NSID,
    );
    let input: lexicon::get_opt_in_status::Input = lexicon::get_opt_in_status::InputData {
        dids: dids.iter().map(|did| parse_did(did)).collect(),
    }
    .into();

    let client = reqwest::Client::new();
    let resp = crate::mls_proxy::with_mls_proxy_header(client.post(&url))
        .bearer_auth(&token)
        .json(&input)
        .send()
        .await
        .map_err(|e| format!("Opt-in check failed: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("Opt-in check failed: {}", resp.status()));
    }

    let body = resp.bytes().await.map_err(|e| e.to_string())?;
    let output =
        parse_lexicon_json::<blue_catbird::mlsChat::opt_in::OptInOutput<String>>(body.as_ref())?;

    Ok(output
        .statuses
        .unwrap_or_default()
        .iter()
        .map(|s| OptInStatusResult {
            did: s.did.to_string(),
            opted_in: s.opted_in,
        })
        .collect())
}

#[tauri::command]
pub async fn promote_member(
    state: State<'_, AppState>,
    conversation_id: String,
    target_did: String,
) -> Result<(), String> {
    let token = state
        .api_client
        .get_auth_token()
        .ok_or("Not authenticated")?;

    let nest_url =
        std::env::var("NEST_URL").unwrap_or_else(|_| "https://api.catbird.blue".to_string());

    let input: lexicon::promote_admin::Input = lexicon::promote_admin::InputData {
        convo_id: conversation_id,
        target_did: parse_did(&target_did),
    }
    .into();

    let client = reqwest::Client::new();
    let resp = crate::mls_proxy::with_mls_proxy_header(client.post(format!(
        "{}/xrpc/{}",
        nest_url,
        lexicon::promote_admin::NSID
    )))
    .bearer_auth(&token)
    .json(&input)
    .send()
    .await
    .map_err(|e| format!("Promote failed: {}", e))?;

    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("Promote failed: {}", body));
    }

    Ok(())
}

#[tauri::command]
pub async fn demote_member(
    state: State<'_, AppState>,
    conversation_id: String,
    target_did: String,
) -> Result<(), String> {
    let token = state
        .api_client
        .get_auth_token()
        .ok_or("Not authenticated")?;

    let nest_url =
        std::env::var("NEST_URL").unwrap_or_else(|_| "https://api.catbird.blue".to_string());

    let input: lexicon::demote_admin::Input = lexicon::demote_admin::InputData {
        convo_id: conversation_id,
        target_did: parse_did(&target_did),
    }
    .into();

    let client = reqwest::Client::new();
    let resp = crate::mls_proxy::with_mls_proxy_header(client.post(format!(
        "{}/xrpc/{}",
        nest_url,
        lexicon::demote_admin::NSID
    )))
    .bearer_auth(&token)
    .json(&input)
    .send()
    .await
    .map_err(|e| format!("Demote failed: {}", e))?;

    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("Demote failed: {}", body));
    }

    Ok(())
}

#[tauri::command]
pub async fn remove_group_member(
    state: State<'_, AppState>,
    conversation_id: String,
    target_did: String,
) -> Result<(), String> {
    log_catmos!(
        "remove_group_member: convo={}, target={}",
        conversation_id,
        target_did
    );

    state
        .orchestrator
        .remove_members(&conversation_id, &[target_did])
        .await
        .map_err(|e| format!("{:?}", e))?;

    Ok(())
}

#[tauri::command]
pub async fn get_group_metadata(
    state: State<'_, AppState>,
    conversation_id: String,
) -> Result<Option<serde_json::Value>, String> {
    // Post-cutover, group titles / descriptions live in the encrypted blob
    // path persisted by `bootstrap_group_metadata`. The plaintext 0xff00
    // extension is gone; serve everything from local SQLite.
    let snapshot = state
        .orchestrator
        .storage()
        .get_metadata_snapshot(&conversation_id);
    Ok(snapshot
        .and_then(|s| s.metadata_json)
        .and_then(|json| serde_json::from_str::<serde_json::Value>(&json).ok()))
}

/// Fetch + decrypt the encrypted group metadata blob for a group at its
/// current epoch and persist title/description/avatar into local SQLite.
///
/// Mirrors iOS `MLSConversationManager+Metadata.swift::bootstrapMetadataAfterJoin`.
/// Call after:
///   - `create_group` succeeds (we authored the first commit at epoch 0)
///   - a Welcome lands and the orchestrator joins a new group
///   - any commit merges that may have updated metadata
///
/// Reuses `catbird_mls::metadata::decrypt_metadata_blob` /
/// `decrypt_avatar_blob` for crypto. AAD = group_id || epoch ||
/// metadata_version, so the call is idempotent: re-running at the same
/// (epoch, version) produces the same plaintext and silently overwrites
/// the SQLite row.
async fn bootstrap_group_metadata(
    state: &AppState,
    group_id_hex: &str,
    convo_id: &str,
) -> std::result::Result<(), String> {
    bootstrap_group_metadata_for_ws(
        &state.orchestrator,
        &state.api_client,
        group_id_hex,
        convo_id,
    )
    .await
}

/// `bootstrap_group_metadata` variant that takes the orchestrator + API
/// client directly so the websocket task — which doesn't carry an
/// `AppState` reference — can drive the same flow inline after a successful
/// `merge_incoming_commit`.
pub(crate) async fn bootstrap_group_metadata_for_ws(
    orchestrator: &Arc<CatmosOrchestrator>,
    api_client: &Arc<crate::api_client::ReqwestApiClient>,
    group_id_hex: &str,
    convo_id: &str,
) -> std::result::Result<(), String> {
    let group_id_bytes = hex::decode(group_id_hex)
        .map_err(|e| format!("Invalid group_id hex {group_id_hex}: {e}"))?;

    let info = match orchestrator
        .mls_context()
        .get_current_metadata(group_id_bytes.clone())
        .map_err(|e| format!("get_current_metadata failed: {e:?}"))?
    {
        Some(info) => info,
        None => {
            log_catmos!(
                "bootstrap_group_metadata: no metadata key for {} (group not found locally)",
                group_id_hex
            );
            return Ok(());
        }
    };

    let Some(reference_json) = info.metadata_reference_json.as_ref() else {
        // No MetadataReference at AppDataDictionary 0x8001 for this group at
        // its current epoch. Two cases:
        //   (a) Newly-joined group whose first metadata commit has not yet
        //       landed — there is genuinely nothing to fetch.
        //   (b) Post-reset group: the conversation_id has a cached
        //       title/description from before the reset, but the new group
        //       (different group_id) has no `MetadataReference` because the
        //       reset created a fresh MLS group at epoch 0 with no metadata
        //       commit. Without action here, the user sees the title
        //       evaporate on every reset — a regression vs the pre-cutover
        //       behaviour where server plaintext survived. Detect this via
        //       "cached snapshot has a non-empty title" and re-publish under
        //       the new group's epoch exporter. The new group's
        //       `MetadataReference` will be installed by a subsequent
        //       `update_group_metadata` GroupContextExtensions commit (out
        //       of scope for Stream F — Phase A core parity), but the blob
        //       is uploaded immediately so other clients can fetch + decrypt
        //       it once the reference lands.
        if let Some(snapshot) = orchestrator.storage().get_metadata_snapshot(convo_id) {
            if let Some(payload) = snapshot.metadata_json.as_deref().and_then(|j| {
                serde_json::from_str::<catbird_mls::metadata::GroupMetadataV1>(j).ok()
            }) {
                let has_title = !payload.title.is_empty();
                let has_description = !payload.description.is_empty();
                if has_title || has_description {
                    log_catmos!(
                        "bootstrap_group_metadata: no MetadataReference at epoch {} for {}, but cached title={:?} present — auto-republishing",
                        info.epoch,
                        group_id_hex,
                        payload.title
                    );

                    let avatar_pair = orchestrator.storage().get_avatar(convo_id);
                    let avatar_bytes = avatar_pair.as_ref().map(|(b, _)| b.clone());
                    let avatar_content_type = avatar_pair.as_ref().and_then(|(_, ct)| ct.clone());

                    let key_arr: [u8; 32] = info
                        .metadata_key
                        .as_slice()
                        .try_into()
                        .map_err(|_| "metadata key length != 32".to_string())?;

                    // Bump metadata_version monotonically. Use the prior
                    // cached version + 1 (defaulting to 1 when absent).
                    let metadata_version: u64 = snapshot
                        .metadata_version
                        .map(|v| (v as u64).saturating_add(1))
                        .unwrap_or(1);

                    let avatar_locator = avatar_bytes
                        .as_ref()
                        .map(|_| uuid::Uuid::new_v4().to_string());

                    let new_payload = catbird_mls::metadata::GroupMetadataV1 {
                        version: 1,
                        title: payload.title.clone(),
                        description: payload.description.clone(),
                        avatar_blob_locator: avatar_locator.clone(),
                        avatar_content_type: avatar_content_type.clone(),
                    };

                    match catbird_mls::metadata::encrypt_metadata_blob(
                        &key_arr,
                        &group_id_bytes,
                        info.epoch,
                        metadata_version,
                        &new_payload,
                    ) {
                        Ok(metadata_ct) => {
                            let metadata_locator = uuid::Uuid::new_v4().to_string();
                            if let Err(e) = api_client
                                .put_group_metadata_blob(
                                    &metadata_locator,
                                    group_id_hex,
                                    &metadata_ct,
                                )
                                .await
                            {
                                log_catmos!(
                                    "bootstrap_group_metadata: post-reset metadata blob upload failed for {}: {:?}",
                                    convo_id,
                                    e
                                );
                            } else {
                                log_catmos!(
                                    "bootstrap_group_metadata: post-reset metadata blob {} uploaded for convo={} (epoch={} version={})",
                                    metadata_locator,
                                    convo_id,
                                    info.epoch,
                                    metadata_version
                                );

                                // Persist the new locator + version locally
                                // so subsequent `bootstrap_group_metadata`
                                // calls observe "in sync at this version"
                                // and skip a redundant fetch.
                                let payload_json =
                                    serde_json::to_string(&new_payload).unwrap_or_default();
                                let _ = orchestrator.storage().update_metadata_json(
                                    convo_id,
                                    &payload_json,
                                    metadata_version,
                                    &metadata_locator,
                                    avatar_locator.as_deref(),
                                    avatar_content_type.as_deref(),
                                );

                                // Optionally re-encrypt + upload the avatar.
                                if let (Some(locator), Some(bytes)) =
                                    (avatar_locator.as_deref(), avatar_bytes.as_deref())
                                {
                                    match catbird_mls::metadata::encrypt_avatar_blob(
                                        &key_arr,
                                        &group_id_bytes,
                                        info.epoch,
                                        metadata_version,
                                        bytes,
                                    ) {
                                        Ok(avatar_ct) => {
                                            if let Err(e) = api_client
                                                .put_group_metadata_blob(
                                                    locator,
                                                    group_id_hex,
                                                    &avatar_ct,
                                                )
                                                .await
                                            {
                                                log_catmos!(
                                                    "bootstrap_group_metadata: post-reset avatar upload failed for {}: {:?}",
                                                    convo_id,
                                                    e
                                                );
                                            }
                                        }
                                        Err(e) => {
                                            log_catmos!(
                                                "bootstrap_group_metadata: post-reset avatar encrypt failed for {}: {}",
                                                convo_id,
                                                e
                                            );
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            log_catmos!(
                                "bootstrap_group_metadata: post-reset metadata encrypt failed for {}: {}",
                                convo_id,
                                e
                            );
                        }
                    }

                    return Ok(());
                }
            }
        }
        log_catmos!(
            "bootstrap_group_metadata: no MetadataReference at AppDataDictionary 0x8001 for {} (epoch={}); nothing to fetch yet",
            group_id_hex,
            info.epoch
        );
        return Ok(());
    };

    let reference: catbird_mls::metadata::MetadataReference =
        serde_json::from_slice(reference_json)
            .map_err(|e| format!("MetadataReference deserialize failed: {e}"))?;

    // Skip the round-trip if local SQLite is already at this version with the
    // same locator — nothing has changed since the last bootstrap.
    if let Some(snapshot) = orchestrator.storage().get_metadata_snapshot(convo_id) {
        if snapshot.metadata_version == Some(reference.metadata_version as i64)
            && snapshot.metadata_blob_locator.as_deref() == Some(reference.blob_locator.as_str())
            && snapshot.metadata_json.is_some()
        {
            log_catmos!(
                "bootstrap_group_metadata: {} already in sync at version {} (locator {})",
                convo_id,
                reference.metadata_version,
                reference.blob_locator
            );
            return Ok(());
        }
    }

    let key_arr: [u8; 32] = info
        .metadata_key
        .as_slice()
        .try_into()
        .map_err(|_| "metadata key length != 32".to_string())?;

    let blob = api_client
        .get_group_metadata_blob(&reference.blob_locator, group_id_hex, Some("metadata"))
        .await
        .map_err(|e| format!("get_group_metadata_blob failed: {e:?}"))?;

    let payload = catbird_mls::metadata::decrypt_metadata_blob(
        &key_arr,
        &group_id_bytes,
        info.epoch,
        reference.metadata_version,
        &blob,
    )
    .map_err(|e| format!("decrypt_metadata_blob failed: {e}"))?;

    let payload_json = serde_json::to_string(&payload)
        .map_err(|e| format!("metadata payload serialize failed: {e}"))?;

    orchestrator
        .storage()
        .update_metadata_json(
            convo_id,
            &payload_json,
            reference.metadata_version,
            &reference.blob_locator,
            payload.avatar_blob_locator.as_deref(),
            payload.avatar_content_type.as_deref(),
        )
        .map_err(|e| format!("update_metadata_json failed: {e:?}"))?;

    log_catmos!(
        "bootstrap_group_metadata: persisted title={:?} description_len={} for {} (epoch={} version={})",
        payload.title,
        payload.description.len(),
        convo_id,
        info.epoch,
        reference.metadata_version
    );

    if let Some(avatar_locator) = payload.avatar_blob_locator.as_deref() {
        match api_client
            .get_group_metadata_blob(avatar_locator, group_id_hex, Some("avatar"))
            .await
        {
            Ok(avatar_ct) => {
                match catbird_mls::metadata::decrypt_avatar_blob(
                    &key_arr,
                    &group_id_bytes,
                    info.epoch,
                    reference.metadata_version,
                    &avatar_ct,
                ) {
                    Ok(avatar_bytes) => {
                        if let Err(e) = orchestrator.storage().update_avatar_bytes(
                            convo_id,
                            &avatar_bytes,
                            payload.avatar_content_type.as_deref(),
                        ) {
                            log_catmos!(
                                "bootstrap_group_metadata: avatar persist failed for {}: {:?}",
                                convo_id,
                                e
                            );
                        } else {
                            log_catmos!(
                                "bootstrap_group_metadata: persisted {} avatar bytes for {}",
                                avatar_bytes.len(),
                                convo_id
                            );
                        }
                    }
                    Err(e) => {
                        log_catmos!(
                            "bootstrap_group_metadata: decrypt_avatar_blob failed for {}: {}",
                            convo_id,
                            e
                        );
                    }
                }
            }
            Err(e) => {
                log_catmos!(
                    "bootstrap_group_metadata: avatar fetch failed for {}: {:?}",
                    convo_id,
                    e
                );
            }
        }
    }

    Ok(())
}

/// Re-encrypt the locally-known group metadata (title / description /
/// avatar bytes) under the freshly-reset group's epoch exporter and upload
/// the resulting blob — and, when an avatar is set, a second avatar blob —
/// to the server. Wired into the `reset_group` Tauri command's success path
/// so a reset preserves the user-visible group identity instead of
/// reverting to "did:plc:abc, did:plc:def".
///
/// The plan calls this `republish_group_metadata_after_reset`. It must be
/// invoked after the new group has been created locally and the
/// orchestrator has switched its in-memory state to the new group_id —
/// i.e. after a successful `bootstrap_reset_group` round trip + first
/// External Commit. We do a best-effort attempt; failure is logged but
/// non-fatal so a metadata-republish hiccup never blocks the user from
/// sending messages on the freshly-reset group.
async fn republish_group_metadata_after_reset(
    state: &AppState,
    convo_id: &str,
    new_group_id_hex: &str,
    new_reset_generation: i64,
    title: Option<String>,
    description: Option<String>,
    avatar_bytes: Option<Vec<u8>>,
    avatar_content_type: Option<String>,
) -> std::result::Result<(), String> {
    let group_id_bytes =
        hex::decode(new_group_id_hex).map_err(|e| format!("Invalid new_group_id hex: {e}"))?;

    let info = state
        .orchestrator
        .mls_context()
        .get_current_metadata(group_id_bytes.clone())
        .map_err(|e| format!("get_current_metadata failed: {e:?}"))?
        .ok_or_else(|| {
            format!(
                "no metadata key for new group {} (post-reset)",
                new_group_id_hex
            )
        })?;

    let key_arr: [u8; 32] = info
        .metadata_key
        .as_slice()
        .try_into()
        .map_err(|_| "metadata key length != 32".to_string())?;

    // Bump the metadata_version monotonically across the reset so old clients
    // that observed the pre-reset blob can detect "this is fresh content,
    // not the cached pre-reset payload". We piggyback on
    // `reset_generation` — server-side it monotonically increases on every
    // reset, and locally we bind the new version to it.
    let metadata_version: u64 = (new_reset_generation as u64).max(1);

    let avatar_locator = avatar_bytes
        .as_ref()
        .map(|_| uuid::Uuid::new_v4().to_string());

    let payload = catbird_mls::metadata::GroupMetadataV1 {
        version: 1,
        title: title.unwrap_or_default(),
        description: description.unwrap_or_default(),
        avatar_blob_locator: avatar_locator.clone(),
        avatar_content_type: avatar_content_type.clone(),
    };

    let metadata_ct = catbird_mls::metadata::encrypt_metadata_blob(
        &key_arr,
        &group_id_bytes,
        info.epoch,
        metadata_version,
        &payload,
    )
    .map_err(|e| format!("encrypt_metadata_blob failed: {e}"))?;

    let metadata_locator = uuid::Uuid::new_v4().to_string();
    state
        .api_client
        .put_group_metadata_blob(&metadata_locator, new_group_id_hex, &metadata_ct)
        .await
        .map_err(|e| format!("put_group_metadata_blob failed: {e:?}"))?;

    log_catmos!(
        "republish_group_metadata_after_reset: uploaded metadata blob {} for convo={} (epoch={} version={})",
        metadata_locator,
        convo_id,
        info.epoch,
        metadata_version
    );

    if let (Some(locator), Some(bytes)) = (avatar_locator.as_deref(), avatar_bytes.as_deref()) {
        match catbird_mls::metadata::encrypt_avatar_blob(
            &key_arr,
            &group_id_bytes,
            info.epoch,
            metadata_version,
            bytes,
        ) {
            Ok(avatar_ct) => {
                if let Err(e) = state
                    .api_client
                    .put_group_metadata_blob(locator, new_group_id_hex, &avatar_ct)
                    .await
                {
                    log_catmos!(
                        "republish_group_metadata_after_reset: avatar upload failed for {}: {:?}",
                        convo_id,
                        e
                    );
                }
            }
            Err(e) => {
                log_catmos!(
                    "republish_group_metadata_after_reset: encrypt_avatar_blob failed for {}: {}",
                    convo_id,
                    e
                );
            }
        }
    }

    // Cache locally so the UI reflects the new title without waiting for the
    // first incoming commit to trigger another bootstrap. Note: the actual
    // commit that installs `MetadataReference { metadata_version, locator }`
    // into AppDataDictionary 0x8001 is the responsibility of the
    // post-reset MLS update_group_metadata flow (separate from this helper);
    // here we only persist what the user already sees.
    let payload_json = serde_json::to_string(&payload)
        .map_err(|e| format!("metadata payload serialize failed: {e}"))?;
    state
        .orchestrator
        .storage()
        .update_metadata_json(
            convo_id,
            &payload_json,
            metadata_version,
            &metadata_locator,
            avatar_locator.as_deref(),
            avatar_content_type.as_deref(),
        )
        .map_err(|e| format!("update_metadata_json (post-reset) failed: {e:?}"))?;

    if let Some(bytes) = avatar_bytes.as_deref() {
        if let Err(e) = state.orchestrator.storage().update_avatar_bytes(
            convo_id,
            bytes,
            avatar_content_type.as_deref(),
        ) {
            log_catmos!(
                "republish_group_metadata_after_reset: local avatar persist failed for {}: {:?}",
                convo_id,
                e
            );
        }
    }

    Ok(())
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
    log_catmos!(
        "update_group_metadata (encrypted Phase A.2): convo={}, name={:?}, description={:?}",
        conversation_id,
        name,
        description
    );

    state
        .orchestrator
        .update_group_metadata_encrypted(
            &conversation_id,
            name.as_deref(),
            description.as_deref(),
            avatar_blob_locator.as_deref(),
            avatar_content_type.as_deref(),
            None,
        )
        .await
        .map_err(|e| format!("{:?}", e))?;

    Ok(())
}

#[tauri::command]
pub async fn add_group_members(
    state: State<'_, AppState>,
    conversation_id: String,
    member_dids: Vec<String>,
) -> Result<(), String> {
    log_catmos!(
        "add_group_members: convo={}, members={:?}",
        conversation_id,
        member_dids
    );

    state
        .orchestrator
        .add_members(&conversation_id, &member_dids)
        .await
        .map_err(|e| e.to_string())?;

    Ok(())
}

#[tauri::command]
pub async fn leave_conversation(
    state: State<'_, AppState>,
    conversation_id: String,
) -> Result<(), String> {
    log_catmos!("leave_conversation: convo={}", conversation_id);

    state
        .orchestrator
        .leave_group(&conversation_id)
        .await
        .map_err(|e| e.to_string())?;

    Ok(())
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

    let user_did = state
        .orchestrator
        .api_client()
        .current_did()
        .await
        .unwrap_or_default();

    // Get all conversations for name lookup
    let conversations = state
        .orchestrator
        .storage()
        .list_conversations(&user_did)
        .await
        .map_err(|e| format!("{:?}", e))?;

    // Encrypted-metadata cutover: titles come from the local SQLite cache
    // populated by `bootstrap_group_metadata`. Plaintext server metadata
    // (`c.metadata`) and the 0xff00 extension are both gone. Fall back to
    // the conversation_id when bootstrap hasn't run yet.
    let convo_names: std::collections::HashMap<String, String> = conversations
        .iter()
        .map(|c| {
            let title = state
                .orchestrator
                .storage()
                .get_metadata_snapshot(&c.conversation_id)
                .and_then(|s| s.metadata_json)
                .and_then(|j| {
                    serde_json::from_str::<catbird_mls::metadata::GroupMetadataV1>(&j).ok()
                })
                .map(|p| p.title)
                .filter(|t| !t.is_empty())
                .unwrap_or_else(|| c.conversation_id.clone());
            (c.conversation_id.clone(), title)
        })
        .collect();

    // Search messages across all conversations
    let mut hits = Vec::new();
    let lower_query = query.to_lowercase();

    for convo in &conversations {
        // Use stable conversation_id for message lookups
        let convo_id = &convo.conversation_id;
        if let Ok(all_msgs) = state
            .orchestrator
            .storage()
            .get_messages(convo_id, 500, None)
            .await
        {
            let convo_name = convo_names
                .get(convo_id)
                .cloned()
                .unwrap_or_else(|| convo_id.clone());

            for msg in all_msgs {
                if msg.text.to_lowercase().contains(&lower_query) {
                    hits.push(SearchHit {
                        message_id: msg.id.clone(),
                        conversation_id: msg.conversation_id.clone(),
                        conversation_name: convo_name.clone(),
                        sender_did: msg.sender_did.clone(),
                        content: msg.text.clone(),
                        timestamp: msg.timestamp.to_rfc3339(),
                    });
                }
            }
        }
    }

    // Sort by timestamp descending (newest first)
    hits.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    hits.truncate(100);

    Ok(hits)
}

#[tauri::command]
pub async fn report_spam(
    state: State<'_, AppState>,
    conversation_id: String,
    reported_did: String,
    reason: Option<String>,
) -> Result<(), String> {
    log_catmos!(
        " report_spam: convo={}, reported={}",
        conversation_id,
        reported_did
    );

    state
        .api_client
        .report_spam(&conversation_id, &reported_did, reason.as_deref())
        .await
        .map_err(|e| {
            log_catmos!(" report_spam error: {:?}", e);
            format!("{:?}", e)
        })
}

#[tauri::command]
pub async fn reset_group(
    state: State<'_, AppState>,
    conversation_id: String,
    reason: Option<String>,
) -> Result<serde_json::Value, String> {
    log_catmos!("reset_group: convo={}", conversation_id);

    let token = state
        .api_client
        .get_auth_token()
        .ok_or("Not authenticated")?;

    let nest_url =
        std::env::var("NEST_URL").unwrap_or_else(|_| "https://api.catbird.blue".to_string());

    // Generate a new group ID (random UUID-based identifier)
    let new_group_id = uuid::Uuid::new_v4().to_string();

    let body = serde_json::json!({
        "convoId": conversation_id,
        "newGroupId": new_group_id,
        "cipherSuite": "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
        "reason": reason,
    });

    let client = reqwest::Client::new();
    let resp = crate::mls_proxy::with_mls_proxy_header(
        client.post(format!("{}/xrpc/blue.catbird.mlsChat.resetGroup", nest_url)),
    )
    .bearer_auth(&token)
    .json(&body)
    .send()
    .await
    .map_err(|e| format!("Reset group failed: {}", e))?;

    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("Reset group failed: {}", body));
    }

    let result: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse reset response: {}", e))?;

    log_catmos!("reset_group success: {:?}", result);

    // Best-effort metadata re-emission. After the server returns success the
    // orchestrator + websocket recovery path will eventually merge an
    // External Commit that joins the new group. The new group's epoch
    // exporter is only available locally AFTER that merge — there's no
    // synchronous signal at this point. The caller (frontend) is expected
    // to invoke `republish_group_metadata` once the
    // `mls:group-reset` → first-merge cycle has completed; the helper here
    // is a no-op-ish probe that succeeds only when the new group is already
    // joined locally.
    if let Some(title_or_desc) = state
        .orchestrator
        .storage()
        .get_metadata_snapshot(&conversation_id)
        .and_then(|s| s.metadata_json)
        .and_then(|j| serde_json::from_str::<catbird_mls::metadata::GroupMetadataV1>(&j).ok())
    {
        let avatar_pair = state.orchestrator.storage().get_avatar(&conversation_id);
        let avatar_bytes = avatar_pair.as_ref().map(|(b, _)| b.clone());
        let avatar_content_type = avatar_pair.and_then(|(_, ct)| ct);
        if let Err(e) = republish_group_metadata_after_reset(
            &state,
            &conversation_id,
            &new_group_id,
            // Use a wall-clock millis tick as the version floor when the
            // server response doesn't expose `resetGeneration` — the server
            // increments its own copy on every reset, and we just need a
            // monotonically-fresh value bound to AAD.
            chrono::Utc::now().timestamp_millis(),
            Some(title_or_desc.title.clone()).filter(|t| !t.is_empty()),
            Some(title_or_desc.description.clone()).filter(|d| !d.is_empty()),
            avatar_bytes,
            avatar_content_type,
        )
        .await
        {
            log_catmos!(
                "reset_group: republish_group_metadata_after_reset deferred for convo={} (will retry via republish_group_metadata command): {}",
                conversation_id,
                e
            );
        }
    }

    Ok(result)
}

/// Re-encrypt and re-upload the locally-known group metadata under the
/// freshly-reset group's epoch exporter. Frontend calls this after observing
/// `mls:group-reset` AND seeing the new group has been joined locally
/// (e.g. on the first incoming message in the new conversation epoch). It
/// is idempotent: if the new group hasn't been joined yet it returns an
/// error and the caller can retry.
#[tauri::command]
pub async fn republish_group_metadata(
    state: State<'_, AppState>,
    conversation_id: String,
    new_group_id: String,
    new_reset_generation: i64,
) -> Result<(), String> {
    log_catmos!(
        "republish_group_metadata: convo={} newGroupId={} gen={}",
        conversation_id,
        new_group_id,
        new_reset_generation
    );

    let snapshot = state
        .orchestrator
        .storage()
        .get_metadata_snapshot(&conversation_id);
    let payload: Option<catbird_mls::metadata::GroupMetadataV1> = snapshot
        .as_ref()
        .and_then(|s| s.metadata_json.as_deref())
        .and_then(|j| serde_json::from_str(j).ok());
    let avatar_pair = state.orchestrator.storage().get_avatar(&conversation_id);
    let avatar_bytes = avatar_pair.as_ref().map(|(b, _)| b.clone());
    let avatar_content_type = avatar_pair.and_then(|(_, ct)| ct);

    let title = payload
        .as_ref()
        .map(|p| p.title.clone())
        .filter(|t| !t.is_empty());
    let description = payload
        .as_ref()
        .map(|p| p.description.clone())
        .filter(|d| !d.is_empty());

    republish_group_metadata_after_reset(
        &state,
        &conversation_id,
        &new_group_id,
        new_reset_generation,
        title,
        description,
        avatar_bytes,
        avatar_content_type,
    )
    .await
}

/// Publish an `app.bsky.graph.block` record to the user's PDS via the nest BFF.
/// Returns the record's AT-URI on success.
#[tauri::command]
pub async fn create_block(
    state: State<'_, AppState>,
    subject_did: String,
) -> Result<String, String> {
    log_catmos!("create_block: subject={}", subject_did);

    let token = state
        .api_client
        .get_auth_token()
        .ok_or("Not authenticated")?;
    let did = state
        .api_client
        .current_did()
        .await
        .ok_or("Not authenticated")?;

    let nest_url =
        std::env::var("NEST_URL").unwrap_or_else(|_| "https://api.catbird.blue".to_string());

    let body = serde_json::json!({
        "repo": did,
        "collection": "app.bsky.graph.block",
        "record": {
            "$type": "app.bsky.graph.block",
            "subject": subject_did,
            "createdAt": chrono::Utc::now().to_rfc3339(),
        },
    });

    // Build a fresh client without the atproto-proxy default header — this is a
    // standard PDS operation, not an MLS service call.
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/xrpc/com.atproto.repo.createRecord", nest_url))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .map_err(|e| {
            log_catmos!("create_block request failed: {}", e);
            format!("createBlock request failed: {}", e)
        })?;

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        log_catmos!("create_block non-success {}: {}", status, body);
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

    log_catmos!("create_block success: uri={}", uri);
    Ok(uri)
}

/// List every DID currently blocked by the authenticated user by paginating
/// `com.atproto.repo.listRecords` over the `app.bsky.graph.block` collection.
#[tauri::command]
pub async fn list_own_blocks(state: State<'_, AppState>) -> Result<Vec<String>, String> {
    let token = state
        .api_client
        .get_auth_token()
        .ok_or("Not authenticated")?;
    let did = state
        .api_client
        .current_did()
        .await
        .ok_or("Not authenticated")?;

    log_catmos!("list_own_blocks: did={}", did);

    let nest_url =
        std::env::var("NEST_URL").unwrap_or_else(|_| "https://api.catbird.blue".to_string());

    let client = reqwest::Client::new();
    let mut blocked: Vec<String> = Vec::new();
    let mut cursor: Option<String> = None;

    // Safety cap matches the browser path (1000 pages * 100 per page = 100k DIDs).
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

        let resp = req.send().await.map_err(|e| {
            log_catmos!("list_own_blocks request failed: {}", e);
            format!("listOwnBlocks request failed: {}", e)
        })?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            log_catmos!("list_own_blocks non-success {}: {}", status, body);
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

    log_catmos!("list_own_blocks success: count={}", blocked.len());
    Ok(blocked)
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 3 quarantine UI surface (catbird-mls Layer 3 plan §3)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QuarantineStateView {
    /// snake_case tag from `QuarantineReason::tag()` (`peer_bad_commit`,
    /// `multi_peer_bad_commits`, `repeated_framing_failures`).
    pub reason_tag: String,
    /// Unix epoch milliseconds when the conversation entered quarantine.
    pub since_ms: i64,
    /// Peers Signal C identified as repeatedly producing peer-bad commits.
    /// Empty when only Signal D (framing-failure burst) tripped quarantine.
    pub suspected_dids: Vec<String>,
}

/// Snapshot the current quarantine state for a conversation, if any. Used by
/// the SvelteKit conversation view to gate the composer + show the banner on
/// first paint after restart (the `mls://quarantined` event only fires on
/// transitions, so a restart with a pre-existing quarantined row needs this
/// pull-based read to seed UI state).
#[tauri::command]
pub async fn get_quarantine_state(
    state: State<'_, AppState>,
    conversation_id: String,
) -> Result<Option<QuarantineStateView>, String> {
    let snapshot = state
        .orchestrator
        .get_conversation_quarantine_state(&conversation_id)
        .await;
    Ok(snapshot.map(|q| QuarantineStateView {
        reason_tag: q.reason.tag().to_string(),
        since_ms: q.since_ms,
        suspected_dids: q.suspected_dids,
    }))
}

/// User-confirmed manual reset for a quarantined conversation (Layer 3
/// banner's `[Reset conversation]` action). Distinct from `reset_group`,
/// which is the bootstrap-reset (External Commit) path: this one routes
/// through `MLSOrchestrator::user_confirmed_manual_reset`, which reports the
/// deliberate user vote to the server's A7 reset pyramid AND clears local
/// quarantine state (`exit_quarantine` → `Active`). The server emits a
/// follow-up `groupResetEvent` if quorum is reached; the existing
/// `mls:group-reset` listener picks that up.
#[tauri::command]
pub async fn confirm_manual_reset(
    state: State<'_, AppState>,
    conversation_id: String,
) -> Result<(), String> {
    log_catmos!("confirm_manual_reset: convo={}", conversation_id);
    state
        .orchestrator
        .user_confirmed_manual_reset(&conversation_id)
        .await
        .map_err(|e| format!("{:?}", e))
}

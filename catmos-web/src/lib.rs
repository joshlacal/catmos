//! catmos-web — Browser WASM entry point for Catmos
//!
//! Exposes `#[wasm_bindgen]` functions matching the Tauri IPC commands in
//! `catmos/src-tauri/src/commands.rs`. All async functions return Promises on
//! the JS side via `wasm_bindgen_futures`.
//!
//! # Architecture
//!
//! Three platform trait implementations + a WASM-native MLS crypto context:
//!
//! | Trait | Implementation | Backend |
//! |---|---|---|
//! | `MLSAPIClient` | `WasmApiClient` | `reqwest` → browser `fetch` |
//! | `MLSStorageBackend` | `WasmStorageBackend` | Encrypted SQLite (OPFS SAH VFS) |
//! | `CredentialStore` | `SqliteCredentialStore` | Encrypted SQLite (OPFS SAH VFS) |
//! | `MlsCryptoContext` | `WasmMLSContext` | OpenMLS + sqlite-wasm-rs + sqlite3mc |
//!
//! All persistent storage uses a single encrypted SQLite database over OPFS,
//! shared across OpenMLS state, conversation/message storage, and credentials.
//!
//! # Worker requirement
//!
//! The OPFS Synchronous Access Handle (SAH) pool VFS is only available inside
//! Web Workers. When `wasm_init()` is called from the main thread, database
//! initialization may fail; the app continues in degraded mode.

mod api_client;
mod credentials;
pub mod mls_storage;
pub mod sqlite_conn;
mod storage;
mod wasm_mls_context;
mod websocket;

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;

use js_sys::Array;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use api_client::WasmApiClient;
use base64::Engine as _;
use credentials::SqliteCredentialStore;
use storage::WasmStorageBackend;
use wasm_mls_context::WasmMLSContext;

// ---------------------------------------------------------------------------
// Re-exports so other crates / tests can reach the trait impls.
// ---------------------------------------------------------------------------

pub use api_client::WasmApiClient as WasmApiClientExport;
pub use credentials::SqliteCredentialStore as SqliteCredentialStoreExport;
pub use mls_storage::WasmSqliteStorage;
pub use sqlite_conn::{SqliteConn, WasmSqliteError};
pub use storage::WasmStorageBackend as WasmStorageBackendExport;

// ---------------------------------------------------------------------------
// Panic hook — must be the very first thing that runs.
// ---------------------------------------------------------------------------

#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

// ---------------------------------------------------------------------------
// Error helper macro
// ---------------------------------------------------------------------------

macro_rules! js_err {
    ($($arg:tt)*) => {
        JsValue::from_str(&format!($($arg)*))
    };
}

// ---------------------------------------------------------------------------
// Public data structures (mirroring commands.rs)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthResponse {
    pub did: String,
    pub handle: String,
    pub display_name: Option<String>,
    pub avatar: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Conversation {
    pub id: String,
    pub display_name: String,
    pub members: Vec<String>,
    pub last_message: Option<String>,
    pub last_message_at: Option<String>,
    pub unread_count: u32,
    pub is_group: bool,
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
    pub message_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupMember {
    pub did: String,
    pub handle: String,
    pub display_name: Option<String>,
    pub role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileView {
    pub did: String,
    pub handle: String,
    pub display_name: Option<String>,
    pub avatar: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchResult {
    pub did: String,
    pub handle: String,
    pub display_name: Option<String>,
    pub avatar: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OptInStatusResult {
    pub did: String,
    pub opted_in: bool,
}

// ---------------------------------------------------------------------------
// Global app state (WASM is single-threaded — thread_local + RefCell is safe)
// ---------------------------------------------------------------------------

struct AppState {
    base_url: String,
    api_client: Arc<WasmApiClient>,
    storage: Arc<WasmStorageBackend>,
    #[allow(dead_code)]
    credentials: Arc<SqliteCredentialStore>,
    user_did: Option<String>,
    auth_token: Option<String>,
    /// WASM-native MLS crypto context (OpenMLS + sqlite-wasm-rs + sqlite3mc).
    /// `None` if `WasmMLSContext::open` failed (logged as a warning; non-crypto
    /// commands continue to work).
    mls_context: Option<Rc<WasmMLSContext>>,
}

thread_local! {
    static STATE: RefCell<Option<AppState>> = RefCell::new(None);
}

// ---------------------------------------------------------------------------
// State access helpers
// ---------------------------------------------------------------------------

fn with_state<F, R>(f: F) -> Result<R, JsValue>
where
    F: FnOnce(&AppState) -> Result<R, JsValue>,
{
    STATE.with(|s| {
        let borrowed = s.borrow();
        let state = borrowed
            .as_ref()
            .ok_or_else(|| js_err!("catmos-web: not initialized — call wasm_init() first"))?;
        f(state)
    })
}

fn with_state_mut<F, R>(f: F) -> Result<R, JsValue>
where
    F: FnOnce(&mut AppState) -> Result<R, JsValue>,
{
    STATE.with(|s| {
        let mut borrowed = s.borrow_mut();
        let state = borrowed
            .as_mut()
            .ok_or_else(|| js_err!("catmos-web: not initialized — call wasm_init() first"))?;
        f(state)
    })
}

// ---------------------------------------------------------------------------
// Session persistence — localStorage (non-persistent across origins/private)
// ---------------------------------------------------------------------------

fn save_session(did: &str, token: &str) -> Result<(), JsValue> {
    let storage = web_sys::window()
        .ok_or_else(|| js_err!("No global window"))?
        .local_storage()
        .map_err(|e| js_err!("localStorage error: {:?}", e))?
        .ok_or_else(|| js_err!("No localStorage available"))?;
    storage.set_item("catmos_session_id", token)?;
    storage.set_item("catmos_user_did", did)?;
    Ok(())
}

fn load_session() -> Option<(String, String)> {
    let storage = web_sys::window()?.local_storage().ok()??;
    let did = storage.get_item("catmos_user_did").ok()??;
    let token = storage.get_item("catmos_session_id").ok()??;
    Some((did, token))
}

fn clear_session() {
    if let Some(Ok(Some(storage))) = web_sys::window().map(|w| w.local_storage()) {
        let _ = storage.remove_item("catmos_session_id");
        let _ = storage.remove_item("catmos_user_did");
    }
}

// ---------------------------------------------------------------------------
// Serialization helper: Vec<T: Serialize> -> JsValue (JS Array)
// ---------------------------------------------------------------------------

fn to_js<T: Serialize>(value: &T) -> Result<JsValue, JsValue> {
    serde_wasm_bindgen::to_value(value).map_err(|e| js_err!("Serialization failed: {}", e))
}

// ---------------------------------------------------------------------------
// js_sys::Array -> Vec<String>
// ---------------------------------------------------------------------------

fn array_to_strings(arr: &Array) -> Vec<String> {
    arr.iter().filter_map(|v| v.as_string()).collect()
}

// ---------------------------------------------------------------------------
// MLS storage key management
// ---------------------------------------------------------------------------

/// Get (or generate and persist) a 256-bit hex key for the MLS SQLite database.
///
/// The key is stored in `sessionStorage` under `"catmos_mls_db_key"`. Using
/// sessionStorage instead of localStorage limits XSS exposure — the key is
/// cleared when the tab/window closes.
///
/// TODO: Migrate to WebCrypto non-extractable key for proper key protection
fn get_or_create_mls_key() -> Result<String, JsValue> {
    let ss = web_sys::window()
        .ok_or_else(|| js_err!("No global window"))?
        .session_storage()
        .map_err(|e| js_err!("sessionStorage unavailable: {:?}", e))?
        .ok_or_else(|| js_err!("No sessionStorage available"))?;

    if let Some(key) = ss.get_item("catmos_mls_db_key").ok().flatten() {
        return Ok(key);
    }

    // Generate a fresh 32-byte random key and persist it.
    let mut key_bytes = [0u8; 32];
    getrandom::getrandom(&mut key_bytes)
        .map_err(|e| js_err!("Failed to generate MLS key: {}", e))?;
    let key_hex: String = key_bytes.iter().map(|b| format!("{:02x}", b)).collect();
    ss.set_item("catmos_mls_db_key", &key_hex)
        .map_err(|e| js_err!("Failed to persist MLS key: {:?}", e))?;
    Ok(key_hex)
}

// ---------------------------------------------------------------------------
// WASM init
// ---------------------------------------------------------------------------

/// Initialize WASM app state. Must be called once after `await init()`.
///
/// `base_url` — base URL of the catmos/nest backend, e.g. `"https://api.catbird.blue"`.
///
/// MLS crypto is initialized automatically from a key stored in `sessionStorage`.
/// If SQLite fails to open (e.g. outside a Worker where OPFS SAH is unavailable)
/// the rest of the app continues without crypto; commands that require it return
/// an error.
#[wasm_bindgen]
pub async fn wasm_init(base_url: String) -> Result<(), JsValue> {
    let api_client = Arc::new(WasmApiClient::new(base_url.clone()));

    // Get or create the encryption key for the shared SQLite database.
    let db_key = get_or_create_mls_key()
        .map_err(|e| js_err!("catmos-web: could not obtain database key — {:?}", e))?;

    // Open ONE shared encrypted SQLite database for all storage.
    let shared_conn = sqlite_conn::SqliteConn::open("catmos-app.db", &db_key)
        .map_err(|e| js_err!("Failed to open SQLite database: {}", e))?;
    let shared_conn = Rc::new(shared_conn);

    // Create all schemas on the shared connection.
    mls_storage::WasmSqliteStorage::ensure_schema(&shared_conn)
        .map_err(|e| js_err!("Failed to create OpenMLS schema: {}", e))?;
    WasmStorageBackend::ensure_schema(&shared_conn)
        .map_err(|e| js_err!("Failed to create storage schema: {}", e))?;
    SqliteCredentialStore::ensure_schema(&shared_conn)
        .map_err(|e| js_err!("Failed to create credential schema: {}", e))?;

    let storage = WasmStorageBackend::new(Rc::clone(&shared_conn));
    let credentials = SqliteCredentialStore::new(Rc::clone(&shared_conn));

    // Create the MLS context using the same shared connection for OpenMLS storage.
    let mls_context: Option<Rc<WasmMLSContext>> = match WasmMLSContext::open_with_conn(Rc::clone(&shared_conn)) {
        Ok(ctx) => Some(Rc::new(ctx)),
        Err(e) => {
            web_sys::console::warn_1(&js_err!(
                "catmos-web: MLS context unavailable ({}). \
                 Crypto commands will return errors. \
                 Ensure wasm_init() runs inside a Worker.",
                e
            ));
            None
        }
    };

    // Share the MLS context with the API client for confirmation tag derivation.
    if let Some(ref ctx) = mls_context {
        api_client.set_confirmation_tag_provider(Rc::clone(ctx) as Rc<dyn api_client::ConfirmationTagProvider>);
    }

    // Reload persisted MLS groups into the in-memory cache so they survive
    // page refreshes.  Group IDs in the `group_states` SQLite table are
    // URL-safe base64 no-pad encoded byte strings.
    if let Some(ref ctx) = mls_context {
        match storage.list_group_ids() {
            Ok(ids) => {
                use base64::engine::general_purpose::URL_SAFE_NO_PAD;
                let mut loaded = 0u32;
                for id_str in &ids {
                    if let Ok(gid_bytes) = URL_SAFE_NO_PAD.decode(id_str) {
                        match ctx.ensure_group_loaded(&gid_bytes) {
                            Ok(true) => loaded += 1,
                            Ok(false) => {
                                web_sys::console::warn_1(&format!(
                                    "catmos-web: group {} in SQLite but not in OpenMLS storage",
                                    id_str
                                ).into());
                            }
                            Err(e) => {
                                web_sys::console::warn_1(&format!(
                                    "catmos-web: failed to load group {}: {}",
                                    id_str, e
                                ).into());
                            }
                        }
                    } else {
                        web_sys::console::warn_1(&format!(
                            "catmos-web: invalid base64 group_id in storage: {}",
                            id_str
                        ).into());
                    }
                }
                web_sys::console::log_1(
                    &format!(
                        "catmos-web: reloaded {}/{} MLS groups from storage",
                        loaded,
                        ids.len()
                    )
                    .into(),
                );
            }
            Err(e) => {
                web_sys::console::warn_1(&format!(
                    "catmos-web: failed to enumerate persisted groups: {}",
                    e
                ).into());
            }
        }
    }

    let state = AppState {
        base_url,
        api_client,
        storage: Arc::new(storage),
        credentials: Arc::new(credentials),
        user_did: None,
        auth_token: None,
        mls_context,
    };

    STATE.with(|s| {
        *s.borrow_mut() = Some(state);
    });

    Ok(())
}

// ---------------------------------------------------------------------------
// Auth commands
// ---------------------------------------------------------------------------

/// Open a browser popup for the OAuth login flow.
///
/// After the popup closes with a `session_id` query param (delivered via
/// postMessage or redirect), call `wasm_complete_login(session_id)`.
///
/// The popup URL is:
///   `{base_url}/auth/login?identifier={identifier}&client=catmos-web&redirect_uri={origin}/oauth-callback`
#[wasm_bindgen]
pub fn wasm_start_login(identifier: String) -> Result<(), JsValue> {
    with_state(|state| {
        let window = web_sys::window().ok_or_else(|| js_err!("No global window"))?;

        let origin = window
            .location()
            .origin()
            .map_err(|e| js_err!("Failed to get origin: {:?}", e))?;

        let redirect_uri = format!("{}/oauth-callback", origin);

        let login_url = format!(
            "{}/auth/login?identifier={}&client=catmos-web&redirect_to={}",
            state.base_url,
            js_sys::encode_uri_component(&identifier),
            js_sys::encode_uri_component(&redirect_uri),
        );

        window
            .open_with_url_and_target(&login_url, "_blank")
            .map_err(|e| js_err!("Failed to open login popup: {:?}", e))?;

        Ok(())
    })
}

/// Complete login after the OAuth callback delivers a `session_id`.
///
/// Validates the session with `GET {base_url}/auth/session`, stores the token
/// in AppState and localStorage, and returns an `AuthResponse`.
#[wasm_bindgen]
pub async fn wasm_complete_login(session_id: String) -> Result<JsValue, JsValue> {
    let base_url = with_state(|s| Ok(s.base_url.clone()))?;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}/auth/session", base_url))
        .bearer_auth(&session_id)
        .send()
        .await
        .map_err(|e| js_err!("Session fetch failed: {}", e))?;

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        return Err(js_err!("Session validation failed ({}): {}", status, body));
    }

    let info: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| js_err!("Failed to parse session response: {}", e))?;

    let did = info["did"].as_str().unwrap_or("").to_string();
    let handle = info["handle"].as_str().unwrap_or("").to_string();

    // Persist to localStorage for future restores
    save_session(&did, &session_id)?;

    // Update AppState
    with_state_mut(|state| {
        state.api_client.set_auth(did.clone(), session_id.clone());
        state.user_did = Some(did.clone());
        state.auth_token = Some(session_id.clone());
        Ok(())
    })?;

    let auth = AuthResponse {
        did,
        handle,
        display_name: None,
        avatar: None,
    };

    to_js(&auth)
}

/// Try to restore a previously saved session from localStorage.
///
/// Returns `null` (JS `null`) if no session is saved or the session is expired.
/// Returns a serialized `AuthResponse` if the session is valid.
#[wasm_bindgen]
pub async fn wasm_try_restore_session() -> Result<JsValue, JsValue> {
    let (did, token) = match load_session() {
        Some(pair) => pair,
        None => return Ok(JsValue::NULL),
    };

    let base_url = with_state(|s| Ok(s.base_url.clone()))?;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}/auth/session", base_url))
        .bearer_auth(&token)
        .send()
        .await
        .map_err(|e| js_err!("Session validate failed: {}", e))?;

    if !resp.status().is_success() {
        // Session expired or invalid — clear localStorage and return null
        clear_session();
        return Ok(JsValue::NULL);
    }

    let info: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| js_err!("Failed to parse session response: {}", e))?;

    let handle = info["handle"]
        .as_str()
        .map(str::to_string)
        .unwrap_or_default();

    // Restore AppState
    with_state_mut(|state| {
        state.api_client.set_auth(did.clone(), token.clone());
        state.user_did = Some(did.clone());
        state.auth_token = Some(token.clone());
        Ok(())
    })?;

    let auth = AuthResponse {
        did,
        handle,
        display_name: None,
        avatar: None,
    };

    to_js(&auth)
}

/// Logout: clear session from AppState and localStorage.
#[wasm_bindgen]
pub async fn wasm_logout() -> Result<(), JsValue> {
    with_state_mut(|state| {
        state.api_client.clear_auth();
        state.user_did = None;
        state.auth_token = None;
        Ok(())
    })?;
    clear_session();
    Ok(())
}

// ---------------------------------------------------------------------------
// Conversation commands
// ---------------------------------------------------------------------------

/// Fetch all conversations. Performs a server sync first then maps the result
/// to the frontend-facing `Conversation` shape.
///
/// Returns a JS Array of `Conversation` objects.
#[wasm_bindgen]
pub async fn wasm_get_conversations() -> Result<JsValue, JsValue> {
    use catbird_mls::orchestrator::api_client::MLSAPIClient;

    let api_client = with_state(|s| Ok(Arc::clone(&s.api_client)))?;

    let page = api_client
        .get_conversations(50, None)
        .await
        .map_err(|e| js_err!("get_conversations failed: {:?}", e))?;

    let convos: Vec<Conversation> = page
        .conversations
        .into_iter()
        .map(|c| {
            let member_dids: Vec<String> = c.members.iter().map(|m| m.did.clone()).collect();
            let display_name = c
                .metadata
                .as_ref()
                .and_then(|m| m.name.clone())
                .unwrap_or_else(|| member_dids.join(", "));
            Conversation {
                id: c.group_id,
                display_name,
                members: member_dids.clone(),
                last_message: None,
                last_message_at: None,
                unread_count: 0,
                is_group: member_dids.len() > 2,
            }
        })
        .collect();

    to_js(&convos)
}

/// Create a new group conversation with optional initial members.
///
/// Flow:
/// 1. Create an empty MLS group locally (`WasmMLSContext::create_group`).
/// 2. If `member_dids` is non-empty, fetch their key packages and produce an
///    `add_members` commit + Welcome message, then merge the pending commit.
/// 3. Publish the group to the server via `create_conversation`.
///
/// Returns a serialized `Conversation` object on success.
#[wasm_bindgen]
pub async fn wasm_create_group(name: String, member_dids: Array) -> Result<JsValue, JsValue> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use catbird_mls::orchestrator::api_client::MLSAPIClient;
    use catbird_mls::orchestrator::types::ConversationMetadata;
    use catbird_mls::KeyPackageData;

    let (api_client, user_did) = with_state(|s| {
        let did = s
            .user_did
            .clone()
            .ok_or_else(|| js_err!("Not authenticated"))?;
        Ok((Arc::clone(&s.api_client), did))
    })?;

    let member_dids_vec = array_to_strings(&member_dids);
    let identity_bytes = user_did.as_bytes().to_vec();

    // Step 1: Create the MLS group locally.
    let group_id_bytes = with_state(|s| {
        let ctx = s.mls_context.as_ref().ok_or_else(|| {
            js_err!("MLS context not initialized — run wasm_init() inside a Worker")
        })?;
        let result = ctx
            .create_group(identity_bytes.clone(), None)
            .map_err(|e| js_err!("create_group failed: {:?}", e))?;
        Ok(result.group_id)
    })?;

    // Step 2: Invite initial members (if any).
    let (commit_bytes, welcome_bytes) = if member_dids_vec.is_empty() {
        (None, None)
    } else {
        // Fetch key packages from the server.
        let kp_refs = api_client
            .get_key_packages(&member_dids_vec)
            .await
            .map_err(|e| js_err!("get_key_packages failed: {:?}", e))?;

        let key_packages: Vec<KeyPackageData> = kp_refs
            .into_iter()
            .map(|r| KeyPackageData {
                data: r.key_package_data,
            })
            .collect();

        let add_result = with_state(|s| {
            let ctx = s
                .mls_context
                .as_ref()
                .ok_or_else(|| js_err!("MLS context not initialized"))?;
            ctx.add_members(group_id_bytes.clone(), key_packages)
                .map_err(|e| js_err!("add_members failed: {:?}", e))
        })?;

        // Merge the pending commit so the local epoch advances.
        with_state(|s| {
            let ctx = s
                .mls_context
                .as_ref()
                .ok_or_else(|| js_err!("MLS context not initialized"))?;
            ctx.merge_pending_commit(group_id_bytes.clone())
                .map_err(|e| js_err!("merge_pending_commit failed: {:?}", e))
        })?;

        (Some(add_result.commit_data), Some(add_result.welcome_data))
    };

    // Step 3: Publish the group to the server.
    let group_id_str = URL_SAFE_NO_PAD.encode(&group_id_bytes);
    let metadata = ConversationMetadata {
        name: Some(name.clone()),
        description: None,
        avatar_url: None,
    };

    let server_result = api_client
        .create_conversation(
            &group_id_str,
            if member_dids_vec.is_empty() {
                None
            } else {
                Some(&member_dids_vec)
            },
            Some(&metadata),
            commit_bytes.as_deref(),
            welcome_bytes.as_deref(),
        )
        .await
        .map_err(|e| js_err!("create_conversation failed: {:?}", e))?;

    let convo = Conversation {
        id: server_result.conversation.group_id,
        display_name: name,
        members: member_dids_vec,
        last_message: None,
        last_message_at: None,
        unread_count: 0,
        is_group: true,
    };

    to_js(&convo)
}

/// Subscribe to real-time updates for a conversation via WebSocket.
///
/// - `on_message` — called with a JSON-serialized `Message` string for each
///   new encrypted message (content will be `[Encrypted]` until WASM crypto
///   is available).
/// - `on_event`   — called with a JSON `{type, data}` string for reactions,
///   read receipts, typing, and membership changes.
/// - `on_status`  — called with a status string: `"connected"`,
///   `"disconnected"`, or `"error: <reason>"`.
///
/// Returns a `WsSubscription` object. Call `.close()` on it to unsubscribe.
#[wasm_bindgen]
pub async fn wasm_subscribe_conversation(
    convo_id: String,
    on_message: js_sys::Function,
    on_event: js_sys::Function,
    on_status: js_sys::Function,
) -> Result<websocket::WsSubscription, JsValue> {
    let (base_url, auth_token) = with_state(|s| {
        let token = s
            .auth_token
            .clone()
            .ok_or_else(|| js_err!("Not authenticated"))?;
        Ok((s.base_url.clone(), token))
    })?;

    websocket::connect(
        convo_id, base_url, auth_token, on_message, on_event, on_status,
    )
    .await
}

/// Unsubscribe from a conversation.
///
/// The frontend should prefer calling `.close()` on the `WsSubscription`
/// returned by `wasm_subscribe_conversation`. This function is a no-op stub
/// kept for API compatibility with the Tauri IPC surface.
#[wasm_bindgen]
pub async fn wasm_unsubscribe_conversation(_convo_id: String) -> Result<(), JsValue> {
    Ok(())
}

// ---------------------------------------------------------------------------
// Message commands
// ---------------------------------------------------------------------------

/// Send an MLS-encrypted message to a conversation.
///
/// `convo_id` is the URL-safe-base64-encoded MLS group ID returned by
/// `wasm_get_conversations` / `wasm_create_group`.
///
/// The plaintext `content` is wrapped in an `MLSMessagePayload` JSON envelope
/// (interoperable with iOS Catbird), MLS-encrypted, padded to the nearest
/// bucket (512 / 1024 / 2048 / 4096 / 8192 bytes), and sent to the server.
///
/// If the MLS group does not exist locally (fresh session), the function
/// auto-joins via Welcome (preferred) or External Commit (fallback) before
/// retrying encryption.
#[wasm_bindgen]
pub async fn wasm_send_message(convo_id: String, content: String) -> Result<JsValue, JsValue> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use catbird_mls::orchestrator::api_client::MLSAPIClient;
    use catbird_mls::orchestrator::types::MLSMessagePayload;

    let (api_client, user_did) = with_state(|s| {
        let did = s
            .user_did
            .clone()
            .ok_or_else(|| js_err!("Not authenticated"))?;
        Ok((Arc::clone(&s.api_client), did))
    })?;

    // Decode the convo_id (URL-safe base64 no-padding) back to group_id bytes.
    let group_id_bytes = URL_SAFE_NO_PAD
        .decode(&convo_id)
        .map_err(|e| js_err!("Invalid convo_id '{}': {}", convo_id, e))?;

    // Encode as MLSMessagePayload JSON (interoperable with iOS Catbird).
    let payload = MLSMessagePayload::text(&content);
    let payload_bytes = payload
        .encode()
        .map_err(|e| js_err!("Failed to encode message payload: {:?}", e))?;

    // Try to encrypt — if group not found locally, auto-join then retry.
    let encrypt_result = {
        let first_try = with_state(|s| {
            let ctx = s.mls_context.as_ref().ok_or_else(|| {
                js_err!("MLS context not initialized — run wasm_init() inside a Worker")
            })?;
            match ctx.encrypt_message(group_id_bytes.clone(), payload_bytes.clone()) {
                Ok(r) => Ok(Ok(r)),
                Err(catbird_mls::MLSError::GroupNotFound { .. }) => Ok(Err(())),
                Err(e) => Err(js_err!("encrypt_message failed: {:?}", e)),
            }
        })?;

        match first_try {
            Ok(result) => result,
            Err(()) => {
                // Spec §5.3: Do NOT perform External Commit in send path.
                // Flag for deferred recovery and return error to UI.
                web_sys::console::log_1(
                    &"[catmos-web] Group not found locally — flagging for deferred rejoin".into(),
                );
                let storage = with_state(|s| Ok(Arc::clone(&s.storage)))?;
                let _ = storage.mark_needs_rejoin(&convo_id).await;
                return Err(js_err!(
                    "Group not found locally — sync in progress, please retry"
                ));
            }
        }
    };

    // Get the current epoch (needed by the server).
    let epoch = with_state(|s| {
        let ctx = s
            .mls_context
            .as_ref()
            .ok_or_else(|| js_err!("MLS context not initialized"))?;
        ctx.get_epoch(group_id_bytes.clone())
            .map_err(|e| js_err!("get_epoch failed: {:?}", e))
    })?;

    // Transmit to server.
    api_client
        .send_message(&convo_id, &encrypt_result.ciphertext, epoch)
        .await
        .map_err(|e| js_err!("send_message API call failed: {:?}", e))?;

    let message = Message {
        id: uuid::Uuid::new_v4().to_string(),
        conversation_id: convo_id,
        sender_did: user_did,
        sender_handle: String::new(),
        content,
        timestamp: chrono::Utc::now().to_rfc3339(),
        status: "sent".to_string(),
        message_type: "text".to_string(),
    };

    to_js(&message)
}

/// Auto-join an MLS group: try Welcome first, fall back to External Commit.
async fn auto_join_group(
    api_client: &Arc<WasmApiClient>,
    user_did: &str,
    convo_id: &str,
    _group_id_bytes: &[u8],
) -> Result<(), JsValue> {
    use catbird_mls::orchestrator::api_client::MLSAPIClient;

    // Step 1: Try Welcome
    match api_client.get_welcome(convo_id).await {
        Ok(welcome_data) => {
            web_sys::console::log_1(
                &format!(
                    "[catmos-web] Welcome found ({} bytes), joining via Welcome",
                    welcome_data.len()
                )
                .into(),
            );
            let identity_bytes = user_did.as_bytes().to_vec();
            let welcome_result = with_state(|s| {
                let ctx = s
                    .mls_context
                    .as_ref()
                    .ok_or_else(|| js_err!("MLS context not initialized"))?;
                ctx.process_welcome(welcome_data, identity_bytes, None)
                    .map_err(|e| js_err!("process_welcome failed: {:?}", e))
            });
            match welcome_result {
                Ok(_) => {
                    web_sys::console::log_1(
                        &"[catmos-web] Successfully joined via Welcome".into(),
                    );
                    return Ok(());
                }
                Err(e) => {
                    web_sys::console::warn_1(
                        &format!(
                            "[catmos-web] Welcome processing failed, trying External Commit: {:?}",
                            e
                        )
                        .into(),
                    );
                }
            }
        }
        Err(e) => {
            web_sys::console::log_1(
                &format!(
                    "[catmos-web] No Welcome available, trying External Commit: {:?}",
                    e
                )
                .into(),
            );
        }
    }

    // Step 2: Fall back to External Commit
    let group_info = api_client
        .get_group_info(convo_id)
        .await
        .map_err(|e| js_err!("get_group_info failed for auto-join: {:?}", e))?;

    let identity_bytes = user_did.as_bytes().to_vec();
    let ext_commit_result = with_state(|s| {
        let ctx = s
            .mls_context
            .as_ref()
            .ok_or_else(|| js_err!("MLS context not initialized"))?;
        ctx.create_external_commit(group_info, identity_bytes)
            .map_err(|e| js_err!("create_external_commit failed: {:?}", e))
    })?;

    // Submit external commit to server
    if let Err(e) = api_client
        .process_external_commit(convo_id, &ext_commit_result.commit_data, None)
        .await
    {
        // Clean up the pending join on failure
        let _ = with_state(|s| {
            if let Some(ctx) = s.mls_context.as_ref() {
                let _ = ctx.discard_pending_external_join(ext_commit_result.group_id.clone());
            }
            Ok(())
        });
        return Err(js_err!("process_external_commit failed: {:?}", e));
    }

    // Merge the pending commit locally
    with_state(|s| {
        let ctx = s
            .mls_context
            .as_ref()
            .ok_or_else(|| js_err!("MLS context not initialized"))?;
        ctx.merge_pending_commit(ext_commit_result.group_id)
            .map_err(|e| js_err!("merge_pending_commit after auto-join failed: {:?}", e))
    })?;

    web_sys::console::log_1(&"[catmos-web] Successfully joined via External Commit".into());
    Ok(())
}

/// Get messages from local IndexedDB storage.
///
/// `before` — optional sequence-number string for pagination; pass `None`
/// (or omit) to start from the most recent messages.
///
/// Returns a JS Array of `Message` objects.
#[wasm_bindgen]
pub async fn wasm_get_messages(
    convo_id: String,
    before: Option<String>,
) -> Result<JsValue, JsValue> {
    use catbird_mls::orchestrator::storage::MLSStorageBackend;

    let storage = with_state(|s| Ok(Arc::clone(&s.storage)))?;

    let before_seq = before.as_deref().and_then(|b| b.parse::<u64>().ok());

    let stored = storage
        .get_messages(&convo_id, 50, before_seq)
        .await
        .map_err(|e| js_err!("get_messages failed: {:?}", e))?;

    let messages: Vec<Message> = stored
        .into_iter()
        .filter(|m| !m.text.trim().is_empty())
        .map(|m| {
            use catbird_mls::orchestrator::types::MLSMessageType;

            let (message_type, content) = if let Some(payload) = m.payload() {
                if payload.message_type == MLSMessageType::System {
                    let display_text = match payload.text.as_deref() {
                        Some("history_boundary.new_member") => {
                            "You joined this conversation".to_string()
                        }
                        Some("history_boundary.device_rejoined") => {
                            "Messages before this point aren't available on this device"
                                .to_string()
                        }
                        Some(other) => other.to_string(),
                        None => m.text.clone(),
                    };
                    ("system".to_string(), display_text)
                } else {
                    ("text".to_string(), m.text.clone())
                }
            } else {
                ("text".to_string(), m.text.clone())
            };

            Message {
                id: m.id,
                conversation_id: m.conversation_id,
                sender_did: m.sender_did,
                sender_handle: String::new(),
                content,
                timestamp: m.timestamp.to_rfc3339(),
                status: if m.is_own {
                    "sent".to_string()
                } else {
                    "delivered".to_string()
                },
                message_type,
            }
        })
        .collect();

    to_js(&messages)
}

/// Fetch new messages from the server and attempt MLS decryption.
///
/// Each incoming envelope's ciphertext is decrypted via `WasmMLSContext` if
/// available. If the MLS group doesn't exist locally, auto-joins via Welcome
/// or External Commit before retrying decryption. Undecryptable messages
/// (wrong epoch, missing key, etc.) are returned with `content: "[Encrypted]"`
/// rather than failing the entire call.
///
/// Returns a JS Array of `Message` objects.
#[wasm_bindgen]
pub async fn wasm_fetch_new_messages(convo_id: String) -> Result<JsValue, JsValue> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use catbird_mls::orchestrator::api_client::MLSAPIClient;
    use catbird_mls::orchestrator::types::MLSMessagePayload;

    let (api_client, user_did) = with_state(|s| {
        let did = s.user_did.clone().unwrap_or_default();
        Ok((Arc::clone(&s.api_client), did))
    })?;

    let (envelopes, _cursor) = api_client
        .get_messages(&convo_id, None, 50)
        .await
        .map_err(|e| js_err!("fetch_new_messages failed: {:?}", e))?;

    // Decode the convo_id to group_id bytes once, outside the loop.
    let group_id_bytes = match URL_SAFE_NO_PAD.decode(&convo_id) {
        Ok(b) => b,
        Err(_) => return to_js(&Vec::<Message>::new()),
    };

    // Track whether we've already attempted auto-join for this batch.
    let mut auto_join_attempted = false;

    let mut messages = Vec::with_capacity(envelopes.len());
    for env in envelopes {
        let msg_id = env
            .server_message_id
            .clone()
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

        // Attempt decryption.
        let decrypt_result = STATE.with(|s| {
            let borrowed = s.borrow();
            let state = borrowed.as_ref()?;
            let ctx = state.mls_context.as_ref()?;
            match ctx.decrypt_message(group_id_bytes.clone(), env.ciphertext.clone()) {
                Ok(res) => Some(Ok(res)),
                Err(catbird_mls::MLSError::GroupNotFound { .. }) => Some(Err(true)),
                Err(_) => Some(Err(false)),
            }
        });

        let (content, sender_did) = match decrypt_result {
            Some(Ok(res)) => {
                // Extract text from MLSMessagePayload JSON envelope (or raw UTF-8 fallback).
                let text = MLSMessagePayload::extract_text(&res.plaintext)
                    .unwrap_or_else(|| {
                        String::from_utf8(res.plaintext)
                            .unwrap_or_else(|_| "[Binary]".to_string())
                    });
                // Skip empty/commit messages.
                if text.trim().is_empty() {
                    continue;
                }
                let sender = String::from_utf8(res.sender_credential.identity)
                    .unwrap_or_else(|_| env.sender_did.clone());
                (text, sender)
            }
            Some(Err(true)) if !auto_join_attempted => {
                // GroupNotFound — try auto-join once per batch.
                auto_join_attempted = true;
                if auto_join_group(&api_client, &user_did, &convo_id, &group_id_bytes)
                    .await
                    .is_ok()
                {
                    // Retry decryption after join.
                    let retry = STATE.with(|s| {
                        let borrowed = s.borrow();
                        let state = borrowed.as_ref()?;
                        let ctx = state.mls_context.as_ref()?;
                        ctx.decrypt_message(group_id_bytes.clone(), env.ciphertext.clone())
                            .ok()
                    });
                    match retry {
                        Some(res) => {
                            let text = MLSMessagePayload::extract_text(&res.plaintext)
                                .unwrap_or_else(|| {
                                    String::from_utf8(res.plaintext)
                                        .unwrap_or_else(|_| "[Binary]".to_string())
                                });
                            if text.trim().is_empty() {
                                continue;
                            }
                            let sender = String::from_utf8(res.sender_credential.identity)
                                .unwrap_or_else(|_| env.sender_did.clone());
                            (text, sender)
                        }
                        None => ("[Encrypted]".to_string(), env.sender_did.clone()),
                    }
                } else {
                    ("[Encrypted]".to_string(), env.sender_did.clone())
                }
            }
            _ => ("[Encrypted]".to_string(), env.sender_did.clone()),
        };

        messages.push(Message {
            id: msg_id,
            conversation_id: env.conversation_id,
            sender_did,
            sender_handle: String::new(),
            content,
            timestamp: env.timestamp.to_rfc3339(),
            status: "delivered".to_string(),
            message_type: "text".to_string(),
        });
    }

    to_js(&messages)
}

/// Send an encrypted image message.
///
/// Encrypts the image blob client-side (AES-256-GCM), uploads ciphertext to the
/// server, then sends an MLS-encrypted message containing the blob reference.
#[wasm_bindgen]
pub async fn wasm_send_image(
    conversation_id: String,
    content: String,
    data: Vec<u8>,
    content_type: String,
    width: u32,
    height: u32,
    alt_text: Option<String>,
) -> Result<JsValue, JsValue> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use catbird_mls::blob_crypto::encrypt_blob;
    use catbird_mls::orchestrator::api_client::MLSAPIClient;
    use catbird_mls::orchestrator::types::{MLSEmbedData, MLSImageEmbed, MLSMessagePayload};

    let (api_client, user_did) = with_state(|s| {
        let did = s
            .user_did
            .clone()
            .ok_or_else(|| js_err!("Not authenticated"))?;
        Ok((Arc::clone(&s.api_client), did))
    })?;

    if !content_type.starts_with("image/") {
        return Err(js_err!("Unsupported image content type: {}", content_type));
    }
    if data.len() > 10 * 1024 * 1024 {
        return Err(js_err!("Image too large (max 10MB)"));
    }

    // Encrypt blob client-side.
    let encrypted = encrypt_blob(&data)
        .map_err(|e| js_err!("Failed to encrypt image: {:?}", e))?;

    // Upload encrypted blob to server.
    let (blob_id, _uploaded_size) = api_client
        .upload_blob(&encrypted.ciphertext, &conversation_id)
        .await
        .map_err(|e| js_err!("Blob upload failed: {:?}", e))?;

    // Build image embed.
    let embed = MLSEmbedData::image(MLSImageEmbed {
        blob_id,
        key: encrypted.key,
        iv: encrypted.iv,
        sha256: encrypted.sha256,
        content_type: content_type.clone(),
        size: data.len(),
        width,
        height,
        alt_text,
        blurhash: None,
    })
    .map_err(|e| js_err!("Failed to create image embed: {:?}", e))?;

    // Encode as MLSMessagePayload with embed.
    let payload = MLSMessagePayload::text_with_embed(&content, embed);
    let payload_bytes = payload
        .encode()
        .map_err(|e| js_err!("Failed to encode message payload: {:?}", e))?;

    // Decode convo_id to group_id bytes.
    let group_id_bytes = URL_SAFE_NO_PAD
        .decode(&conversation_id)
        .map_err(|e| js_err!("Invalid convo_id '{}': {}", conversation_id, e))?;

    // Encrypt via MLS — auto-join if group not found locally.
    let encrypt_result = {
        let first_try = with_state(|s| {
            let ctx = s.mls_context.as_ref().ok_or_else(|| {
                js_err!("MLS context not initialized — run wasm_init() inside a Worker")
            })?;
            match ctx.encrypt_message(group_id_bytes.clone(), payload_bytes.clone()) {
                Ok(r) => Ok(Ok(r)),
                Err(catbird_mls::MLSError::GroupNotFound { .. }) => Ok(Err(())),
                Err(e) => Err(js_err!("encrypt_message failed: {:?}", e)),
            }
        })?;

        match first_try {
            Ok(result) => result,
            Err(()) => {
                // Spec §5.3: Do NOT perform External Commit in send path.
                web_sys::console::log_1(
                    &"[catmos-web] Group not found locally for image — flagging for deferred rejoin"
                        .into(),
                );
                let storage = with_state(|s| Ok(Arc::clone(&s.storage)))?;
                let _ = storage.mark_needs_rejoin(&conversation_id).await;
                return Err(js_err!(
                    "Group not found locally — sync in progress, please retry"
                ));
            }
        }
    };

    // Get the current epoch.
    let epoch = with_state(|s| {
        let ctx = s
            .mls_context
            .as_ref()
            .ok_or_else(|| js_err!("MLS context not initialized"))?;
        ctx.get_epoch(group_id_bytes.clone())
            .map_err(|e| js_err!("get_epoch failed: {:?}", e))
    })?;

    // Send to server.
    api_client
        .send_message(&conversation_id, &encrypt_result.ciphertext, epoch)
        .await
        .map_err(|e| js_err!("send_message API call failed: {:?}", e))?;

    let message = Message {
        id: uuid::Uuid::new_v4().to_string(),
        conversation_id,
        sender_did: user_did,
        sender_handle: String::new(),
        content,
        timestamp: chrono::Utc::now().to_rfc3339(),
        status: "sent".to_string(),
        message_type: "image".to_string(),
    };

    to_js(&message)
}

/// Send an encrypted reaction to a message.
///
/// `action` should be `"add"` or `"remove"`.
///
/// The reaction is MLS-encrypted as an application message with
/// `messageType: "reaction"`, matching the iOS `sendEncryptedReaction` path.
#[wasm_bindgen]
pub async fn wasm_send_reaction(
    conversation_id: String,
    message_id: String,
    emoji: String,
    action: String,
) -> Result<(), JsValue> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use catbird_mls::orchestrator::api_client::MLSAPIClient;
    use catbird_mls::orchestrator::types::{MLSMessagePayload, ReactionAction};

    let (api_client, user_did) = with_state(|s| {
        let did = s
            .user_did
            .clone()
            .ok_or_else(|| js_err!("Not authenticated"))?;
        Ok((Arc::clone(&s.api_client), did))
    })?;

    let reaction_action = if action == "remove" {
        ReactionAction::Remove
    } else {
        ReactionAction::Add
    };

    // Build reaction payload (matches iOS MLSMessagePayload.reaction()).
    let payload = MLSMessagePayload::reaction(&message_id, &emoji, reaction_action);
    let payload_bytes = payload
        .encode()
        .map_err(|e| js_err!("Failed to encode reaction payload: {:?}", e))?;

    // Decode convo_id (URL-safe base64 no-padding) to group_id bytes.
    let group_id_bytes = URL_SAFE_NO_PAD
        .decode(&conversation_id)
        .map_err(|e| js_err!("Invalid convo_id '{}': {}", conversation_id, e))?;

    // Encrypt via MLS — auto-join if group not found locally.
    let encrypt_result = {
        let first_try = with_state(|s| {
            let ctx = s.mls_context.as_ref().ok_or_else(|| {
                js_err!("MLS context not initialized — run wasm_init() inside a Worker")
            })?;
            match ctx.encrypt_message(group_id_bytes.clone(), payload_bytes.clone()) {
                Ok(r) => Ok(Ok(r)),
                Err(catbird_mls::MLSError::GroupNotFound { .. }) => Ok(Err(())),
                Err(e) => Err(js_err!("encrypt_message failed: {:?}", e)),
            }
        })?;

        match first_try {
            Ok(result) => result,
            Err(()) => {
                // Spec §5.3: Do NOT perform External Commit in send path.
                web_sys::console::log_1(
                    &"[catmos-web] Group not found locally for reaction — flagging for deferred rejoin"
                        .into(),
                );
                let storage = with_state(|s| Ok(Arc::clone(&s.storage)))?;
                let _ = storage.mark_needs_rejoin(&conversation_id).await;
                return Err(js_err!(
                    "Group not found locally — sync in progress, please retry"
                ));
            }
        }
    };

    // Get the current epoch.
    let epoch = with_state(|s| {
        let ctx = s
            .mls_context
            .as_ref()
            .ok_or_else(|| js_err!("MLS context not initialized"))?;
        ctx.get_epoch(group_id_bytes.clone())
            .map_err(|e| js_err!("get_epoch failed: {:?}", e))
    })?;

    // Send encrypted reaction to delivery service.
    api_client
        .send_message(&conversation_id, &encrypt_result.ciphertext, epoch)
        .await
        .map_err(|e| js_err!("Reaction send failed: {:?}", e))?;

    Ok(())
}

/// Send a typing indicator event to a conversation.
///
/// When `is_typing` is true this sends action `"typing"`, otherwise `"typingStop"`.
#[wasm_bindgen]
pub async fn wasm_send_typing(conversation_id: String, is_typing: bool) -> Result<(), JsValue> {
    let (base_url, auth_token) = with_state(|s| {
        let token = s
            .auth_token
            .clone()
            .ok_or_else(|| js_err!("Not authenticated"))?;
        Ok((s.base_url.clone(), token))
    })?;

    let client = reqwest::Client::new();
    let action_name = if is_typing { "typing" } else { "typingStop" };
    let no_op_ciphertext = base64::engine::general_purpose::STANDARD.encode(vec![0u8; 512]);

    let input = serde_json::json!({
        "convoId": conversation_id,
        "delivery": "ephemeral",
        "action": action_name,
        "msgId": uuid::Uuid::new_v4().to_string(),
        "epoch": 0,
        "paddedSize": 512,
        "ciphertext": { "$bytes": no_op_ciphertext },
    });

    let resp = client
        .post(format!(
            "{}/xrpc/blue.catbird.mlsChat.sendMessage",
            base_url
        ))
        .bearer_auth(&auth_token)
        .json(&input)
        .send()
        .await
        .map_err(|e| js_err!("Typing update failed: {}", e))?;

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        return Err(js_err!("Typing update failed ({}): {}", status, body));
    }

    Ok(())
}

/// Update the read cursor for a conversation.
#[wasm_bindgen]
pub async fn wasm_update_cursor(
    conversation_id: String,
    cursor: String,
) -> Result<(), JsValue> {
    let (base_url, auth_token) = with_state(|s| {
        let token = s
            .auth_token
            .clone()
            .ok_or_else(|| js_err!("Not authenticated"))?;
        Ok((s.base_url.clone(), token))
    })?;

    let input = serde_json::json!({
        "convoId": conversation_id,
        "cursor": cursor,
    });

    let client = reqwest::Client::new();
    let resp = client
        .post(format!(
            "{}/xrpc/blue.catbird.mlsChat.updateCursor",
            base_url
        ))
        .bearer_auth(&auth_token)
        .json(&input)
        .send()
        .await
        .map_err(|e| js_err!("Update cursor failed: {}", e))?;

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        return Err(js_err!("Update cursor failed ({}): {}", status, body));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Member commands
// ---------------------------------------------------------------------------

/// Get group members from local IndexedDB storage.
///
/// Returns a JS Array of `GroupMember` objects.
#[wasm_bindgen]
pub async fn wasm_get_group_members(conversation_id: String) -> Result<JsValue, JsValue> {
    use catbird_mls::orchestrator::storage::MLSStorageBackend;

    let (storage, user_did) = with_state(|s| {
        let did = s
            .user_did
            .clone()
            .ok_or_else(|| js_err!("Not authenticated"))?;
        Ok((Arc::clone(&s.storage), did))
    })?;

    let convo = storage
        .get_conversation(&user_did, &conversation_id)
        .await
        .map_err(|e| js_err!("get_group_members storage error: {:?}", e))?;

    let members: Vec<GroupMember> = match convo {
        Some(c) => c
            .members
            .into_iter()
            .map(|m| GroupMember {
                did: m.did.clone(),
                handle: String::new(),
                display_name: None,
                role: format!("{:?}", m.role),
            })
            .collect(),
        None => vec![],
    };

    to_js(&members)
}

/// Promote a member to admin.
#[wasm_bindgen]
pub async fn wasm_promote_member(
    conversation_id: String,
    target_did: String,
) -> Result<(), JsValue> {
    let (base_url, auth_token) = with_state(|s| {
        let token = s
            .auth_token
            .clone()
            .ok_or_else(|| js_err!("Not authenticated"))?;
        Ok((s.base_url.clone(), token))
    })?;

    let input = serde_json::json!({
        "convoId": conversation_id,
        "targetDid": target_did,
    });

    let client = reqwest::Client::new();
    let resp = client
        .post(format!(
            "{}/xrpc/blue.catbird.mlsChat.promoteAdmin",
            base_url
        ))
        .bearer_auth(&auth_token)
        .json(&input)
        .send()
        .await
        .map_err(|e| js_err!("promote_member failed: {}", e))?;

    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(js_err!("promote_member failed: {}", body));
    }

    Ok(())
}

/// Demote a member from admin.
#[wasm_bindgen]
pub async fn wasm_demote_member(
    conversation_id: String,
    target_did: String,
) -> Result<(), JsValue> {
    let (base_url, auth_token) = with_state(|s| {
        let token = s
            .auth_token
            .clone()
            .ok_or_else(|| js_err!("Not authenticated"))?;
        Ok((s.base_url.clone(), token))
    })?;

    let input = serde_json::json!({
        "convoId": conversation_id,
        "targetDid": target_did,
    });

    let client = reqwest::Client::new();
    let resp = client
        .post(format!(
            "{}/xrpc/blue.catbird.mlsChat.demoteAdmin",
            base_url
        ))
        .bearer_auth(&auth_token)
        .json(&input)
        .send()
        .await
        .map_err(|e| js_err!("demote_member failed: {}", e))?;

    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(js_err!("demote_member failed: {}", body));
    }

    Ok(())
}

/// Remove a member from the group.
///
/// Note: this currently calls the leaveConvo endpoint with a `targetDid` field
/// matching the desktop Tauri implementation's remove_members path.
#[wasm_bindgen]
pub async fn wasm_remove_group_member(
    conversation_id: String,
    target_did: String,
) -> Result<(), JsValue> {
    use catbird_mls::orchestrator::api_client::MLSAPIClient;

    let api_client = with_state(|s| Ok(Arc::clone(&s.api_client)))?;

    // The WasmApiClient remove_members implementation routes through leaveConvo
    // with targetDid — this matches the Tauri desktop behaviour.
    api_client
        .remove_members(&conversation_id, &[target_did], &[])
        .await
        .map_err(|e| js_err!("remove_group_member failed: {:?}", e))?;

    Ok(())
}

/// Leave a conversation.
#[wasm_bindgen]
pub async fn wasm_leave_conversation(conversation_id: String) -> Result<(), JsValue> {
    use catbird_mls::orchestrator::api_client::MLSAPIClient;

    let api_client = with_state(|s| Ok(Arc::clone(&s.api_client)))?;

    api_client
        .leave_conversation(&conversation_id)
        .await
        .map_err(|e| js_err!("leave_conversation failed: {:?}", e))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Profile commands
// ---------------------------------------------------------------------------

/// Get profiles for a list of DIDs via the Bluesky public API.
///
/// `dids` — JS Array of DID strings.
///
/// Returns a JS Array of `ProfileView` objects.
#[wasm_bindgen]
pub async fn wasm_get_profiles(dids: Array) -> Result<JsValue, JsValue> {
    let dids = array_to_strings(&dids);
    if dids.is_empty() {
        return to_js(&Vec::<ProfileView>::new());
    }

    let auth_token = with_state(|s| {
        s.auth_token
            .clone()
            .ok_or_else(|| js_err!("Not authenticated"))
    })?;

    let client = reqwest::Client::new();
    let mut url =
        reqwest::Url::parse("https://public.api.bsky.app/xrpc/app.bsky.actor.getProfiles")
            .map_err(|e| js_err!("URL parse error: {}", e))?;

    for did in &dids {
        url.query_pairs_mut().append_pair("actors", did);
    }

    let resp = client
        .get(url)
        .bearer_auth(&auth_token)
        .send()
        .await
        .map_err(|e| js_err!("Profile fetch failed: {}", e))?;

    if !resp.status().is_success() {
        return Err(js_err!("Profile fetch failed: {}", resp.status()));
    }

    let data: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| js_err!("Profile parse failed: {}", e))?;

    let profiles: Vec<ProfileView> = data["profiles"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .map(|p| ProfileView {
                    did: p["did"].as_str().unwrap_or("").to_string(),
                    handle: p["handle"].as_str().unwrap_or("").to_string(),
                    display_name: p["displayName"].as_str().map(str::to_string),
                    avatar: p["avatar"].as_str().map(str::to_string),
                })
                .collect()
        })
        .unwrap_or_default();

    to_js(&profiles)
}

/// Search for users by query string using Bluesky's typeahead endpoint.
///
/// Returns a JS Array of `SearchResult` objects (up to 10 results).
#[wasm_bindgen]
pub async fn wasm_search_users(query: String) -> Result<JsValue, JsValue> {
    if query.trim().is_empty() {
        return to_js(&Vec::<SearchResult>::new());
    }

    let auth_token = with_state(|s| {
        s.auth_token
            .clone()
            .ok_or_else(|| js_err!("Not authenticated"))
    })?;

    let client = reqwest::Client::new();
    let url = reqwest::Url::parse_with_params(
        "https://public.api.bsky.app/xrpc/app.bsky.actor.searchActorsTypeahead",
        &[("q", query.as_str()), ("limit", "10")],
    )
    .map_err(|e| js_err!("URL parse error: {}", e))?;

    let resp = client
        .get(url)
        .bearer_auth(&auth_token)
        .send()
        .await
        .map_err(|e| js_err!("Search failed: {}", e))?;

    if !resp.status().is_success() {
        return Err(js_err!("Search failed: {}", resp.status()));
    }

    let data: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| js_err!("Search parse failed: {}", e))?;

    let results: Vec<SearchResult> = data["actors"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .map(|a| SearchResult {
                    did: a["did"].as_str().unwrap_or("").to_string(),
                    handle: a["handle"].as_str().unwrap_or("").to_string(),
                    display_name: a["displayName"].as_str().map(str::to_string),
                    avatar: a["avatar"].as_str().map(str::to_string),
                })
                .collect()
        })
        .unwrap_or_default();

    to_js(&results)
}

/// Check MLS opt-in status for a list of DIDs.
///
/// `dids` — JS Array of DID strings.
///
/// Returns a JS Array of `OptInStatusResult` objects.
#[wasm_bindgen]
pub async fn wasm_check_opt_in_status(dids: Array) -> Result<JsValue, JsValue> {
    let dids = array_to_strings(&dids);
    if dids.is_empty() {
        return to_js(&Vec::<OptInStatusResult>::new());
    }

    let (base_url, auth_token) = with_state(|s| {
        let token = s
            .auth_token
            .clone()
            .ok_or_else(|| js_err!("Not authenticated"))?;
        Ok((s.base_url.clone(), token))
    })?;

    let dids_param = dids.join(",");
    let url = format!(
        "{}/xrpc/blue.catbird.mlsChat.getOptInStatus?dids={}",
        base_url, dids_param
    );

    let client = reqwest::Client::new();
    let resp = client
        .get(&url)
        .bearer_auth(&auth_token)
        .send()
        .await
        .map_err(|e| js_err!("check_opt_in_status failed: {}", e))?;

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        return Err(js_err!("check_opt_in_status failed ({}): {}", status, body));
    }

    let output: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| js_err!("check_opt_in_status parse failed: {}", e))?;

    let statuses: Vec<OptInStatusResult> = output["statuses"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .map(|s| OptInStatusResult {
                    did: s["did"].as_str().unwrap_or("").to_string(),
                    opted_in: s["optedIn"].as_bool().unwrap_or(false),
                })
                .collect()
        })
        .unwrap_or_default();

    to_js(&statuses)
}

// ---------------------------------------------------------------------------
// Group metadata commands
// ---------------------------------------------------------------------------

/// Get encrypted group metadata (decrypted locally from MLS group context).
/// Returns JSON string with { name, description, avatar_hash } or empty string if none.
///
/// `convo_id` is the URL-safe-base64-encoded (no-padding) MLS group ID.
#[wasm_bindgen]
pub fn wasm_get_group_metadata(convo_id: String) -> Result<JsValue, JsValue> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    let group_id = URL_SAFE_NO_PAD
        .decode(&convo_id)
        .map_err(|e| js_err!("Invalid convo_id '{}': {}", convo_id, e))?;

    with_state(|s| {
        let ctx = s.mls_context.as_ref().ok_or_else(|| {
            js_err!("MLS context not initialized — run wasm_init() inside a Worker")
        })?;
        let meta_bytes = ctx
            .get_group_metadata(group_id)
            .map_err(|e| js_err!("get_group_metadata failed: {:?}", e))?;
        if meta_bytes.is_empty() {
            Ok(JsValue::from_str(""))
        } else {
            let json = String::from_utf8(meta_bytes)
                .map_err(|e| js_err!("metadata not valid UTF-8: {:?}", e))?;
            Ok(JsValue::from_str(&json))
        }
    })
}

/// Update group metadata (encrypted in MLS group context).
/// Commits the change and sends it to the server.
///
/// `convo_id` is the URL-safe-base64-encoded (no-padding) MLS group ID.
#[wasm_bindgen]
pub async fn wasm_update_group_metadata(
    convo_id: String,
    name: Option<String>,
    description: Option<String>,
    avatar_hash: Option<String>,
) -> Result<JsValue, JsValue> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use catbird_mls::group_metadata::GroupMetadata;
    use catbird_mls::orchestrator::api_client::MLSAPIClient;

    let group_id = URL_SAFE_NO_PAD
        .decode(&convo_id)
        .map_err(|e| js_err!("Invalid convo_id '{}': {}", convo_id, e))?;

    let metadata = GroupMetadata {
        v: 1,
        name,
        description,
        avatar_hash,
    };
    let metadata_json = metadata
        .to_extension_bytes()
        .map_err(|e| js_err!("serialize metadata: {:?}", e))?;

    // Step 1: Update MLS group context (synchronous crypto)
    let commit_data = with_state(|s| {
        let ctx = s.mls_context.as_ref().ok_or_else(|| {
            js_err!("MLS context not initialized — run wasm_init() inside a Worker")
        })?;
        ctx.update_group_metadata(group_id.clone(), metadata_json)
            .map_err(|e| js_err!("update_group_metadata failed: {:?}", e))
    })?;

    // Step 2: Send commit to server
    let api_client = with_state(|s| Ok(Arc::clone(&s.api_client)))?;
    api_client
        .commit_group_change(&convo_id, &commit_data, "updateMetadata")
        .await
        .map_err(|e| js_err!("commit_group_change failed: {:?}", e))?;

    // Step 3: Merge pending commit locally
    with_state(|s| {
        let ctx = s.mls_context.as_ref().ok_or_else(|| {
            js_err!("MLS context not initialized")
        })?;
        ctx.merge_pending_commit(group_id)
            .map_err(|e| js_err!("merge_pending_commit failed: {:?}", e))?;
        Ok(())
    })?;

    Ok(JsValue::from_str("ok"))
}

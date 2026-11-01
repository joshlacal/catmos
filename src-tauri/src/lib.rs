mod api_client;
mod native_keyring;
pub use catbird_atproto::catbird;
pub use catbird_atproto::types;
mod commands;
mod credentials;
mod keychain;
mod keys;
pub mod mls;
mod mls_proxy;
mod quarantine_observer;
mod recovery;
mod session_restore;
mod storage;
mod websocket;

use std::collections::HashMap;
pub(crate) fn nest_url() -> String {
    std::env::var("NEST_URL").unwrap_or_else(|_| "https://api.catbird.blue".to_string())
}
use std::sync::Arc;

use api_client::ReqwestApiClient;
use catbird_mls::orchestrator::MLSOrchestrator;
use credentials::KeyringCredentialStore;
use keychain::KeyringKeychainAccess;
use quarantine_observer::QuarantineObserver;
use storage::SqliteStorage;
use tauri::Manager;
use tokio::sync::Mutex;

/// Retrieve or generate a random 32-byte hex key stored in the OS keychain.
/// `label` distinguishes between multiple databases (e.g. "conversation-db", "mls-db").
fn get_or_create_db_key(label: &str) -> String {
    let service = "blue.catbird.catmos";
    let entry = crate::native_keyring::entry(service, label)
        .expect("Failed to create keyring entry for DB key");

    // Try to load an existing key
    match entry.get_password() {
        Ok(existing) => existing,
        Err(keyring::Error::NoEntry) => {
            // Generate a random 32-byte key and hex-encode it
            let mut key_bytes = [0u8; 32];
            getrandom::fill(&mut key_bytes).expect("Failed to generate random DB key");
            let hex_key: String = key_bytes.iter().map(|b| format!("{b:02x}")).collect();
            entry
                .set_password(&hex_key)
                .expect("Failed to store DB key in keychain");
            hex_key
        }
        Err(e) => panic!("Failed to read DB key from keychain: {e}"),
    }
}

pub type CatmosOrchestrator = MLSOrchestrator<
    SqliteStorage,
    ReqwestApiClient,
    KeyringCredentialStore,
    catbird_mls::MLSContext,
>;

fn resolve_data_dir() -> std::path::PathBuf {
    #[cfg(target_os = "android")]
    {
        if let Some(home) = std::env::var_os("HOME") {
            return std::path::PathBuf::from(home).join("files").join("catmos");
        }
        return std::path::PathBuf::from("/data/local/tmp").join("catmos");
    }

    if let Some(path) = dirs::data_local_dir() {
        return path.join("catmos");
    }
    if let Some(home) = std::env::var_os("HOME") {
        return std::path::PathBuf::from(home).join(".catmos");
    }
    std::env::temp_dir().join("catmos")
}

/// Per-conversation WebSocket subscription handle
pub struct WsHandle {
    pub shutdown: tokio::sync::watch::Sender<bool>,
}

impl WsHandle {
    pub(crate) fn owns(&self, sender: &tokio::sync::watch::Sender<bool>) -> bool {
        self.shutdown.same_channel(sender)
    }
}

pub struct AppState {
    pub orchestrator: Arc<CatmosOrchestrator>,
    pub mls_manager: Arc<mls::TauriMlsManager>,
    pub api_client: Arc<ReqwestApiClient>,
    /// Runtime-owned clean-chat auth capabilities. The provider contains
    /// opaque session/device/JKT state; commands never persist or log secrets.
    pub(crate) chat_auth: Arc<api_client::ChatAuthProvider>,
    pub ws_handles: Arc<Mutex<HashMap<String, WsHandle>>>,
    pub kp_monitor: Mutex<Option<tokio::task::JoinHandle<()>>>,
    pub sync_loop: Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// Per-app data directory (`~/Library/Application Support/catmos` on macOS,
    /// platform-equivalent elsewhere). Used by the auth flow to resolve the
    /// per-DID content-root key file (`keys::load_or_create_content_root_key`).
    pub data_dir: std::path::PathBuf,
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Resolve paths
    let data_dir = resolve_data_dir();
    std::fs::create_dir_all(&data_dir).unwrap_or_else(|e| {
        panic!(
            "Failed to create data directory {}: {}",
            data_dir.display(),
            e
        )
    });

    let db_path = data_dir.join("catmos.db");
    let db_path_str = db_path.to_string_lossy().to_string();

    // Route XRPC calls through nest BFF (handles DPoP auth, session management)
    let mls_ds_url = nest_url();
    // Create platform implementations
    let conversation_encryption_key = get_or_create_db_key("conversation-db");
    let storage = Arc::new(
        SqliteStorage::new(&db_path_str, &conversation_encryption_key)
            .expect("Failed to initialize SQLite storage"),
    );
    let api_client = Arc::new(ReqwestApiClient::new(mls_ds_url));
    let cred_store = Arc::new(KeyringCredentialStore::new());

    // Create MLS FFI context — create parent directory first
    let mls_state_dir = data_dir.join("mls-state");
    std::fs::create_dir_all(&mls_state_dir).expect("Failed to create mls-state directory");

    let mls_db_path = mls_state_dir.join("mls.db");
    let encryption_key = get_or_create_db_key("mls-db");
    let keychain = Box::new(KeyringKeychainAccess::new());
    let mls_context = catbird_mls::MLSContext::new(
        mls_db_path.to_string_lossy().to_string(),
        encryption_key,
        keychain,
    )
    .expect("Failed to initialize MLS context");

    if let Err(e) = mls_context.launch_checkpoint() {
        eprintln!(
            "[catmos] Warning: launch checkpoint failed (non-fatal): {:?}",
            e
        );
    }

    api_client.set_mls_context(mls_context.clone());
    storage.set_mls_context(mls_context.clone());

    let orchestrator = Arc::new(MLSOrchestrator::new(
        mls_context,
        storage,
        api_client.clone(),
        cred_store,
        catbird_mls::orchestrator::OrchestratorConfig::default(),
    ));
    let mls_manager = Arc::new(mls::TauriMlsManager::new(data_dir.clone()));
    let chat_auth = api_client.chat_auth_provider();
    let app_state = AppState {
        orchestrator,
        mls_manager,
        chat_auth,
        api_client,
        ws_handles: Arc::new(Mutex::new(HashMap::new())),
        kp_monitor: Mutex::new(None),
        sync_loop: Mutex::new(None),
        data_dir,
    };

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(app_state)
        .invoke_handler(tauri::generate_handler![
            commands::start_login,
            commands::complete_login,
            commands::try_restore_session,
            commands::logout,
            commands::get_conversations,
            commands::create_group,
            commands::send_message,
            commands::send_image,
            commands::get_messages,
            commands::get_image_attachment,
            commands::get_group_members,
            commands::subscribe_conversation,
            commands::unsubscribe_conversation,
            commands::subscribe_all_events,
            commands::unsubscribe_all_events,
            commands::fetch_new_messages,
            commands::get_profiles,
            commands::send_reaction,
            commands::send_typing,
            commands::update_cursor,
            commands::search_users,
            commands::check_opt_in_status,
            commands::promote_member,
            commands::demote_member,
            commands::remove_group_member,
            commands::get_group_metadata,
            commands::update_group_metadata,
            commands::add_group_members,
            commands::leave_conversation,
            commands::search_messages,
            commands::report_spam,
            commands::reset_group,
            commands::republish_group_metadata,
            commands::create_block,
            commands::list_own_blocks,
            commands::get_quarantine_state,
            commands::confirm_manual_reset,
            commands::labyrinth_enable_and_enroll,
            commands::labyrinth_status,
            commands::labyrinth_setup_recovery_code,
            commands::labyrinth_restore_recovery_code,
            commands::labyrinth_register_passkey_prf,
            commands::labyrinth_initiate_otc,
            commands::labyrinth_complete_otc,
            commands::labyrinth_revoke_device,
        ])
        .setup(|app| {
            let app_handle = app.handle().clone();
            let state = app.state::<AppState>();
            state.mls_manager.attach_app_handle(app_handle.clone());
            let orchestrator = state.orchestrator.clone();
            let observer: Arc<
                dyn catbird_mls::orchestrator::event_observer::OrchestratorEventObserver,
            > = Arc::new(QuarantineObserver::new(app_handle));
            tauri::async_runtime::block_on(async move {
                orchestrator.set_event_observer(Some(observer)).await;
            });
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running Catmos");
}

mod api_client;
pub use catbird_atproto::catbird;
pub use catbird_atproto::types;
pub mod commands;
pub mod credentials;
pub mod keychain;
pub mod keys;
pub mod mls_proxy;
pub mod quarantine_observer;
pub mod recovery;
pub mod session_restore;
pub mod storage;
pub mod websocket;

use std::collections::HashMap;
use std::sync::Arc;

use api_client::ReqwestApiClient;
use catbird_mls::orchestrator::MLSOrchestrator;
use credentials::KeyringCredentialStore;
use keychain::KeyringKeychainAccess;
use quarantine_observer::QuarantineObserver;
use storage::SqliteStorage;
use tauri::Manager;
use tokio::sync::Mutex;


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

    let db_path = data_dir.join(format!("catmos-{}.db", storage::MLS_KEY_SUFFIX));

    // Process explicit recovery opt-in switch if supplied
    let should_reset = std::env::args().any(|arg| arg == "--reset-mls-storage");
    if should_reset {
        tracing::info!("[catmos] Explicit --reset-mls-storage requested; resetting clean storage generation");
        if let Err(e) = tauri::async_runtime::block_on(storage::reset_clean_storage(
            &data_dir,
            None,
            None,
            None,
            storage::DB_KEYRING_SERVICE,
        )) {
            panic!("Failed to reset clean storage via --reset-mls-storage: {e}");
        }
    }

    // Route XRPC calls through nest BFF (handles DPoP auth, session management)
    let mls_ds_url =
        std::env::var("NEST_URL").unwrap_or_else(|_| "https://api.catbird.blue".to_string());

    // Create platform implementations
    let storage = Arc::new(
        storage::open_clean_sqlite_storage(&db_path, storage::DB_KEYRING_SERVICE)
            .unwrap_or_else(|e| {
                panic!(
                    "Failed to initialize clean SQLite storage ({e}). \
                     To recover from a mixed or interrupted storage state, restart with --reset-mls-storage."
                )
            }),
    );
    let api_client = Arc::new(ReqwestApiClient::new(mls_ds_url));
    let cred_store = Arc::new(KeyringCredentialStore::new());

    // Create MLS FFI context — create parent directory first
    let mls_state_dir = data_dir.join(storage::MLS_STORAGE_GENERATION);
    std::fs::create_dir_all(&mls_state_dir).expect("Failed to create mls-state directory");

    let mls_db_path = mls_state_dir.join("mls.db");
    let keychain = Box::new(KeyringKeychainAccess::new());
    let mls_context = storage::open_clean_mls_context(&mls_db_path, storage::DB_KEYRING_SERVICE, keychain)
        .unwrap_or_else(|e| {
            panic!(
                "Failed to initialize clean MLS context ({e}). \
                 To recover from a mixed or interrupted storage state, restart with --reset-mls-storage."
            )
        });
    // checkpointed into the main database file before we start reading.
    if let Err(e) = mls_context.launch_checkpoint() {
        eprintln!(
            "[catmos] Warning: launch checkpoint failed (non-fatal): {:?}",
            e
        );
    }

    // Share the MLS context with the API client so it can derive confirmation tags.
    api_client.set_mls_context(mls_context.clone());

    // Share the MLS context with storage so the field-level (envelope)
    // encryption layer can encrypt on write / decrypt on read. The content
    // root key is installed later in the auth flow once `user_did` is known
    // (see `commands::complete_login` / `commands::try_restore_session`).
    storage.set_mls_context(mls_context.clone());

    // Create orchestrator (MLSContext::new already returns Arc<MLSContext>)
    let orchestrator = Arc::new(MLSOrchestrator::new(
        mls_context,
        storage,
        api_client.clone(),
        cred_store,
        catbird_mls::orchestrator::OrchestratorConfig::default(),
    ));
    let chat_auth = api_client.chat_auth_provider();
    let app_state = AppState {
        orchestrator,
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
        ])
        .setup(|app| {
            // Layer 3 MLS quarantine: install the orchestrator event observer
            // so quarantine entry/exit events become Tauri events
            // (`mls://quarantined` / `mls://quarantine-cleared`) the
            // SvelteKit frontend can listen for. Done inside `setup` because
            // an `AppHandle` is required to emit, and one isn't available at
            // `run()` time. The orchestrator's setter is async, so we
            // block_on it from the Tauri runtime.
            let app_handle = app.handle().clone();
            let state = app.state::<AppState>();
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

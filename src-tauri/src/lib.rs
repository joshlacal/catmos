pub mod api_client;
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

/// Tear an account runtime down in the one order the clean-storage contract
/// allows: stop the orchestrator, unbind the MLS context from every holder,
/// drop the content-root key, then flush and close the MLS database. Both the
/// provisional-failure path and the active-runtime path go through here so the
/// order can never diverge between them.
async fn teardown_runtime(
    orchestrator: &CatmosOrchestrator,
    storage: &SqliteStorage,
    api_client: &ReqwestApiClient,
    mls_context: &catbird_mls::MLSContext,
) {
    orchestrator.shutdown().await;
    storage.clear_mls_context();
    api_client.clear_mls_context();
    mls_context.clear_content_root_key();
    mls_context.interrupt();
    let _ = mls_context.flush_and_prepare_close();
}

pub struct ProvisionalAccountRuntime {
    pub user_did: String,
    pub account_id: String,
    pub orchestrator: Arc<CatmosOrchestrator>,
    pub storage: Arc<SqliteStorage>,
    pub mls_context: Arc<catbird_mls::MLSContext>,
    pub account_lock: storage::AccountLock,
    pub(crate) api_client: Arc<ReqwestApiClient>,
}

impl ProvisionalAccountRuntime {
    pub(crate) async fn drop_runtime(self) {
        teardown_runtime(
            &self.orchestrator,
            &self.storage,
            &self.api_client,
            &self.mls_context,
        )
        .await;
    }

    pub(crate) fn into_active(self) -> Arc<ActiveAccountRuntime> {
        Arc::new(ActiveAccountRuntime {
            user_did: self.user_did,
            account_id: self.account_id,
            orchestrator: self.orchestrator,
            storage: self.storage,
            mls_context: self.mls_context,
            _account_lock: self.account_lock,
        })
    }
}

pub struct ActiveAccountRuntime {
    pub(crate) user_did: String,
    pub(crate) account_id: String,
    pub(crate) orchestrator: Arc<CatmosOrchestrator>,
    pub(crate) storage: Arc<SqliteStorage>,
    pub(crate) mls_context: Arc<catbird_mls::MLSContext>,
    pub(crate) _account_lock: storage::AccountLock,
}

impl ActiveAccountRuntime {
    pub fn user_did(&self) -> &str {
        &self.user_did
    }

    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    pub fn orchestrator(&self) -> &Arc<CatmosOrchestrator> {
        &self.orchestrator
    }

    pub fn storage(&self) -> &Arc<SqliteStorage> {
        &self.storage
    }

    pub fn mls_context(&self) -> &Arc<catbird_mls::MLSContext> {
        &self.mls_context
    }
}

pub struct AppState {
    pub(crate) active_runtime: tokio::sync::RwLock<Option<Arc<ActiveAccountRuntime>>>,
    pub(crate) lifecycle_lock: tokio::sync::Mutex<()>,
    pub api_client: Arc<ReqwestApiClient>,
    /// Runtime-owned clean-chat auth capabilities. The provider contains
    /// opaque session/device/JKT state; commands never persist or log secrets.
    pub(crate) chat_auth: Arc<api_client::ChatAuthProvider>,
    pub(crate) ws_handles: Arc<Mutex<HashMap<String, WsHandle>>>,
    pub(crate) kp_monitor: Mutex<Option<tokio::task::JoinHandle<()>>>,
    pub(crate) sync_loop: Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// Per-app data directory (`~/Library/Application Support/catmos` on macOS,
    /// platform-equivalent elsewhere).
    pub(crate) data_dir: std::path::PathBuf,
    pub(crate) event_observer: std::sync::RwLock<
        Option<Arc<dyn catbird_mls::orchestrator::event_observer::OrchestratorEventObserver>>,
    >,
}

impl AppState {
    pub fn new(data_dir: std::path::PathBuf, nest_url: String) -> Self {
        let api_client = Arc::new(ReqwestApiClient::new(nest_url));
        let chat_auth = api_client.chat_auth_provider();
        Self {
            active_runtime: tokio::sync::RwLock::new(None),
            lifecycle_lock: tokio::sync::Mutex::new(()),
            chat_auth,
            api_client,
            ws_handles: Arc::new(Mutex::new(HashMap::new())),
            kp_monitor: Mutex::new(None),
            sync_loop: Mutex::new(None),
            data_dir,
            event_observer: std::sync::RwLock::new(None),
        }
    }

    pub async fn has_active_runtime(&self) -> bool {
        self.active_runtime.read().await.is_some()
    }

    pub async fn get_orchestrator(&self) -> Result<Arc<CatmosOrchestrator>, String> {
        self.active_runtime
            .read()
            .await
            .as_ref()
            .map(|r| r.orchestrator.clone())
            .ok_or_else(|| "No active MLS session; please log in".to_string())
    }

    pub async fn get_active_runtime(&self) -> Result<Arc<ActiveAccountRuntime>, String> {
        self.active_runtime
            .read()
            .await
            .as_ref()
            .cloned()
            .ok_or_else(|| "No active MLS session; please log in".to_string())
    }
    pub(crate) async fn create_provisional_account_runtime(
        &self,
        user_did: &str,
    ) -> Result<ProvisionalAccountRuntime, String> {
        let normalized_did = crate::keys::normalize_did(user_did);
        let account_id = crate::keys::derive_account_id(&normalized_did);

        // Abort prior account background tasks and drain all websocket handles
        if let Some(handle) = self.kp_monitor.lock().await.take() {
            handle.abort();
        }
        if let Some(handle) = self.sync_loop.lock().await.take() {
            handle.abort();
        }
        let mut ws = self.ws_handles.lock().await;
        for (_, handle) in ws.drain() {
            let _ = handle.shutdown.send(true);
        }
        drop(ws);

        // Drop prior runtime if activating a new account
        self.drop_account_runtime_internal().await?;

        let (storage, mls_context, content_root_key, lock) = storage::open_clean_account_storage(
            &self.data_dir,
            &normalized_did,
            storage::DB_KEYRING_SERVICE,
        )
        .map_err(|e| format!("failed to initialize clean storage for account {account_id}: {e}"))?;

        mls_context
            .set_content_root_key(content_root_key)
            .map_err(|e| format!("failed to install content-root key into MLSContext: {e:?}"))?;

        let provisional_api_client = Arc::new(self.api_client.clone_with_local_mls_context());
        provisional_api_client.set_mls_context(mls_context.clone());
        storage.set_mls_context(mls_context.clone());

        if let Err(e) = mls_context.launch_checkpoint() {
            tracing::warn!(
                "[catmos] Warning: launch checkpoint failed (non-fatal): {:?}",
                e
            );
        }

        let cred_store = Arc::new(KeyringCredentialStore::new());
        let orchestrator = Arc::new(MLSOrchestrator::new(
            mls_context.clone(),
            storage.clone(),
            provisional_api_client.clone(),
            cred_store,
            catbird_mls::orchestrator::OrchestratorConfig::default(),
        ));

        let observer = self.event_observer.read().ok().and_then(|g| g.clone());
        if let Some(obs) = observer {
            orchestrator.set_event_observer(Some(obs)).await;
        }

        Ok(ProvisionalAccountRuntime {
            user_did: normalized_did,
            account_id,
            orchestrator,
            storage,
            mls_context,
            account_lock: lock,
            api_client: provisional_api_client,
        })
    }

    pub(crate) async fn publish_active_runtime(
        &self,
        provisional: ProvisionalAccountRuntime,
    ) -> Result<Arc<CatmosOrchestrator>, String> {
        let cred_state = crate::credentials::KeyringCredentialStore::check_credential_state(
            &provisional.user_did,
        )
        .map_err(|e| format!("credential check failed before publication: {e}"))?;
        if cred_state != crate::credentials::CredentialEnrollmentState::FullyEnrolled {
            return Err(format!(
                "cannot publish runtime in incomplete credential state: {cred_state:?}"
            ));
        }

        let app_db_name = storage::app_db_file_name(&provisional.account_id);
        let mls_db_name = storage::mls_db_file_name(&provisional.account_id);
        let marker_file = storage::account_marker_path(&self.data_dir, &provisional.account_id);
        let marker_status = storage::read_account_marker(
            &marker_file,
            &provisional.user_did,
            &provisional.account_id,
            &app_db_name,
            &mls_db_name,
        )
        .map_err(|e| format!("marker check failed before publication: {e}"))?;

        if marker_status != Some(storage::MarkerStatus::Complete) {
            return Err(format!(
                "cannot publish runtime with non-complete marker: {marker_status:?}"
            ));
        }

        // Install mls_context onto shared api_client atomically at publication
        self.api_client
            .set_mls_context(provisional.mls_context.clone());

        let orchestrator = provisional.orchestrator.clone();
        let active = provisional.into_active();
        *self.active_runtime.write().await = Some(active);
        Ok(orchestrator)
    }

    async fn drop_account_runtime_internal(&self) -> Result<(), String> {
        let runtime_opt = self.active_runtime.write().await.take();
        if let Some(runtime) = runtime_opt {
            teardown_runtime(
                &runtime.orchestrator,
                &runtime.storage,
                &self.api_client,
                &runtime.mls_context,
            )
            .await;
        }
        Ok(())
    }

    pub async fn drop_account_runtime(&self) -> Result<(), String> {
        let _guard = self.lifecycle_lock.lock().await;
        self.drop_account_runtime_internal().await
    }
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

    // Process explicit recovery opt-in switch if supplied
    let args: Vec<String> = std::env::args().collect();
    let reset_idx = args.iter().position(|arg| arg == "--reset-mls-storage");
    if let Some(idx) = reset_idx {
        tracing::info!(
            "[catmos] Explicit --reset-mls-storage requested; resetting clean storage generation"
        );
        let saved_did = commands::get_saved_session_did()
            .unwrap_or_else(|e| panic!("Failed to resolve saved session DID for reset: {e}"));

        let reset_did = if idx + 1 < args.len() && !args[idx + 1].starts_with("--") {
            args[idx + 1].clone()
        } else {
            saved_did
                .clone()
                .expect("--reset-mls-storage requires a saved session DID or explicit DID argument")
        };

        let normalized_reset_did = crate::keys::normalize_did(&reset_did);
        if let Err(e) = tauri::async_runtime::block_on(storage::reset_account_storage(
            &data_dir,
            &normalized_reset_did,
            None,
            None,
            storage::DB_KEYRING_SERVICE,
        )) {
            panic!("Failed to reset clean storage via --reset-mls-storage: {e}");
        }

        if let Some(ref s_did) = saved_did {
            if crate::keys::normalize_did(s_did) == normalized_reset_did {
                if let Err(e) = commands::delete_saved_session_credentials() {
                    panic!("Failed to clear saved session credentials after reset: {e}");
                }
            }
        }
    }

    // Route XRPC calls through nest BFF (handles DPoP auth, session management)
    let mls_ds_url =
        std::env::var("NEST_URL").unwrap_or_else(|_| "https://api.catbird.blue".to_string());

    let app_state = AppState::new(data_dir, mls_ds_url);
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
            let app_handle = app.handle().clone();
            let state = app.state::<AppState>();
            let observer: Arc<
                dyn catbird_mls::orchestrator::event_observer::OrchestratorEventObserver,
            > = Arc::new(QuarantineObserver::new(app_handle));
            *state.event_observer.write().unwrap() = Some(observer);
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running Catmos");
}

mod auth;
mod commands;
pub mod mls;
#[cfg(test)]
#[rustfmt::skip]
#[path = "../../../catbird-mls/tests/support/native_archive_auth.rs"]
pub(crate) mod native_archive_auth;
mod native_keyring;
mod recovery;

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use tauri::Manager;
use tokio::sync::Mutex;

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

/// Per-conversation or global sync subscription handle.
pub struct WsHandle {
    pub shutdown: tokio::sync::watch::Sender<bool>,
}

impl WsHandle {
    pub(crate) fn owns(&self, sender: &tokio::sync::watch::Sender<bool>) -> bool {
        self.shutdown.same_channel(sender)
    }
}

pub struct AppState {
    pub mls_manager: Arc<mls::TauriMlsManager>,
    /// DID of the signed-in account.
    pub(crate) session_did: RwLock<Option<String>>,
    /// The OAuth client, opened on first use because it needs the OS keyring.
    auth: std::sync::Mutex<Option<Arc<auth::DesktopAuth>>>,
    pub ws_handles: Arc<Mutex<HashMap<String, WsHandle>>>,
    pub kp_monitor: Mutex<Option<tokio::task::JoinHandle<()>>>,
    pub sync_loop: Mutex<Option<tokio::task::JoinHandle<()>>>,
    pub data_dir: std::path::PathBuf,
}

impl AppState {
    pub(crate) fn set_session_did(&self, did: String) {
        if let Ok(mut guard) = self.session_did.write() {
            *guard = Some(did);
        }
    }

    pub(crate) fn clear_session_auth(&self) {
        if let Ok(mut guard) = self.session_did.write() {
            *guard = None;
        }
    }

    pub(crate) fn current_did(&self) -> Option<String> {
        self.session_did.read().ok().and_then(|g| g.clone())
    }

    /// The desktop OAuth client. Fails, without signing anyone out, while
    /// the OS keyring cannot be reached.
    pub(crate) fn auth(&self) -> Result<Arc<auth::DesktopAuth>, String> {
        let mut guard = self
            .auth
            .lock()
            .map_err(|_| "sign-in state is unavailable".to_string())?;
        if let Some(existing) = guard.as_ref() {
            return Ok(Arc::clone(existing));
        }
        let opened = Arc::new(auth::DesktopAuth::open(
            &self.data_dir,
            &mls::TauriMlsManager::home_ds_did(),
        )?);
        *guard = Some(Arc::clone(&opened));
        Ok(opened)
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // ctl #2: Create only the empty data directory on startup — never open any SQLite DB
    // or upload KeyPackages until explicit per-DID opt-in.
    let data_dir = resolve_data_dir();
    std::fs::create_dir_all(&data_dir).unwrap_or_else(|e| {
        panic!(
            "Failed to create data directory {}: {}",
            data_dir.display(),
            e
        )
    });

    let mls_manager = Arc::new(mls::TauriMlsManager::new(data_dir.clone()));
    let app_state = AppState {
        mls_manager,
        session_did: RwLock::new(None),
        auth: std::sync::Mutex::new(None),
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
            commands::try_restore_session,
            commands::logout,
            commands::delete_account_data,
            commands::retire_current_device,
            commands::get_conversations,
            commands::create_group,
            commands::send_message,
            commands::send_image,
            commands::send_voice,
            commands::get_messages,
            commands::get_image_attachment,
            commands::fetch_and_decrypt_blob,
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
            commands::labyrinth_probe_pds_spaces,
            commands::labyrinth_enable_and_enroll,
            commands::labyrinth_status,
            commands::labyrinth_sync_backfill,
            commands::labyrinth_restore_archived_conversations,
            commands::labyrinth_restore_conversation_history,
            commands::labyrinth_current_device_id,
            commands::labyrinth_setup_recovery_code,
            commands::labyrinth_restore_recovery_code,
            commands::labyrinth_register_passkey_prf,
            commands::labyrinth_restore_passkey_prf,
            commands::labyrinth_is_device_pending_approval,
            commands::labyrinth_approve_device,
            commands::labyrinth_list_devices,
            commands::labyrinth_revoke_device,
            commands::labyrinth_revoke_device_live,
            commands::labyrinth_initiate_otc,
            commands::labyrinth_start_otc,
            commands::labyrinth_respond_otc,
            commands::labyrinth_complete_otc,
            commands::labyrinth_verify_and_reindex_history,
            commands::labyrinth_get_read_state,
            commands::labyrinth_advance_read_state,
            commands::labyrinth_list_read_states,
            commands::labyrinth_get_circle_owner_state,
            commands::labyrinth_put_circle_owner_state,
            commands::labyrinth_merge_circle_owner_state,
            commands::labyrinth_clear_circle_acl_tombstone,
            commands::labyrinth_list_circle_owner_states,
        ])
        .setup(|app| {
            let app_handle = app.handle().clone();
            let state = app.state::<AppState>();
            state.mls_manager.attach_app_handle(app_handle);
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running Catmos");
}

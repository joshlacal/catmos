//! Unified Tauri desktop MLS + Labyrinth 1.1 manager (`Spec §6.3`, `D4`, `I8`, `I15`, `I16`, `ctl #2`).
//!
//! Wraps `catbird_mls::CatbirdMlsClient` directly on desktop with:
//! - OS Keyring key custody (`TauriKeyStore`, falling back cleanly in headless unit tests)
//! - `reqwest` HTTP transport (`TauriTransport`) preserving `Atproto-Space-Mac` and `Atproto-Space-Credential`
//! - Tauri event invalidation (`TauriChangeObserver` emitting `mls://platform-change`)
//! - Strict `ctl #2` default-off gate (`<data_dir>/mls-opt-in/<sha256(normalized_did)>.enabled`):
//!   fresh sign-ins never open SQLite databases, upload KeyPackages, or probe PDS/DS endpoints
//!   until explicit user opt-in.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use catbird_mls::client::{
    account_did_hash_hex, normalize_account_did, CatbirdMlsClient, CatbirdMlsClientConfig,
    LabyrinthBackupStatus, OtcPairingCompletion, OtcPairingOffer, PlatformChangeEvent,
    PlatformChangeObserver, PlatformHttpHeader, PlatformHttpRequest, PlatformHttpResponse,
    PlatformKeyStore, PlatformTransport, REQUIRED_LABYRINTH_OAUTH_SCOPES,
};
use catbird_mls::MLSError;
use tauri::{AppHandle, Emitter};

const KEYRING_SERVICE: &str = "blue.catbird.catmos.clean-slate";

pub struct TauriKeyStore {
    use_os_keyring: bool,
    memory_fallback: Mutex<HashMap<String, Vec<u8>>>,
    dpop_tokens: Mutex<HashMap<String, (String, i64)>>,
}

impl TauriKeyStore {
    pub fn new_os_keyring() -> Self {
        Self {
            use_os_keyring: true,
            memory_fallback: Mutex::new(HashMap::new()),
            dpop_tokens: Mutex::new(HashMap::new()),
        }
    }

    pub fn new_in_memory() -> Self {
        Self {
            use_os_keyring: false,
            memory_fallback: Mutex::new(HashMap::new()),
            dpop_tokens: Mutex::new(HashMap::new()),
        }
    }

    fn read_secret(&self, label: &str) -> Result<Option<Vec<u8>>, MLSError> {
        if self.use_os_keyring {
            if let Ok(entry) = crate::native_keyring::entry(KEYRING_SERVICE, label) {
                match entry.get_password() {
                    Ok(b64) => {
                        let decoded = BASE64_STANDARD.decode(b64.trim()).map_err(|e| {
                            MLSError::Internal(format!("decode keyring secret `{label}`: {e}"))
                        })?;
                        return Ok(Some(decoded));
                    }
                    Err(keyring::Error::NoEntry) => return Ok(None),
                    Err(_) => {
                        // Fall through to in-memory map if OS keyring is locked/unavailable.
                    }
                }
            }
        }
        let guard = self
            .memory_fallback
            .lock()
            .map_err(|_| MLSError::Internal("keystore mutex poisoned".to_string()))?;
        Ok(guard.get(label).cloned())
    }

    fn write_secret(&self, label: &str, bytes: &[u8]) -> Result<(), MLSError> {
        if self.use_os_keyring {
            if let Ok(entry) = crate::native_keyring::entry(KEYRING_SERVICE, label) {
                let encoded = BASE64_STANDARD.encode(bytes);
                if entry.set_password(&encoded).is_ok() {
                    return Ok(());
                }
            }
        }
        let mut guard = self
            .memory_fallback
            .lock()
            .map_err(|_| MLSError::Internal("keystore mutex poisoned".to_string()))?;
        guard.insert(label.to_string(), bytes.to_vec());
        Ok(())
    }

    fn delete_secret(&self, label: &str) {
        if self.use_os_keyring {
            if let Ok(entry) = crate::native_keyring::entry(KEYRING_SERVICE, label) {
                let _ = entry.delete_credential();
            }
        }
        if let Ok(mut guard) = self.memory_fallback.lock() {
            guard.remove(label);
        }
    }
}

impl PlatformKeyStore for TauriKeyStore {
    fn load_or_create_db_key(&self, account_did_hash: String) -> Result<Vec<u8>, MLSError> {
        let label = format!("db-key:{account_did_hash}");
        if let Some(existing) = self.read_secret(&label)? {
            if existing.len() == 32 {
                return Ok(existing);
            }
        }
        let mut fresh = vec![0u8; 32];
        getrandom::fill(&mut fresh)
            .map_err(|e| MLSError::Internal(format!("generate 32-byte DB key: {e}")))?;
        self.write_secret(&label, &fresh)?;
        Ok(fresh)
    }

    fn load_signature_keypair(&self, key_id: String) -> Result<Option<Vec<u8>>, MLSError> {
        self.read_secret(&format!("sig:{key_id}"))
    }

    fn store_signature_keypair(
        &self,
        key_id: String,
        keypair_bytes: Vec<u8>,
    ) -> Result<(), MLSError> {
        self.write_secret(&format!("sig:{key_id}"), &keypair_bytes)
    }

    fn delete_account_keys(&self, account_did_hash: String) -> Result<(), MLSError> {
        self.delete_secret(&format!("db-key:{account_did_hash}"));
        self.delete_secret(&format!("sig:mls-signer:{account_did_hash}"));
        if let Ok(mut dpop) = self.dpop_tokens.lock() {
            dpop.remove(&account_did_hash);
        }
        Ok(())
    }

    fn load_cached_chat_dpop_token(
        &self,
        account_did_hash: String,
    ) -> Result<Option<String>, MLSError> {
        let now_ms = chrono::Utc::now().timestamp_millis();
        let guard = self
            .dpop_tokens
            .lock()
            .map_err(|_| MLSError::Internal("dpop mutex poisoned".to_string()))?;
        Ok(guard.get(&account_did_hash).and_then(|(tok, exp)| {
            if *exp > now_ms {
                Some(tok.clone())
            } else {
                None
            }
        }))
    }

    fn store_cached_chat_dpop_token(
        &self,
        account_did_hash: String,
        token: String,
        expires_at_ms: i64,
    ) -> Result<(), MLSError> {
        let mut guard = self
            .dpop_tokens
            .lock()
            .map_err(|_| MLSError::Internal("dpop mutex poisoned".to_string()))?;
        guard.insert(account_did_hash, (token, expires_at_ms));
        Ok(())
    }
}

type SpaceRecordKey = (String, String, String);

fn percent_decode_query_param(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(hex_str) = std::str::from_utf8(&bytes[i + 1..i + 3]) {
                if let Ok(val) = u8::from_str_radix(hex_str, 16) {
                    out.push(val);
                    i += 3;
                    continue;
                }
            }
        }
        if bytes[i] == b'+' {
            out.push(b' ');
        } else {
            out.push(bytes[i]);
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub struct TauriTransport {
    client: reqwest::Client,
    session_token: RwLock<Option<String>>,
    offline_pds_spaces_override: RwLock<Option<bool>>,
    offline_space_records: Mutex<std::collections::BTreeMap<SpaceRecordKey, serde_json::Value>>,
}

impl TauriTransport {
    pub fn new(offline_pds_spaces_override: Option<bool>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            client,
            session_token: RwLock::new(None),
            offline_pds_spaces_override: RwLock::new(offline_pds_spaces_override),
            offline_space_records: Mutex::new(std::collections::BTreeMap::new()),
        }
    }

    pub fn set_session_token(&self, token: Option<String>) {
        if let Ok(mut guard) = self.session_token.write() {
            *guard = token;
        }
    }

    pub fn set_offline_pds_spaces_override(&self, value: Option<bool>) {
        if let Ok(mut guard) = self.offline_pds_spaces_override.write() {
            *guard = value;
        }
    }

    fn handle_offline_xrpc(
        &self,
        supports: bool,
        request: &PlatformHttpRequest,
    ) -> Result<PlatformHttpResponse, MLSError> {
        if !supports {
            return Ok(PlatformHttpResponse {
                status: 501,
                headers: Vec::new(),
                body: b"{\"error\":\"XRPCNotSupported\"}".to_vec(),
            });
        }

        let (path_part, query_opt) = match request.url.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (request.url.as_str(), None),
        };
        let nsid = path_part
            .rsplit_once("/xrpc/")
            .map(|(_, n)| n)
            .unwrap_or("");

        match nsid {
            "com.atproto.space.getSpace" if query_opt.is_none() => Ok(PlatformHttpResponse {
                status: 401,
                headers: Vec::new(),
                body: b"{\"error\":\"AuthMissing\"}".to_vec(),
            }),
            "com.atproto.space.applyWrites" => {
                let parsed: serde_json::Value = serde_json::from_slice(
                    request.body.as_deref().unwrap_or(b"{}"),
                )
                .map_err(|e| MLSError::Internal(format!("offline applyWrites JSON: {e}")))?;
                let space = parsed
                    .get("space")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                if let Some(writes) = parsed.get("writes").and_then(|v| v.as_array()) {
                    let mut store = self.offline_space_records.lock().map_err(|_| {
                        MLSError::Internal("offline space store poisoned".to_string())
                    })?;
                    for w in writes {
                        let op = w.get("$type").and_then(|v| v.as_str()).unwrap_or_default();
                        let col = w
                            .get("collection")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default()
                            .to_string();
                        let rkey = w
                            .get("rkey")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default()
                            .to_string();
                        if op.ends_with("#delete") {
                            store.remove(&(space.clone(), col, rkey));
                        } else if let Some(val) = w.get("value") {
                            store.insert((space.clone(), col, rkey), val.clone());
                        }
                    }
                }
                Ok(PlatformHttpResponse {
                    status: 200,
                    headers: Vec::new(),
                    body: b"{\"results\":[]}".to_vec(),
                })
            }
            "com.atproto.space.listRecords" => {
                let mut space = String::new();
                let mut collection = String::new();
                if let Some(q) = query_opt {
                    for pair in q.split('&').filter(|s| !s.is_empty()) {
                        if let Some((k, v)) = pair.split_once('=') {
                            let dk = percent_decode_query_param(k);
                            let dv = percent_decode_query_param(v);
                            if dk == "space" {
                                space = dv;
                            } else if dk == "collection" {
                                collection = dv;
                            }
                        }
                    }
                }
                let store = self
                    .offline_space_records
                    .lock()
                    .map_err(|_| MLSError::Internal("offline space store poisoned".to_string()))?;
                let records: Vec<serde_json::Value> = store
                    .iter()
                    .filter(|((s, c, _), _)| s == &space && c == &collection)
                    .map(|((_, c, rkey), val)| {
                        serde_json::json!({
                            "uri": format!("{space}/{c}/{rkey}"),
                            "cid": "bafyreiofflinetest00000000000000000000000000000000000000000",
                            "value": val,
                        })
                    })
                    .collect();
                let body = serde_json::to_vec(&serde_json::json!({ "records": records }))
                    .map_err(|e| MLSError::Internal(format!("offline listRecords JSON: {e}")))?;
                Ok(PlatformHttpResponse {
                    status: 200,
                    headers: Vec::new(),
                    body,
                })
            }
            _ => Ok(PlatformHttpResponse {
                status: 200,
                headers: Vec::new(),
                body: b"{}".to_vec(),
            }),
        }
    }
}

impl PlatformTransport for TauriTransport {
    fn execute_http(&self, request: PlatformHttpRequest) -> Result<PlatformHttpResponse, MLSError> {
        if let Ok(guard) = self.offline_pds_spaces_override.read() {
            if let Some(supports) = *guard {
                return self.handle_offline_xrpc(supports, &request);
            }
        }

        let client = self.client.clone();
        let bearer = self.session_token.read().ok().and_then(|g| g.clone());

        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| MLSError::Internal(format!("build transport runtime: {e}")))?;
            rt.block_on(async move {
                let method = reqwest::Method::from_bytes(request.method.as_bytes())
                    .map_err(|e| MLSError::invalid_input(format!("invalid HTTP method: {e}")))?;
                let mut builder = client.request(method, &request.url);
                let mut has_auth = false;
                for h in &request.headers {
                    if h.name.eq_ignore_ascii_case("authorization") {
                        has_auth = true;
                    }
                    builder = builder.header(&h.name, &h.value);
                }
                if !has_auth {
                    if let Some(tok) = bearer {
                        builder = builder.bearer_auth(tok);
                    }
                }
                if let Some(body) = request.body {
                    builder = builder.body(body);
                }
                let resp = builder
                    .send()
                    .await
                    .map_err(|e| MLSError::Internal(format!("HTTP transport failed: {e}")))?;
                let status = resp.status().as_u16();
                let headers = resp
                    .headers()
                    .iter()
                    .filter_map(|(k, v)| {
                        v.to_str().ok().map(|val| PlatformHttpHeader {
                            name: k.as_str().to_string(),
                            value: val.to_string(),
                        })
                    })
                    .collect();
                let body = resp
                    .bytes()
                    .await
                    .map_err(|e| MLSError::Internal(format!("read HTTP body: {e}")))?
                    .to_vec();
                Ok(PlatformHttpResponse {
                    status,
                    headers,
                    body,
                })
            })
        })
        .join()
        .map_err(|_| MLSError::Internal("HTTP transport worker panicked".to_string()))?
    }

    fn connect_realtime_stream(
        &self,
        _home_ds_endpoint: String,
        _cursor_seq: Option<i64>,
    ) -> Result<(), MLSError> {
        Ok(())
    }

    fn disconnect_realtime_stream(&self) -> Result<(), MLSError> {
        Ok(())
    }
}

pub struct TauriChangeObserver {
    app_handle: RwLock<Option<AppHandle>>,
}

impl Default for TauriChangeObserver {
    fn default() -> Self {
        Self::new()
    }
}

impl TauriChangeObserver {
    pub fn new() -> Self {
        Self {
            app_handle: RwLock::new(None),
        }
    }

    pub fn set_app_handle(&self, handle: AppHandle) {
        if let Ok(mut guard) = self.app_handle.write() {
            *guard = Some(handle);
        }
    }
}

impl PlatformChangeObserver for TauriChangeObserver {
    fn on_change(&self, event: PlatformChangeEvent) {
        if let Ok(guard) = self.app_handle.read() {
            if let Some(ref app) = *guard {
                let _ = app.emit("mls://platform-change", &event);
            }
        }
    }
}

pub struct TauriMlsManager {
    data_dir: PathBuf,
    keystore: Arc<TauriKeyStore>,
    transport: Arc<TauriTransport>,
    observer: Arc<TauriChangeObserver>,
    clients: Mutex<HashMap<String, Arc<CatbirdMlsClient>>>,
}

impl TauriMlsManager {
    pub fn new(data_dir: PathBuf) -> Self {
        Self {
            data_dir,
            keystore: Arc::new(TauriKeyStore::new_os_keyring()),
            transport: Arc::new(TauriTransport::new(None)),
            observer: Arc::new(TauriChangeObserver::new()),
            clients: Mutex::new(HashMap::new()),
        }
    }

    pub fn new_for_testing(data_dir: PathBuf, pds_supports_spaces: bool) -> Self {
        Self {
            data_dir,
            keystore: Arc::new(TauriKeyStore::new_in_memory()),
            transport: Arc::new(TauriTransport::new(Some(pds_supports_spaces))),
            observer: Arc::new(TauriChangeObserver::new()),
            clients: Mutex::new(HashMap::new()),
        }
    }

    pub fn attach_app_handle(&self, handle: AppHandle) {
        self.observer.set_app_handle(handle);
    }

    pub fn set_session_token(&self, token: Option<String>) {
        self.transport.set_session_token(token);
    }

    fn opt_in_marker_path(&self, did: &str) -> Result<PathBuf, String> {
        let normalized = normalize_account_did(did).map_err(|e| e.to_string())?;
        let did_hash = account_did_hash_hex(&normalized).map_err(|e| e.to_string())?;
        Ok(self
            .data_dir
            .join("mls-opt-in")
            .join(format!("{did_hash}.enabled")))
    }

    /// Strict `ctl #2` check: returns `false` on fresh sign-ins without opening any DB or network socket.
    pub fn is_opted_in(&self, did: &str) -> bool {
        self.opt_in_marker_path(did)
            .map(|p| p.exists())
            .unwrap_or(false)
    }

    pub fn set_opted_in(&self, did: &str, enabled: bool) -> Result<(), String> {
        let marker = self.opt_in_marker_path(did)?;
        if enabled {
            if let Some(parent) = marker.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            std::fs::write(&marker, b"1").map_err(|e| e.to_string())?;
        } else if marker.exists() {
            let _ = std::fs::remove_file(&marker);
        }
        Ok(())
    }

    fn load_or_create_device_id(&self, did_hash: &str) -> Result<String, String> {
        let dir = self.data_dir.join("mls-opt-in");
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let path = dir.join(format!("{did_hash}.device"));
        if let Ok(existing) = std::fs::read_to_string(&path) {
            let trimmed = existing.trim();
            if !trimmed.is_empty() {
                return Ok(trimmed.to_string());
            }
        }
        let dev_id = format!("catmos-desktop-{}", uuid::Uuid::new_v4());
        std::fs::write(&path, dev_id.as_bytes()).map_err(|e| e.to_string())?;
        Ok(dev_id)
    }

    pub fn open_or_get_client(&self, did: &str) -> Result<Arc<CatbirdMlsClient>, String> {
        let normalized = normalize_account_did(did).map_err(|e| e.to_string())?;
        let did_hash = account_did_hash_hex(&normalized).map_err(|e| e.to_string())?;

        let mut guard = self
            .clients
            .lock()
            .map_err(|_| "MLS client map mutex poisoned".to_string())?;
        if let Some(existing) = guard.get(&did_hash) {
            return Ok(Arc::clone(existing));
        }

        let device_id = self.load_or_create_device_id(&did_hash)?;
        let home_ds_endpoint =
            std::env::var("CATMOS_MLS_DS_URL").unwrap_or_else(|_| crate::nest_url());
        let home_ds_did = std::env::var("CATMOS_MLS_DS_DID")
            .unwrap_or_else(|_| "did:web:mlschat.catbird.blue".to_string());
        let pds_endpoint =
            std::env::var("CATMOS_PDS_URL").unwrap_or_else(|_| "https://swan.place".to_string());

        let cfg = CatbirdMlsClientConfig {
            storage_root: self.data_dir.to_string_lossy().to_string(),
            account_did: normalized,
            device_id,
            home_ds_did,
            home_ds_endpoint,
            pds_endpoint,
        };
        let observer: Arc<dyn PlatformChangeObserver> =
            Arc::clone(&self.observer) as Arc<dyn PlatformChangeObserver>;
        let client = CatbirdMlsClient::open(
            cfg,
            Arc::clone(&self.keystore) as Arc<dyn PlatformKeyStore>,
            Arc::clone(&self.transport) as Arc<dyn PlatformTransport>,
            Some(observer),
        )
        .map_err(|e| e.to_string())?;

        guard.insert(did_hash, Arc::clone(&client));
        Ok(client)
    }

    pub fn enable_and_enroll(
        &self,
        did: &str,
        pds_supports_spaces: Option<bool>,
        granted_scopes: Option<Vec<String>>,
    ) -> Result<LabyrinthBackupStatus, String> {
        if let Some(supports) = pds_supports_spaces {
            self.transport
                .set_offline_pds_spaces_override(Some(supports));
        }
        let scopes = granted_scopes.unwrap_or_else(|| {
            REQUIRED_LABYRINTH_OAUTH_SCOPES
                .iter()
                .map(|s| (*s).to_string())
                .collect()
        });
        let client = self.open_or_get_client(did)?;
        if let Err(err) = client.enroll_device(&scopes) {
            let _ = self.set_opted_in(did, false);
            return Err(err.to_string());
        }
        self.set_opted_in(did, true)?;
        client.labyrinth_status().map_err(|e| e.to_string())
    }

    pub fn status(&self, did: &str) -> Result<Option<LabyrinthBackupStatus>, String> {
        if !self.is_opted_in(did) {
            return Ok(None);
        }
        let client = self.open_or_get_client(did)?;
        client
            .labyrinth_status()
            .map(Some)
            .map_err(|e| e.to_string())
    }

    pub fn setup_recovery_code(&self, did: &str) -> Result<String, String> {
        let client = self.open_or_get_client(did)?;
        client.setup_recovery_code().map_err(|e| e.to_string())
    }

    pub fn restore_recovery_code(
        &self,
        did: &str,
        recovery_code_input: &str,
    ) -> Result<LabyrinthBackupStatus, String> {
        let client = self.open_or_get_client(did)?;
        client
            .restore_with_recovery_code(recovery_code_input)
            .map_err(|e| e.to_string())
    }

    pub fn register_passkey_prf(
        &self,
        did: &str,
        credential_id: Vec<u8>,
        prf_output32: Vec<u8>,
    ) -> Result<LabyrinthBackupStatus, String> {
        let client = self.open_or_get_client(did)?;
        client
            .register_passkey_prf(credential_id, prf_output32)
            .map_err(|e| e.to_string())
    }

    pub fn initiate_otc(&self, did: &str) -> Result<OtcPairingOffer, String> {
        let client = self.open_or_get_client(did)?;
        client.initiate_otc_pairing().map_err(|e| e.to_string())
    }

    pub fn complete_otc(
        &self,
        did: &str,
        six_digit_code: &str,
    ) -> Result<OtcPairingCompletion, String> {
        let client = self.open_or_get_client(did)?;
        client
            .complete_otc_pairing(six_digit_code)
            .map_err(|e| e.to_string())
    }

    pub fn revoke_device(
        &self,
        did: &str,
        target_device_id: &str,
    ) -> Result<LabyrinthBackupStatus, String> {
        let client = self.open_or_get_client(did)?;
        client
            .revoke_labyrinth_device(target_device_id)
            .map_err(|e| e.to_string())
    }

    pub fn sign_out_and_wipe(&self, did: &str) -> Result<(), String> {
        let normalized = normalize_account_did(did).map_err(|e| e.to_string())?;
        let did_hash = account_did_hash_hex(&normalized).map_err(|e| e.to_string())?;
        let removed = self
            .clients
            .lock()
            .map_err(|_| "MLS client map mutex poisoned".to_string())?
            .remove(&did_hash);
        if let Some(client) = removed {
            client.sign_out_and_wipe().map_err(|e| e.to_string())?;
        }
        let _ = self.set_opted_in(did, false);
        Ok(())
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_login_is_opted_out_and_creates_zero_mls_db_files_ctl2() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mgr = TauriMlsManager::new_for_testing(tmp.path().to_path_buf(), true);
        let did = "did:plc:catmostaurictl2user01";

        assert!(!mgr.is_opted_in(did));
        assert!(mgr.status(did).expect("status while opted out").is_none());
        assert!(
            !tmp.path().join("catbird-mls").exists(),
            "ctl #2: fresh sign-in without opt-in must not create catbird-mls DB directory"
        );
    }

    #[test]
    fn enable_and_enroll_opens_hashed_db_and_rotates_recovery_and_otc_epochs() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mgr = TauriMlsManager::new_for_testing(tmp.path().to_path_buf(), true);
        let did = "did:plc:catmostauriuser000001";

        let status = mgr
            .enable_and_enroll(did, Some(true), None)
            .expect("enroll should succeed when Spaces + scopes are available");
        assert!(mgr.is_opted_in(did));
        assert!(status.backup_enabled);
        assert_eq!(status.epoch_seq, 1);

        let did_hash = account_did_hash_hex(did).expect("did hash");
        assert!(
            tmp.path()
                .join("catbird-mls")
                .join(format!("{did_hash}.db"))
                .exists(),
            "I8: per-account SQLCipher DB must use sha256(normalized_did).db"
        );
        assert!(
            !tmp.path()
                .join("catbird-mls")
                .join("accounts.json")
                .exists(),
            "I8: plaintext accounts.json must never exist"
        );

        let code = mgr.setup_recovery_code(did).expect("setup recovery code");
        assert_eq!(
            code.chars().filter(|c| c.is_ascii_alphanumeric()).count(),
            40
        );

        let restored = mgr
            .restore_recovery_code(did, &code)
            .expect("restore with 40-char code");
        assert_eq!(restored.epoch_seq, 2);

        let offer = mgr.initiate_otc(did).expect("initiate OTC");
        let completion = mgr
            .complete_otc(did, &offer.six_digit_code)
            .expect("complete PQ OTC");
        assert_eq!(completion.initiator_mlkem768_ek_len, 1184);
        assert_eq!(completion.responder_mlkem768_ct_len, 1088);
        assert_eq!(completion.new_epoch_seq, 3);

        mgr.sign_out_and_wipe(did).expect("sign out and wipe");
        assert!(!mgr.is_opted_in(did));
        assert!(!tmp
            .path()
            .join("catbird-mls")
            .join(format!("{did_hash}.db"))
            .exists());
    }

    #[test]
    fn spaces_gate_blocks_enrollment_when_pds_lacks_spaces_i15() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mgr = TauriMlsManager::new_for_testing(tmp.path().to_path_buf(), false);
        let did = "did:plc:catmosnospacesuser001";

        let err = mgr
            .enable_and_enroll(did, Some(false), None)
            .expect_err("PDS without Spaces must reject enrollment");
        assert!(err.contains("Spaces"));
        assert!(!mgr.is_opted_in(did));
    }
}

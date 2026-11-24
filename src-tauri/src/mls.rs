//! Unified Tauri desktop MLS + Labyrinth 1.1 manager (`Spec §6.3`, `D4`, `I8`, `I15`, `I16`, `ctl #2`).
//!
//! Wraps `catbird_mls::CatbirdMlsClient` directly on desktop with:
//! - OS Keyring key custody (`TauriKeyStore`, falling back cleanly in headless unit tests)
//! - `reqwest` HTTP transport (`TauriTransport`) preserving `Atproto-Space-Mac` and `Atproto-Space-Credential`
//! - Tauri event invalidation (`TauriChangeObserver` emitting `mls://platform-change`)
//! - Strict `ctl #2` default-off gate (`<data_dir>/mls-opt-in/<sha256(normalized_did)>.enabled`):
//!   fresh sign-ins never open SQLite databases, upload KeyPackages, or probe PDS/DS endpoints
//!   until explicit user opt-in.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, RwLock};

use atproto_spaces::{
    did_resolver::DidDocument,
    http_signature::sign_credential_request_minimal,
    is_valid_did,
    kem::{encode_p256_did_key, P256SecretKey},
    SpaceUri,
};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use catbird_mls::blob_crypto::decrypt_blob;
use catbird_mls::client::{
    account_did_hash_hex, normalize_account_did, CatbirdMlsClient, CatbirdMlsClientConfig,
    CircleOwnerStateDto, DeviceRevocationReport, LabyrinthBackupStatus, LabyrinthRevocationOutcome,
    LeaveConversationOutcome, MailboxReadStateRecord, OtcInitiatedSession, OtcPairingCompletion,
    OtcPairingOffer, PlatformChangeEvent, PlatformChangeObserver, PlatformHttpHeader,
    PlatformHttpRequest, PlatformHttpResponse, PlatformKeyStore, PlatformTransport,
    RegisteredDeviceInfo, UploadedConversationAttachment, REQUIRED_LABYRINTH_OAUTH_SCOPES,
};
use catbird_mls::payload_types::{MLSAudioEmbed, MLSEmbedData, MLSImageEmbed, MLSMessagePayload};
use catbird_mls::MLSError;
use tauri::{AppHandle, Emitter};

const KEYRING_SERVICE: &str = "blue.catbird.catmos.clean-slate";

enum KeyStoreBackend {
    OsKeyring,
    #[cfg(test)]
    InMemory(Mutex<HashMap<String, Vec<u8>>>),
    #[cfg(test)]
    SimulatedUnavailable(&'static str),
}

pub struct TauriKeyStore {
    backend: KeyStoreBackend,
    dpop_tokens: Mutex<HashMap<String, (String, i64)>>,
}

impl TauriKeyStore {
    pub fn new_os_keyring() -> Self {
        Self {
            backend: KeyStoreBackend::OsKeyring,
            dpop_tokens: Mutex::new(HashMap::new()),
        }
    }

    #[cfg(test)]
    pub fn new_in_memory() -> Self {
        Self {
            backend: KeyStoreBackend::InMemory(Mutex::new(HashMap::new())),
            dpop_tokens: Mutex::new(HashMap::new()),
        }
    }

    #[cfg(test)]
    pub fn new_simulated_unavailable(reason: &'static str) -> Self {
        Self {
            backend: KeyStoreBackend::SimulatedUnavailable(reason),
            dpop_tokens: Mutex::new(HashMap::new()),
        }
    }

    fn read_secret(&self, label: &str) -> Result<Option<Vec<u8>>, MLSError> {
        match &self.backend {
            KeyStoreBackend::OsKeyring => {
                let entry = crate::native_keyring::entry(KEYRING_SERVICE, label).map_err(|e| {
                    MLSError::Internal(format!(
                        "OS keyring unavailable while opening `{label}`: {e}"
                    ))
                })?;
                match entry.get_password() {
                    Ok(b64) => {
                        let decoded = BASE64_STANDARD.decode(b64.trim()).map_err(|e| {
                            MLSError::Internal(format!("decode keyring secret `{label}`: {e}"))
                        })?;
                        Ok(Some(decoded))
                    }
                    Err(keyring::Error::NoEntry) => Ok(None),
                    Err(e) => Err(MLSError::Internal(format!(
                        "OS keyring read failed for `{label}` (refusing ephemeral fallback): {e}"
                    ))),
                }
            }
            #[cfg(test)]
            KeyStoreBackend::InMemory(map) => {
                let guard = map
                    .lock()
                    .map_err(|_| MLSError::Internal("keystore mutex poisoned".to_string()))?;
                Ok(guard.get(label).cloned())
            }
            #[cfg(test)]
            KeyStoreBackend::SimulatedUnavailable(reason) => Err(MLSError::Internal(format!(
                "OS keyring read failed for `{label}` (refusing ephemeral fallback): {reason}"
            ))),
        }
    }

    fn write_secret(&self, label: &str, bytes: &[u8]) -> Result<(), MLSError> {
        match &self.backend {
            KeyStoreBackend::OsKeyring => {
                let entry = crate::native_keyring::entry(KEYRING_SERVICE, label).map_err(|e| {
                    MLSError::Internal(format!(
                        "OS keyring unavailable while opening `{label}`: {e}"
                    ))
                })?;
                let encoded = BASE64_STANDARD.encode(bytes);
                entry.set_password(&encoded).map_err(|e| {
                    MLSError::Internal(format!(
                        "OS keyring write failed for `{label}` (refusing ephemeral fallback): {e}"
                    ))
                })
            }
            #[cfg(test)]
            KeyStoreBackend::InMemory(map) => {
                let mut guard = map
                    .lock()
                    .map_err(|_| MLSError::Internal("keystore mutex poisoned".to_string()))?;
                guard.insert(label.to_string(), bytes.to_vec());
                Ok(())
            }
            #[cfg(test)]
            KeyStoreBackend::SimulatedUnavailable(reason) => Err(MLSError::Internal(format!(
                "OS keyring write failed for `{label}` (refusing ephemeral fallback): {reason}"
            ))),
        }
    }

    fn delete_secret(&self, label: &str) -> Result<(), MLSError> {
        match &self.backend {
            KeyStoreBackend::OsKeyring => {
                let entry = crate::native_keyring::entry(KEYRING_SERVICE, label).map_err(|e| {
                    MLSError::Internal(format!(
                        "OS keyring unavailable while deleting `{label}`: {e}"
                    ))
                })?;
                match entry.delete_credential() {
                    Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
                    Err(e) => Err(MLSError::Internal(format!(
                        "OS keyring delete failed for `{label}`: {e}"
                    ))),
                }
            }
            #[cfg(test)]
            KeyStoreBackend::InMemory(map) => {
                let mut guard = map
                    .lock()
                    .map_err(|_| MLSError::Internal("keystore mutex poisoned".to_string()))?;
                guard.remove(label);
                Ok(())
            }
            #[cfg(test)]
            KeyStoreBackend::SimulatedUnavailable(reason) => Err(MLSError::Internal(format!(
                "OS keyring delete failed for `{label}`: {reason}"
            ))),
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
        self.delete_secret(&format!("db-key:{account_did_hash}"))?;
        self.delete_secret(&format!("sig:mls-signer:{account_did_hash}"))?;
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

fn origin_key(url_str: &str) -> Option<(String, String, Option<u16>)> {
    let parsed = reqwest::Url::parse(url_str).ok()?;
    let host = parsed.host_str()?.to_ascii_lowercase();
    Some((
        parsed.scheme().to_ascii_lowercase(),
        host,
        parsed.port_or_known_default(),
    ))
}

fn extract_xrpc_nsid(url_str: &str) -> Option<String> {
    let path_part = url_str.split('?').next().unwrap_or(url_str);
    let (_, nsid) = path_part.rsplit_once("/xrpc/")?;
    let trimmed = nsid.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn store_seq_hash(space: &str, col: &str, rkey: &str, val: Option<&serde_json::Value>) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    space.hash(&mut h);
    col.hash(&mut h);
    rkey.hash(&mut h);
    if let Some(v) = val {
        v.to_string().hash(&mut h);
    }
    h.finish()
}

const PERSONAL_SPACE_READ_METHODS: &[&str] = &[
    "com.atproto.space.getRecord",
    "com.atproto.space.listRecords",
    "com.atproto.space.listRepoOps",
    "com.atproto.space.getRepo",
    "com.atproto.space.getLatestCommit",
    "com.atproto.space.getBlob",
    "com.atproto.space.getSpace",
    "com.atproto.space.listWriters",
];

fn validate_direct_pds_endpoint(pds_url: &str) -> Result<reqwest::Url, MLSError> {
    let parsed = reqwest::Url::parse(pds_url)
        .map_err(|e| MLSError::invalid_input(format!("invalid personal Space PDS URL: {e}")))?;
    let scheme = parsed.scheme();
    let host = parsed
        .host_str()
        .ok_or_else(|| MLSError::invalid_input("personal Space PDS URL missing host"))?;
    let is_loopback = matches!(host, "127.0.0.1" | "localhost" | "[::1]" | "::1");
    let scheme_ok = scheme == "https" || (cfg!(test) && scheme == "http" && is_loopback);
    if !scheme_ok
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(MLSError::invalid_input(
            "Invalid personal Space PDS endpoint",
        ));
    }
    Ok(parsed)
}

pub(crate) fn personal_space_read_url(
    request: &PlatformHttpRequest,
    account_did: &str,
    session_origin: &str,
    pds_url: &str,
) -> Result<String, MLSError> {
    if !request.method.eq_ignore_ascii_case("GET") {
        return Err(MLSError::invalid_input(
            "Personal Space read does not match the signed-in account",
        ));
    }
    let source = reqwest::Url::parse(&request.url).map_err(|_| {
        MLSError::invalid_input("Personal Space read does not match the signed-in account")
    })?;
    let nsid = extract_xrpc_nsid(&request.url).ok_or_else(|| {
        MLSError::invalid_input("Personal Space read does not match the signed-in account")
    })?;
    let audience = request
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("atproto-space-audience"))
        .map(|h| h.value.as_str());
    let query = source.query();
    if origin_key(&request.url) != origin_key(session_origin)
        || !PERSONAL_SPACE_READ_METHODS.contains(&nsid.as_str())
        || audience != Some(account_did)
        || query.is_none()
    {
        return Err(MLSError::invalid_input(
            "Personal Space read does not match the signed-in account",
        ));
    }
    let pds = validate_direct_pds_endpoint(pds_url)?;
    let mut target = format!("{}/xrpc/{nsid}", pds.as_str().trim_end_matches('/'));
    if let Some(q) = query {
        target.push('?');
        target.push_str(q);
    }
    Ok(target)
}

/// D1-safe fallback URL for `com.atproto.identity.resolveDid` when the account's
/// PDS (e.g. Swan) does not expose `resolveDid` (returns 404/501).
///
/// Strictly restricted to `home_ds_did` (which the client already contacts
/// directly for MLS delivery RPCs); foreign `did:web:*` sequencers ALWAYS return
/// `None` so Space interest is never leaked to a foreign host.
pub(crate) fn home_ds_resolve_did_fallback_url(
    request: &PlatformHttpRequest,
    pds_endpoint: &str,
    home_ds_endpoint: &str,
    home_ds_did: &str,
) -> Option<String> {
    if !request.method.eq_ignore_ascii_case("GET") {
        return None;
    }
    if origin_key(&request.url) != origin_key(pds_endpoint) {
        return None;
    }
    if extract_xrpc_nsid(&request.url).as_deref() != Some("com.atproto.identity.resolveDid") {
        return None;
    }
    if !home_ds_did.starts_with("did:web:") {
        return None;
    }
    let parsed = reqwest::Url::parse(&request.url).ok()?;
    let requested_did = parsed
        .query_pairs()
        .find(|(k, _)| k == "did")
        .map(|(_, v)| v.into_owned())?;
    if requested_did.trim() != home_ds_did {
        return None;
    }
    let endpoint = validate_direct_pds_endpoint(home_ds_endpoint).ok()?;
    Some(format!(
        "{}/.well-known/did.json",
        endpoint.as_str().trim_end_matches('/')
    ))
}

async fn resolve_did_pds_endpoint(client: &reqwest::Client, did: &str) -> Result<String, MLSError> {
    let url = if did.starts_with("did:plc:") {
        format!("https://plc.directory/{}", urlencoding::encode(did))
    } else if let Some(rest) = did.strip_prefix("did:web:") {
        if rest.is_empty() || rest.contains('/') || rest.contains('?') || rest.contains('#') {
            return Err(MLSError::invalid_input(format!(
                "unsupported did:web for PDS lookup: {did}"
            )));
        }
        let host = urlencoding::decode(rest).map_err(|_| {
            MLSError::invalid_input(format!("invalid did:web host encoding: {did}"))
        })?;
        format!("https://{host}/.well-known/did.json")
    } else {
        return Err(MLSError::invalid_input(format!(
            "unsupported DID method for PDS lookup: {did}"
        )));
    };
    let resp = client.get(&url).send().await.map_err(|e| {
        MLSError::Internal(format!(
            "resolve DID document for {did}: {}",
            format_reqwest_error(&e)
        ))
    })?;
    if !resp.status().is_success() {
        return Err(MLSError::Internal(format!(
            "resolve DID document for {did} returned HTTP {}",
            resp.status().as_u16()
        )));
    }
    let body = resp.bytes().await.map_err(|e| {
        MLSError::Internal(format!(
            "read DID document for {did}: {}",
            format_reqwest_error(&e)
        ))
    })?;
    let doc = DidDocument::parse_json(did, &body)
        .map_err(|e| MLSError::Internal(format!("parse DID document for {did}: {e}")))?;
    doc.pds_endpoint()
        .map(str::to_owned)
        .map_err(|e| MLSError::Internal(format!("DID document for {did} missing PDS: {e}")))
}

/// Persistent multi-threaded Tokio runtime dedicated to `TauriTransport`'s
/// `reqwest::Client` pools.
///
/// Driving a shared `reqwest::Client` on ephemeral per-request runtimes kills
/// Hyper's background HTTP/2 / keep-alive connection drivers as soon as the
/// first request finishes, causing subsequent pooled requests to the same host
/// to fail immediately with `error sending request for url (...)`. Keeping one
/// process-global runtime avoids both dead pooled connections and Tokio's
/// drop-in-async-context panic.
fn tauri_http_runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("catmos-http")
            .enable_all()
            .build()
            .expect("build persistent TauriTransport HTTP runtime")
    })
}

fn format_reqwest_error(err: &reqwest::Error) -> String {
    let mut parts = vec![err.to_string()];
    let mut source = std::error::Error::source(err);
    while let Some(cause) = source {
        let msg = cause.to_string();
        if parts.last().map(|prev| prev != &msg).unwrap_or(true) {
            parts.push(msg);
        }
        source = cause.source();
    }
    parts.join(": ")
}

pub struct TauriTransport {
    client: reqwest::Client,
    direct_client: reqwest::Client,
    session_token: RwLock<Option<String>>,
    account_did: RwLock<Option<String>>,
    resolved_pds_cache: RwLock<HashMap<String, String>>,
    pds_endpoint: RwLock<String>,
    home_ds_endpoint: RwLock<String>,
    home_ds_did: RwLock<String>,
    offline_pds_spaces_override: RwLock<Option<bool>>,
    offline_space_records: Mutex<std::collections::BTreeMap<SpaceRecordKey, serde_json::Value>>,
}

impl TauriTransport {
    pub fn new(offline_pds_spaces_override: Option<bool>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .pool_idle_timeout(std::time::Duration::from_secs(60))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        let direct_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .pool_idle_timeout(std::time::Duration::from_secs(60))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            client,
            direct_client,
            session_token: RwLock::new(None),
            account_did: RwLock::new(None),
            resolved_pds_cache: RwLock::new(HashMap::new()),
            pds_endpoint: RwLock::new(crate::nest_url()),
            home_ds_endpoint: RwLock::new("https://chat.catbird.blue".to_string()),
            home_ds_did: RwLock::new("did:web:chat.catbird.blue".to_string()),
            offline_pds_spaces_override: RwLock::new(offline_pds_spaces_override),
            offline_space_records: Mutex::new(std::collections::BTreeMap::new()),
        }
    }

    pub fn configure_endpoints(
        &self,
        pds_endpoint: &str,
        home_ds_endpoint: &str,
        home_ds_did: &str,
    ) {
        if let Ok(mut g) = self.pds_endpoint.write() {
            *g = pds_endpoint.trim_end_matches('/').to_string();
        }
        if let Ok(mut g) = self.home_ds_endpoint.write() {
            *g = home_ds_endpoint.trim_end_matches('/').to_string();
        }
        if let Ok(mut g) = self.home_ds_did.write() {
            *g = home_ds_did
                .split('#')
                .next()
                .unwrap_or(home_ds_did)
                .to_string();
        }
    }

    pub fn set_session_token(&self, token: Option<String>) {
        if let Ok(mut guard) = self.session_token.write() {
            *guard = token;
        }
    }

    pub fn set_account_did(&self, did: Option<String>) {
        if let Ok(mut guard) = self.account_did.write() {
            *guard = did.map(|d| d.split('#').next().unwrap_or(&d).to_string());
        }
    }

    #[cfg(test)]
    pub(crate) fn set_resolved_pds_for_testing(&self, did: &str, pds_url: &str) {
        if let Ok(mut cache) = self.resolved_pds_cache.write() {
            cache.insert(did.to_string(), pds_url.to_string());
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
            "com.atproto.space.getSpace" => Ok(PlatformHttpResponse {
                status: 200,
                headers: Vec::new(),
                body: b"{\"uri\":\"at://did:plc:mock/blue.catbird.labyrinth.ownerMailbox/self\"}".to_vec(),
            }),
            "com.atproto.space.createSpace" => Ok(PlatformHttpResponse {
                status: 200,
                headers: Vec::new(),
                body: b"{\"uri\":\"at://did:plc:mock/blue.catbird.labyrinth.ownerMailbox/self\"}".to_vec(),
            }),
            "com.atproto.space.putRecord" => {
                let parsed: serde_json::Value = serde_json::from_slice(
                    request.body.as_deref().unwrap_or(b"{}"),
                )
                .map_err(|e| MLSError::Internal(format!("offline putRecord JSON: {e}")))?;
                let space = parsed
                    .get("space")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                let col = parsed
                    .get("collection")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                let rkey = parsed
                    .get("rkey")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                let cid = format!(
                    "bafyreiofflineput{:016x}",
                    store_seq_hash(&space, &col, &rkey, parsed.get("record"))
                );
                if let Some(rec) = parsed.get("record") {
                    let mut store = self.offline_space_records.lock().map_err(|_| {
                        MLSError::Internal("offline space store poisoned".to_string())
                    })?;
                    store.insert((space.clone(), col.clone(), rkey.clone()), rec.clone());
                }
                let body = serde_json::to_vec(&serde_json::json!({
                    "uri": format!("{space}/{col}/{rkey}"),
                    "cid": cid,
                }))
                .map_err(|e| MLSError::Internal(format!("offline putRecord resp: {e}")))?;
                Ok(PlatformHttpResponse {
                    status: 200,
                    headers: Vec::new(),
                    body,
                })
            }
            "com.atproto.space.getRecord" => {
                let mut space = String::new();
                let mut col = String::new();
                let mut rkey = String::new();
                if let Some(q) = query_opt {
                    for pair in q.split('&').filter(|s| !s.is_empty()) {
                        if let Some((k, v)) = pair.split_once('=') {
                            let dk = percent_decode_query_param(k);
                            let dv = percent_decode_query_param(v);
                            match dk.as_str() {
                                "space" => space = dv,
                                "collection" => col = dv,
                                "rkey" => rkey = dv,
                                _ => {}
                            }
                        }
                    }
                }
                let store = self
                    .offline_space_records
                    .lock()
                    .map_err(|_| MLSError::Internal("offline space store poisoned".to_string()))?;
                if let Some(val) = store.get(&(space.clone(), col.clone(), rkey.clone())) {
                    let cid = format!(
                        "bafyreiofflineput{:016x}",
                        store_seq_hash(&space, &col, &rkey, Some(val))
                    );
                    let body = serde_json::to_vec(&serde_json::json!({
                        "uri": format!("{space}/{col}/{rkey}"),
                        "cid": cid,
                        "value": val,
                    }))
                    .map_err(|e| MLSError::Internal(format!("offline getRecord JSON: {e}")))?;
                    Ok(PlatformHttpResponse {
                        status: 200,
                        headers: Vec::new(),
                        body,
                    })
                } else {
                    Ok(PlatformHttpResponse {
                        status: 404,
                        headers: Vec::new(),
                        body: b"{\"error\":\"RecordNotFound\"}".to_vec(),
                    })
                }
            }
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
            "com.atproto.repo.createRecord" | "com.atproto.repo.putRecord" => {
                Ok(PlatformHttpResponse {
                    status: 200,
                    headers: Vec::new(),
                    body: b"{\"uri\":\"at://did:plc:mock/blue.catbird.chat.device/self\",\"cid\":\"bafyreimock\"}".to_vec(),
                })
            }
            "com.atproto.space.deleteSpace"
            | "com.atproto.space.deleteRecord"
            | "blue.catbird.labyrinth.deleteAccountData"
            | "blue.catbird.chat.deleteChatDevice"
            | "com.atproto.repo.deleteRecord" => {
                if nsid == "com.atproto.space.deleteSpace" {
                    if let Ok(mut store) = self.offline_space_records.lock() {
                        store.clear();
                    }
                } else if nsid == "com.atproto.space.deleteRecord" {
                    if let Ok(parsed) = serde_json::from_slice::<serde_json::Value>(
                        request.body.as_deref().unwrap_or(b"{}"),
                    ) {
                        let space = parsed["space"].as_str().unwrap_or_default().to_string();
                        let col = parsed["collection"].as_str().unwrap_or_default().to_string();
                        let rkey = parsed["rkey"].as_str().unwrap_or_default().to_string();
                        if let Ok(mut store) = self.offline_space_records.lock() {
                            store.remove(&(space, col, rkey));
                        }
                    }
                }
                Ok(PlatformHttpResponse {
                    status: 200,
                    headers: Vec::new(),
                    body: b"{}".to_vec(),
                })
            }
            "com.atproto.space.listSpaces" => Ok(PlatformHttpResponse {
                status: 200,
                headers: Vec::new(),
                body: b"{\"spaces\":[]}".to_vec(),
            }),
            "com.atproto.repo.listRecords" => Ok(PlatformHttpResponse {
                status: 200,
                headers: Vec::new(),
                body: b"{\"records\":[]}".to_vec(),
            }),
            "blue.catbird.chat.enrollDevice" => Ok(PlatformHttpResponse {
                status: 200,
                headers: Vec::new(),
                body: b"{\"authGeneration\":1,\"device\":{\"authGeneration\":1}}".to_vec(),
            }),
            "blue.catbird.chat.publishDirectRequestKeys"
            | "blue.catbird.chat.replenishKeyPackages" => Ok(PlatformHttpResponse {
                status: 200,
                headers: Vec::new(),
                body: b"{\"accepted\":true}".to_vec(),
            }),
            _ => Ok(PlatformHttpResponse {
                status: 404,
                headers: Vec::new(),
                body: b"{\"error\":\"NotFound\"}".to_vec(),
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
        let direct_client = self.direct_client.clone();
        let bearer = self.session_token.read().ok().and_then(|g| g.clone());
        let account_did = self.account_did.read().ok().and_then(|g| g.clone());
        let cached_pds = account_did.as_ref().and_then(|did| {
            self.resolved_pds_cache
                .read()
                .ok()
                .and_then(|cache| cache.get(did).cloned())
        });
        let pds_endpoint = self
            .pds_endpoint
            .read()
            .map(|g| g.clone())
            .unwrap_or_else(|_| crate::nest_url());
        let home_ds_endpoint = self
            .home_ds_endpoint
            .read()
            .map(|g| g.clone())
            .unwrap_or_else(|_| "https://chat.catbird.blue".to_string());
        let home_ds_did = self
            .home_ds_did
            .read()
            .map(|g| g.clone())
            .unwrap_or_else(|_| "did:web:chat.catbird.blue".to_string());

        let is_space_credential_read = request.headers.iter().any(|h| {
            h.name.eq_ignore_ascii_case("authorization")
                && h.value.starts_with("Atproto-Space-Credential ")
        });
        let home_ds_did_fallback_url = home_ds_resolve_did_fallback_url(
            &request,
            &pds_endpoint,
            &home_ds_endpoint,
            &home_ds_did,
        );

        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        tauri_http_runtime().spawn(async move {
            let outcome: Result<(PlatformHttpResponse, Option<(String, String)>), MLSError> =
                async move {
                    let method =
                        reqwest::Method::from_bytes(request.method.as_bytes()).map_err(|e| {
                            MLSError::invalid_input(format!("invalid HTTP method: {e}"))
                        })?;

                    // Personal Space reads carry `Atproto-Space-Credential` + RFC 9421 proof of
                    // possession headers that the BFF gateway strips, so route them directly to
                    // the signed-in account's resolved PDS (matching iOS PetrelPlatformTransport).
                    let mut resolved_pds_update: Option<(String, String)> = None;
                    let (effective_client, target_url) = if is_space_credential_read {
                        let did = account_did.ok_or_else(|| {
                            MLSError::invalid_input(
                                "Personal Space read requires an authenticated account DID",
                            )
                        })?;
                        let resolved_pds = match cached_pds {
                            Some(pds) => pds,
                            None => {
                                let pds = resolve_did_pds_endpoint(&direct_client, &did).await?;
                                resolved_pds_update = Some((did.clone(), pds.clone()));
                                pds
                            }
                        };
                        let direct_url =
                            personal_space_read_url(&request, &did, &pds_endpoint, &resolved_pds)?;
                        (&direct_client, direct_url)
                    } else {
                        (&client, request.url.clone())
                    };

                    let mut builder = effective_client.request(method, &target_url);
                    let mut has_auth = false;
                    for h in &request.headers {
                        if h.name.eq_ignore_ascii_case("authorization") {
                            has_auth = true;
                        }
                        builder = builder.header(&h.name, &h.value);
                    }
                    if !has_auth {
                        if let Some(tok) = bearer {
                            let req_origin = origin_key(&request.url);
                            let delivery_method = extract_xrpc_nsid(&request.url).filter(|nsid| {
                                req_origin.is_some()
                                    && req_origin == origin_key(&home_ds_endpoint)
                                    && (nsid.starts_with("blue.catbird.chat.")
                                        || nsid.starts_with("blue.catbird.labyrinth."))
                            });
                            if let Some(nsid) = delivery_method {
                                let sa_url = format!(
                                    "{}/xrpc/com.atproto.server.getServiceAuth",
                                    pds_endpoint.trim_end_matches('/')
                                );
                                let sa_resp = client
                                    .get(&sa_url)
                                    .query(&[("aud", home_ds_did.as_str()), ("lxm", nsid.as_str())])
                                    .bearer_auth(&tok)
                                    .send()
                                    .await
                                    .map_err(|e| {
                                        MLSError::Internal(format!(
                                            "mint getServiceAuth `{nsid}` failed: {}",
                                            format_reqwest_error(&e)
                                        ))
                                    })?;
                                if !sa_resp.status().is_success() {
                                    let status = sa_resp.status().as_u16();
                                    let text = sa_resp.text().await.unwrap_or_default();
                                    return Err(MLSError::Internal(format!(
                                        "getServiceAuth `{nsid}` returned HTTP {status}: {text}"
                                    )));
                                }
                                let sa_json: serde_json::Value =
                                    sa_resp.json().await.map_err(|e| {
                                        MLSError::Internal(format!(
                                            "decode getServiceAuth `{nsid}` JSON: {}",
                                            format_reqwest_error(&e)
                                        ))
                                    })?;
                                let service_jwt = sa_json
                                    .get("token")
                                    .and_then(|v| v.as_str())
                                    .ok_or_else(|| {
                                        MLSError::Internal(format!(
                                            "getServiceAuth `{nsid}` response missing token"
                                        ))
                                    })?;
                                if service_jwt.is_empty() || service_jwt == tok {
                                    return Err(MLSError::Internal(
                                        "PDS did not return a separate service token".to_string(),
                                    ));
                                }
                                builder = builder.bearer_auth(service_jwt);
                            } else if req_origin.is_some()
                                && req_origin == origin_key(&pds_endpoint)
                            {
                                builder = builder.bearer_auth(tok);
                            }
                        }
                    }
                    if let Some(body) = request.body {
                        builder = builder.body(body);
                    }
                    let resp = builder.send().await.map_err(|e| {
                        MLSError::Internal(format!(
                            "HTTP transport failed: {}",
                            format_reqwest_error(&e)
                        ))
                    })?;
                    let status = resp.status().as_u16();
                    if matches!(status, 404 | 501) {
                        if let Some(fallback_url) = home_ds_did_fallback_url {
                            if let Ok(fb_resp) = direct_client.get(&fallback_url).send().await {
                                if fb_resp.status().is_success() {
                                    let fb_status = fb_resp.status().as_u16();
                                    let fb_headers = fb_resp
                                        .headers()
                                        .iter()
                                        .filter_map(|(k, v)| {
                                            v.to_str().ok().map(|val| PlatformHttpHeader {
                                                name: k.as_str().to_string(),
                                                value: val.to_string(),
                                            })
                                        })
                                        .collect();
                                    if let Ok(fb_bytes) = fb_resp.bytes().await {
                                        let id_matches =
                                            serde_json::from_slice::<serde_json::Value>(&fb_bytes)
                                                .ok()
                                                .and_then(|v| {
                                                    v.get("id")
                                                        .and_then(|id| id.as_str())
                                                        .map(|id| id == home_ds_did)
                                                })
                                                .unwrap_or(false);
                                        if id_matches {
                                            return Ok((
                                                PlatformHttpResponse {
                                                    status: fb_status,
                                                    headers: fb_headers,
                                                    body: fb_bytes.to_vec(),
                                                },
                                                resolved_pds_update,
                                            ));
                                        }
                                    }
                                }
                            }
                        }
                    }
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
                        .map_err(|e| {
                            MLSError::Internal(format!(
                                "read HTTP body: {}",
                                format_reqwest_error(&e)
                            ))
                        })?
                        .to_vec();
                    Ok((
                        PlatformHttpResponse {
                            status,
                            headers,
                            body,
                        },
                        resolved_pds_update,
                    ))
                }
                .await;
            let _ = tx.send(outcome);
        });
        let (response, resolved_pds_update) = rx
            .recv()
            .map_err(|_| MLSError::Internal("HTTP transport worker panicked".to_string()))??;
        if let Some((did, pds)) = resolved_pds_update {
            if let Ok(mut cache) = self.resolved_pds_cache.write() {
                cache.insert(did, pds);
            }
        }
        Ok(response)
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

#[cfg(test)]
type LiveTestTransportOverride = (Arc<dyn PlatformTransport>, String, String, String);

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LabyrinthArchiveRestoreSummary {
    pub conversations_discovered: u32,
    pub conversations_restored: u32,
    pub messages_restored: u32,
    pub errors: Vec<String>,
}

fn collect_archive_candidate_conversation_ids(
    local_ids: impl IntoIterator<Item = String>,
    account_meta_kind_keys: impl IntoIterator<Item = String>,
    read_state_ids: impl IntoIterator<Item = String>,
) -> Vec<String> {
    let mut ids = BTreeSet::new();
    for id in local_ids {
        let trimmed = id.trim();
        if !trimmed.is_empty() {
            ids.insert(trimmed.to_owned());
        }
    }
    for key in account_meta_kind_keys {
        if let Some(cid) = key.strip_prefix("conversation_kind:") {
            let trimmed = cid.trim();
            if !trimmed.is_empty() {
                ids.insert(trimmed.to_owned());
            }
        }
    }
    for id in read_state_ids {
        let trimmed = id.trim();
        if !trimmed.is_empty() {
            ids.insert(trimmed.to_owned());
        }
    }
    ids.into_iter().collect()
}

pub struct TauriMlsManager {
    data_dir: PathBuf,
    keystore: Arc<TauriKeyStore>,
    transport: Arc<TauriTransport>,
    observer: Arc<TauriChangeObserver>,
    clients: Mutex<HashMap<String, Arc<CatbirdMlsClient>>>,
    #[cfg(test)]
    live_test_transport: Option<LiveTestTransportOverride>,
}

impl TauriMlsManager {
    pub fn new(data_dir: PathBuf) -> Self {
        Self {
            data_dir,
            keystore: Arc::new(TauriKeyStore::new_os_keyring()),
            transport: Arc::new(TauriTransport::new(None)),
            observer: Arc::new(TauriChangeObserver::new()),
            clients: Mutex::new(HashMap::new()),
            #[cfg(test)]
            live_test_transport: None,
        }
    }

    #[cfg(test)]
    pub fn new_for_testing(data_dir: PathBuf, pds_supports_spaces: bool) -> Self {
        Self {
            data_dir,
            keystore: Arc::new(TauriKeyStore::new_in_memory()),
            transport: Arc::new(TauriTransport::new(Some(pds_supports_spaces))),
            observer: Arc::new(TauriChangeObserver::new()),
            clients: Mutex::new(HashMap::new()),
            #[cfg(test)]
            live_test_transport: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn new_with_live_transport_for_testing(
        data_dir: PathBuf,
        transport: Arc<dyn PlatformTransport>,
        pds_endpoint: impl Into<String>,
        home_ds_endpoint: impl Into<String>,
        home_ds_did: impl Into<String>,
    ) -> Self {
        Self {
            data_dir,
            keystore: Arc::new(TauriKeyStore::new_in_memory()),
            transport: Arc::new(TauriTransport::new(None)),
            observer: Arc::new(TauriChangeObserver::new()),
            clients: Mutex::new(HashMap::new()),
            live_test_transport: Some((
                transport,
                pds_endpoint.into(),
                home_ds_endpoint.into(),
                home_ds_did.into(),
            )),
        }
    }

    pub fn attach_app_handle(&self, handle: AppHandle) {
        self.observer.set_app_handle(handle);
    }

    pub fn set_session_token(&self, token: Option<String>) {
        self.transport.set_session_token(token);
    }

    pub fn set_account_did(&self, did: Option<String>) {
        self.transport.set_account_did(did);
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
            if let Some(valid) = uuid::Uuid::parse_str(existing.trim())
                .ok()
                .filter(|u| u.get_version_num() == 4)
            {
                return Ok(valid.hyphenated().to_string());
            }
        }
        let dev_id = uuid::Uuid::new_v4().hyphenated().to_string();
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
        let home_ds_endpoint = std::env::var("CATMOS_MLS_DS_URL")
            .unwrap_or_else(|_| "https://chat.catbird.blue".to_string());
        let home_ds_did = std::env::var("CATMOS_MLS_DS_DID")
            .unwrap_or_else(|_| "did:web:chat.catbird.blue".to_string());
        let pds_endpoint = std::env::var("CATMOS_PDS_URL").unwrap_or_else(|_| crate::nest_url());

        self.transport
            .configure_endpoints(&pds_endpoint, &home_ds_endpoint, &home_ds_did);
        self.transport.set_account_did(Some(normalized.clone()));

        #[cfg(test)]
        if let Some((ref live_tx, ref pds_url, ref ds_url, ref ds_did)) = self.live_test_transport {
            let live_cfg = CatbirdMlsClientConfig {
                storage_root: self.data_dir.to_string_lossy().to_string(),
                account_did: normalized,
                device_id,
                home_ds_did: ds_did.clone(),
                home_ds_endpoint: ds_url.clone(),
                pds_endpoint: pds_url.clone(),
            };
            let observer: Arc<dyn PlatformChangeObserver> =
                Arc::clone(&self.observer) as Arc<dyn PlatformChangeObserver>;
            let client = CatbirdMlsClient::open(
                live_cfg,
                Arc::clone(&self.keystore) as Arc<dyn PlatformKeyStore>,
                Arc::clone(live_tx),
                Some(observer),
            )
            .map_err(|e| e.to_string())?;
            guard.insert(did_hash, Arc::clone(&client));
            return Ok(client);
        }
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
        // Unit tests drive Space-only flows over the offline test transport, so they open
        // catbird-mls's explicit offline archive harness; every other build opens the live client.
        #[cfg(test)]
        let open = CatbirdMlsClient::open_offline_archive_for_test;
        #[cfg(not(test))]
        let open = CatbirdMlsClient::open;
        let client = open(
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
        #[cfg(test)]
        let use_offline_override = self.live_test_transport.is_none();
        #[cfg(not(test))]
        let use_offline_override = true;
        if use_offline_override {
            if let Some(supports) = pds_supports_spaces {
                self.transport
                    .set_offline_pds_spaces_override(Some(supports));
            }
        }
        let scopes = granted_scopes.unwrap_or_else(|| {
            REQUIRED_LABYRINTH_OAUTH_SCOPES
                .iter()
                .map(|s| (*s).to_string())
                .collect()
        });
        let was_opted_in = self.is_opted_in(did);
        let client = self.open_or_get_client(did)?;
        if let Err(err) = client.enroll_device(&scopes) {
            if !was_opted_in {
                let _ = self.set_opted_in(did, false);
            }
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
    ) -> Result<LabyrinthRevocationOutcome, String> {
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

    pub fn home_ds_did() -> String {
        std::env::var("CATMOS_MLS_DS_DID")
            .unwrap_or_else(|_| "did:web:chat.catbird.blue".to_string())
    }

    pub fn home_ds_endpoint() -> String {
        std::env::var("CATMOS_MLS_DS_URL")
            .unwrap_or_else(|_| "https://chat.catbird.blue".to_string())
    }

    /// If this device is still locally marked `pending_approval`, re-run idempotent
    /// `enroll_device` so `catbird-mls` checks `getOwnDevices` on `chat.catbird.blue`.
    /// Once an existing active device (e.g. iPhone) approves this device, this flips local
    /// status to `active` and publishes `DirectRequestKeys` automatically.
    /// Returns `true` if the device is STILL `pending_approval` on the delivery service.
    fn refresh_pending_device_approval_if_needed(&self, client: &CatbirdMlsClient) -> bool {
        if !client.is_device_pending_approval().unwrap_or(false) {
            return false;
        }
        let scopes: Vec<String> = REQUIRED_LABYRINTH_OAUTH_SCOPES
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        let _ = client.enroll_device(&scopes);
        client.is_device_pending_approval().unwrap_or(false)
    }

    pub fn sync(&self, did: &str) -> Result<u32, String> {
        let client = self.open_or_get_client(did)?;
        if self.refresh_pending_device_approval_if_needed(&client) {
            return Ok(0);
        }
        let applied = client.sync().map_err(|e| e.to_string())?;
        let _ = client.fulfill_pending_group_leaves();
        Ok(applied)
    }

    pub fn current_device_id(&self, did: &str) -> Result<Option<String>, String> {
        let normalized = normalize_account_did(did).map_err(|e| e.to_string())?;
        let did_hash = account_did_hash_hex(&normalized).map_err(|e| e.to_string())?;
        let path = self
            .data_dir
            .join("mls-opt-in")
            .join(format!("{did_hash}.device"));
        let Ok(raw) = std::fs::read_to_string(&path) else {
            return Ok(None);
        };
        Ok(uuid::Uuid::parse_str(raw.trim())
            .ok()
            .filter(|u| u.get_version_num() == 4)
            .map(|u| u.hyphenated().to_string()))
    }

    pub fn is_device_pending_approval(&self, did: &str) -> Result<bool, String> {
        if !self.is_opted_in(did) {
            return Ok(false);
        }
        let client = self.open_or_get_client(did)?;
        client
            .is_device_pending_approval()
            .map_err(|e| e.to_string())
    }

    pub fn approve_device(&self, did: &str, target_device_id: &str) -> Result<(), String> {
        let client = self.open_or_get_client(did)?;
        client
            .approve_device(target_device_id)
            .map_err(|e| e.to_string())
    }

    pub fn list_devices(&self, did: &str) -> Result<Vec<RegisteredDeviceInfo>, String> {
        if !self.is_opted_in(did) {
            return Ok(Vec::new());
        }
        let client = self.open_or_get_client(did)?;
        client.list_devices().map_err(|e| e.to_string())
    }

    pub fn revoke_device_live(
        &self,
        did: &str,
        target_device_id: &str,
    ) -> Result<DeviceRevocationReport, String> {
        let client = self.open_or_get_client(did)?;
        client
            .revoke_device(target_device_id)
            .map_err(|e| e.to_string())
    }

    pub fn retire_current_device(&self, did: &str) -> Result<(), String> {
        let normalized = normalize_account_did(did).map_err(|e| e.to_string())?;
        let did_hash = account_did_hash_hex(&normalized).map_err(|e| e.to_string())?;
        let client = self.open_or_get_client(did)?;
        client.retire_current_device().map_err(|e| e.to_string())?;
        if let Ok(mut guard) = self.clients.lock() {
            guard.remove(&did_hash);
        }
        let _ = self.set_opted_in(did, false);
        let _ = std::fs::remove_file(
            self.data_dir
                .join("mls-opt-in")
                .join(format!("{did_hash}.device")),
        );
        Ok(())
    }

    /// Fail-closed full account deletion (`D-3`): deletes remote Space/PDS/DS account state
    /// FIRST, preserving the open client, SQLCipher DB, and opt-in markers if any remote delete
    /// fails.
    pub fn delete_account_data(&self, did: &str) -> Result<(), String> {
        let normalized = normalize_account_did(did).map_err(|e| e.to_string())?;
        let did_hash = account_did_hash_hex(&normalized).map_err(|e| e.to_string())?;
        let client = self.open_or_get_client(did)?;
        client.delete_account_data().map_err(|e| e.to_string())?;
        if let Ok(mut guard) = self.clients.lock() {
            guard.remove(&did_hash);
        }
        let _ = self.set_opted_in(did, false);
        let _ = std::fs::remove_file(
            self.data_dir
                .join("mls-opt-in")
                .join(format!("{did_hash}.device")),
        );
        Ok(())
    }

    pub fn restore_passkey_prf(
        &self,
        did: &str,
        credential_id: Vec<u8>,
        prf_output32: Vec<u8>,
    ) -> Result<LabyrinthBackupStatus, String> {
        let client = self.open_or_get_client(did)?;
        client
            .restore_with_passkey_prf(credential_id, prf_output32)
            .map_err(|e| e.to_string())
    }

    pub fn start_otc(
        &self,
        did: &str,
        six_digit_code: &str,
    ) -> Result<OtcInitiatedSession, String> {
        let client = self.open_or_get_client(did)?;
        client
            .start_otc_pairing(six_digit_code)
            .map_err(|e| e.to_string())
    }

    pub fn respond_otc(
        &self,
        did: &str,
        session_id_hex: &str,
        six_digit_code: Option<&str>,
    ) -> Result<(), String> {
        let client = self.open_or_get_client(did)?;
        client
            .respond_otc_pairing(session_id_hex, six_digit_code)
            .map_err(|e| e.to_string())
    }

    pub fn verify_and_reindex_history(
        &self,
        did: &str,
        conversation_id: &str,
    ) -> Result<u32, String> {
        let client = self.open_or_get_client(did)?;
        client
            .verify_and_reindex_history(conversation_id)
            .map_err(|e| e.to_string())
    }

    pub fn restore_conversation_from_owner_mailbox(
        &self,
        did: &str,
        conversation_id: &str,
    ) -> Result<u32, String> {
        let client = self.open_or_get_client(did)?;
        client
            .restore_conversation_from_owner_mailbox(conversation_id)
            .map_err(|e| e.to_string())
    }

    /// Discovers existing conversations across live DS inventory (`sync()` -> `conversation_kind:*`),
    /// local conversations, and personal `OwnerMailbox` read states, then pulls & decrypts their
    /// archived Labyrinth message batches into the local SQLite database.
    pub fn restore_archived_conversations(
        &self,
        did: &str,
    ) -> Result<LabyrinthArchiveRestoreSummary, String> {
        let client = self.open_or_get_client(did)?;
        let mut summary = LabyrinthArchiveRestoreSummary::default();

        // Step 0: If this device was enrolled in `pending_approval`, re-check whether an existing
        // authorized device (e.g. iPhone) has approved it yet on `chat.catbird.blue`.
        if self.refresh_pending_device_approval_if_needed(&client) {
            let dev_label = self
                .current_device_id(did)
                .ok()
                .flatten()
                .unwrap_or_else(|| "this device".to_string());
            summary.errors.push(format!(
                "Device {dev_label} is still pending approval on chat.catbird.blue — your Labyrinth mailbox keys are unlocked, but the delivery service blocks conversation listing until approved. Open Catbird on your iPhone -> Settings -> Account & Security -> Devices, tap Approve for {dev_label}, then click Sync History Now."
            ));
        } else if let Err(err) = client.sync() {
            // Step 1: Run live sync so `blue.catbird.chat.getConversations` populates
            // `conversation_kind:<cid>` for every active conversation (and processes any pending Welcomes).
            summary.errors.push(format!("sync: {err}"));
        }

        // Step 2: Gather candidate conversation IDs from all authoritative sources.
        let local_ids: Vec<String> = client
            .list_conversations(None, 500)
            .unwrap_or_default()
            .into_iter()
            .map(|row| row.conversation_id)
            .collect();
        let meta_keys: Vec<String> = client
            .db()
            .read_tx(|tx| tx.list_account_meta_prefix("conversation_kind:"))
            .unwrap_or_default()
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        let read_state_ids: Vec<String> = match client.list_read_states() {
            Ok(states) => states.into_iter().map(|s| s.conversation_id).collect(),
            Err(err) => {
                summary.errors.push(format!("list_read_states: {err}"));
                Vec::new()
            }
        };

        let candidates =
            collect_archive_candidate_conversation_ids(local_ids, meta_keys, read_state_ids);
        summary.conversations_discovered = candidates.len() as u32;

        // Step 3: Pull & decrypt Labyrinth archive history for each discovered conversation.
        for cid in candidates {
            match client.restore_conversation_from_owner_mailbox(&cid) {
                Ok(restored) => {
                    if restored > 0 {
                        summary.conversations_restored =
                            summary.conversations_restored.saturating_add(1);
                        summary.messages_restored =
                            summary.messages_restored.saturating_add(restored);
                    }
                }
                Err(err) => {
                    summary.errors.push(format!("{cid}: {err}"));
                }
            }
        }

        Ok(summary)
    }

    pub fn leave_conversation(
        &self,
        did: &str,
        conversation_id: &str,
    ) -> Result<LeaveConversationOutcome, String> {
        let client = self.open_or_get_client(did)?;
        if let Ok(requests) = client.list_requests(None) {
            if let Some(pending) = requests
                .into_iter()
                .find(|r| r.request_id == conversation_id || r.conversation_id == conversation_id)
            {
                client
                    .decline_direct_request(&pending.request_id)
                    .map_err(|e| e.to_string())?;
                return Ok(LeaveConversationOutcome {
                    left_immediately: true,
                    leave_request_id: None,
                    rearchived_messages: 0,
                });
            }
        }
        client
            .leave_conversation(conversation_id)
            .map_err(|e| e.to_string())
    }

    pub fn upload_conversation_attachment(
        &self,
        did: &str,
        conversation_id: &str,
        plaintext: Vec<u8>,
        mime_type: String,
    ) -> Result<UploadedConversationAttachment, String> {
        let client = self.open_or_get_client(did)?;
        client
            .upload_conversation_attachment(conversation_id, plaintext, mime_type)
            .map_err(|e| e.to_string())
    }

    pub fn download_conversation_attachment(
        &self,
        did: &str,
        locator: &str,
        key: &[u8],
        iv: &[u8],
        expected_sha256_hex: &str,
    ) -> Result<Vec<u8>, String> {
        let (space_raw, repo_did, cid) = split_attachment_locator(locator).ok_or_else(|| {
            format!(
                "invalid Space attachment locator `{locator}`: expected \"{{spaceURI}}|{{repoDID}}|{{cid}}\" or \"{{spaceURI}}/{{repoDID}}#{{cid}}\""
            )
        })?;
        if !is_valid_did(repo_did) {
            return Err(format!("invalid Space attachment writer DID: {repo_did}"));
        }
        let space = SpaceUri::parse_hedged(space_raw)
            .map_err(|e| format!("invalid Space attachment URI `{space_raw}`: {e}"))?;
        if space.space_type != "blue.catbird.labyrinth.conversation" {
            return Err(format!(
                "unsupported attachment Space type: {}",
                space.space_type
            ));
        }

        let normalized = normalize_account_did(did).map_err(|e| e.to_string())?;
        let did_hash = account_did_hash_hex(&normalized).map_err(|e| e.to_string())?;
        let device_id = self.load_or_create_device_id(&did_hash)?;
        let pds_endpoint = std::env::var("CATMOS_PDS_URL").unwrap_or_else(|_| crate::nest_url());
        let home_ds_endpoint = Self::home_ds_endpoint();

        let pop_key = {
            let mut found = None;
            for _ in 0..128 {
                let mut entropy = [0u8; 32];
                getrandom::fill(&mut entropy)
                    .map_err(|e| format!("generate Space attachment PoP entropy: {e}"))?;
                if let Ok(sk) = P256SecretKey::from_slice(&entropy) {
                    found = Some(sk);
                    break;
                }
            }
            found.ok_or_else(|| "generate Space attachment PoP key exhausted".to_string())?
        };
        let cnf_kid = encode_p256_did_key(&pop_key.public_key());

        let deleg_resp = self
            .transport
            .execute_http(PlatformHttpRequest {
                method: "GET".to_string(),
                url: format!(
                    "{}/xrpc/com.atproto.space.getDelegationToken?space={}",
                    pds_endpoint.trim_end_matches('/'),
                    urlencoding::encode(&space.raw),
                ),
                headers: Vec::new(),
                body: None,
            })
            .map_err(|e| format!("getDelegationToken failed: {e}"))?;
        if !(200..300).contains(&deleg_resp.status) {
            return Err(format!(
                "getDelegationToken returned HTTP {}: {}",
                deleg_resp.status,
                String::from_utf8_lossy(&deleg_resp.body)
            ));
        }
        let deleg_json: serde_json::Value = serde_json::from_slice(&deleg_resp.body)
            .map_err(|e| format!("decode delegation token JSON: {e}"))?;
        let delegation_token = deleg_json["token"]
            .as_str()
            .filter(|t| !t.is_empty())
            .ok_or_else(|| "getDelegationToken response missing token".to_string())?;

        let cred_body = serde_json::to_vec(&serde_json::json!({
            "actorDeviceId": device_id,
            "authorityDid": space.authority,
            "space": space.raw,
            "delegationToken": delegation_token,
            "cnfKey": cnf_kid,
        }))
        .map_err(|e| format!("encode relaySpaceCredential body: {e}"))?;
        let cred_resp = self
            .transport
            .execute_http(PlatformHttpRequest {
                method: "POST".to_string(),
                url: format!(
                    "{}/xrpc/blue.catbird.chat.relaySpaceCredential",
                    home_ds_endpoint.trim_end_matches('/'),
                ),
                headers: vec![PlatformHttpHeader {
                    name: "content-type".to_string(),
                    value: "application/json".to_string(),
                }],
                body: Some(cred_body),
            })
            .map_err(|e| format!("relaySpaceCredential failed: {e}"))?;
        if !(200..300).contains(&cred_resp.status) {
            return Err(format!(
                "relaySpaceCredential returned HTTP {}: {}",
                cred_resp.status,
                String::from_utf8_lossy(&cred_resp.body)
            ));
        }
        let cred_json: serde_json::Value = serde_json::from_slice(&cred_resp.body)
            .map_err(|e| format!("decode Space credential JSON: {e}"))?;
        let credential_jwt = cred_json["credential"]
            .as_str()
            .filter(|t| !t.is_empty())
            .ok_or_else(|| "relaySpaceCredential response missing credential".to_string())?;

        let signed = sign_credential_request_minimal(&pop_key, credential_jwt, repo_did)
            .map_err(|e| format!("sign Space getBlob credential PoP: {e}"))?;
        let query = format!(
            "cid={}&repo={}&space={}",
            urlencoding::encode(cid),
            urlencoding::encode(repo_did),
            urlencoding::encode(&space.raw),
        );
        let read_body = serde_json::to_vec(&serde_json::json!({
            "actorDeviceId": device_id,
            "targetDid": repo_did,
            "nsid": "com.atproto.space.getBlob",
            "query": query,
            "credential": credential_jwt,
            "spaceAudience": signed.atproto_space_audience,
            "signatureInput": signed.signature_input,
            "signature": signed.signature,
        }))
        .map_err(|e| format!("encode relaySpaceRead body: {e}"))?;
        let blob_resp = self
            .transport
            .execute_http(PlatformHttpRequest {
                method: "POST".to_string(),
                url: format!(
                    "{}/xrpc/blue.catbird.chat.relaySpaceRead",
                    home_ds_endpoint.trim_end_matches('/'),
                ),
                headers: vec![PlatformHttpHeader {
                    name: "content-type".to_string(),
                    value: "application/json".to_string(),
                }],
                body: Some(read_body),
            })
            .map_err(|e| format!("relaySpaceRead(getBlob) failed: {e}"))?;
        if !(200..300).contains(&blob_resp.status) {
            return Err(format!(
                "relaySpaceRead(getBlob) returned HTTP {}: {}",
                blob_resp.status,
                String::from_utf8_lossy(&blob_resp.body)
            ));
        }

        decrypt_blob(&blob_resp.body, key, iv, expected_sha256_hex)
            .map_err(|e| format!("decrypt Space attachment failed: {e}"))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn send_image_message(
        &self,
        did: &str,
        conversation_id: &str,
        content: &str,
        data: Vec<u8>,
        content_type: String,
        width: u32,
        height: u32,
        alt_text: Option<String>,
    ) -> Result<catbird_mls::storage::MessageRow, String> {
        let uploaded =
            self.upload_conversation_attachment(did, conversation_id, data, content_type)?;
        let embed = MLSEmbedData::image(MLSImageEmbed {
            blob_id: uploaded.locator,
            key: uploaded.symmetric_key,
            iv: uploaded.iv,
            sha256: hex::encode(&uploaded.ciphertext_sha256),
            content_type: uploaded.mime_type,
            size: uploaded.ciphertext_size as usize,
            width,
            height,
            alt_text,
            blurhash: None,
        })
        .map_err(|e| format!("build image embed: {e}"))?;
        let payload = MLSMessagePayload::text_with_embed(content, embed);
        let payload_json =
            serde_json::to_string(&payload).map_err(|e| format!("serialize image payload: {e}"))?;
        self.send_message(did, conversation_id, &payload_json)
    }

    pub fn send_voice_message(
        &self,
        did: &str,
        conversation_id: &str,
        audio_data: Vec<u8>,
        duration_ms: u64,
        waveform: Vec<f32>,
        content_type: String,
    ) -> Result<catbird_mls::storage::MessageRow, String> {
        let uploaded =
            self.upload_conversation_attachment(did, conversation_id, audio_data, content_type)?;
        let embed = MLSEmbedData::audio(MLSAudioEmbed {
            blob_id: uploaded.locator,
            key: uploaded.symmetric_key,
            iv: uploaded.iv,
            sha256: hex::encode(&uploaded.ciphertext_sha256),
            content_type: uploaded.mime_type,
            size: uploaded.ciphertext_size,
            duration_ms: duration_ms.max(1),
            waveform,
            transcript: None,
        })
        .map_err(|e| format!("build voice embed: {e}"))?;
        let payload = MLSMessagePayload::text_with_embed("", embed);
        let payload_json =
            serde_json::to_string(&payload).map_err(|e| format!("serialize voice payload: {e}"))?;
        self.send_message(did, conversation_id, &payload_json)
    }

    pub fn get_read_state(
        &self,
        did: &str,
        conversation_id: &str,
    ) -> Result<Option<MailboxReadStateRecord>, String> {
        let client = self.open_or_get_client(did)?;
        client
            .get_read_state(conversation_id)
            .map_err(|e| e.to_string())
    }

    pub fn advance_read_state(
        &self,
        did: &str,
        conversation_id: &str,
        candidate_seq: u64,
    ) -> Result<MailboxReadStateRecord, String> {
        let client = self.open_or_get_client(did)?;
        client
            .advance_read_state(conversation_id, candidate_seq)
            .map_err(|e| e.to_string())
    }

    pub fn list_read_states(&self, did: &str) -> Result<Vec<MailboxReadStateRecord>, String> {
        let client = self.open_or_get_client(did)?;
        client.list_read_states().map_err(|e| e.to_string())
    }

    pub fn get_circle_owner_state(
        &self,
        did: &str,
        circle_id: &str,
    ) -> Result<Option<CircleOwnerStateDto>, String> {
        let client = self.open_or_get_client(did)?;
        client
            .get_circle_owner_state(circle_id)
            .map_err(|e| e.to_string())
    }

    pub fn put_circle_owner_state(
        &self,
        did: &str,
        state_dto: CircleOwnerStateDto,
        swap_record_cid: Option<String>,
    ) -> Result<String, String> {
        let client = self.open_or_get_client(did)?;
        client
            .put_circle_owner_state(state_dto, swap_record_cid)
            .map_err(|e| e.to_string())
    }

    pub fn merge_circle_owner_state(
        &self,
        did: &str,
        update: CircleOwnerStateDto,
    ) -> Result<CircleOwnerStateDto, String> {
        let client = self.open_or_get_client(did)?;
        client
            .merge_circle_owner_state(update)
            .map_err(|e| e.to_string())
    }

    pub fn clear_circle_acl_tombstone(
        &self,
        did: &str,
        circle_id: &str,
        member_did: &str,
    ) -> Result<Option<CircleOwnerStateDto>, String> {
        let client = self.open_or_get_client(did)?;
        client
            .clear_circle_acl_tombstone(circle_id, member_did)
            .map_err(|e| e.to_string())
    }

    pub fn list_circle_owner_states(&self, did: &str) -> Result<Vec<CircleOwnerStateDto>, String> {
        let client = self.open_or_get_client(did)?;
        client.list_circle_owner_states().map_err(|e| e.to_string())
    }

    pub fn replenish_key_packages(&self, did: &str, count: u32) -> Result<u32, String> {
        let client = self.open_or_get_client(did)?;
        client
            .replenish_key_packages(count)
            .map_err(|e| e.to_string())
    }

    pub fn flush_labyrinth_queue(&self, did: &str) -> Result<u32, String> {
        let client = self.open_or_get_client(did)?;
        client.flush_labyrinth_queue().map_err(|e| e.to_string())
    }

    #[allow(clippy::type_complexity)]
    pub fn list_conversations_detailed(
        &self,
        did: &str,
        limit: u32,
    ) -> Result<
        Vec<(
            catbird_mls::storage::ConversationRow,
            Vec<String>,
            Option<catbird_mls::storage::GroupMetadataRow>,
            Option<catbird_mls::storage::MessageRow>,
        )>,
        String,
    > {
        let client = self.open_or_get_client(did)?;
        let rows = client
            .list_conversations(None, limit)
            .map_err(|e| e.to_string())?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let mut members = client
                .list_members(&row.conversation_id)
                .unwrap_or_default();
            let meta = client
                .get_group_metadata(&row.conversation_id)
                .ok()
                .flatten();
            let recent_msgs = client
                .list_messages(
                    &row.conversation_id,
                    None,
                    if members.is_empty() { 50 } else { 1 },
                )
                .unwrap_or_default();
            if members.is_empty() && !recent_msgs.is_empty() {
                let mut seen = BTreeSet::new();
                for msg in &recent_msgs {
                    let sender = msg.sender_did.trim();
                    if !sender.is_empty() && seen.insert(sender.to_owned()) {
                        members.push(sender.to_owned());
                    }
                }
                let self_did = normalize_account_did(did).unwrap_or_else(|_| did.to_owned());
                if !self_did.is_empty() && seen.insert(self_did.clone()) {
                    members.push(self_did);
                }
            }
            let last_msg = recent_msgs.into_iter().last();
            out.push((row, members, meta, last_msg));
        }
        Ok(out)
    }

    pub fn create_group_detailed(
        &self,
        did: &str,
        name: String,
        member_dids: Vec<String>,
        description: Option<String>,
    ) -> Result<
        (
            catbird_mls::storage::ConversationRow,
            Vec<String>,
            Option<catbird_mls::storage::GroupMetadataRow>,
        ),
        String,
    > {
        let client = self.open_or_get_client(did)?;
        let conversation_id = uuid::Uuid::new_v4().hyphenated().to_string();
        let sequencer_did = Self::home_ds_did();
        let title_opt = if name.trim().is_empty() {
            None
        } else {
            Some(name)
        };
        let row = client
            .create_group(
                &conversation_id,
                &sequencer_did,
                member_dids,
                title_opt,
                description,
            )
            .map_err(|e| e.to_string())?;
        let members = client
            .list_members(&row.conversation_id)
            .unwrap_or_default();
        let meta = client
            .get_group_metadata(&row.conversation_id)
            .ok()
            .flatten();
        Ok((row, members, meta))
    }

    pub fn send_message(
        &self,
        did: &str,
        conversation_id: &str,
        content: &str,
    ) -> Result<catbird_mls::storage::MessageRow, String> {
        let client = self.open_or_get_client(did)?;
        let message_id = uuid::Uuid::new_v4().hyphenated().to_string();
        let row = client
            .send_message(conversation_id, &message_id, content)
            .map_err(|e| e.to_string())?;
        let _ = client.flush_labyrinth_queue();
        Ok(row)
    }

    pub fn list_messages(
        &self,
        did: &str,
        conversation_id: &str,
        before_seq: Option<i64>,
        limit: u32,
    ) -> Result<Vec<catbird_mls::storage::MessageRow>, String> {
        let client = self.open_or_get_client(did)?;
        client
            .list_messages(conversation_id, before_seq, limit)
            .map_err(|e| e.to_string())
    }

    pub fn list_members(&self, did: &str, conversation_id: &str) -> Result<Vec<String>, String> {
        let client = self.open_or_get_client(did)?;
        client
            .list_members(conversation_id)
            .map_err(|e| e.to_string())
    }

    pub fn add_group_members(
        &self,
        did: &str,
        conversation_id: &str,
        member_dids: Vec<String>,
    ) -> Result<catbird_mls::storage::ConversationRow, String> {
        let client = self.open_or_get_client(did)?;
        client
            .add_group_members(conversation_id, member_dids)
            .map_err(|e| e.to_string())
    }

    pub fn remove_group_member(
        &self,
        did: &str,
        conversation_id: &str,
        target_did: &str,
    ) -> Result<(), String> {
        let client = self.open_or_get_client(did)?;
        client
            .remove_group_member(
                catbird_mls::groups::lifecycle::MemberRole::Admin,
                conversation_id,
                target_did,
            )
            .map_err(|e| e.to_string())
    }

    pub fn get_group_metadata(
        &self,
        did: &str,
        conversation_id: &str,
    ) -> Result<Option<catbird_mls::storage::GroupMetadataRow>, String> {
        let client = self.open_or_get_client(did)?;
        client
            .get_group_metadata(conversation_id)
            .map_err(|e| e.to_string())
    }

    pub fn update_group_metadata(
        &self,
        did: &str,
        conversation_id: &str,
        title: String,
        description: String,
    ) -> Result<catbird_mls::storage::GroupMetadataRow, String> {
        let client = self.open_or_get_client(did)?;
        client
            .update_group_metadata(conversation_id, title, description, None)
            .map_err(|e| e.to_string())
    }

    pub fn list_requests(
        &self,
        did: &str,
        consent_filter: Option<&str>,
    ) -> Result<Vec<catbird_mls::storage::RequestRow>, String> {
        let client = self.open_or_get_client(did)?;
        client
            .list_requests(consent_filter)
            .map_err(|e| e.to_string())
    }

    pub fn accept_direct_request(&self, did: &str, request_id: &str) -> Result<(), String> {
        let client = self.open_or_get_client(did)?;
        client
            .accept_direct_request(request_id)
            .map_err(|e| e.to_string())
    }

    pub fn decline_direct_request(&self, did: &str, request_id: &str) -> Result<(), String> {
        let client = self.open_or_get_client(did)?;
        client
            .decline_direct_request(request_id)
            .map_err(|e| e.to_string())
    }

    pub fn acknowledge_entries_up_to(
        &self,
        did: &str,
        conversation_id: &str,
        up_to_seq: i64,
    ) -> Result<(), String> {
        let client = self.open_or_get_client(did)?;
        client
            .acknowledge_entries_up_to(conversation_id, up_to_seq)
            .map_err(|e| e.to_string())
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native_archive_auth;
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicBool, Ordering};

    const LIVE_PDS_URL: &str = "https://pds.catmos.test";
    const LIVE_DS_URL: &str = "https://ds.catmos.test";
    const LIVE_DS_DID: &str = "did:web:ds.catmos.test";

    #[test]
    fn backup_rpc_uses_a_service_token_even_when_the_origins_match() {
        use std::io::{BufRead, BufReader, Write};
        use std::net::TcpListener;

        let method = "blue.catbird.labyrinth.getRecoveryShareCapabilities";
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let mock = std::thread::spawn(move || {
            let mut observed = Vec::new();
            // Close each connection after its response. A regression that skips the token
            // request still finishes the fixture when the capability request arrives.
            loop {
                let (mut socket, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(&socket);
                let mut start = String::new();
                reader.read_line(&mut start).unwrap();
                let mut authorization = String::new();
                for line in reader.lines() {
                    let line = line.unwrap();
                    if line.is_empty() {
                        break;
                    }
                    if let Some((key, value)) = line.split_once(':') {
                        if key.eq_ignore_ascii_case("authorization") {
                            authorization = value.trim().to_owned();
                        }
                    }
                }
                let minting = start.contains("/xrpc/com.atproto.server.getServiceAuth?");
                let body = if minting {
                    r#"{"token":"fixture-service-token"}"#
                } else {
                    "{}"
                };
                write!(socket, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).unwrap();
                observed.push((start, authorization));
                if !minting || observed.len() == 2 {
                    return observed;
                }
            }
        });

        let transport = TauriTransport::new(None);
        transport.configure_endpoints(&endpoint, &endpoint, LIVE_DS_DID);
        transport.set_session_token(Some("fixture-account-token".into()));
        let response = transport
            .execute_http(PlatformHttpRequest {
                method: "GET".into(),
                url: format!("{endpoint}/xrpc/{method}"),
                headers: vec![],
                body: None,
            })
            .unwrap();
        assert_eq!(response.status, 200);
        let observed = mock.join().unwrap();
        assert_eq!(observed.len(), 2);
        assert!(observed[0].0.contains("aud=did%3Aweb%3Ads.catmos.test"));
        assert!(observed[0].0.contains(&format!("lxm={method}")));
        assert_eq!(observed[0].1, "Bearer fixture-account-token");
        assert!(observed[1].0.starts_with(&format!("GET /xrpc/{method} ")));
        assert_eq!(observed[1].1, "Bearer fixture-service-token");
    }

    #[test]
    fn personal_space_read_rewrites_gateway_origin_to_direct_pds_and_preserves_headers() {
        use std::io::{BufRead, BufReader, Write};
        use std::net::TcpListener;

        let account_did = "did:plc:directspaceread123";
        let direct_pds = TcpListener::bind("127.0.0.1:0").unwrap();
        let direct_pds_url = format!("http://{}", direct_pds.local_addr().unwrap());

        let mock_pds = std::thread::spawn(move || {
            let (mut socket, _) = direct_pds.accept().unwrap();
            let mut reader = BufReader::new(&socket);
            let mut start = String::new();
            reader.read_line(&mut start).unwrap();
            let mut seen = HashMap::new();
            for line in reader.lines() {
                let line = line.unwrap();
                if line.is_empty() {
                    break;
                }
                if let Some((k, v)) = line.split_once(':') {
                    seen.insert(k.trim().to_ascii_lowercase(), v.trim().to_owned());
                }
            }
            let body = r#"{"value":{"$type":"blue.catbird.labyrinth.epoch"}}"#;
            write!(
                socket,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
            (start, seen)
        });

        let transport = TauriTransport::new(None);
        transport.configure_endpoints(
            "https://api.catbird.blue",
            "https://chat.catbird.blue",
            "did:web:chat.catbird.blue",
        );
        transport.set_account_did(Some(account_did.into()));
        transport.set_resolved_pds_for_testing(account_did, &direct_pds_url);

        let query = "space=at%3A%2F%2Fdid%3Aplc%3Adirectspaceread123%2Fspace%2Fblue.catbird.labyrinth.mailbox%2Fself&repo=did%3Aplc%3Adirectspaceread123&collection=blue.catbird.labyrinth.epoch&rkey=000000000000";
        let response = transport
            .execute_http(PlatformHttpRequest {
                method: "GET".into(),
                url: format!("https://api.catbird.blue/xrpc/com.atproto.space.getRecord?{query}"),
                headers: vec![
                    PlatformHttpHeader {
                        name: "Authorization".into(),
                        value: "Atproto-Space-Credential cred.jwt.sig".into(),
                    },
                    PlatformHttpHeader {
                        name: "Atproto-Space-Audience".into(),
                        value: account_did.into(),
                    },
                    PlatformHttpHeader {
                        name: "Signature-Input".into(),
                        value: "sig1=(\"@method\" \"@target-uri\");created=1700000000".into(),
                    },
                    PlatformHttpHeader {
                        name: "Signature".into(),
                        value: "sig1=:dGVzdA==:".into(),
                    },
                    PlatformHttpHeader {
                        name: "Accept-Signature".into(),
                        value: "sig1=(\"atproto-space-record\")".into(),
                    },
                ],
                body: None,
            })
            .unwrap();
        assert_eq!(response.status, 200);
        let (start, headers) = mock_pds.join().unwrap();
        assert!(start.starts_with(&format!("GET /xrpc/com.atproto.space.getRecord?{query} ")));
        assert_eq!(
            headers.get("authorization").map(String::as_str),
            Some("Atproto-Space-Credential cred.jwt.sig")
        );
        assert_eq!(
            headers.get("atproto-space-audience").map(String::as_str),
            Some(account_did)
        );
        assert_eq!(
            headers.get("signature").map(String::as_str),
            Some("sig1=:dGVzdA==:")
        );
        assert!(headers.contains_key("signature-input"));
        assert!(headers.contains_key("accept-signature"));
    }

    #[test]
    fn personal_space_read_rejects_mismatched_audience() {
        let req = PlatformHttpRequest {
            method: "GET".into(),
            url: "https://api.catbird.blue/xrpc/com.atproto.space.getRecord?space=at%3A%2F%2Fdid%3Aplc%3Aalice%2Fspace%2Fblue.catbird.labyrinth.mailbox%2Fself".into(),
            headers: vec![
                PlatformHttpHeader {
                    name: "Authorization".into(),
                    value: "Atproto-Space-Credential cred.jwt.sig".into(),
                },
                PlatformHttpHeader {
                    name: "Atproto-Space-Audience".into(),
                    value: "did:plc:bob".into(),
                },
            ],
            body: None,
        };
        let err = personal_space_read_url(
            &req,
            "did:plc:alice",
            "https://api.catbird.blue",
            "https://swan.place",
        )
        .unwrap_err();
        assert!(err.to_string().contains("signed-in account"));
    }

    #[derive(Default)]
    struct LiveMockState {
        repo: BTreeMap<(String, String, String), serde_json::Value>,
        heads: HashMap<String, Vec<serde_json::Value>>,
        chat_keys: HashMap<String, Vec<serde_json::Value>>,
    }

    struct FaultableLiveTransport {
        did: String,
        archive_auth: Arc<native_archive_auth::NativeArchiveAuthFixture>,
        state: Mutex<LiveMockState>,
        delete_fault: AtomicBool,
    }

    impl FaultableLiveTransport {
        fn new(did: &str) -> Arc<Self> {
            Arc::new(Self {
                did: did.to_string(),
                archive_auth: Arc::new(native_archive_auth::NativeArchiveAuthFixture::new(
                    did,
                    Arc::new(|| chrono::Utc::now().timestamp_millis()),
                )),
                state: Mutex::new(LiveMockState::default()),
                delete_fault: AtomicBool::new(false),
            })
        }

        fn set_delete_fault(&self, fault: bool) {
            self.delete_fault.store(fault, Ordering::SeqCst);
        }

        fn ok_json(val: serde_json::Value) -> Result<PlatformHttpResponse, MLSError> {
            Ok(PlatformHttpResponse {
                status: 200,
                headers: Vec::new(),
                body: serde_json::to_vec(&val).unwrap(),
            })
        }

        fn err_json(status: u16, code: &str) -> Result<PlatformHttpResponse, MLSError> {
            Ok(PlatformHttpResponse {
                status,
                headers: Vec::new(),
                body: serde_json::to_vec(&serde_json::json!({ "error": code, "message": code }))
                    .unwrap(),
            })
        }
    }

    impl PlatformTransport for FaultableLiveTransport {
        fn execute_http(
            &self,
            request: PlatformHttpRequest,
        ) -> Result<PlatformHttpResponse, MLSError> {
            if let Some(did) = request.url.strip_prefix("https://plc.directory/") {
                return Self::ok_json(self.archive_auth.did_document(did, LIVE_PDS_URL)?);
            }
            self.archive_auth.execute_for(&self.did, &request, |req| {
                let (path, query_opt) = match req.url.split_once('?') {
                    Some((p, q)) => (p, Some(q)),
                    None => (req.url.as_str(), None),
                };
                let Some((_, nsid)) = path.rsplit_once("/xrpc/") else {
                    return Self::err_json(404, "NotFound");
                };
                let mut q = HashMap::new();
                if let Some(qs) = query_opt {
                    for pair in qs.split('&').filter(|s| !s.is_empty()) {
                        if let Some((k, v)) = pair.split_once('=') {
                            q.insert(percent_decode_query_param(k), percent_decode_query_param(v));
                        }
                    }
                }
                let body: serde_json::Value = req
                    .body
                    .as_deref()
                    .and_then(|b| serde_json::from_slice(b).ok())
                    .unwrap_or(serde_json::Value::Null);
                let mut st = self.state.lock().unwrap();
                match nsid {
                    "com.atproto.repo.createRecord" | "com.atproto.repo.putRecord" => {
                        let repo = body["repo"].as_str().unwrap_or_default().to_string();
                        let col = body["collection"].as_str().unwrap_or_default().to_string();
                        let rkey = body["rkey"].as_str().unwrap_or_default().to_string();
                        if nsid == "com.atproto.repo.createRecord"
                            && st
                                .repo
                                .contains_key(&(repo.clone(), col.clone(), rkey.clone()))
                        {
                            return Self::err_json(400, "RecordAlreadyExists");
                        }
                        let uri = format!("at://{repo}/{col}/{rkey}");
                        st.repo.insert((repo, col, rkey), body["record"].clone());
                        Self::ok_json(serde_json::json!({ "uri": uri, "cid": "bafyreilivetest" }))
                    }
                    "com.atproto.repo.getRecord" => {
                        let repo = q.get("repo").cloned().unwrap_or_default();
                        let col = q.get("collection").cloned().unwrap_or_default();
                        let rkey = q.get("rkey").cloned().unwrap_or_default();
                        match st.repo.get(&(repo.clone(), col.clone(), rkey.clone())) {
                            Some(val) => Self::ok_json(serde_json::json!({
                                "uri": format!("at://{repo}/{col}/{rkey}"),
                                "cid": "bafyreilivetest",
                                "value": val,
                            })),
                            None => Self::err_json(400, "RecordNotFound"),
                        }
                    }
                    "com.atproto.repo.listRecords" => {
                        let repo = q.get("repo").cloned().unwrap_or_default();
                        let col = q.get("collection").cloned().unwrap_or_default();
                        let records: Vec<serde_json::Value> = st
                            .repo
                            .iter()
                            .filter(|((r, c, _), _)| *r == repo && *c == col)
                            .map(|((r, c, k), v)| {
                                serde_json::json!({
                                    "uri": format!("at://{r}/{c}/{k}"),
                                    "cid": "bafyreilivetest",
                                    "value": v,
                                })
                            })
                            .collect();
                        Self::ok_json(serde_json::json!({ "records": records }))
                    }
                    "com.atproto.repo.deleteRecord" => {
                        if self.delete_fault.load(Ordering::SeqCst) {
                            return Self::err_json(500, "InternalServerError");
                        }
                        let repo = body["repo"].as_str().unwrap_or_default().to_string();
                        let col = body["collection"].as_str().unwrap_or_default().to_string();
                        let rkey = body["rkey"].as_str().unwrap_or_default().to_string();
                        st.repo.remove(&(repo, col, rkey));
                        Self::ok_json(serde_json::json!({}))
                    }
                    "blue.catbird.chat.enrollDevice" => {
                        let b = &body["signedRequest"]["body"];
                        let dev = b["deviceId"].as_str().unwrap_or_default().to_string();
                        let pk_raw =
                            catbird_mls::client::chat_wire::json_bytes(&b["signaturePublicKey"])?;
                        let key_id = catbird_mls::canonical_transport::derive_key_id(&pk_raw);
                        let pk = if b["signaturePublicKey"].is_string() {
                            serde_json::json!({ "$bytes": b["signaturePublicKey"] })
                        } else {
                            b["signaturePublicKey"].clone()
                        };
                        let keys = st.chat_keys.entry(self.did.clone()).or_default();
                        if !keys.contains(&pk) {
                            keys.push(pk.clone());
                        }
                        Self::ok_json(serde_json::json!({
                            "device": {
                                "deviceId": dev,
                                "keyId": key_id,
                                "signaturePublicKey": pk,
                                "authGeneration": 1,
                                "status": "active",
                                "createdAt": "2026-11-14T00:00:00.000Z",
                                "updatedAt": "2026-11-14T00:00:00.000Z",
                                "availablePackageCount": 2,
                                "reservedPackageCount": 0,
                            }
                        }))
                    }
                    "blue.catbird.chat.publishDirectRequestKeys" => {
                        Self::ok_json(serde_json::json!({ "published": true }))
                    }
                    "blue.catbird.chat.replenishKeyPackages" => {
                        Self::ok_json(serde_json::json!({ "acceptedCount": 4 }))
                    }
                    "blue.catbird.labyrinth.publishEpochHead" => {
                        let epoch = body["epoch"].clone();
                        let n = epoch["epochNumber"].as_u64();
                        let list = st.heads.entry(self.did.clone()).or_default();
                        list.retain(|e| e["epochNumber"].as_u64() != n);
                        list.push(epoch);
                        list.sort_by_key(|e| e["epochNumber"].as_u64());
                        Self::ok_json(serde_json::json!({}))
                    }
                    "blue.catbird.labyrinth.getEpochHead" => {
                        let did = q.get("did").cloned().unwrap_or_default();
                        let seq = q.get("epochNumber").and_then(|s| s.parse::<u64>().ok());
                        let list = st.heads.get(&did).cloned().unwrap_or_default();
                        let found = match seq {
                            Some(n) => list
                                .iter()
                                .find(|e| e["epochNumber"].as_u64() == Some(n))
                                .cloned(),
                            None => list.last().cloned(),
                        };
                        match found {
                            Some(epoch) => {
                                let upto = epoch["epochNumber"].as_u64();
                                let chain: Vec<serde_json::Value> = list
                                    .iter()
                                    .filter(|e| e["epochNumber"].as_u64() <= upto)
                                    .cloned()
                                    .collect();
                                let floor = chain
                                    .first()
                                    .and_then(|e| e["epochNumber"].as_u64())
                                    .unwrap_or(0);
                                Self::ok_json(serde_json::json!({
                                    "epoch": epoch,
                                    "chain": chain,
                                    "floorSeq": floor,
                                    "receivedAt": "2026-11-14T00:00:00Z",
                                }))
                            }
                            None => Self::err_json(404, "EpochNotFound"),
                        }
                    }
                    "blue.catbird.labyrinth.deleteAccountData" => {
                        if self.delete_fault.load(Ordering::SeqCst) {
                            return Self::err_json(500, "InternalServerError");
                        }
                        st.heads.remove(&self.did);
                        st.chat_keys.remove(&self.did);
                        Self::ok_json(serde_json::json!({}))
                    }
                    "blue.catbird.labyrinth.getChatDeviceKeys"
                    | "blue.catbird.labyrinth.getMemberDevices" => {
                        let did = q.get("did").cloned().unwrap_or_default();
                        let items: Vec<serde_json::Value> = st
                            .chat_keys
                            .get(&did)
                            .cloned()
                            .unwrap_or_default()
                            .into_iter()
                            .map(|k| serde_json::json!({ "signingPublicKey": k, "joinedSeq": 0 }))
                            .collect();
                        Self::ok_json(serde_json::json!({ "items": items }))
                    }
                    other => Self::err_json(501, other),
                }
            })
        }

        fn connect_realtime_stream(&self, _: String, _: Option<i64>) -> Result<(), MLSError> {
            Ok(())
        }

        fn disconnect_realtime_stream(&self) -> Result<(), MLSError> {
            Ok(())
        }
    }

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
        let did_hash = account_did_hash_hex(did).expect("did hash");

        // Seed a legacy non-UUIDv4 `.device` file and verify migration to canonical lowercase UUIDv4.
        let opt_dir = tmp.path().join("mls-opt-in");
        std::fs::create_dir_all(&opt_dir).expect("mkdir mls-opt-in");
        std::fs::write(
            opt_dir.join(format!("{did_hash}.device")),
            b"catmos-desktop-legacy",
        )
        .expect("seed legacy device file");

        let status = mgr
            .enable_and_enroll(did, Some(true), None)
            .expect("enroll should succeed when Spaces + scopes are available");
        assert!(mgr.is_opted_in(did));
        assert!(status.backup_enabled);
        assert_eq!(status.epoch_seq, 1);
        assert_eq!(status.active_device_ids.len(), 1);
        let parsed_uuid = uuid::Uuid::parse_str(&status.active_device_ids[0])
            .expect("enrolled device_id must be valid UUID");
        assert_eq!(parsed_uuid.get_version_num(), 4);
        assert_eq!(
            status.active_device_ids[0],
            parsed_uuid.hyphenated().to_string()
        );

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

    #[test]
    fn delete_account_data_fails_closed_when_remote_delete_errors_d3() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let did = "did:plc:catmosdfailclosedaaaaaaa";
        let did_hash = account_did_hash_hex(did).expect("did hash");
        let live_tx = FaultableLiveTransport::new(did);
        let mgr = TauriMlsManager::new_with_live_transport_for_testing(
            tmp.path().to_path_buf(),
            Arc::clone(&live_tx) as Arc<dyn PlatformTransport>,
            LIVE_PDS_URL,
            LIVE_DS_URL,
            LIVE_DS_DID,
        );

        mgr.enable_and_enroll(did, None, None)
            .expect("enroll should succeed");
        assert!(mgr.is_opted_in(did));
        let db_path = tmp
            .path()
            .join("catbird-mls")
            .join(format!("{did_hash}.db"));
        assert!(db_path.exists());

        live_tx.set_delete_fault(true);
        let err = mgr
            .delete_account_data(did)
            .expect_err("D-3: remote delete failure must fail closed");
        assert!(!err.is_empty());
        assert!(
            mgr.is_opted_in(did),
            "D-3: opt-in marker must remain intact when remote delete fails"
        );
        assert!(
            db_path.exists(),
            "D-3: encrypted SQLite DB must remain intact when remote delete fails"
        );

        live_tx.set_delete_fault(false);
        mgr.delete_account_data(did)
            .expect("delete_account_data succeeds once remote delete succeeds");
        assert!(!mgr.is_opted_in(did));
        assert!(!db_path.exists());
    }

    #[test]
    fn read_state_and_circle_owner_state_roundtrip_via_space() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let did = "did:plc:catmosreadcircleaaaaaaaa";
        let live_tx = FaultableLiveTransport::new(did);
        let mgr = TauriMlsManager::new_with_live_transport_for_testing(
            tmp.path().to_path_buf(),
            Arc::clone(&live_tx) as Arc<dyn PlatformTransport>,
            LIVE_PDS_URL,
            LIVE_DS_URL,
            LIVE_DS_DID,
        );

        mgr.enable_and_enroll(did, None, None)
            .expect("enroll should succeed");

        let convo_id = "01900000-0000-7000-8000-0000000000aa";
        assert!(mgr
            .get_read_state(did, convo_id)
            .expect("initial get")
            .is_none());

        let r5 = mgr
            .advance_read_state(did, convo_id, 5)
            .expect("advance to 5");
        assert_eq!(r5.read_through_seq, 5);

        let r3 = mgr
            .advance_read_state(did, convo_id, 3)
            .expect("monotonic advance with smaller seq");
        assert_eq!(r3.read_through_seq, 5);

        let listed_reads = mgr.list_read_states(did).expect("list read states");
        assert_eq!(listed_reads.len(), 1);
        assert_eq!(listed_reads[0].conversation_id, convo_id);
        assert_eq!(listed_reads[0].read_through_seq, 5);

        let circle_id = "01982b6e-a100-7000-8000-000000000001";
        let removed_did = "did:plc:removedaaaaaaaaaaaaaaaaa";
        let initial_circle = CircleOwnerStateDto {
            circle_id: circle_id.to_string(),
            space_uri: format!("at:space://{did}/{circle_id}"),
            current_key_version: 1,
            joined_at_version_json: serde_json::json!({
                "did:plc:aliceaaaaaaaaaaaaaaaaaaa": 1
            })
            .to_string(),
            pending_ops_json: serde_json::json!({
                format!("__acl__:{removed_did}"): "aclRemovePending:rotated"
            })
            .to_string(),
            updated_at: "2026-11-14T12:00:00Z".to_string(),
            record_cid: None,
        };
        let cid1 = mgr
            .put_circle_owner_state(did, initial_circle.clone(), None)
            .expect("put circle owner state");
        assert!(!cid1.is_empty());

        let fetched = mgr
            .get_circle_owner_state(did, circle_id)
            .expect("get circle owner state")
            .expect("circle owner state present");
        assert_eq!(fetched.current_key_version, 1);

        let merged = mgr
            .merge_circle_owner_state(
                did,
                CircleOwnerStateDto {
                    current_key_version: 2,
                    ..fetched
                },
            )
            .expect("merge circle owner state");
        assert_eq!(merged.current_key_version, 2);
        assert!(merged.pending_ops_json.contains("__acl__:"));

        let cleared = mgr
            .clear_circle_acl_tombstone(did, circle_id, removed_did)
            .expect("clear ACL tombstone")
            .expect("circle state after clear");
        assert!(!cleared.pending_ops_json.contains("__acl__:"));

        let listed_circles = mgr
            .list_circle_owner_states(did)
            .expect("list circle owner states");
        assert_eq!(listed_circles.len(), 1);
        assert_eq!(listed_circles[0].circle_id, circle_id);
    }

    #[test]
    fn tauri_keystore_fails_closed_when_os_keyring_unavailable() {
        let store = TauriKeyStore::new_simulated_unavailable("Secret Service locked");
        let err = store
            .load_or_create_db_key("a".repeat(64))
            .expect_err("locked OS keyring must fail closed without RAM fallback");
        assert!(err.to_string().contains("refusing ephemeral fallback"));
        assert!(store
            .store_signature_keypair("key-1".to_string(), vec![1u8; 32])
            .is_err());
        assert!(store.load_signature_keypair("key-1".to_string()).is_err());
        assert!(store.delete_account_keys("a".repeat(64)).is_err());
    }

    #[test]
    fn archive_candidate_discovery_merges_and_deduplicates_all_sources() {
        let ids = collect_archive_candidate_conversation_ids(
            vec!["convo-local".to_string(), "convo-shared".to_string()],
            vec![
                "conversation_kind:convo-ds-only".to_string(),
                "conversation_kind:convo-shared".to_string(),
                "unrelated_meta:ignored".to_string(),
            ],
            vec![
                "convo-readstate".to_string(),
                "convo-ds-only".to_string(),
                "  ".to_string(),
            ],
        );
        assert_eq!(
            ids,
            vec![
                "convo-ds-only".to_string(),
                "convo-local".to_string(),
                "convo-readstate".to_string(),
                "convo-shared".to_string(),
            ]
        );
    }

    #[test]
    fn tauri_transport_reuses_pooled_keepalive_connections_across_sequential_calls() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        let accepted = Arc::new(AtomicUsize::new(0));
        let accepted_server = Arc::clone(&accepted);

        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept client");
            accepted_server.fetch_add(1, Ordering::SeqCst);
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .expect("set timeout");
            for i in 0..4usize {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 1024];
                loop {
                    let n = stream.read(&mut tmp).expect("read request");
                    assert!(n > 0, "unexpected EOF before request {i}");
                    buf.extend_from_slice(&tmp[..n]);
                    if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                let body = format!("{{\"seq\":{i}}}");
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream.write_all(resp.as_bytes()).expect("write response");
                stream.flush().expect("flush");
            }
        });

        let transport = TauriTransport::new(None);
        // First 2 requests from a plain thread, next 2 from inside an active Tokio runtime.
        for i in 0..2usize {
            let resp = transport
                .execute_http(PlatformHttpRequest {
                    method: "GET".to_string(),
                    url: format!("http://{addr}/ping/{i}"),
                    headers: vec![],
                    body: None,
                })
                .expect("sequential pooled HTTP request must succeed");
            assert_eq!(resp.status, 200);
            assert_eq!(
                String::from_utf8(resp.body).unwrap(),
                format!("{{\"seq\":{i}}}")
            );
        }

        let caller_rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("caller rt");
        caller_rt.block_on(async {
            for i in 2..4usize {
                let resp = transport
                    .execute_http(PlatformHttpRequest {
                        method: "GET".to_string(),
                        url: format!("http://{addr}/ping/{i}"),
                        headers: vec![],
                        body: None,
                    })
                    .expect("nested-runtime pooled HTTP request must succeed");
                assert_eq!(resp.status, 200);
                assert_eq!(
                    String::from_utf8(resp.body).unwrap(),
                    format!("{{\"seq\":{i}}}")
                );
            }
        });

        server.join().expect("server thread");
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            1,
            "all 4 requests should reuse the single keep-alive pooled connection"
        );
    }

    #[test]
    fn home_ds_resolve_did_fallback_only_matches_configured_home_ds_and_preserves_d1() {
        let own_ds_req = PlatformHttpRequest {
            method: "GET".to_string(),
            url: "https://api.catbird.blue/xrpc/com.atproto.identity.resolveDid?did=did%3Aweb%3Achat.catbird.blue".to_string(),
            headers: vec![],
            body: None,
        };
        assert_eq!(
            home_ds_resolve_did_fallback_url(
                &own_ds_req,
                "https://api.catbird.blue",
                "https://chat.catbird.blue",
                "did:web:chat.catbird.blue",
            ),
            Some("https://chat.catbird.blue/.well-known/did.json".to_string())
        );

        // Foreign did:web:* must NEVER fall back directly (preserves D1).
        let foreign_ds_req = PlatformHttpRequest {
            method: "GET".to_string(),
            url: "https://api.catbird.blue/xrpc/com.atproto.identity.resolveDid?did=did%3Aweb%3Aforeign.example.com".to_string(),
            headers: vec![],
            body: None,
        };
        assert_eq!(
            home_ds_resolve_did_fallback_url(
                &foreign_ds_req,
                "https://api.catbird.blue",
                "https://chat.catbird.blue",
                "did:web:chat.catbird.blue",
            ),
            None
        );

        // Non-resolveDid XRPCs and non-GET requests never match.
        let other_req = PlatformHttpRequest {
            method: "GET".to_string(),
            url: "https://api.catbird.blue/xrpc/com.atproto.space.getSpace?did=did%3Aweb%3Achat.catbird.blue".to_string(),
            headers: vec![],
            body: None,
        };
        assert_eq!(
            home_ds_resolve_did_fallback_url(
                &other_req,
                "https://api.catbird.blue",
                "https://chat.catbird.blue",
                "did:web:chat.catbird.blue",
            ),
            None
        );
    }
}

/// Split a Space attachment locator into `(spaceURI, repoDID, cid)`.
///
/// Accepts both shapes Catbird iOS reads (`MLSSpaceBlobLocator.parse`):
/// `"{spaceURI}|{repoDID}|{cid}"` and `"{spaceURI}/{repoDID}#{cid}"`.
pub(crate) fn split_attachment_locator(locator: &str) -> Option<(&str, &str, &str)> {
    let trimmed = locator.trim();
    if trimmed.contains('|') {
        let mut parts = trimmed.splitn(3, '|');
        let (space, repo, cid) = (parts.next()?, parts.next()?, parts.next()?);
        return (!space.trim().is_empty() && !repo.trim().is_empty() && !cid.trim().is_empty())
            .then_some((space, repo, cid));
    }
    let (before_hash, cid) = trimmed.split_once('#')?;
    let (space, repo) = before_hash.rsplit_once('/')?;
    (!space.is_empty() && !repo.is_empty() && !cid.is_empty()).then_some((space, repo, cid))
}

#[cfg(test)]
mod attachment_locator_tests {
    use super::split_attachment_locator;

    const SPACE: &str =
        "at://did:web:chat.catbird.blue/space/blue.catbird.labyrinth.conversation/abc";

    #[test]
    fn splits_pipe_locator() {
        let raw = format!("{SPACE}|did:plc:writer|bafkreicid");
        assert_eq!(
            split_attachment_locator(&raw),
            Some((SPACE, "did:plc:writer", "bafkreicid"))
        );
    }

    #[test]
    fn splits_hash_locator() {
        let raw = format!("{SPACE}/did:plc:writer#bafkreicid");
        assert_eq!(
            split_attachment_locator(&raw),
            Some((SPACE, "did:plc:writer", "bafkreicid"))
        );
    }

    #[test]
    fn rejects_bare_cid_and_empty_parts() {
        assert_eq!(split_attachment_locator("bafkreicid"), None);
        assert_eq!(split_attachment_locator("||"), None);
        assert_eq!(
            split_attachment_locator(&format!("{SPACE}/did:plc:writer#")),
            None
        );
    }
}

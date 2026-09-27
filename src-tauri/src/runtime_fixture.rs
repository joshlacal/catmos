//! Opt-in debug gateway support. No production trust/profile configuration changes.
#[cfg(all(feature = "local-runtime-fixture", not(debug_assertions)))]
compile_error!("local-runtime-fixture is forbidden in release builds");

pub(crate) fn keychain_service(production: &str) -> String {
    #[cfg(feature = "local-runtime-fixture")]
    if let Some(config) = enabled::CONFIG.get() {
        return format!("{}.{}", config.keychain_namespace, production);
    }
    if cfg!(test) {
        return format!("{production}.unit-fixture");
    }
    production.to_owned()
}
pub(crate) fn keychain_get(service: &str, key: &str) -> Result<String, keyring::Error> {
    #[cfg(feature = "local-runtime-fixture")]
    if let Some(config) = enabled::CONFIG.get() {
        return config.keychain_get(service, key);
    }
    keyring::Entry::new(service, key)?.get_password()
}

pub(crate) fn keychain_set(service: &str, key: &str, value: &str) -> Result<(), keyring::Error> {
    #[cfg(feature = "local-runtime-fixture")]
    if let Some(config) = enabled::CONFIG.get() {
        return config.keychain_set(service, key, value);
    }
    keyring::Entry::new(service, key)?.set_password(value)
}

pub(crate) fn keychain_delete(service: &str, key: &str) -> Result<(), keyring::Error> {
    #[cfg(feature = "local-runtime-fixture")]
    if let Some(config) = enabled::CONFIG.get() {
        return config.keychain_delete(service, key);
    }
    match keyring::Entry::new(service, key)?.delete_credential() {
        Ok(_) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(e),
    }
}

pub(crate) fn data_dir() -> Option<std::path::PathBuf> {
    #[cfg(feature = "local-runtime-fixture")]
    if let Some(config) = enabled::CONFIG.get() {
        return Some(config.profile.clone());
    }
    None
}
pub(crate) fn origin() -> Option<String> {
    #[cfg(feature = "local-runtime-fixture")]
    if let Some(config) = enabled::CONFIG.get() {
        return Some(config.manifest.origin.clone());
    }
    None
}
pub(crate) fn appview_url(path: &str) -> String {
    // Only callers with fixed AppView paths use this fixture routing seam.
    format!(
        "{}{}",
        origin().unwrap_or_else(|| "https://public.api.bsky.app".into()),
        path
    )
}
pub(crate) fn http_builder() -> reqwest::ClientBuilder {
    let builder = reqwest::Client::builder();
    #[cfg(feature = "local-runtime-fixture")]
    if let Some(config) = enabled::CONFIG.get() {
        return config.client_builder(builder);
    }
    builder
}
pub(crate) fn http_client() -> reqwest::Client {
    http_builder()
        .build()
        .expect("HTTP client configuration must be valid")
}
pub(crate) async fn connect_websocket(
    url: &str,
) -> Result<
    (
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        tokio_tungstenite::tungstenite::handshake::client::Response,
    ),
    String,
> {
    #[cfg(feature = "local-runtime-fixture")]
    if let Some(config) = enabled::CONFIG.get() {
        return config.connect_websocket(url).await;
    }
    tokio_tungstenite::connect_async(url)
        .await
        .map_err(|e| format!("WebSocket connect failed: {e}"))
}

#[cfg(all(test, not(feature = "local-runtime-fixture")))]
pub(crate) async fn seed_native_authority(
    _context: &catbird_mls::MLSContext,
    _credentials: &crate::credentials::KeyringCredentialStore,
) -> Result<(), String> {
    Ok(())
}
pub(crate) fn initialize() {
    #[cfg(feature = "local-runtime-fixture")]
    enabled::initialize().expect("Invalid isolated runtime fixture configuration");
}

#[cfg(feature = "local-runtime-fixture")]
pub(crate) use enabled::seed_native_authority;

#[derive(Clone, Copy, Debug)]
pub(crate) struct DenyDns;

impl reqwest::dns::Resolve for DenyDns {
    fn resolve(&self, _: reqwest::dns::Name) -> reqwest::dns::Resolving {
        Box::pin(async {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "Host absent from fixture manifest or peer resolution denied",
            )
            .into())
        })
    }
}

pub(crate) fn fixture_host_addr(host: &str) -> Option<std::net::SocketAddr> {
    #[cfg(feature = "local-runtime-fixture")]
    if let Some(config) = enabled::CONFIG.get() {
        return config.manifest.hosts.get(host).copied();
    }
    let _ = host;
    None
}

pub(crate) fn is_fixture_active() -> bool {
    #[cfg(feature = "local-runtime-fixture")]
    {
        enabled::CONFIG.get().is_some()
    }
    #[cfg(not(feature = "local-runtime-fixture"))]
    {
        false
    }
}

#[cfg(feature = "local-runtime-fixture")]
mod enabled {
    use base64::Engine;
    use catbird_mls::orchestrator::credentials::CredentialStore;
    use serde::Deserialize;
    use std::{
        collections::BTreeMap,
        net::SocketAddr,
        path::{Path, PathBuf},
        sync::{Arc, OnceLock},
    };
    pub(super) static CONFIG: OnceLock<Config> = OnceLock::new();
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Launch {
        manifest: PathBuf,
        sessions: PathBuf,
        label: String,
        profile: PathBuf,
        keychain_namespace: String,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub(super) struct Manifest {
        fixture_only: bool,
        pub origin: String,
        ca_pem: PathBuf,
        pub(super) hosts: BTreeMap<String, SocketAddr>,
        accounts: Vec<Account>,
    }
    #[derive(Clone, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Account {
        label: String,
        did: String,
        device_id: String,
        session: Option<String>,
    }
    pub(super) struct Config {
        pub manifest: Manifest,
        pub profile: PathBuf,
        pub keychain_namespace: String,
        account: Account,
        ca: reqwest::Certificate,
        ws_connector: tokio_tungstenite::Connector,
        keychain_file: PathBuf,
        keychain_store: Arc<std::sync::Mutex<std::collections::BTreeMap<String, String>>>,
    }

    fn parse_pem_cert(pem: &[u8]) -> Result<rustls_pki_types::CertificateDer<'static>, String> {
        let s = std::str::from_utf8(pem).map_err(|e| e.to_string())?;
        let start = s.find("-----BEGIN CERTIFICATE-----").ok_or("No cert start")?;
        let end = s.find("-----END CERTIFICATE-----").ok_or("No cert end")?;
        let b64 = &s[start + "-----BEGIN CERTIFICATE-----".len()..end];
        let b64: String = b64.chars().filter(|c| !c.is_whitespace()).collect();
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&b64)
            .map_err(|e| e.to_string())?;
        Ok(rustls_pki_types::CertificateDer::from(bytes))
    }

    fn build_ws_connector(ca_pem: &[u8]) -> Result<tokio_tungstenite::Connector, String> {
        let ca_cert = parse_pem_cert(ca_pem)?;
        let mut root_store = rustls::RootCertStore::empty();
        root_store
            .add(ca_cert)
            .map_err(|e| format!("Invalid fixture root cert: {e}"))?;
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        Ok(tokio_tungstenite::Connector::Rustls(Arc::new(
            client_config,
        )))
    }
    fn read_private(path: &Path) -> Result<Vec<u8>, String> {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::symlink_metadata(path).map_err(|_| "Fixture file missing")?;
        if !metadata.is_file()
            || metadata.len() > 65536
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err("Fixture file must be a bounded private regular file".into());
        }
        use std::io::Read;
        let file = std::fs::File::open(path).map_err(|_| "Fixture file unreadable")?;
        let opened = file
            .metadata()
            .map_err(|_| "Fixture file metadata unavailable")?;
        use std::os::unix::fs::MetadataExt;
        if !opened.is_file()
            || opened.ino() != metadata.ino()
            || opened.dev() != metadata.dev()
            || opened.permissions().mode() & 0o077 != 0
        {
            return Err("Fixture file changed during admission".into());
        }
        let mut bytes = Vec::new();
        file.take(65537)
            .read_to_end(&mut bytes)
            .map_err(|_| "Fixture file unreadable")?;
        if bytes.len() > 65536 {
            return Err("Fixture file exceeded admission bound".into());
        }
        Ok(bytes)
    }
    pub(super) fn initialize() -> Result<(), String> {
        let path = required_launch_path(std::env::var_os("CATMOS_RUNTIME_FIXTURE_CONFIG"))?;
        let launch: Launch = serde_json::from_slice(&read_private(Path::new(&path))?)
            .map_err(|_| "Invalid fixture launch document")?;
        let mut manifest: Manifest = serde_json::from_slice(&read_private(&launch.manifest)?)
            .map_err(|_| "Invalid fixture manifest")?;
        // This shared manifest entry is for the DS relationship fixture only.
        // Desktop traffic has no authority to contact it through this profile.
        manifest.hosts.remove("public.api.bsky.app");
        validate_manifest(&manifest)?;
        if !launch.profile.is_absolute()
            || launch
                .profile
                .components()
                .any(|p| matches!(p, std::path::Component::ParentDir))
            || !launch
                .keychain_namespace
                .starts_with("blue.catbird.catmos.fixture.")
            || uuid::Uuid::parse_str(
                launch
                    .keychain_namespace
                    .trim_start_matches("blue.catbird.catmos.fixture."),
            )
            .is_err()
        {
            return Err("Invalid isolated profile/namespace".into());
        }
        let sessions: serde_json::Value = serde_json::from_slice(&read_private(&launch.sessions)?)
            .map_err(|_| "Invalid protected session document")?;
        let accounts: Vec<Account> = serde_json::from_value(
            sessions
                .get("accounts")
                .cloned()
                .ok_or("Missing protected accounts")?,
        )
        .map_err(|_| "Invalid protected accounts")?;
        let account = accounts
            .into_iter()
            .find(|a| a.label == launch.label)
            .ok_or("Unknown fixture account")?;
        if account
            .session
            .as_ref()
            .is_none_or(|s| s.is_empty() || s.len() > 4096)
            || !manifest.accounts.iter().any(|a| {
                a.label == account.label && a.did == account.did && a.device_id == account.device_id
            })
        {
            return Err("Fixture session does not match public account".into());
        }
        let ca_bytes = read_private(&manifest.ca_pem)?;
        let ca = reqwest::Certificate::from_pem(&ca_bytes)
            .map_err(|_| "Invalid fixture CA")?;
        let ws_connector = build_ws_connector(&ca_bytes)?;
        let marker = launch.profile.join("runtime-fixture.json");
        let marker_bytes=serde_json::to_vec(&serde_json::json!({"origin":manifest.origin,"did":account.did,"deviceId":account.device_id,"namespace":launch.keychain_namespace})).unwrap();
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
        if launch.profile.exists() {
            if read_private(&marker)? != marker_bytes {
                return Err("Existing profile belongs to another runtime fixture".into());
            }
        } else {
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&launch.profile)
                .map_err(|_| "Cannot create isolated fixture profile")?;
            use std::io::Write;
            std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&marker)
                .and_then(|mut f| f.write_all(&marker_bytes))
                .map_err(|_| "Cannot mark isolated fixture profile")?;
        }
        let keychain_file = launch.profile.join("fixture-keychain.json");
        let keychain_store = if keychain_file.exists() {
            let bytes = read_private(&keychain_file)?;
            let map: std::collections::BTreeMap<String, String> =
                serde_json::from_slice(&bytes).unwrap_or_default();
            Arc::new(std::sync::Mutex::new(map))
        } else {
            Arc::new(std::sync::Mutex::new(std::collections::BTreeMap::new()))
        };
        CONFIG
            .set(Config {
                manifest,
                profile: launch.profile,
                keychain_namespace: launch.keychain_namespace,
                account,
                ca,
                ws_connector,
                keychain_file,
                keychain_store,
            })
            .map_err(|_| "Fixture already configured")?;
        Ok(())
    }
    fn required_launch_path(
        path: Option<std::ffi::OsString>,
    ) -> Result<std::ffi::OsString, String> {
        path.filter(|p|!p.is_empty()).ok_or_else(||"Fixture binary requires CATMOS_RUNTIME_FIXTURE_CONFIG; production profile fallback is forbidden".into())
    }
    fn fixture_host(host: &str) -> bool {
        host.len() <= 253
            && host.ends_with(".request-fixture.catbird.blue")
            && host.split('.').all(|part| {
                !part.is_empty()
                    && part.len() <= 63
                    && !part.starts_with('-')
                    && !part.ends_with('-')
                    && part
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            })
    }
    fn validate_manifest(manifest: &Manifest) -> Result<(), String> {
        let origin = reqwest::Url::parse(&manifest.origin).map_err(|_| "Invalid fixture origin")?;
        if !manifest.fixture_only
            || origin.scheme() != "https"
            || origin.path() != "/"
            || origin.query().is_some()
            || origin.fragment().is_some()
            || !origin.username().is_empty()
            || origin.password().is_some()
            || !origin
                .host_str()
                .is_some_and(|h| manifest.hosts.contains_key(h))
            || manifest.hosts.is_empty()
            || manifest.hosts.len() > 16
        {
            return Err("Invalid fixture authority".into());
        }
        for (host, address) in &manifest.hosts {
            if !(host == "chat.catbird.blue" || fixture_host(host))
                || !address.ip().is_loopback()
                || address.port() == 0
            {
                return Err("Fixture DNS must map exact hosts to loopback".into());
            }
        }
        if manifest.accounts.is_empty() || manifest.accounts.len() > 2 {
            return Err("Fixture requires bounded synthetic accounts".into());
        }
        let mut labels = std::collections::HashSet::new();
        let mut dids = std::collections::HashSet::new();
        let mut devices = std::collections::HashSet::new();
        for account in &manifest.accounts {
            let host = account
                .did
                .strip_prefix("did:web:")
                .ok_or("Fixture account must be did:web")?;
            let device = uuid::Uuid::parse_str(&account.device_id)
                .map_err(|_| "Fixture device UUID invalid")?;
            if !fixture_host(host)
                || !manifest.hosts.contains_key(host)
                || device.get_version_num() != 4
                || device.to_string() != account.device_id
                || !matches!(account.label.as_str(), "alice" | "bob")
                || !labels.insert(&account.label)
                || !dids.insert(&account.did)
                || !devices.insert(&account.device_id)
            {
                return Err("Invalid or duplicate synthetic fixture account".into());
            }
        }
        Ok(())
    }
    use super::DenyDns;
    impl Config {
        pub(super) fn client_builder(
            &self,
            mut builder: reqwest::ClientBuilder,
        ) -> reqwest::ClientBuilder {
            builder = builder
                .no_proxy()
                .https_only(true)
                .tls_built_in_root_certs(false)
                .add_root_certificate(self.ca.clone())
                .dns_resolver(Arc::new(DenyDns))
                .redirect(reqwest::redirect::Policy::none());
            for (host, address) in &self.manifest.hosts {
                builder = builder.resolve(host, *address);
            }
            builder
        }
        pub(super) fn keychain_get(&self, service: &str, key: &str) -> Result<String, keyring::Error> {
            let store = self.keychain_store.lock().unwrap();
            let map_key = format!("{service}:{key}");
            store.get(&map_key).cloned().ok_or(keyring::Error::NoEntry)
        }

        pub(super) fn keychain_set(&self, service: &str, key: &str, value: &str) -> Result<(), keyring::Error> {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut store = self.keychain_store.lock().unwrap();
            let map_key = format!("{service}:{key}");
            store.insert(map_key, value.to_string());
            let bytes = serde_json::to_vec_pretty(&*store).map_err(|e| keyring::Error::PlatformFailure(Box::new(e)))?;
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .mode(0o600)
                .open(&self.keychain_file)
                .map_err(|e| keyring::Error::PlatformFailure(Box::new(e)))?;
            file.write_all(&bytes).map_err(|e| keyring::Error::PlatformFailure(Box::new(e)))?;
            Ok(())
        }

        pub(super) fn keychain_delete(&self, service: &str, key: &str) -> Result<(), keyring::Error> {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut store = self.keychain_store.lock().unwrap();
            let map_key = format!("{service}:{key}");
            store.remove(&map_key);
            let bytes = serde_json::to_vec_pretty(&*store).map_err(|e| keyring::Error::PlatformFailure(Box::new(e)))?;
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .mode(0o600)
                .open(&self.keychain_file)
                .map_err(|e| keyring::Error::PlatformFailure(Box::new(e)))?;
            file.write_all(&bytes).map_err(|e| keyring::Error::PlatformFailure(Box::new(e)))?;
            Ok(())
        }
        pub(super) async fn connect_websocket(
            &self,
            url: &str,
        ) -> Result<
            (
                tokio_tungstenite::WebSocketStream<
                    tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
                >,
                tokio_tungstenite::tungstenite::handshake::client::Response,
            ),
            String,
        > {
            use tokio_tungstenite::tungstenite::client::IntoClientRequest;
            let request = url
                .into_client_request()
                .map_err(|e| format!("Invalid WebSocket request: {e}"))?;
            let uri = request.uri().clone();
            let host = uri
                .host()
                .ok_or_else(|| "WebSocket URL missing host".to_string())?;

            let pinned_addr = self
                .manifest
                .hosts
                .get(host)
                .copied()
                .ok_or_else(|| format!("Host {host} absent from fixture manifest"))?;

            let socket = tokio::net::TcpStream::connect(pinned_addr)
                .await
                .map_err(|e| format!("Failed to connect to pinned address {pinned_addr} for {host}: {e}"))?;
            let _ = socket.set_nodelay(true);

            let scheme = uri.scheme_str().unwrap_or("wss");
            let connector = match scheme {
                "wss" => Some(self.ws_connector.clone()),
                "ws" => Some(tokio_tungstenite::Connector::Plain),
                other => return Err(format!("Unsupported WebSocket scheme: {other}")),
            };

            tokio_tungstenite::client_async_tls_with_config(request, socket, None, connector)
                .await
                .map_err(|e| format!("WebSocket connect failed: {e}"))
        }
    }
    pub(crate) async fn seed_native_authority(
        context: &catbird_mls::MLSContext,
        credentials: &crate::credentials::KeyringCredentialStore,
    ) -> Result<(), String> {
        let Some(config) = CONFIG.get() else {
            return Ok(());
        };
        let a = &config.account;
        let identity = format!("{}#{}", a.did, a.device_id);
        if context.identity_public_key(identity.clone()).is_err() {
            context
                .create_key_package(identity.as_bytes().to_vec())
                .map_err(|_| "Cannot initialize protected fixture identity")?;
        }
        let private = context
            .export_identity_key(identity.clone())
            .map_err(|_| "Cannot retain native identity")?;
        context
            .import_identity_key(a.did.clone(), private.clone())
            .map_err(|_| "Cannot restore native compatibility identity")?;
        credentials
            .store_signing_key(&a.did, &private)
            .await
            .map_err(|_| "Cannot retain native signer")?;
        credentials
            .store_local_device_uuid(&a.did, &a.device_id)
            .await
            .map_err(|_| "Cannot retain native UUID")?;
        let public = context
            .identity_public_key(identity)
            .map_err(|_| "Missing native public identity")?;
        let response=super::http_client().post(format!("{}/fixture/enroll",config.manifest.origin)).bearer_auth(a.session.as_ref().unwrap()).json(&serde_json::json!({"device_id":a.device_id,"signature_public_key":base64::engine::general_purpose::STANDARD.encode(public)})).send().await.map_err(|_|"Native public-key fixture preseed failed")?;
        if !response.status().is_success() {
            return Err(format!(
                "Native fixture preseed rejected: {}",
                response.status()
            ));
        }
        let service = super::keychain_service("catmos");
        for (key, value) in [
            ("session_id", a.session.as_ref().unwrap()),
            ("user_did", &a.did),
        ] {
            super::keychain_set(&service, key, value)
                .map_err(|_| "Cannot retain isolated fixture session")?;
        }
        Ok(())
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        fn manifest() -> Manifest {
            Manifest {
                fixture_only: true,
                origin: "https://fixture.request-fixture.catbird.blue".into(),
                ca_pem: "/tmp/unused.pem".into(),
                hosts: BTreeMap::from([(
                    "fixture.request-fixture.catbird.blue".into(),
                    "127.0.0.1:4443".parse().unwrap(),
                )]),
                accounts: vec![Account {
                    label: "alice".into(),
                    did: "did:web:fixture.request-fixture.catbird.blue".into(),
                    device_id: "00000000-0000-4000-8000-000000000001".into(),
                    session: None,
                }],
            }
        }
        #[test]
        fn manifest_rejects_remote_addresses_and_unmapped_or_insecure_origins() {
            let mut m = manifest();
            assert!(validate_manifest(&m).is_ok());
            m.hosts.insert(
                "fixture.request-fixture.catbird.blue".into(),
                "192.0.2.1:443".parse().unwrap(),
            );
            assert!(validate_manifest(&m).is_err());
            let mut m = manifest();
            m.origin = "http://fixture.request-fixture.catbird.blue".into();
            assert!(validate_manifest(&m).is_err());
            m.origin = "https://unmapped.request-fixture.catbird.blue".into();
            assert!(validate_manifest(&m).is_err());
            let mut m = manifest();
            m.fixture_only = false;
            assert!(validate_manifest(&m).is_err());
        }
        #[test]
        fn missing_config_and_nonsynthetic_accounts_are_rejected() {
            assert!(required_launch_path(None).is_err());
            let mut m = manifest();
            m.accounts[0].did = "did:web:real.example.com".into();
            assert!(validate_manifest(&m).is_err());
            let mut m = manifest();
            m.hosts
                .insert("real.example.com".into(), "127.0.0.1:4443".parse().unwrap());
            assert!(validate_manifest(&m).is_err());
            let mut m = manifest();
            m.accounts[0].device_id = "00000000-0000-1000-8000-000000000001".into();
            assert!(validate_manifest(&m).is_err());
        }
        #[tokio::test]
        async fn unlisted_dns_never_falls_back_to_public_resolution() {
            use reqwest::dns::Resolve;
            assert!(DenyDns
                .resolve("example.com".parse().unwrap())
                .await
                .is_err());
        }
        #[test]
        fn private_fixture_reader_rejects_broad_permissions_and_symlinks() {
            use std::os::unix::fs::{symlink, PermissionsExt};
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("session");
            std::fs::write(&path, b"{}").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(read_private(&path).is_err());
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            assert!(read_private(&path).is_ok());
            let link = dir.path().join("link");
            symlink(&path, &link).unwrap();
            assert!(read_private(&link).is_err());
        }
        #[tokio::test]
        async fn fixture_websocket_routes_pinned_hosts_and_fails_closed_for_unpinned_hosts() {
            let dir = tempfile::tempdir().unwrap();
            let ca_key = dir.path().join("ca.key");
            let ca_pem = dir.path().join("ca.pem");
            let srv_key = dir.path().join("server.key");
            let srv_csr = dir.path().join("server.csr");
            let srv_pem = dir.path().join("server.pem");
            let ext = dir.path().join("ext.cnf");
            std::fs::write(&ext, "subjectAltName=DNS:fixture.request-fixture.catbird.blue\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n").unwrap();

            std::process::Command::new("openssl")
                .args(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=Fixture CA", "-addext", "basicConstraints=critical,CA:TRUE", "-keyout"])
                .arg(&ca_key)
                .arg("-out")
                .arg(&ca_pem)
                .status()
                .unwrap();

            std::process::Command::new("openssl")
                .args(["req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=fixture.request-fixture.catbird.blue", "-keyout"])
                .arg(&srv_key)
                .arg("-out")
                .arg(&srv_csr)
                .status()
                .unwrap();

            std::process::Command::new("openssl")
                .args(["x509", "-req", "-days", "1", "-CA"])
                .arg(&ca_pem)
                .arg("-CAkey")
                .arg(&ca_key)
                .arg("-CAcreateserial")
                .arg("-in")
                .arg(&srv_csr)
                .arg("-extfile")
                .arg(&ext)
                .arg("-out")
                .arg(&srv_pem)
                .status()
                .unwrap();

            let mut py_server = tokio::process::Command::new("python3")
                .arg("-c")
                .arg(r#"
import ssl, socket, hashlib, base64, sys, time

srv_pem = sys.argv[1]
srv_key = sys.argv[2]

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(srv_pem, srv_key)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('127.0.0.1', 0))
port = sock.getsockname()[1]
sock.listen(1)

print(port, flush=True)

raw, _ = sock.accept()
ssock = ctx.wrap_socket(raw, server_side=True)
data = ssock.recv(4096).decode('utf-8', errors='ignore')
key = None
for line in data.split('\r\n'):
    if line.lower().startswith('sec-websocket-key:'):
        key = line.split(':', 1)[1].strip()
        break
if key:
    guid = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
    accept = base64.b64encode(hashlib.sha1((key + guid).encode('utf-8')).digest()).decode('utf-8')
    resp = f'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n'
    ssock.sendall(resp.encode('utf-8'))
    time.sleep(1.0)
ssock.close()
"#)
                .arg(&srv_pem)
                .arg(&srv_key)
                .stdout(std::process::Stdio::piped())
                .spawn()
                .unwrap();

            let stdout = py_server.stdout.take().unwrap();
            let mut reader = tokio::io::BufReader::new(stdout);
            let mut port_line = String::new();
            tokio::io::AsyncBufReadExt::read_line(&mut reader, &mut port_line).await.unwrap();
            let tls_port: u16 = port_line.trim().parse().unwrap();

            let mut m = manifest();
            m.ca_pem = ca_pem.clone();
            m.hosts = BTreeMap::from([(
                "fixture.request-fixture.catbird.blue".into(),
                format!("127.0.0.1:{tls_port}").parse().unwrap(),
            )]);

            let config = Config {
                manifest: m,
                profile: dir.path().to_path_buf(),
                keychain_namespace: "blue.catbird.catmos.fixture.00000000-0000-4000-8000-000000000001".into(),
                account: Account {
                    label: "alice".into(),
                    did: "did:web:fixture.request-fixture.catbird.blue".into(),
                    device_id: "00000000-0000-4000-8000-000000000001".into(),
                    session: None,
                },
                ca: reqwest::Certificate::from_pem(&std::fs::read(&ca_pem).unwrap()).unwrap(),
                ws_connector: build_ws_connector(&std::fs::read(&ca_pem).unwrap()).unwrap(),
                keychain_file: dir.path().join("fixture-keychain.json"),
                keychain_store: Arc::new(std::sync::Mutex::new(std::collections::BTreeMap::new())),
            };

            // Test 1: Unpinned host must fail closed without DNS lookup
            let unpinned_err = config
                .connect_websocket("wss://unpinned-test-host.catbird.blue/xrpc/blue.catbird.chat.subscribeEvents")
                .await
                .unwrap_err();
            assert!(
                unpinned_err.contains("absent from fixture manifest"),
                "Unpinned host should fail closed with 'absent from fixture manifest', got: {unpinned_err}"
            );

            // Test 2: Pinned host must connect to local TLS listener
            let pinned_url = format!("wss://fixture.request-fixture.catbird.blue:{tls_port}/xrpc/blue.catbird.chat.subscribeEvents");
            let pinned_res = config.connect_websocket(&pinned_url).await;
            assert!(pinned_res.is_ok(), "Pinned host connection failed: {:?}", pinned_res.err());

            let _ = py_server.kill().await;
        }

        #[test]
        fn fixture_keychain_is_file_backed_and_never_calls_system_keychain() {
            let dir = tempfile::tempdir().unwrap();
            let keychain_file = dir.path().join("fixture-keychain.json");
            assert!(!keychain_file.exists());

            let mut m = manifest();
            let ca_pem = dir.path().join("ca.pem");
            std::fs::write(&ca_pem, "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----").unwrap();
            m.ca_pem = ca_pem.clone();

            let config = Config {
                manifest: m,
                profile: dir.path().to_path_buf(),
                keychain_namespace: "blue.catbird.catmos.fixture.00000000-0000-4000-8000-000000000001".into(),
                account: Account {
                    label: "alice".into(),
                    did: "did:web:fixture.request-fixture.catbird.blue".into(),
                    device_id: "00000000-0000-4000-8000-000000000001".into(),
                    session: None,
                },
                ca: reqwest::Certificate::from_pem(&std::fs::read(&ca_pem).unwrap()).unwrap(),
                ws_connector: tokio_tungstenite::Connector::Plain,
                keychain_file: keychain_file.clone(),
                keychain_store: Arc::new(std::sync::Mutex::new(std::collections::BTreeMap::new())),
            };

            // Pre-fix: setting a credential in fixture mode called keyring::Entry on macOS login keychain,
            // producing 0 files in profile dir and prompting SecurityAgent for password.
            // Post-fix: writes strictly to profile dir fixture-keychain.json with mode 0600.
            config.keychain_set("catmos", "session_id", "test-session-token").unwrap();
            assert!(keychain_file.exists(), "fixture-keychain.json must exist in profile dir");

            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::metadata(&keychain_file).unwrap();
            assert_eq!(meta.permissions().mode() & 0o777, 0o600, "fixture-keychain.json must have 0600 permissions");

            // Getting the credential reads back without touching system keychain
            let val = config.keychain_get("catmos", "session_id").unwrap();
            assert_eq!(val, "test-session-token");

            // Deleting removes from the file
            config.keychain_delete("catmos", "session_id").unwrap();
            assert!(matches!(config.keychain_get("catmos", "session_id"), Err(keyring::Error::NoEntry)));
        }
    }
}

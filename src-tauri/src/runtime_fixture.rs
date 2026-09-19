//! Opt-in debug gateway support. No production trust/profile configuration changes.
#[cfg(all(feature = "local-runtime-fixture", not(debug_assertions)))]
compile_error!("local-runtime-fixture is forbidden in release builds");

pub(crate) fn keychain_service(production: &str) -> String {
    #[cfg(feature = "local-runtime-fixture")]
    if let Some(config) = enabled::CONFIG.get() {
        return format!("{}.{}", config.keychain_namespace, production);
    }
    production.to_owned()
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
pub(crate) fn initialize() {
    #[cfg(feature = "local-runtime-fixture")]
    enabled::initialize().expect("Invalid isolated runtime fixture configuration");
}

#[cfg(feature = "local-runtime-fixture")]
pub(crate) use enabled::seed_native_authority;

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
        hosts: BTreeMap<String, SocketAddr>,
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
        std::fs::read(path).map_err(|_| "Fixture file unreadable".into())
    }
    pub(super) fn initialize() -> Result<(), String> {
        let Some(path) = std::env::var_os("CATMOS_RUNTIME_FIXTURE_CONFIG") else {
            return Ok(());
        };
        let launch: Launch = serde_json::from_slice(&read_private(Path::new(&path))?)
            .map_err(|_| "Invalid fixture launch document")?;
        let manifest: Manifest = serde_json::from_slice(&read_private(&launch.manifest)?)
            .map_err(|_| "Invalid fixture manifest")?;
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
        let ca = reqwest::Certificate::from_pem(&read_private(&manifest.ca_pem)?)
            .map_err(|_| "Invalid fixture CA")?;
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
        CONFIG
            .set(Config {
                manifest,
                profile: launch.profile,
                keychain_namespace: launch.keychain_namespace,
                account,
                ca,
            })
            .map_err(|_| "Fixture already configured")?;
        Ok(())
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
            if host.is_empty()
                || host.contains(['/', ':'])
                || !address.ip().is_loopback()
                || address.port() == 0
            {
                return Err("Fixture DNS must map exact hosts to loopback".into());
            }
        }
        Ok(())
    }
    struct DenyDns;
    impl reqwest::dns::Resolve for DenyDns {
        fn resolve(&self, _: reqwest::dns::Name) -> reqwest::dns::Resolving {
            Box::pin(async {
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "Host absent from fixture manifest",
                )
                .into())
            })
        }
    }
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
        for (key, value) in [
            ("session_id", a.session.as_ref().unwrap()),
            ("user_did", &a.did),
        ] {
            keyring::Entry::new(&super::keychain_service("catmos"), key)
                .and_then(|e| e.set_password(value))
                .map_err(|_| "Cannot retain isolated fixture session")?;
        }
        Ok(())
    }
}

//! Direct sign-in for the desktop app.
//!
//! Catmos holds its own OAuth session through Petrel's Rust client. A client
//! assertion backend (CAB) keeps the app's signing key and hands out a short
//! assertion for each authorization-server request, so no token ever passes
//! through a gateway. Sessions and their DPoP keys live in an encrypted
//! directory whose key is kept in the OS keyring.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use bytes::Bytes;
use http::{HeaderMap, Method, Response};
use petrel::identity::{HickoryResolver, IdentityOptions, IdentityResolver};
use petrel::net::{ReqwestTransport, SharedTransport};
use petrel::oauth::{
    ClientAuth, OAuthClient, OAuthConfig, OAuthError, OAuthIdentityAdapter, OAuthStartOptions,
    OAuthTarget, PendingOAuthFlow,
};
use petrel::service_auth::ServiceRef;
use petrel::storage::{FileSecretStore, SessionStore, StoreError};
use petrel::xrpc::{CallOptions, XrpcBody, XrpcClient};
use petrel_core::{AtIdentifier, Did, Nsid};
use url::Url;

use crate::mls::{AccountAuth, AuthFuture};
use catbird_mls::client::{PlatformHttpHeader, PlatformHttpRequest, PlatformHttpResponse};

const DEFAULT_CLIENT_ID: &str = "https://catmos.catbird.blue/oauth/client-metadata.json";
const DEFAULT_REDIRECT_URI: &str = "https://catmos.catbird.blue/auth/desktop-callback";
const DEFAULT_CAB_URL: &str = "https://api.catbird.blue/cab/catmos";
const STORE_NAMESPACE: &str = "catmos-desktop";
const STORE_KEY_ENTRY: &str = "oauth_store_key";
/// Service id of the delivery service in its DID document. An `rpc:` scope
/// and the matching `getServiceAuth` audience must both name it.
pub(crate) const DELIVERY_SERVICE_ID: &str = "atproto_mls";
/// Attachments and restored history can be far larger than an API response.
const MAX_PDS_RESPONSE_BYTES: u64 = 128 * 1024 * 1024;
const PDS_TIMEOUT: Duration = Duration::from_secs(60);

/// Permissions beyond the set Encrypted Chat itself checks for
/// (`catbird_mls::client::REQUIRED_LABYRINTH_OAUTH_SCOPES`).
const EXTRA_SCOPES: [&str; 2] = [
    "repo:blue.catbird.chat.declaration?action=create&action=update",
    "repo:app.bsky.graph.block?action=create",
];

/// The whole scope Catmos asks for at sign-in. `static/oauth/client-metadata.json`
/// must declare exactly this string; a test holds the two together.
pub(crate) fn oauth_scope(delivery_service_did: &str) -> String {
    let mut scopes: Vec<String> = catbird_mls::client::REQUIRED_LABYRINTH_OAUTH_SCOPES
        .iter()
        .chain(EXTRA_SCOPES.iter())
        .map(|scope| (*scope).to_string())
        .collect();
    scopes.push(format!(
        "rpc:*?aud={}%23{DELIVERY_SERVICE_ID}",
        delivery_service_did
    ));
    scopes.join(" ")
}

/// What the UI needs to know about the signed-in account.
#[derive(Debug, Clone)]
pub(crate) struct SignedIn {
    pub did: String,
    pub handle: String,
    pub pds: String,
    pub granted_scopes: Vec<String>,
}

/// Why a stored session could not be used.
#[derive(Debug)]
pub(crate) enum AuthFailure {
    /// The account has to sign in again.
    SignedOut(String),
    /// Something that may pass: the keyring is locked, the disk is busy, the
    /// network is down. Saved credentials are kept.
    Retryable(String),
}

impl AuthFailure {
    pub(crate) fn message(&self) -> &str {
        match self {
            Self::SignedOut(message) | Self::Retryable(message) => message,
        }
    }
}

struct Settings {
    client_id: String,
    redirect_uri: Url,
    authentication: ClientAuth,
    /// A fixed port means a public loopback client for local development.
    loopback_port: Option<u16>,
    scope: String,
}

impl Settings {
    fn from_env(delivery_service_did: &str) -> Result<Self, String> {
        let scope = oauth_scope(delivery_service_did);
        if let Some(port) = env("CATMOS_OAUTH_LOOPBACK_PORT") {
            let port: u16 = port
                .parse()
                .ok()
                .filter(|port| *port != 0)
                .ok_or("CATMOS_OAUTH_LOOPBACK_PORT must be a port number")?;
            return Ok(Self {
                client_id: String::new(),
                redirect_uri: Url::parse(&format!("http://127.0.0.1:{port}/callback"))
                    .map_err(|e| e.to_string())?,
                authentication: ClientAuth::Public,
                loopback_port: Some(port),
                scope,
            });
        }
        let client_id = env("CATMOS_OAUTH_CLIENT_ID").unwrap_or_else(|| DEFAULT_CLIENT_ID.into());
        let redirect_uri = env("CATMOS_OAUTH_REDIRECT_URI")
            .unwrap_or_else(|| DEFAULT_REDIRECT_URI.into())
            .parse::<Url>()
            .map_err(|e| format!("invalid OAuth redirect URI: {e}"))?;
        let backend_url = env("CATMOS_CAB_URL")
            .unwrap_or_else(|| DEFAULT_CAB_URL.into())
            .parse::<Url>()
            .map_err(|e| format!("invalid client assertion backend URL: {e}"))?;
        Ok(Self {
            authentication: ClientAuth::Cab {
                backend_url,
                client_id: client_id.clone(),
            },
            client_id,
            redirect_uri,
            loopback_port: None,
            scope,
        })
    }

    fn config(&self) -> Result<OAuthConfig, OAuthError> {
        match self.loopback_port {
            Some(port) => OAuthConfig::loopback(port, "/callback", &self.scope),
            None => OAuthConfig::new(
                self.client_id.clone(),
                self.redirect_uri.clone(),
                &self.scope,
                self.authentication.clone(),
            ),
        }
    }
}

fn env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// The desktop app's OAuth client and the sessions it holds.
pub(crate) struct DesktopAuth {
    transport: SharedTransport,
    client: Arc<OAuthClient>,
    store: SessionStore,
    redirect_uri: Url,
    loopback_port: Option<u16>,
    pds_by_did: RwLock<HashMap<String, Url>>,
}

impl DesktopAuth {
    /// Opens the encrypted session directory under `data_dir`. Fails closed
    /// when the OS keyring cannot supply or keep the directory key.
    pub(crate) fn open(data_dir: &Path, delivery_service_did: &str) -> Result<Self, String> {
        let settings = Settings::from_env(delivery_service_did)?;
        let key = load_or_create_store_key()?;
        let secrets = FileSecretStore::open(data_dir.join("oauth"), &key)
            .map_err(|e| format!("Could not open the saved sign-in store: {e}"))?;
        let store = SessionStore::new(Arc::new(secrets), STORE_NAMESPACE)
            .map_err(|e| format!("Could not open the saved sign-in store: {e}"))?;

        let transport: SharedTransport = Arc::new(
            ReqwestTransport::new().map_err(|e| format!("Could not start networking: {e}"))?,
        );
        let dns = HickoryResolver::system().map_err(|e| format!("Could not start DNS: {e}"))?;
        let resolver =
            IdentityResolver::new(Arc::clone(&transport), dns, IdentityOptions::default());
        let config = settings
            .config()
            .map_err(|e| format!("Invalid OAuth client configuration: {e}"))?;
        let client = OAuthClient::new(
            Arc::clone(&transport),
            Arc::new(OAuthIdentityAdapter::new(resolver)),
            store.clone(),
            config,
        )
        .map_err(|e| format!("Invalid OAuth client configuration: {e}"))?;

        Ok(Self {
            transport,
            client: Arc::new(client),
            store,
            redirect_uri: settings.redirect_uri,
            loopback_port: settings.loopback_port,
            pds_by_did: RwLock::new(HashMap::new()),
        })
    }

    /// The port the callback listener must bind, when the client is the
    /// local-development loopback client. `None` lets the OS pick.
    pub(crate) fn fixed_callback_port(&self) -> Option<u16> {
        self.loopback_port
    }

    /// Starts an authorization for a handle, DID or server URL. `port` is the
    /// loopback listener the hosted callback page forwards to; it travels in
    /// the `state` value as `<port>.<random>`.
    pub(crate) async fn begin_login(
        &self,
        identifier: &str,
        port: u16,
    ) -> Result<PendingOAuthFlow, String> {
        let identifier = identifier.trim().trim_start_matches('@');
        let target = if identifier.starts_with("https://") {
            OAuthTarget::Server(
                identifier
                    .parse()
                    .map_err(|_| "That server address is not valid".to_string())?,
            )
        } else {
            OAuthTarget::Identifier(
                AtIdentifier::parse(identifier)
                    .map_err(|_| "Enter a handle such as name.bsky.social".to_string())?,
            )
        };
        let prefix = port.to_string();
        let options = OAuthStartOptions {
            scope: None,
            state_prefix: self.loopback_port.is_none().then_some(prefix.as_str()),
        };
        self.client
            .start_authorization_with_options(target, options)
            .await
            .map_err(|e| format!("Could not start sign-in: {e}"))
    }

    /// Abandons a flow the user did not finish.
    pub(crate) async fn cancel_login(&self, state: &str) {
        let _ = self.client.cancel_authorization(state).await;
    }

    /// Completes a flow from the query string the callback delivered.
    pub(crate) async fn finish_login(&self, query: &str) -> Result<SignedIn, String> {
        let mut callback = self.redirect_uri.clone();
        callback.set_query(Some(query));
        let session = self
            .client
            .complete_authorization(&callback)
            .await
            .map_err(|e| match e {
                OAuthError::Cancelled => "Sign-in was cancelled".to_string(),
                other => format!("Sign-in failed: {other}"),
            })?;
        self.signed_in(&session.did, session.scope())
            .await
            .map_err(|failure| failure.message().to_string())
    }

    /// The account selected at the last sign-in, if its session is still stored.
    /// Reads local storage only, so it works offline.
    pub(crate) async fn restore(&self) -> Result<Option<SignedIn>, AuthFailure> {
        let Some(did) = self.store.get_current_did().await.map_err(store_failure)? else {
            return Ok(None);
        };
        match self.client.session(&did).await {
            Ok(Some(session)) => self.signed_in(&did, session.scope()).await.map(Some),
            Ok(None) => Ok(None),
            Err(OAuthError::Store(error)) => Err(store_failure(error)),
            Err(error) => Err(AuthFailure::SignedOut(error.to_string())),
        }
    }

    async fn signed_in(&self, did: &Did, scope: &str) -> Result<SignedIn, AuthFailure> {
        let account = self
            .store
            .get_account(did)
            .await
            .map_err(store_failure)?
            .ok_or_else(|| AuthFailure::SignedOut("The saved account is incomplete".into()))?;
        let pds = account
            .pds
            .parse::<Url>()
            .map_err(|_| AuthFailure::SignedOut("The saved account has no valid server".into()))?;
        if let Ok(mut cache) = self.pds_by_did.write() {
            cache.insert(did.as_str().to_string(), pds);
        }
        Ok(SignedIn {
            did: did.as_str().to_string(),
            handle: account
                .handle
                .map_or_else(|| did.as_str().to_string(), |handle| handle.to_string()),
            pds: account.pds.trim_end_matches('/').to_string(),
            granted_scopes: scope.split_ascii_whitespace().map(str::to_string).collect(),
        })
    }

    /// Revokes the session upstream where possible and clears it locally.
    pub(crate) async fn logout(&self, did: &str) -> Result<(), String> {
        let did = parse_did(did)?;
        if let Ok(mut cache) = self.pds_by_did.write() {
            cache.remove(did.as_str());
        }
        self.client
            .logout(&did)
            .await
            .map(|_| ())
            .map_err(|e| format!("Could not clear the saved sign-in: {e}"))
    }

    /// An XRPC client for the account's own server, signed with its session.
    pub(crate) fn pds_client(&self, did: &str) -> Result<XrpcClient, String> {
        let parsed = parse_did(did)?;
        let pds = self
            .pds_by_did
            .read()
            .ok()
            .and_then(|cache| cache.get(parsed.as_str()).cloned())
            .ok_or("Not authenticated")?;
        Ok(XrpcClient::new(pds, Arc::clone(&self.transport))
            .map_err(|e| e.to_string())?
            .with_auth_provider(Arc::new(self.client.session_auth(parsed))))
    }

    /// An unauthenticated XRPC client for a public service.
    pub(crate) fn public_client(&self, base: &str) -> Result<XrpcClient, String> {
        let base = base.parse::<Url>().map_err(|e| e.to_string())?;
        XrpcClient::new(base, Arc::clone(&self.transport)).map_err(|e| e.to_string())
    }

    /// Asks the account's server for a token addressed to one service method.
    pub(crate) async fn service_token(
        &self,
        did: &str,
        audience: &str,
        method: &str,
    ) -> Result<String, String> {
        let audience = ServiceRef::parse(audience)
            .map_err(|e| format!("invalid service audience `{audience}`: {e}"))?;
        let method = method
            .parse::<Nsid>()
            .map_err(|_| format!("invalid service method `{method}`"))?;
        let token = self
            .client
            .session_auth(parse_did(did)?)
            .get_service_auth(&audience, Some(&method), None)
            .await
            .map_err(|e| format!("getServiceAuth `{method}` failed: {e}"))?;
        Ok(token.as_str().to_string())
    }

    /// Sends one XRPC call to the account's server and returns the response
    /// as received, error statuses included.
    pub(crate) async fn pds_exchange(
        &self,
        did: &str,
        method: Method,
        nsid: &str,
        params: Vec<(String, String)>,
        headers: HeaderMap,
        body: Option<(Bytes, String)>,
    ) -> Result<Response<Bytes>, String> {
        let client = self.pds_client(did)?;
        let body = body
            .map(|(bytes, content_type)| XrpcBody::bytes(bytes, &content_type))
            .transpose()
            .map_err(|e| e.to_string())?;
        let mut options = CallOptions::default();
        options.headers = headers;
        options.transport.timeout = Some(PDS_TIMEOUT);
        options.transport.max_response_bytes = Some(MAX_PDS_RESPONSE_BYTES);
        client
            .exchange(method, nsid, params, body, &options)
            .await
            .map_err(|e| e.to_string())
    }
}

/// Signs the MLS transport's requests with one account's session.
pub(crate) struct SessionSigner {
    auth: Arc<DesktopAuth>,
    did: String,
}

impl SessionSigner {
    pub(crate) fn new(auth: Arc<DesktopAuth>, did: String) -> Self {
        Self { auth, did }
    }
}

/// Headers the XRPC client sets itself from the method, body and session.
fn is_managed_header(name: &str) -> bool {
    ["authorization", "dpop", "content-type", "content-length", "host"]
        .iter()
        .any(|managed| name.eq_ignore_ascii_case(managed))
}

impl AccountAuth for SessionSigner {
    fn service_token<'a>(&'a self, audience: &'a str, method: &'a str) -> AuthFuture<'a, String> {
        Box::pin(self.auth.service_token(&self.did, audience, method))
    }

    fn pds_exchange<'a>(
        &'a self,
        request: &'a PlatformHttpRequest,
    ) -> AuthFuture<'a, PlatformHttpResponse> {
        Box::pin(async move {
            let url = Url::parse(&request.url).map_err(|e| format!("invalid URL: {e}"))?;
            let nsid = url
                .path()
                .strip_prefix("/xrpc/")
                .ok_or("not an XRPC request")?
                .to_string();
            let method = Method::from_bytes(request.method.as_bytes())
                .map_err(|e| format!("invalid HTTP method: {e}"))?;
            let params = url.query_pairs().into_owned().collect();

            let mut headers = HeaderMap::new();
            let mut content_type = None;
            for header in &request.headers {
                if header.name.eq_ignore_ascii_case("content-type") {
                    content_type = Some(header.value.clone());
                }
                if is_managed_header(&header.name) {
                    continue;
                }
                let name = http::HeaderName::from_bytes(header.name.as_bytes())
                    .map_err(|_| format!("invalid header name `{}`", header.name))?;
                let value = http::HeaderValue::from_str(&header.value)
                    .map_err(|_| format!("invalid value for header `{}`", header.name))?;
                headers.append(name, value);
            }
            let body = request.body.clone().map(|bytes| {
                (
                    Bytes::from(bytes),
                    content_type.unwrap_or_else(|| "application/json".to_string()),
                )
            });

            let response = self
                .auth
                .pds_exchange(&self.did, method, &nsid, params, headers, body)
                .await?;
            Ok(PlatformHttpResponse {
                status: response.status().as_u16(),
                headers: response
                    .headers()
                    .iter()
                    .filter_map(|(name, value)| {
                        value.to_str().ok().map(|value| PlatformHttpHeader {
                            name: name.as_str().to_string(),
                            value: value.to_string(),
                        })
                    })
                    .collect(),
                body: response.into_body().to_vec(),
            })
        })
    }
}

pub(crate) fn parse_did(did: &str) -> Result<Did, String> {
    Did::parse(did).map_err(|e| format!("invalid DID `{did}`: {e}"))
}

fn store_failure(error: StoreError) -> AuthFailure {
    AuthFailure::Retryable(format!("The saved sign-in could not be read: {error}"))
}

fn load_or_create_store_key() -> Result<[u8; 32], String> {
    let entry = crate::native_keyring::entry("catmos", STORE_KEY_ENTRY)
        .map_err(|e| format!("The system keyring is unavailable: {e}"))?;
    match entry.get_password() {
        Ok(encoded) => {
            let bytes = B64
                .decode(encoded.trim())
                .map_err(|_| "The saved sign-in key is damaged".to_string())?;
            <[u8; 32]>::try_from(bytes.as_slice())
                .map_err(|_| "The saved sign-in key is damaged".to_string())
        }
        Err(keyring::Error::NoEntry) => {
            let mut key = [0u8; 32];
            getrandom::fill(&mut key).map_err(|e| format!("Could not create a key: {e}"))?;
            entry
                .set_password(&B64.encode(key))
                .map_err(|e| format!("The system keyring refused the sign-in key: {e}"))?;
            Ok(key)
        }
        Err(error) => Err(format!("The system keyring is unavailable: {error}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOME_DS: &str = "did:web:chat.catbird.blue";

    #[test]
    fn published_client_metadata_declares_the_requested_scope() {
        let metadata: serde_json::Value =
            serde_json::from_str(include_str!("../../static/oauth/client-metadata.json")).unwrap();
        assert_eq!(metadata["scope"], oauth_scope(HOME_DS));
        assert_eq!(metadata["client_id"], DEFAULT_CLIENT_ID);
        assert!(metadata["redirect_uris"]
            .as_array()
            .unwrap()
            .iter()
            .any(|uri| uri == DEFAULT_REDIRECT_URI));
        assert_eq!(
            metadata["jwks_uri"],
            format!("{DEFAULT_CAB_URL}/.well-known/jwks.json")
        );
    }

    #[test]
    fn production_configuration_is_accepted_by_the_oauth_client() {
        let settings = Settings {
            client_id: DEFAULT_CLIENT_ID.into(),
            redirect_uri: DEFAULT_REDIRECT_URI.parse().unwrap(),
            authentication: ClientAuth::Cab {
                backend_url: DEFAULT_CAB_URL.parse().unwrap(),
                client_id: DEFAULT_CLIENT_ID.into(),
            },
            loopback_port: None,
            scope: oauth_scope(HOME_DS),
        };
        settings.config().expect("production OAuth configuration");
    }

    #[test]
    fn scope_grants_only_the_delivery_service_and_drops_the_generic_grant() {
        let scope = oauth_scope(HOME_DS);
        assert!(scope
            .split(' ')
            .any(|s| s == "rpc:*?aud=did:web:chat.catbird.blue%23atproto_mls"));
        assert!(!scope.contains("transition:generic"));
        assert!(scope.split(' ').next() == Some("atproto"));
    }

    #[test]
    fn loopback_configuration_is_a_public_client_on_the_fixed_port() {
        let settings = Settings {
            client_id: String::new(),
            redirect_uri: "http://127.0.0.1:43117/callback".parse().unwrap(),
            authentication: ClientAuth::Public,
            loopback_port: Some(43117),
            scope: oauth_scope(HOME_DS),
        };
        settings.config().expect("loopback OAuth configuration");
    }
}

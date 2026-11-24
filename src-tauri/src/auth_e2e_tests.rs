//! Signs the desktop auth module in against real servers: Petrel's Swift
//! example authorization server and client assertion backend, run locally.
//!
//! Opt-in, like Petrel's own end-to-end tests: set
//! `PETREL_E2E_SERVER_BIN_DIR` to the directory holding
//! `petrel-oauth-server-example` and `petrel-cab-server`. Without it the test
//! reports that it was skipped.

use std::future::{ready, Future};
use std::net::IpAddr;
use std::sync::Arc;

use catbird_mls::client::PlatformHttpRequest;
use petrel::identity::{
    DnsError, DnsResolver, HandleLookup, HandleStrategy, IdentityError, IdentityOptions,
    IdentityResolver,
};
use petrel::net::{ReqwestTransport, SharedTransport};
use petrel::oauth::{ClientAuth, OAuthConfig, OAuthIdentityAdapter};
use petrel::rt::BoxFuture;
use petrel::storage::{MemorySecretStore, SessionStore};
use petrel_core::{Did, Handle};
use petrel_e2e::{
    headless_approve, CabClient, ExampleServer, FakePlc, ServerBins, CAB_CLIENT_ID, CAB_REDIRECT,
    DEMO_DID, DEMO_HANDLE, DEMO_SCOPE,
};

use super::{DesktopAuth, SessionSigner};
use crate::mls::AccountAuth;

#[derive(Clone, Copy)]
struct NoDns;

impl DnsResolver for NoDns {
    fn txt(&self, _name: &str) -> impl Future<Output = Result<Vec<String>, DnsError>> + Send {
        ready(Err(DnsError::Lookup("no DNS in this test".into())))
    }

    fn lookup_ip(&self, _host: &str) -> impl Future<Output = Result<Vec<IpAddr>, DnsError>> + Send {
        ready(Err(DnsError::Lookup("no DNS in this test".into())))
    }
}

struct DemoHandleLookup;

impl HandleLookup for DemoHandleLookup {
    fn lookup<'a>(
        &'a self,
        handle: &'a Handle,
    ) -> BoxFuture<'a, Result<Option<Did>, IdentityError>> {
        Box::pin(async move {
            Ok((handle.as_str() == DEMO_HANDLE).then(|| DEMO_DID.parse().expect("demo DID")))
        })
    }
}

fn desktop_auth(store: SessionStore, plc: &FakePlc, cab: &url::Url) -> Arc<DesktopAuth> {
    let transport: SharedTransport =
        Arc::new(ReqwestTransport::with_dns(NoDns).expect("transport"));
    let options = IdentityOptions {
        plc_directory: plc.origin().clone(),
        handle_strategy: HandleStrategy::Custom {
            lookup: Arc::new(DemoHandleLookup),
            fallback_to_direct: false,
        },
        allow_development_identifiers: true,
        ..IdentityOptions::default()
    };
    let resolver = IdentityResolver::new(Arc::clone(&transport), NoDns, options);
    let redirect: url::Url = CAB_REDIRECT.parse().unwrap();
    let config = OAuthConfig::new(
        CAB_CLIENT_ID,
        redirect.clone(),
        DEMO_SCOPE,
        ClientAuth::Cab {
            backend_url: cab.clone(),
            client_id: CAB_CLIENT_ID.to_owned(),
        },
    )
    .expect("OAuth configuration")
    .with_loopback_development();
    Arc::new(
        DesktopAuth::assemble(
            transport,
            Arc::new(OAuthIdentityAdapter::new(resolver).with_loopback_development()),
            store,
            config,
            redirect,
            None,
            true,
        )
        .expect("assemble desktop auth"),
    )
}

#[tokio::test]
async fn desktop_sign_in_through_a_client_assertion_backend() {
    let Some(bins) = ServerBins::from_env() else {
        return;
    };
    let registration = CabClient::generate();
    let issuer = ExampleServer::spawn(&bins, &[registration.metadata()])
        .await
        .expect("start the Swift authorization server");
    // The backend demands a DPoP nonce, so every assertion takes the retry.
    let cab = registration
        .spawn(&bins, issuer.origin(), true, &[])
        .await
        .expect("start the Swift client assertion backend");
    let plc = FakePlc::start(DEMO_DID, issuer.origin())
        .await
        .expect("start the PLC stand-in");

    let store =
        SessionStore::new(Arc::new(MemorySecretStore::new()), "catmos-desktop-e2e").unwrap();
    let auth = desktop_auth(store.clone(), &plc, cab.origin());
    assert!(auth.restore().await.unwrap().is_none());

    // Sign in. The listener port rides in `state`, as the hosted callback
    // page expects, and the listener accepts only that state.
    let flow = auth.begin_login(DEMO_HANDLE, 49152).await.unwrap();
    assert!(flow.state.starts_with("49152."));
    let callback = headless_approve(issuer.origin(), &flow.authorize_url)
        .await
        .expect("approve the sign-in on the Swift server");
    let query = callback.query().expect("callback query").to_owned();
    assert_eq!(
        crate::commands::classify_callback_query(&query, &flow.state),
        crate::commands::CallbackQuery::Answer { denied: false }
    );
    let signed_in = auth.finish_login(&query).await.unwrap();
    assert_eq!(signed_in.did, DEMO_DID);
    assert_eq!(signed_in.handle, DEMO_HANDLE);
    assert_eq!(
        signed_in.pds,
        issuer.origin().as_str().trim_end_matches('/')
    );
    assert_eq!(signed_in.granted_scopes, ["atproto", "transition:generic"]);
    // A callback cannot be replayed.
    assert!(auth.finish_login(&query).await.is_err());

    // The MLS transport's signer reaches the account's server with the
    // DPoP-bound session and hands back what the server said.
    let signer = SessionSigner::new(Arc::clone(&auth), signed_in.did.clone());
    let get = |nsid: &str| PlatformHttpRequest {
        method: "GET".into(),
        url: format!("{}/xrpc/{nsid}", signed_in.pds),
        headers: vec![],
        body: None,
    };
    let response = signer
        .pds_exchange(&get("com.atproto.server.getSession"))
        .await
        .unwrap();
    assert_eq!(response.status, 200);
    let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(body["did"], DEMO_DID);
    // An error from the server arrives with its status, not as a failure.
    let missing = signer
        .pds_exchange(&get("com.example.notImplemented"))
        .await
        .unwrap();
    assert!(missing.status >= 400, "status {}", missing.status);

    // After a restart the stored session is found without the network.
    let restarted = desktop_auth(store, &plc, cab.origin());
    let restored = restarted.restore().await.unwrap().expect("stored session");
    assert_eq!(restored.did, DEMO_DID);
    let after_restart = SessionSigner::new(Arc::clone(&restarted), restored.did.clone())
        .pds_exchange(&get("com.atproto.server.getSession"))
        .await
        .unwrap();
    assert_eq!(after_restart.status, 200);

    // Signing out revokes the grant and forgets the account.
    restarted.logout(DEMO_DID).await.unwrap();
    assert!(restarted.restore().await.unwrap().is_none());
    assert!(restarted.pds_client(DEMO_DID).is_err());
}

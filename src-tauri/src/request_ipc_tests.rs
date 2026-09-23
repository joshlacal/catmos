//! C29/C30 desktop evidence through the real Tauri IPC dispatcher (MockRuntime)
//! with the production `ReqwestApiClient` aimed at a loopback listener that
//! records every TCP connection. The listener is the transport boundary: any
//! reqwest effect from these commands is counted, whatever its path.
use crate::api_client::ReqwestApiClient;
use crate::credentials::KeyringCredentialStore;
use crate::storage::SqliteStorage;
use crate::{commands, request_commands, AppState};
use catbird_mls::{KeychainAccess, MLSContext, MLSError};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use tauri::ipc::{CallbackFn, InvokeBody};
use tauri::webview::InvokeRequest;

const DB_KEY: &str = "0badc0de0badc0de0badc0de0badc0de0badc0de0badc0de0badc0de0badc0de";
const ALICE: &str = "did:plc:c29aliceaaaaaaaaaaaaaaaa";
const BOB: &str = "did:plc:c29bobbbbbbbbbbbbbbbbbbb";
const PEER: &str = "did:plc:c29peerpppppppppppppppp";
const SECRET: &str = "C29 private introduction that must stay local";

struct MemoryKeychain(Mutex<HashMap<String, Vec<u8>>>);
#[async_trait::async_trait]
impl KeychainAccess for MemoryKeychain {
    async fn read(&self, key: String) -> Result<Option<Vec<u8>>, MLSError> {
        Ok(self.0.lock().unwrap().get(&key).cloned())
    }
    async fn write(&self, key: String, value: Vec<u8>) -> Result<(), MLSError> {
        self.0.lock().unwrap().insert(key, value);
        Ok(())
    }
    async fn delete(&self, key: String) -> Result<(), MLSError> {
        self.0.lock().unwrap().remove(&key);
        Ok(())
    }
}

/// Every accepted connection is recorded with its request line, then refused
/// with 503 so no code path can mistake it for a successful remote effect.
fn transport_spy() -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sink = seen.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).unwrap_or(0);
            let line = String::from_utf8_lossy(&buf[..n])
                .lines()
                .next()
                .unwrap_or("<connection without request>")
                .to_owned();
            sink.lock().unwrap().push(line);
            let _ = stream.write_all(
                b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            );
        }
    });
    (base, seen)
}

fn call(webview: &tauri::WebviewWindow<tauri::test::MockRuntime>, cmd: &str, body: Value) -> Result<Value, Value> {
    tauri::test::get_ipc_response(
        webview,
        InvokeRequest {
            cmd: cmd.into(),
            callback: CallbackFn(0),
            error: CallbackFn(1),
            url: "http://tauri.localhost".parse().unwrap(),
            body: InvokeBody::Json(body),
            headers: Default::default(),
            invoke_key: tauri::test::INVOKE_KEY.to_string(),
        },
    )
    .map(|response| response.deserialize::<Value>().unwrap())
}

fn activate(state: &AppState, did: &str, token: &str) -> String {
    state.api_client.set_auth(did.into(), token.into());
    commands::install_content_root_key(state, did);
    state.api_client.current_session().unwrap().revision.to_string()
}

#[test]
fn draft_entrypoints_and_account_switch_have_zero_transport_effects() {
    let tmp = tempfile::tempdir().unwrap();
    let (base, transport) = transport_spy();
    let host_db = tmp.path().join("catmos.db");
    let storage = Arc::new(SqliteStorage::new(host_db.to_str().unwrap(), DB_KEY).unwrap());
    let api_client = Arc::new(ReqwestApiClient::new(base));
    let mls_context = MLSContext::new(
        tmp.path().join("mls.db").to_string_lossy().into_owned(),
        DB_KEY.into(),
        Box::new(MemoryKeychain(Mutex::new(HashMap::new()))),
    )
    .unwrap();
    api_client.set_mls_context(mls_context.clone());
    storage.set_mls_context(mls_context.clone());
    let credentials = Arc::new(KeyringCredentialStore::with_chat_auth(
        api_client.chat_auth_provider(),
        mls_context.clone(),
    ));
    let orchestrator = Arc::new(catbird_mls::orchestrator::MLSOrchestrator::new(
        mls_context,
        storage.clone(),
        api_client.clone(),
        credentials,
        catbird_mls::orchestrator::OrchestratorConfig::default(),
    ));
    let state = AppState {
        request_scope: tokio::sync::Mutex::new(()),
        orchestrator,
        chat_auth: api_client.chat_auth_provider(),
        api_client,
        ws_handles: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        kp_monitor: tokio::sync::Mutex::new(None),
        sync_loop: tokio::sync::Mutex::new(None),
        data_dir: tmp.path().to_path_buf(),
    };
    let alice_rev = activate(&state, ALICE, "alice-session");
    let app = tauri::test::mock_builder()
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            request_commands::save_request_draft,
            request_commands::cancel_request_draft,
            request_commands::resume_request_draft,
            commands::send_image,
        ])
        .build(tauri::test::mock_context(tauri::test::noop_assets()))
        .unwrap();
    let webview = tauri::WebviewWindowBuilder::new(&app, "main", Default::default())
        .build()
        .unwrap();
    let state = tauri::Manager::state::<AppState>(&app);
    let effects = || transport.lock().unwrap().clone();

    // Contact selection opens the composer with an empty draft, then typing saves.
    let first = uuid::Uuid::new_v4().to_string();
    let input = |id: &str, text: &str| json!({"draftId":id,"recipientDid":PEER,"text":text,"invitation":null});
    let saved = call(&webview, "save_request_draft", json!({"ownerDid":ALICE,"ownerRevision":alice_rev,"input":input(&first,""),"recipientLabel":"Peer"})).unwrap();
    assert_eq!(saved["phase"], "draft");
    let saved = call(&webview, "save_request_draft", json!({"ownerDid":ALICE,"ownerRevision":alice_rev,"input":input(&first,SECRET),"recipientLabel":"Peer"})).unwrap();
    assert_eq!(saved["input"]["text"], SECRET);
    assert_eq!(effects(), Vec::<String>::new(), "composer open and draft typing");

    // Attachment before acceptance on an unaccepted conversation: rejected, nothing uploaded.
    let attach = call(&webview, "send_image", json!({"ownerDid":ALICE,"ownerRevision":alice_rev,"conversationId":uuid::Uuid::new_v4().to_string(),"content":"","data":[137,80,78,71],"contentType":"image/png","width":1,"height":1,"altText":null}));
    let reason = attach.expect_err("attachment-first must be rejected");
    eprintln!("attachment-first rejection: {reason}");
    assert!(effects().iter().all(|line| !line.contains("upload") && !line.contains("Blob") && !line.contains("sendMessage")),
        "no upload or send transport: {:?}", effects());

    // Draft cancel is local archival.
    let cancelled = call(&webview, "cancel_request_draft", json!({"ownerDid":ALICE,"ownerRevision":alice_rev,"draftId":first})).unwrap();
    assert_eq!(cancelled["archived"], true);

    // A live, unarchived draft that the next account must not see or resume.
    let retained = uuid::Uuid::new_v4().to_string();
    call(&webview, "save_request_draft", json!({"ownerDid":ALICE,"ownerRevision":alice_rev,"input":input(&retained,SECRET),"recipientLabel":"Peer"})).unwrap();
    let draft_effects = effects();

    // Account switch through the real activation path.
    let bob_rev = activate(&state, BOB, "bob-session");
    let resumed = call(&webview, "resume_request_draft", json!({"ownerDid":BOB,"ownerRevision":bob_rev,"draftId":retained}));
    assert!(resumed.unwrap_err().to_string().contains("Draft not found for this account"));
    let stale = call(&webview, "resume_request_draft", json!({"ownerDid":ALICE,"ownerRevision":alice_rev,"draftId":retained}));
    assert!(stale.unwrap_err().to_string().contains("Account session changed"));
    let stale_save = call(&webview, "save_request_draft", json!({"ownerDid":ALICE,"ownerRevision":alice_rev,"input":input(&retained,"overwrite"),"recipientLabel":"Peer"}));
    assert!(stale_save.is_err());
    assert!(state.orchestrator.storage().request_drafts(BOB).unwrap().is_empty());
    assert!(state.orchestrator.storage().request_draft(ALICE, &retained).is_err());
    assert_eq!(effects(), draft_effects, "account switch attempts add no transport effects");

    // Protected storage: host file carries no plaintext and needs the SQLCipher key.
    let bytes = std::fs::read(&host_db).unwrap();
    assert!(!String::from_utf8_lossy(&bytes).contains(SECRET));
    let unkeyed = rusqlite::Connection::open(&host_db).unwrap();
    assert!(unkeyed.execute_batch("SELECT count(*) FROM sqlite_master;").is_err());

    // Returning to Alice restores her retained draft unchanged.
    activate(&state, ALICE, "alice-session-2");
    let restored = state.orchestrator.storage().request_draft(ALICE, &retained).unwrap().unwrap();
    assert_eq!(restored.input.text, SECRET);
    assert_eq!(restored.phase, "draft");

    let all = effects();
    eprintln!("transport effects observed: {all:?}");
    assert!(all.is_empty(), "draft-only entrypoints and account switch reached the network: {all:?}");
}

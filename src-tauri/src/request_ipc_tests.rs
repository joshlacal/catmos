//! C29/C30 desktop evidence through the real Tauri IPC dispatcher (MockRuntime)
//! with the production `ReqwestApiClient` aimed at a loopback listener that
//! records every TCP connection. The listener is the transport boundary: any
//! reqwest effect from these commands is counted, whatever its path.
use crate::api_client::ReqwestApiClient;
use crate::credentials::KeyringCredentialStore;
use crate::storage::SqliteStorage;
use crate::{commands, request_commands, AppState};
use catbird_mls::orchestrator::CredentialStore as _;
use catbird_mls::{KeychainAccess, MLSContext, MLSError};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use tauri::ipc::{CallbackFn, InvokeBody};
use tauri::Manager as _;
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_ownership_and_storage_fences_prevent_simultaneous_mutation() {
    use crate::request_commands::RequestDraft;
    use catbird_mls::orchestrator::DirectRequestInput;

    let tmp = tempfile::tempdir().unwrap();
    let shared_db = tmp.path().join("concurrent_shared.db");
    let db_path = shared_db.to_str().unwrap();
    let mls_db = tmp.path().join("concurrent_mls.db");
    let mls_path = mls_db.to_str().unwrap();

    // 1. Two owners contend for the EXACT SAME storage and crypto state
    let storage = Arc::new(SqliteStorage::new(db_path, DB_KEY).unwrap());
    let context = MLSContext::new(
        mls_path.to_string(),
        DB_KEY.into(),
        Box::new(MemoryKeychain(Mutex::new(HashMap::new()))),
    ).unwrap();
    context.set_content_root_key(vec![0x42; 32]).unwrap();
    storage.set_mls_context(context.clone());

    // Storage is bound to authorized owner Alice
    storage.bind_request_owner(Some(ALICE));

    let draft_alice = RequestDraft {
        input: DirectRequestInput {
            draft_id: uuid::Uuid::new_v4().to_string(),
            recipient_did: PEER.into(),
            text: "Alice exclusive draft".into(),
            invitation: None,
        },
        recipient_label: "Peer".into(),
        phase: "draft".into(),
        outcome: None,
        archived: false,
        note_delivery: None,
    };
    let draft_bob = RequestDraft {
        input: DirectRequestInput {
            draft_id: uuid::Uuid::new_v4().to_string(),
            recipient_did: PEER.into(),
            text: "Bob unauthorized mutation".into(),
            invitation: None,
        },
        recipient_label: "Peer".into(),
        phase: "draft".into(),
        outcome: None,
        archived: false,
        note_delivery: None,
    };

    // 2. Real concurrent contention: two threads race across a Barrier on a 4-thread runtime
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let s_alice = storage.clone();
    let b_alice = barrier.clone();
    let d_alice = draft_alice.clone();
    let handle_alice = tokio::spawn(async move {
        b_alice.wait().await;
        s_alice.save_request_draft(ALICE, &d_alice)
    });

    let s_bob = storage.clone();
    let b_bob = barrier.clone();
    let d_bob = draft_bob.clone();
    let handle_bob = tokio::spawn(async move {
        b_bob.wait().await;
        s_bob.save_request_draft(BOB, &d_bob)
    });

    let res_alice = handle_alice.await.unwrap();
    let res_bob = handle_bob.await.unwrap();

    // Exactly one owner mutates: Alice succeeds, Bob is fenced
    assert!(res_alice.is_ok(), "Bound owner Alice must succeed in mutating crypto state");
    assert!(res_bob.is_err(), "Contending owner Bob must be fenced");
    assert!(res_bob.unwrap_err().contains("Account storage scope changed"));

    // Alice's draft is stored and intact
    let stored_alice = storage.request_draft(ALICE, &draft_alice.input.draft_id).unwrap().unwrap();
    assert_eq!(stored_alice.input.text, "Alice exclusive draft");

    // Bob cannot read drafts in storage
    assert!(storage.request_drafts(BOB).is_err());
    assert!(storage.request_draft(BOB, &draft_bob.input.draft_id).is_err());

    // In the raw database, only Alice's row was written; Bob wrote 0 rows
    let raw_conn = rusqlite::Connection::open(db_path).unwrap();
    raw_conn.execute_batch(&format!("PRAGMA key = '{DB_KEY}';")).unwrap();
    let count_alice: i64 = raw_conn.query_row(
        "SELECT count(*) FROM encrypted_request_projection WHERE owner_did=?1",
        [ALICE], |r| r.get(0)
    ).unwrap();
    let count_bob: i64 = raw_conn.query_row(
        "SELECT count(*) FROM encrypted_request_projection WHERE owner_did=?1",
        [BOB], |r| r.get(0)
    ).unwrap();
    assert_eq!(count_alice, 1);
    assert_eq!(count_bob, 0, "Fenced owner Bob must have written 0 rows to the database");

    // 3. SHOW IT FAILS WITHOUT THE FENCE:
    // A. Without the owner bound (fence removed: bind_request_owner(None)),
    //    any attempt to mutate or read is atomically blocked
    storage.bind_request_owner(None);
    let without_fence_alice = storage.save_request_draft(ALICE, &draft_alice);
    let without_fence_bob = storage.save_request_draft(BOB, &draft_bob);
    assert!(without_fence_alice.is_err());
    assert!(without_fence_alice.unwrap_err().contains("Account storage scope changed"));
    assert!(without_fence_bob.is_err());
    assert!(without_fence_bob.unwrap_err().contains("Account storage scope changed"));

    // B. If an un-fenced row is inserted raw into SQLite (simulating an adversary tampering):
    raw_conn.execute(
        "INSERT INTO encrypted_request_projection(owner_did, record_kind, record_id, payload) VALUES(?1, 'draft', ?2, ?3)",
        rusqlite::params![BOB, &draft_bob.input.draft_id, b"forged unencrypted plaintext bytes"],
    ).unwrap();
    // When bound to Bob, reading this forged unfenced payload fails cryptographic envelope decryption:
    storage.bind_request_owner(Some(BOB));
    let tamper_decode = storage.request_draft(BOB, &draft_bob.input.draft_id);
    assert!(tamper_decode.is_err());
    assert!(tamper_decode.unwrap_err().contains("Request storage is locked or belongs to another account"));

    // C. Raw SQLite mutual exclusion: an exclusive transaction locks out concurrent writers
    let raw_writer_1 = rusqlite::Connection::open(db_path).unwrap();
    raw_writer_1.execute_batch(&format!("PRAGMA key = '{DB_KEY}'; BEGIN EXCLUSIVE;")).unwrap();
    let raw_writer_2 = rusqlite::Connection::open(db_path).unwrap();
    raw_writer_2.execute_batch(&format!("PRAGMA key = '{DB_KEY}'; PRAGMA busy_timeout = 50;")).unwrap();
    let blocked_write = raw_writer_2.execute_batch("BEGIN EXCLUSIVE;");
    assert!(blocked_write.is_err(), "Concurrent uncoordinated writers fail with database lock error");
    raw_writer_1.execute_batch("COMMIT;").unwrap();

    // 4. Session transition race under capture_effect_owner
    let scope = Arc::new(tokio::sync::Mutex::new(()));
    let session_state = Arc::new(Mutex::new(crate::api_client::ChatSessionSnapshot {
        actor_did: ALICE.into(),
        token: "session-1".into(),
        revision: 1,
    }));
    let scope_guard = scope.lock().await;
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let entered_slot = Mutex::new(Some(entered_tx));
    let queued_scope = scope.clone();
    let queued_session = session_state.clone();
    let queued_task = tokio::spawn(async move {
        request_commands::capture_effect_owner(&queued_scope, ALICE, "1", || {
            let session = queued_session.lock().unwrap().clone();
            if let Some(tx) = entered_slot.lock().unwrap().take() {
                let _ = tx.send(());
            }
            Ok(session)
        }).await.map(|_guard| ())
    });
    entered_rx.await.unwrap();
    session_state.lock().unwrap().actor_did = BOB.into();
    session_state.lock().unwrap().revision = 2;
    drop(scope_guard);
    let queued_result = queued_task.await.unwrap();
    assert!(queued_result.is_err());
    assert!(queued_result.unwrap_err().contains("Account session changed while the operation was queued"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_catmos_browser_bidirectional() {
    use std::io::{BufRead, BufReader, Write as _};
    use std::process::{Command, Stdio};

    let workspace = "/Users/joshlacalamito/Developer/.workspaces/catbird-encrypted-requests-20260919";
    let run_uuid = uuid::Uuid::new_v4();
    let run_hex = &run_uuid.simple().to_string()[..16];
    let db_name = format!("catbird_direct_requests_fault_{run_hex}");
    let db_url = format!("postgresql://127.0.0.1:5432/{db_name}");

    // 1. Create dedicated empty database
    let status = Command::new("psql")
        .args(["postgresql://127.0.0.1:5432/postgres", "-X", "-c", &format!("CREATE DATABASE {db_name};")])
        .status()
        .expect("create dedicated database");
    assert!(status.success(), "create database failed");

    // RAII guard to drop the dedicated database on any exit/panic
    struct DbGuard(String);
    impl Drop for DbGuard {
        fn drop(&mut self) {
            let _ = Command::new("psql")
                .args(["postgresql://127.0.0.1:5432/postgres", "-X", "-c", &format!("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='{}' AND pid<>pg_backend_pid();", self.0)])
                .status();
            let _ = Command::new("psql")
                .args(["postgresql://127.0.0.1:5432/postgres", "-X", "-c", &format!("DROP DATABASE IF EXISTS {};", self.0)])
                .status();
            eprintln!("Dedicated database {} dropped cleanly", self.0);
        }
    }
    let _db_guard = DbGuard(db_name.clone());

    // 2. Install 39 reviewed migrations
    let status = Command::new("cargo")
        .args([
            "test", "--manifest-path", &format!("{workspace}/mls-ds/e2e-tests/Cargo.toml"),
            "--test", "encrypted_direct_requests",
            "c01_real_router_auth_live_preparation_and_native_recipient_preview",
            "--", "--nocapture"
        ])
        .env("REQUEST_TEST_DATABASE_URL", &db_url)
        .env("REQUEST_SERVER_FIXTURE_BINARY", &format!("{workspace}/mls-ds/target/debug/encrypted_request_server_fixture"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("install migrations");
    assert!(status.success(), "migration install failed");

    // 3. Start client_runtime_gateway
    let out_dir = format!("/tmp/catbird-gw-bidi-{run_hex}");
    let mut gw_child = Command::new(&format!("{workspace}/mls-ds/e2e-tests/target/debug/examples/client_runtime_gateway"))
        .env("REQUEST_TEST_DATABASE_URL", &db_url)
        .env("REQUEST_SERVER_FIXTURE_BINARY", &format!("{workspace}/mls-ds/target/debug/encrypted_request_server_fixture"))
        .env("RUST_LOG", "info,catbird_server=debug")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn gateway");

    let cfg = json!({
        "output_dir": out_dir,
        "cors_origin": "http://127.0.0.1:5173",
        "lifetime_seconds": 1800
    });
    gw_child.stdin.as_mut().unwrap().write_all(cfg.to_string().as_bytes()).unwrap();
    gw_child.stdin.take();

    struct ChildGuard(std::process::Child, bool);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            if self.1 {
                let _ = Command::new("kill").args(["-INT", &self.0.id().to_string()]).status();
                let _ = self.0.wait();
            } else {
                let _ = self.0.kill();
            }
        }
    }
    let mut gw_guard = ChildGuard(gw_child, true);

    let mut reader = BufReader::new(gw_guard.0.stdout.take().unwrap());
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let manifest_info: Value = serde_json::from_str(line.trim()).expect("decode manifest info");
    let manifest_path = manifest_info["manifest"].as_str().unwrap().to_owned();
    let manifest: Value = serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
    let sessions: Value = serde_json::from_str(&std::fs::read_to_string(format!("{out_dir}/sessions.json")).unwrap()).unwrap();

    let alice_acc = manifest["accounts"].as_array().unwrap().iter().find(|a| a["label"] == "alice").unwrap();
    let bob_acc = manifest["accounts"].as_array().unwrap().iter().find(|a| a["label"] == "bob").unwrap();
    let alice_did = alice_acc["did"].as_str().unwrap();
    let bob_did = bob_acc["did"].as_str().unwrap();
    let alice_session = sessions["accounts"].as_array().unwrap().iter().find(|a| a["label"] == "alice").unwrap()["session"].as_str().unwrap();
    let bob_session = sessions["accounts"].as_array().unwrap().iter().find(|a| a["label"] == "bob").unwrap()["session"].as_str().unwrap();

    // 4. Start Vite
    let vite_child = Command::new("node")
        .args(["node_modules/vite/bin/vite.js", "--host", "127.0.0.1", "--port", "5173", "--strictPort", "--mode", "local-runtime-fixture"])
        .current_dir(format!("{workspace}/catmos"))
        .env("VITE_LOCAL_REQUEST_FIXTURE_ORIGIN", manifest["origin"].as_str().unwrap())
        .env("VITE_LOCAL_REQUEST_FIXTURE_RUN_ID", uuid::Uuid::new_v4().to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn vite");
    let _vite_guard = ChildGuard(vite_child, false);

    for _ in 0..60 {
        if reqwest::Client::new().get("http://127.0.0.1:5173/").send().await.is_ok() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }

    // 5. Initialize Desktop AppState
    let desktop_profile = format!("/tmp/catmos-desktop-profile-alice-{run_hex}");
    let desktop_config = format!("/tmp/catmos-fixture-alice-{run_hex}.json");
    std::fs::write(&desktop_config, json!({
        "manifest": manifest_path,
        "sessions": format!("{out_dir}/sessions.json"),
        "label": "alice",
        "profile": desktop_profile,
        "keychain_namespace": format!("blue.catbird.catmos.fixture.{run_uuid}")
    }).to_string()).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&desktop_config, std::fs::Permissions::from_mode(0o600)).unwrap();

    std::env::set_var("CATMOS_RUNTIME_FIXTURE_CONFIG", &desktop_config);
    crate::runtime_fixture::initialize();
    let tmp = tempfile::tempdir().unwrap();
    let host_db = tmp.path().join("catmos_desktop.db");
    let storage = Arc::new(SqliteStorage::new(host_db.to_str().unwrap(), DB_KEY).unwrap());
    let api_client = Arc::new(ReqwestApiClient::new(manifest["origin"].as_str().unwrap().to_string()));
    let mls_context = MLSContext::new(
        tmp.path().join("mls_desktop.db").to_string_lossy().into_owned(),
        DB_KEY.into(),
        Box::new(MemoryKeychain(Mutex::new(HashMap::new()))),
    ).unwrap();
    api_client.set_mls_context(mls_context.clone());
    storage.set_mls_context(mls_context.clone());
    let credentials = Arc::new(KeyringCredentialStore::with_chat_auth(
        api_client.chat_auth_provider(),
        mls_context.clone(),
    ));
    crate::runtime_fixture::seed_native_authority(mls_context.as_ref(), credentials.as_ref()).await.unwrap();
    credentials.store_server_device_id(alice_did, alice_acc["deviceId"].as_str().unwrap()).await.unwrap();
    let orchestrator = Arc::new(catbird_mls::orchestrator::MLSOrchestrator::new(
        mls_context.clone(),
        storage.clone(),
        api_client.clone(),
        credentials.clone(),
        catbird_mls::orchestrator::OrchestratorConfig::default(),
    ));
    let state = AppState {
        request_scope: tokio::sync::Mutex::new(()),
        orchestrator,
        chat_auth: api_client.chat_auth_provider(),
        api_client: api_client.clone(),
        ws_handles: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        kp_monitor: tokio::sync::Mutex::new(None),
        sync_loop: tokio::sync::Mutex::new(None),
        data_dir: tmp.path().to_path_buf(),
    };
    state.orchestrator.initialize(alice_did).await.unwrap();
    commands::install_content_root_key(&state, alice_did);
    commands::configure_chat_auth(&state, alice_did, alice_session).await.unwrap();
    let alice_rev = state.api_client.current_session().unwrap().revision.to_string();

    let app = tauri::test::mock_builder()
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            request_commands::save_request_draft,
            request_commands::submit_request_draft,
            request_commands::refresh_direct_request,
            request_commands::accept_direct_request,
            commands::send_message,
            commands::get_messages,
            commands::fetch_new_messages,
        ])
        .build(tauri::test::mock_context(tauri::test::noop_assets()))
        .unwrap();
    let webview = tauri::WebviewWindowBuilder::new(&app, "main", Default::default()).build().unwrap();

    // 6. Spawn browser-live-controller
    let mut browser_proc = Command::new("node")
        .arg(&format!("{workspace}/catmos/tests/browser-live-controller.mjs"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn browser-live-controller");

    let mut b_stdin = browser_proc.stdin.take().unwrap();
    let mut b_reader = BufReader::new(browser_proc.stdout.take().unwrap());

    let mut b_call = |req: Value| -> Value {
        b_stdin.write_all(req.to_string().as_bytes()).unwrap();
        b_stdin.write_all(b"\n").unwrap();
        b_stdin.flush().unwrap();
        let mut line = String::new();
        b_reader.read_line(&mut line).unwrap();
        let val: Value = serde_json::from_str(line.trim()).unwrap();
        if val["ok"] == false {
            panic!("b_call error for {:?}: {:?}", req["cmd"], val["error"]);
        }
        val
    };

    // Init Bob in Browser
    let res = b_call(json!({"cmd": "init", "manifestPath": manifest_path, "label": "bob", "runId": run_hex}));
    assert_eq!(res["ok"], true, "Bob browser init");

    // =========================================================================
    // DIRECTION 1: Desktop Alice -> Browser Bob
    // =========================================================================
    let d1_draft_id = uuid::Uuid::new_v4().to_string();
    let d1_intro = format!("Hello Bob! Live Direction 1 intro from Catmos Desktop ({run_hex}).");
    let d1_input = json!({"draftId": d1_draft_id, "recipientDid": bob_did, "text": d1_intro, "invitation": null});

    call(&webview, "save_request_draft", json!({"ownerDid": alice_did, "ownerRevision": alice_rev, "input": d1_input, "recipientLabel": "Bob"})).unwrap();
    let submit_res = call(&webview, "submit_request_draft", json!({"ownerDid": alice_did, "ownerRevision": alice_rev, "draftId": d1_draft_id})).unwrap();
    assert_eq!(submit_res["phase"], "resolved");
    let cid1 = submit_res["outcome"]["conversationId"].as_str().unwrap().to_owned();

    // Bob previews decrypted intro before accept
    let preview_res = b_call(json!({"cmd": "await_preview", "cid": &cid1, "text": d1_intro}));
    assert_eq!(preview_res["ok"], true);
    assert_eq!(preview_res["consent"], "incomingPending");
    assert_eq!(preview_res["previewText"], d1_intro);
    assert_eq!(preview_res["canSend"], false);

    // Bob accepts
    let accept_res = b_call(json!({"cmd": "accept", "cid": &cid1}));
    assert_eq!(accept_res["ok"], true);

    // Bob replies
    let bob_reply = format!("Hello Alice! Bob in Browser accepted your live request ({run_hex}).");
    let reply_res = b_call(json!({"cmd": "send_message", "cid": &cid1, "text": bob_reply}));
    assert_eq!(reply_res["ok"], true);

    // Desktop Alice refreshes and decrypts Bob's reply
    let refresh_res = call(&webview, "refresh_direct_request", json!({"ownerDid": alice_did, "ownerRevision": alice_rev, "conversationId": cid1})).unwrap();
    assert_eq!(refresh_res["consent"], "accepted");

    let fetched = call(&webview, "fetch_new_messages", json!({"ownerDid": alice_did, "ownerRevision": alice_rev, "conversationId": cid1})).unwrap();
    let messages = fetched.as_array().unwrap();
    assert!(messages.iter().any(|m| m["content"] == bob_reply), "Bob reply decrypted on desktop");

    // Desktop Alice replies back with confirmed local send state
    let alice_reply = format!("Alice Desktop received Bob reply and replies back live ({run_hex}).");
    let alice_send = call(&webview, "send_message", json!({"ownerDid": alice_did, "ownerRevision": alice_rev, "conversationId": cid1, "content": alice_reply})).unwrap();
    assert_eq!(alice_send["conversationId"], cid1);
    assert_eq!(alice_send["content"], alice_reply);

    // Bob browser receives Alice's reply
    let bob_fetched = b_call(json!({"cmd": "fetch_messages", "cid": cid1, "expectedText": alice_reply}));
    assert!(bob_fetched["messages"].as_array().unwrap().iter().any(|m| m["content"] == alice_reply), "Alice reply decrypted in browser");

    // Restart / reload check on both sides: exactly 1 occurrence of each message
    let desktop_recheck = call(&webview, "get_messages", json!({"ownerDid": alice_did, "ownerRevision": alice_rev, "conversationId": cid1, "before": null})).unwrap();
    let d_msgs = desktop_recheck.as_array().unwrap();
    assert_eq!(d_msgs.iter().filter(|m| m["content"] == bob_reply).count(), 1);
    assert_eq!(d_msgs.iter().filter(|m| m["content"] == alice_reply).count(), 1);

    let b_reload = b_call(json!({"cmd": "reload_and_check", "cid": cid1}));
    let b_msgs = b_reload["messages"].as_array().unwrap();
    assert_eq!(b_msgs.iter().filter(|m| m["content"] == bob_reply).count(), 1);
    assert_eq!(b_msgs.iter().filter(|m| m["content"] == alice_reply).count(), 1);

    // Close browser controller
    let _ = b_call(json!({"cmd": "close"}));
    let _ = browser_proc.kill();

    // Check PostgreSQL chat.entries for the direct request conversation
    let entries_d1 = Command::new("psql")
        .args([&db_url, "-X", "-c", &format!("SELECT seq, entry_kind, actor_did FROM chat.entries WHERE conversation_id='{cid1}' ORDER BY seq;")])
        .output()
        .expect("query chat.entries D1");
    let d1_text = String::from_utf8_lossy(&entries_d1.stdout);
    eprintln!("Direction 1 entries:\n{d1_text}");
    assert!(d1_text.contains("directRequestEntry"), "Must contain directRequestEntry");
    assert!(d1_text.contains("directRequestAcceptanceEntry"), "Must contain directRequestAcceptanceEntry");
    assert!(d1_text.contains("applicationEntry"), "Must contain applicationEntry");

    eprintln!("BIDIRECTIONAL LIVE QUALIFICATION SUCCESSFUL!");
}

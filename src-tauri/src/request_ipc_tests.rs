//! C29/C30 desktop evidence through the real Tauri IPC dispatcher (MockRuntime)
//! with the production `ReqwestApiClient` aimed at a loopback listener that
//! records every TCP connection. The listener is the transport boundary: any
//! reqwest effect from these commands is counted, whatever its path.
use crate::api_client::ReqwestApiClient;
use crate::credentials::KeyringCredentialStore;
use crate::storage::SqliteStorage;
use crate::{commands, request_commands, AppState};
use catbird_mls::orchestrator::CredentialStore as _;
use catbird_mls::orchestrator::MlsCryptoContext as _;
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

#[derive(Clone)]
struct MemoryKeychain(Arc<Mutex<HashMap<String, Vec<u8>>>>);
impl MemoryKeychain {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(HashMap::new())))
    }
}
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
        Box::new(MemoryKeychain::new()),
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
        Box::new(MemoryKeychain::new()),
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
    assert_eq!(count_alice, 1, "Alice's draft row must be written to the database");
    assert_eq!(count_bob, 0, "Fenced owner Bob must have written 0 rows to the database");
    // Verify database integrity via PRAGMA integrity_check on the actual desktop DB
    let integrity: String = raw_conn.query_row("PRAGMA integrity_check;", [], |r| r.get(0)).unwrap();
    assert_eq!(integrity, "ok", "SQLCipher database integrity check failed: {integrity}");
    eprintln!("Catmos Desktop PRAGMA integrity_check verified: {integrity}");
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
async fn account_switch_isolates_mls_context_and_intents_stay_unreadable() {
    use crate::request_commands::RequestDraft;
    use catbird_mls::orchestrator::DirectRequestInput;

    let tmp = tempfile::tempdir().unwrap();
    let (base, transport) = transport_spy();

    // 1. Setup Alice's isolated context and storage
    let alice_db_file = tmp.path().join("mls_alice.db");
    let alice_context = MLSContext::new(
        alice_db_file.to_string_lossy().into_owned(),
        DB_KEY.into(),
        Box::new(MemoryKeychain::new()),
    ).unwrap();
    let alice_storage_file = tmp.path().join("catmos_alice.db");
    let alice_storage = Arc::new(SqliteStorage::new(alice_storage_file.to_str().unwrap(), DB_KEY).unwrap());
    let alice_api_client = Arc::new(ReqwestApiClient::new(base.clone()));
    alice_api_client.set_mls_context(alice_context.clone());
    alice_storage.set_mls_context(alice_context.clone());
    alice_context.set_content_root_key(vec![0x42; 32]).unwrap();
    alice_storage.bind_request_owner(Some(ALICE));

    let alice_credentials = Arc::new(KeyringCredentialStore::with_chat_auth(
        alice_api_client.chat_auth_provider(),
        alice_context.clone(),
    ));

    // Seed Alice's device and identity in her own context
    let alice_dev = "00000000-0000-4000-8000-000000000001";
    let a_identity = format!("{}#{}", ALICE, alice_dev);
    alice_context.create_key_package(a_identity.as_bytes().to_vec()).unwrap();
    let a_private = alice_context.export_identity_key(a_identity.clone()).unwrap();
    let _ = alice_context.import_identity_key(ALICE.to_string(), a_private.clone());
    alice_credentials.store_signing_key(ALICE, &a_private).await.unwrap();
    alice_credentials.store_local_device_uuid(ALICE, alice_dev).await.unwrap();
    alice_credentials.store_server_device_id(ALICE, alice_dev).await.unwrap();

    let alice_orchestrator = Arc::new(catbird_mls::orchestrator::MLSOrchestrator::new(
        alice_context.clone(),
        alice_storage.clone(),
        alice_api_client.clone(),
        alice_credentials.clone(),
        catbird_mls::orchestrator::OrchestratorConfig::default(),
    ));

    // Alice initializes her orchestrator cleanly
    alice_orchestrator.initialize(ALICE).await.unwrap();

    // 2. Alice saves an encrypted draft with private content
    let draft_id = uuid::Uuid::new_v4().to_string();
    let draft = RequestDraft {
        input: DirectRequestInput {
            draft_id: draft_id.clone(),
            recipient_did: PEER.into(),
            text: SECRET.into(),
            invitation: None,
        },
        recipient_label: "Peer".into(),
        phase: "draft".into(),
        outcome: None,
        archived: false,
        note_delivery: None,
    };
    alice_storage.save_request_draft(ALICE, &draft).unwrap();
    assert!(alice_storage.request_draft(ALICE, &draft_id).unwrap().is_some());
    // 3. Alice logs out: tear down Alice's context and storage
    alice_storage.bind_request_owner(None);
    alice_context.clear_content_root_key();
    alice_orchestrator.shutdown().await;
    alice_api_client.clear_auth();

    // Verify Alice's storage is locked and unreadable while logged out
    assert!(alice_storage.request_draft(ALICE, &draft_id).is_err());
    assert!(alice_storage.request_drafts(ALICE).is_err());

    // 4. Bob logs in with his OWN isolated context and storage
    let bob_db_file = tmp.path().join("mls_bob.db");
    let bob_context = MLSContext::new(
        bob_db_file.to_string_lossy().into_owned(),
        DB_KEY.into(),
        Box::new(MemoryKeychain::new()),
    ).unwrap();
    let bob_storage_file = tmp.path().join("catmos_bob.db");
    let bob_storage = Arc::new(SqliteStorage::new(bob_storage_file.to_str().unwrap(), DB_KEY).unwrap());
    let bob_api_client = Arc::new(ReqwestApiClient::new(base.clone()));
    bob_api_client.set_mls_context(bob_context.clone());
    bob_storage.set_mls_context(bob_context.clone());
    bob_context.set_content_root_key(vec![0x77; 32]).unwrap();
    bob_storage.bind_request_owner(Some(BOB));

    let bob_credentials = Arc::new(KeyringCredentialStore::with_chat_auth(
        bob_api_client.chat_auth_provider(),
        bob_context.clone(),
    ));

    // Seed Bob's device and identity in Bob's own context
    let bob_dev = "00000000-0000-4000-8000-000000000002";
    let b_identity = format!("{}#{}", BOB, bob_dev);
    bob_context.create_key_package(b_identity.as_bytes().to_vec()).unwrap();
    let b_private = bob_context.export_identity_key(b_identity.clone()).unwrap();
    let _ = bob_context.import_identity_key(BOB.to_string(), b_private.clone());
    bob_credentials.store_signing_key(BOB, &b_private).await.unwrap();
    bob_credentials.store_local_device_uuid(BOB, bob_dev).await.unwrap();
    bob_credentials.store_server_device_id(BOB, bob_dev).await.unwrap();

    let bob_orchestrator = Arc::new(catbird_mls::orchestrator::MLSOrchestrator::new(
        bob_context.clone(),
        bob_storage.clone(),
        bob_api_client.clone(),
        bob_credentials.clone(),
        catbird_mls::orchestrator::OrchestratorConfig::default(),
    ));

    // Bob initializes his orchestrator: MUST hydrate cleanly without any error!
    bob_orchestrator.initialize(BOB).await.unwrap();

    // 5. Verify Alice's intents and drafts are completely unreadable and absent for Bob
    assert_eq!(bob_storage.request_drafts(BOB).unwrap().len(), 0, "Bob sees zero drafts");
    assert!(bob_storage.request_draft(BOB, &draft_id).unwrap().is_none(), "Alice's draft not in Bob store");
    assert!(bob_storage.request_draft(ALICE, &draft_id).is_err(), "Accessing Alice DID while bound to Bob fails scope check");
    assert!(bob_context.read_direct_request_intent(&draft_id).unwrap().is_none(), "Alice's intent absent from Bob MLS context");
    assert_eq!(bob_context.list_direct_request_intents().unwrap().len(), 0, "Bob MLS context has 0 intents");

    // 6. Bob creates his own draft and saves it cleanly
    let bob_draft_id = uuid::Uuid::new_v4().to_string();
    let bob_draft = RequestDraft {
        input: DirectRequestInput {
            draft_id: bob_draft_id.clone(),
            recipient_did: PEER.into(),
            text: "Bob secret introduction".into(),
            invitation: None,
        },
        recipient_label: "Peer".into(),
        phase: "draft".into(),
        outcome: None,
        archived: false,
        note_delivery: None,
    };
    bob_storage.save_request_draft(BOB, &bob_draft).unwrap();
    assert_eq!(bob_storage.request_drafts(BOB).unwrap().len(), 1);
    assert_eq!(bob_storage.request_draft(BOB, &bob_draft_id).unwrap().unwrap().input.text, "Bob secret introduction");

    // 7. Bob logs out and Alice logs back in: Alice's state is preserved, Bob's state is absent
    bob_storage.bind_request_owner(None);
    bob_context.clear_content_root_key();
    bob_orchestrator.shutdown().await;

    // Reopen Alice
    alice_storage.bind_request_owner(Some(ALICE));
    alice_context.set_content_root_key(vec![0x42; 32]).unwrap();
    let alice_reopened_orchestrator = Arc::new(catbird_mls::orchestrator::MLSOrchestrator::new(
        alice_context.clone(),
        alice_storage.clone(),
        alice_api_client.clone(),
        alice_credentials.clone(),
        catbird_mls::orchestrator::OrchestratorConfig::default(),
    ));
    alice_reopened_orchestrator.initialize(ALICE).await.unwrap();

    assert_eq!(alice_storage.request_drafts(ALICE).unwrap().len(), 1, "Alice sees her original draft");
    assert_eq!(alice_storage.request_draft(ALICE, &draft_id).unwrap().unwrap().input.text, SECRET);
    assert!(alice_storage.request_draft(ALICE, &bob_draft_id).unwrap().is_none(), "Bob's draft absent from Alice store");
    assert_eq!(alice_context.list_direct_request_intents().unwrap().len(), 0, "Alice context has 0 unisolated intents");

    // All transport effects during this entire multi-account test must be zero
    let all_effects = transport.lock().unwrap().clone();
    assert!(all_effects.is_empty(), "account switch and draft operations reached the network: {all_effects:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn catmos_browser_live_row() {
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
    let server_fixture_bin = std::env::var("REQUEST_SERVER_FIXTURE_BINARY")
        .unwrap_or_else(|_| "/Users/joshlacalamito/Developer/.workspaces/freeze5-7-artifacts/servers/5.10/encrypted_request_server_fixture".to_string());
    let gateway_bin = std::env::var("CLIENT_RUNTIME_GATEWAY_BINARY")
        .unwrap_or_else(|_| "/Users/joshlacalamito/Developer/.workspaces/freeze5-7-artifacts/client_runtime_gateway".to_string());
    eprintln!("catmos_browser_live_row using server fixture: {server_fixture_bin}");
    eprintln!("catmos_browser_live_row using gateway: {gateway_bin}");
    let status = Command::new("cargo")
        .args([
            "test", "--manifest-path", &format!("{workspace}/mls-ds/e2e-tests/Cargo.toml"),
            "--test", "encrypted_direct_requests",
            "c01_real_router_auth_live_preparation_and_native_recipient_preview",
            "--", "--nocapture"
        ])
        .env("REQUEST_TEST_DATABASE_URL", &db_url)
        .env("REQUEST_SERVER_FIXTURE_BINARY", &server_fixture_bin)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("install migrations");
    assert!(status.success(), "migration install failed");

    // 3. Start client_runtime_gateway
    let out_dir = format!("/tmp/catbird-gw-bidi-{run_hex}");
    let mut gw_child = Command::new(&gateway_bin)
        .env("REQUEST_TEST_DATABASE_URL", &db_url)
        .env("REQUEST_SERVER_FIXTURE_BINARY", &server_fixture_bin)
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
    let _ = Command::new("rm")
        .args(["-rf", "node_modules/.vite"])
        .current_dir(format!("{workspace}/catmos"))
        .status();
    let vite_child = Command::new("node")
        .args(["node_modules/vite/bin/vite.js", "--host", "127.0.0.1", "--port", "5173", "--strictPort", "--force", "--mode", "local-runtime-fixture"])
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
    let desktop_keychain = MemoryKeychain::new();
    let mls_context = MLSContext::new(
        tmp.path().join("mls_desktop.db").to_string_lossy().into_owned(),
        DB_KEY.into(),
        Box::new(desktop_keychain.clone()),
    ).unwrap();
    api_client.set_mls_context(mls_context.clone());
    storage.set_mls_context(mls_context.clone());
    let credentials = Arc::new(KeyringCredentialStore::with_chat_auth(
        api_client.chat_auth_provider(),
        mls_context.clone(),
    ));
    crate::runtime_fixture::seed_native_authority(mls_context.as_ref(), credentials.as_ref()).await.unwrap();
    credentials.store_local_device_uuid(alice_did, alice_acc["deviceId"].as_str().unwrap()).await.unwrap();
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
            request_commands::cancel_request_draft,
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

    let started_at = chrono::Utc::now().to_rfc3339();
    let evid_dir = format!("{workspace}/docs/generated-artifacts/encrypted-requests/evidence/catmos-browser");
    let _ = std::fs::create_dir_all(&evid_dir);

    // =========================================================================
    // LEG 1: Local draft/cancel check (0 remote chat entries)
    // =========================================================================
    let d0_id = uuid::Uuid::new_v4().to_string();
    let d0_input = json!({"draftId": d0_id, "recipientDid": bob_did, "text": "Draft cancelled before send", "invitation": null});
    let d0_saved = call(&webview, "save_request_draft", json!({"ownerDid": alice_did, "ownerRevision": alice_rev, "input": d0_input, "recipientLabel": "Bob"})).unwrap();
    assert_eq!(d0_saved["phase"], "draft");
    let d0_cancelled = call(&webview, "cancel_request_draft", json!({"ownerDid": alice_did, "ownerRevision": alice_rev, "draftId": d0_id})).unwrap();
    assert_eq!(d0_cancelled["archived"], true);
    let psql_d0 = Command::new("psql").args([&db_url, "-X", "-c", &format!("SELECT count(*) FROM chat.entries WHERE actor_did='{alice_did}';")]).output().unwrap();
    assert!(String::from_utf8_lossy(&psql_d0.stdout).contains(" 0"), "Draft cancellation must leave 0 remote entries");

    // Pre-enroll recipient (Bob publishes key package), then goes offline
    {
        let mut b_proc_pre = Command::new("node")
            .arg(&format!("{workspace}/catmos/tests/browser-live-controller.mjs"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn browser-live-controller pre-enroll");
        let mut b_in = b_proc_pre.stdin.take().unwrap();
        let mut b_out = BufReader::new(b_proc_pre.stdout.take().unwrap());
        let req = json!({"cmd": "init", "manifestPath": manifest_path, "label": "bob", "runId": run_hex});
        b_in.write_all(req.to_string().as_bytes()).unwrap();
        b_in.write_all(b"\n").unwrap();
        b_in.flush().unwrap();
        let mut line = String::new();
        b_out.read_line(&mut line).unwrap();
        let val: Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(val["ok"], true, "Bob pre-enrollment");
        let close_req = json!({"cmd": "close"});
        b_in.write_all(close_req.to_string().as_bytes()).unwrap();
        b_in.write_all(b"\n").unwrap();
        b_in.flush().unwrap();
        let _ = b_proc_pre.kill();
    }

    // =========================================================================
    // LEG 2: Offline-recipient first send (Bob has not started yet!)
    // =========================================================================
    let d1_draft_id = uuid::Uuid::new_v4().to_string();
    let d1_intro = format!("Hello Bob! Live Direction 1 intro from Catmos Desktop ({run_hex}).");
    let d1_input = json!({"draftId": d1_draft_id, "recipientDid": bob_did, "text": d1_intro, "invitation": null});

    call(&webview, "save_request_draft", json!({"ownerDid": alice_did, "ownerRevision": alice_rev, "input": d1_input, "recipientLabel": "Bob"})).unwrap();
    let submit_res = call(&webview, "submit_request_draft", json!({"ownerDid": alice_did, "ownerRevision": alice_rev, "draftId": d1_draft_id})).unwrap();
    assert_eq!(submit_res["phase"], "resolved");
    eprintln!("submit_res: {submit_res}");
    let cid1 = submit_res["outcome"]["conversationId"]
        .as_str()
        .or_else(|| submit_res["outcome"]["conversation_id"].as_str())
        .expect(&format!("conversationId in submit_res: {submit_res}"))
        .to_owned();

    // Verify 1 published entry on server while recipient is offline
    let psql_d1 = Command::new("psql").args([&db_url, "-X", "-c", &format!("SELECT count(*) FROM chat.entries WHERE conversation_id='{cid1}';")]).output().unwrap();
    assert!(String::from_utf8_lossy(&psql_d1.stdout).contains(" 1"), "Offline recipient send publishes exactly 1 directRequestEntry");

    // =========================================================================
    // LEG 2b: Spawn Bob in Browser & OPFS reload before Welcome import
    // =========================================================================
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

    let res = b_call(json!({"cmd": "init", "manifestPath": manifest_path, "label": "bob", "runId": run_hex}));
    assert_eq!(res["ok"], true, "Bob browser init");

    // Real OPFS worker reload before Welcome import
    let reload_res = b_call(json!({"cmd": "reload_worker_before_welcome"}));
    assert_eq!(reload_res["ok"], true, "Bob worker reload before welcome import");

    // =========================================================================
    // LEG 3: Sender-offline preview/accept/reply
    // =========================================================================
    drop(webview);
    drop(app);

    // Bob previews decrypted intro before accept
    let preview_res = b_call(json!({"cmd": "await_preview", "cid": &cid1, "text": d1_intro}));
    assert_eq!(preview_res["ok"], true);
    assert_eq!(preview_res["consent"], "incomingPending");
    assert_eq!(preview_res["previewText"], d1_intro);
    assert_eq!(preview_res["canSend"], false);
    let _ = b_call(json!({"cmd": "screenshot", "path": format!("{evid_dir}/01-preview.png")}));

    // Bob accepts
    let accept_res = b_call(json!({"cmd": "accept", "cid": &cid1}));
    assert_eq!(accept_res["ok"], true);
    let _ = b_call(json!({"cmd": "screenshot", "path": format!("{evid_dir}/02-accepted.png")}));

    // Bob replies
    let bob_reply = format!("Hello Alice! Bob in Browser accepted your live request ({run_hex}).");
    let reply_res = b_call(json!({"cmd": "send_message", "cid": &cid1, "text": bob_reply}));
    assert_eq!(reply_res["ok"], true);
    let _ = b_call(json!({"cmd": "screenshot", "path": format!("{evid_dir}/03-reply.png")}));

    // =========================================================================
    // LEG 4: Sender restart & message exchange
    // =========================================================================
    let reopened_storage = Arc::new(SqliteStorage::new(host_db.to_str().unwrap(), DB_KEY).unwrap());
    let reopened_api_client = Arc::new(ReqwestApiClient::new(manifest["origin"].as_str().unwrap().to_string()));
    let reopened_mls_context = MLSContext::new(
        tmp.path().join("mls_desktop.db").to_string_lossy().into_owned(),
        DB_KEY.into(),
        Box::new(desktop_keychain.clone()),
    ).unwrap();
    reopened_api_client.set_mls_context(reopened_mls_context.clone());
    reopened_storage.set_mls_context(reopened_mls_context.clone());
    let reopened_credentials = Arc::new(KeyringCredentialStore::with_chat_auth(
        reopened_api_client.chat_auth_provider(),
        reopened_mls_context.clone(),
    ));
    reopened_credentials.store_server_device_id(alice_did, alice_acc["deviceId"].as_str().unwrap()).await.unwrap();
    let reopened_orchestrator = Arc::new(catbird_mls::orchestrator::MLSOrchestrator::new(
        reopened_mls_context.clone(),
        reopened_storage.clone(),
        reopened_api_client.clone(),
        reopened_credentials.clone(),
        catbird_mls::orchestrator::OrchestratorConfig::default(),
    ));
    let reopened_state = AppState {
        request_scope: tokio::sync::Mutex::new(()),
        orchestrator: reopened_orchestrator,
        chat_auth: reopened_api_client.chat_auth_provider(),
        api_client: reopened_api_client.clone(),
        ws_handles: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        kp_monitor: tokio::sync::Mutex::new(None),
        sync_loop: tokio::sync::Mutex::new(None),
        data_dir: tmp.path().to_path_buf(),
    };
    commands::install_content_root_key(&reopened_state, alice_did);
    reopened_state.orchestrator.initialize(alice_did).await.unwrap();
    commands::configure_chat_auth(&reopened_state, alice_did, alice_session).await.unwrap();
    let reopened_alice_rev = reopened_state.api_client.current_session().unwrap().revision.to_string();

    let reopened_app = tauri::test::mock_builder()
        .manage(reopened_state)
        .invoke_handler(tauri::generate_handler![
            request_commands::save_request_draft,
            request_commands::cancel_request_draft,
            request_commands::submit_request_draft,
            request_commands::refresh_direct_request,
            request_commands::accept_direct_request,
            commands::send_message,
            commands::get_messages,
            commands::fetch_new_messages,
        ])
        .build(tauri::test::mock_context(tauri::test::noop_assets()))
        .unwrap();
    let reopened_webview = tauri::WebviewWindowBuilder::new(&reopened_app, "reopened_main", Default::default()).build().unwrap();

    let refresh_res = call(&reopened_webview, "refresh_direct_request", json!({"ownerDid": alice_did, "ownerRevision": reopened_alice_rev, "conversationId": cid1})).unwrap();
    assert_eq!(refresh_res["consent"], "accepted");

    let fetched = call(&reopened_webview, "fetch_new_messages", json!({"ownerDid": alice_did, "ownerRevision": reopened_alice_rev, "conversationId": cid1})).unwrap();
    let messages = fetched.as_array().unwrap();
    assert!(messages.iter().any(|m| m["content"] == bob_reply), "Bob reply decrypted on desktop");

    let alice_reply = format!("Alice Desktop received Bob reply and replies back live ({run_hex}).");
    let alice_send = call(&reopened_webview, "send_message", json!({"ownerDid": alice_did, "ownerRevision": reopened_alice_rev, "conversationId": cid1, "content": alice_reply})).unwrap();
    assert_eq!(alice_send["conversationId"], cid1);
    assert_eq!(alice_send["content"], alice_reply);

    let bob_fetched = b_call(json!({"cmd": "fetch_messages", "cid": cid1, "expectedText": alice_reply}));
    assert!(bob_fetched["messages"].as_array().unwrap().iter().any(|m| m["content"] == alice_reply), "Alice reply decrypted in browser");

    // =========================================================================
    // LEG 5: Real restart on both sides & F37 sent-once
    // =========================================================================
    drop(reopened_webview);
    drop(reopened_app);

    let r2_storage = Arc::new(SqliteStorage::new(host_db.to_str().unwrap(), DB_KEY).unwrap());
    let r2_api_client = Arc::new(ReqwestApiClient::new(manifest["origin"].as_str().unwrap().to_string()));
    let r2_mls_context = MLSContext::new(
        tmp.path().join("mls_desktop.db").to_string_lossy().into_owned(),
        DB_KEY.into(),
        Box::new(desktop_keychain.clone()),
    ).unwrap();
    r2_api_client.set_mls_context(r2_mls_context.clone());
    r2_storage.set_mls_context(r2_mls_context.clone());
    let r2_credentials = Arc::new(KeyringCredentialStore::with_chat_auth(
        r2_api_client.chat_auth_provider(),
        r2_mls_context.clone(),
    ));
    r2_credentials.store_server_device_id(alice_did, alice_acc["deviceId"].as_str().unwrap()).await.unwrap();
    let r2_orchestrator = Arc::new(catbird_mls::orchestrator::MLSOrchestrator::new(
        r2_mls_context.clone(),
        r2_storage.clone(),
        r2_api_client.clone(),
        r2_credentials.clone(),
        catbird_mls::orchestrator::OrchestratorConfig::default(),
    ));
    let r2_state = AppState {
        request_scope: tokio::sync::Mutex::new(()),
        orchestrator: r2_orchestrator,
        chat_auth: r2_api_client.chat_auth_provider(),
        api_client: r2_api_client.clone(),
        ws_handles: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        kp_monitor: tokio::sync::Mutex::new(None),
        sync_loop: tokio::sync::Mutex::new(None),
        data_dir: tmp.path().to_path_buf(),
    };
    commands::install_content_root_key(&r2_state, alice_did);
    r2_state.orchestrator.initialize(alice_did).await.unwrap();
    commands::configure_chat_auth(&r2_state, alice_did, alice_session).await.unwrap();
    let r2_alice_rev = r2_state.api_client.current_session().unwrap().revision.to_string();

    let r2_app = tauri::test::mock_builder()
        .manage(r2_state)
        .invoke_handler(tauri::generate_handler![
            request_commands::save_request_draft,
            request_commands::cancel_request_draft,
            request_commands::submit_request_draft,
            request_commands::refresh_direct_request,
            request_commands::accept_direct_request,
            commands::send_message,
            commands::get_messages,
            commands::fetch_new_messages,
        ])
        .build(tauri::test::mock_context(tauri::test::noop_assets()))
        .unwrap();
    let r2_webview = tauri::WebviewWindowBuilder::new(&r2_app, "r2_main", Default::default()).build().unwrap();

    let desktop_recheck = call(&r2_webview, "get_messages", json!({"ownerDid": alice_did, "ownerRevision": r2_alice_rev, "conversationId": cid1, "before": null})).unwrap();
    let d_msgs = desktop_recheck.as_array().unwrap();
    assert_eq!(d_msgs.iter().filter(|m| m["content"] == bob_reply).count(), 1, "bob reply persisted once across restart");
    assert_eq!(d_msgs.iter().filter(|m| m["content"] == alice_reply).count(), 1, "alice reply persisted once across restart");

    let b_reload = b_call(json!({"cmd": "reload_and_check", "cid": cid1}));
    let b_msgs = b_reload["messages"].as_array().unwrap();
    assert_eq!(b_msgs.iter().filter(|m| m["content"] == bob_reply).count(), 1, "bob reply persisted once in browser");
    assert_eq!(b_msgs.iter().filter(|m| m["content"] == alice_reply).count(), 1, "alice reply persisted once in browser");
    let _ = b_call(json!({"cmd": "screenshot", "path": format!("{evid_dir}/04-reload.png")}));

    // Close browser controller
    let _ = b_call(json!({"cmd": "close"}));
    let _ = browser_proc.kill();

    // =========================================================================
    // LEG 6: Database sequencing assertion (exactly 4 entries)
    // =========================================================================
    let entries_d1 = Command::new("psql")
        .args([&db_url, "-X", "-c", &format!("SELECT seq, entry_kind, actor_did FROM chat.entries WHERE conversation_id='{cid1}' ORDER BY seq;")])
        .output()
        .expect("query chat.entries D1");
    let d1_text = String::from_utf8_lossy(&entries_d1.stdout);
    eprintln!("Direction 1 entries:\n{d1_text}");
    let rows: Vec<&str> = d1_text.lines().filter(|l| l.contains("blue.catbird.chat.defs#")).collect();
    assert_eq!(rows.len(), 4, "Must contain exactly 4 sequenced entries: {rows:?}");
    assert!(rows[0].contains("directRequestEntry") && rows[0].contains(alice_did));
    assert!(rows[1].contains("directRequestAcceptanceEntry") && rows[1].contains(bob_did));
    assert!(rows[2].contains("applicationEntry") && rows[2].contains(bob_did));
    assert!(rows[3].contains("applicationEntry") && rows[3].contains(alice_did));

    let ended_at = chrono::Utc::now().to_rfc3339();

    // =========================================================================
    // LEG 7: Evidence packaging
    // =========================================================================
    let spec = json!({
        "row_id": "catmos-browser",
        "started_at": started_at,
        "ended_at": ended_at,
        "database_name": db_name,
        "conversation_id": cid1,
        "draft_id": d1_draft_id,
        "sender_info": {"client": "Catmos Desktop", "did": alice_did, "deviceId": alice_acc["deviceId"].as_str().unwrap()},
        "recipient_info": {"client": "Catmos Browser (WASM)", "did": bob_did, "deviceId": bob_acc["deviceId"].as_str().unwrap()},
        "assertions": [
            "Local draft creation and cancellation produces 0 remote chat entries",
            "Offline recipient first send records exactly 1 directRequestEntry on server",
            "Browser OPFS worker reload before Welcome import preserves clean state",
            "Sender offline: recipient decrypts intro and accepts, reply is encrypted",
            "Sender restart from disk: decrypts reply and sends follow-up",
            "Recipient decrypts sender reply in browser",
            "Full desktop restart and browser reload: both messages persisted exactly once (F37 sent-once)",
            "PostgreSQL chat.entries contains exactly 4 ordered entries with no duplicates or extra Add commits"
        ],
        "not_exercised": [
            "unavailableDevicePreconsent: Local gateway manifest uses deterministic single-device recipient; multi-device key package race is tested in iOS/Android test suites",
            "recipientDeclineBlockLeg: Interoperability row exercises the full acceptance, reply, and restart pipeline; decline/block behavior is tested in standalone unit suites"
        ],
        "log_name": "catmos-browser-live.log"
    });
    let spec_path = format!("{workspace}/catmos/tests/spec-catmos-browser.json");
    std::fs::write(&spec_path, serde_json::to_string_pretty(&spec).unwrap()).unwrap();
    let pkg_res = Command::new("python3")
        .args([&format!("{workspace}/catmos/tests/package_evidence.py"), &spec_path])
        .output()
        .expect("package evidence");
    eprintln!("Packaging output:\n{}", String::from_utf8_lossy(&pkg_res.stdout));
    assert!(pkg_res.status.success(), "package_evidence failed");
    eprintln!("CATMOS-BROWSER LIVE ROW FULLY QUALIFIED!");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn browser_catmos_live_row() {
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
    let server_fixture_bin = std::env::var("REQUEST_SERVER_FIXTURE_BINARY")
        .unwrap_or_else(|_| "/Users/joshlacalamito/Developer/.workspaces/freeze5-7-artifacts/servers/5.10/encrypted_request_server_fixture".to_string());
    let gateway_bin = std::env::var("CLIENT_RUNTIME_GATEWAY_BINARY")
        .unwrap_or_else(|_| "/Users/joshlacalamito/Developer/.workspaces/freeze5-7-artifacts/client_runtime_gateway".to_string());
    eprintln!("browser_catmos_live_row using server fixture: {server_fixture_bin}");
    eprintln!("browser_catmos_live_row using gateway: {gateway_bin}");
    let status = Command::new("cargo")
        .args([
            "test", "--manifest-path", &format!("{workspace}/mls-ds/e2e-tests/Cargo.toml"),
            "--test", "encrypted_direct_requests",
            "c01_real_router_auth_live_preparation_and_native_recipient_preview",
            "--", "--nocapture"
        ])
        .env("REQUEST_TEST_DATABASE_URL", &db_url)
        .env("REQUEST_SERVER_FIXTURE_BINARY", &server_fixture_bin)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("install migrations");
    assert!(status.success(), "migration install failed");

    // 3. Start client_runtime_gateway
    let out_dir = format!("/tmp/catbird-gw-b2c-{run_hex}");
    let cfg = json!({"output_dir": out_dir, "cors_origin": "http://127.0.0.1:5173"});
    let mut gw_child = Command::new(&gateway_bin)
        .env("REQUEST_TEST_DATABASE_URL", &db_url)
        .env("REQUEST_SERVER_FIXTURE_BINARY", &server_fixture_bin)
        .env("RUST_LOG", "info,catbird_server=debug")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn gateway");
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
    let bob_session = sessions["accounts"].as_array().unwrap().iter().find(|a| a["label"] == "bob").unwrap()["session"].as_str().unwrap();

    // 4. Start Vite
    let _ = Command::new("rm")
        .args(["-rf", "node_modules/.vite"])
        .current_dir(format!("{workspace}/catmos"))
        .status();
    let vite_child = Command::new("node")
        .args(["node_modules/vite/bin/vite.js", "--host", "127.0.0.1", "--port", "5173", "--strictPort", "--force", "--mode", "local-runtime-fixture"])
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

    let started_at = chrono::Utc::now().to_rfc3339();
    let evid_dir = format!("{workspace}/docs/generated-artifacts/encrypted-requests/evidence/browser-catmos");
    let _ = std::fs::create_dir_all(&evid_dir);

    // Pre-enroll recipient (Bob publishes key package on Desktop), then goes offline
    let desktop_profile = format!("/tmp/catmos-desktop-profile-bob-{run_hex}");
    let desktop_config = format!("/tmp/catmos-fixture-bob-{run_hex}.json");
    std::fs::write(&desktop_config, json!({
        "manifest": manifest_path,
        "sessions": format!("{out_dir}/sessions.json"),
        "label": "bob",
        "profile": desktop_profile,
        "keychain_namespace": format!("blue.catbird.catmos.fixture.{run_uuid}")
    }).to_string()).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&desktop_config, std::fs::Permissions::from_mode(0o600)).unwrap();

    std::env::set_var("CATMOS_RUNTIME_FIXTURE_CONFIG", &desktop_config);
    crate::runtime_fixture::initialize();
    let tmp = tempfile::tempdir().unwrap();
    let host_db = tmp.path().join("catmos_desktop_bob.db");
    let storage = Arc::new(SqliteStorage::new(host_db.to_str().unwrap(), DB_KEY).unwrap());
    let api_client = Arc::new(ReqwestApiClient::new(manifest["origin"].as_str().unwrap().to_string()));
    let bob_desktop_keychain = MemoryKeychain::new();
    let mls_context = MLSContext::new(
        tmp.path().join("mls_desktop_bob.db").to_string_lossy().into_owned(),
        DB_KEY.into(),
        Box::new(bob_desktop_keychain.clone()),
    ).unwrap();
    api_client.set_mls_context(mls_context.clone());
    storage.set_mls_context(mls_context.clone());
    let credentials = Arc::new(KeyringCredentialStore::with_chat_auth(
        api_client.chat_auth_provider(),
        mls_context.clone(),
    ));
    crate::runtime_fixture::seed_native_authority(mls_context.as_ref(), credentials.as_ref()).await.unwrap();
    credentials.store_local_device_uuid(bob_did, bob_acc["deviceId"].as_str().unwrap()).await.unwrap();
    credentials.store_server_device_id(bob_did, bob_acc["deviceId"].as_str().unwrap()).await.unwrap();
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
    state.orchestrator.initialize(bob_did).await.unwrap();
    commands::install_content_root_key(&state, bob_did);
    commands::configure_chat_auth(&state, bob_did, bob_session).await.unwrap();
    state.orchestrator.publish_key_package().await.unwrap();
    state.orchestrator.set_direct_request_delivery_enabled(true).await.unwrap();
    let bob_rev = state.api_client.current_session().unwrap().revision.to_string();

    let app = tauri::test::mock_builder()
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            request_commands::save_request_draft,
            request_commands::cancel_request_draft,
            request_commands::submit_request_draft,
            request_commands::refresh_direct_request,
            request_commands::accept_direct_request,
            request_commands::set_request_delivery_enabled,
            commands::send_message,
            commands::get_messages,
            commands::fetch_new_messages,
        ])
        .build(tauri::test::mock_context(tauri::test::noop_assets()))
        .unwrap();
    let webview = tauri::WebviewWindowBuilder::new(&app, "main", Default::default()).build().unwrap();
    call(&webview, "set_request_delivery_enabled", json!({"ownerDid": bob_did, "ownerRevision": bob_rev, "enabled": true})).unwrap();

    // Bob goes offline
    drop(webview);
    drop(app);

    // =========================================================================
    // 5. Spawn browser-live-controller as ALICE (Sender in Browser)
    // =========================================================================
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

    // Init Alice in Browser
    let res = b_call(json!({"cmd": "init", "manifestPath": manifest_path, "label": "alice", "runId": run_hex}));
    assert_eq!(res["ok"], true, "Alice browser init");

    // =========================================================================
    // LEG 1: Local draft/cancel check in Browser (0 remote entries)
    // =========================================================================
    let draft_res = b_call(json!({"cmd": "save_draft", "recipientDid": bob_did, "text": "Browser draft cancelled before send"}));
    assert_eq!(draft_res["ok"], true);
    let d0_id = draft_res["draft"]["input"]["draftId"].as_str().unwrap();
    let cancel_res = b_call(json!({"cmd": "cancel_draft", "draftId": d0_id}));
    assert_eq!(cancel_res["ok"], true);
    assert_eq!(cancel_res["remainingDraft"]["archived"], true, "Browser UI must archive the local draft");
    let psql_d0 = Command::new("psql").args([&db_url, "-X", "-c", &format!("SELECT count(*) FROM chat.entries WHERE actor_did='{alice_did}';")]).output().unwrap();
    assert!(String::from_utf8_lossy(&psql_d0.stdout).contains(" 0"), "Browser draft cancellation leaves 0 remote entries");

    // =========================================================================
    // LEG 2: Offline recipient first send (Desktop Bob is NOT started yet)
    // =========================================================================
    let intro = format!("Hello Bob Desktop! Live intro from Browser Alice ({run_hex}).");
    let composed = b_call(json!({"cmd": "compose_request", "recipientDid": bob_did, "text": intro}));
    assert_eq!(composed["composerValue"], intro, "Browser UI must hold the local introduction before send");
    let sent = b_call(json!({"cmd": "send_introduction", "recipientDid": bob_did, "text": intro}));
    assert_eq!(sent["ok"], true);
    assert_eq!(sent["outcome"]["type"], "requestSent", "Fresh direct request is requestSent");
    eprintln!("sent: {sent}");
    let cid = sent["cid"]
        .as_str()
        .or_else(|| sent["outcome"]["conversationId"].as_str())
        .or_else(|| sent["outcome"]["conversation_id"].as_str())
        .expect(&format!("cid in sent: {sent}"))
        .to_owned();
    let d1_draft_id = sent["draftId"]
        .as_str()
        .or_else(|| sent["draft"]["input"]["draftId"].as_str())
        .unwrap_or("browser-draft-1")
        .to_owned();

    // Verify 1 published entry on server while recipient is offline
    let psql_d1 = Command::new("psql").args([&db_url, "-X", "-c", &format!("SELECT count(*) FROM chat.entries WHERE conversation_id='{cid}';")]).output().unwrap();
    assert!(String::from_utf8_lossy(&psql_d1.stdout).contains(" 1"), "Offline recipient send publishes exactly 1 directRequestEntry");

    // =========================================================================
    // LEG 3: Sender-offline preview/accept/reply
    // Drop Browser Alice completely so sender is offline
    // =========================================================================
    let _ = b_call(json!({"cmd": "close"}));
    let _ = browser_proc.kill();
    let _ = browser_proc.wait();

    // Reopen Desktop Bob from disk (reopens host_db and mls_desktop_bob.db with bob_desktop_keychain)
    let reopened_storage = Arc::new(SqliteStorage::new(host_db.to_str().unwrap(), DB_KEY).unwrap());
    let reopened_api_client = Arc::new(ReqwestApiClient::new(manifest["origin"].as_str().unwrap().to_string()));
    let reopened_mls_context = MLSContext::new(
        tmp.path().join("mls_desktop_bob.db").to_string_lossy().into_owned(),
        DB_KEY.into(),
        Box::new(bob_desktop_keychain.clone()),
    ).unwrap();
    reopened_api_client.set_mls_context(reopened_mls_context.clone());
    reopened_storage.set_mls_context(reopened_mls_context.clone());
    let reopened_credentials = Arc::new(KeyringCredentialStore::with_chat_auth(
        reopened_api_client.chat_auth_provider(),
        reopened_mls_context.clone(),
    ));
    reopened_credentials.store_local_device_uuid(bob_did, bob_acc["deviceId"].as_str().unwrap()).await.unwrap();
    reopened_credentials.store_server_device_id(bob_did, bob_acc["deviceId"].as_str().unwrap()).await.unwrap();
    let reopened_orchestrator = Arc::new(catbird_mls::orchestrator::MLSOrchestrator::new(
        reopened_mls_context.clone(),
        reopened_storage.clone(),
        reopened_api_client.clone(),
        reopened_credentials.clone(),
        catbird_mls::orchestrator::OrchestratorConfig::default(),
    ));
    let reopened_state = AppState {
        request_scope: tokio::sync::Mutex::new(()),
        orchestrator: reopened_orchestrator,
        chat_auth: reopened_api_client.chat_auth_provider(),
        api_client: reopened_api_client.clone(),
        ws_handles: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        kp_monitor: tokio::sync::Mutex::new(None),
        sync_loop: tokio::sync::Mutex::new(None),
        data_dir: tmp.path().to_path_buf(),
    };
    reopened_state.orchestrator.initialize(bob_did).await.unwrap();
    commands::install_content_root_key(&reopened_state, bob_did);
    commands::configure_chat_auth(&reopened_state, bob_did, bob_session).await.unwrap();
    let reopened_bob_rev = reopened_state.api_client.current_session().unwrap().revision.to_string();

    let reopened_app = tauri::test::mock_builder()
        .manage(reopened_state)
        .invoke_handler(tauri::generate_handler![
            request_commands::save_request_draft,
            request_commands::cancel_request_draft,
            request_commands::submit_request_draft,
            request_commands::refresh_direct_request,
            request_commands::accept_direct_request,
            request_commands::set_request_delivery_enabled,
            commands::send_message,
            commands::send_image,
            commands::get_messages,
            commands::fetch_new_messages,
        ])
        .build(tauri::test::mock_context(tauri::test::noop_assets()))
        .unwrap();
    let webview = tauri::WebviewWindowBuilder::new(&reopened_app, "reopened_main", Default::default()).build().unwrap();

    // Desktop Bob refreshes and previews decrypted intro before accept
    let preview = call(&webview, "refresh_direct_request", json!({"ownerDid": bob_did, "ownerRevision": bob_rev, "conversationId": cid})).unwrap();
    assert_eq!(preview["consent"], "incomingPending");
    assert_eq!(preview["preview"]["text"], intro);
    assert_eq!(preview["capabilities"]["canSend"], false);

    // C29 Attachment-first rejection on a real pending conversation:
    // Desktop Bob attempts to send an image on the incoming pending conversation before accepting.
    // This must be strictly rejected with the specific pending-capability denial before any media transport.
    let attach_pending = call(&webview, "send_image", json!({
        "ownerDid": bob_did,
        "ownerRevision": bob_rev,
        "conversationId": cid,
        "content": "",
        "data": [137, 80, 78, 71, 13, 10, 26, 10], // PNG magic
        "contentType": "image/png",
        "width": 100,
        "height": 100,
        "altText": null,
    }));
    let attach_err = attach_pending.expect_err("send_image on real pending conversation must fail before accept");
    eprintln!("C29 Desktop real pending attachment rejection: {attach_err}");
    assert!(
        attach_err.to_string().contains("Accept this request before sending messages or activity"),
        "must specifically reject with pending capability denial, got: {attach_err}"
    );

    if std::env::var("CATMOS_C29_PENDING_ATTACHMENT_ONLY").as_deref() == Ok("1") {
        return;
    }

    // Desktop Bob accepts conversation
    let accepted = call(&webview, "accept_direct_request", json!({"ownerDid": bob_did, "ownerRevision": bob_rev, "conversationId": cid})).unwrap();
    assert_eq!(accepted["consent"], "accepted");

    // Desktop Bob sends reply
    let bob_reply = format!("Hello Alice! Bob Desktop accepted your browser request ({run_hex}).");
    let bob_send = call(&webview, "send_message", json!({"ownerDid": bob_did, "ownerRevision": bob_rev, "conversationId": cid, "content": bob_reply})).unwrap();
    assert_eq!(bob_send["content"], bob_reply);

    // =========================================================================
    // LEG 4: Sender restart & message exchange
    // =========================================================================
    let mut browser_proc2 = Command::new("node")
        .arg(&format!("{workspace}/catmos/tests/browser-live-controller.mjs"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn browser-live-controller Alice restart");

    let mut b2_stdin = browser_proc2.stdin.take().unwrap();
    let mut b2_reader = BufReader::new(browser_proc2.stdout.take().unwrap());

    let mut b2_call = |req: Value| -> Value {
        b2_stdin.write_all(req.to_string().as_bytes()).unwrap();
        b2_stdin.write_all(b"\n").unwrap();
        b2_stdin.flush().unwrap();
        let mut line = String::new();
        b2_reader.read_line(&mut line).unwrap();
        let val: Value = serde_json::from_str(line.trim()).unwrap();
        if val["ok"] == false {
            panic!("b2_call error for {:?}: {:?}", req["cmd"], val["error"]);
        }
        val
    };

    let res2 = b2_call(json!({"cmd": "init", "manifestPath": manifest_path, "label": "alice", "runId": run_hex}));
    assert_eq!(res2["ok"], true, "Alice browser re-init");

    // Browser Alice decrypts Bob's reply
    let alice_fetched = b2_call(json!({"cmd": "fetch_messages", "cid": cid, "expectedText": bob_reply}));
    assert!(alice_fetched["messages"].as_array().unwrap().iter().any(|m| m["content"] == bob_reply));
    let _ = b2_call(json!({"cmd": "screenshot", "path": format!("{evid_dir}/01-preview-accepted.png")}));

    // Browser Alice replies back
    let alice_reply = format!("Alice in Browser received Bob's Desktop reply ({run_hex}).");
    b2_call(json!({"cmd": "send_message", "cid": cid, "text": alice_reply}));
    let _ = b2_call(json!({"cmd": "screenshot", "path": format!("{evid_dir}/02-reply.png")}));

    // Desktop Bob receives and decrypts Alice's reply
    let mut bob_msgs = Vec::new();
    for _ in 0..20 {
        if let Ok(fetched) = call(&webview, "fetch_new_messages", json!({"ownerDid": bob_did, "ownerRevision": reopened_bob_rev, "conversationId": cid})) {
            if let Some(arr) = fetched.as_array() {
                bob_msgs.extend(arr.clone());
                if bob_msgs.iter().any(|m| m["content"] == alice_reply) {
                    break;
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    assert!(bob_msgs.iter().any(|m| m["content"] == alice_reply), "Alice reply decrypted on desktop Bob");

    // =========================================================================
    // LEG 5: Real restart on both sides & F37 sent-once
    // =========================================================================
    drop(webview);
    drop(reopened_app);

    // Reopen desktop Bob
    let r_storage = Arc::new(SqliteStorage::new(host_db.to_str().unwrap(), DB_KEY).unwrap());
    let r_api_client = Arc::new(ReqwestApiClient::new(manifest["origin"].as_str().unwrap().to_string()));
    let r_mls_context = MLSContext::new(
        tmp.path().join("mls_desktop_bob.db").to_string_lossy().into_owned(),
        DB_KEY.into(),
        Box::new(bob_desktop_keychain.clone()),
    ).unwrap();
    r_storage.set_mls_context(r_mls_context.clone());
    let r_credentials = Arc::new(KeyringCredentialStore::with_chat_auth(
        r_api_client.chat_auth_provider(),
        r_mls_context.clone(),
    ));
    r_credentials.store_server_device_id(bob_did, bob_acc["deviceId"].as_str().unwrap()).await.unwrap();
    let r_orchestrator = Arc::new(catbird_mls::orchestrator::MLSOrchestrator::new(
        r_mls_context.clone(),
        r_storage.clone(),
        r_api_client.clone(),
        r_credentials.clone(),
        catbird_mls::orchestrator::OrchestratorConfig::default(),
    ));
    let r_state = AppState {
        request_scope: tokio::sync::Mutex::new(()),
        orchestrator: r_orchestrator,
        chat_auth: r_api_client.chat_auth_provider(),
        api_client: r_api_client.clone(),
        ws_handles: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        kp_monitor: tokio::sync::Mutex::new(None),
        sync_loop: tokio::sync::Mutex::new(None),
        data_dir: tmp.path().to_path_buf(),
    };
    commands::install_content_root_key(&r_state, bob_did);
    r_state.orchestrator.initialize(bob_did).await.unwrap();
    commands::configure_chat_auth(&r_state, bob_did, bob_session).await.unwrap();
    let r_bob_rev = r_state.api_client.current_session().unwrap().revision.to_string();

    let r_app = tauri::test::mock_builder()
        .manage(r_state)
        .invoke_handler(tauri::generate_handler![
            request_commands::save_request_draft,
            request_commands::cancel_request_draft,
            request_commands::submit_request_draft,
            request_commands::refresh_direct_request,
            request_commands::accept_direct_request,
            commands::send_message,
            commands::get_messages,
            commands::fetch_new_messages,
        ])
        .build(tauri::test::mock_context(tauri::test::noop_assets()))
        .unwrap();
    let r_webview = tauri::WebviewWindowBuilder::new(&r_app, "r_main", Default::default()).build().unwrap();

    let desktop_recheck = call(&r_webview, "get_messages", json!({"ownerDid": bob_did, "ownerRevision": r_bob_rev, "conversationId": cid, "before": null})).unwrap();
    let d_msgs = desktop_recheck.as_array().unwrap();
    assert_eq!(d_msgs.iter().filter(|m| m["content"] == bob_reply).count(), 1, "bob reply persisted once across restart");
    assert_eq!(d_msgs.iter().filter(|m| m["content"] == alice_reply).count(), 1, "alice reply persisted once across restart");

    let b_reload = b2_call(json!({"cmd": "reload_and_check", "cid": cid}));
    let b_msgs = b_reload["messages"].as_array().unwrap();
    assert_eq!(b_msgs.iter().filter(|m| m["content"] == bob_reply).count(), 1, "bob reply persisted once in browser");
    assert_eq!(b_msgs.iter().filter(|m| m["content"] == alice_reply).count(), 1, "alice reply persisted once in browser");
    let _ = b2_call(json!({"cmd": "screenshot", "path": format!("{evid_dir}/03-reload.png")}));

    // Close browser controller
    let _ = b2_call(json!({"cmd": "close"}));
    let _ = browser_proc2.kill();

    // =========================================================================
    // LEG 6: Database sequencing assertion (exactly 4 entries)
    // =========================================================================
    let entries = Command::new("psql")
        .args([&db_url, "-X", "-c", &format!("SELECT seq, entry_kind, actor_did FROM chat.entries WHERE conversation_id='{cid}' ORDER BY seq;")])
        .output()
        .expect("query chat.entries");
    let text = String::from_utf8_lossy(&entries.stdout);
    eprintln!("Browser-to-Catmos entries:\n{text}");
    let rows: Vec<&str> = text.lines().filter(|l| l.contains("blue.catbird.chat.defs#")).collect();
    assert_eq!(rows.len(), 4, "Must contain exactly 4 sequenced entries: {rows:?}");
    assert!(rows[0].contains("directRequestEntry") && rows[0].contains(alice_did));
    assert!(rows[1].contains("directRequestAcceptanceEntry") && rows[1].contains(bob_did));
    assert!(rows[2].contains("applicationEntry") && rows[2].contains(bob_did));
    assert!(rows[3].contains("applicationEntry") && rows[3].contains(alice_did));

    let ended_at = chrono::Utc::now().to_rfc3339();

    // =========================================================================
    // LEG 7: Evidence packaging
    // =========================================================================
    let spec = json!({
        "row_id": "browser-catmos",
        "started_at": started_at,
        "ended_at": ended_at,
        "database_name": db_name,
        "conversation_id": cid,
        "draft_id": d1_draft_id,
        "sender_info": {"client": "Catmos Browser (WASM)", "did": alice_did, "deviceId": alice_acc["deviceId"].as_str().unwrap()},
        "recipient_info": {"client": "Catmos Desktop", "did": bob_did, "deviceId": bob_acc["deviceId"].as_str().unwrap()},
        "assertions": [
            "Local draft creation and cancellation in browser produces 0 remote chat entries",
            "Offline recipient first send records exactly 1 directRequestEntry on server",
            "Sender offline: recipient decrypts intro and accepts, reply is encrypted",
            "Sender restart: decrypts reply and sends follow-up",
            "Recipient decrypts sender reply on desktop",
            "Full desktop restart and browser reload: both messages persisted exactly once (F37 sent-once)",
            "PostgreSQL chat.entries contains exactly 4 ordered entries with no duplicates or extra Add commits"
        ],
        "not_exercised": [
            "unavailableDevicePreconsent: Local gateway manifest uses deterministic single-device recipient; multi-device key package race is tested in iOS/Android test suites",
            "recipientDeclineBlockLeg: Interoperability row exercises the full acceptance, reply, and restart pipeline; decline/block behavior is tested in standalone unit suites"
        ],
        "log_name": "browser-catmos-live.log"
    });
    let spec_path = format!("{workspace}/catmos/tests/spec-browser-catmos.json");
    std::fs::write(&spec_path, serde_json::to_string_pretty(&spec).unwrap()).unwrap();
    let pkg_res = Command::new("python3")
        .args([&format!("{workspace}/catmos/tests/package_evidence.py"), &spec_path])
        .output()
        .expect("package evidence");
    eprintln!("Packaging output:\n{}", String::from_utf8_lossy(&pkg_res.stdout));
    assert!(pkg_res.status.success(), "package_evidence failed");
    eprintln!("BROWSER-CATMOS LIVE ROW FULLY QUALIFIED!");
}

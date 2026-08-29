use catmos_lib::storage::{
    account_marker_path, app_db_file_name, app_db_key_label, create_db_key_in_store,
    mls_db_file_name, mls_db_key_label, open_clean_account_storage_with_store, read_account_marker,
    reset_account_storage_with_store, validate_app_db_readonly, write_account_marker_complete,
    write_account_marker_creating, DatabaseInitError, DbKeyStore, MarkerStatus, MemoryDbKeyStore,
    MLS_KEY_SUFFIX, MLS_STORAGE_GENERATION,
};
use std::fs;
fn generate_real_exported_identity_key(account_id: &str, identity: &str) -> Vec<u8> {
    let tmp_context_dir = tempfile::tempdir().unwrap();
    let tmp_mls_db = tmp_context_dir.path().join("mls.db");
    let key_context = catbird_mls::MLSContext::new(
        tmp_mls_db.to_string_lossy().to_string(),
        "fixture-key".to_string(),
        Box::new(catmos_lib::keychain::KeyringKeychainAccess::new(
            account_id.to_string(),
        )),
    )
    .unwrap();
    let _kp = key_context
        .create_key_package(identity.as_bytes().to_vec())
        .unwrap();
    let real_exported_key = key_context
        .export_identity_key(identity.to_string())
        .unwrap();
    let _ = key_context.flush_and_prepare_close();
    real_exported_key
}
#[test]
fn generation_constants_match_specification() {
    assert_eq!(
        catmos_lib::storage::MLS_STORAGE_GENERATION,
        "mls-state-clean-v2-openmls-v09"
    );
    assert_eq!(catmos_lib::storage::MLS_KEY_SUFFIX, "clean-v2-openmls-v09");
    assert_eq!(
        catmos_lib::storage::DB_KEYRING_SERVICE,
        "blue.catbird.catmos.clean-v2-openmls-v09"
    );
    assert_eq!(
        catmos_lib::keys::MLS_CONTENT_ROOT_DIR,
        "mls-content-root-clean-v2-openmls-v09"
    );
}

#[test]
fn content_root_key_lifecycle_and_legacy_isolation() {
    let tmp = tempfile::tempdir().unwrap();
    let did = "did:plc:cutover-test-user";
    let account_id = catmos_lib::keys::derive_account_id(did);

    // Set up a legacy content-root sentinel
    let legacy_dir = tmp.path().join("mls-content-root");
    fs::create_dir_all(&legacy_dir).unwrap();
    let legacy_file = legacy_dir.join("legacy_sentinel.key");
    fs::write(&legacy_file, b"legacy-sentinel-data-32-bytes!!!").unwrap();

    // Clean load/create
    let clean_key = catmos_lib::keys::load_or_create_content_root_key(tmp.path(), did)
        .expect("load_or_create should succeed");
    assert_eq!(clean_key.len(), 32);

    let clean_dir = tmp.path().join(catmos_lib::keys::MLS_CONTENT_ROOT_DIR);
    assert!(clean_dir.exists());
    let key_file = clean_dir.join(format!("{}.key", account_id));
    assert!(key_file.exists());

    // Reopen returns same bytes
    let reopened = catmos_lib::keys::load_or_create_content_root_key(tmp.path(), did)
        .expect("reopen should succeed");
    assert_eq!(clean_key, reopened);

    // Delete removes clean key only
    catmos_lib::keys::delete_content_root_key(tmp.path(), did).expect("delete should succeed");
    assert!(!key_file.exists());

    // Legacy sentinel remains intact
    assert!(legacy_file.exists());
    assert_eq!(
        fs::read(&legacy_file).unwrap(),
        b"legacy-sentinel-data-32-bytes!!!"
    );
}

#[test]
fn strict_key_loader_and_atomic_creator() {
    let tmp = tempfile::tempdir().unwrap();
    let did = "did:plc:strict-key-user";

    // load_existing fails when absent
    assert!(catmos_lib::keys::load_existing_content_root_key(tmp.path(), did).is_err());

    // create_new creates fresh key
    let key = catmos_lib::keys::create_new_content_root_key(tmp.path(), did)
        .expect("create_new should succeed");
    assert_eq!(key.len(), 32);

    // create_new fails when key already exists
    assert!(catmos_lib::keys::create_new_content_root_key(tmp.path(), did).is_err());

    // load_existing succeeds now
    let loaded = catmos_lib::keys::load_existing_content_root_key(tmp.path(), did)
        .expect("load_existing should succeed");
    assert_eq!(key, loaded);
}

#[test]
fn content_root_key_rejects_corrupt_file() {
    let tmp = tempfile::tempdir().unwrap();
    let did = "did:plc:corrupt-key-user";
    let clean_dir = tmp.path().join(catmos_lib::keys::MLS_CONTENT_ROOT_DIR);
    fs::create_dir_all(&clean_dir).unwrap();

    let account_id = catmos_lib::keys::derive_account_id(did);
    let key_file = clean_dir.join(format!("{}.key", account_id));
    fs::write(&key_file, b"corrupted-short-key").unwrap();

    let err = catmos_lib::keys::load_or_create_content_root_key(tmp.path(), did).unwrap_err();
    assert!(err.to_string().contains("wrong length"));
    // Corrupt file must NOT have been overwritten
    assert_eq!(fs::read(&key_file).unwrap(), b"corrupted-short-key");
}

#[tokio::test(flavor = "multi_thread")]
async fn clean_account_storage_fresh_creation_and_reopen() {
    let store = MemoryDbKeyStore::new();
    let test_service = "catmos-test";
    let tmp = tempfile::tempdir().unwrap();
    let did = "did:plc:fresh-account-user";
    let account_id = catmos_lib::keys::derive_account_id(did);

    let _ = catmos_lib::credentials::KeyringCredentialStore::delete_exact_account_credentials(did);
    let _ = catmos_lib::keychain::KeyringKeychainAccess::reset_account_signer_slots(
        &account_id,
        tmp.path(),
    );
    let app_db_path = tmp.path().join(app_db_file_name(&account_id));
    let mls_state_dir = tmp.path().join(MLS_STORAGE_GENERATION);
    let mls_db_path = mls_state_dir.join(mls_db_file_name(&account_id));
    let marker_file = account_marker_path(tmp.path(), &account_id);

    assert!(!app_db_path.exists());
    assert!(!mls_db_path.exists());
    assert!(!marker_file.exists());

    // First open: creates keys, DBs, and creating marker
    let (storage, mls_ctx, key, _lock) =
        open_clean_account_storage_with_store(tmp.path(), did, test_service, &store)
            .expect("first open of account storage should succeed");

    assert_eq!(key.len(), 32);
    assert!(app_db_path.exists());
    assert!(mls_db_path.exists());
    assert!(marker_file.exists());

    let marker = read_account_marker(
        &marker_file,
        did,
        &account_id,
        &app_db_file_name(&account_id),
        &mls_db_file_name(&account_id),
    )
    .unwrap();
    assert_eq!(marker, Some(MarkerStatus::Creating));

    use catbird_mls::orchestrator::credentials::CredentialStore;
    use catbird_mls::KeychainAccess;
    let cred_store = catmos_lib::credentials::KeyringCredentialStore::try_new().unwrap();
    let local_uuid = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d";
    let server_dev_id = local_uuid;
    let identity = format!("{did}#{local_uuid}");
    let _kp = mls_ctx
        .create_key_package(identity.as_bytes().to_vec())
        .unwrap();
    let exported_key = mls_ctx.export_identity_key(identity.clone()).unwrap();

    cred_store
        .store_signing_key(did, &exported_key)
        .await
        .unwrap();
    cred_store.store_mls_did(did, &identity).await.unwrap();
    cred_store
        .store_server_device_id(did, server_dev_id)
        .await
        .unwrap();
    cred_store
        .store_local_device_uuid(did, local_uuid)
        .await
        .unwrap();

    write_account_marker_complete(
        &marker_file,
        did,
        &account_id,
        &app_db_file_name(&account_id),
        &mls_db_file_name(&account_id),
    )
    .unwrap();

    let _ = mls_ctx.flush_and_prepare_close();
    drop(storage);
    drop(mls_ctx);
    drop(_lock);
    // Second open: reopens existing valid DBs after read-only SQLCipher validation
    let (storage2, mls_ctx2, key2, _lock2) =
        open_clean_account_storage_with_store(tmp.path(), did, test_service, &store)
            .expect("reopen of account storage should succeed");
    assert_eq!(key2, key);
    storage2.validate().expect("reopened DB must be valid");
    drop(storage2);
    drop(mls_ctx2);
    drop(_lock2);

    let _ = catmos_lib::credentials::KeyringCredentialStore::delete_exact_account_credentials(did);
    let _ = catmos_lib::keychain::KeyringKeychainAccess::reset_account_signer_slots(
        &account_id,
        tmp.path(),
    );
}

#[test]
fn clean_account_storage_mixed_states_fail_closed() {
    let tmp = tempfile::tempdir().unwrap();
    let did = "did:plc:mixed-state-user";
    let account_id = catmos_lib::keys::derive_account_id(did);

    let app_db_name = app_db_file_name(&account_id);
    let mls_db_name = mls_db_file_name(&account_id);
    let app_db_path = tmp.path().join(&app_db_name);
    let mls_state_dir = tmp.path().join(MLS_STORAGE_GENERATION);
    let mls_db_path = mls_state_dir.join(&mls_db_name);
    let marker_file = account_marker_path(tmp.path(), &account_id);
    let content_root_path = catmos_lib::keys::content_root_key_path(tmp.path(), &account_id);

    let app_key_label = app_db_key_label(&account_id);
    let mls_key_label = mls_db_key_label(&account_id);

    // Case 1: absent DB, present key
    let store1 = MemoryDbKeyStore::new();
    let _ = create_db_key_in_store(&store1, "s1", &app_key_label).unwrap();
    let err = open_clean_account_storage_with_store(tmp.path(), did, "s1", &store1)
        .err()
        .expect("absent DB with present key must fail closed");
    assert!(matches!(
        err,
        DatabaseInitError::MixedStateAbsentDbPresentKey
    ));

    // Case 2: present DB, absent key
    let store2 = MemoryDbKeyStore::new();
    fs::write(&app_db_path, b"fake-db-bytes").unwrap();
    let err = open_clean_account_storage_with_store(tmp.path(), did, "s2", &store2)
        .err()
        .expect("present DB with absent key must fail closed");
    assert!(matches!(
        err,
        DatabaseInitError::MixedStatePresentDbAbsentKey
    ));
    let _ = fs::remove_file(&app_db_path);

    // Case 3: creating marker with present DB and keys (InitializationIncomplete)
    let store3 = MemoryDbKeyStore::new();
    let _ = create_db_key_in_store(&store3, "s3", &app_key_label).unwrap();
    let _ = create_db_key_in_store(&store3, "s3", &mls_key_label).unwrap();
    fs::create_dir_all(&mls_state_dir).unwrap();
    fs::write(&app_db_path, b"fake-db-bytes").unwrap();
    fs::write(&mls_db_path, b"fake-mls-db-bytes").unwrap();
    let _ = catmos_lib::keys::create_new_content_root_key(tmp.path(), did).unwrap();
    write_account_marker_creating(&marker_file, did, &account_id, &app_db_name, &mls_db_name)
        .unwrap();
    let err = open_clean_account_storage_with_store(tmp.path(), did, "s3", &store3)
        .err()
        .expect("creating marker must fail closed as incomplete initialization");
    assert!(matches!(err, DatabaseInitError::InitializationIncomplete));
    let _ = fs::remove_file(&app_db_path);
    let _ = fs::remove_file(&mls_db_path);
    let _ = fs::remove_file(&marker_file);
    let _ = fs::remove_file(&content_root_path);

    // Case 4: orphan complete marker -> InvalidMarker
    let store4 = MemoryDbKeyStore::new();
    write_account_marker_complete(&marker_file, did, &account_id, &app_db_name, &mls_db_name)
        .unwrap();
    let err = open_clean_account_storage_with_store(tmp.path(), did, "s4", &store4)
        .err()
        .expect("orphan complete marker must fail closed as invalid marker");
    assert!(matches!(err, DatabaseInitError::InvalidMarker(_)));
    let _ = fs::remove_file(&marker_file);
}

#[tokio::test(flavor = "multi_thread")]
async fn clean_account_storage_reset_and_legacy_isolation() {
    let store = MemoryDbKeyStore::new();
    let test_service = "catmos-test";
    let tmp = tempfile::tempdir().unwrap();
    let did = "did:plc:reset-test-user";
    let account_id = catmos_lib::keys::derive_account_id(did);

    // Set up legacy sentinels
    let legacy_db = tmp.path().join("catmos.db");
    fs::write(&legacy_db, b"legacy-catmos-db-sentinel").unwrap();
    let legacy_mls_dir = tmp.path().join("mls-state");
    fs::create_dir_all(&legacy_mls_dir).unwrap();
    let legacy_mls_db = legacy_mls_dir.join("mls.db");
    fs::write(&legacy_mls_db, b"legacy-mls-db-sentinel").unwrap();

    // Create clean account storage
    let (storage, mls_ctx, _key, lock) =
        open_clean_account_storage_with_store(tmp.path(), did, test_service, &store).unwrap();
    let app_db_path = tmp.path().join(app_db_file_name(&account_id));
    let marker_file = account_marker_path(tmp.path(), &account_id);
    let content_key_path = catmos_lib::keys::content_root_key_path(tmp.path(), &account_id);

    assert!(app_db_path.exists());
    assert!(marker_file.exists());
    assert!(content_key_path.exists());

    // Drop active lock before reset
    drop(lock);

    // Perform explicit reset (must not deadlock!)
    reset_account_storage_with_store(
        tmp.path(),
        did,
        Some(storage),
        Some(&mls_ctx),
        test_service,
        &store,
    )
    .await
    .expect("reset should succeed without deadlock");

    // Clean account DB, content root key, and marker should be gone
    assert!(!app_db_path.exists());
    assert!(!marker_file.exists());
    assert!(!content_key_path.exists());

    // Legacy files MUST remain untouched
    assert!(legacy_db.exists());
    assert_eq!(fs::read(&legacy_db).unwrap(), b"legacy-catmos-db-sentinel");
    assert!(legacy_mls_db.exists());
    assert_eq!(fs::read(&legacy_mls_db).unwrap(), b"legacy-mls-db-sentinel");
}

#[test]
fn write_account_marker_complete_produces_valid_durable_marker() {
    let tmp = tempfile::tempdir().unwrap();
    let did = "did:plc:marker-test-user";
    let account_id = catmos_lib::keys::derive_account_id(did);
    let app_name = app_db_file_name(&account_id);
    let mls_name = mls_db_file_name(&account_id);
    let marker = account_marker_path(tmp.path(), &account_id);

    write_account_marker_complete(&marker, did, &account_id, &app_name, &mls_name)
        .expect("write complete marker should succeed");
    assert!(marker.exists());

    let parsed = read_account_marker(&marker, did, &account_id, &app_name, &mls_name)
        .expect("read marker should parse");
    assert_eq!(parsed, Some(MarkerStatus::Complete));

    let content = fs::read_to_string(&marker).expect("read content");
    assert_eq!(
        content,
        format!(
            "complete\n{}\n{}\n{}\n{}\n{}\n",
            did, account_id, MLS_STORAGE_GENERATION, app_name, mls_name
        )
    );
}

#[test]
fn missing_schema_fails_closed() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("empty.db");
    let key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    // Open empty DB without tables
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    conn.execute_batch(&format!("PRAGMA key = '{key}';"))
        .unwrap();
    drop(conn);

    // Read-only validation must fail because required tables are missing
    let err = catmos_lib::storage::validate_app_db_readonly(&db_path, key)
        .err()
        .expect("empty DB must fail validation");
    assert!(matches!(err, DatabaseInitError::ValidationFailed(_)));
}

#[test]
fn signer_remnants_fail_closed() {
    let store = MemoryDbKeyStore::new();
    let test_service = "catmos-test";
    let tmp = tempfile::tempdir().unwrap();
    let did = "did:plc:remnant-user";
    let account_id = catmos_lib::keys::derive_account_id(did);

    // Put a signer slot into keychain without DBs or marker
    let idx_key = format!("signer_slots_index:{}:{}", account_id, MLS_KEY_SUFFIX);
    let entry =
        keyring::Entry::new("blue.catbird.catmos.mls.clean-v2-openmls-v09", &idx_key).unwrap();
    let mut set = std::collections::BTreeSet::new();
    set.insert(format!("sig_key_remnant:{}:{}", account_id, MLS_KEY_SUFFIX));
    entry
        .set_password(&serde_json::to_string(&set).unwrap())
        .unwrap();

    let err = open_clean_account_storage_with_store(tmp.path(), did, test_service, &store)
        .err()
        .expect("signer remnants without DBs/markers must fail closed");
    assert!(matches!(err, DatabaseInitError::MixedStateMissingMarker));

    // Clean up test entry
    let _ = entry.delete_credential();
}

#[tokio::test(flavor = "multi_thread")]
async fn runtime_retains_exclusive_lock_and_allows_signer_write_and_delete() {
    let store = MemoryDbKeyStore::new();
    let test_service = "catmos-test";
    let tmp = tempfile::tempdir().unwrap();
    let did = "did:plc:signer-runtime-user";
    let account_id = catmos_lib::keys::derive_account_id(did);

    // Open account storage (retains exclusive account flock)
    let (storage, mls_ctx, _key, lock) =
        open_clean_account_storage_with_store(tmp.path(), did, test_service, &store)
            .expect("open account storage should succeed");

    // Signer write and delete through KeyringKeychainAccess under the active runtime
    let keychain = catmos_lib::keychain::KeyringKeychainAccess::new(account_id.clone());

    use catbird_mls::KeychainAccess;
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        keychain
            .write("test_sig_slot".to_string(), b"private-key-bytes".to_vec())
            .await
            .expect("signer slot write under active lock must not deadlock");

        let read_val = keychain
            .read("test_sig_slot".to_string())
            .await
            .expect("read signer slot must succeed");
        assert_eq!(read_val, Some(b"private-key-bytes".to_vec()));

        keychain
            .delete("test_sig_slot".to_string())
            .await
            .expect("signer slot delete under active lock must not deadlock");
    })
    .await
    .expect("signer operations timed out (self-deadlock regression!)");

    drop(storage);
    drop(mls_ctx);
    drop(lock);
}

#[tokio::test(flavor = "multi_thread")]
async fn reopen_does_not_mutate_existing_valid_databases() {
    let store = MemoryDbKeyStore::new();
    let test_service = "catmos-test";
    let tmp = tempfile::tempdir().unwrap();
    let did = "did:plc:nomutate-user";
    let account_id = catmos_lib::keys::derive_account_id(did);

    let _ = catmos_lib::credentials::KeyringCredentialStore::delete_exact_account_credentials(did);
    let _ = catmos_lib::keychain::KeyringKeychainAccess::reset_account_signer_slots(
        &account_id,
        tmp.path(),
    );
    let (storage, mls_ctx, _key, lock) =
        open_clean_account_storage_with_store(tmp.path(), did, test_service, &store).unwrap();

    use catbird_mls::orchestrator::credentials::CredentialStore;
    let cred_store = catmos_lib::credentials::KeyringCredentialStore::try_new().unwrap();
    let local_uuid = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d";
    let server_dev_id = local_uuid;
    let identity = format!("{did}#{local_uuid}");
    let _kp = mls_ctx
        .create_key_package(identity.as_bytes().to_vec())
        .unwrap();
    let exported_key = mls_ctx.export_identity_key(identity.clone()).unwrap();

    cred_store
        .store_signing_key(did, &exported_key)
        .await
        .unwrap();
    cred_store.store_mls_did(did, &identity).await.unwrap();
    cred_store
        .store_server_device_id(did, server_dev_id)
        .await
        .unwrap();
    cred_store
        .store_local_device_uuid(did, local_uuid)
        .await
        .unwrap();

    write_account_marker_complete(
        &account_marker_path(tmp.path(), &account_id),
        did,
        &account_id,
        &app_db_file_name(&account_id),
        &mls_db_file_name(&account_id),
    )
    .unwrap();
    let _ = mls_ctx.flush_and_prepare_close();
    drop(storage);
    drop(mls_ctx);
    drop(lock);
    let app_db_path = tmp.path().join(app_db_file_name(&account_id));
    let mls_state_dir = tmp.path().join(MLS_STORAGE_GENERATION);
    let mls_db_path = mls_state_dir.join(mls_db_file_name(&account_id));
    let app_meta_before = fs::metadata(&app_db_path).unwrap();
    let mls_meta_before = fs::metadata(&mls_db_path).unwrap();

    let (storage2, mls_ctx2, _key2, lock2) =
        open_clean_account_storage_with_store(tmp.path(), did, test_service, &store).unwrap();
    let _ = mls_ctx2.flush_and_prepare_close();
    drop(storage2);
    drop(mls_ctx2);
    drop(lock2);
    let app_meta_after = fs::metadata(&app_db_path).unwrap();
    let mls_meta_after = fs::metadata(&mls_db_path).unwrap();

    assert_eq!(app_meta_before.len(), app_meta_after.len());
    assert_eq!(mls_meta_before.len(), mls_meta_after.len());

    let _ = catmos_lib::credentials::KeyringCredentialStore::delete_exact_account_credentials(did);
    let _ = catmos_lib::keychain::KeyringKeychainAccess::reset_account_signer_slots(
        &account_id,
        tmp.path(),
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn corrupt_index_fails_reset_leaving_all_resources_unchanged() {
    let store = MemoryDbKeyStore::new();
    let test_service = "catmos-test";
    let tmp = tempfile::tempdir().unwrap();
    let did_owned = format!("did:plc:corrupt-idx-user-{}", uuid::Uuid::new_v4());
    let did = &did_owned;
    let account_id = catmos_lib::keys::derive_account_id(did);

    let foreign_account_id = format!("other_account_xyz_{}", uuid::Uuid::new_v4());
    let foreign_slot = format!("sig_key_foreign:{}:{}", foreign_account_id, MLS_KEY_SUFFIX);
    let foreign_slot_entry = keyring::Entry::new(
        "blue.catbird.catmos.mls.clean-v2-openmls-v09",
        &foreign_slot,
    )
    .unwrap();
    foreign_slot_entry
        .set_password("foreign-key-payload")
        .unwrap();

    let idx_key = format!("signer_slots_index:{}:{}", account_id, MLS_KEY_SUFFIX);
    let entry =
        keyring::Entry::new("blue.catbird.catmos.mls.clean-v2-openmls-v09", &idx_key).unwrap();
    let _ = entry.delete_credential();

    let (storage, mls_ctx, _key, lock) =
        open_clean_account_storage_with_store(tmp.path(), did, test_service, &store).unwrap();
    drop(lock);

    let local_uuid = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d";
    let identity = format!("{did}#{local_uuid}");
    let _kp = mls_ctx
        .create_key_package(identity.as_bytes().to_vec())
        .unwrap();
    let exported_key = mls_ctx.export_identity_key(identity.clone()).unwrap();
    let _ = mls_ctx.flush_and_prepare_close();
    drop(storage);
    drop(mls_ctx);

    use catbird_mls::orchestrator::credentials::CredentialStore;
    let cred_store = catmos_lib::credentials::KeyringCredentialStore::try_new().unwrap();
    cred_store
        .store_signing_key(did, &exported_key)
        .await
        .unwrap();

    let app_db_path = tmp.path().join(app_db_file_name(&account_id));
    let mls_db_path = tmp
        .path()
        .join(MLS_STORAGE_GENERATION)
        .join(mls_db_file_name(&account_id));
    let cr_key_path = catmos_lib::keys::content_root_key_path(tmp.path(), &account_id);
    let marker_file = account_marker_path(tmp.path(), &account_id);

    let app_meta_before = fs::metadata(&app_db_path).unwrap();
    let mls_meta_before = fs::metadata(&mls_db_path).unwrap();
    let cr_meta_before = fs::metadata(&cr_key_path).unwrap();

    entry.set_password("not-valid-json-corrupted").unwrap();

    let reset_res =
        reset_account_storage_with_store(tmp.path(), did, None, None, test_service, &store).await;

    // Reset MUST fail on corrupt index before any deletion to prevent orphaning unnameable secrets
    assert!(
        reset_res.is_err(),
        "reset with corrupt index must fail closed"
    );

    // All resources must be completely unchanged
    assert_eq!(entry.get_password().unwrap(), "not-valid-json-corrupted");
    assert_eq!(
        cred_store.get_signing_key(did).await.unwrap(),
        Some(exported_key)
    );
    assert_eq!(
        fs::metadata(&app_db_path).unwrap().len(),
        app_meta_before.len()
    );
    assert_eq!(
        fs::metadata(&mls_db_path).unwrap().len(),
        mls_meta_before.len()
    );
    assert_eq!(
        fs::metadata(&cr_key_path).unwrap().len(),
        cr_meta_before.len()
    );
    assert!(marker_file.exists());

    // Foreign account slot must be completely unchanged
    assert_eq!(
        foreign_slot_entry.get_password().unwrap(),
        "foreign-key-payload"
    );

    // Clean up
    let _ = entry.delete_credential();
    let _ = foreign_slot_entry.delete_credential();
    let _ = catmos_lib::credentials::KeyringCredentialStore::delete_exact_account_credentials(did);
}

#[tokio::test(flavor = "multi_thread")]
async fn fresh_enroll_terminate_cold_reopen_complete() {
    let store = MemoryDbKeyStore::new();
    let test_service = "catmos-test";
    let tmp = tempfile::tempdir().unwrap();
    let did_owned = format!("did:plc:cold-reopen-user-{}", uuid::Uuid::new_v4());
    let did = &did_owned;
    let account_id = catmos_lib::keys::derive_account_id(did);

    // Clean up any leftover keyring credentials and signer slots from prior runs
    let _ = catmos_lib::credentials::KeyringCredentialStore::delete_exact_account_credentials(did);
    let _ = catmos_lib::keychain::KeyringKeychainAccess::reset_account_signer_slots(
        &account_id,
        tmp.path(),
    );
    // 1. Fresh open (unenrolled)
    let (storage, mls_ctx, _key, lock) =
        open_clean_account_storage_with_store(tmp.path(), did, test_service, &store)
            .expect("first open should succeed");

    // 2. Perform enrollment (create key package on mls_ctx, export key, and store credentials)
    use catbird_mls::orchestrator::credentials::CredentialStore;
    let cred_store = catmos_lib::credentials::KeyringCredentialStore::try_new().unwrap();
    let local_uuid = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d";
    let server_dev_id = local_uuid;
    let identity = format!("{did}#{local_uuid}");
    let _kp = mls_ctx
        .create_key_package(identity.as_bytes().to_vec())
        .unwrap();
    let exported_key = mls_ctx.export_identity_key(identity.clone()).unwrap();

    cred_store
        .store_signing_key(did, &exported_key)
        .await
        .unwrap();
    cred_store.store_mls_did(did, &identity).await.unwrap();
    cred_store
        .store_server_device_id(did, server_dev_id)
        .await
        .unwrap();
    cred_store
        .store_local_device_uuid(did, local_uuid)
        .await
        .unwrap();
    write_account_marker_complete(
        &account_marker_path(tmp.path(), &account_id),
        did,
        &account_id,
        &app_db_file_name(&account_id),
        &mls_db_file_name(&account_id),
    )
    .unwrap();
    let _ = mls_ctx.flush_and_prepare_close();
    drop(storage);
    drop(mls_ctx);
    drop(lock);
    // 4. Cold reopen (must validate existing DB read-only and verify complete device enrollment state)
    let (storage2, mls_ctx2, _key2, lock2) =
        open_clean_account_storage_with_store(tmp.path(), did, test_service, &store)
            .expect("cold reopen with full enrollment must succeed");

    storage2.validate().expect("reopened storage must be valid");
    let _ = mls_ctx2.flush_and_prepare_close();
    drop(storage2);
    drop(mls_ctx2);
    drop(lock2);

    // Clean up keyring credentials and signer slots for test isolation
    let _ = catmos_lib::credentials::KeyringCredentialStore::delete_exact_account_credentials(did);
    let _ = catmos_lib::keychain::KeyringKeychainAccess::reset_account_signer_slots(
        &account_id,
        tmp.path(),
    );
}

#[test]
fn schema_validator_rejects_wrong_index_and_extra_objects_read_only() {
    let store = MemoryDbKeyStore::new();
    let test_service = "catmos-test";
    let tmp = tempfile::tempdir().unwrap();
    let did = "did:plc:schema-val-user";
    let account_id = catmos_lib::keys::derive_account_id(did);

    let app_key_label = app_db_key_label(&account_id);
    let app_key = create_db_key_in_store(&store, test_service, &app_key_label).unwrap();
    let app_db_path = tmp.path().join(app_db_file_name(&account_id));

    // Create valid baseline app db
    let storage =
        catmos_lib::storage::SqliteStorage::create_new(&app_db_path.to_string_lossy(), &app_key)
            .unwrap();
    drop(storage);

    // Baseline validation must succeed
    validate_app_db_readonly(&app_db_path, &app_key).expect("baseline validation must succeed");

    // Helper closure to create a test copy and test mutation rejection
    let test_mutation = |mutator: &dyn Fn(&rusqlite::Connection)| {
        let copy_path = tmp
            .path()
            .join(format!("test-copy-{}.db", uuid::Uuid::new_v4()));
        fs::copy(&app_db_path, &copy_path).unwrap();

        let conn = rusqlite::Connection::open(&copy_path).unwrap();
        conn.execute_batch(&format!("PRAGMA key = '{}';", app_key))
            .unwrap();
        mutator(&conn);
        drop(conn);

        let meta_before = fs::metadata(&copy_path).unwrap();
        let res = validate_app_db_readonly(&copy_path, &app_key);
        let meta_after = fs::metadata(&copy_path).unwrap();

        assert!(
            matches!(res, Err(DatabaseInitError::ValidationFailed(_))),
            "expected ValidationFailed, got: {res:?}"
        );
        // Validator must remain strictly read-only
        assert_eq!(
            meta_before.len(),
            meta_after.len(),
            "validator must not mutate file"
        );
        let _ = fs::remove_file(&copy_path);
    };

    // 1. Same-name wrong index (reversed column order)
    test_mutation(&|conn| {
        conn.execute_batch(
            "DROP INDEX idx_messages_convo_seq;
             CREATE INDEX idx_messages_convo_seq ON messages(sequence_number, conversation_id);",
        )
        .unwrap();
    });

    // 2. Same-name wrong index (UNIQUE flag when should be non-unique)
    test_mutation(&|conn| {
        conn.execute_batch(
            "DROP INDEX idx_messages_convo_seq;
             CREATE UNIQUE INDEX idx_messages_convo_seq ON messages(conversation_id, sequence_number);",
        )
        .unwrap();
    });

    // 3. Extra table
    test_mutation(&|conn| {
        conn.execute_batch("CREATE TABLE extra_table (id TEXT PRIMARY KEY);")
            .unwrap();
    });

    // 4. Extra index on messages
    test_mutation(&|conn| {
        conn.execute_batch("CREATE INDEX idx_extra ON messages(sender_did);")
            .unwrap();
    });

    // 5. Extra view
    test_mutation(&|conn| {
        conn.execute_batch("CREATE VIEW v_messages AS SELECT * FROM messages;")
            .unwrap();
    });

    // 6. Extra trigger
    test_mutation(&|conn| {
        conn.execute_batch("CREATE TRIGGER tr_extra AFTER INSERT ON messages BEGIN SELECT 1; END;")
            .unwrap();
    });

    // 7. Extra foreign key
    test_mutation(&|conn| {
        conn.execute_batch(
            "CREATE TABLE child_tbl (id TEXT PRIMARY KEY, convo_id TEXT REFERENCES conversations(conversation_id));",
        )
        .unwrap();
    });
}

#[tokio::test(flavor = "multi_thread")]
async fn enrollment_failure_leaves_no_active_runtime_and_allows_retry() {
    let tmp = tempfile::tempdir().unwrap();
    let did_owned = format!("did:plc:enroll-fail-retry-user-{}", uuid::Uuid::new_v4());
    let did = &did_owned;
    let _account_id = catmos_lib::keys::derive_account_id(did);
    // Clean up any remnants in OS keyring before starting
    let _ = catmos_lib::storage::reset_account_storage(
        tmp.path(),
        did,
        None,
        None,
        catmos_lib::storage::DB_KEYRING_SERVICE,
    )
    .await;
    let state = catmos_lib::AppState::new(
        tmp.path().to_path_buf(),
        "http://127.0.0.1:9999".to_string(),
    );

    // 1. Initial state: accessors must fail closed
    assert!(state.get_orchestrator().await.is_err());
    assert!(state.get_active_runtime().await.is_err());

    // 2. Concurrency check: spawn tasks trying to access orchestrator
    let state_arc = std::sync::Arc::new(state);
    let mut handles = Vec::new();
    for _ in 0..5 {
        let st = state_arc.clone();
        handles.push(tokio::spawn(async move {
            assert!(st.get_orchestrator().await.is_err());
            assert!(st.get_active_runtime().await.is_err());
        }));
    }
    for h in handles {
        h.await.unwrap();
    }

    // 3. Attempt enrollment with an invalid session (fails before publication)
    let enroll_res =
        catmos_lib::commands::enroll_account_runtime(&state_arc, did, "invalid_session_xyz").await;
    assert!(
        enroll_res.is_err(),
        "enrollment with invalid session must fail"
    );

    // After failure: active runtime remains empty, accessors still fail closed
    assert!(state_arc.get_orchestrator().await.is_err());
    assert!(state_arc.get_active_runtime().await.is_err());
    assert!(!state_arc.has_active_runtime().await);

    // Retrying enrollment before explicit reset fails because of incomplete Creating marker
    let retry_before_reset =
        catmos_lib::commands::enroll_account_runtime(&state_arc, did, "invalid_session_xyz").await;
    assert!(
        retry_before_reset.is_err(),
        "retrying before reset must fail on Creating marker"
    );

    // 4. Perform explicit reset as required by clean contract
    catmos_lib::storage::reset_account_storage(
        tmp.path(),
        did,
        None,
        None,
        catmos_lib::storage::DB_KEYRING_SERVICE,
    )
    .await
    .unwrap();

    // Clean up
    let _ = catmos_lib::storage::reset_account_storage(
        tmp.path(),
        did,
        None,
        None,
        catmos_lib::storage::DB_KEYRING_SERVICE,
    )
    .await;
}
#[test]
fn cross_account_signer_index_entry_fails_reset_other_account_unchanged() {
    let tmp = tempfile::tempdir().unwrap();
    let account_id = format!("test_acc_preflight_{}", uuid::Uuid::new_v4());
    let other_account_id = format!("other_account_{}", uuid::Uuid::new_v4());
    let idx_key = catmos_lib::keychain::KeyringKeychainAccess::index_key_for_account(&account_id);
    let idx_entry = keyring::Entry::new(catmos_lib::keychain::SERVICE_NAME, &idx_key).unwrap();

    let valid_slot = format!("sig_key_valid:{}:{}", account_id, MLS_KEY_SUFFIX);
    let foreign_slot = format!("sig_key_foreign:{}:{}", other_account_id, MLS_KEY_SUFFIX);

    let slot_entry = keyring::Entry::new(catmos_lib::keychain::SERVICE_NAME, &valid_slot).unwrap();
    let valid_signer_json =
        serde_json::to_string(&serde_json::json!({"public": "pk", "private": "sk"})).unwrap();
    slot_entry.set_password(&valid_signer_json).unwrap();

    let foreign_slot_entry =
        keyring::Entry::new(catmos_lib::keychain::SERVICE_NAME, &foreign_slot).unwrap();
    foreign_slot_entry
        .set_password("foreign-slot-payload")
        .unwrap();

    let mut set = std::collections::BTreeSet::new();
    set.insert(valid_slot.clone());
    set.insert(foreign_slot.clone());
    idx_entry
        .set_password(&serde_json::to_string(&set).unwrap())
        .unwrap();
    let reset_res = catmos_lib::keychain::KeyringKeychainAccess::reset_account_signer_slots(
        &account_id,
        tmp.path(),
    );
    assert!(
        reset_res.is_err(),
        "reset must fail when index contains foreign slot"
    );
    // Neither slot nor index entry must be deleted
    assert_eq!(
        foreign_slot_entry.get_password().unwrap(),
        "foreign-slot-payload"
    );
    assert!(slot_entry.get_password().is_ok());

    // Clean up
    let _ = slot_entry.delete_credential();
    let _ = foreign_slot_entry.delete_credential();
    let _ = idx_entry.delete_credential();
}

#[test]
fn complete_marker_with_unenrolled_credentials_fails_before_open() {
    let store = MemoryDbKeyStore::new();
    let test_service = "catmos-test";
    let tmp = tempfile::tempdir().unwrap();
    let did_owned = format!(
        "did:plc:complete-marker-unenrolled-{}",
        uuid::Uuid::new_v4()
    );
    let did = &did_owned;
    let account_id = catmos_lib::keys::derive_account_id(did);

    // Clean up any remnants
    let _ = catmos_lib::credentials::KeyringCredentialStore::delete_exact_account_credentials(did);
    let _ = catmos_lib::keychain::KeyringKeychainAccess::reset_account_signer_slots(
        &account_id,
        tmp.path(),
    );
    // Create clean storage initially
    let (storage, mls_ctx, _key, lock) =
        open_clean_account_storage_with_store(tmp.path(), did, test_service, &store).unwrap();
    let _ = mls_ctx.flush_and_prepare_close();
    drop(storage);
    drop(mls_ctx);
    drop(lock);

    // Write a complete marker manually while leaving credentials completely unenrolled
    write_account_marker_complete(
        &account_marker_path(tmp.path(), &account_id),
        did,
        &account_id,
        &app_db_file_name(&account_id),
        &mls_db_file_name(&account_id),
    )
    .unwrap();

    // Reopen MUST fail before opening because credentials are unenrolled
    let reopen_res = open_clean_account_storage_with_store(tmp.path(), did, test_service, &store);
    assert!(
        matches!(reopen_res, Err(DatabaseInitError::ValidationFailed(_))),
        "expected ValidationFailed"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn account_reset_deletes_temp_files_without_touching_neighbors() {
    let store = MemoryDbKeyStore::new();
    let test_service = "catmos-test";
    let tmp = tempfile::tempdir().unwrap();
    let did = "did:plc:target-acc-reset";
    let account_id = catmos_lib::keys::derive_account_id(did);

    let neighbor_account_id = format!("{}_neighbor", account_id);

    // Create account storage
    let (storage, mls_ctx, _key, lock) =
        open_clean_account_storage_with_store(tmp.path(), did, test_service, &store).unwrap();
    drop(lock);
    // Create temp files for target account in data_dir and content-root dir
    let target_tmp1 = tmp.path().join(format!(
        "catmos-{}-{}.key.tmp.1234",
        account_id, MLS_KEY_SUFFIX
    ));
    let target_tmp2 = tmp.path().join(format!(
        "catmos-{}-{}.marker.tmp.5678",
        account_id, MLS_KEY_SUFFIX
    ));
    fs::write(&target_tmp1, b"temp-key").unwrap();
    fs::write(&target_tmp2, b"temp-marker").unwrap();

    let content_root_dir = tmp.path().join(catmos_lib::keys::MLS_CONTENT_ROOT_DIR);
    fs::create_dir_all(&content_root_dir).unwrap();
    let target_cr_tmp = content_root_dir.join(format!("{}.tmp.1234", account_id));
    fs::write(&target_cr_tmp, b"target-cr-temp").unwrap();

    // Create temp files for prefix neighbor
    let neighbor_tmp = tmp.path().join(format!(
        "catmos-{}-{}.key.tmp.9999",
        neighbor_account_id, MLS_KEY_SUFFIX
    ));
    fs::write(&neighbor_tmp, b"neighbor-temp-key").unwrap();
    let neighbor_cr_tmp = content_root_dir.join(format!("{}.tmp.5678", neighbor_account_id));
    fs::write(&neighbor_cr_tmp, b"neighbor-cr-temp").unwrap();

    // Perform reset on target account
    reset_account_storage_with_store(
        tmp.path(),
        did,
        Some(storage),
        Some(&mls_ctx),
        test_service,
        &store,
    )
    .await
    .unwrap();

    // Target temp files must be deleted
    assert!(
        !target_tmp1.exists(),
        "target temp key file must be deleted"
    );
    assert!(
        !target_tmp2.exists(),
        "target temp marker file must be deleted"
    );
    assert!(
        !target_cr_tmp.exists(),
        "target content root temp file must be deleted"
    );

    // Neighbor temp files must NOT be deleted
    assert!(
        neighbor_tmp.exists(),
        "neighbor temp file must remain intact"
    );
    assert!(
        neighbor_cr_tmp.exists(),
        "neighbor content root temp file must remain intact"
    );
}

#[test]
fn marker_reader_rejects_non_six_lines() {
    let tmp = tempfile::tempdir().unwrap();
    let did = "did:plc:marker-line-test";
    let account_id = catmos_lib::keys::derive_account_id(did);
    let app_db_name = app_db_file_name(&account_id);
    let mls_db_name = mls_db_file_name(&account_id);
    let marker_path = tmp.path().join("test.marker");

    // 5 lines
    fs::write(
        &marker_path,
        format!("complete\n{did}\n{account_id}\n{MLS_STORAGE_GENERATION}\n{app_db_name}\n"),
    )
    .unwrap();
    let res5 = read_account_marker(&marker_path, did, &account_id, &app_db_name, &mls_db_name);
    assert!(matches!(res5, Err(DatabaseInitError::InvalidMarker(_))));

    // 7 lines
    fs::write(
        &marker_path,
        format!("complete\n{did}\n{account_id}\n{MLS_STORAGE_GENERATION}\n{app_db_name}\n{mls_db_name}\nextra_line\n"),
    )
    .unwrap();
    let res7 = read_account_marker(&marker_path, did, &account_id, &app_db_name, &mls_db_name);
    assert!(matches!(res7, Err(DatabaseInitError::InvalidMarker(_))));

    // Exactly 6 lines
    fs::write(
        &marker_path,
        format!("complete\n{did}\n{account_id}\n{MLS_STORAGE_GENERATION}\n{app_db_name}\n{mls_db_name}\n"),
    )
    .unwrap();
    let res6 = read_account_marker(&marker_path, did, &account_id, &app_db_name, &mls_db_name);
    assert_eq!(res6.unwrap(), Some(MarkerStatus::Complete));
}

#[test]
fn schema_validator_rejects_unexpected_default_value() {
    let store = MemoryDbKeyStore::new();
    let test_service = "catmos-test";
    let tmp = tempfile::tempdir().unwrap();
    let did = "did:plc:schema-dflt-val-user";
    let account_id = catmos_lib::keys::derive_account_id(did);

    let app_key_label = app_db_key_label(&account_id);
    let app_key = create_db_key_in_store(&store, test_service, &app_key_label).unwrap();
    let app_db_path = tmp.path().join(app_db_file_name(&account_id));

    let storage =
        catmos_lib::storage::SqliteStorage::create_new(&app_db_path.to_string_lossy(), &app_key)
            .unwrap();
    drop(storage);

    // Mutate conversations table column created_at to have unexpected default value 'NOW'
    let conn = rusqlite::Connection::open(&app_db_path).unwrap();
    conn.execute_batch(&format!("PRAGMA key = '{}';", app_key))
        .unwrap();
    conn.execute_batch(
        "ALTER TABLE conversations RENAME TO old_conversations;
         CREATE TABLE conversations (
             conversation_id TEXT NOT NULL,
             user_did TEXT NOT NULL,
             group_id TEXT NOT NULL,
             epoch INTEGER NOT NULL DEFAULT 0,
             state TEXT NOT NULL DEFAULT 'Active',
             join_method TEXT,
             join_epoch INTEGER,
             needs_rejoin INTEGER NOT NULL DEFAULT 0,
             members_json TEXT NOT NULL DEFAULT '[]',
             metadata_json TEXT,
             metadata_version INTEGER,
             metadata_blob_locator TEXT,
             avatar_blob_locator TEXT,
             avatar_bytes BLOB,
             avatar_content_type TEXT,
             created_at TEXT DEFAULT 'NOW',
             updated_at TEXT,
             sequencer_did TEXT,
             reset_new_group_id TEXT,
             reset_generation INTEGER,
             reset_notified_at_ms INTEGER,
             quarantine_reason_tag TEXT,
             quarantine_since_ms INTEGER,
             PRIMARY KEY (conversation_id, user_did)
         );
         DROP TABLE old_conversations;",
    )
    .unwrap();
    drop(conn);

    let res = validate_app_db_readonly(&app_db_path, &app_key);
    assert!(
        matches!(res, Err(DatabaseInitError::ValidationFailed(_))),
        "expected ValidationFailed for unexpected default value, got: {res:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn check_credential_state_exact_binding_and_tamper_tests() {
    let tmp = tempfile::tempdir().unwrap();
    let did_owned = format!("did:plc:tamper-test-user-{}", uuid::Uuid::new_v4());
    let did = &did_owned;
    let account_id = catmos_lib::keys::derive_account_id(did);

    // Clean up
    let _ = catmos_lib::credentials::KeyringCredentialStore::delete_exact_account_credentials(did);
    let _ = catmos_lib::keychain::KeyringKeychainAccess::reset_account_signer_slots(
        &account_id,
        tmp.path(),
    );
    use catbird_mls::orchestrator::credentials::CredentialStore;
    let cred_store = catmos_lib::credentials::KeyringCredentialStore::try_new().unwrap();
    let local_uuid = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d";
    let server_dev_id = local_uuid;
    let identity = format!("{did}#{local_uuid}");
    let real_exported_key = generate_real_exported_identity_key(&account_id, &identity);
    let signer_val: serde_json::Value = serde_json::from_slice(&real_exported_key).unwrap();
    let pk_bytes: Vec<u8> = signer_val["public"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n.as_u64().unwrap() as u8)
        .collect();
    let slot_key = catbird_mls::canonical_signer_keychain_key(&pk_bytes).unwrap();

    let keychain = catmos_lib::keychain::KeyringKeychainAccess::new(account_id.clone());
    use catbird_mls::KeychainAccess;
    keychain
        .write(slot_key.clone(), real_exported_key.clone())
        .await
        .unwrap();

    // 1. Valid enrollment
    cred_store
        .store_signing_key(did, &real_exported_key)
        .await
        .unwrap();
    cred_store.store_mls_did(did, &identity).await.unwrap();
    cred_store
        .store_server_device_id(did, server_dev_id)
        .await
        .unwrap();
    cred_store
        .store_local_device_uuid(did, local_uuid)
        .await
        .unwrap();

    let state =
        catmos_lib::credentials::KeyringCredentialStore::check_credential_state(did).unwrap();
    assert_eq!(
        state,
        catmos_lib::credentials::CredentialEnrollmentState::FullyEnrolled
    );

    // 2. Tamper signing_key with empty JSON object
    cred_store.store_signing_key(did, b"{}").await.unwrap();
    let empty_obj_res =
        catmos_lib::credentials::KeyringCredentialStore::check_credential_state(did);
    assert!(
        empty_obj_res.is_err(),
        "empty json object must fail validation"
    );

    // 3. Tamper signing_key with non-JSON raw bytes
    cred_store
        .store_signing_key(did, b"fake-non-json-key-seed-bytes")
        .await
        .unwrap();
    let tampered_key_res =
        catmos_lib::credentials::KeyringCredentialStore::check_credential_state(did);
    assert!(
        tampered_key_res.is_err(),
        "tampered signing key must fail validation"
    );

    // 4. Tamper with swapped valid keypair (public key does not match slot in keychain)
    let other_local_uuid = "99999999-9999-4999-8999-999999999999";
    let other_identity = format!("did:plc:other#{other_local_uuid}");
    let other_real_key = generate_real_exported_identity_key("other_account_id", &other_identity);
    cred_store
        .store_signing_key(did, &other_real_key)
        .await
        .unwrap();
    let swapped_res = catmos_lib::credentials::KeyringCredentialStore::check_credential_state(did);
    assert!(
        swapped_res.is_err(),
        "swapped keypair must fail validation due to missing bound slot"
    );

    // Restore valid signing key
    cred_store
        .store_signing_key(did, &real_exported_key)
        .await
        .unwrap();

    // 5. Tamper local_device_uuid with non-UUID string
    cred_store
        .store_local_device_uuid(did, "not-a-valid-uuid")
        .await
        .unwrap();
    let non_uuid_res = catmos_lib::credentials::KeyringCredentialStore::check_credential_state(did);
    assert!(
        non_uuid_res.is_err(),
        "non-UUID local_device_uuid must fail validation"
    );
    cred_store
        .store_local_device_uuid(did, local_uuid)
        .await
        .unwrap();

    // 6. Tamper server_device_id with mismatched UUID
    cred_store
        .store_server_device_id(did, "99999999-9999-4999-8999-999999999999")
        .await
        .unwrap();
    let mismatched_server_res =
        catmos_lib::credentials::KeyringCredentialStore::check_credential_state(did);
    assert!(
        mismatched_server_res.is_err(),
        "mismatched server_device_id must fail validation"
    );
    cred_store
        .store_server_device_id(did, server_dev_id)
        .await
        .unwrap();

    // 7. Tamper mls_did with mismatched user DID
    cred_store
        .store_mls_did(did, &format!("did:plc:other-user#{local_uuid}"))
        .await
        .unwrap();
    let tampered_did_res =
        catmos_lib::credentials::KeyringCredentialStore::check_credential_state(did);
    assert!(
        tampered_did_res.is_err(),
        "tampered mls_did user DID must fail validation"
    );

    // 8. Tamper mls_did with mismatched UUID
    cred_store
        .store_mls_did(did, &format!("{did}#88888888-8888-4888-8888-888888888888"))
        .await
        .unwrap();
    let tampered_uuid_res =
        catmos_lib::credentials::KeyringCredentialStore::check_credential_state(did);
    assert!(
        tampered_uuid_res.is_err(),
        "tampered mls_did device UUID must fail validation"
    );
    // Clean up
    let _ = catmos_lib::credentials::KeyringCredentialStore::delete_exact_account_credentials(did);
    let _ = catmos_lib::keychain::KeyringKeychainAccess::reset_account_signer_slots(
        &account_id,
        tmp.path(),
    );
    let _ = catmos_lib::keychain::KeyringKeychainAccess::reset_account_signer_slots(
        "other_account_id",
        tmp.path(),
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn cold_reopen_missing_or_unreconciled_device_fails_closed() {
    let store = MemoryDbKeyStore::new();
    let test_service = "catmos-test";
    let tmp = tempfile::tempdir().unwrap();
    let did_owned = format!("did:plc:unreconciled-reopen-user-{}", uuid::Uuid::new_v4());
    let did = &did_owned;
    let account_id = catmos_lib::keys::derive_account_id(did);

    // Clean up
    let _ = catmos_lib::credentials::KeyringCredentialStore::delete_exact_account_credentials(did);
    let _ = catmos_lib::keychain::KeyringKeychainAccess::reset_account_signer_slots(
        &account_id,
        tmp.path(),
    );
    let (storage, mls_ctx, _key, lock) =
        open_clean_account_storage_with_store(tmp.path(), did, test_service, &store).unwrap();

    use catbird_mls::orchestrator::credentials::CredentialStore;
    let cred_store = catmos_lib::credentials::KeyringCredentialStore::try_new().unwrap();
    let local_uuid = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d";
    let server_dev_id = local_uuid;
    let identity = format!("{did}#{local_uuid}");
    let _kp = mls_ctx
        .create_key_package(identity.as_bytes().to_vec())
        .unwrap();
    let exported_key = mls_ctx.export_identity_key(identity.clone()).unwrap();

    cred_store
        .store_signing_key(did, &exported_key)
        .await
        .unwrap();
    cred_store.store_mls_did(did, &identity).await.unwrap();
    cred_store
        .store_server_device_id(did, server_dev_id)
        .await
        .unwrap();
    // Intentionally omit local_device_uuid to simulate missing / unreconciled device
    let _ = mls_ctx.flush_and_prepare_close();
    drop(storage);
    drop(mls_ctx);
    drop(lock);
    write_account_marker_complete(
        &account_marker_path(tmp.path(), &account_id),
        did,
        &account_id,
        &app_db_file_name(&account_id),
        &mls_db_file_name(&account_id),
    )
    .unwrap();

    // Reopen MUST fail closed because local device UUID is missing
    let reopen_res = open_clean_account_storage_with_store(tmp.path(), did, test_service, &store);
    assert!(
        matches!(reopen_res, Err(DatabaseInitError::ValidationFailed(_))),
        "reopen without local device UUID must fail validation"
    );
    // Clean up
    let _ = catmos_lib::credentials::KeyringCredentialStore::delete_exact_account_credentials(did);
    let _ = catmos_lib::keychain::KeyringKeychainAccess::reset_account_signer_slots(
        &account_id,
        tmp.path(),
    );
}

#[test]
fn schema_validator_rejects_injected_check_constraint() {
    let store = MemoryDbKeyStore::new();
    let test_service = "catmos-test";
    let tmp = tempfile::tempdir().unwrap();
    let did = "did:plc:schema-check-val-user";
    let account_id = catmos_lib::keys::derive_account_id(did);

    let app_key_label = app_db_key_label(&account_id);
    let app_key = create_db_key_in_store(&store, test_service, &app_key_label).unwrap();
    let app_db_path = tmp.path().join(app_db_file_name(&account_id));

    let storage =
        catmos_lib::storage::SqliteStorage::create_new(&app_db_path.to_string_lossy(), &app_key)
            .unwrap();
    drop(storage);

    // Mutate conversations table to inject CHECK(length(group_id)=1)
    let conn = rusqlite::Connection::open(&app_db_path).unwrap();
    conn.execute_batch(&format!("PRAGMA key = '{}';", app_key))
        .unwrap();
    conn.execute_batch(
        "ALTER TABLE conversations RENAME TO old_conversations;
         CREATE TABLE conversations (
             conversation_id TEXT NOT NULL,
             user_did TEXT NOT NULL,
             group_id TEXT NOT NULL CHECK(length(group_id)=1),
             epoch INTEGER NOT NULL DEFAULT 0,
             state TEXT NOT NULL DEFAULT 'Active',
             join_method TEXT,
             join_epoch INTEGER,
             needs_rejoin INTEGER NOT NULL DEFAULT 0,
             members_json TEXT NOT NULL DEFAULT '[]',
             metadata_json TEXT,
             metadata_version INTEGER,
             metadata_blob_locator TEXT,
             avatar_blob_locator TEXT,
             avatar_bytes BLOB,
             avatar_content_type TEXT,
             created_at TEXT,
             updated_at TEXT,
             sequencer_did TEXT,
             reset_new_group_id TEXT,
             reset_generation INTEGER,
             reset_notified_at_ms INTEGER,
             quarantine_reason_tag TEXT,
             quarantine_since_ms INTEGER,
             PRIMARY KEY (conversation_id, user_did)
         );
         DROP TABLE old_conversations;",
    )
    .unwrap();
    drop(conn);

    let res = validate_app_db_readonly(&app_db_path, &app_key);
    assert!(
        matches!(res, Err(DatabaseInitError::ValidationFailed(_))),
        "expected ValidationFailed for injected CHECK constraint, got: {res:?}"
    );
}

#[test]
fn missing_or_corrupt_signer_slot_in_index_fails_open() {
    let account_id = format!("test_acc_missing_slot_{}", uuid::Uuid::new_v4());
    let tmp = tempfile::tempdir().unwrap();
    let idx_key = catmos_lib::keychain::KeyringKeychainAccess::index_key_for_account(&account_id);
    let idx_entry = keyring::Entry::new(catmos_lib::keychain::SERVICE_NAME, &idx_key).unwrap();
    // Add slot reference in index without writing the slot entry to keyring
    let missing_slot = format!("sig_key_missing:{}:{}", account_id, MLS_KEY_SUFFIX);
    let mut set = std::collections::BTreeSet::new();
    set.insert(missing_slot);
    idx_entry
        .set_password(&serde_json::to_string(&set).unwrap())
        .unwrap();
    let val_res = catmos_lib::keychain::KeyringKeychainAccess::reset_account_signer_slots(
        &account_id,
        tmp.path(),
    );
    assert!(
        val_res.is_err(),
        "reset must fail when referenced signer slot is missing"
    );

    // Clean up
    let _ = idx_entry.delete_credential();
}

#[test]
fn corrupt_non_json_signer_slot_in_index_fails_validation() {
    let account_id = format!("test_acc_corrupt_slot_{}", uuid::Uuid::new_v4());
    let tmp = tempfile::tempdir().unwrap();
    let idx_key = catmos_lib::keychain::KeyringKeychainAccess::index_key_for_account(&account_id);
    let idx_entry = keyring::Entry::new(catmos_lib::keychain::SERVICE_NAME, &idx_key).unwrap();

    let slot_name = format!("sig_key_corrupt:{}:{}", account_id, MLS_KEY_SUFFIX);
    let slot_entry = keyring::Entry::new(catmos_lib::keychain::SERVICE_NAME, &slot_name).unwrap();
    slot_entry
        .set_password("raw-non-json-corrupt-bytes")
        .unwrap();

    let mut set = std::collections::BTreeSet::new();
    set.insert(slot_name);
    idx_entry
        .set_password(&serde_json::to_string(&set).unwrap())
        .unwrap();
    let val_res = catmos_lib::keychain::KeyringKeychainAccess::reset_account_signer_slots(
        &account_id,
        tmp.path(),
    );
    assert!(
        val_res.is_err(),
        "reset must fail when signer slot contains invalid non-JSON data"
    );

    // Clean up
    let _ = slot_entry.delete_credential();
    let _ = idx_entry.delete_credential();
}

#[tokio::test(flavor = "multi_thread")]
async fn injected_temp_and_marker_removal_failure_reports_error_and_retry_succeeds() {
    let store = MemoryDbKeyStore::new();
    let test_service = "catmos-test";
    let tmp = tempfile::tempdir().unwrap();
    let did_owned = format!("did:plc:removal-fail-retry-user-{}", uuid::Uuid::new_v4());
    let did = &did_owned;
    let account_id = catmos_lib::keys::derive_account_id(did);

    let (storage, mls_ctx, _key, lock) =
        open_clean_account_storage_with_store(tmp.path(), did, test_service, &store).unwrap();
    drop(lock);

    // Create a temp file and make its directory non-writable or make file read-only
    let temp_file = tmp.path().join(format!(
        "catmos-{}-{}.key.tmp.immutable",
        account_id, MLS_KEY_SUFFIX
    ));
    fs::write(&temp_file, b"temp-key-data").unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(tmp.path()).unwrap().permissions();
        perms.set_mode(0o555); // read-only directory
        let _ = fs::set_permissions(tmp.path(), perms);

        let reset_res = reset_account_storage_with_store(
            tmp.path(),
            did,
            Some(storage.clone()),
            Some(&mls_ctx),
            test_service,
            &store,
        )
        .await;

        // Must report error on failed removal
        assert!(
            reset_res.is_err(),
            "reset must fail when directory cannot remove files"
        );

        // Restore permissions
        let mut restore_perms = fs::metadata(tmp.path()).unwrap().permissions();
        restore_perms.set_mode(0o755);
        fs::set_permissions(tmp.path(), restore_perms).unwrap();
    }

    // Retry reset: succeeds cleanly
    let retry_res = reset_account_storage_with_store(
        tmp.path(),
        did,
        Some(storage),
        Some(&mls_ctx),
        test_service,
        &store,
    )
    .await;
    assert!(
        retry_res.is_ok(),
        "retry after permission restore must succeed: {retry_res:?}"
    );
    assert!(!temp_file.exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn shared_auth_provider_propagates_session_and_same_did_token_refresh() {
    let tmp = tempfile::tempdir().unwrap();
    let did_owned = format!("did:plc:shared-auth-refresh-user-{}", uuid::Uuid::new_v4());
    let did = &did_owned;
    let _account_id = catmos_lib::keys::derive_account_id(did);

    let _ = catmos_lib::storage::reset_account_storage(
        tmp.path(),
        did,
        None,
        None,
        catmos_lib::storage::DB_KEYRING_SERVICE,
    )
    .await;

    let state = catmos_lib::AppState::new(
        tmp.path().to_path_buf(),
        "http://127.0.0.1:9999".to_string(),
    );
    use catbird_mls::orchestrator::MLSAPIClient;
    // Initial auth
    state
        .api_client
        .set_auth(did.to_string(), "initial_token_123".to_string());
    assert_eq!(state.api_client.current_did().await, Some(did.to_string()));

    // Token refresh on same DID updates auth provider
    state
        .api_client
        .set_auth(did.to_string(), "refreshed_token_456".to_string());
    assert_eq!(state.api_client.current_did().await, Some(did.to_string()));
    let _ = catmos_lib::storage::reset_account_storage(
        tmp.path(),
        did,
        None,
        None,
        catmos_lib::storage::DB_KEYRING_SERVICE,
    )
    .await;
}

#[test]
fn mismatched_signer_slot_name_and_coherent_keypair_fails_pre_open() {
    let account_id = format!("test_acc_mismatched_slot_{}", uuid::Uuid::new_v4());
    let tmp = tempfile::tempdir().unwrap();
    let did = "did:plc:mismatched-slot-user";
    let identity = format!("{did}#a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d");

    let real_exported_key = generate_real_exported_identity_key(&account_id, &identity);
    let real_key_str = String::from_utf8(real_exported_key).unwrap();

    let idx_key = catmos_lib::keychain::KeyringKeychainAccess::index_key_for_account(&account_id);
    let idx_entry = keyring::Entry::new(catmos_lib::keychain::SERVICE_NAME, &idx_key).unwrap();

    // Intentionally name the slot differently from derived canonical public key name
    let mismatched_slot = format!(
        "sig_key_0000000000000000000000000000000000000000000000000000000000000000:{}:{}",
        account_id, MLS_KEY_SUFFIX
    );
    let slot_entry =
        keyring::Entry::new(catmos_lib::keychain::SERVICE_NAME, &mismatched_slot).unwrap();
    slot_entry.set_password(&real_key_str).unwrap();

    let mut set = std::collections::BTreeSet::new();
    set.insert(mismatched_slot.clone());
    idx_entry
        .set_password(&serde_json::to_string(&set).unwrap())
        .unwrap();
    let val_res = catmos_lib::keychain::KeyringKeychainAccess::reset_account_signer_slots(
        &account_id,
        tmp.path(),
    );
    assert!(
        val_res.is_err(),
        "reset must fail when slot name does not match derived public key"
    );

    // Clean up
    let _ = slot_entry.delete_credential();
    let _ = idx_entry.delete_credential();
}

#[tokio::test(flavor = "multi_thread")]
async fn remove_signers_manifest_row_fails_preopen_without_mutation() {
    let store = MemoryDbKeyStore::new();
    let test_service = "catmos-test";
    let tmp = tempfile::tempdir().unwrap();
    let did_owned = format!(
        "did:plc:remove-signers-manifest-user-{}",
        uuid::Uuid::new_v4()
    );
    let did = &did_owned;
    let account_id = catmos_lib::keys::derive_account_id(did);

    // Clean up
    let _ = catmos_lib::credentials::KeyringCredentialStore::delete_exact_account_credentials(did);
    let _ = catmos_lib::keychain::KeyringKeychainAccess::reset_account_signer_slots(
        &account_id,
        tmp.path(),
    );
    let (storage, mls_ctx, _key, lock) =
        open_clean_account_storage_with_store(tmp.path(), did, test_service, &store).unwrap();

    use catbird_mls::orchestrator::credentials::CredentialStore;
    let cred_store = catmos_lib::credentials::KeyringCredentialStore::try_new().unwrap();
    let local_uuid = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d";
    let server_dev_id = local_uuid;
    let identity = format!("{did}#{local_uuid}");
    let _kp = mls_ctx
        .create_key_package(identity.as_bytes().to_vec())
        .unwrap();
    let exported_key = mls_ctx.export_identity_key(identity.clone()).unwrap();

    cred_store
        .store_signing_key(did, &exported_key)
        .await
        .unwrap();
    cred_store.store_mls_did(did, &identity).await.unwrap();
    cred_store
        .store_server_device_id(did, server_dev_id)
        .await
        .unwrap();
    cred_store
        .store_local_device_uuid(did, local_uuid)
        .await
        .unwrap();
    let _ = mls_ctx.flush_and_prepare_close();
    drop(storage);
    drop(mls_ctx);
    drop(lock);
    write_account_marker_complete(
        &account_marker_path(tmp.path(), &account_id),
        did,
        &account_id,
        &app_db_file_name(&account_id),
        &mls_db_file_name(&account_id),
    )
    .unwrap();
    let mls_state_dir = tmp.path().join(MLS_STORAGE_GENERATION);
    let mls_db_path = mls_state_dir.join(mls_db_file_name(&account_id));
    let mls_key_label = mls_db_key_label(&account_id);
    let mls_key = store
        .get_password(test_service, &mls_key_label)
        .unwrap()
        .unwrap();

    // Delete signers manifest row from MLS DB
    let conn = rusqlite::Connection::open(&mls_db_path).unwrap();
    conn.pragma_update(None, "cipher_memory_security", "OFF")
        .unwrap();
    conn.pragma_update(None, "key", &mls_key).unwrap();
    conn.pragma_update(None, "cipher_plaintext_header_size", 32)
        .unwrap();
    let salt_hex = catmos_lib::storage::derive_cipher_salt_hex(&mls_key);
    conn.pragma_update(None, "cipher_salt", format!("x'{}'", salt_hex))
        .unwrap();
    conn.pragma_update(None, "cipher_page_size", 4096).unwrap();
    conn.pragma_update(None, "kdf_iter", 256000).unwrap();
    conn.pragma_update(None, "cipher_hmac_algorithm", "HMAC_SHA512")
        .unwrap();
    conn.pragma_update(None, "cipher_kdf_algorithm", "PBKDF2_HMAC_SHA512")
        .unwrap();
    conn.execute("DELETE FROM mls_manifests WHERE key = 'signers'", [])
        .unwrap();
    drop(conn);

    let meta_before = fs::metadata(&mls_db_path).unwrap();
    let reopen_res = open_clean_account_storage_with_store(tmp.path(), did, test_service, &store);
    let meta_after = fs::metadata(&mls_db_path).unwrap();

    assert!(
        matches!(reopen_res, Err(DatabaseInitError::ValidationFailed(_))),
        "reopen without signers manifest row must fail validation"
    );
    assert_eq!(
        meta_before.len(),
        meta_after.len(),
        "failed validation must not mutate DB"
    );

    // Clean up
    let _ = catmos_lib::credentials::KeyringCredentialStore::delete_exact_account_credentials(did);
    let _ = catmos_lib::keychain::KeyringKeychainAccess::reset_account_signer_slots(
        &account_id,
        tmp.path(),
    );
}

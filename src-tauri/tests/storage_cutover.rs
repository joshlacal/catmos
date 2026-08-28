use async_trait::async_trait;
use catbird_mls::{KeychainAccess, MLSError};
use catmos_lib::storage::{
    create_db_key_in_store, marker_path, open_clean_mls_context_with_store, read_marker,
    write_marker_complete, write_marker_creating, DatabaseInitError, MarkerStatus,
    MemoryDbKeyStore, CONVERSATION_DB_KEY_LABEL, DB_KEYRING_SERVICE, MLS_DB_KEY_LABEL,
    MLS_KEY_SUFFIX, MLS_STORAGE_GENERATION,
};
use std::collections::HashMap;
use std::fs;
use std::sync::Mutex;

struct TestKeychain {
    values: Mutex<HashMap<String, Vec<u8>>>,
}

impl TestKeychain {
    fn new() -> Self {
        Self {
            values: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl KeychainAccess for TestKeychain {
    async fn read(&self, key: String) -> Result<Option<Vec<u8>>, MLSError> {
        Ok(self.values.lock().unwrap().get(&key).cloned())
    }

    async fn write(&self, key: String, value: Vec<u8>) -> Result<(), MLSError> {
        self.values.lock().unwrap().insert(key, value);
        Ok(())
    }

    async fn delete(&self, key: String) -> Result<(), MLSError> {
        self.values.lock().unwrap().remove(&key);
        Ok(())
    }
}

#[test]
fn generation_constants_match_specification() {
    assert_eq!(
        catmos_lib::storage::MLS_STORAGE_GENERATION,
        "mls-state-clean-v2-openmls-v09"
    );
    assert_eq!(
        catmos_lib::storage::MLS_KEY_SUFFIX,
        "clean-v2-openmls-v09"
    );
    assert_eq!(
        catmos_lib::storage::CONVERSATION_DB_KEY_LABEL,
        "conversation-db-clean-v2-openmls-v09"
    );
    assert_eq!(
        catmos_lib::storage::MLS_DB_KEY_LABEL,
        "mls-db-clean-v2-openmls-v09"
    );
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

    // Reopen returns same bytes
    let reopened = catmos_lib::keys::load_or_create_content_root_key(tmp.path(), did)
        .expect("reopen should succeed");
    assert_eq!(clean_key, reopened);

    // Delete removes clean key only
    catmos_lib::keys::delete_content_root_key(tmp.path(), did)
        .expect("delete should succeed");

    // Legacy sentinel remains intact
    assert!(legacy_file.exists());
    assert_eq!(
        fs::read(&legacy_file).unwrap(),
        b"legacy-sentinel-data-32-bytes!!!"
    );
}

#[test]
fn content_root_key_rejects_corrupt_file() {
    let tmp = tempfile::tempdir().unwrap();
    let did = "did:plc:corrupt-key-user";
    let clean_dir = tmp.path().join(catmos_lib::keys::MLS_CONTENT_ROOT_DIR);
    fs::create_dir_all(&clean_dir).unwrap();

    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(did.as_bytes());
    let did_hash = hex::encode(hasher.finalize());
    let key_file = clean_dir.join(format!("{}.key", did_hash));
    fs::write(&key_file, b"corrupted-short-key").unwrap();

    let err = catmos_lib::keys::load_or_create_content_root_key(tmp.path(), did).unwrap_err();
    assert!(err.to_string().contains("wrong length"));
    // Corrupt file must NOT have been overwritten
    assert_eq!(fs::read(&key_file).unwrap(), b"corrupted-short-key");
}

#[test]
fn clean_mls_context_fresh_creation_and_reopen() {
    let store = MemoryDbKeyStore::new();
    let test_service = "catmos-test-mls";
    let tmp = tempfile::tempdir().unwrap();
    let mls_state_dir = tmp.path().join(MLS_STORAGE_GENERATION);
    fs::create_dir_all(&mls_state_dir).unwrap();
    let mls_db_path = mls_state_dir.join("mls.db");
    let marker_file = marker_path(&mls_db_path);
    let db_file_name = mls_db_path.file_name().unwrap().to_str().unwrap();

    assert!(!mls_db_path.exists());
    assert!(!marker_file.exists());

    // First open: creates key, DB, and marker
    let ctx = open_clean_mls_context_with_store(
        &mls_db_path,
        test_service,
        Box::new(TestKeychain::new()),
        &store,
    )
    .expect("first open of MLSContext should succeed");
    assert!(mls_db_path.exists());
    assert!(marker_file.exists());
    let marker = read_marker(&marker_file, db_file_name).unwrap();
    assert_eq!(marker, Some(MarkerStatus::Complete));
    drop(ctx);

    // Second open: reopens existing valid MLS database
    let ctx2 = open_clean_mls_context_with_store(
        &mls_db_path,
        test_service,
        Box::new(TestKeychain::new()),
        &store,
    )
    .expect("reopen of MLSContext should succeed");
    drop(ctx2);
}

#[test]
fn clean_mls_context_mixed_states_fail_closed() {
    let tmp = tempfile::tempdir().unwrap();
    let mls_state_dir = tmp.path().join(MLS_STORAGE_GENERATION);
    fs::create_dir_all(&mls_state_dir).unwrap();
    let mls_db_path = mls_state_dir.join("mls.db");
    let marker_file = marker_path(&mls_db_path);
    let db_file_name = mls_db_path.file_name().unwrap().to_str().unwrap();

    // Case 1: absent DB, present key
    let store1 = MemoryDbKeyStore::new();
    let _ = create_db_key_in_store(&store1, "s1", MLS_DB_KEY_LABEL).unwrap();
    let err = open_clean_mls_context_with_store(
        &mls_db_path,
        "s1",
        Box::new(TestKeychain::new()),
        &store1,
    )
    .unwrap_err();
    assert!(matches!(err, DatabaseInitError::MixedStateAbsentDbPresentKey));

    // Case 2: present DB, absent key
    let store2 = MemoryDbKeyStore::new();
    fs::write(&mls_db_path, b"fake-mls-db-bytes").unwrap();
    let err = open_clean_mls_context_with_store(
        &mls_db_path,
        "s2",
        Box::new(TestKeychain::new()),
        &store2,
    )
    .unwrap_err();
    assert!(matches!(err, DatabaseInitError::MixedStatePresentDbAbsentKey));
    let _ = fs::remove_file(&mls_db_path);

    // Case 3: creating marker with present DB and present key (InitializationIncomplete)
    let store3 = MemoryDbKeyStore::new();
    let _ = create_db_key_in_store(&store3, "s3", MLS_DB_KEY_LABEL).unwrap();
    fs::write(&mls_db_path, b"fake-mls-db-bytes").unwrap();
    write_marker_creating(&marker_file, db_file_name).unwrap();
    let err = open_clean_mls_context_with_store(
        &mls_db_path,
        "s3",
        Box::new(TestKeychain::new()),
        &store3,
    )
    .unwrap_err();
    assert!(matches!(err, DatabaseInitError::InitializationIncomplete));
    let _ = fs::remove_file(&mls_db_path);
    let _ = fs::remove_file(&marker_file);

    // Case 4: orphan complete marker (DB and key absent) -> InvalidMarker
    let store4 = MemoryDbKeyStore::new();
    write_marker_complete(&marker_file, db_file_name).unwrap();
    let err = open_clean_mls_context_with_store(
        &mls_db_path,
        "s4",
        Box::new(TestKeychain::new()),
        &store4,
    )
    .unwrap_err();
    assert!(matches!(err, DatabaseInitError::InvalidMarker(_)));
    let _ = fs::remove_file(&marker_file);
}

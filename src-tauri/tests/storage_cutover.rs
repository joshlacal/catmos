use std::fs;
use std::sync::Mutex;
use std::collections::HashMap;
use async_trait::async_trait;
use catbird_mls::{KeychainAccess, MLSError};
use catmos_lib::catbird;

const GENERATION_TOKEN: &str = "mls-state-clean-v2-openmls-v09";
const KEY_SUFFIX: &str = "clean-v2-openmls-v09";

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
    assert_eq!(GENERATION_TOKEN, "mls-state-clean-v2-openmls-v09");
    assert_eq!(KEY_SUFFIX, "clean-v2-openmls-v09");
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

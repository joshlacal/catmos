use async_trait::async_trait;
use catbird_mls::KeychainAccess;
use catbird_mls::MLSError;
use keyring::Entry;
use std::collections::BTreeSet;
use std::sync::Mutex;

pub const SERVICE_NAME: &str = "blue.catbird.catmos.mls.clean-v2-openmls-v09";
pub const KEY_SUFFIX: &str = "clean-v2-openmls-v09";
pub const SIGNER_INDEX_KEY: &str = "signer_slots_index";

static INDEX_LOCK: Mutex<()> = Mutex::new(());

/// OS keychain-backed implementation of `KeychainAccess` for MLS FFI.
pub struct KeyringKeychainAccess;

impl KeyringKeychainAccess {
    pub fn new() -> Self {
        match Self::try_new() {
            Ok(keychain) => keychain,
            Err(err) => panic!("{err}"),
        }
    }

    pub fn try_new() -> std::result::Result<Self, MLSError> {
        #[cfg(target_os = "android")]
        {
            Err(MLSError::Internal(
                "Android secure MLS keychain is not implemented; refusing to initialize MLS with keyring's mock store"
                    .to_string(),
            ))
        }

        #[cfg(not(target_os = "android"))]
        {
            Ok(Self)
        }
    }

    pub(crate) fn scoped_key(key: &str) -> String {
        format!("{}:{}", key, KEY_SUFFIX)
    }

    fn entry(key: &str) -> std::result::Result<Entry, keyring::Error> {
        Entry::new(SERVICE_NAME, &Self::scoped_key(key))
    }

    fn index_entry() -> std::result::Result<Entry, keyring::Error> {
        Entry::new(SERVICE_NAME, &Self::scoped_key(SIGNER_INDEX_KEY))
    }

    fn load_index_locked() -> std::result::Result<BTreeSet<String>, MLSError> {
        let entry = Self::index_entry().map_err(|e| MLSError::Internal(e.to_string()))?;
        match entry.get_password() {
            Ok(json_str) => {
                let set: BTreeSet<String> = serde_json::from_str(&json_str)
                    .map_err(|e| MLSError::Internal(format!("corrupt signer slots index: {e}")))?;
                Ok(set)
            }
            Err(keyring::Error::NoEntry) => Ok(BTreeSet::new()),
            Err(e) => Err(MLSError::Internal(e.to_string())),
        }
    }

    fn save_index_locked(index: &BTreeSet<String>) -> std::result::Result<(), MLSError> {
        let entry = Self::index_entry().map_err(|e| MLSError::Internal(e.to_string()))?;
        if index.is_empty() {
            match entry.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
                Err(e) => Err(MLSError::Internal(e.to_string())),
            }
        } else {
            let json_str = serde_json::to_string(index)
                .map_err(|e| MLSError::Internal(format!("failed to serialize signer slots index: {e}")))?;
            entry
                .set_password(&json_str)
                .map_err(|e| MLSError::Internal(e.to_string()))
        }
    }

    pub fn clear_all() -> std::result::Result<(), String> {
        #[cfg(target_os = "android")]
        {
            Err("Android secure MLS keychain is not implemented; refusing to clear via keyring".to_string())
        }

        #[cfg(not(target_os = "android"))]
        {
            let _guard = INDEX_LOCK.lock().unwrap();
            let index = Self::load_index_locked().map_err(|e| e.to_string())?;
            for scoped_account in index {
                let entry = Entry::new(SERVICE_NAME, &scoped_account)
                    .map_err(|e| format!("failed to access entry for signer slot {scoped_account}: {e}"))?;
                match entry.delete_credential() {
                    Ok(()) | Err(keyring::Error::NoEntry) => {}
                    Err(e) => return Err(format!("failed to delete signer slot {scoped_account}: {e}")),
                }
            }
            let idx_entry = Self::index_entry()
                .map_err(|e| format!("failed to access signer index entry: {e}"))?;
            match idx_entry.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => {}
                Err(e) => return Err(format!("failed to delete signer index entry: {e}")),
            }
            Ok(())
        }
    }
}
#[async_trait]
impl KeychainAccess for KeyringKeychainAccess {
    async fn read(&self, key: String) -> Result<Option<Vec<u8>>, MLSError> {
        match Self::entry(&key) {
            Ok(entry) => match entry.get_password() {
                Ok(val) => Ok(Some(val.into_bytes())),
                Err(keyring::Error::NoEntry) => Ok(None),
                Err(e) => Err(MLSError::Internal(e.to_string())),
            },
            Err(e) => Err(MLSError::Internal(e.to_string())),
        }
    }

    async fn write(&self, key: String, value: Vec<u8>) -> Result<(), MLSError> {
        let val_str = String::from_utf8(value).map_err(|e| MLSError::Internal(e.to_string()))?;
        let entry =
            Self::entry(&key).map_err(|e: keyring::Error| MLSError::Internal(e.to_string()))?;
        let scoped_slot = Self::scoped_key(&key);

        // Record exact scoped slot in index before writing value
        let _guard = INDEX_LOCK.lock().unwrap();
        let mut index = Self::load_index_locked()?;
        if !index.contains(&scoped_slot) {
            index.insert(scoped_slot);
            Self::save_index_locked(&index)?;
        }

        entry
            .set_password(&val_str)
            .map_err(|e| MLSError::Internal(e.to_string()))
    }

    async fn delete(&self, key: String) -> Result<(), MLSError> {
        let entry =
            Self::entry(&key).map_err(|e: keyring::Error| MLSError::Internal(e.to_string()))?;

        let _guard = INDEX_LOCK.lock().unwrap();
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => {}
            Err(e) => return Err(MLSError::Internal(e.to_string())),
        }

        let scoped_slot = Self::scoped_key(&key);
        let mut index = Self::load_index_locked()?;
        if index.remove(&scoped_slot) {
            Self::save_index_locked(&index)?;
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "android")]
    #[test]
    fn android_keychain_constructor_fails_closed() {
        let err = match KeyringKeychainAccess::try_new() {
            Ok(_) => panic!("Android must not use keyring's mock key store"),
            Err(err) => err,
        };
        assert!(
            err.to_string()
                .contains("Android secure MLS keychain is not implemented"),
            "unexpected error: {err}"
        );
    }

    #[cfg(not(target_os = "android"))]
    #[test]
    fn non_android_keychain_constructor_succeeds() {
        let _ = KeyringKeychainAccess::try_new().expect("desktop keychain constructor should work");
    }

    #[test]
    fn signer_index_and_slot_key_scoping_matches_clean_generation() {
        assert_eq!(SERVICE_NAME, "blue.catbird.catmos.mls.clean-v2-openmls-v09");
        assert_eq!(KEY_SUFFIX, "clean-v2-openmls-v09");
        assert_eq!(
            KeyringKeychainAccess::scoped_key(SIGNER_INDEX_KEY),
            "signer_slots_index:clean-v2-openmls-v09"
        );
        assert_eq!(
            KeyringKeychainAccess::scoped_key("sig_key_test_pubkey_123"),
            "sig_key_test_pubkey_123:clean-v2-openmls-v09"
        );
    }

    #[test]
    fn signer_index_serialization_round_trip() {
        let mut set = BTreeSet::new();
        set.insert("sig_key_abc:clean-v2-openmls-v09".to_string());
        set.insert("sig_key_xyz:clean-v2-openmls-v09".to_string());
        let json_str = serde_json::to_string(&set).expect("serialize index");
        let restored: BTreeSet<String> = serde_json::from_str(&json_str).expect("deserialize index");
        assert_eq!(set, restored);
    }
}

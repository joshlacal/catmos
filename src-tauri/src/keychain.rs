use async_trait::async_trait;
use catbird_mls::KeychainAccess;
use catbird_mls::MLSError;
use keyring::Entry;
use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Mutex;

pub const SERVICE_NAME: &str = "blue.catbird.catmos.mls.clean-v2-openmls-v09";
pub const KEY_SUFFIX: &str = "clean-v2-openmls-v09";

static INDEX_MUTEX: Mutex<()> = Mutex::new(());

/// OS keychain-backed implementation of `KeychainAccess` for MLS FFI,
/// scoped to a single account ID.
pub struct KeyringKeychainAccess {
    account_id: String,
}

impl KeyringKeychainAccess {
    pub fn new(account_id: String) -> Self {
        match Self::try_new(account_id) {
            Ok(keychain) => keychain,
            Err(err) => panic!("{err}"),
        }
    }

    pub fn try_new(account_id: String) -> std::result::Result<Self, MLSError> {
        #[cfg(target_os = "android")]
        {
            let _ = account_id;
            Err(MLSError::Internal(
                "Android secure MLS keychain is not implemented; refusing to initialize MLS with keyring's mock store"
                    .to_string(),
            ))
        }

        #[cfg(not(target_os = "android"))]
        {
            Ok(Self { account_id })
        }
    }

    pub fn scoped_key(&self, key: &str) -> String {
        format!("{}:{}:{}", key, self.account_id, KEY_SUFFIX)
    }

    pub fn index_key_for_account(account_id: &str) -> String {
        format!("signer_slots_index:{}:{}", account_id, KEY_SUFFIX)
    }

    fn index_key(&self) -> String {
        Self::index_key_for_account(&self.account_id)
    }

    fn entry(&self, key: &str) -> std::result::Result<Entry, keyring::Error> {
        Entry::new(SERVICE_NAME, &self.scoped_key(key))
    }

    fn index_entry(&self) -> std::result::Result<Entry, keyring::Error> {
        Entry::new(SERVICE_NAME, &self.index_key())
    }

    fn load_index(&self) -> std::result::Result<BTreeSet<String>, MLSError> {
        let entry = self
            .index_entry()
            .map_err(|e| MLSError::Internal(e.to_string()))?;
        match entry.get_password() {
            Ok(json_str) => {
                let trimmed = json_str.trim();
                if trimmed.is_empty() {
                    return Err(MLSError::Internal(
                        "signer slots index is empty or corrupt in keychain".into(),
                    ));
                }
                let set: BTreeSet<String> = serde_json::from_str(trimmed)
                    .map_err(|e| MLSError::Internal(format!("corrupt signer slots index: {e}")))?;
                Ok(set)
            }
            Err(keyring::Error::NoEntry) => Ok(BTreeSet::new()),
            Err(e) => Err(MLSError::Internal(e.to_string())),
        }
    }

    fn save_index(&self, index: &BTreeSet<String>) -> std::result::Result<(), MLSError> {
        let entry = self
            .index_entry()
            .map_err(|e| MLSError::Internal(e.to_string()))?;
        if index.is_empty() {
            match entry.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
                Err(e) => Err(MLSError::Internal(e.to_string())),
            }
        } else {
            let json_str = serde_json::to_string(index).map_err(|e| {
                MLSError::Internal(format!("failed to serialize signer slots index: {e}"))
            })?;
            entry
                .set_password(&json_str)
                .map_err(|e| MLSError::Internal(e.to_string()))
        }
    }
    pub(crate) fn has_signer_slots_unlocked(account_id: &str) -> std::result::Result<bool, String> {
        #[cfg(target_os = "android")]
        {
            let _ = account_id;
            Ok(false)
        }

        #[cfg(not(target_os = "android"))]
        {
            let _guard = INDEX_MUTEX.lock().unwrap();
            let idx_key = Self::index_key_for_account(account_id);
            let idx_entry = Entry::new(SERVICE_NAME, &idx_key)
                .map_err(|e| format!("failed to access signer index entry: {e}"))?;

            match idx_entry.get_password() {
                Ok(json_str) => {
                    let trimmed = json_str.trim();
                    if trimmed.is_empty() {
                        Ok(false)
                    } else if let Ok(set) = serde_json::from_str::<BTreeSet<String>>(trimmed) {
                        Ok(!set.is_empty())
                    } else {
                        Ok(true) // Non-empty entry exists
                    }
                }
                Err(keyring::Error::NoEntry) => Ok(false),
                Err(e) => Err(format!("failed to read signer index: {e}")),
            }
        }
    }

    /// Perform strict read-only validation of all signer slots for `account_id` in keychain:
    /// verifies exact account-scoped index entries, and verifies every referenced keyring value
    /// is present, non-empty, and valid UTF-8/bytes.
    pub(crate) fn validate_signer_slots_unlocked(
        account_id: &str,
    ) -> std::result::Result<(), String> {
        Self::preflight_account_signer_slots_reset(account_id)?;
        Ok(())
    }

    /// Read-only preflight for signer slot reset: validates that index is readable,
    /// each indexed slot exists, is non-empty, contains valid JSON, has a coherent keypair,
    /// and matches the exact derived public key name, returning the verified list of slots.
    pub(crate) fn preflight_account_signer_slots_reset(
        account_id: &str,
    ) -> std::result::Result<Vec<String>, String> {
        #[cfg(target_os = "android")]
        {
            let _ = account_id;
            Err(
                "Android secure MLS keychain is not implemented; refusing to clear via keyring"
                    .to_string(),
            )
        }

        #[cfg(not(target_os = "android"))]
        {
            let _guard = INDEX_MUTEX.lock().unwrap();
            let idx_key = Self::index_key_for_account(account_id);
            let idx_entry = Entry::new(SERVICE_NAME, &idx_key)
                .map_err(|e| format!("failed to access signer index entry: {e}"))?;

            let expected_suffix = format!(":{}:{}", account_id, KEY_SUFFIX);

            let index: BTreeSet<String> = match idx_entry.get_password() {
                Ok(json_str) => {
                    let trimmed = json_str.trim();
                    if trimmed.is_empty() {
                        return Err(
                            "signer slots index is empty or corrupt in keychain".to_string()
                        );
                    }
                    serde_json::from_str(trimmed)
                        .map_err(|e| format!("corrupt signer slots index: {e}"))?
                }
                Err(keyring::Error::NoEntry) => BTreeSet::new(),
                Err(e) => return Err(format!("failed to read signer index: {e}")),
            };

            let mut slots = Vec::new();
            for scoped_slot in &index {
                if !scoped_slot.ends_with(&expected_suffix) {
                    return Err(format!(
                        "signer slots index contains non-account scoped slot `{scoped_slot}`"
                    ));
                }
                if !scoped_slot.starts_with("sig_key_") {
                    return Err(format!(
                        "signer slots index contains non-signer slot `{scoped_slot}`"
                    ));
                }

                let slot_entry = Entry::new(SERVICE_NAME, scoped_slot).map_err(|e| {
                    format!("failed to access entry for signer slot {scoped_slot}: {e}")
                })?;

                match slot_entry.get_password() {
                    Ok(val) => {
                        let trimmed = val.trim();
                        if trimmed.is_empty() {
                            return Err(format!(
                                "signer slot {scoped_slot} in keychain is empty or corrupt"
                            ));
                        }
                        let val_bytes = val.as_bytes();
                        let val_json: serde_json::Value = serde_json::from_str(trimmed)
                            .map_err(|e| format!("signer slot {scoped_slot} is not valid canonical SignatureKeyPair JSON: {e}"))?;
                        let pk_val = val_json.get("public").and_then(|p| p.as_array()).ok_or_else(|| {
                            format!("signer slot {scoped_slot} is missing public field in SignatureKeyPair")
                        })?;
                        let pk_bytes: Vec<u8> = pk_val
                            .iter()
                            .filter_map(|v| v.as_u64().and_then(|n| u8::try_from(n).ok()))
                            .collect();
                        if pk_bytes.len() != 32 {
                            return Err(format!(
                                "signer slot {scoped_slot} has invalid public key length {}",
                                pk_bytes.len()
                            ));
                        }

                        // Validate internal coherence of serialized keypair against public key
                        catbird_mls::validate_serialized_signer_keypair_coherence(
                            val_bytes, &pk_bytes,
                        )
                        .map_err(|e| {
                            format!("signer slot {scoped_slot} has incoherent keypair: {e}")
                        })?;

                        // Compute canonical signer slot name and verify exact match
                        let canonical_slot_key =
                            catbird_mls::canonical_signer_keychain_key(&pk_bytes).map_err(|e| {
                                format!(
                                    "failed to compute canonical slot key for {scoped_slot}: {e}"
                                )
                            })?;
                        let expected_slot_name =
                            format!("{}:{}:{}", canonical_slot_key, account_id, KEY_SUFFIX);

                        if scoped_slot != &expected_slot_name {
                            return Err(format!(
                                "signer slot `{scoped_slot}` does not match derived public key slot name `{expected_slot_name}`"
                            ));
                        }

                        slots.push(scoped_slot.clone());
                    }
                    Err(keyring::Error::NoEntry) => {
                        return Err(format!(
                            "signer slot {scoped_slot} referenced in index is missing from keychain"
                        ));
                    }
                    Err(e) => {
                        return Err(format!(
                            "failed to read signer slot {scoped_slot} from keychain: {e}"
                        ));
                    }
                }
            }

            Ok(slots)
        }
    }

    /// Execute deletion of verified signer slots and index entry.
    pub(crate) fn execute_account_signer_slots_reset(
        account_id: &str,
        slots_to_delete: Vec<String>,
    ) -> std::result::Result<(), String> {
        #[cfg(target_os = "android")]
        {
            let _ = (account_id, slots_to_delete);
            Err(
                "Android secure MLS keychain is not implemented; refusing to clear via keyring"
                    .to_string(),
            )
        }

        #[cfg(not(target_os = "android"))]
        {
            let _guard = INDEX_MUTEX.lock().unwrap();
            let expected_suffix = format!(":{}:{}", account_id, KEY_SUFFIX);

            // Revalidate every slot has exact canonical prefix and suffix before performing any delete
            for scoped_slot in &slots_to_delete {
                if !scoped_slot.ends_with(&expected_suffix) {
                    return Err(format!(
                        "cannot delete foreign or malformed slot `{scoped_slot}` for account `{account_id}`"
                    ));
                }
                if !scoped_slot.starts_with("sig_key_") {
                    return Err(format!(
                        "cannot delete non-signer slot `{scoped_slot}` for account `{account_id}`"
                    ));
                }
            }

            let idx_key = Self::index_key_for_account(account_id);
            let idx_entry = Entry::new(SERVICE_NAME, &idx_key)
                .map_err(|e| format!("failed to access signer index entry: {e}"))?;

            for scoped_slot in slots_to_delete {
                let entry = Entry::new(SERVICE_NAME, &scoped_slot).map_err(|e| {
                    format!("failed to access entry for signer slot {scoped_slot}: {e}")
                })?;
                match entry.delete_credential() {
                    Ok(()) | Err(keyring::Error::NoEntry) => {}
                    Err(e) => {
                        return Err(format!("failed to delete signer slot {scoped_slot}: {e}"))
                    }
                }
            }

            match idx_entry.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => {}
                Err(e) => return Err(format!("failed to delete signer index entry: {e}")),
            }

            Ok(())
        }
    }

    /// Reset all signer slots belonging to the specified `account_id` when the
    /// exclusive account lock is ALREADY held by the caller.
    pub(crate) fn reset_account_signer_slots_unlocked(
        account_id: &str,
    ) -> std::result::Result<(), String> {
        let slots = Self::preflight_account_signer_slots_reset(account_id)?;
        Self::execute_account_signer_slots_reset(account_id, slots)
    }
    /// Reset all signer slots belonging to the specified `account_id` (acquires lock).
    pub fn reset_account_signer_slots(
        account_id: &str,
        lock_dir: &Path,
    ) -> std::result::Result<(), String> {
        #[cfg(target_os = "android")]
        {
            let _ = (account_id, lock_dir);
            Err(
                "Android secure MLS keychain is not implemented; refusing to clear via keyring"
                    .to_string(),
            )
        }

        #[cfg(not(target_os = "android"))]
        {
            let _lock =
                crate::storage::acquire_account_lock(lock_dir, account_id).map_err(|e| {
                    format!("failed to acquire account lock for signer slot reset: {e}")
                })?;
            Self::reset_account_signer_slots_unlocked(account_id)
        }
    }
}

#[async_trait]
impl KeychainAccess for KeyringKeychainAccess {
    async fn read(&self, key: String) -> Result<Option<Vec<u8>>, MLSError> {
        match self.entry(&key) {
            Ok(entry) => match entry.get_password() {
                Ok(val) => {
                    let trimmed = val.trim();
                    if trimmed.is_empty() {
                        return Err(MLSError::Internal(format!(
                            "signer slot {key} is empty or corrupt in keychain"
                        )));
                    }
                    Ok(Some(val.into_bytes()))
                }
                Err(keyring::Error::NoEntry) => Ok(None),
                Err(e) => Err(MLSError::Internal(e.to_string())),
            },
            Err(e) => Err(MLSError::Internal(e.to_string())),
        }
    }

    async fn write(&self, key: String, value: Vec<u8>) -> Result<(), MLSError> {
        if value.is_empty() {
            return Err(MLSError::Internal(
                "cannot persist empty signer slot value".into(),
            ));
        }
        let val_str = String::from_utf8(value).map_err(|e| MLSError::Internal(e.to_string()))?;
        let entry = self
            .entry(&key)
            .map_err(|e: keyring::Error| MLSError::Internal(e.to_string()))?;
        let scoped_slot = self.scoped_key(&key);

        {
            let _guard = INDEX_MUTEX.lock().unwrap();
            let mut index = self.load_index()?;
            if !index.contains(&scoped_slot) {
                index.insert(scoped_slot);
                self.save_index(&index)?;
            }
        }

        entry
            .set_password(&val_str)
            .map_err(|e| MLSError::Internal(e.to_string()))
    }

    async fn delete(&self, key: String) -> Result<(), MLSError> {
        let entry = self
            .entry(&key)
            .map_err(|e: keyring::Error| MLSError::Internal(e.to_string()))?;

        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => {}
            Err(e) => return Err(MLSError::Internal(e.to_string())),
        }

        let scoped_slot = self.scoped_key(&key);
        {
            let _guard = INDEX_MUTEX.lock().unwrap();
            let mut index = self.load_index()?;
            if index.remove(&scoped_slot) {
                self.save_index(&index)?;
            }
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
        let err = match KeyringKeychainAccess::try_new("test_account".to_string()) {
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
        let _ = KeyringKeychainAccess::try_new("test_account".to_string())
            .expect("desktop keychain constructor should work");
    }

    #[test]
    fn signer_index_and_slot_key_scoping_matches_clean_generation() {
        let ka = KeyringKeychainAccess::new("account_123".to_string());
        assert_eq!(SERVICE_NAME, "blue.catbird.catmos.mls.clean-v2-openmls-v09");
        assert_eq!(KEY_SUFFIX, "clean-v2-openmls-v09");
        assert_eq!(
            ka.index_key(),
            "signer_slots_index:account_123:clean-v2-openmls-v09"
        );
        assert_eq!(
            ka.scoped_key("sig_key_test_pubkey_123"),
            "sig_key_test_pubkey_123:account_123:clean-v2-openmls-v09"
        );
    }

    #[test]
    fn signer_index_serialization_round_trip() {
        let mut set = BTreeSet::new();
        set.insert("sig_key_abc:account1:clean-v2-openmls-v09".to_string());
        set.insert("sig_key_xyz:account1:clean-v2-openmls-v09".to_string());
        let json_str = serde_json::to_string(&set).expect("serialize index");
        let restored: BTreeSet<String> =
            serde_json::from_str(&json_str).expect("deserialize index");
        assert_eq!(set, restored);
    }

    #[test]
    fn execute_account_signer_slots_reset_rejects_foreign_or_malformed_slots() {
        let valid = format!("sig_key_test:account_a:{KEY_SUFFIX}");
        let foreign = format!("sig_key_test:account_b:{KEY_SUFFIX}");
        let malformed = format!("not_a_signer_slot:account_a:{KEY_SUFFIX}");

        let foreign_error = KeyringKeychainAccess::execute_account_signer_slots_reset(
            "account_a",
            vec![valid, foreign],
        )
        .expect_err("another account's slot must be rejected");
        assert!(foreign_error.contains("foreign or malformed slot"));

        let malformed_error =
            KeyringKeychainAccess::execute_account_signer_slots_reset("account_a", vec![malformed])
                .expect_err("a non-signer slot must be rejected");
        assert!(malformed_error.contains("non-signer slot"));
    }
}

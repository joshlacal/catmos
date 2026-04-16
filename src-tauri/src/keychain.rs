use async_trait::async_trait;
use catbird_mls::KeychainAccess;
use catbird_mls::MLSError;
use keyring::Entry;

const SERVICE_NAME: &str = "blue.catbird.catmos.mls";

/// OS keychain-backed implementation of `KeychainAccess` for MLS FFI.
pub struct KeyringKeychainAccess;

impl KeyringKeychainAccess {
    pub fn new() -> Self {
        #[cfg(target_os = "android")]
        tracing::warn!(
            "Android MLS keychain access is currently backed by keyring's mock store; implement Android secure storage before production use"
        );
        Self
    }

    fn entry(key: &str) -> std::result::Result<Entry, keyring::Error> {
        Entry::new(SERVICE_NAME, key)
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
        entry
            .set_password(&val_str)
            .map_err(|e| MLSError::Internal(e.to_string()))
    }

    async fn delete(&self, key: String) -> Result<(), MLSError> {
        match Self::entry(&key) {
            Ok(entry) => match entry.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
                Err(e) => Err(MLSError::Internal(e.to_string())),
            },
            Err(e) => Err(MLSError::Internal(e.to_string())),
        }
    }
}

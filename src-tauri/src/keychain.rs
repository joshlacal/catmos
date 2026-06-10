use async_trait::async_trait;
use catbird_mls::KeychainAccess;
use catbird_mls::MLSError;
use keyring::Entry;

const SERVICE_NAME: &str = "blue.catbird.catmos.mls";

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
}

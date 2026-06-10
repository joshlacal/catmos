use async_trait::async_trait;
use keyring::Entry;

use catbird_mls::orchestrator::credentials::CredentialStore;
use catbird_mls::orchestrator::error::{OrchestratorError, Result};

const SERVICE_NAME: &str = "blue.catbird.catmos";

/// OS keychain-backed credential store using the `keyring` crate.
pub struct KeyringCredentialStore;

impl KeyringCredentialStore {
    pub fn new() -> Self {
        match Self::try_new() {
            Ok(store) => store,
            Err(err) => panic!("{err}"),
        }
    }

    pub fn try_new() -> Result<Self> {
        #[cfg(target_os = "android")]
        {
            Err(OrchestratorError::Credential(
                "Android secure credential storage is not implemented; refusing to initialize MLS with keyring's mock store"
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

    fn key_signing(user_did: &str) -> String {
        format!("signing_key:{}", user_did)
    }

    fn key_mls_did(user_did: &str) -> String {
        format!("mls_did:{}", user_did)
    }

    fn key_device_uuid(user_did: &str) -> String {
        format!("device_uuid:{}", user_did)
    }
}

#[async_trait]
impl CredentialStore for KeyringCredentialStore {
    async fn store_signing_key(&self, user_did: &str, key_data: &[u8]) -> Result<()> {
        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode(key_data);
        Self::entry(&Self::key_signing(user_did))
            .map_err(|e| OrchestratorError::Credential(e.to_string()))?
            .set_password(&encoded)
            .map_err(|e| OrchestratorError::Credential(e.to_string()))
    }

    async fn get_signing_key(&self, user_did: &str) -> Result<Option<Vec<u8>>> {
        use base64::Engine;
        match Self::entry(&Self::key_signing(user_did)) {
            Ok(entry) => match entry.get_password() {
                Ok(encoded) => {
                    let bytes = base64::engine::general_purpose::STANDARD
                        .decode(&encoded)
                        .map_err(|e| OrchestratorError::Credential(e.to_string()))?;
                    Ok(Some(bytes))
                }
                Err(keyring::Error::NoEntry) => Ok(None),
                Err(e) => Err(OrchestratorError::Credential(e.to_string())),
            },
            Err(e) => Err(OrchestratorError::Credential(e.to_string())),
        }
    }

    async fn delete_signing_key(&self, user_did: &str) -> Result<()> {
        match Self::entry(&Self::key_signing(user_did)) {
            Ok(entry) => match entry.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
                Err(e) => Err(OrchestratorError::Credential(e.to_string())),
            },
            Err(e) => Err(OrchestratorError::Credential(e.to_string())),
        }
    }

    async fn store_mls_did(&self, user_did: &str, mls_did: &str) -> Result<()> {
        Self::entry(&Self::key_mls_did(user_did))
            .map_err(|e| OrchestratorError::Credential(e.to_string()))?
            .set_password(mls_did)
            .map_err(|e| OrchestratorError::Credential(e.to_string()))
    }

    async fn get_mls_did(&self, user_did: &str) -> Result<Option<String>> {
        match Self::entry(&Self::key_mls_did(user_did)) {
            Ok(entry) => match entry.get_password() {
                Ok(val) => Ok(Some(val)),
                Err(keyring::Error::NoEntry) => Ok(None),
                Err(e) => Err(OrchestratorError::Credential(e.to_string())),
            },
            Err(e) => Err(OrchestratorError::Credential(e.to_string())),
        }
    }

    async fn store_device_uuid(&self, user_did: &str, uuid: &str) -> Result<()> {
        Self::entry(&Self::key_device_uuid(user_did))
            .map_err(|e| OrchestratorError::Credential(e.to_string()))?
            .set_password(uuid)
            .map_err(|e| OrchestratorError::Credential(e.to_string()))
    }

    async fn get_device_uuid(&self, user_did: &str) -> Result<Option<String>> {
        match Self::entry(&Self::key_device_uuid(user_did)) {
            Ok(entry) => match entry.get_password() {
                Ok(val) => Ok(Some(val)),
                Err(keyring::Error::NoEntry) => Ok(None),
                Err(e) => Err(OrchestratorError::Credential(e.to_string())),
            },
            Err(e) => Err(OrchestratorError::Credential(e.to_string())),
        }
    }

    async fn has_credentials(&self, user_did: &str) -> Result<bool> {
        let has_key = self.get_signing_key(user_did).await?.is_some();
        let has_uuid = self.get_device_uuid(user_did).await?.is_some();
        Ok(has_key && has_uuid)
    }

    async fn clear_all(&self, user_did: &str) -> Result<()> {
        self.delete_signing_key(user_did).await?;
        // Delete MLS DID
        if let Ok(entry) = Self::entry(&Self::key_mls_did(user_did)) {
            let _ = entry.delete_credential();
        }
        // Delete device UUID
        if let Ok(entry) = Self::entry(&Self::key_device_uuid(user_did)) {
            let _ = entry.delete_credential();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "android")]
    #[test]
    fn android_credential_store_constructor_fails_closed() {
        let err = match KeyringCredentialStore::try_new() {
            Ok(_) => panic!("Android must not use keyring's mock credential store"),
            Err(err) => err,
        };
        assert!(
            err.to_string()
                .contains("Android secure credential storage is not implemented"),
            "unexpected error: {err}"
        );
    }

    #[cfg(not(target_os = "android"))]
    #[test]
    fn non_android_credential_store_constructor_succeeds() {
        let _ =
            KeyringCredentialStore::try_new().expect("desktop credential constructor should work");
    }
}

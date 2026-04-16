//! SqliteCredentialStore — implements CredentialStore using encrypted SQLite.
//!
//! Replaces the previous IndexedDB implementation (`catmos-credentials` database).
//! Credentials are now stored in the same encrypted SQLite database as all other
//! app data, via the shared `SqliteConn` from `sqlite_conn.rs`.
//!
//! # Migration Note
//!
//! No migration from the old IndexedDB database is performed. Users with
//! existing credentials will need to re-login. This is acceptable at the
//! current development stage.
//!
//! # Schema
//!
//! ```sql
//! CREATE TABLE IF NOT EXISTS credentials (
//!     user_did        TEXT NOT NULL,
//!     credential_type TEXT NOT NULL,
//!     value           BLOB NOT NULL,
//!     PRIMARY KEY (user_did, credential_type)
//! );
//! ```
//!
//! # Security
//!
//! All credential data (signing keys, MLS DID, device UUID) is stored in
//! an encrypted SQLite database using sqlite3mc ChaCha20. This is a significant
//! improvement over the previous plaintext IndexedDB storage.

use async_trait::async_trait;
use catbird_mls::orchestrator::credentials::CredentialStore;
use catbird_mls::orchestrator::error::{OrchestratorError, Result};
use std::rc::Rc;

use crate::sqlite_conn::SqliteConn;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

// Credential type keys stored in the `credential_type` column.
const TYPE_SIGNING_KEY: &str = "signing_key";
const TYPE_MLS_DID: &str = "mls_did";
const TYPE_DEVICE_UUID: &str = "device_uuid";

// ---------------------------------------------------------------------------
// SqliteCredentialStore
// ---------------------------------------------------------------------------

/// An implementation of [`CredentialStore`] that persists credentials in the
/// shared encrypted SQLite database, suitable for WASM environments.
pub struct SqliteCredentialStore {
    conn: Rc<SqliteConn>,
}

impl SqliteCredentialStore {
    /// Create a new credential store wrapping the shared SQLite connection.
    ///
    /// The caller must have already called `ensure_schema()` on this connection.
    pub fn new(conn: Rc<SqliteConn>) -> Self {
        Self { conn }
    }

    /// Create the credentials table on the shared connection.
    pub fn ensure_schema(conn: &SqliteConn) -> std::result::Result<(), String> {
        conn.exec_raw(
            "CREATE TABLE IF NOT EXISTS credentials (
                user_did        TEXT NOT NULL,
                credential_type TEXT NOT NULL,
                value           BLOB NOT NULL,
                PRIMARY KEY (user_did, credential_type)
            );",
        )
        .map_err(|e| format!("credentials table: {}", e))
    }

    fn cred_err(e: impl std::fmt::Debug) -> OrchestratorError {
        OrchestratorError::Credential(format!("{:?}", e))
    }

    /// Store a credential value as a BLOB.
    fn put_blob(&self, user_did: &str, credential_type: &str, value: &[u8]) -> Result<()> {
        self.conn
            .exec_with_text_and_blob_params(
                "INSERT OR REPLACE INTO credentials (user_did, credential_type, value)
                 VALUES (?1, ?2, ?3)",
                &[(1, user_did), (2, credential_type)],
                &[(3, value)],
            )
            .map_err(Self::cred_err)
    }

    /// Retrieve a credential value as bytes.
    fn get_blob(&self, user_did: &str, credential_type: &str) -> Result<Option<Vec<u8>>> {
        self.conn
            .query_blob(
                "SELECT value FROM credentials WHERE user_did = ?1 AND credential_type = ?2",
                &[(1, user_did), (2, credential_type)],
            )
            .map_err(Self::cred_err)
    }

    /// Delete a credential.
    fn delete_credential(&self, user_did: &str, credential_type: &str) -> Result<()> {
        self.conn
            .exec_with_text_params(
                "DELETE FROM credentials WHERE user_did = ?1 AND credential_type = ?2",
                &[(1, user_did), (2, credential_type)],
            )
            .map_err(Self::cred_err)
    }
}

// ---------------------------------------------------------------------------
// CredentialStore trait implementation
// ---------------------------------------------------------------------------

#[async_trait(?Send)]
impl CredentialStore for SqliteCredentialStore {
    // -- Signing key ---------------------------------------------------------

    async fn store_signing_key(&self, user_did: &str, key_data: &[u8]) -> Result<()> {
        self.put_blob(user_did, TYPE_SIGNING_KEY, key_data)
    }

    async fn get_signing_key(&self, user_did: &str) -> Result<Option<Vec<u8>>> {
        self.get_blob(user_did, TYPE_SIGNING_KEY)
    }

    async fn delete_signing_key(&self, user_did: &str) -> Result<()> {
        self.delete_credential(user_did, TYPE_SIGNING_KEY)
    }

    // -- MLS DID -------------------------------------------------------------

    async fn store_mls_did(&self, user_did: &str, mls_did: &str) -> Result<()> {
        self.put_blob(user_did, TYPE_MLS_DID, mls_did.as_bytes())
    }

    async fn get_mls_did(&self, user_did: &str) -> Result<Option<String>> {
        let blob = self.get_blob(user_did, TYPE_MLS_DID)?;
        match blob {
            None => Ok(None),
            Some(bytes) => {
                let s = String::from_utf8(bytes)
                    .map_err(|e| OrchestratorError::Credential(format!("UTF-8 decode: {}", e)))?;
                Ok(Some(s))
            }
        }
    }

    // -- Device UUID ---------------------------------------------------------

    async fn store_device_uuid(&self, user_did: &str, uuid: &str) -> Result<()> {
        self.put_blob(user_did, TYPE_DEVICE_UUID, uuid.as_bytes())
    }

    async fn get_device_uuid(&self, user_did: &str) -> Result<Option<String>> {
        let blob = self.get_blob(user_did, TYPE_DEVICE_UUID)?;
        match blob {
            None => Ok(None),
            Some(bytes) => {
                let s = String::from_utf8(bytes)
                    .map_err(|e| OrchestratorError::Credential(format!("UTF-8 decode: {}", e)))?;
                Ok(Some(s))
            }
        }
    }

    // -- Aggregate queries ---------------------------------------------------

    async fn has_credentials(&self, user_did: &str) -> Result<bool> {
        let signing_key = self.get_blob(user_did, TYPE_SIGNING_KEY)?;
        if signing_key.is_none() {
            return Ok(false);
        }
        let mls_did = self.get_blob(user_did, TYPE_MLS_DID)?;
        if mls_did.is_none() {
            return Ok(false);
        }
        let device_uuid = self.get_blob(user_did, TYPE_DEVICE_UUID)?;
        Ok(device_uuid.is_some())
    }

    async fn clear_all(&self, user_did: &str) -> Result<()> {
        self.conn
            .exec_with_text_params(
                "DELETE FROM credentials WHERE user_did = ?1",
                &[(1, user_did)],
            )
            .map_err(Self::cred_err)
    }
}

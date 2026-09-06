use async_trait::async_trait;
use rusqlite::{Connection, OptionalExtension};
use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};

use catbird_mls::orchestrator::error::{OrchestratorError, Result};
use catbird_mls::orchestrator::storage::MLSStorageBackend;
use catbird_mls::orchestrator::types::*;
use catbird_mls::MLSContext;

pub const MLS_STORAGE_GENERATION: &str = "mls-state-clean-v2-openmls-v09";
pub const MLS_KEY_SUFFIX: &str = "clean-v2-openmls-v09";
pub const DB_KEYRING_SERVICE: &str = "blue.catbird.catmos.clean-v2-openmls-v09";

pub fn app_db_file_name(account_id: &str) -> String {
    format!("catmos-{}-{}.db", account_id, MLS_KEY_SUFFIX)
}

pub fn mls_db_file_name(account_id: &str) -> String {
    format!("mls-{}-{}.db", account_id, MLS_KEY_SUFFIX)
}

pub fn app_db_key_label(account_id: &str) -> String {
    format!("conversation-db:{}:{}", account_id, MLS_KEY_SUFFIX)
}

pub fn mls_db_key_label(account_id: &str) -> String {
    format!("mls-db:{}:{}", account_id, MLS_KEY_SUFFIX)
}

pub fn account_marker_path(data_dir: &Path, account_id: &str) -> PathBuf {
    data_dir.join(format!("catmos-{}-{}.marker", account_id, MLS_KEY_SUFFIX))
}

pub struct AccountLock {
    _file: std::fs::File,
}

pub(crate) fn acquire_account_lock(
    data_dir: &Path,
    account_id: &str,
) -> std::result::Result<AccountLock, DatabaseInitError> {
    let lock_path = data_dir.join(format!("{}-{}.lock", account_id, MLS_KEY_SUFFIX));
    if let Some(parent) = lock_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)?;
    use fs2::FileExt;
    file.lock_exclusive()?;
    Ok(AccountLock { _file: file })
}

#[derive(Debug)]
pub enum DatabaseInitError {
    MixedStateAbsentDbPresentKey,
    MixedStatePresentDbAbsentKey,
    MixedStateMissingMarker,
    InitializationIncomplete,
    InvalidMarker(String),
    KeyringError(String),
    InvalidKeyFormat,
    ValidationFailed(String),
    Io(std::io::Error),
    Sqlite(rusqlite::Error),
}

impl fmt::Display for DatabaseInitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MixedStateAbsentDbPresentKey => {
                write!(
                    f,
                    "mixed storage state: database file is absent but key exists in secure store"
                )
            }
            Self::MixedStatePresentDbAbsentKey => {
                write!(
                    f,
                    "mixed storage state: database file is present but key is absent from secure store"
                )
            }
            Self::MixedStateMissingMarker => {
                write!(
                    f,
                    "mixed storage state: database or key exists without complete initialization marker"
                )
            }
            Self::InitializationIncomplete => {
                write!(
                    f,
                    "storage initialization was interrupted in creating state; explicit reset required"
                )
            }
            Self::InvalidMarker(msg) => {
                write!(
                    f,
                    "storage initialization record is corrupt or invalid: {msg}"
                )
            }
            Self::KeyringError(msg) => {
                write!(f, "secure store access failed: {msg}")
            }
            Self::InvalidKeyFormat => {
                write!(
                    f,
                    "invalid key format in secure store: expected 64 hex characters (32 bytes)"
                )
            }
            Self::ValidationFailed(msg) => {
                write!(f, "database validation failed: {msg}")
            }
            Self::Io(err) => write!(f, "database I/O error: {err}"),
            Self::Sqlite(err) => write!(f, "database SQLite error: {err}"),
        }
    }
}

impl std::error::Error for DatabaseInitError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::Sqlite(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for DatabaseInitError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<rusqlite::Error> for DatabaseInitError {
    fn from(err: rusqlite::Error) -> Self {
        Self::Sqlite(err)
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum MarkerStatus {
    Creating,
    Complete,
}

pub fn read_account_marker(
    marker_path: &Path,
    expected_normalized_did: &str,
    expected_account_id: &str,
    expected_app_db_name: &str,
    expected_mls_db_name: &str,
) -> std::result::Result<Option<MarkerStatus>, DatabaseInitError> {
    if !marker_path.exists() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(marker_path)?;
    let lines: Vec<&str> = content.lines().collect();
    if lines.is_empty() {
        return Err(DatabaseInitError::InvalidMarker("empty marker file".into()));
    }
    let status_str = lines[0].trim();
    let status = match status_str {
        "creating" => MarkerStatus::Creating,
        "complete" => MarkerStatus::Complete,
        other => {
            return Err(DatabaseInitError::InvalidMarker(format!(
                "unknown marker content: {other}"
            )));
        }
    };
    if lines.len() != 6 {
        return Err(DatabaseInitError::InvalidMarker(format!(
            "invalid marker line count: expected exactly 6 lines, got {}",
            lines.len()
        )));
    }
    let normalized_did = lines[1].trim();
    let account_id = lines[2].trim();
    let generation = lines[3].trim();
    let app_db_name = lines[4].trim();
    let mls_db_name = lines[5].trim();

    if normalized_did != expected_normalized_did {
        return Err(DatabaseInitError::InvalidMarker(format!(
            "marker normalized DID mismatch: expected {expected_normalized_did}, got {normalized_did}"
        )));
    }
    if account_id != expected_account_id {
        return Err(DatabaseInitError::InvalidMarker(format!(
            "marker account ID mismatch: expected {expected_account_id}, got {account_id}"
        )));
    }
    if generation != MLS_STORAGE_GENERATION {
        return Err(DatabaseInitError::InvalidMarker(format!(
            "marker generation mismatch: expected {MLS_STORAGE_GENERATION}, got {generation}"
        )));
    }
    if app_db_name != expected_app_db_name {
        return Err(DatabaseInitError::InvalidMarker(format!(
            "marker app db name mismatch: expected {expected_app_db_name}, got {app_db_name}"
        )));
    }
    if mls_db_name != expected_mls_db_name {
        return Err(DatabaseInitError::InvalidMarker(format!(
            "marker mls db name mismatch: expected {expected_mls_db_name}, got {mls_db_name}"
        )));
    }
    Ok(Some(status))
}

pub fn write_account_marker_creating(
    marker_path: &Path,
    normalized_did: &str,
    account_id: &str,
    app_db_name: &str,
    mls_db_name: &str,
) -> std::result::Result<(), DatabaseInitError> {
    if let Some(parent) = marker_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(marker_path)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                DatabaseInitError::InvalidMarker("marker already exists during create".into())
            } else {
                DatabaseInitError::Io(e)
            }
        })?;
    let content = format!(
        "creating\n{}\n{}\n{}\n{}\n{}\n",
        normalized_did, account_id, MLS_STORAGE_GENERATION, app_db_name, mls_db_name
    );
    file.write_all(content.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

pub fn write_account_marker_complete(
    marker_path: &Path,
    normalized_did: &str,
    account_id: &str,
    app_db_name: &str,
    mls_db_name: &str,
) -> std::result::Result<(), DatabaseInitError> {
    if let Some(parent) = marker_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let content = format!(
        "complete\n{}\n{}\n{}\n{}\n{}\n",
        normalized_did, account_id, MLS_STORAGE_GENERATION, app_db_name, mls_db_name
    );
    let tmp_path = format!("{}.tmp.{}", marker_path.display(), uuid::Uuid::new_v4());
    let write_res = (|| -> std::result::Result<(), std::io::Error> {
        use std::io::Write;
        let mut file = std::fs::File::create(&tmp_path)?;
        file.write_all(content.as_bytes())?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&tmp_path, marker_path)?;
        Ok(())
    })();
    if let Err(e) = write_res {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(DatabaseInitError::Io(e));
    }
    Ok(())
}

pub trait DbKeyStore: Send + Sync {
    fn get_password(
        &self,
        service: &str,
        label: &str,
    ) -> std::result::Result<Option<String>, DatabaseInitError>;
    fn set_password(
        &self,
        service: &str,
        label: &str,
        password: &str,
    ) -> std::result::Result<(), DatabaseInitError>;
    fn delete_password(
        &self,
        service: &str,
        label: &str,
    ) -> std::result::Result<(), DatabaseInitError>;
}

pub struct KeyringDbKeyStore;

impl DbKeyStore for KeyringDbKeyStore {
    fn get_password(
        &self,
        service: &str,
        label: &str,
    ) -> std::result::Result<Option<String>, DatabaseInitError> {
        let entry = keyring::Entry::new(service, label)
            .map_err(|e| DatabaseInitError::KeyringError(e.to_string()))?;
        match entry.get_password() {
            Ok(val) => Ok(Some(val)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(DatabaseInitError::KeyringError(e.to_string())),
        }
    }

    fn set_password(
        &self,
        service: &str,
        label: &str,
        password: &str,
    ) -> std::result::Result<(), DatabaseInitError> {
        let entry = keyring::Entry::new(service, label)
            .map_err(|e| DatabaseInitError::KeyringError(e.to_string()))?;
        entry
            .set_password(password)
            .map_err(|e| DatabaseInitError::KeyringError(e.to_string()))
    }

    fn delete_password(
        &self,
        service: &str,
        label: &str,
    ) -> std::result::Result<(), DatabaseInitError> {
        let entry = keyring::Entry::new(service, label)
            .map_err(|e| DatabaseInitError::KeyringError(e.to_string()))?;
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(DatabaseInitError::KeyringError(e.to_string())),
        }
    }
}

#[derive(Default)]
pub struct MemoryDbKeyStore {
    entries: Mutex<HashMap<(String, String), String>>,
}

impl MemoryDbKeyStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl DbKeyStore for MemoryDbKeyStore {
    fn get_password(
        &self,
        service: &str,
        label: &str,
    ) -> std::result::Result<Option<String>, DatabaseInitError> {
        let guard = self.entries.lock().unwrap();
        Ok(guard
            .get(&(service.to_string(), label.to_string()))
            .cloned())
    }

    fn set_password(
        &self,
        service: &str,
        label: &str,
        password: &str,
    ) -> std::result::Result<(), DatabaseInitError> {
        let mut guard = self.entries.lock().unwrap();
        guard.insert(
            (service.to_string(), label.to_string()),
            password.to_string(),
        );
        Ok(())
    }

    fn delete_password(
        &self,
        service: &str,
        label: &str,
    ) -> std::result::Result<(), DatabaseInitError> {
        let mut guard = self.entries.lock().unwrap();
        guard.remove(&(service.to_string(), label.to_string()));
        Ok(())
    }
}

/// Accept only a 64-character lowercase-or-uppercase hex SQLCipher key.
fn checked_db_key(raw: &str) -> std::result::Result<String, DatabaseInitError> {
    let trimmed = raw.trim();
    if trimmed.len() == 64 && hex::decode(trimmed).is_ok() {
        Ok(trimmed.to_string())
    } else {
        Err(DatabaseInitError::InvalidKeyFormat)
    }
}

/// Map a SQLite declared column type onto the storage class the schema
/// descriptors are written in, following SQLite's own affinity substring rules.
fn column_storage_class(declared: &str) -> Option<&'static str> {
    let upper = declared.to_uppercase();
    if upper.contains("INT") {
        Some("INTEGER")
    } else if upper.contains("TEXT") || upper.contains("CHAR") {
        Some("TEXT")
    } else if upper.contains("BLOB") {
        Some("BLOB")
    } else {
        None
    }
}

pub fn load_db_key_from_store(
    store: &dyn DbKeyStore,
    service: &str,
    label: &str,
) -> std::result::Result<Option<String>, DatabaseInitError> {
    store
        .get_password(service, label)?
        .map(|pwd| checked_db_key(&pwd))
        .transpose()
}

pub fn create_db_key_in_store(
    store: &dyn DbKeyStore,
    service: &str,
    label: &str,
) -> std::result::Result<String, DatabaseInitError> {
    if let Some(existing) = store.get_password(service, label)? {
        return checked_db_key(&existing);
    }

    let mut key_bytes = [0u8; 32];
    getrandom::getrandom(&mut key_bytes)
        .map_err(|e| DatabaseInitError::ValidationFailed(format!("RNG failure: {e}")))?;
    let hex_key = hex::encode(key_bytes);
    store.set_password(service, label, &hex_key)?;

    // Re-read so a concurrent writer's value, not ours, becomes the key in use.
    let winner = store
        .get_password(service, label)?
        .ok_or_else(|| DatabaseInitError::KeyringError("key missing after set".into()))?;
    checked_db_key(&winner)
}

pub fn derive_cipher_salt_hex(encryption_key: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(encryption_key.as_bytes());
    let digest = hasher.finalize();
    hex::encode(&digest[..16])
}

/// Open the MLS SQLCipher database read-only with the exact cipher parameters
/// `MLSContext` writes with. Every read-only inspection of the MLS DB must go
/// through here so the parameters can never drift between call sites.
fn open_mls_db_readonly(
    path: &Path,
    encryption_key: &str,
) -> std::result::Result<Connection, DatabaseInitError> {
    let conn = Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    conn.pragma_update(None, "cipher_memory_security", "OFF")?;
    conn.pragma_update(None, "key", encryption_key)?;
    conn.pragma_update(None, "cipher_plaintext_header_size", 32)?;
    let salt_hex = derive_cipher_salt_hex(encryption_key);
    conn.pragma_update(None, "cipher_salt", format!("x'{}'", salt_hex))?;
    conn.pragma_update(None, "cipher_page_size", 4096)?;
    conn.pragma_update(None, "kdf_iter", 256000)?;
    conn.pragma_update(None, "cipher_hmac_algorithm", "HMAC_SHA512")?;
    conn.pragma_update(None, "cipher_kdf_algorithm", "PBKDF2_HMAC_SHA512")?;
    conn.pragma_update(None, "query_only", "ON")?;
    Ok(conn)
}

pub fn validate_mls_db_readonly(
    path: &Path,
    encryption_key: &str,
) -> std::result::Result<(), DatabaseInitError> {
    let conn = open_mls_db_readonly(path, encryption_key)?;

    // 1. Validate openmls_sqlite_storage_migrations has EXACTLY versions 1..=6
    let mut stmt = conn
        .prepare("SELECT version FROM openmls_sqlite_storage_migrations ORDER BY version ASC")
        .map_err(|e| {
            DatabaseInitError::ValidationFailed(format!(
                "openmls_sqlite_storage_migrations missing or invalid: {e}"
            ))
        })?;
    let versions: Vec<i32> = stmt
        .query_map([], |row| row.get(0))
        .map_err(|e| {
            DatabaseInitError::ValidationFailed(format!("Failed to query migration versions: {e}"))
        })?
        .filter_map(|r| r.ok())
        .collect();
    if versions != vec![1, 2, 3, 4, 5, 6] {
        return Err(DatabaseInitError::ValidationFailed(format!(
            "Refinery schema versions mismatch: expected [1, 2, 3, 4, 5, 6], found {versions:?}"
        )));
    }

    // 2. Validate all expected OpenMLS and Catbird tables and exact column descriptors exist
    #[derive(Debug, PartialEq, Eq)]
    struct ColumnDescriptor {
        name: &'static str,
        col_type: &'static str,
        notnull: bool,
        pk: i32,
    }

    struct TableDescriptor {
        name: &'static str,
        columns: &'static [ColumnDescriptor],
    }

    const REQUIRED_TABLE_DESCRIPTORS: &[TableDescriptor] = &[
        TableDescriptor {
            name: "openmls_sqlite_storage_migrations",
            columns: &[
                ColumnDescriptor {
                    name: "version",
                    col_type: "INTEGER",
                    notnull: false,
                    pk: 1,
                },
                ColumnDescriptor {
                    name: "name",
                    col_type: "TEXT",
                    notnull: false,
                    pk: 0,
                },
                ColumnDescriptor {
                    name: "applied_on",
                    col_type: "TEXT",
                    notnull: false,
                    pk: 0,
                },
                ColumnDescriptor {
                    name: "checksum",
                    col_type: "TEXT",
                    notnull: false,
                    pk: 0,
                },
            ],
        },
        TableDescriptor {
            name: "openmls_encryption_keys",
            columns: &[
                ColumnDescriptor {
                    name: "provider_version",
                    col_type: "INTEGER",
                    notnull: true,
                    pk: 0,
                },
                ColumnDescriptor {
                    name: "public_key",
                    col_type: "BLOB",
                    notnull: false,
                    pk: 1,
                },
                ColumnDescriptor {
                    name: "key_pair",
                    col_type: "BLOB",
                    notnull: true,
                    pk: 0,
                },
            ],
        },
        TableDescriptor {
            name: "openmls_epoch_keys_pairs",
            columns: &[
                ColumnDescriptor {
                    name: "provider_version",
                    col_type: "INTEGER",
                    notnull: true,
                    pk: 0,
                },
                ColumnDescriptor {
                    name: "group_id",
                    col_type: "BLOB",
                    notnull: true,
                    pk: 1,
                },
                ColumnDescriptor {
                    name: "epoch_id",
                    col_type: "BLOB",
                    notnull: true,
                    pk: 2,
                },
                ColumnDescriptor {
                    name: "leaf_index",
                    col_type: "INTEGER",
                    notnull: true,
                    pk: 3,
                },
                ColumnDescriptor {
                    name: "key_pairs",
                    col_type: "BLOB",
                    notnull: true,
                    pk: 0,
                },
            ],
        },
        TableDescriptor {
            name: "openmls_group_data",
            columns: &[
                ColumnDescriptor {
                    name: "provider_version",
                    col_type: "INTEGER",
                    notnull: true,
                    pk: 0,
                },
                ColumnDescriptor {
                    name: "group_id",
                    col_type: "BLOB",
                    notnull: true,
                    pk: 1,
                },
                ColumnDescriptor {
                    name: "data_type",
                    col_type: "TEXT",
                    notnull: true,
                    pk: 2,
                },
                ColumnDescriptor {
                    name: "group_data",
                    col_type: "BLOB",
                    notnull: true,
                    pk: 0,
                },
            ],
        },
        TableDescriptor {
            name: "openmls_key_packages",
            columns: &[
                ColumnDescriptor {
                    name: "provider_version",
                    col_type: "INTEGER",
                    notnull: true,
                    pk: 0,
                },
                ColumnDescriptor {
                    name: "key_package_ref",
                    col_type: "BLOB",
                    notnull: false,
                    pk: 1,
                },
                ColumnDescriptor {
                    name: "key_package",
                    col_type: "BLOB",
                    notnull: true,
                    pk: 0,
                },
            ],
        },
        TableDescriptor {
            name: "openmls_own_leaf_nodes",
            columns: &[
                ColumnDescriptor {
                    name: "provider_version",
                    col_type: "INTEGER",
                    notnull: true,
                    pk: 0,
                },
                ColumnDescriptor {
                    name: "id",
                    col_type: "INTEGER",
                    notnull: false,
                    pk: 1,
                },
                ColumnDescriptor {
                    name: "group_id",
                    col_type: "BLOB",
                    notnull: true,
                    pk: 0,
                },
                ColumnDescriptor {
                    name: "leaf_node",
                    col_type: "BLOB",
                    notnull: true,
                    pk: 0,
                },
            ],
        },
        TableDescriptor {
            name: "openmls_proposals",
            columns: &[
                ColumnDescriptor {
                    name: "provider_version",
                    col_type: "INTEGER",
                    notnull: true,
                    pk: 0,
                },
                ColumnDescriptor {
                    name: "group_id",
                    col_type: "BLOB",
                    notnull: true,
                    pk: 1,
                },
                ColumnDescriptor {
                    name: "proposal_ref",
                    col_type: "BLOB",
                    notnull: true,
                    pk: 2,
                },
                ColumnDescriptor {
                    name: "proposal",
                    col_type: "BLOB",
                    notnull: true,
                    pk: 0,
                },
            ],
        },
        TableDescriptor {
            name: "openmls_psks",
            columns: &[
                ColumnDescriptor {
                    name: "provider_version",
                    col_type: "INTEGER",
                    notnull: true,
                    pk: 0,
                },
                ColumnDescriptor {
                    name: "psk_id",
                    col_type: "BLOB",
                    notnull: false,
                    pk: 1,
                },
                ColumnDescriptor {
                    name: "psk_bundle",
                    col_type: "BLOB",
                    notnull: true,
                    pk: 0,
                },
            ],
        },
        TableDescriptor {
            name: "openmls_signature_keys",
            columns: &[
                ColumnDescriptor {
                    name: "provider_version",
                    col_type: "INTEGER",
                    notnull: true,
                    pk: 0,
                },
                ColumnDescriptor {
                    name: "public_key",
                    col_type: "BLOB",
                    notnull: false,
                    pk: 1,
                },
                ColumnDescriptor {
                    name: "signature_key",
                    col_type: "BLOB",
                    notnull: true,
                    pk: 0,
                },
            ],
        },
        TableDescriptor {
            name: "vc_emulation_group_secrets",
            columns: &[
                ColumnDescriptor {
                    name: "provider_version",
                    col_type: "INTEGER",
                    notnull: true,
                    pk: 0,
                },
                ColumnDescriptor {
                    name: "epoch_id",
                    col_type: "BLOB",
                    notnull: true,
                    pk: 1,
                },
                ColumnDescriptor {
                    name: "secret_type",
                    col_type: "TEXT",
                    notnull: true,
                    pk: 2,
                },
                ColumnDescriptor {
                    name: "vc_secret",
                    col_type: "BLOB",
                    notnull: true,
                    pk: 0,
                },
            ],
        },
        TableDescriptor {
            name: "vc_emulation_bindings",
            columns: &[
                ColumnDescriptor {
                    name: "provider_version",
                    col_type: "INTEGER",
                    notnull: true,
                    pk: 0,
                },
                ColumnDescriptor {
                    name: "group_id",
                    col_type: "BLOB",
                    notnull: true,
                    pk: 1,
                },
                ColumnDescriptor {
                    name: "bindings",
                    col_type: "BLOB",
                    notnull: true,
                    pk: 0,
                },
            ],
        },
        TableDescriptor {
            name: "vc_operation_trees",
            columns: &[
                ColumnDescriptor {
                    name: "provider_version",
                    col_type: "INTEGER",
                    notnull: true,
                    pk: 0,
                },
                ColumnDescriptor {
                    name: "epoch_id",
                    col_type: "BLOB",
                    notnull: true,
                    pk: 1,
                },
                ColumnDescriptor {
                    name: "operation_tree",
                    col_type: "BLOB",
                    notnull: true,
                    pk: 0,
                },
            ],
        },
        TableDescriptor {
            name: "vc_retained_key_package_material",
            columns: &[
                ColumnDescriptor {
                    name: "provider_version",
                    col_type: "INTEGER",
                    notnull: true,
                    pk: 0,
                },
                ColumnDescriptor {
                    name: "key_package_ref",
                    col_type: "BLOB",
                    notnull: true,
                    pk: 1,
                },
                ColumnDescriptor {
                    name: "epoch_id",
                    col_type: "BLOB",
                    notnull: true,
                    pk: 0,
                },
                ColumnDescriptor {
                    name: "record",
                    col_type: "BLOB",
                    notnull: true,
                    pk: 0,
                },
            ],
        },
        TableDescriptor {
            name: "registered_vc_emulation_epochs",
            columns: &[
                ColumnDescriptor {
                    name: "provider_version",
                    col_type: "INTEGER",
                    notnull: true,
                    pk: 0,
                },
                ColumnDescriptor {
                    name: "group_id",
                    col_type: "BLOB",
                    notnull: true,
                    pk: 1,
                },
                ColumnDescriptor {
                    name: "registration",
                    col_type: "BLOB",
                    notnull: true,
                    pk: 0,
                },
            ],
        },
        TableDescriptor {
            name: "mls_manifests",
            columns: &[
                ColumnDescriptor {
                    name: "key",
                    col_type: "TEXT",
                    notnull: false,
                    pk: 1,
                },
                ColumnDescriptor {
                    name: "value",
                    col_type: "TEXT",
                    notnull: true,
                    pk: 0,
                },
            ],
        },
        TableDescriptor {
            name: "mls_key_package_bundles",
            columns: &[
                ColumnDescriptor {
                    name: "hash_ref",
                    col_type: "TEXT",
                    notnull: false,
                    pk: 1,
                },
                ColumnDescriptor {
                    name: "bundle_b64",
                    col_type: "TEXT",
                    notnull: true,
                    pk: 0,
                },
                ColumnDescriptor {
                    name: "created_at",
                    col_type: "INTEGER",
                    notnull: true,
                    pk: 0,
                },
            ],
        },
        TableDescriptor {
            name: "mls_own_echo_proofs",
            columns: &[
                ColumnDescriptor {
                    name: "canonical_entry_sha256",
                    col_type: "BLOB",
                    notnull: false,
                    pk: 1,
                },
                ColumnDescriptor {
                    name: "accepted_request_sha256",
                    col_type: "BLOB",
                    notnull: true,
                    pk: 0,
                },
                ColumnDescriptor {
                    name: "conversation_id",
                    col_type: "TEXT",
                    notnull: true,
                    pk: 0,
                },
                ColumnDescriptor {
                    name: "group_id",
                    col_type: "BLOB",
                    notnull: true,
                    pk: 0,
                },
                ColumnDescriptor {
                    name: "server_entry_id",
                    col_type: "TEXT",
                    notnull: true,
                    pk: 0,
                },
                ColumnDescriptor {
                    name: "mls_epoch",
                    col_type: "INTEGER",
                    notnull: true,
                    pk: 0,
                },
                ColumnDescriptor {
                    name: "aad_sha256",
                    col_type: "BLOB",
                    notnull: true,
                    pk: 0,
                },
                ColumnDescriptor {
                    name: "ciphertext_sha256",
                    col_type: "BLOB",
                    notnull: true,
                    pk: 0,
                },
            ],
        },
    ];

    let mut stmt = conn
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
        .map_err(|e| {
            DatabaseInitError::ValidationFailed(format!("MLS DB prepare sqlite_master failed: {e}"))
        })?;
    let existing_tables: std::collections::HashSet<String> = stmt
        .query_map([], |row| row.get(0))
        .map_err(|e| {
            DatabaseInitError::ValidationFailed(format!(
                "MLS DB query_map sqlite_master failed: {e}"
            ))
        })?
        .filter_map(|r| r.ok())
        .collect();

    for desc in REQUIRED_TABLE_DESCRIPTORS {
        if !existing_tables.contains(desc.name) {
            return Err(DatabaseInitError::ValidationFailed(format!(
                "MLS DB missing required clean-v09 table: {}",
                desc.name
            )));
        }
        let mut stmt = conn
            .prepare(&format!("PRAGMA table_info({})", desc.name))
            .map_err(|e| {
                DatabaseInitError::ValidationFailed(format!(
                    "Failed to query table_info for {}: {e}",
                    desc.name
                ))
            })?;
        let actual_cols: Vec<ColumnDescriptor> = stmt
            .query_map([], |row| {
                let name: String = row.get(1)?;
                let col_type: String = row.get(2)?;
                let notnull: bool = row.get::<_, i32>(3)? != 0;
                let pk: i32 = row.get(5)?;
                Ok((name, col_type, notnull, pk))
            })
            .map_err(|e| {
                DatabaseInitError::ValidationFailed(format!(
                    "Failed to map column info for {}: {e}",
                    desc.name
                ))
            })?
            .filter_map(|r| r.ok())
            .map(|(name, col_type, notnull, pk)| {
                let static_name = desc
                    .columns
                    .iter()
                    .find(|c| c.name == name)
                    .map(|c| c.name)
                    .unwrap_or("");
                let static_type = column_storage_class(&col_type).unwrap_or("");
                ColumnDescriptor {
                    name: static_name,
                    col_type: static_type,
                    notnull,
                    pk,
                }
            })
            .collect();
        if actual_cols != desc.columns {
            return Err(DatabaseInitError::ValidationFailed(format!(
                "MLS DB table `{}` schema mismatch (expected {:?}, found {:?})",
                desc.name, desc.columns, actual_cols
            )));
        }
    }

    // 3. Validate index vc_retained_key_package_material_epoch_id
    let mut stmt = conn
        .prepare("SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'vc_retained_key_package_material'")
        .map_err(|e| DatabaseInitError::ValidationFailed(format!("Failed to query index list: {e}")))?;
    let indices: std::collections::HashSet<String> = stmt
        .query_map([], |row| row.get(0))
        .map_err(|e| {
            DatabaseInitError::ValidationFailed(format!("Failed to read index names: {e}"))
        })?
        .filter_map(|r| r.ok())
        .collect();
    if !indices.contains("vc_retained_key_package_material_epoch_id") {
        return Err(DatabaseInitError::ValidationFailed(
            "MLS DB missing required index vc_retained_key_package_material_epoch_id".into(),
        ));
    }

    let quick_check: String = conn
        .pragma_query_value(None, "quick_check", |row| row.get(0))
        .map_err(|e| {
            DatabaseInitError::ValidationFailed(format!("MLS DB quick_check query failed: {e}"))
        })?;
    if quick_check != "ok" {
        return Err(DatabaseInitError::ValidationFailed(format!(
            "MLS DB quick_check returned: {quick_check}"
        )));
    }
    Ok(())
}

pub fn validate_app_db_readonly(
    path: &Path,
    encryption_key: &str,
) -> std::result::Result<(), DatabaseInitError> {
    let conn = Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    conn.execute_batch(&format!("PRAGMA key = '{}';", encryption_key))?;
    conn.pragma_update(None, "query_only", "ON")?;
    #[cfg(target_os = "android")]
    {
        let version: String = conn
            .pragma_query_value(None, "cipher_version", |row| row.get(0))
            .map_err(|e| {
                DatabaseInitError::ValidationFailed(format!("cipher_version query failed: {e}"))
            })?;
        if version.is_empty() {
            return Err(DatabaseInitError::ValidationFailed(
                "Android SQLCipher probe returned empty cipher_version".into(),
            ));
        }
    }

    // 1. Check for extra objects (tables, views, triggers) and inspect table DDL SQL in sqlite_master
    let mut stmt = conn
        .prepare(
            "SELECT type, name, tbl_name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'",
        )
        .map_err(|e| {
            DatabaseInitError::ValidationFailed(format!("App DB prepare sqlite_master failed: {e}"))
        })?;

    let mut existing_tables = std::collections::BTreeSet::new();
    let rows = stmt
        .query_map([], |row| {
            let obj_type: String = row.get(0)?;
            let name: String = row.get(1)?;
            let tbl_name: String = row.get(2)?;
            let sql: Option<String> = row.get(3)?;
            Ok((obj_type, name, tbl_name, sql))
        })
        .map_err(|e| {
            DatabaseInitError::ValidationFailed(format!(
                "App DB query_map sqlite_master failed: {e}"
            ))
        })?;

    for row_res in rows {
        let (obj_type, name, _tbl_name, sql_opt) = row_res.map_err(|e| {
            DatabaseInitError::ValidationFailed(format!("Failed to read sqlite_master row: {e}"))
        })?;
        match obj_type.as_str() {
            "table" => {
                if let Some(ref sql) = sql_opt {
                    let sql_upper = sql.to_uppercase();
                    const FORBIDDEN_DDL: &[(&[&str], &str)] = &[
                        (&[" CHECK", "CHECK(", "CHECK ("], "CHECK constraint"),
                        (&["STRICT"], "STRICT option"),
                        (&["WITHOUT ROWID"], "WITHOUT ROWID option"),
                        (&["GENERATED", " AS (", " AS("], "GENERATED column"),
                        (&["COLLATE"], "COLLATE clause"),
                        (&["REFERENCES"], "FOREIGN KEY constraint"),
                    ];
                    for (needles, what) in FORBIDDEN_DDL {
                        if needles.iter().any(|needle| sql_upper.contains(*needle)) {
                            return Err(DatabaseInitError::ValidationFailed(format!(
                                "App DB table `{name}` has unexpected {what} in DDL"
                            )));
                        }
                    }
                }
                existing_tables.insert(name);
            }
            "view" => {
                return Err(DatabaseInitError::ValidationFailed(format!(
                    "App DB has unexpected view object: {name}"
                )));
            }
            "trigger" => {
                return Err(DatabaseInitError::ValidationFailed(format!(
                    "App DB has unexpected trigger object: {name}"
                )));
            }
            "index" => {
                // Index validation is performed per-table below
            }
            other => {
                return Err(DatabaseInitError::ValidationFailed(format!(
                    "App DB has unexpected sqlite_master object of type {other}: {name}"
                )));
            }
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    struct ExpectedColumnDescriptor {
        name: &'static str,
        col_type: &'static str,
        notnull: bool,
        dflt_value: Option<&'static str>,
        pk: i32,
    }

    #[derive(Debug, PartialEq, Eq)]
    struct ActualColumnDescriptor {
        name: String,
        col_type: String,
        notnull: bool,
        dflt_value: Option<String>,
        pk: i32,
    }

    struct TableDescriptor {
        name: &'static str,
        columns: &'static [ExpectedColumnDescriptor],
    }

    const REQUIRED_TABLE_DESCRIPTORS: &[TableDescriptor] = &[
        TableDescriptor {
            name: "conversations",
            columns: &[
                ExpectedColumnDescriptor {
                    name: "conversation_id",
                    col_type: "TEXT",
                    notnull: true,
                    dflt_value: None,
                    pk: 1,
                },
                ExpectedColumnDescriptor {
                    name: "user_did",
                    col_type: "TEXT",
                    notnull: true,
                    dflt_value: None,
                    pk: 2,
                },
                ExpectedColumnDescriptor {
                    name: "group_id",
                    col_type: "TEXT",
                    notnull: true,
                    dflt_value: None,
                    pk: 0,
                },
                ExpectedColumnDescriptor {
                    name: "epoch",
                    col_type: "INTEGER",
                    notnull: true,
                    dflt_value: Some("0"),
                    pk: 0,
                },
                ExpectedColumnDescriptor {
                    name: "state",
                    col_type: "TEXT",
                    notnull: true,
                    dflt_value: Some("'Active'"),
                    pk: 0,
                },
                ExpectedColumnDescriptor {
                    name: "join_method",
                    col_type: "TEXT",
                    notnull: false,
                    dflt_value: None,
                    pk: 0,
                },
                ExpectedColumnDescriptor {
                    name: "join_epoch",
                    col_type: "INTEGER",
                    notnull: false,
                    dflt_value: None,
                    pk: 0,
                },
                ExpectedColumnDescriptor {
                    name: "needs_rejoin",
                    col_type: "INTEGER",
                    notnull: true,
                    dflt_value: Some("0"),
                    pk: 0,
                },
                ExpectedColumnDescriptor {
                    name: "members_json",
                    col_type: "TEXT",
                    notnull: true,
                    dflt_value: Some("'[]'"),
                    pk: 0,
                },
                ExpectedColumnDescriptor {
                    name: "metadata_json",
                    col_type: "TEXT",
                    notnull: false,
                    dflt_value: None,
                    pk: 0,
                },
                ExpectedColumnDescriptor {
                    name: "metadata_version",
                    col_type: "INTEGER",
                    notnull: false,
                    dflt_value: None,
                    pk: 0,
                },
                ExpectedColumnDescriptor {
                    name: "metadata_blob_locator",
                    col_type: "TEXT",
                    notnull: false,
                    dflt_value: None,
                    pk: 0,
                },
                ExpectedColumnDescriptor {
                    name: "avatar_blob_locator",
                    col_type: "TEXT",
                    notnull: false,
                    dflt_value: None,
                    pk: 0,
                },
                ExpectedColumnDescriptor {
                    name: "avatar_bytes",
                    col_type: "BLOB",
                    notnull: false,
                    dflt_value: None,
                    pk: 0,
                },
                ExpectedColumnDescriptor {
                    name: "avatar_content_type",
                    col_type: "TEXT",
                    notnull: false,
                    dflt_value: None,
                    pk: 0,
                },
                ExpectedColumnDescriptor {
                    name: "created_at",
                    col_type: "TEXT",
                    notnull: false,
                    dflt_value: None,
                    pk: 0,
                },
                ExpectedColumnDescriptor {
                    name: "updated_at",
                    col_type: "TEXT",
                    notnull: false,
                    dflt_value: None,
                    pk: 0,
                },
                ExpectedColumnDescriptor {
                    name: "sequencer_did",
                    col_type: "TEXT",
                    notnull: false,
                    dflt_value: None,
                    pk: 0,
                },
                ExpectedColumnDescriptor {
                    name: "reset_new_group_id",
                    col_type: "TEXT",
                    notnull: false,
                    dflt_value: None,
                    pk: 0,
                },
                ExpectedColumnDescriptor {
                    name: "reset_generation",
                    col_type: "INTEGER",
                    notnull: false,
                    dflt_value: None,
                    pk: 0,
                },
                ExpectedColumnDescriptor {
                    name: "reset_notified_at_ms",
                    col_type: "INTEGER",
                    notnull: false,
                    dflt_value: None,
                    pk: 0,
                },
                ExpectedColumnDescriptor {
                    name: "quarantine_reason_tag",
                    col_type: "TEXT",
                    notnull: false,
                    dflt_value: None,
                    pk: 0,
                },
                ExpectedColumnDescriptor {
                    name: "quarantine_since_ms",
                    col_type: "INTEGER",
                    notnull: false,
                    dflt_value: None,
                    pk: 0,
                },
            ],
        },
        TableDescriptor {
            name: "messages",
            columns: &[
                ExpectedColumnDescriptor {
                    name: "id",
                    col_type: "TEXT",
                    notnull: false,
                    dflt_value: None,
                    pk: 1,
                },
                ExpectedColumnDescriptor {
                    name: "conversation_id",
                    col_type: "TEXT",
                    notnull: true,
                    dflt_value: None,
                    pk: 0,
                },
                ExpectedColumnDescriptor {
                    name: "sender_did",
                    col_type: "TEXT",
                    notnull: true,
                    dflt_value: None,
                    pk: 0,
                },
                ExpectedColumnDescriptor {
                    name: "text",
                    col_type: "TEXT",
                    notnull: true,
                    dflt_value: None,
                    pk: 0,
                },
                ExpectedColumnDescriptor {
                    name: "timestamp",
                    col_type: "TEXT",
                    notnull: true,
                    dflt_value: None,
                    pk: 0,
                },
                ExpectedColumnDescriptor {
                    name: "epoch",
                    col_type: "INTEGER",
                    notnull: true,
                    dflt_value: None,
                    pk: 0,
                },
                ExpectedColumnDescriptor {
                    name: "sequence_number",
                    col_type: "INTEGER",
                    notnull: true,
                    dflt_value: None,
                    pk: 0,
                },
                ExpectedColumnDescriptor {
                    name: "is_own",
                    col_type: "INTEGER",
                    notnull: true,
                    dflt_value: Some("0"),
                    pk: 0,
                },
                ExpectedColumnDescriptor {
                    name: "delivery_status_json",
                    col_type: "TEXT",
                    notnull: false,
                    dflt_value: None,
                    pk: 0,
                },
                ExpectedColumnDescriptor {
                    name: "payload_json",
                    col_type: "TEXT",
                    notnull: false,
                    dflt_value: None,
                    pk: 0,
                },
                ExpectedColumnDescriptor {
                    name: "payload_encrypted",
                    col_type: "BLOB",
                    notnull: false,
                    dflt_value: None,
                    pk: 0,
                },
                ExpectedColumnDescriptor {
                    name: "entry_hmac",
                    col_type: "BLOB",
                    notnull: false,
                    dflt_value: None,
                    pk: 0,
                },
                ExpectedColumnDescriptor {
                    name: "payload_key_version",
                    col_type: "INTEGER",
                    notnull: false,
                    dflt_value: None,
                    pk: 0,
                },
                ExpectedColumnDescriptor {
                    name: "is_tombstone",
                    col_type: "INTEGER",
                    notnull: true,
                    dflt_value: Some("0"),
                    pk: 0,
                },
                ExpectedColumnDescriptor {
                    name: "deleted_at",
                    col_type: "INTEGER",
                    notnull: false,
                    dflt_value: None,
                    pk: 0,
                },
            ],
        },
        TableDescriptor {
            name: "sync_cursors",
            columns: &[
                ExpectedColumnDescriptor {
                    name: "user_did",
                    col_type: "TEXT",
                    notnull: false,
                    dflt_value: None,
                    pk: 1,
                },
                ExpectedColumnDescriptor {
                    name: "conversations_cursor",
                    col_type: "TEXT",
                    notnull: false,
                    dflt_value: None,
                    pk: 0,
                },
                ExpectedColumnDescriptor {
                    name: "messages_cursor",
                    col_type: "TEXT",
                    notnull: false,
                    dflt_value: None,
                    pk: 0,
                },
            ],
        },
        TableDescriptor {
            name: "group_states",
            columns: &[
                ExpectedColumnDescriptor {
                    name: "group_id",
                    col_type: "TEXT",
                    notnull: false,
                    dflt_value: None,
                    pk: 1,
                },
                ExpectedColumnDescriptor {
                    name: "conversation_id",
                    col_type: "TEXT",
                    notnull: true,
                    dflt_value: None,
                    pk: 0,
                },
                ExpectedColumnDescriptor {
                    name: "epoch",
                    col_type: "INTEGER",
                    notnull: true,
                    dflt_value: None,
                    pk: 0,
                },
                ExpectedColumnDescriptor {
                    name: "members_json",
                    col_type: "TEXT",
                    notnull: true,
                    dflt_value: Some("'[]'"),
                    pk: 0,
                },
            ],
        },
        TableDescriptor {
            name: "ws_cursors",
            columns: &[
                ExpectedColumnDescriptor {
                    name: "conversation_id",
                    col_type: "TEXT",
                    notnull: false,
                    dflt_value: None,
                    pk: 1,
                },
                ExpectedColumnDescriptor {
                    name: "cursor",
                    col_type: "TEXT",
                    notnull: true,
                    dflt_value: None,
                    pk: 0,
                },
            ],
        },
        TableDescriptor {
            name: "pending_messages",
            columns: &[
                ExpectedColumnDescriptor {
                    name: "message_id",
                    col_type: "TEXT",
                    notnull: false,
                    dflt_value: None,
                    pk: 1,
                },
                ExpectedColumnDescriptor {
                    name: "conversation_id",
                    col_type: "TEXT",
                    notnull: true,
                    dflt_value: None,
                    pk: 0,
                },
                ExpectedColumnDescriptor {
                    name: "created_at",
                    col_type: "INTEGER",
                    notnull: true,
                    dflt_value: None,
                    pk: 0,
                },
            ],
        },
        TableDescriptor {
            name: "recovery_backoffs",
            columns: &[
                ExpectedColumnDescriptor {
                    name: "conversation_id",
                    col_type: "TEXT",
                    notnull: false,
                    dflt_value: None,
                    pk: 1,
                },
                ExpectedColumnDescriptor {
                    name: "failed_rejoin_count",
                    col_type: "INTEGER",
                    notnull: true,
                    dflt_value: None,
                    pk: 0,
                },
                ExpectedColumnDescriptor {
                    name: "last_attempt_at_ms",
                    col_type: "INTEGER",
                    notnull: true,
                    dflt_value: None,
                    pk: 0,
                },
                ExpectedColumnDescriptor {
                    name: "quarantined_until_ms",
                    col_type: "INTEGER",
                    notnull: false,
                    dflt_value: None,
                    pk: 0,
                },
            ],
        },
        TableDescriptor {
            name: "recovery_globals",
            columns: &[
                ExpectedColumnDescriptor {
                    name: "key",
                    col_type: "TEXT",
                    notnull: false,
                    dflt_value: None,
                    pk: 1,
                },
                ExpectedColumnDescriptor {
                    name: "val_int",
                    col_type: "INTEGER",
                    notnull: false,
                    dflt_value: None,
                    pk: 0,
                },
            ],
        },
        TableDescriptor {
            name: "migration_status",
            columns: &[
                ExpectedColumnDescriptor {
                    name: "name",
                    col_type: "TEXT",
                    notnull: false,
                    dflt_value: None,
                    pk: 1,
                },
                ExpectedColumnDescriptor {
                    name: "applied_at",
                    col_type: "INTEGER",
                    notnull: true,
                    dflt_value: None,
                    pk: 0,
                },
            ],
        },
    ];

    let expected_tables: std::collections::BTreeSet<String> = REQUIRED_TABLE_DESCRIPTORS
        .iter()
        .map(|d| d.name.to_string())
        .collect();

    if existing_tables != expected_tables {
        return Err(DatabaseInitError::ValidationFailed(format!(
            "App DB table set mismatch: expected {expected_tables:?}, found {existing_tables:?}"
        )));
    }

    for desc in REQUIRED_TABLE_DESCRIPTORS {
        let mut stmt = conn
            .prepare(&format!("PRAGMA table_info({})", desc.name))
            .map_err(|e| {
                DatabaseInitError::ValidationFailed(format!(
                    "Failed to query table_info for {}: {e}",
                    desc.name
                ))
            })?;
        let actual_cols: Vec<ActualColumnDescriptor> = stmt
            .query_map([], |row| {
                let name: String = row.get(1)?;
                let col_type_raw: String = row.get(2)?;
                let notnull: bool = row.get::<_, i32>(3)? != 0;
                let dflt_value: Option<String> = row.get(4)?;
                let pk: i32 = row.get(5)?;
                let col_type = match column_storage_class(&col_type_raw) {
                    Some(class) => class.to_string(),
                    None => col_type_raw,
                };
                Ok(ActualColumnDescriptor {
                    name,
                    col_type,
                    notnull,
                    dflt_value,
                    pk,
                })
            })
            .map_err(|e| {
                DatabaseInitError::ValidationFailed(format!(
                    "Failed to map column info for {}: {e}",
                    desc.name
                ))
            })?
            .filter_map(|r| r.ok())
            .collect();

        let mismatch = actual_cols.len() != desc.columns.len()
            || actual_cols
                .iter()
                .zip(desc.columns.iter())
                .any(|(actual, expected)| {
                    actual.name != expected.name
                        || actual.col_type != expected.col_type
                        || actual.notnull != expected.notnull
                        || actual.dflt_value.as_deref() != expected.dflt_value
                        || actual.pk != expected.pk
                });
        if mismatch {
            return Err(DatabaseInitError::ValidationFailed(format!(
                "App DB table `{}` schema mismatch (expected {:?}, found {:?})",
                desc.name, desc.columns, actual_cols
            )));
        }

        // Validate foreign keys: expect exactly zero foreign keys for every table
        let mut fk_stmt = conn
            .prepare(&format!("PRAGMA foreign_key_list({})", desc.name))
            .map_err(|e| {
                DatabaseInitError::ValidationFailed(format!(
                    "Failed to query foreign_key_list for {}: {e}",
                    desc.name
                ))
            })?;
        let fk_count: usize = fk_stmt
            .query_map([], |_r| Ok(()))
            .map_err(|e| {
                DatabaseInitError::ValidationFailed(format!("Failed to read FK list: {e}"))
            })?
            .count();
        if fk_count > 0 {
            return Err(DatabaseInitError::ValidationFailed(format!(
                "App DB table `{}` has unexpected foreign keys (count: {fk_count})",
                desc.name
            )));
        }

        // Validate indices for this table
        let mut idx_stmt = conn
            .prepare(&format!("PRAGMA index_list({})", desc.name))
            .map_err(|e| {
                DatabaseInitError::ValidationFailed(format!(
                    "Failed to query index_list for {}: {e}",
                    desc.name
                ))
            })?;
        let table_indices: Vec<(String, bool, String, bool)> = idx_stmt
            .query_map([], |row| {
                let name: String = row.get(1)?;
                let unique: bool = row.get::<_, i32>(2)? != 0;
                let origin: String = row.get(3)?;
                let partial: bool = row.get::<_, i32>(4)? != 0;
                Ok((name, unique, origin, partial))
            })
            .map_err(|e| {
                DatabaseInitError::ValidationFailed(format!(
                    "Failed to map index list for {}: {e}",
                    desc.name
                ))
            })?
            .filter_map(|r| r.ok())
            .collect();

        if desc.name == "messages" {
            // messages must have exactly: 1 pk autoindex, and idx_messages_convo_seq (non-unique, non-partial)
            let mut has_expected_user_idx = false;
            for (idx_name, unique, origin, partial) in &table_indices {
                if idx_name == "idx_messages_convo_seq" {
                    if *unique || *partial || origin != "c" {
                        return Err(DatabaseInitError::ValidationFailed(format!(
                            "idx_messages_convo_seq has invalid index properties: unique={unique}, partial={partial}, origin={origin}"
                        )));
                    }
                    // Validate exact column sequence
                    let mut info_stmt = conn
                        .prepare("PRAGMA index_info(idx_messages_convo_seq)")
                        .map_err(|e| {
                        DatabaseInitError::ValidationFailed(format!(
                            "Failed to query index_info: {e}"
                        ))
                    })?;
                    let indexed_cols: Vec<(i32, String)> = info_stmt
                        .query_map([], |row| {
                            let seqno: i32 = row.get(0)?;
                            let col_name: String = row.get(2)?;
                            Ok((seqno, col_name))
                        })
                        .map_err(|e| {
                            DatabaseInitError::ValidationFailed(format!(
                                "Failed to map index_info: {e}"
                            ))
                        })?
                        .filter_map(|r| r.ok())
                        .collect();
                    let expected_cols = vec![
                        (0, "conversation_id".to_string()),
                        (1, "sequence_number".to_string()),
                    ];
                    if indexed_cols != expected_cols {
                        return Err(DatabaseInitError::ValidationFailed(format!(
                            "idx_messages_convo_seq column mismatch: expected {expected_cols:?}, found {indexed_cols:?}"
                        )));
                    }
                    has_expected_user_idx = true;
                } else if origin == "pk" {
                    // Expected primary key autoindex
                } else {
                    return Err(DatabaseInitError::ValidationFailed(format!(
                        "App DB table messages has unexpected extra index: {idx_name}"
                    )));
                }
            }
            if !has_expected_user_idx {
                return Err(DatabaseInitError::ValidationFailed(
                    "App DB missing required index idx_messages_convo_seq".into(),
                ));
            }
        } else {
            // All other tables must ONLY have the PK autoindex and NO extra index / UNIQUE constraint
            for (idx_name, _unique, origin, _partial) in &table_indices {
                if origin != "pk" {
                    return Err(DatabaseInitError::ValidationFailed(format!(
                        "App DB table `{}` has unexpected extra index / constraint: {idx_name}",
                        desc.name
                    )));
                }
            }
        }
    }

    // 2. Validate MLSMessageFieldMigrationV1 status row exists
    let migration_count: i64 = conn
        .query_row(
            "SELECT count(*) FROM migration_status WHERE name = 'MLSMessageFieldMigrationV1'",
            [],
            |r| r.get(0),
        )
        .map_err(|e| {
            DatabaseInitError::ValidationFailed(format!(
                "App DB migration_status check failed: {e}"
            ))
        })?;
    if migration_count == 0 {
        return Err(DatabaseInitError::ValidationFailed(
            "App DB missing MLSMessageFieldMigrationV1 status row".into(),
        ));
    }

    let quick_check: String = conn
        .pragma_query_value(None, "quick_check", |row| row.get(0))
        .map_err(|e| {
            DatabaseInitError::ValidationFailed(format!("App DB quick_check query failed: {e}"))
        })?;
    if quick_check != "ok" {
        return Err(DatabaseInitError::ValidationFailed(format!(
            "App DB quick_check returned: {quick_check}"
        )));
    }
    Ok(())
}

pub fn open_clean_account_storage(
    data_dir: &Path,
    user_did: &str,
    service: &str,
) -> std::result::Result<
    (
        Arc<SqliteStorage>,
        Arc<catbird_mls::MLSContext>,
        Vec<u8>,
        AccountLock,
    ),
    DatabaseInitError,
> {
    open_clean_account_storage_with_store(data_dir, user_did, service, &KeyringDbKeyStore)
}

pub fn open_clean_account_storage_with_store(
    data_dir: &Path,
    user_did: &str,
    service: &str,
    store: &dyn DbKeyStore,
) -> std::result::Result<
    (
        Arc<SqliteStorage>,
        Arc<catbird_mls::MLSContext>,
        Vec<u8>,
        AccountLock,
    ),
    DatabaseInitError,
> {
    let normalized_did = crate::keys::normalize_did(user_did);
    let account_id = crate::keys::derive_account_id(&normalized_did);

    let lock = acquire_account_lock(data_dir, &account_id)?;

    let app_db_name = app_db_file_name(&account_id);
    let mls_db_name = mls_db_file_name(&account_id);
    let app_db_path = data_dir.join(&app_db_name);
    let mls_state_dir = data_dir.join(MLS_STORAGE_GENERATION);
    let mls_db_path = mls_state_dir.join(&mls_db_name);
    let marker_file = account_marker_path(data_dir, &account_id);
    let content_root_path = crate::keys::content_root_key_path(data_dir, &account_id);

    let app_key_label = app_db_key_label(&account_id);
    let mls_key_label = mls_db_key_label(&account_id);

    let app_db_exists = app_db_path.exists();
    let app_sidecars_exist = app_db_path.with_extension("db-wal").exists()
        || app_db_path.with_extension("db-shm").exists()
        || app_db_path.with_extension("db-journal").exists();

    let mls_db_exists = mls_db_path.exists();
    let mls_sidecars_exist = mls_db_path.with_extension("db-wal").exists()
        || mls_db_path.with_extension("db-shm").exists()
        || mls_db_path.with_extension("db-journal").exists();

    let app_key_opt = load_db_key_from_store(store, service, &app_key_label)?;
    let mls_key_opt = load_db_key_from_store(store, service, &mls_key_label)?;
    let content_root_exists = content_root_path.exists();
    let marker_opt = read_account_marker(
        &marker_file,
        &normalized_did,
        &account_id,
        &app_db_name,
        &mls_db_name,
    )?;

    let credential_state =
        crate::credentials::KeyringCredentialStore::check_credential_state(&normalized_did)
            .map_err(|e| DatabaseInitError::KeyringError(e.to_string()))?;
    let signer_slots_exist =
        crate::keychain::KeyringKeychainAccess::has_signer_slots_unlocked(&account_id)
            .map_err(DatabaseInitError::KeyringError)?;

    let credentials_absent =
        credential_state == crate::credentials::CredentialEnrollmentState::Unenrolled;
    let all_absent = !app_db_exists
        && !app_sidecars_exist
        && !mls_db_exists
        && !mls_sidecars_exist
        && app_key_opt.is_none()
        && mls_key_opt.is_none()
        && !content_root_exists
        && marker_opt.is_none()
        && credentials_absent
        && !signer_slots_exist;

    let all_present = app_db_exists
        && mls_db_exists
        && app_key_opt.is_some()
        && mls_key_opt.is_some()
        && content_root_exists
        && marker_opt == Some(MarkerStatus::Complete);
    if all_absent {
        if let Some(parent) = app_db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::create_dir_all(&mls_state_dir)?;

        write_account_marker_creating(
            &marker_file,
            &normalized_did,
            &account_id,
            &app_db_name,
            &mls_db_name,
        )?;

        let content_root_key = crate::keys::create_new_content_root_key(data_dir, &normalized_did)
            .map_err(|e| {
                DatabaseInitError::ValidationFailed(format!(
                    "content root key creation failed: {e}"
                ))
            })?;
        if content_root_key.len() != crate::keys::KEY_LEN {
            return Err(DatabaseInitError::ValidationFailed(
                "invalid content root key length".into(),
            ));
        }

        let app_key = create_db_key_in_store(store, service, &app_key_label)?;
        let mls_key = create_db_key_in_store(store, service, &mls_key_label)?;

        let storage = Arc::new(SqliteStorage::create_new(
            &app_db_path.to_string_lossy(),
            &app_key,
        )?);

        let keychain = Box::new(crate::keychain::KeyringKeychainAccess::new(
            account_id.clone(),
        ));
        let mls_context = catbird_mls::MLSContext::new(
            mls_db_path.to_string_lossy().to_string(),
            mls_key,
            keychain,
        )
        .map_err(|e| DatabaseInitError::ValidationFailed(format!("MLSContext init failed: {e}")))?;

        if let Err(e) = mls_context.launch_checkpoint() {
            tracing::warn!("MLSContext launch_checkpoint warning: {:?}", e);
        }

        // Creation marker stays `creating` until credential tuple enrollment succeeds
        Ok((storage, mls_context, content_root_key, lock))
    } else if all_present {
        match credential_state {
            crate::credentials::CredentialEnrollmentState::Partial(msg) => {
                return Err(DatabaseInitError::ValidationFailed(format!(
                    "partial credential state: {msg}"
                )));
            }
            crate::credentials::CredentialEnrollmentState::FullyEnrolled => {
                if !signer_slots_exist {
                    return Err(DatabaseInitError::ValidationFailed(
                        "fully enrolled credentials present without signer slots".into(),
                    ));
                }
                crate::keychain::KeyringKeychainAccess::validate_signer_slots_unlocked(&account_id)
                    .map_err(DatabaseInitError::KeyringError)?;
            }
            crate::credentials::CredentialEnrollmentState::Unenrolled => {
                return Err(DatabaseInitError::ValidationFailed(
                    "complete marker present but credentials are unenrolled".into(),
                ));
            }
        }

        let content_root_key = crate::keys::load_existing_content_root_key(
            data_dir,
            &normalized_did,
        )
        .map_err(|e| {
            DatabaseInitError::ValidationFailed(format!("content root key read failed: {e}"))
        })?;

        let app_key = app_key_opt.unwrap();
        let mls_key = mls_key_opt.unwrap();

        // Read-only SQLCipher validation before opening writable constructors
        validate_app_db_readonly(&app_db_path, &app_key)?;
        validate_mls_db_readonly(&mls_db_path, &mls_key)?;

        // Verify that the exact manifest signer binds to persisted mls_did and signing_key public key
        {
            let mls_conn = open_mls_db_readonly(&mls_db_path, &mls_key)?;

            let signers_json: String = mls_conn
                .query_row(
                    "SELECT value FROM mls_manifests WHERE key = 'signers'",
                    [],
                    |r| r.get(0),
                )
                .map_err(|e| {
                    DatabaseInitError::ValidationFailed(format!(
                        "MLS DB missing `signers` manifest: {e}"
                    ))
                })?;
            let signers_map: std::collections::HashMap<String, String> =
                serde_json::from_str(&signers_json).map_err(|e| {
                    DatabaseInitError::ValidationFailed(format!("Corrupt signers manifest: {e}"))
                })?;
            if signers_map.is_empty() {
                return Err(DatabaseInitError::ValidationFailed(
                    "MLS DB signers manifest is empty".into(),
                ));
            }

            let mls_did_key =
                crate::credentials::KeyringCredentialStore::key_mls_did(&normalized_did);
            let mls_did_entry = keyring::Entry::new(crate::credentials::SERVICE_NAME, &mls_did_key)
                .map_err(|e| DatabaseInitError::KeyringError(e.to_string()))?;
            let persisted_mls_did = mls_did_entry.get_password().map_err(|e| {
                DatabaseInitError::KeyringError(format!("missing persisted mls_did: {e}"))
            })?;

            let hex_identity = hex::encode(persisted_mls_did.trim().as_bytes());
            let hex_pk = signers_map.get(&hex_identity).ok_or_else(|| {
                DatabaseInitError::ValidationFailed(format!(
                    "signers manifest does not contain persisted identity `{persisted_mls_did}`"
                ))
            })?;
            let manifest_pk = hex::decode(hex_pk).map_err(|e| {
                DatabaseInitError::ValidationFailed(format!(
                    "invalid hex in signers manifest pk: {e}"
                ))
            })?;

            // Verify public key matches the signing_key credential
            let signing_key_name =
                crate::credentials::KeyringCredentialStore::key_signing(&normalized_did);
            let signing_key_entry =
                keyring::Entry::new(crate::credentials::SERVICE_NAME, &signing_key_name)
                    .map_err(|e| DatabaseInitError::KeyringError(e.to_string()))?;
            let signing_key_b64 = signing_key_entry.get_password().map_err(|e| {
                DatabaseInitError::KeyringError(format!("missing persisted signing_key: {e}"))
            })?;
            use base64::engine::general_purpose::STANDARD as B64;
            use base64::Engine;
            let signing_key_bytes = B64.decode(signing_key_b64.trim()).map_err(|e| {
                DatabaseInitError::ValidationFailed(format!("invalid base64 in signing_key: {e}"))
            })?;
            let val: serde_json::Value =
                serde_json::from_slice(&signing_key_bytes).map_err(|e| {
                    DatabaseInitError::ValidationFailed(format!("invalid JSON in signing_key: {e}"))
                })?;
            let pk_val = val
                .get("public")
                .and_then(|p| p.as_array())
                .ok_or_else(|| {
                    DatabaseInitError::ValidationFailed(
                        "missing public field in signing_key".into(),
                    )
                })?;
            let signing_key_pk: Vec<u8> = pk_val
                .iter()
                .filter_map(|v| v.as_u64().and_then(|n| u8::try_from(n).ok()))
                .collect();
            if signing_key_pk != manifest_pk {
                return Err(DatabaseInitError::ValidationFailed(
                    "public key mismatch between signers manifest and signing_key credential"
                        .into(),
                ));
            }
        }
        let storage = Arc::new(SqliteStorage::open_existing(
            &app_db_path.to_string_lossy(),
            &app_key,
        )?);
        let keychain = Box::new(crate::keychain::KeyringKeychainAccess::new(
            account_id.clone(),
        ));
        let mls_context = catbird_mls::MLSContext::new(
            mls_db_path.to_string_lossy().to_string(),
            mls_key,
            keychain,
        )
        .map_err(|e| {
            DatabaseInitError::ValidationFailed(format!("MLSContext reopen failed: {e}"))
        })?;

        Ok((storage, mls_context, content_root_key, lock))
    } else {
        if marker_opt == Some(MarkerStatus::Creating) {
            return Err(DatabaseInitError::InitializationIncomplete);
        }
        if app_sidecars_exist && !app_db_exists || mls_sidecars_exist && !mls_db_exists {
            return Err(DatabaseInitError::MixedStatePresentDbAbsentKey);
        }
        if !app_db_exists && app_key_opt.is_some() || !mls_db_exists && mls_key_opt.is_some() {
            return Err(DatabaseInitError::MixedStateAbsentDbPresentKey);
        }
        if app_db_exists && app_key_opt.is_none() || mls_db_exists && mls_key_opt.is_none() {
            return Err(DatabaseInitError::MixedStatePresentDbAbsentKey);
        }
        if marker_opt.is_none()
            && (app_db_exists
                || mls_db_exists
                || app_key_opt.is_some()
                || mls_key_opt.is_some()
                || content_root_exists
                || !credentials_absent
                || signer_slots_exist)
        {
            return Err(DatabaseInitError::MixedStateMissingMarker);
        }
        if marker_opt == Some(MarkerStatus::Complete)
            && (!app_db_exists
                || !mls_db_exists
                || app_key_opt.is_none()
                || mls_key_opt.is_none()
                || !content_root_exists)
        {
            return Err(DatabaseInitError::InvalidMarker(
                "complete marker present but resource set is incomplete or mixed".into(),
            ));
        }
        Err(DatabaseInitError::MixedStateMissingMarker)
    }
}

/// Remove a SQLite database file together with its WAL/SHM/journal sidecars.
fn remove_db_with_sidecars(db_path: &Path) -> std::result::Result<(), String> {
    for path in [
        db_path.to_path_buf(),
        db_path.with_extension("db-wal"),
        db_path.with_extension("db-shm"),
        db_path.with_extension("db-journal"),
    ] {
        if path.exists() {
            std::fs::remove_file(&path)
                .map_err(|e| format!("failed to remove {}: {e}", path.display()))?;
        }
    }
    Ok(())
}

/// Remove temp files matching `matches` in `dir`, tolerating a missing directory.
/// `what` prefixes the error messages ("" for the data dir, "content-root " for the key dir).
fn remove_temp_files(
    dir: &Path,
    what: &str,
    matches: impl Fn(&str) -> bool,
) -> std::result::Result<(), String> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(format!(
                "failed to read {what}directory {}: {e}",
                dir.display()
            ))
        }
    };
    for entry_res in entries {
        let entry = entry_res.map_err(|e| {
            format!(
                "failed to read {what}directory entry in {}: {e}",
                dir.display()
            )
        })?;
        let file_name = entry.file_name().to_string_lossy().to_string();
        if !matches(&file_name) {
            continue;
        }
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(format!(
                    "failed to remove {what}temp file {}: {e}",
                    path.display()
                ))
            }
        }
    }
    Ok(())
}

pub async fn reset_account_storage(
    data_dir: &Path,
    user_did: &str,
    storage: Option<Arc<SqliteStorage>>,
    mls_context: Option<&catbird_mls::MLSContext>,
    service: &str,
) -> std::result::Result<(), String> {
    reset_account_storage_with_store(
        data_dir,
        user_did,
        storage,
        mls_context,
        service,
        &KeyringDbKeyStore,
    )
    .await
}

pub async fn reset_account_storage_with_store(
    data_dir: &Path,
    user_did: &str,
    storage: Option<Arc<SqliteStorage>>,
    mls_context: Option<&catbird_mls::MLSContext>,
    service: &str,
    store: &dyn DbKeyStore,
) -> std::result::Result<(), String> {
    let normalized_did = crate::keys::normalize_did(user_did);
    let account_id = crate::keys::derive_account_id(&normalized_did);

    let _lock = acquire_account_lock(data_dir, &account_id)
        .map_err(|e| format!("failed to acquire account lock for reset: {e}"))?;

    // --- PHASE 1: PREFLIGHT (ZERO MUTATION) ---
    // Validate that signer index is readable and parseable before deleting ANY secret
    let signer_slots_to_delete =
        crate::keychain::KeyringKeychainAccess::preflight_account_signer_slots_reset(&account_id)
            .map_err(|e| format!("preflight signer index failed: {e}"))?;

    // --- PHASE 2: EXECUTION ---
    // 1. Close MLSContext if provided
    if let Some(ctx) = mls_context {
        ctx.clear_content_root_key();
        ctx.interrupt();
        ctx.flush_and_prepare_close()
            .map_err(|e| format!("MLSContext flush_and_prepare_close failed: {e:?}"))?;
    }

    // 2. Drop SqliteStorage handle
    drop(storage);

    // 3. Clear exact-DID credentials from keyring
    crate::credentials::KeyringCredentialStore::delete_exact_account_credentials(&normalized_did)
        .map_err(|e| format!("failed to clear keyring credentials: {e}"))?;

    // 4. Delete exact account content-root key file and .tmp.<uuid> files
    crate::keys::delete_content_root_key(data_dir, &normalized_did)
        .map_err(|e| format!("failed to delete content-root key: {e}"))?;

    // 5. Delete preflight-verified MLS signer slots and index entry
    crate::keychain::KeyringKeychainAccess::execute_account_signer_slots_reset(
        &account_id,
        signer_slots_to_delete,
    )
    .map_err(|e| format!("failed to clear indexed MLS signer slots: {e}"))?;

    // 6. Delete App DB and sidecars
    remove_db_with_sidecars(&data_dir.join(app_db_file_name(&account_id)))?;

    // 7. Delete App DB key from store
    let app_key_label = app_db_key_label(&account_id);
    store
        .delete_password(service, &app_key_label)
        .map_err(|e| format!("failed to delete conversation DB key: {e}"))?;

    // 8. Delete MLS DB and sidecars
    let mls_db_path = data_dir
        .join(MLS_STORAGE_GENERATION)
        .join(mls_db_file_name(&account_id));
    remove_db_with_sidecars(&mls_db_path)?;

    // 9. Delete MLS DB key from store
    let mls_key_label = mls_db_key_label(&account_id);
    store
        .delete_password(service, &mls_key_label)
        .map_err(|e| format!("failed to delete MLS DB key: {e}"))?;

    // 10. Delete all account-scoped temp files in data_dir (.tmp.*) and content-root dir ({account_id}.tmp.*)
    let account_file_prefix = format!("catmos-{}-{}.", account_id, MLS_KEY_SUFFIX);
    remove_temp_files(data_dir, "", |file_name| {
        file_name.starts_with(&account_file_prefix) && file_name.contains(".tmp")
    })?;

    let cr_dir = data_dir.join(crate::keys::MLS_CONTENT_ROOT_DIR);
    let cr_temp_prefix = format!("{}.tmp.", account_id);
    remove_temp_files(&cr_dir, "content-root ", |file_name| {
        file_name.starts_with(&cr_temp_prefix)
    })?;

    // 11. Delete marker file explicitly LAST and propagate failure
    let marker_file = account_marker_path(data_dir, &account_id);
    match std::fs::remove_file(&marker_file) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(format!(
                "failed to remove marker file {}: {e}",
                marker_file.display()
            ))
        }
    }

    Ok(())
}
/// Locally cached encrypted-metadata snapshot for a conversation. Mirrors
/// what `bootstrap_group_metadata` writes after a successful blob fetch +
/// decrypt: the JSON-serialized `GroupMetadataV1` payload, the bound
/// `metadata_version`, and the locator pointing at the server-stored
/// ciphertext. Used by the bootstrap path to detect "blob already in sync at
/// this version" and skip a redundant fetch.
pub struct LocalMetadataSnapshot {
    pub metadata_json: Option<String>,
    pub metadata_version: Option<i64>,
    pub metadata_blob_locator: Option<String>,
}

/// JSON-shaped canonical plaintext that gets sealed by the field-level
/// encryption layer before persistence. Storing the rich payload (rather
/// than the bare `text` column) means that encrypted rows retain enough
/// fidelity to rebuild the in-memory `Message` after a round-trip, while
/// the `text NOT NULL` constraint is satisfied by writing an empty string
/// to the legacy column when the encrypted payload is the source of truth.
#[derive(serde::Serialize, serde::Deserialize)]
struct CanonicalMessageBody<'a> {
    text: &'a str,
    payload_json: Option<&'a str>,
}

#[derive(serde::Deserialize)]
struct CanonicalMessageBodyOwned {
    text: String,
    payload_json: Option<String>,
}

/// Version tag stamped into `payload_key_version` on every encrypted row.
const PAYLOAD_KEY_VERSION_V1: i64 = 1;

/// SQLite-backed storage for Catmos desktop.
pub struct SqliteStorage {
    conn: Mutex<Connection>,
    /// Shared MLS context used for the field-level (envelope) encryption layer.
    /// Set via [`SqliteStorage::set_mls_context`] after the context is built
    /// in `lib.rs`. When unset — or when the per-DID content root key is not
    /// yet installed — the write/read paths fall back to plaintext columns so
    /// the orchestrator can keep functioning during the bootstrap window
    /// (initial sync may run before login completes).
    mls_context: RwLock<Option<Arc<MLSContext>>>,
}

impl SqliteStorage {
    /// Open a keyed SQLCipher connection and wrap it, without touching schema.
    pub fn open_existing(
        db_path: &str,
        encryption_key: &str,
    ) -> std::result::Result<Self, rusqlite::Error> {
        let conn = Connection::open(db_path)?;
        // Set SQLCipher key (required even for unencrypted use with bundled-sqlcipher)
        conn.execute_batch(&format!("PRAGMA key = '{}';", encryption_key))?;
        #[cfg(target_os = "android")]
        {
            let version: String =
                conn.pragma_query_value(None, "cipher_version", |row| row.get(0))?;
            if version.is_empty() {
                tracing::error!("Android SQLCipher probe returned empty cipher_version");
                return Err(rusqlite::Error::InvalidQuery);
            }
            tracing::info!("Android SQLCipher enabled (cipher_version={version})");
        }
        conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000;")?;
        Ok(Self {
            conn: Mutex::new(conn),
            mls_context: RwLock::new(None),
        })
    }

    pub fn create_new(
        db_path: &str,
        encryption_key: &str,
    ) -> std::result::Result<Self, rusqlite::Error> {
        let storage = Self::open_existing(db_path, encryption_key)?;
        storage.create_tables()?;
        storage.validate().map_err(|e| match e {
            DatabaseInitError::Sqlite(err) => err,
            other => rusqlite::Error::InvalidParameterName(other.to_string()),
        })?;
        Ok(storage)
    }

    pub fn validate(&self) -> std::result::Result<(), DatabaseInitError> {
        let conn = self.conn.lock().unwrap();
        #[cfg(target_os = "android")]
        {
            let version: String = conn
                .pragma_query_value(None, "cipher_version", |row| row.get(0))
                .map_err(|e| {
                    DatabaseInitError::ValidationFailed(format!("cipher_version query failed: {e}"))
                })?;
            if version.is_empty() {
                return Err(DatabaseInitError::ValidationFailed(
                    "Android SQLCipher probe returned empty cipher_version".into(),
                ));
            }
        }
        let _count: i64 = conn
            .query_row("SELECT count(*) FROM sqlite_master", [], |row| row.get(0))
            .map_err(|e| {
                DatabaseInitError::ValidationFailed(format!(
                    "sqlite_master query failed (wrong key or corrupt db): {e}"
                ))
            })?;
        let quick_check: String = conn
            .pragma_query_value(None, "quick_check", |row| row.get(0))
            .map_err(|e| {
                DatabaseInitError::ValidationFailed(format!("quick_check query failed: {e}"))
            })?;
        if quick_check != "ok" {
            return Err(DatabaseInitError::ValidationFailed(format!(
                "quick_check returned: {quick_check}"
            )));
        }
        Ok(())
    }

    pub fn clear_mls_context(&self) {
        if let Ok(mut guard) = self.mls_context.write() {
            *guard = None;
        }
    }

    /// Bind the per-process MLS context for the field-level encryption layer.
    /// Called once from `lib.rs::run()` right after the context is constructed.
    /// Idempotent; later calls replace the binding.
    pub fn set_mls_context(&self, ctx: Arc<MLSContext>) {
        if let Ok(mut guard) = self.mls_context.write() {
            *guard = Some(ctx);
        }
    }

    fn mls_context_snapshot(&self) -> Option<Arc<MLSContext>> {
        self.mls_context
            .read()
            .ok()
            .and_then(|g| g.as_ref().cloned())
    }

    /// Read the most recent (highest sequence_number) `entry_hmac` for a
    /// conversation so the next encrypted row can extend the HMAC chain.
    /// Returns `None` for the first row in a conversation (chain seed = 32
    /// zero bytes is supplied by the Rust core when `prev_hmac=None`) or
    /// when prior rows are legacy-plaintext (no chain).
    fn last_entry_hmac(&self, conversation_id: &str) -> Option<Vec<u8>> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT entry_hmac FROM messages
             WHERE conversation_id = ?1 AND entry_hmac IS NOT NULL
             ORDER BY sequence_number DESC LIMIT 1",
            rusqlite::params![conversation_id],
            |r| r.get::<_, Option<Vec<u8>>>(0),
        )
        .optional()
        .ok()
        .flatten()
        .flatten()
    }

    /// Seal a `Message` for storage via the field-level encryption layer.
    /// Returns `None` if the MLS context is unbound or its content root key
    /// has not been installed yet — callers fall back to legacy plaintext
    /// columns and log a warning so the orchestrator can continue functioning
    /// during the bootstrap window (initial sync may run before login
    /// finishes installing the content root key).
    fn try_encrypt_message_body(&self, message: &Message) -> Option<(Vec<u8>, Vec<u8>)> {
        let ctx = self.mls_context_snapshot()?;
        let body = CanonicalMessageBody {
            text: &message.text,
            payload_json: message.payload_json.as_deref(),
        };
        let plaintext = match serde_json::to_vec(&body) {
            Ok(v) => v,
            Err(err) => {
                tracing::warn!(
                    message_id = %message.id,
                    error = %err,
                    "try_encrypt_message_body: canonical body serialization failed; falling back to plaintext"
                );
                return None;
            }
        };
        let encrypted = match ctx
            .encrypt_message_payload(message.conversation_id.clone(), plaintext)
        {
            Ok(bytes) => bytes,
            Err(err) => {
                tracing::warn!(
                    message_id = %message.id,
                    error = ?err,
                    "try_encrypt_message_body: encrypt_message_payload failed (content root key may be unset); falling back to plaintext"
                );
                return None;
            }
        };
        let prev_hmac = self.last_entry_hmac(&message.conversation_id);
        let entry_hmac = match ctx.compute_message_hmac(
            message.conversation_id.clone(),
            prev_hmac,
            message.id.clone(),
            encrypted.clone(),
        ) {
            Ok(tag) => tag,
            Err(err) => {
                tracing::warn!(
                    message_id = %message.id,
                    error = ?err,
                    "try_encrypt_message_body: compute_message_hmac failed; falling back to plaintext"
                );
                return None;
            }
        };
        Some((encrypted, entry_hmac))
    }

    fn create_tables(&self) -> std::result::Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS conversations (
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

            CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY,
                conversation_id TEXT NOT NULL,
                sender_did TEXT NOT NULL,
                text TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                epoch INTEGER NOT NULL,
                sequence_number INTEGER NOT NULL,
                is_own INTEGER NOT NULL DEFAULT 0,
                delivery_status_json TEXT,
                payload_json TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_messages_convo_seq
                ON messages(conversation_id, sequence_number);

            CREATE TABLE IF NOT EXISTS sync_cursors (
                user_did TEXT PRIMARY KEY,
                conversations_cursor TEXT,
                messages_cursor TEXT
            );

            CREATE TABLE IF NOT EXISTS group_states (
                group_id TEXT PRIMARY KEY,
                conversation_id TEXT NOT NULL,
                epoch INTEGER NOT NULL,
                members_json TEXT NOT NULL DEFAULT '[]'
            );

            CREATE TABLE IF NOT EXISTS ws_cursors (
                conversation_id TEXT PRIMARY KEY,
                cursor TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS pending_messages (
                message_id TEXT PRIMARY KEY,
                conversation_id TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS recovery_backoffs (
                conversation_id TEXT PRIMARY KEY,
                failed_rejoin_count INTEGER NOT NULL,
                last_attempt_at_ms INTEGER NOT NULL,
                quarantined_until_ms INTEGER
            );

            CREATE TABLE IF NOT EXISTS recovery_globals (
                key TEXT PRIMARY KEY,
                val_int INTEGER
            );
            ",
        )?;
        Self::ensure_messages_delivery_status_column(&conn)?;
        Self::ensure_conversations_reset_pending_columns(&conn)?;
        Self::ensure_conversations_metadata_columns(&conn)?;
        Self::ensure_conversations_sequencer_column(&conn)?;
        Self::ensure_conversations_quarantine_columns(&conn)?;
        Self::ensure_message_field_columns(&conn)?;
        Self::ensure_message_field_migration_v1(&conn)?;
        Ok(())
    }

    /// Add the field-level-encryption columns to the `messages` table on
    /// pre-cutover installs. New installs already get these columns from the
    /// `CREATE TABLE` above implicitly via the migration path; this helper
    /// is the only place that adds them so the column list stays in one place.
    /// `text` stays `NOT NULL` because making it nullable would require a full
    /// table rebuild on SQLite; encrypted rows write an empty string into it
    /// and put the real payload in `payload_encrypted`.
    fn ensure_message_field_columns(conn: &Connection) -> std::result::Result<(), rusqlite::Error> {
        let existing: std::collections::HashSet<String> = {
            let mut stmt = conn.prepare("PRAGMA table_info(messages)")?;
            let rows = stmt.query_map([], |r| r.get::<_, String>(1))?;
            rows.filter_map(|r| r.ok()).collect()
        };
        if !existing.contains("payload_encrypted") {
            conn.execute("ALTER TABLE messages ADD COLUMN payload_encrypted BLOB", [])?;
        }
        if !existing.contains("entry_hmac") {
            conn.execute("ALTER TABLE messages ADD COLUMN entry_hmac BLOB", [])?;
        }
        if !existing.contains("payload_key_version") {
            conn.execute(
                "ALTER TABLE messages ADD COLUMN payload_key_version INTEGER",
                [],
            )?;
        }
        // Tombstone parity with iOS/Android: catmos desktop does not currently
        // expose user-initiated message delete, but the columns are added now
        // so that when a delete path lands later it can soft-delete without
        // another schema migration breaking the HMAC chain.
        if !existing.contains("is_tombstone") {
            conn.execute(
                "ALTER TABLE messages ADD COLUMN is_tombstone INTEGER NOT NULL DEFAULT 0",
                [],
            )?;
        }
        if !existing.contains("deleted_at") {
            conn.execute("ALTER TABLE messages ADD COLUMN deleted_at INTEGER", [])?;
        }
        Ok(())
    }

    /// First-run drop of any pre-field-encryption message rows. Matches the
    /// `MLSPlaintextHeaderMigration` precedent on iOS / Android: existing
    /// transcripts cannot satisfy the encrypted-row invariants (no HMAC chain
    /// seed, no per-conversation content key derivation history), so we drop
    /// them once and record the migration in a `migration_status` table so
    /// it is never re-run.
    fn ensure_message_field_migration_v1(
        conn: &Connection,
    ) -> std::result::Result<(), rusqlite::Error> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS migration_status (
                name TEXT PRIMARY KEY,
                applied_at INTEGER NOT NULL
            )",
            [],
        )?;
        let already: i64 = conn.query_row(
            "SELECT COUNT(*) FROM migration_status WHERE name = ?1",
            ["MLSMessageFieldMigrationV1"],
            |r| r.get(0),
        )?;
        if already > 0 {
            return Ok(());
        }
        conn.execute("DELETE FROM messages", [])?;
        conn.execute(
            "INSERT INTO migration_status (name, applied_at) VALUES (?1, strftime('%s','now'))",
            ["MLSMessageFieldMigrationV1"],
        )?;
        Ok(())
    }

    /// Layer 3 quarantine: add `quarantine_reason_tag` + `quarantine_since_ms`
    /// columns to existing installs. New schemas already have them via the
    /// `CREATE TABLE` above; this idempotent migration covers upgrades.
    /// Mirrors the `ensure_conversations_reset_pending_columns` pattern.
    fn ensure_conversations_quarantine_columns(
        conn: &Connection,
    ) -> std::result::Result<(), rusqlite::Error> {
        let mut stmt = conn.prepare("PRAGMA table_info(conversations)")?;
        let mut has_quarantine_reason_tag = false;
        let mut has_quarantine_since_ms = false;
        let column_names = stmt.query_map([], |row| row.get::<_, String>(1))?;

        for column_name in column_names {
            match column_name?.as_str() {
                "quarantine_reason_tag" => has_quarantine_reason_tag = true,
                "quarantine_since_ms" => has_quarantine_since_ms = true,
                _ => {}
            }
        }

        if !has_quarantine_reason_tag {
            conn.execute(
                "ALTER TABLE conversations ADD COLUMN quarantine_reason_tag TEXT",
                [],
            )?;
        }
        if !has_quarantine_since_ms {
            conn.execute(
                "ALTER TABLE conversations ADD COLUMN quarantine_since_ms INTEGER",
                [],
            )?;
        }
        Ok(())
    }

    /// Add the encrypted-metadata bookkeeping columns to `conversations` for
    /// pre-cutover databases. New schemas already include these columns from
    /// `CREATE TABLE`, but existing installs need an in-place migration.
    /// Each ALTER is guarded by a PRAGMA inspection so re-running is a no-op.
    fn ensure_conversations_metadata_columns(
        conn: &Connection,
    ) -> std::result::Result<(), rusqlite::Error> {
        let mut stmt = conn.prepare("PRAGMA table_info(conversations)")?;
        let mut has_metadata_version = false;
        let mut has_metadata_blob_locator = false;
        let mut has_avatar_blob_locator = false;
        let mut has_avatar_bytes = false;
        let mut has_avatar_content_type = false;
        let column_names = stmt.query_map([], |row| row.get::<_, String>(1))?;

        for column_name in column_names {
            match column_name?.as_str() {
                "metadata_version" => has_metadata_version = true,
                "metadata_blob_locator" => has_metadata_blob_locator = true,
                "avatar_blob_locator" => has_avatar_blob_locator = true,
                "avatar_bytes" => has_avatar_bytes = true,
                "avatar_content_type" => has_avatar_content_type = true,
                _ => {}
            }
        }

        if !has_metadata_version {
            conn.execute(
                "ALTER TABLE conversations ADD COLUMN metadata_version INTEGER",
                [],
            )?;
        }
        if !has_metadata_blob_locator {
            conn.execute(
                "ALTER TABLE conversations ADD COLUMN metadata_blob_locator TEXT",
                [],
            )?;
        }
        if !has_avatar_blob_locator {
            conn.execute(
                "ALTER TABLE conversations ADD COLUMN avatar_blob_locator TEXT",
                [],
            )?;
        }
        if !has_avatar_bytes {
            conn.execute("ALTER TABLE conversations ADD COLUMN avatar_bytes BLOB", [])?;
        }
        if !has_avatar_content_type {
            conn.execute(
                "ALTER TABLE conversations ADD COLUMN avatar_content_type TEXT",
                [],
            )?;
        }
        Ok(())
    }

    fn ensure_conversations_sequencer_column(
        conn: &Connection,
    ) -> std::result::Result<(), rusqlite::Error> {
        let mut stmt = conn.prepare("PRAGMA table_info(conversations)")?;
        let mut has_sequencer_did = false;
        let column_names = stmt.query_map([], |row| row.get::<_, String>(1))?;

        for column_name in column_names {
            if column_name? == "sequencer_did" {
                has_sequencer_did = true;
            }
        }

        if !has_sequencer_did {
            conn.execute(
                "ALTER TABLE conversations ADD COLUMN sequencer_did TEXT",
                [],
            )?;
        }
        Ok(())
    }

    fn ensure_conversations_reset_pending_columns(
        conn: &Connection,
    ) -> std::result::Result<(), rusqlite::Error> {
        let mut stmt = conn.prepare("PRAGMA table_info(conversations)")?;
        let mut has_reset_new_group_id = false;
        let mut has_reset_generation = false;
        let mut has_reset_notified_at_ms = false;
        let column_names = stmt.query_map([], |row| row.get::<_, String>(1))?;

        for column_name in column_names {
            match column_name?.as_str() {
                "reset_new_group_id" => has_reset_new_group_id = true,
                "reset_generation" => has_reset_generation = true,
                "reset_notified_at_ms" => has_reset_notified_at_ms = true,
                _ => {}
            }
        }

        if !has_reset_new_group_id {
            conn.execute(
                "ALTER TABLE conversations ADD COLUMN reset_new_group_id TEXT",
                [],
            )?;
        }
        if !has_reset_generation {
            conn.execute(
                "ALTER TABLE conversations ADD COLUMN reset_generation INTEGER",
                [],
            )?;
        }
        if !has_reset_notified_at_ms {
            conn.execute(
                "ALTER TABLE conversations ADD COLUMN reset_notified_at_ms INTEGER",
                [],
            )?;
        }
        Ok(())
    }

    fn ensure_messages_delivery_status_column(
        conn: &Connection,
    ) -> std::result::Result<(), rusqlite::Error> {
        let mut stmt = conn.prepare("PRAGMA table_info(messages)")?;
        let mut has_delivery_status_json = false;
        let mut has_payload_json = false;
        let column_names = stmt.query_map([], |row| row.get::<_, String>(1))?;

        for column_name in column_names {
            match column_name?.as_str() {
                "delivery_status_json" => has_delivery_status_json = true,
                "payload_json" => has_payload_json = true,
                _ => {}
            }
        }

        if !has_delivery_status_json {
            conn.execute(
                "ALTER TABLE messages ADD COLUMN delivery_status_json TEXT",
                [],
            )?;
        }

        if !has_payload_json {
            conn.execute("ALTER TABLE messages ADD COLUMN payload_json TEXT", [])?;
        }

        Ok(())
    }

    /// Adopt a new MLS group id for a conversation after a server-initiated
    /// group reset (spec §8.5). catmos stays in the deferred-recovery
    /// architecture: the websocket handler flags `needs_rejoin` and sets
    /// `ConversationState::NeedsRejoin`; this method additionally rewrites
    /// `conversations.group_id` so the subsequent External Commit in the sync
    /// loop targets the new group instead of re-deriving the old one.
    pub fn update_conversation_group_id(
        &self,
        conversation_id: &str,
        new_group_id_hex: &str,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE conversations SET group_id = ?1 WHERE conversation_id = ?2",
            rusqlite::params![new_group_id_hex, conversation_id],
        )
        .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Rehydrate a `ConversationState::ResetPending` payload from the
    /// persisted columns (spec §8.5). Returns `Some(ResetPending { .. })`
    /// only when all three reset columns are non-NULL — partial rows are
    /// treated as "no payload" and yield `None`. Callers that need to
    /// repopulate the orchestrator's in-memory `conversation_states` map
    /// after restart should consult this helper.
    pub fn get_reset_pending(&self, conversation_id: &str) -> Option<ConversationState> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT reset_new_group_id, reset_generation, reset_notified_at_ms
             FROM conversations WHERE conversation_id = ?1",
            rusqlite::params![conversation_id],
            |row| {
                let new_group_id: Option<String> = row.get(0)?;
                let reset_generation: Option<i64> = row.get(1)?;
                let notified_at_ms: Option<i64> = row.get(2)?;
                Ok((new_group_id, reset_generation, notified_at_ms))
            },
        )
        .ok()
        .and_then(|(new_group_id, reset_generation, notified_at_ms)| {
            match (new_group_id, reset_generation, notified_at_ms) {
                (Some(new_group_id), Some(reset_generation), Some(notified_at_ms)) => {
                    Some(ConversationState::ResetPending {
                        new_group_id,
                        reset_generation: reset_generation as i32,
                        notified_at_ms,
                    })
                }
                _ => None,
            }
        })
    }

    /// Persist the decrypted `GroupMetadataV1` payload (as JSON) along with
    /// the version and blob locator that produced it. Avatars are persisted
    /// separately via [`update_avatar_bytes`] so a metadata-only update does
    /// not invalidate cached avatar bytes.
    pub fn update_metadata_json(
        &self,
        conversation_id: &str,
        metadata_json: &str,
        metadata_version: u64,
        metadata_blob_locator: &str,
        avatar_blob_locator: Option<&str>,
        avatar_content_type: Option<&str>,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE conversations
             SET metadata_json = ?1,
                 metadata_version = ?2,
                 metadata_blob_locator = ?3,
                 avatar_blob_locator = ?4,
                 avatar_content_type = COALESCE(?5, avatar_content_type)
             WHERE conversation_id = ?6",
            rusqlite::params![
                metadata_json,
                metadata_version as i64,
                metadata_blob_locator,
                avatar_blob_locator,
                avatar_content_type,
                conversation_id,
            ],
        )
        .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Persist decrypted avatar bytes alongside their MIME type so the
    /// SvelteKit frontend can render them as a `data:` URL without a second
    /// IPC round-trip per render.
    pub fn update_avatar_bytes(
        &self,
        conversation_id: &str,
        avatar_bytes: &[u8],
        content_type: Option<&str>,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE conversations
             SET avatar_bytes = ?1,
                 avatar_content_type = COALESCE(?2, avatar_content_type)
             WHERE conversation_id = ?3",
            rusqlite::params![avatar_bytes, content_type, conversation_id],
        )
        .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Read the cached metadata snapshot for a conversation (decrypted JSON +
    /// version + locator). Returns `None` only when the conversation row is
    /// missing; otherwise an all-`None`-fields snapshot indicates "no
    /// bootstrap has run yet for this conversation".
    pub fn get_metadata_snapshot(&self, conversation_id: &str) -> Option<LocalMetadataSnapshot> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT metadata_json, metadata_version, metadata_blob_locator
             FROM conversations WHERE conversation_id = ?1",
            rusqlite::params![conversation_id],
            |row| {
                Ok(LocalMetadataSnapshot {
                    metadata_json: row.get(0)?,
                    metadata_version: row.get(1)?,
                    metadata_blob_locator: row.get(2)?,
                })
            },
        )
        .ok()
    }

    /// Read raw avatar bytes + MIME type for a conversation. Returns `None`
    /// when no avatar has been bootstrapped (or has been cleared).
    pub fn get_avatar(&self, conversation_id: &str) -> Option<(Vec<u8>, Option<String>)> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT avatar_bytes, avatar_content_type
             FROM conversations WHERE conversation_id = ?1",
            rusqlite::params![conversation_id],
            |row| {
                let bytes: Option<Vec<u8>> = row.get(0)?;
                let ct: Option<String> = row.get(1)?;
                Ok(bytes.map(|b| (b, ct)))
            },
        )
        .ok()
        .flatten()
    }

    /// Persist a per-conversation WebSocket cursor (spec §7.1).
    pub fn set_ws_cursor(&self, conversation_id: &str, cursor: &str) {
        let conn = self.conn.lock().unwrap();
        let _ = conn.execute(
            "INSERT OR REPLACE INTO ws_cursors (conversation_id, cursor) VALUES (?1, ?2)",
            rusqlite::params![conversation_id, cursor],
        );
    }

    /// Load a persisted WebSocket cursor for a conversation.
    pub fn get_ws_cursor(&self, conversation_id: &str) -> Option<String> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT cursor FROM ws_cursors WHERE conversation_id = ?1",
            rusqlite::params![conversation_id],
            |row| row.get(0),
        )
        .ok()
    }
}

#[async_trait]
impl MLSStorageBackend for SqliteStorage {
    async fn ensure_conversation_exists(
        &self,
        user_did: &str,
        conversation_id: &str,
        group_id: &str,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO conversations (conversation_id, user_did, group_id)
             VALUES (?1, ?2, ?3)",
            rusqlite::params![conversation_id, user_did, group_id],
        )
        .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn update_join_info(
        &self,
        conversation_id: &str,
        user_did: &str,
        join_method: JoinMethod,
        join_epoch: u64,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let method_str = serde_json::to_string(&join_method)
            .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        conn.execute(
            "UPDATE conversations SET join_method = ?1, join_epoch = ?2
             WHERE conversation_id = ?3 AND user_did = ?4",
            rusqlite::params![method_str, join_epoch, conversation_id, user_did],
        )
        .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn get_conversation(
        &self,
        user_did: &str,
        conversation_id: &str,
    ) -> Result<Option<ConversationView>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT conversation_id, group_id, epoch, members_json, metadata_json, created_at, updated_at, sequencer_did
                 FROM conversations WHERE conversation_id = ?1 AND user_did = ?2",
            )
            .map_err(|e| OrchestratorError::Storage(e.to_string()))?;

        let result = stmt
            .query_row(rusqlite::params![conversation_id, user_did], |row| {
                let conversation_id: String = row.get(0)?;
                let group_id: String = row.get(1)?;
                let epoch: u64 = row.get(2)?;
                let members_json: String = row.get(3)?;
                let metadata_json: Option<String> = row.get(4)?;
                let created_at: Option<String> = row.get(5)?;
                let updated_at: Option<String> = row.get(6)?;
                let sequencer_did: Option<String> = row.get(7)?;

                let members: Vec<MemberView> =
                    serde_json::from_str(&members_json).unwrap_or_default();
                let metadata: Option<ConversationMetadata> =
                    metadata_json.and_then(|j| serde_json::from_str(&j).ok());
                let created = created_at.and_then(|s| s.parse().ok());
                let updated = updated_at.and_then(|s| s.parse().ok());

                Ok(ConversationView {
                    group_id,
                    conversation_id,
                    epoch,
                    members,
                    metadata,
                    created_at: created,
                    updated_at: updated,
                    sequencer_did,
                    canonical_state: None,
                })
            })
            .ok();

        Ok(result)
    }

    async fn list_conversations(&self, user_did: &str) -> Result<Vec<ConversationView>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT conversation_id, group_id, epoch, members_json, metadata_json, created_at, updated_at, sequencer_did
                 FROM conversations WHERE user_did = ?1",
            )
            .map_err(|e| OrchestratorError::Storage(e.to_string()))?;

        let rows = stmt
            .query_map(rusqlite::params![user_did], |row| {
                let conversation_id: String = row.get(0)?;
                let group_id: String = row.get(1)?;
                let epoch: u64 = row.get(2)?;
                let members_json: String = row.get(3)?;
                let metadata_json: Option<String> = row.get(4)?;
                let created_at: Option<String> = row.get(5)?;
                let updated_at: Option<String> = row.get(6)?;
                let sequencer_did: Option<String> = row.get(7)?;

                let members: Vec<MemberView> =
                    serde_json::from_str(&members_json).unwrap_or_default();
                let metadata = metadata_json.and_then(|j| serde_json::from_str(&j).ok());
                let created = created_at.and_then(|s| s.parse().ok());
                let updated = updated_at.and_then(|s| s.parse().ok());

                Ok(ConversationView {
                    group_id,
                    conversation_id,
                    epoch,
                    members,
                    metadata,
                    created_at: created,
                    updated_at: updated,
                    sequencer_did,
                    canonical_state: None,
                })
            })
            .map_err(|e| OrchestratorError::Storage(e.to_string()))?;

        let mut result = Vec::new();
        for row in rows {
            result.push(row.map_err(|e| OrchestratorError::Storage(e.to_string()))?);
        }
        Ok(result)
    }

    async fn delete_conversations(&self, user_did: &str, ids: &[&str]) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        for id in ids {
            conn.execute(
                "DELETE FROM conversations WHERE conversation_id = ?1 AND user_did = ?2",
                rusqlite::params![id, user_did],
            )
            .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        }
        Ok(())
    }

    async fn set_conversation_state(
        &self,
        conversation_id: &str,
        state: ConversationState,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let state_str =
            serde_json::to_string(&state).map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        conn.execute(
            "UPDATE conversations SET state = ?1 WHERE conversation_id = ?2
             AND state NOT IN ('\"Closed\"', '\"DeviceRemoved\"')",
            rusqlite::params![state_str, conversation_id],
        )
        .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn clear_device_removal_after_verified_welcome(&self, conversation_id: &str) -> Result<()> {
        let error = |error: rusqlite::Error| OrchestratorError::Storage(error.to_string());
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate).map_err(error)?;
        let count: i64 = tx.query_row("SELECT COUNT(*) FROM conversations WHERE conversation_id = ?1", [conversation_id], |row| row.get(0)).map_err(error)?;
        if count != 1 {
            return Err(OrchestratorError::Storage("Verified Welcome has no unambiguous conversation".into()));
        }
        let (state, target, notified): (String, Option<String>, Option<i64>) = tx.query_row(
            "SELECT state, reset_new_group_id, reset_notified_at_ms FROM conversations WHERE conversation_id = ?1",
            [conversation_id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        ).map_err(error)?;
        let state = if state == "Active" { ConversationState::Active } else {
            serde_json::from_str(&state).map_err(|error| OrchestratorError::Storage(error.to_string()))?
        };
        if matches!(state, ConversationState::Closed | ConversationState::ResetPending { .. })
            || target.is_some() || notified.is_some()
        {
            return Err(OrchestratorError::Storage("Newer lifecycle authority prevents Welcome activation".into()));
        }
        tx.execute("UPDATE conversations SET state = '\"Active\"', needs_rejoin = 0 WHERE conversation_id = ?1", [conversation_id]).map_err(error)?;
        tx.commit().map_err(error)?;
        Ok(())
    }

    async fn complete_account_exit(
        &self,
        conversation_id: &str,
        expected_group_id_hex: &str,
        expected_reset_generation: Option<i32>,
        terminal_epoch: u64,
        terminal_state: ConversationState,
    ) -> Result<bool> {
        if !matches!(terminal_state, ConversationState::Closed | ConversationState::DeviceRemoved)
            || catbird_mls::chat_v2::ids::CanonicalUuid::parse(conversation_id).is_err()
            || expected_group_id_hex.len() != 64
            || !expected_group_id_hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || terminal_epoch > 9_007_199_254_740_991
            || expected_reset_generation.is_some_and(|generation| generation <= 0)
        {
            return Err(OrchestratorError::Storage("Invalid account exit projection".into()));
        }
        let storage_error = |error: rusqlite::Error| OrchestratorError::Storage(error.to_string());
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(storage_error)?;
        // This callback has no account argument. Never choose between two
        // account-scoped rows sharing a CID, even if one happens to match.
        let count: i64 = tx.query_row(
            "SELECT COUNT(*) FROM conversations WHERE conversation_id = ?1",
            [conversation_id], |row| row.get(0),
        ).map_err(storage_error)?;
        if count != 1 { return Ok(false); }
        let (user_did, group_id, epoch, state, target, generation, notified, needs_rejoin):
            (String, String, u64, String, Option<String>, Option<i32>, Option<i64>, i32) =
            tx.query_row(
                "SELECT user_did, group_id, epoch, state, reset_new_group_id, reset_generation, reset_notified_at_ms, needs_rejoin
                 FROM conversations WHERE conversation_id = ?1",
                [conversation_id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?)),
            ).map_err(storage_error)?;
        if generation.is_some_and(|generation| generation < 0) { return Ok(false); }
        let state: ConversationState = if state == "Active" {
            ConversationState::Active
        } else {
            serde_json::from_str(&state).map_err(|error| OrchestratorError::Storage(error.to_string()))?
        };
        // Closed is permanent. DeviceRemoved only describes this device's
        // access: a new, durably accepted account exit can still advance it.
        // Native validates that proof and its incarnation before this callback.
        let matches = if state == ConversationState::Closed {
            state == terminal_state && group_id == expected_group_id_hex && epoch == terminal_epoch
                && target.is_none() && notified.is_none()
                && needs_rejoin == 0
                && expected_reset_generation.is_none_or(|expected| generation == Some(expected))
        } else {
            match (&state, expected_reset_generation) {
                (ConversationState::ResetPending { new_group_id, reset_generation, notified_at_ms }, Some(expected)) => {
                    new_group_id == expected_group_id_hex && *reset_generation == expected
                        && target.as_deref() == Some(expected_group_id_hex)
                        && generation == Some(expected) && notified == Some(*notified_at_ms)
                        && (group_id != expected_group_id_hex || epoch <= terminal_epoch)
                }
                (ConversationState::ResetPending { .. }, None) => false,
                (ConversationState::DeviceRemoved, Some(expected)) => {
                    generation == Some(expected) && target.is_none() && notified.is_none()
                        && group_id == expected_group_id_hex && epoch == terminal_epoch
                        && state == terminal_state && needs_rejoin == 0
                }
                (_, Some(_)) => false,
                (_, None) => group_id == expected_group_id_hex && epoch <= terminal_epoch
                    && target.is_none() && notified.is_none(),
            }
        };
        if !matches { return Ok(false); }
        if state == terminal_state && group_id == expected_group_id_hex && epoch == terminal_epoch
            && target.is_none() && notified.is_none() && needs_rejoin == 0 {
            return Ok(true);
        }
        let state = serde_json::to_string(&terminal_state)
            .map_err(|error| OrchestratorError::Storage(error.to_string()))?;
        tx.execute(
            "UPDATE conversations SET group_id = ?1, epoch = ?2, state = ?3,
             needs_rejoin = 0, reset_new_group_id = NULL, reset_notified_at_ms = NULL
             WHERE conversation_id = ?4 AND user_did = ?5",
            rusqlite::params![expected_group_id_hex, terminal_epoch, state, conversation_id, user_did],
        ).map_err(storage_error)?;
        // reset_generation is the retained high-water; message/MLS rows are
        // untouched. Native durable evidence precedes this projection.
        tx.commit().map_err(storage_error)?;
        Ok(true)
    }

    /// Read the persisted conversation state (spec §8.2). The `state` column
    /// stores a JSON-serialized `ConversationState`, so we round-trip through
    /// serde and the full payload (including `ResetPending {..}`) survives.
    /// Returns `Ok(None)` when the row is missing or the column is NULL/empty.
    async fn get_conversation_state(
        &self,
        conversation_id: &str,
    ) -> Result<Option<ConversationState>> {
        let conn = self.conn.lock().unwrap();
        let state_str: Option<String> = conn
            .query_row(
                "SELECT state FROM conversations WHERE conversation_id = ?1",
                rusqlite::params![conversation_id],
                |row| row.get::<_, Option<String>>(0),
            )
            .ok()
            .flatten();
        let Some(s) = state_str else {
            return Ok(None);
        };
        if s.is_empty() {
            return Ok(None);
        }
        // Fresh installs historically used the SQL default `Active` before
        // state persistence was JSON-backed. Treat that legacy value as the
        // canonical enum so callers can still apply lifecycle freshness gates
        // without accepting an unparseable state as proof of currency.
        if s == "Active" {
            return Ok(Some(ConversationState::Active));
        }
        serde_json::from_str::<ConversationState>(&s)
            .map(Some)
            .map_err(|e| OrchestratorError::Storage(e.to_string()))
    }

    async fn mark_needs_rejoin(&self, conversation_id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE conversations SET needs_rejoin = 1 WHERE conversation_id = ?1
             AND state NOT IN ('\"Closed\"', '\"DeviceRemoved\"')",
            rusqlite::params![conversation_id],
        )
        .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn needs_rejoin(&self, conversation_id: &str) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let val: i32 = conn
            .query_row(
                "SELECT needs_rejoin FROM conversations WHERE conversation_id = ?1",
                rusqlite::params![conversation_id],
                |row| row.get(0),
            )
            .unwrap_or(0);
        Ok(val != 0)
    }

    async fn clear_rejoin_flag(&self, conversation_id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE conversations SET needs_rejoin = 0 WHERE conversation_id = ?1",
            rusqlite::params![conversation_id],
        )
        .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Persist the RESET_PENDING payload (spec §8.5) so a `groupReset`
    /// observed before a restart survives the restart and the deferred
    /// recovery loop can resume Phase 1 against the new group id.
    async fn mark_reset_pending(
        &self,
        conversation_id: &str,
        new_group_id_hex: &str,
        reset_generation: i32,
        notified_at_ms: i64,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE conversations
             SET reset_new_group_id = ?1,
                 reset_generation = ?2,
                 reset_notified_at_ms = ?3
             WHERE conversation_id = ?4",
            rusqlite::params![
                new_group_id_hex,
                reset_generation as i64,
                notified_at_ms,
                conversation_id,
            ],
        )
        .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn clear_reset_pending_for_delete(
        &self,
        conversation_id: &str,
        expected_generation: i32,
    ) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE conversations
             SET reset_new_group_id = NULL,
                 reset_generation = NULL,
                 reset_notified_at_ms = NULL
             WHERE conversation_id = ?1 AND reset_generation = ?2",
            rusqlite::params![conversation_id, expected_generation],
        )
        .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        Ok(true)
    }

    async fn set_conversation_sequencer(
        &self,
        conversation_id: &str,
        sequencer_did: &str,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE conversations SET sequencer_did = ?1 WHERE conversation_id = ?2",
            rusqlite::params![sequencer_did, conversation_id],
        )
        .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Layer 3 quarantine persistence (spec MLS robustness Layer 3). Mirrors
    /// `mark_reset_pending`: the orchestrator's `enter_quarantine` writes the
    /// JSON-serialized `ConversationState::Quarantined` into `state` (via
    /// `set_conversation_state`) AND calls this hook for the dedicated
    /// columns, so reads (incl. `get_conversation_state`) round-trip through
    /// the existing JSON path while the columns are available for direct UI
    /// queries via `get_quarantine_state` without re-parsing JSON.
    async fn mark_quarantined(
        &self,
        conversation_id: &str,
        reason_tag: &str,
        since_ms: i64,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE conversations
             SET quarantine_reason_tag = ?1,
                 quarantine_since_ms = ?2
             WHERE conversation_id = ?3",
            rusqlite::params![reason_tag, since_ms, conversation_id],
        )
        .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn clear_quarantine(&self, conversation_id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE conversations
             SET quarantine_reason_tag = NULL,
                 quarantine_since_ms = NULL
             WHERE conversation_id = ?1",
            rusqlite::params![conversation_id],
        )
        .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn store_message(&self, message: &Message) -> Result<()> {
        let delivery_status_json = message
            .delivery_status
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|e| OrchestratorError::Storage(e.to_string()))?;

        let ctx = self.mls_context_snapshot().ok_or_else(|| {
            OrchestratorError::Storage(
                "store_message: missing MLS context for message encryption".to_string(),
            )
        })?;
        let body = CanonicalMessageBody {
            text: &message.text,
            payload_json: message.payload_json.as_deref(),
        };
        let plaintext = serde_json::to_vec(&body).map_err(|e| {
            OrchestratorError::Storage(format!("canonical body serialization failed: {e}"))
        })?;
        let encrypted = ctx
            .encrypt_message_payload(message.conversation_id.clone(), plaintext)
            .map_err(|e| {
                OrchestratorError::Storage(format!("encrypt_message_payload failed: {e:?}"))
            })?;
        let prev_hmac = self.last_entry_hmac(&message.conversation_id);
        let entry_hmac = ctx
            .compute_message_hmac(
                message.conversation_id.clone(),
                prev_hmac,
                message.id.clone(),
                encrypted.clone(),
            )
            .map_err(|e| {
                OrchestratorError::Storage(format!("compute_message_hmac failed: {e:?}"))
            })?;

        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO messages (id, conversation_id, sender_did, text, timestamp, epoch, sequence_number, is_own, delivery_status_json, payload_json, payload_encrypted, entry_hmac, payload_key_version)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            rusqlite::params![
                message.id,
                message.conversation_id,
                message.sender_did,
                "",
                message.timestamp.to_rfc3339(),
                message.epoch,
                message.sequence_number,
                message.is_own as i32,
                delivery_status_json,
                Option::<String>::None,
                encrypted,
                entry_hmac,
                PAYLOAD_KEY_VERSION_V1,
            ],
        )
        .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn get_messages(
        &self,
        conversation_id: &str,
        limit: u32,
        before_sequence: Option<u64>,
    ) -> Result<Vec<Message>> {
        let mls_ctx = self.mls_context_snapshot();
        let conn = self.conn.lock().unwrap();
        let mut result = Vec::new();

        if let Some(before) = before_sequence {
            let mut stmt = conn
                .prepare(
                    "SELECT id, conversation_id, sender_did, text, timestamp, epoch, sequence_number, is_own, delivery_status_json, payload_json, payload_encrypted
                     FROM messages WHERE conversation_id = ?1 AND sequence_number < ?2 AND COALESCE(is_tombstone, 0) = 0
                     ORDER BY sequence_number DESC LIMIT ?3",
                )
                .map_err(|e| OrchestratorError::Storage(e.to_string()))?;

            let rows = stmt
                .query_map(rusqlite::params![conversation_id, before, limit], |row| {
                    row_to_message(row, mls_ctx.as_deref())
                })
                .map_err(|e| OrchestratorError::Storage(e.to_string()))?;

            for row in rows {
                result.push(row.map_err(|e| OrchestratorError::Storage(e.to_string()))?);
            }
        } else {
            let mut stmt = conn
                .prepare(
                    "SELECT id, conversation_id, sender_did, text, timestamp, epoch, sequence_number, is_own, delivery_status_json, payload_json, payload_encrypted
                     FROM messages WHERE conversation_id = ?1 AND COALESCE(is_tombstone, 0) = 0
                     ORDER BY sequence_number DESC LIMIT ?2",
                )
                .map_err(|e| OrchestratorError::Storage(e.to_string()))?;

            let rows = stmt
                .query_map(rusqlite::params![conversation_id, limit], |row| {
                    row_to_message(row, mls_ctx.as_deref())
                })
                .map_err(|e| OrchestratorError::Storage(e.to_string()))?;

            for row in rows {
                result.push(row.map_err(|e| OrchestratorError::Storage(e.to_string()))?);
            }
        }

        result.reverse();
        Ok(result)
    }

    async fn message_exists(&self, message_id: &str) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let count: i32 = conn
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE id = ?1",
                rusqlite::params![message_id],
                |row| row.get(0),
            )
            .unwrap_or(0);
        Ok(count > 0)
    }

    async fn get_sync_cursor(&self, user_did: &str) -> Result<SyncCursor> {
        let conn = self.conn.lock().unwrap();
        let cursor = conn
            .query_row(
                "SELECT conversations_cursor, messages_cursor FROM sync_cursors WHERE user_did = ?1",
                rusqlite::params![user_did],
                |row| {
                    Ok(SyncCursor {
                        conversations_cursor: row.get(0)?,
                        messages_cursor: row.get(1)?,
                    })
                },
            )
            .unwrap_or_default();
        Ok(cursor)
    }

    async fn set_sync_cursor(&self, user_did: &str, cursor: &SyncCursor) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO sync_cursors (user_did, conversations_cursor, messages_cursor)
             VALUES (?1, ?2, ?3)",
            rusqlite::params![
                user_did,
                cursor.conversations_cursor,
                cursor.messages_cursor,
            ],
        )
        .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn set_group_state(&self, state: &GroupState) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let members_json = serde_json::to_string(&state.members)
            .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        conn.execute(
            "INSERT OR REPLACE INTO group_states (group_id, conversation_id, epoch, members_json)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                state.group_id,
                state.conversation_id,
                state.epoch,
                members_json
            ],
        )
        .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn get_group_state(&self, group_id: &str) -> Result<Option<GroupState>> {
        let conn = self.conn.lock().unwrap();
        let result = conn
            .query_row(
                "SELECT group_id, conversation_id, epoch, members_json FROM group_states WHERE group_id = ?1",
                rusqlite::params![group_id],
                |row| {
                    let group_id: String = row.get(0)?;
                    let conversation_id: String = row.get(1)?;
                    let epoch: u64 = row.get(2)?;
                    let members_json: String = row.get(3)?;
                    let members: Vec<String> =
                        serde_json::from_str(&members_json).unwrap_or_default();
                    Ok(GroupState {
                        group_id,
                        conversation_id,
                        epoch,
                        members,
                    })
                },
            )
            .ok();
        Ok(result)
    }

    async fn delete_group_state(&self, group_id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM group_states WHERE group_id = ?1",
            rusqlite::params![group_id],
        )
        .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        Ok(())
    }

    // -- Pending Messages (self-echo dedup across restarts, spec §5) --

    async fn store_pending_message(&self, conversation_id: &str, message_id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().timestamp();
        conn.execute(
            "INSERT OR IGNORE INTO pending_messages (message_id, conversation_id, created_at)
             VALUES (?1, ?2, ?3)",
            rusqlite::params![message_id, conversation_id, now],
        )
        .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn remove_pending_message(&self, message_id: &str) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let rows = conn
            .execute(
                "DELETE FROM pending_messages WHERE message_id = ?1",
                rusqlite::params![message_id],
            )
            .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        Ok(rows > 0)
    }

    async fn get_recovery_state(&self) -> Result<PersistedRecoveryState> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT conversation_id, failed_rejoin_count, last_attempt_at_ms, quarantined_until_ms
                 FROM recovery_backoffs",
            )
            .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        let rows = stmt
            .query_map([], |row| {
                Ok(PersistedRecoveryBackoff {
                    conversation_id: row.get(0)?,
                    failed_rejoin_count: row.get(1)?,
                    last_attempt_at_ms: row.get(2)?,
                    quarantined_until_ms: row.get(3)?,
                })
            })
            .map_err(|e| OrchestratorError::Storage(e.to_string()))?;

        let mut entries = Vec::new();
        for r in rows {
            entries.push(r.map_err(|e| OrchestratorError::Storage(e.to_string()))?);
        }

        let last_global_rejoin_attempt_at_ms = conn
            .query_row(
                "SELECT val_int FROM recovery_globals WHERE key = 'last_global_rejoin_attempt_at_ms'",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| OrchestratorError::Storage(e.to_string()))?;

        Ok(PersistedRecoveryState {
            entries,
            last_global_rejoin_attempt_at_ms,
        })
    }

    async fn set_recovery_backoff(&self, entry: &PersistedRecoveryBackoff) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO recovery_backoffs
             (conversation_id, failed_rejoin_count, last_attempt_at_ms, quarantined_until_ms)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                entry.conversation_id,
                entry.failed_rejoin_count,
                entry.last_attempt_at_ms,
                entry.quarantined_until_ms,
            ],
        )
        .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn clear_recovery_backoff(&self, conversation_id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM recovery_backoffs WHERE conversation_id = ?1",
            rusqlite::params![conversation_id],
        )
        .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn set_last_global_rejoin_attempt_at(&self, at_ms: i64) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO recovery_globals (key, val_int)
             VALUES ('last_global_rejoin_attempt_at_ms', ?1)",
            rusqlite::params![at_ms],
        )
        .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        Ok(())
    }

    fn implemented_optional_methods(&self) -> &'static [&'static str] {
        &[
            "get_conversation_state",
            "complete_account_exit",
            "mark_reset_pending",
            "clear_reset_pending_for_delete",
            "set_conversation_sequencer",
            "mark_quarantined",
            "clear_quarantine",
            "store_pending_message",
            "remove_pending_message",
            "get_recovery_state",
            "set_recovery_backoff",
            "clear_recovery_backoff",
            "set_last_global_rejoin_attempt_at",
        ]
    }
}

fn row_to_message(row: &rusqlite::Row, mls_ctx: Option<&MLSContext>) -> rusqlite::Result<Message> {
    let id: String = row.get(0)?;
    let conversation_id: String = row.get(1)?;
    let sender_did: String = row.get(2)?;
    let _legacy_text: String = row.get(3)?;
    let timestamp_str: String = row.get(4)?;
    let epoch: u64 = row.get(5)?;
    let sequence_number: u64 = row.get(6)?;
    let is_own: i32 = row.get(7)?;
    let delivery_status_json: Option<String> = row.get(8)?;
    let _legacy_payload_json: Option<String> = row.get(9)?;
    let payload_encrypted: Option<Vec<u8>> = row.get(10)?;

    let timestamp = timestamp_str
        .parse::<chrono::DateTime<chrono::Utc>>()
        .unwrap_or_else(|_| chrono::Utc::now());
    let delivery_status =
        delivery_status_json.and_then(|json| match serde_json::from_str::<DeliveryStatus>(&json) {
            Ok(status) => Some(status),
            Err(err) => {
                tracing::warn!(
                    message_id = %id,
                    error = %err,
                    "Failed to deserialize delivery_status_json; defaulting to None"
                );
                None
            }
        });

    let ctx = mls_ctx.ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            10,
            rusqlite::types::Type::Blob,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "missing MLS context for encrypted message read",
            )),
        )
    })?;

    let wire = payload_encrypted.filter(|b| !b.is_empty()).ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            10,
            rusqlite::types::Type::Blob,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "missing or empty encrypted message payload",
            )),
        )
    })?;

    let plaintext = ctx
        .decrypt_message_payload(conversation_id.clone(), wire)
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(
                10,
                rusqlite::types::Type::Blob,
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("decrypt_message_payload failed: {e:?}"),
                )),
            )
        })?;

    let body = serde_json::from_slice::<CanonicalMessageBodyOwned>(&plaintext).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(10, rusqlite::types::Type::Blob, Box::new(e))
    })?;

    Ok(Message {
        id,
        conversation_id,
        sender_did,
        text: body.text,
        timestamp,
        epoch,
        sequence_number,
        is_own: is_own != 0,
        delivery_status,
        payload_json: body.payload_json,
    })
}

#[cfg(test)]
mod field_encryption_tests {
    use super::*;
    use catbird_mls::KeychainAccess;
    use catbird_mls::MLSError;
    use chrono::Utc;
    use std::collections::HashMap;
    use std::sync::Mutex as StdMutex;

    struct InMemoryKeychain {
        inner: StdMutex<HashMap<String, Vec<u8>>>,
    }

    impl InMemoryKeychain {
        fn new() -> Self {
            Self {
                inner: StdMutex::new(HashMap::new()),
            }
        }
    }

    #[async_trait::async_trait]
    impl KeychainAccess for InMemoryKeychain {
        async fn read(&self, key: String) -> std::result::Result<Option<Vec<u8>>, MLSError> {
            Ok(self.inner.lock().unwrap().get(&key).cloned())
        }
        async fn write(&self, key: String, value: Vec<u8>) -> std::result::Result<(), MLSError> {
            self.inner.lock().unwrap().insert(key, value);
            Ok(())
        }
        async fn delete(&self, key: String) -> std::result::Result<(), MLSError> {
            self.inner.lock().unwrap().remove(&key);
            Ok(())
        }
    }

    const TEST_DB_KEY: &str = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

    fn new_temp_storage() -> (tempfile::TempDir, SqliteStorage) {
        let tmp = tempfile::tempdir().expect("temp dir");
        let db_path = tmp.path().join("catmos-test.db");
        let storage = SqliteStorage::create_new(db_path.to_str().unwrap(), TEST_DB_KEY)
            .expect("open SqliteStorage");
        (tmp, storage)
    }

    #[test]
    fn message_field_columns_and_migration_row_exist() {
        let (_tmp, storage) = new_temp_storage();
        let conn = storage.conn.lock().unwrap();

        let mut stmt = conn.prepare("PRAGMA table_info(messages)").unwrap();
        let cols: std::collections::HashSet<String> = stmt
            .query_map([], |r| r.get::<_, String>(1))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();
        for required in &[
            "payload_encrypted",
            "entry_hmac",
            "payload_key_version",
            "is_tombstone",
            "deleted_at",
        ] {
            assert!(
                cols.contains(*required),
                "missing required column on messages: {}",
                required
            );
        }

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM migration_status WHERE name = 'MLSMessageFieldMigrationV1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "MLSMessageFieldMigrationV1 row should be present");
    }

    #[tokio::test]
    async fn store_message_fails_closed_without_mls_context() {
        let (_tmp, storage) = new_temp_storage();
        let now = Utc::now();
        let msg = Message {
            id: "msg-1".into(),
            conversation_id: "conv-1".into(),
            sender_did: "did:plc:sender".into(),
            text: "hello bootstrap".into(),
            timestamp: now,
            epoch: 0,
            sequence_number: 1,
            is_own: true,
            delivery_status: None,
            payload_json: None,
        };
        // Without MLS context bound, store_message MUST fail closed
        assert!(storage.store_message(&msg).await.is_err());
    }

    #[tokio::test]
    async fn conversation_sequencer_did_round_trips() {
        let (_tmp, storage) = new_temp_storage();
        let user_did = "did:plc:alice";
        let conversation_id = "conv-sequencer";
        let group_id = "group-sequencer";
        let sequencer_did = "did:web:ds-b.example";

        storage
            .ensure_conversation_exists(user_did, conversation_id, group_id)
            .await
            .expect("create conversation");
        storage
            .set_conversation_sequencer(conversation_id, sequencer_did)
            .await
            .expect("persist sequencer");
        assert!(
            storage
                .implemented_optional_methods()
                .contains(&"set_conversation_sequencer"),
            "storage capabilities should report sequencer persistence"
        );

        let got = storage
            .get_conversation(user_did, conversation_id)
            .await
            .expect("load conversation")
            .expect("conversation exists");
        assert_eq!(got.sequencer_did.as_deref(), Some(sequencer_did));

        let listed = storage
            .list_conversations(user_did)
            .await
            .expect("list conversations");
        let listed = listed
            .into_iter()
            .find(|c| c.conversation_id == conversation_id)
            .expect("listed conversation");
        assert_eq!(listed.sequencer_did.as_deref(), Some(sequencer_did));
    }

    #[tokio::test]
    async fn message_round_trip_with_field_encryption() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let storage_db = tmp.path().join("catmos-test.db");
        let mls_db = tmp.path().join("mls-test.db");

        let storage = SqliteStorage::create_new(storage_db.to_str().unwrap(), TEST_DB_KEY)
            .expect("open SqliteStorage");

        let keychain: Box<dyn KeychainAccess> = Box::new(InMemoryKeychain::new());
        let mls_ctx = catbird_mls::MLSContext::new(
            mls_db.to_string_lossy().to_string(),
            TEST_DB_KEY.to_string(),
            keychain,
        )
        .expect("construct MLSContext");
        mls_ctx
            .set_content_root_key(vec![0x42u8; 32])
            .expect("set content root key");
        storage.set_mls_context(mls_ctx.clone());

        let now = Utc::now();
        let msg = Message {
            id: "msg-rt".into(),
            conversation_id: "conv-rt".into(),
            sender_did: "did:plc:sender".into(),
            text: "round-trip body".into(),
            timestamp: now,
            epoch: 0,
            sequence_number: 1,
            is_own: true,
            delivery_status: None,
            payload_json: Some(
                r#"{"version":1,"messageType":"text","text":"round-trip body"}"#.into(),
            ),
        };
        storage.store_message(&msg).await.expect("store");

        // The encrypted column and HMAC tag must be persisted; the legacy
        // text column should hold an empty string (NOT NULL constraint).
        {
            let conn = storage.conn.lock().unwrap();
            let (payload_encrypted, entry_hmac, text, payload_key_version): (
                Option<Vec<u8>>,
                Option<Vec<u8>>,
                String,
                Option<i64>,
            ) = conn
                .query_row(
                    "SELECT payload_encrypted, entry_hmac, text, payload_key_version FROM messages WHERE id = 'msg-rt'",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .unwrap();
            assert!(
                payload_encrypted
                    .as_ref()
                    .map(|b| !b.is_empty())
                    .unwrap_or(false),
                "payload_encrypted must be populated"
            );
            assert!(
                entry_hmac.as_ref().map(|b| !b.is_empty()).unwrap_or(false),
                "entry_hmac must be populated"
            );
            assert_eq!(
                text, "",
                "legacy text column should be empty for sealed rows"
            );
            assert_eq!(payload_key_version, Some(1));
        }

        // Read back through the public API — should decrypt and restore the
        // original text + payload_json.
        let got = storage
            .get_messages("conv-rt", 10, None)
            .await
            .expect("read");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].text, "round-trip body");
        assert_eq!(
            got[0].payload_json.as_deref(),
            Some(r#"{"version":1,"messageType":"text","text":"round-trip body"}"#)
        );
    }
}

#[cfg(test)]
mod storage_cutover_tests {
    use super::*;
    use std::fs;

    #[tokio::test(flavor = "multi_thread")]
    async fn clean_account_storage_fresh_creation_and_reopen() {
        use catbird_mls::orchestrator::credentials::CredentialStore;
        let store = MemoryDbKeyStore::new();
        let test_service = "catmos-test";
        let tmp = tempfile::tempdir().unwrap();
        let did = "did:plc:account-test-user";
        let account_id = crate::keys::derive_account_id(did);

        let _ = crate::credentials::KeyringCredentialStore::delete_exact_account_credentials(did);
        let _ = crate::keychain::KeyringKeychainAccess::reset_account_signer_slots(
            &account_id,
            tmp.path(),
        );

        let app_db_path = tmp.path().join(app_db_file_name(&account_id));
        let marker_file = account_marker_path(tmp.path(), &account_id);

        assert!(!app_db_path.exists());
        assert!(!marker_file.exists());

        // First open: creates keys, DBs, content root, and marker
        let (storage, mls_ctx, _key, lock) =
            open_clean_account_storage_with_store(tmp.path(), did, test_service, &store)
                .expect("first open should succeed");
        assert!(app_db_path.exists());
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

        let cred_store = crate::credentials::KeyringCredentialStore::try_new().unwrap();
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
        drop(lock);

        // Second open: reopens existing valid account storage
        let (storage2, mls_ctx2, _key2, lock2) =
            open_clean_account_storage_with_store(tmp.path(), did, test_service, &store)
                .expect("reopen should succeed");
        storage2.validate().expect("reopened DB must be valid");
        let _ = mls_ctx2.flush_and_prepare_close();
        drop(storage2);
        drop(mls_ctx2);
        drop(lock2);

        let _ = crate::credentials::KeyringCredentialStore::delete_exact_account_credentials(did);
        let _ = crate::keychain::KeyringKeychainAccess::reset_account_signer_slots(
            &account_id,
            tmp.path(),
        );
    }

    #[tokio::test]
    async fn clean_account_storage_reset_and_legacy_isolation() {
        let store = MemoryDbKeyStore::new();
        let test_service = "catmos-test";
        let tmp = tempfile::tempdir().unwrap();
        let did = "did:plc:reset-test-user";
        let account_id = crate::keys::derive_account_id(did);

        // Set up legacy sentinels
        let legacy_db = tmp.path().join("catmos.db");
        fs::write(&legacy_db, b"legacy-catmos-db-sentinel").unwrap();
        let legacy_mls_dir = tmp.path().join("mls-state");
        fs::create_dir_all(&legacy_mls_dir).unwrap();
        let legacy_mls_db = legacy_mls_dir.join("mls.db");
        fs::write(&legacy_mls_db, b"legacy-mls-db-sentinel").unwrap();

        // Create account storage
        let (storage, mls_ctx, _key, lock) =
            open_clean_account_storage_with_store(tmp.path(), did, test_service, &store).unwrap();
        let app_db_path = tmp.path().join(app_db_file_name(&account_id));
        let marker_file = account_marker_path(tmp.path(), &account_id);
        let content_key_path = crate::keys::content_root_key_path(tmp.path(), &account_id);

        assert!(app_db_path.exists());
        assert!(marker_file.exists());
        assert!(content_key_path.exists());
        drop(lock);
        // Perform explicit reset
        reset_account_storage_with_store(
            tmp.path(),
            did,
            Some(storage),
            Some(&mls_ctx),
            test_service,
            &store,
        )
        .await
        .expect("reset should succeed");

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
    #[tokio::test]
    async fn account_exit_cas_retires_only_exact_reset_and_preserves_history() {
        let (tmp, storage) = new_temp_storage();
        let old = "11".repeat(32);
        let target = "22".repeat(32);
        storage.ensure_conversation_exists("did:plc:alice", "9cf78d05-d9e1-4a20-b501-80e6d3d1b764", &old).await.unwrap();
        let reset = ConversationState::ResetPending {
            new_group_id: target.clone(), reset_generation: 4, notified_at_ms: 123,
        };
        storage.set_conversation_state("9cf78d05-d9e1-4a20-b501-80e6d3d1b764", reset.clone()).await.unwrap();
        storage.mark_reset_pending("9cf78d05-d9e1-4a20-b501-80e6d3d1b764", &target, 4, 123).await.unwrap();
        storage.mark_needs_rejoin("9cf78d05-d9e1-4a20-b501-80e6d3d1b764").await.unwrap();
        {
            let conn = storage.conn.lock().unwrap();
            conn.execute("INSERT INTO messages (id, conversation_id, sender_did, text, timestamp, epoch, sequence_number, is_own, payload_encrypted, entry_hmac)
                VALUES ('retained', '9cf78d05-d9e1-4a20-b501-80e6d3d1b764', 'did:plc:alice', '', '2026-09-05T00:00:00.000Z', 3, 7, 1, x'010203', x'040506')", []).unwrap();
        }
        assert!(!storage.complete_account_exit("9cf78d05-d9e1-4a20-b501-80e6d3d1b764", &target, Some(3), 5, ConversationState::Closed).await.unwrap());
        assert!(!storage.complete_account_exit("9cf78d05-d9e1-4a20-b501-80e6d3d1b764", &old, Some(4), 5, ConversationState::Closed).await.unwrap());
        assert!(!storage.complete_account_exit("9cf78d05-d9e1-4a20-b501-80e6d3d1b764", &target, None, 5, ConversationState::Closed).await.unwrap());
        assert_eq!(storage.get_conversation_state("9cf78d05-d9e1-4a20-b501-80e6d3d1b764").await.unwrap(), Some(reset));
        {
            let conn = storage.conn.lock().unwrap();
            conn.execute("UPDATE conversations SET group_id = ?1, epoch = 20", [&target]).unwrap();
        }
        assert!(!storage.complete_account_exit("9cf78d05-d9e1-4a20-b501-80e6d3d1b764", &target, Some(4), 5, ConversationState::Closed).await.unwrap());
        {
            let conn = storage.conn.lock().unwrap();
            conn.execute("UPDATE conversations SET group_id = ?1, epoch = 3", [&old]).unwrap();
        }
        assert!(storage.complete_account_exit("9cf78d05-d9e1-4a20-b501-80e6d3d1b764", &target, Some(4), 5, ConversationState::Closed).await.unwrap());
        drop(storage);
        let storage = SqliteStorage::open_existing(tmp.path().join("catmos-test.db").to_str().unwrap(), TEST_DB_KEY).unwrap();
        assert!(storage.complete_account_exit("9cf78d05-d9e1-4a20-b501-80e6d3d1b764", &target, Some(4), 5, ConversationState::Closed).await.unwrap());
        assert!(!storage.complete_account_exit("9cf78d05-d9e1-4a20-b501-80e6d3d1b764", &target, Some(5), 5, ConversationState::Closed).await.unwrap());
        assert!(!storage.complete_account_exit("9cf78d05-d9e1-4a20-b501-80e6d3d1b764", &target, Some(4), 4, ConversationState::Closed).await.unwrap());
        assert!(!storage.complete_account_exit("9cf78d05-d9e1-4a20-b501-80e6d3d1b764", &target, Some(4), 5, ConversationState::DeviceRemoved).await.unwrap());
        assert_eq!(storage.get_conversation_state("9cf78d05-d9e1-4a20-b501-80e6d3d1b764").await.unwrap(), Some(ConversationState::Closed));
        assert!(!storage.needs_rejoin("9cf78d05-d9e1-4a20-b501-80e6d3d1b764").await.unwrap());
        let conn = storage.conn.lock().unwrap();
        let proof: (String, i64, Option<String>, Option<i64>, i64) = conn.query_row(
            "SELECT group_id, reset_generation, reset_new_group_id, reset_notified_at_ms, epoch FROM conversations WHERE conversation_id = '9cf78d05-d9e1-4a20-b501-80e6d3d1b764'", [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        ).unwrap();
        assert_eq!(proof, (target, 4, None, None, 5));
        let history: (Vec<u8>, Vec<u8>) = conn.query_row(
            "SELECT payload_encrypted, entry_hmac FROM messages WHERE id = 'retained'", [], |row| Ok((row.get(0)?, row.get(1)?)),
        ).unwrap();
        assert_eq!(history, (vec![1, 2, 3], vec![4, 5, 6]));
    }

    #[tokio::test]
    async fn account_exit_cas_fences_ambiguity_and_preserves_old_reset_high_water() {
        let (_tmp, storage) = new_temp_storage();
        let group = "33".repeat(32);
        storage.ensure_conversation_exists("did:plc:alice", "9cf78d05-d9e1-4a20-b501-80e6d3d1b764", &group).await.unwrap();
        {
            let conn = storage.conn.lock().unwrap();
            conn.execute("UPDATE conversations SET reset_generation = 9, epoch = 12", []).unwrap();
        }
        assert!(!storage.complete_account_exit("9cf78d05-d9e1-4a20-b501-80e6d3d1b764", &group, None, 11, ConversationState::DeviceRemoved).await.unwrap());
        assert!(storage.complete_account_exit("9cf78d05-d9e1-4a20-b501-80e6d3d1b764", &group, None, 12, ConversationState::DeviceRemoved).await.unwrap());
        assert!(storage.complete_account_exit("9cf78d05-d9e1-4a20-b501-80e6d3d1b764", &group, None, 12, ConversationState::DeviceRemoved).await.unwrap());
        assert!(!storage.complete_account_exit("9cf78d05-d9e1-4a20-b501-80e6d3d1b764", &group, Some(9), 13, ConversationState::DeviceRemoved).await.unwrap());
        assert!(!storage.complete_account_exit("9cf78d05-d9e1-4a20-b501-80e6d3d1b764", &group, Some(9), 12, ConversationState::Closed).await.unwrap());
        storage.set_conversation_state("9cf78d05-d9e1-4a20-b501-80e6d3d1b764", ConversationState::Active).await.unwrap();
        assert_eq!(storage.get_conversation_state("9cf78d05-d9e1-4a20-b501-80e6d3d1b764").await.unwrap(), Some(ConversationState::DeviceRemoved));
        storage.clear_device_removal_after_verified_welcome("9cf78d05-d9e1-4a20-b501-80e6d3d1b764").await.unwrap();
        assert_eq!(storage.get_conversation_state("9cf78d05-d9e1-4a20-b501-80e6d3d1b764").await.unwrap(), Some(ConversationState::Active));
        assert!(storage.complete_account_exit("9cf78d05-d9e1-4a20-b501-80e6d3d1b764", &group, None, 12, ConversationState::DeviceRemoved).await.unwrap());
        assert!(storage.complete_account_exit("9cf78d05-d9e1-4a20-b501-80e6d3d1b764", &group, None, 13, ConversationState::DeviceRemoved).await.unwrap());
        assert!(!storage.complete_account_exit("9cf78d05-d9e1-4a20-b501-80e6d3d1b764", &group, None, 12, ConversationState::Closed).await.unwrap());
        assert!(storage.complete_account_exit("9cf78d05-d9e1-4a20-b501-80e6d3d1b764", &group, None, 13, ConversationState::Closed).await.unwrap());
        assert!(!storage.complete_account_exit("9cf78d05-d9e1-4a20-b501-80e6d3d1b764", &group, None, 14, ConversationState::Closed).await.unwrap());
        assert!(!storage.complete_account_exit("9cf78d05-d9e1-4a20-b501-80e6d3d1b764", &group, None, 13, ConversationState::DeviceRemoved).await.unwrap());
        storage.set_conversation_state("9cf78d05-d9e1-4a20-b501-80e6d3d1b764", ConversationState::Active).await.unwrap();
        assert_eq!(storage.get_conversation_state("9cf78d05-d9e1-4a20-b501-80e6d3d1b764").await.unwrap(), Some(ConversationState::Closed));
        assert!(storage.clear_device_removal_after_verified_welcome("9cf78d05-d9e1-4a20-b501-80e6d3d1b764").await.is_err());
        assert!(storage.complete_account_exit("9cf78d05-d9e1-4a20-b501-80e6d3d1b764", &group, None, 12, ConversationState::Active).await.is_err());
        assert!(storage.complete_account_exit("9cf78d05-d9e1-4a20-b501-80e6d3d1b764", "invalid", None, 12, ConversationState::Closed).await.is_err());
        assert!(storage.complete_account_exit("not-a-canonical-cid", &group, None, 12, ConversationState::Closed).await.is_err());
        assert!(storage.complete_account_exit("9cf78d05-d9e1-4a20-b501-80e6d3d1b764", &group, Some(0), 12, ConversationState::Closed).await.is_err());
        storage.ensure_conversation_exists("did:plc:bob", "9cf78d05-d9e1-4a20-b501-80e6d3d1b764", &group).await.unwrap();
        assert!(!storage.complete_account_exit("9cf78d05-d9e1-4a20-b501-80e6d3d1b764", &group, None, 12, ConversationState::DeviceRemoved).await.unwrap());
        let conn = storage.conn.lock().unwrap();
        let generation: i32 = conn.query_row("SELECT reset_generation FROM conversations WHERE user_did = 'did:plc:alice'", [], |row| row.get(0)).unwrap();
        assert_eq!(generation, 9);
        let other: String = conn.query_row("SELECT state FROM conversations WHERE user_did = 'did:plc:bob'", [], |row| row.get(0)).unwrap();
        assert_eq!(other, "Active");
    }

    #[tokio::test]
    async fn account_exit_exact_removed_retry_is_read_only_and_rejects_torn_reset() {
        let (_tmp, storage) = new_temp_storage();
        let cid = "16e7956b-695e-4148-a1b4-bfd2d4efad05";
        let group = "44".repeat(32);
        storage.ensure_conversation_exists("did:plc:alice", cid, &group).await.unwrap();
        assert!(storage.complete_account_exit(cid, &group, None, 0, ConversationState::DeviceRemoved).await.unwrap());
        {
            let conn = storage.conn.lock().unwrap();
            conn.execute_batch("CREATE TRIGGER reject_terminal_retry BEFORE UPDATE ON conversations BEGIN SELECT RAISE(ABORT, 'exact terminal retry wrote a row'); END;").unwrap();
        }
        assert!(storage.complete_account_exit(cid, &group, None, 0, ConversationState::DeviceRemoved).await.unwrap());
        {
            let conn = storage.conn.lock().unwrap();
            conn.execute_batch("DROP TRIGGER reject_terminal_retry;").unwrap();
            conn.execute("UPDATE conversations SET reset_new_group_id = ?1, reset_generation = 3, reset_notified_at_ms = 123", [&group]).unwrap();
        }
        // Live columns without committed typed ResetPending are not reset authority.
        assert!(!storage.complete_account_exit(cid, &group, Some(3), 0, ConversationState::Closed).await.unwrap());
        {
            let conn = storage.conn.lock().unwrap();
            conn.execute_batch("UPDATE conversations SET reset_new_group_id = NULL, reset_notified_at_ms = NULL, reset_generation = -1;").unwrap();
        }
        assert!(!storage.complete_account_exit(cid, &group, None, 0, ConversationState::DeviceRemoved).await.unwrap());
    }

}

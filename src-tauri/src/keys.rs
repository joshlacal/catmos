//! Per-DID content-root key storage for the MLS field-level encryption layer.
//!
//! The content-root key is a 32-byte secret used by `catbird_mls::field_encryption`
//! to derive per-conversation AES-GCM content keys and HMAC chain keys. It is
//! held in process memory inside `MLSContext` and must be available on every
//! cold start, so we persist it as a binary file under
//! `{app_data_dir}/mls-content-root-clean-v2-openmls-v09/{sha256(normalized_did)}.key`.
//!
//! The file is protected by OS-level filesystem permissions (`0o600` on Unix).
//! It is **not** the SQLCipher database key — the two are stored separately so
//! that compromise of the database key alone does not directly expose decrypted
//! message bodies (the threat model the field-level layer addresses).

use anyhow::{anyhow, Context, Result};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

pub const MLS_CONTENT_ROOT_DIR: &str = "mls-content-root-clean-v2-openmls-v09";
pub const KEY_LEN: usize = 32;

/// Normalize DID to trimmed lowercase.
pub fn normalize_did(user_did: &str) -> String {
    user_did.trim().to_lowercase()
}

/// Derive the full SHA-256 lowercase hex account ID from normalized DID.
pub fn derive_account_id(user_did: &str) -> String {
    let normalized = normalize_did(user_did);
    let mut hasher = Sha256::new();
    hasher.update(normalized.as_bytes());
    hex::encode(hasher.finalize())
}

/// Path to content root key for an account.
pub fn content_root_key_path(app_data_dir: &Path, account_id: &str) -> PathBuf {
    app_data_dir
        .join(MLS_CONTENT_ROOT_DIR)
        .join(format!("{}.key", account_id))
}

/// Load an existing content-root key strictly without creating a fresh one.
pub fn load_existing_content_root_key(app_data_dir: &Path, user_did: &str) -> Result<Vec<u8>> {
    let account_id = derive_account_id(user_did);
    let path = content_root_key_path(app_data_dir, &account_id);
    if !path.exists() {
        return Err(anyhow!(
            "content root key file absent at {}",
            path.display()
        ));
    }
    let buf = fs::read(&path).context("read existing content root key")?;
    if buf.len() != KEY_LEN {
        return Err(anyhow!(
            "content root key file at {} has wrong length: expected {}, got {}",
            path.display(),
            KEY_LEN,
            buf.len(),
        ));
    }
    Ok(buf)
}

/// Create a fresh content-root key atomically strictly expecting it not to exist.
pub fn create_new_content_root_key(app_data_dir: &Path, user_did: &str) -> Result<Vec<u8>> {
    let account_id = derive_account_id(user_did);
    let dir = app_data_dir.join(MLS_CONTENT_ROOT_DIR);
    fs::create_dir_all(&dir).context("create mls-content-root dir")?;
    let path = content_root_key_path(app_data_dir, &account_id);

    if path.exists() {
        return Err(anyhow!(
            "content root key already exists at {}",
            path.display()
        ));
    }

    let mut buf = vec![0u8; KEY_LEN];
    rand::thread_rng().fill_bytes(&mut buf);

    let tmp_path = dir.join(format!("{}.tmp.{}", account_id, uuid::Uuid::new_v4()));
    let write_res = (|| -> std::io::Result<()> {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)?;
        file.write_all(&buf)?;
        file.sync_all()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = file.metadata()?.permissions();
            perms.set_mode(0o600);
            file.set_permissions(perms)?;
        }
        drop(file);
        std::fs::rename(&tmp_path, &path)?;
        Ok(())
    })();

    if let Err(e) = write_res {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(anyhow!(e).context("atomic write new content root key"));
    }

    Ok(buf)
}

/// Load the content-root key for `user_did` from `{app_data_dir}/mls-content-root-clean-v2-openmls-v09/{account_id}.key`,
/// creating a fresh random 32-byte key on first use. Permissions are tightened to
/// `0o600` on Unix-likes; on other platforms the OS default applies.
pub fn load_or_create_content_root_key(app_data_dir: &Path, user_did: &str) -> Result<Vec<u8>> {
    let path = content_root_key_path(app_data_dir, &derive_account_id(user_did));
    if path.exists() {
        return load_existing_content_root_key(app_data_dir, user_did);
    }
    create_new_content_root_key(app_data_dir, user_did)
}

/// Remove the content-root key file and any exact account `.tmp.<uuid>` files for `user_did`.
pub fn delete_content_root_key(app_data_dir: &Path, user_did: &str) -> Result<()> {
    let account_id = derive_account_id(user_did);
    let dir = app_data_dir.join(MLS_CONTENT_ROOT_DIR);
    let path = content_root_key_path(app_data_dir, &account_id);
    if path.exists() {
        fs::remove_file(&path).context("remove content root key file")?;
    }

    // Enumerate clean content-root dir and delete ONLY exact normalized account_id .tmp. prefix files
    match fs::read_dir(&dir) {
        Ok(entries) => {
            let temp_prefix = format!("{}.tmp.", account_id);
            for entry_res in entries {
                let entry = entry_res.context("read content root directory entry")?;
                let file_name = entry.file_name().to_string_lossy().to_string();
                if file_name.starts_with(&temp_prefix) {
                    let entry_path = entry.path();
                    if entry_path.is_file() {
                        match fs::remove_file(&entry_path) {
                            Ok(()) => {}
                            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                            Err(e) => {
                                return Err(anyhow!(e).context(format!(
                                    "failed to remove content root temp file {}",
                                    entry_path.display()
                                )))
                            }
                        }
                    }
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(anyhow!(e).context(format!("read content root directory {}", dir.display())))
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_then_load_returns_same_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        let did = "did:plc:catmos-test-user";
        let first = load_or_create_content_root_key(tmp.path(), did).unwrap();
        let second = load_existing_content_root_key(tmp.path(), did).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.len(), KEY_LEN);
    }

    #[test]
    fn different_dids_get_different_keys() {
        let tmp = tempfile::tempdir().unwrap();
        let a = load_or_create_content_root_key(tmp.path(), "did:plc:a").unwrap();
        let b = load_or_create_content_root_key(tmp.path(), "did:plc:b").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn normalized_did_gives_same_account_id() {
        let did1 = "DID:PLC:AbCd123 ";
        let did2 = "did:plc:abcd123";
        assert_eq!(derive_account_id(did1), derive_account_id(did2));
    }

    #[test]
    fn delete_removes_file() {
        let tmp = tempfile::tempdir().unwrap();
        let did = "did:plc:delete-me";
        let _ = load_or_create_content_root_key(tmp.path(), did).unwrap();
        delete_content_root_key(tmp.path(), did).unwrap();
        delete_content_root_key(tmp.path(), did).unwrap();
        let new_key = load_or_create_content_root_key(tmp.path(), did).unwrap();
        assert_eq!(new_key.len(), KEY_LEN);
    }

    #[test]
    fn rejects_wrong_length_file() {
        let tmp = tempfile::tempdir().unwrap();
        let did = "did:plc:bad";
        let account_id = derive_account_id(did);
        let dir = tmp.path().join(MLS_CONTENT_ROOT_DIR);
        fs::create_dir_all(&dir).unwrap();
        fs::write(content_root_key_path(tmp.path(), &account_id), b"too-short").unwrap();
        let err = load_existing_content_root_key(tmp.path(), did).unwrap_err();
        assert!(err.to_string().contains("wrong length"));
    }
}

//! WasmMLSContext — implements `MlsCryptoContext` for WASM targets.
//!
//! Combines `openmls_libcrux_crypto` (post-quantum crypto) with
//! `WasmSqliteStorage` (OPFS SAH VFS, sqlite3mc encrypted) to give a
//! fully in-browser OpenMLS stack.
//!
//! # Threading model
//!
//! WASM is single-threaded. All mutable state lives in `RefCell` rather
//! than `Mutex`. The `MlsCryptoContextBounds` supertrait removes the
//! `Send + Sync` requirement on WASM, so this compiles cleanly.
//!
//! # Persistence
//!
//! Groups and signing keys are persisted to `WasmSqliteStorage` by
//! OpenMLS itself (via the `StorageProvider` trait). The `RefCell` caches
//! only keep recently used objects in memory for performance.

use std::cell::RefCell;
use std::collections::HashMap;

use base64::Engine as _;
use openmls::prelude::tls_codec::Serialize as TlsSerialize;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_libcrux_crypto::CryptoProvider as LibcruxCrypto;
use openmls_traits::OpenMlsProvider;

use catbird_mls::{
    AddMembersResult, CredentialData, DecryptResult, EncryptResult, ExternalCommitResult,
    GroupConfig, GroupCreationResult, KeyPackageData, KeyPackageResult, MLSError, WelcomeResult,
};

use crate::mls_storage::WasmSqliteStorage;
use crate::sqlite_conn::SqliteConn;
use std::rc::Rc;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;
const BUCKET_SIZES: [usize; 5] = [512, 1024, 2048, 4096, 8192];

// ---------------------------------------------------------------------------
// OpenMLS provider: LibcruxCrypto + WasmSqliteStorage
// ---------------------------------------------------------------------------

pub struct WasmOpenMlsProvider {
    crypto: LibcruxCrypto,
    storage: WasmSqliteStorage,
}

impl OpenMlsProvider for WasmOpenMlsProvider {
    type CryptoProvider = LibcruxCrypto;
    type RandProvider = LibcruxCrypto;
    type StorageProvider = WasmSqliteStorage;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}

// ---------------------------------------------------------------------------
// WasmMLSContext
// ---------------------------------------------------------------------------

/// MLS crypto context backed by WASM-compatible storage and crypto.
///
/// Owns the OpenMLS provider and caches in-memory group + signer state.
pub struct WasmMLSContext {
    provider: WasmOpenMlsProvider,
    /// Cached in-memory groups: group_id bytes → MlsGroup.
    groups: RefCell<HashMap<Vec<u8>, MlsGroup>>,
    /// Cached signing keys: identity bytes → SignatureKeyPair.
    signers: RefCell<HashMap<Vec<u8>, SignatureKeyPair>>,
    /// Per-group metadata encryption keys (MEK), cached in memory.
    metadata_keys: RefCell<HashMap<Vec<u8>, [u8; 32]>>,
}

impl WasmMLSContext {
    /// Open (or create) the MLS SQLite database.
    ///
    /// * `db_path` — path for the SQLite file (OPFS path in a Worker).
    /// * `encryption_key` — hex-encoded 256-bit key for sqlite3mc.
    #[allow(dead_code)]
    pub fn open(db_path: &str, encryption_key: &str) -> Result<Self, MLSError> {
        let storage = WasmSqliteStorage::open(db_path, encryption_key)
            .map_err(|e| MLSError::invalid_input(format!("WasmSqliteStorage::open: {e}")))?;

        let crypto = LibcruxCrypto::new()
            .map_err(|e| MLSError::OpenMLS(format!("LibcruxCrypto::new: {e:?}")))?;
        Ok(Self {
            provider: WasmOpenMlsProvider { crypto, storage },
            groups: RefCell::new(HashMap::new()),
            signers: RefCell::new(HashMap::new()),
            metadata_keys: RefCell::new(HashMap::new()),
        })
    }

    /// Open using a shared `SqliteConn`.
    ///
    /// The caller must have already called `WasmSqliteStorage::ensure_schema()`
    /// on the connection.
    pub fn open_with_conn(conn: Rc<SqliteConn>) -> Result<Self, MLSError> {
        let storage = WasmSqliteStorage::new(conn);

        let crypto = LibcruxCrypto::new()
            .map_err(|e| MLSError::OpenMLS(format!("LibcruxCrypto::new: {e:?}")))?;
        Ok(Self {
            provider: WasmOpenMlsProvider { crypto, storage },
            groups: RefCell::new(HashMap::new()),
            signers: RefCell::new(HashMap::new()),
            metadata_keys: RefCell::new(HashMap::new()),
        })
    }

    // -----------------------------------------------------------------------
    // Internal: signer helpers
    // -----------------------------------------------------------------------

    /// Get or create an Ed25519 `SignatureKeyPair` for `identity_bytes`.
    ///
    /// Creates a new pair on first call, persists it via `StorageProvider`,
    /// and caches it in `self.signers`.
    fn get_or_create_signer(&self, identity_bytes: &[u8]) -> Result<SignatureKeyPair, MLSError> {
        if let Some(s) = self.signers.borrow().get(identity_bytes) {
            return Ok(s.clone());
        }

        let signer = SignatureKeyPair::new(SignatureScheme::ED25519)
            .map_err(|e| MLSError::OpenMLS(format!("SignatureKeyPair::new: {e:?}")))?;

        signer
            .store(self.provider.storage())
            .map_err(|e| MLSError::OpenMLS(format!("signer.store: {e:?}")))?;

        let result = signer.clone();
        self.signers
            .borrow_mut()
            .insert(identity_bytes.to_vec(), signer);
        Ok(result)
    }

    /// Load the signing key for a group's own leaf from storage (or cache).
    ///
    /// Called inside methods that hold `&mut MlsGroup` — `group` is passed
    /// by reference so we can extract the identity/pubkey before the borrow
    /// overlaps with the `signers` RefCell.
    fn signer_from_identity(
        &self,
        identity: Vec<u8>,
        pub_key: Vec<u8>,
    ) -> Result<SignatureKeyPair, MLSError> {
        if let Some(s) = self.signers.borrow().get(&identity) {
            return Ok(s.clone());
        }

        let s = SignatureKeyPair::read(self.provider.storage(), &pub_key, SignatureScheme::ED25519)
            .ok_or_else(|| {
                MLSError::invalid_input(
                    "signing key not found in storage — re-initialise the context",
                )
            })?;

        self.signers.borrow_mut().insert(identity, s.clone());
        Ok(s)
    }

    // -----------------------------------------------------------------------
    // Internal: group config builders
    // -----------------------------------------------------------------------

    fn make_create_config(config: &GroupConfig) -> MlsGroupCreateConfig {
        MlsGroupCreateConfig::builder()
            .ciphersuite(CIPHERSUITE)
            .max_past_epochs(config.max_past_epochs as usize)
            .sender_ratchet_configuration(SenderRatchetConfiguration::new(
                config.out_of_order_tolerance,
                config.maximum_forward_distance,
            ))
            .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
            .use_ratchet_tree_extension(true)
            .build()
    }

    fn make_join_config(config: &GroupConfig) -> MlsGroupJoinConfig {
        MlsGroupJoinConfig::builder()
            .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
            .max_past_epochs(config.max_past_epochs as usize)
            .sender_ratchet_configuration(SenderRatchetConfiguration::new(
                config.out_of_order_tolerance,
                config.maximum_forward_distance,
            ))
            .use_ratchet_tree_extension(true)
            .build()
    }

    fn default_config() -> GroupConfig {
        GroupConfig::default()
    }

    // -----------------------------------------------------------------------
    // Internal: load group from storage into cache
    // -----------------------------------------------------------------------

    /// Try to load a persisted group into the in-memory cache.
    ///
    /// Returns `Ok(true)` if the group was found and loaded (or was already
    /// cached), `Ok(false)` if the group does not exist in OpenMLS storage.
    pub fn ensure_group_loaded(&self, group_id: &[u8]) -> Result<bool, MLSError> {
        if self.groups.borrow().contains_key(group_id) {
            return Ok(true);
        }

        let gid = GroupId::from_slice(group_id);
        match MlsGroup::load(self.provider.storage(), &gid) {
            Ok(Some(group)) => {
                self.groups.borrow_mut().insert(group_id.to_vec(), group);
                Ok(true)
            }
            Ok(None) => Ok(false),
            Err(e) => Err(MLSError::OpenMLS(format!("MlsGroup::load: {e:?}"))),
        }
    }

    /// Ensure the group is in the in-memory cache, loading from OpenMLS
    /// storage if necessary.
    fn ensure_loaded(&self, group_id: &[u8]) -> Result<(), MLSError> {
        if self.groups.borrow().contains_key(group_id) {
            return Ok(());
        }

        let gid = GroupId::from_slice(group_id);
        let group = MlsGroup::load(self.provider.storage(), &gid)
            .map_err(|e| MLSError::OpenMLS(format!("MlsGroup::load: {e:?}")))?
            .ok_or_else(|| {
                MLSError::group_not_found(format!(
                    "group {} not found in storage",
                    base64::engine::general_purpose::STANDARD.encode(group_id),
                ))
            })?;

        self.groups.borrow_mut().insert(group_id.to_vec(), group);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Padding — must match catbird-mls/src/api.rs exactly.
//
// Format: [4-byte big-endian length][MLS ciphertext][zero padding → bucket]
// ---------------------------------------------------------------------------

fn pad_ciphertext(ciphertext: &[u8]) -> (Vec<u8>, u32) {
    let actual_len = ciphertext.len();
    let total_needed = 4 + actual_len;
    let bucket = BUCKET_SIZES
        .iter()
        .copied()
        .find(|&b| b >= total_needed)
        .unwrap_or_else(|| total_needed.div_ceil(8192) * 8192);

    let mut padded = Vec::with_capacity(bucket);
    padded.extend_from_slice(&(actual_len as u32).to_be_bytes());
    padded.extend_from_slice(ciphertext);
    padded.resize(bucket, 0);
    (padded, bucket as u32)
}

fn strip_padding(data: &[u8]) -> &[u8] {
    if data.len() < 5 {
        return data;
    }
    let claimed_len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if claimed_len > 0 && claimed_len <= data.len() - 4 && matches!(data[4], 0x00..=0x04) {
        &data[4..4 + claimed_len]
    } else {
        data
    }
}

// ---------------------------------------------------------------------------
// MlsCryptoContext implementation
// ---------------------------------------------------------------------------

impl WasmMLSContext {
    // ------------------------------------------------------------------
    // Group lifecycle
    // ------------------------------------------------------------------

    pub(crate) fn create_group(
        &self,
        identity_bytes: Vec<u8>,
        config: Option<GroupConfig>,
    ) -> Result<GroupCreationResult, MLSError> {
        let config = config.unwrap_or_else(Self::default_config);
        let signer = self.get_or_create_signer(&identity_bytes)?;

        let credential = BasicCredential::new(identity_bytes.clone());
        let cred_with_key = CredentialWithKey {
            credential: credential.into(),
            signature_key: signer.public().into(),
        };

        let group_config = Self::make_create_config(&config);
        let group = MlsGroup::new(&self.provider, &signer, &group_config, cred_with_key)
            .map_err(|e| MLSError::OpenMLS(format!("MlsGroup::new: {e:?}")))?;

        let group_id = group.group_id().as_slice().to_vec();
        self.groups.borrow_mut().insert(group_id.clone(), group);

        Ok(GroupCreationResult { group_id })
    }

    pub(crate) fn delete_group(&self, group_id: Vec<u8>) -> Result<(), MLSError> {
        if let Some(mut group) = self.groups.borrow_mut().remove(&group_id) {
            let _ = group.delete(self.provider.storage());
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Member management
    // ------------------------------------------------------------------

    pub(crate) fn add_members(
        &self,
        group_id: Vec<u8>,
        key_packages: Vec<KeyPackageData>,
    ) -> Result<AddMembersResult, MLSError> {
        // Deserialize + validate incoming key packages.
        let kps: Vec<KeyPackage> = key_packages
            .iter()
            .map(|kpd| {
                let (kp_in, _) = KeyPackageIn::tls_deserialize_bytes(&kpd.data)
                    .map_err(|e| MLSError::OpenMLS(format!("KP deserialize: {e:?}")))?;
                kp_in
                    .validate(self.provider.crypto(), ProtocolVersion::default())
                    .map_err(|e| MLSError::OpenMLS(format!("KP validate: {e:?}")))
            })
            .collect::<Result<_, _>>()?;

        self.ensure_loaded(&group_id)?;
        let mut groups = self.groups.borrow_mut();
        let group = groups
            .get_mut(&group_id)
            .expect("ensure_loaded guarantees presence");

        // Extract own leaf data before taking a mutable reference.
        let (identity, pub_key) = {
            let leaf = group
                .own_leaf()
                .ok_or_else(|| MLSError::invalid_input("group has no own leaf"))?;
            (
                leaf.credential().serialized_content().to_vec(),
                leaf.signature_key().as_slice().to_vec(),
            )
        };
        let signer = self.signer_from_identity(identity, pub_key)?;

        let (commit_msg, welcome, _group_info) =
            group
                .add_members(&self.provider, &signer, &kps)
                .map_err(|e| MLSError::OpenMLS(format!("add_members: {e:?}")))?;

        let commit_data = commit_msg
            .tls_serialize_detached()
            .map_err(|e| MLSError::OpenMLS(format!("commit serialize: {e:?}")))?;

        let welcome_data = welcome
            .tls_serialize_detached()
            .map_err(|e| MLSError::OpenMLS(format!("welcome serialize: {e:?}")))?;

        Ok(AddMembersResult {
            commit_data,
            welcome_data,
        })
    }

    pub(crate) fn remove_members(
        &self,
        group_id: Vec<u8>,
        member_identities: Vec<Vec<u8>>,
    ) -> Result<Vec<u8>, MLSError> {
        self.ensure_loaded(&group_id)?;
        let mut groups = self.groups.borrow_mut();
        let group = groups
            .get_mut(&group_id)
            .expect("ensure_loaded guarantees presence");

        let leaf_indices: Vec<LeafNodeIndex> = group
            .members()
            .filter(|m| {
                member_identities
                    .iter()
                    .any(|i| i.as_slice() == m.credential.serialized_content())
            })
            .map(|m| m.index)
            .collect();

        if leaf_indices.is_empty() {
            return Err(MLSError::invalid_input(
                "remove_members: no matching members found",
            ));
        }

        let (identity, pub_key) = {
            let leaf = group
                .own_leaf()
                .ok_or_else(|| MLSError::invalid_input("group has no own leaf"))?;
            (
                leaf.credential().serialized_content().to_vec(),
                leaf.signature_key().as_slice().to_vec(),
            )
        };
        let signer = self.signer_from_identity(identity, pub_key)?;

        let (commit_msg, _welcome, _group_info) = group
            .remove_members(&self.provider, &signer, &leaf_indices)
            .map_err(|e| MLSError::OpenMLS(format!("remove_members: {e:?}")))?;

        commit_msg
            .tls_serialize_detached()
            .map_err(|e| MLSError::OpenMLS(format!("commit serialize: {e:?}")))
    }

    // ------------------------------------------------------------------
    // Commit management
    // ------------------------------------------------------------------

    pub(crate) fn merge_pending_commit(&self, group_id: Vec<u8>) -> Result<u64, MLSError> {
        self.ensure_loaded(&group_id)?;
        let mut groups = self.groups.borrow_mut();
        let group = groups
            .get_mut(&group_id)
            .expect("ensure_loaded guarantees presence");

        group
            .merge_pending_commit(&self.provider)
            .map_err(|e| MLSError::OpenMLS(format!("merge_pending_commit: {e:?}")))?;

        Ok(group.epoch().as_u64())
    }

    pub(crate) fn clear_pending_commit(&self, group_id: Vec<u8>) -> Result<(), MLSError> {
        self.ensure_loaded(&group_id)?;
        let mut groups = self.groups.borrow_mut();
        let group = groups
            .get_mut(&group_id)
            .expect("ensure_loaded guarantees presence");

        group
            .clear_pending_commit(self.provider.storage())
            .map_err(|e| MLSError::OpenMLS(format!("clear_pending_commit: {e:?}")))?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Group state queries
    // ------------------------------------------------------------------

    pub(crate) fn get_epoch(&self, group_id: Vec<u8>) -> Result<u64, MLSError> {
        self.ensure_loaded(&group_id)?;
        let groups = self.groups.borrow();
        let group = groups
            .get(&group_id)
            .expect("ensure_loaded guarantees presence");
        Ok(group.epoch().as_u64())
    }

    pub(crate) fn export_group_info(
        &self,
        group_id: Vec<u8>,
        signer_identity_bytes: Vec<u8>,
    ) -> Result<Vec<u8>, MLSError> {
        let signer = self.get_or_create_signer(&signer_identity_bytes)?;

        self.ensure_loaded(&group_id)?;
        let mut groups = self.groups.borrow_mut();
        let group = groups
            .get_mut(&group_id)
            .expect("ensure_loaded guarantees presence");

        let group_info = group
            .export_group_info(self.provider.crypto(), &signer, true)
            .map_err(|e| MLSError::OpenMLS(format!("export_group_info: {e:?}")))?;

        group_info
            .tls_serialize_detached()
            .map_err(|e| MLSError::OpenMLS(format!("group_info serialize: {e:?}")))
    }

    // ------------------------------------------------------------------
    // Joining
    // ------------------------------------------------------------------

    pub(crate) fn process_welcome(
        &self,
        welcome_bytes: Vec<u8>,
        identity_bytes: Vec<u8>,
        config: Option<GroupConfig>,
    ) -> Result<WelcomeResult, MLSError> {
        let config = config.unwrap_or_else(Self::default_config);
        let signer = self.get_or_create_signer(&identity_bytes)?;

        let (msg_in, _) = MlsMessageIn::tls_deserialize_bytes(&welcome_bytes)
            .map_err(|e| MLSError::OpenMLS(format!("Welcome msg deserialize: {e:?}")))?;

        let welcome = match msg_in.extract() {
            MlsMessageBodyIn::Welcome(w) => w,
            other => {
                return Err(MLSError::invalid_input(format!(
                    "expected Welcome, got {:?}",
                    std::mem::discriminant(&other)
                )))
            }
        };

        let join_config = Self::make_join_config(&config);
        let staged = StagedWelcome::new_from_welcome(&self.provider, &join_config, welcome, None)
            .map_err(|e| {
            MLSError::OpenMLS(format!("StagedWelcome::new_from_welcome: {e:?}"))
        })?;

        let group = staged
            .into_group(&self.provider)
            .map_err(|e| MLSError::OpenMLS(format!("staged.into_group: {e:?}")))?;

        let group_id = group.group_id().as_slice().to_vec();
        self.groups.borrow_mut().insert(group_id.clone(), group);
        self.signers.borrow_mut().insert(identity_bytes, signer);

        Ok(WelcomeResult { group_id })
    }

    pub(crate) fn create_external_commit(
        &self,
        group_info_bytes: Vec<u8>,
        identity_bytes: Vec<u8>,
    ) -> Result<ExternalCommitResult, MLSError> {
        let config = Self::default_config();
        let signer = self.get_or_create_signer(&identity_bytes)?;

        let credential = BasicCredential::new(identity_bytes.clone());
        let cred_with_key = CredentialWithKey {
            credential: credential.into(),
            signature_key: signer.public().into(),
        };

        let (msg_in, _) = MlsMessageIn::tls_deserialize_bytes(&group_info_bytes)
            .map_err(|e| MLSError::OpenMLS(format!("GroupInfo deserialize: {e:?}")))?;

        let verifiable_group_info = match msg_in.extract() {
            MlsMessageBodyIn::GroupInfo(gi) => gi,
            _ => {
                return Err(MLSError::invalid_input(
                    "expected GroupInfo for external commit",
                ))
            }
        };

        let join_config = Self::make_join_config(&config);

        let (group, commit_msg, _group_info_out) = MlsGroup::join_by_external_commit(
            &self.provider,
            &signer,
            None,
            verifiable_group_info,
            &join_config,
            None,
            None,
            b"",
            cred_with_key,
        )
        .map_err(|e| MLSError::OpenMLS(format!("join_by_external_commit: {e:?}")))?;

        let commit_data = commit_msg
            .tls_serialize_detached()
            .map_err(|e| MLSError::OpenMLS(format!("commit serialize: {e:?}")))?;

        let group_id = group.group_id().as_slice().to_vec();
        self.groups.borrow_mut().insert(group_id.clone(), group);
        self.signers.borrow_mut().insert(identity_bytes, signer);

        Ok(ExternalCommitResult {
            commit_data,
            group_id,
        })
    }

    pub(crate) fn discard_pending_external_join(&self, group_id: Vec<u8>) -> Result<(), MLSError> {
        if let Some(mut group) = self.groups.borrow_mut().remove(&group_id) {
            let _ = group.delete(self.provider.storage());
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Messaging
    // ------------------------------------------------------------------

    pub(crate) fn encrypt_message(
        &self,
        group_id: Vec<u8>,
        plaintext: Vec<u8>,
    ) -> Result<EncryptResult, MLSError> {
        self.ensure_loaded(&group_id)?;
        let mut groups = self.groups.borrow_mut();
        let group = groups
            .get_mut(&group_id)
            .expect("ensure_loaded guarantees presence");

        let (identity, pub_key) = {
            let leaf = group
                .own_leaf()
                .ok_or_else(|| MLSError::invalid_input("group has no own leaf"))?;
            (
                leaf.credential().serialized_content().to_vec(),
                leaf.signature_key().as_slice().to_vec(),
            )
        };
        let signer = self.signer_from_identity(identity, pub_key)?;

        let msg_out = group
            .create_message(&self.provider, &signer, &plaintext)
            .map_err(|e| MLSError::OpenMLS(format!("create_message: {e:?}")))?;

        let raw = msg_out
            .tls_serialize_detached()
            .map_err(|e| MLSError::OpenMLS(format!("msg serialize: {e:?}")))?;

        let (padded, padded_size) = pad_ciphertext(&raw);
        Ok(EncryptResult {
            ciphertext: padded,
            padded_size,
        })
    }

    pub(crate) fn decrypt_message(
        &self,
        group_id: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> Result<DecryptResult, MLSError> {
        let raw = strip_padding(&ciphertext);

        let (msg_in, _) = MlsMessageIn::tls_deserialize_bytes(raw)
            .map_err(|e| MLSError::OpenMLS(format!("MlsMessageIn deserialize: {e:?}")))?;

        let protocol_msg: ProtocolMessage = msg_in
            .try_into()
            .map_err(|e| MLSError::OpenMLS(format!("MlsMessageIn to ProtocolMessage: {e:?}")))?;

        self.ensure_loaded(&group_id)?;
        let mut groups = self.groups.borrow_mut();
        let group = groups
            .get_mut(&group_id)
            .expect("ensure_loaded guarantees presence");

        let processed = group
            .process_message(&self.provider, protocol_msg)
            .map_err(|e| MLSError::OpenMLS(format!("process_message: {e:?}")))?;

        let epoch = group.epoch().as_u64();

        // Extract credential data before consuming `processed`.
        let sender_credential = {
            let cred = processed.credential();
            CredentialData {
                credential_type: "basic".to_string(),
                identity: cred.serialized_content().to_vec(),
            }
        };

        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app_msg) => Ok(DecryptResult {
                plaintext: app_msg.into_bytes(),
                epoch,
                sequence_number: 0,
                sender_credential,
            }),

            ProcessedMessageContent::StagedCommitMessage(commit) => {
                // Auto-merge commits from other members.
                group
                    .merge_staged_commit(&self.provider, *commit)
                    .map_err(|e| MLSError::OpenMLS(format!("merge_staged_commit: {e:?}")))?;

                Err(MLSError::invalid_input(
                    "received a commit message (not application data)",
                ))
            }

            ProcessedMessageContent::ProposalMessage(_) => Err(MLSError::invalid_input(
                "received a proposal (not application data)",
            )),

            ProcessedMessageContent::ExternalJoinProposalMessage(_) => {
                Err(MLSError::invalid_input(
                    "received an external join proposal (not application data)",
                ))
            }
        }
    }

    // ------------------------------------------------------------------
    // Key packages
    // ------------------------------------------------------------------

    pub(crate) fn create_key_package(
        &self,
        identity_bytes: Vec<u8>,
    ) -> Result<KeyPackageResult, MLSError> {
        let signer = self.get_or_create_signer(&identity_bytes)?;

        let credential = BasicCredential::new(identity_bytes.clone());
        let cred_with_key = CredentialWithKey {
            credential: credential.into(),
            signature_key: signer.public().into(),
        };

        let bundle = KeyPackage::builder()
            .build(CIPHERSUITE, &self.provider, &signer, cred_with_key)
            .map_err(|e| MLSError::OpenMLS(format!("KeyPackage::builder: {e:?}")))?;
        let key_package = bundle.key_package().clone();

        let hash_ref = key_package
            .hash_ref(self.provider.crypto())
            .map(|h| h.as_slice().to_vec())
            .map_err(|e| MLSError::OpenMLS(format!("key_package.hash_ref: {e:?}")))?;

        let key_package_data = key_package
            .tls_serialize_detached()
            .map_err(|e| MLSError::OpenMLS(format!("key_package serialize: {e:?}")))?;

        Ok(KeyPackageResult {
            key_package_data,
            hash_ref,
        })
    }

    // ------------------------------------------------------------------
    // Group metadata
    // ------------------------------------------------------------------

    /// Build a storage key for a metadata encryption key (MEK).
    fn mek_storage_key(group_id: &[u8]) -> Vec<u8> {
        let mut k = b"catbird_mek_".to_vec();
        k.extend_from_slice(group_id);
        k
    }

    /// Retrieve the MEK from in-memory cache, falling back to DB.
    fn get_metadata_key(&self, group_id: &[u8]) -> Option<[u8; 32]> {
        if let Some(key) = self.metadata_keys.borrow().get(group_id) {
            return Some(*key);
        }
        // Try loading from DB
        let storage_key = Self::mek_storage_key(group_id);
        if let Ok(Some(bytes)) = self.provider.storage().conn().get(&storage_key) {
            if bytes.len() == 32 {
                let mut key = [0u8; 32];
                key.copy_from_slice(&bytes);
                self.metadata_keys
                    .borrow_mut()
                    .insert(group_id.to_vec(), key);
                return Some(key);
            }
        }
        None
    }

    /// Store a MEK in both in-memory cache and DB.
    fn store_metadata_key(&self, group_id: &[u8], key: &[u8; 32]) {
        self.metadata_keys
            .borrow_mut()
            .insert(group_id.to_vec(), *key);
        let storage_key = Self::mek_storage_key(group_id);
        let _ = self.provider.storage().conn().put(&storage_key, key);
    }

    /// Read group metadata from MLS group context extensions.
    /// Returns JSON bytes of the metadata, or empty vec if none set.
    pub(crate) fn get_group_metadata(&self, group_id: Vec<u8>) -> Result<Vec<u8>, MLSError> {
        self.ensure_loaded(&group_id)?;
        let groups = self.groups.borrow();
        let group = groups
            .get(&group_id)
            .expect("ensure_loaded guarantees presence");

        let mek = self.get_metadata_key(&group_id);

        let meta = match mek {
            Some(key) => {
                catbird_mls::group_metadata::decrypt_metadata_from_group_with_key(group, &key)
            }
            None => catbird_mls::group_metadata::GroupMetadata::from_group(group),
        };

        match meta {
            Some(m) => m
                .to_extension_bytes()
                .map_err(|e| MLSError::Internal(format!("JSON serialize: {}", e))),
            None => Ok(Vec::new()),
        }
    }

    /// Update group metadata by proposing + committing a GroupContextExtensions change.
    /// Encrypts the metadata with ChaCha20-Poly1305 using a stable per-group MEK.
    /// Returns the commit message bytes that must be sent to the server.
    pub(crate) fn update_group_metadata(
        &self,
        group_id: Vec<u8>,
        metadata_json: Vec<u8>,
    ) -> Result<Vec<u8>, MLSError> {
        use catbird_mls::group_metadata::{
            encrypt_metadata_with_key, GroupMetadata, CATBIRD_METADATA_EXTENSION_TYPE,
        };
        use openmls_traits::random::OpenMlsRand;

        let metadata = GroupMetadata::from_extension_bytes(&metadata_json)
            .map_err(|e| MLSError::invalid_input(format!("Invalid metadata JSON: {}", e)))?;

        // Get or generate MEK
        let mek = match self.get_metadata_key(&group_id) {
            Some(key) => key,
            None => {
                let key_bytes = self
                    .provider
                    .rand()
                    .random_vec(32)
                    .map_err(|e| MLSError::Internal(format!("MEK generation: {:?}", e)))?;
                let mut key = [0u8; 32];
                key.copy_from_slice(&key_bytes);
                self.store_metadata_key(&group_id, &key);
                key
            }
        };

        self.ensure_loaded(&group_id)?;
        let mut groups = self.groups.borrow_mut();
        let group = groups
            .get_mut(&group_id)
            .expect("ensure_loaded guarantees presence");

        // Get signer for this group
        let (identity, pub_key) = {
            let leaf = group
                .own_leaf()
                .ok_or_else(|| MLSError::invalid_input("group has no own leaf"))?;
            (
                leaf.credential().serialized_content().to_vec(),
                leaf.signature_key().as_slice().to_vec(),
            )
        };
        let signer = self.signer_from_identity(identity, pub_key)?;

        // Encrypt metadata with stable per-group MEK
        let envelope = encrypt_metadata_with_key(&mek, &metadata, self.provider.rand())
            .map_err(|e| MLSError::Internal(format!("encrypt metadata: {}", e)))?;
        let envelope_bytes = serde_json::to_vec(&envelope)
            .map_err(|e| MLSError::Internal(format!("serialize envelope: {}", e)))?;

        // Clone existing extensions and add/replace the encrypted metadata extension.
        let mut extensions = group.extensions().clone();

        // Read existing RequiredCapabilities and merge our extension type
        let existing_rc = extensions.required_capabilities().cloned();
        let mut ext_types: Vec<ExtensionType> = existing_rc
            .as_ref()
            .map(|rc| rc.extension_types().to_vec())
            .unwrap_or_default();
        if !ext_types.contains(&ExtensionType::Unknown(CATBIRD_METADATA_EXTENSION_TYPE)) {
            ext_types.push(ExtensionType::Unknown(CATBIRD_METADATA_EXTENSION_TYPE));
        }
        if !ext_types.contains(&ExtensionType::RatchetTree) {
            ext_types.push(ExtensionType::RatchetTree);
        }

        let proposal_types = existing_rc
            .as_ref()
            .map(|rc| rc.proposal_types().to_vec())
            .unwrap_or_default();
        let credential_types = existing_rc
            .as_ref()
            .map(|rc| rc.credential_types().to_vec())
            .unwrap_or_default();

        extensions
            .add_or_replace(Extension::RequiredCapabilities(
                RequiredCapabilitiesExtension::new(
                    &ext_types,
                    &proposal_types,
                    &credential_types,
                ),
            ))
            .map_err(|e| {
                MLSError::Internal(format!(
                    "Failed to add required capabilities extension: {:?}",
                    e
                ))
            })?;

        extensions
            .add_or_replace(Extension::Unknown(
                CATBIRD_METADATA_EXTENSION_TYPE,
                UnknownExtension(envelope_bytes),
            ))
            .map_err(|e| {
                MLSError::Internal(format!("Failed to add metadata extension: {:?}", e))
            })?;

        let (commit_msg, _welcome, _group_info) = group
            .update_group_context_extensions(&self.provider, extensions, &signer)
            .map_err(|e| {
                MLSError::OpenMLS(format!("update_group_context_extensions: {:?}", e))
            })?;

        commit_msg
            .tls_serialize_detached()
            .map_err(|e| MLSError::OpenMLS(format!("commit serialize: {e:?}")))
    }
}

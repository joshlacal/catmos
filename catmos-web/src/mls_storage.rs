//! WasmSqliteStorage — implements `openmls_traits::storage::StorageProvider<CURRENT_VERSION>`
//! backed by sqlite-wasm-rs with OPFS SAH VFS and sqlite3mc ChaCha20 encryption.
//!
//! # Architecture
//!
//! OpenMLS's `StorageProvider` trait is **synchronous** (no async). The only browser
//! API offering synchronous file I/O is OPFS `createSyncAccessHandle()` (Workers only).
//! `sqlite-wasm-rs` exposes this via its `opfs-sahpool` VFS.
//!
//! We use a single KV table with label-prefix keys to avoid collisions between
//! different OpenMLS data types — matching the pattern used by `openmls_memory_storage`.
//!
//! # Schema
//!
//! ```sql
//! CREATE TABLE IF NOT EXISTS openmls_kv (
//!     storage_key BLOB PRIMARY KEY,
//!     value       BLOB NOT NULL
//! );
//! ```

use openmls_traits::storage::{traits, Entity, StorageProvider, CURRENT_VERSION};
use serde::Serialize;
use std::rc::Rc;

use crate::sqlite_conn::{SqliteConn, WasmSqliteError};

// ---------------------------------------------------------------------------
// WasmSqliteStorage
// ---------------------------------------------------------------------------

/// OpenMLS `StorageProvider` backed by sqlite-wasm-rs.
///
/// Uses the same label-prefix key strategy as `openmls_memory_storage`:
///   storage_key = label ++ serde_json(key) ++ VERSION.to_be_bytes()
///
/// Values are serialized with `serde_json`.
pub struct WasmSqliteStorage {
    conn: Rc<SqliteConn>,
}

impl WasmSqliteStorage {
    /// Create a new storage wrapper around a shared connection.
    ///
    /// The connection must already have the `openmls_kv` table created.
    pub fn new(conn: Rc<SqliteConn>) -> Self {
        Self { conn }
    }

    /// Access the underlying SQLite connection (e.g. for MEK persistence).
    pub fn conn(&self) -> &Rc<SqliteConn> {
        &self.conn
    }

    /// Open (or create) a **standalone** encrypted database for backward compat.
    ///
    /// - `db_name` -- file path for the database (e.g. `"mls-state.db"`)
    /// - `key` -- hex-encoded 256-bit key for sqlite3mc ChaCha20 encryption
    #[allow(dead_code)]
    pub fn open(db_name: &str, key: &str) -> Result<Self, WasmSqliteError> {
        let conn = SqliteConn::open(db_name, key)?;
        conn.exec_raw(
            "CREATE TABLE IF NOT EXISTS openmls_kv (
                storage_key BLOB PRIMARY KEY,
                value       BLOB NOT NULL
            );",
        )?;
        Ok(Self {
            conn: Rc::new(conn),
        })
    }

    /// Create the `openmls_kv` table on the given shared connection.
    pub fn ensure_schema(conn: &SqliteConn) -> Result<(), WasmSqliteError> {
        conn.exec_raw(
            "CREATE TABLE IF NOT EXISTS openmls_kv (
                storage_key BLOB PRIMARY KEY,
                value       BLOB NOT NULL
            );",
        )
    }

    // -- Internal helpers mirroring openmls_memory_storage --

    /// Build a storage key: label ++ key_data ++ VERSION
    fn build_key(label: &[u8], key_data: Vec<u8>) -> Vec<u8> {
        let mut k = label.to_vec();
        k.extend_from_slice(&key_data);
        k.extend_from_slice(&u16::to_be_bytes(CURRENT_VERSION));
        k
    }

    /// Build a storage key from a serializable value.
    fn build_key_ser<K: Serialize>(label: &[u8], key: &K) -> Result<Vec<u8>, WasmSqliteError> {
        let key_bytes = serde_json::to_vec(key)?;
        Ok(Self::build_key(label, key_bytes))
    }

    /// Write a single value.
    fn write_kv(
        &self,
        label: &[u8],
        key: &[u8],
        value: Vec<u8>,
    ) -> Result<(), WasmSqliteError> {
        let storage_key = Self::build_key(label, key.to_vec());
        self.conn.put(&storage_key, &value)
    }

    /// Read a single value.
    fn read_kv<V: Entity<CURRENT_VERSION>>(
        &self,
        label: &[u8],
        key: &[u8],
    ) -> Result<Option<V>, WasmSqliteError> {
        let storage_key = Self::build_key(label, key.to_vec());
        match self.conn.get(&storage_key)? {
            Some(bytes) => {
                let val: V = serde_json::from_slice(&bytes)?;
                Ok(Some(val))
            }
            None => Ok(None),
        }
    }

    /// Delete a single value.
    fn delete_kv(&self, label: &[u8], key: &[u8]) -> Result<(), WasmSqliteError> {
        let storage_key = Self::build_key(label, key.to_vec());
        self.conn.remove(&storage_key)
    }

    /// Read a list (stored as JSON array of byte arrays).
    fn read_list<V: Entity<CURRENT_VERSION>>(
        &self,
        label: &[u8],
        key: &[u8],
    ) -> Result<Vec<V>, WasmSqliteError> {
        let storage_key = Self::build_key(label, key.to_vec());
        match self.conn.get(&storage_key)? {
            Some(bytes) => {
                let items: Vec<Vec<u8>> = serde_json::from_slice(&bytes)?;
                items
                    .iter()
                    .map(|item_bytes| {
                        serde_json::from_slice(item_bytes).map_err(|_| {
                            WasmSqliteError::Serialization("list item deserialization".into())
                        })
                    })
                    .collect()
            }
            None => Ok(vec![]),
        }
    }

    /// Append a value to a list stored as JSON array of byte arrays.
    fn append_to_list(
        &self,
        label: &[u8],
        key: &[u8],
        value: Vec<u8>,
    ) -> Result<(), WasmSqliteError> {
        let storage_key = Self::build_key(label, key.to_vec());
        let mut list: Vec<Vec<u8>> = match self.conn.get(&storage_key)? {
            Some(bytes) => serde_json::from_slice(&bytes)?,
            None => vec![],
        };
        list.push(value);
        let new_bytes = serde_json::to_vec(&list)?;
        self.conn.put(&storage_key, &new_bytes)
    }

    /// Remove a specific item from a list stored as JSON array of byte arrays.
    fn remove_from_list(
        &self,
        label: &[u8],
        key: &[u8],
        value: Vec<u8>,
    ) -> Result<(), WasmSqliteError> {
        let storage_key = Self::build_key(label, key.to_vec());
        let mut list: Vec<Vec<u8>> = match self.conn.get(&storage_key)? {
            Some(bytes) => serde_json::from_slice(&bytes)?,
            None => vec![],
        };
        if let Some(pos) = list.iter().position(|item| item == &value) {
            list.remove(pos);
        }
        let new_bytes = serde_json::to_vec(&list)?;
        self.conn.put(&storage_key, &new_bytes)
    }
}

// ---------------------------------------------------------------------------
// Label constants (matching openmls_memory_storage)
// ---------------------------------------------------------------------------

const KEY_PACKAGE_LABEL: &[u8] = b"KeyPackage";
const PSK_LABEL: &[u8] = b"Psk";
const ENCRYPTION_KEY_PAIR_LABEL: &[u8] = b"EncryptionKeyPair";
const SIGNATURE_KEY_PAIR_LABEL: &[u8] = b"SignatureKeyPair";
const EPOCH_KEY_PAIRS_LABEL: &[u8] = b"EpochKeyPairs";
const TREE_LABEL: &[u8] = b"Tree";
const GROUP_CONTEXT_LABEL: &[u8] = b"GroupContext";
const INTERIM_TRANSCRIPT_HASH_LABEL: &[u8] = b"InterimTranscriptHash";
const CONFIRMATION_TAG_LABEL: &[u8] = b"ConfirmationTag";
const JOIN_CONFIG_LABEL: &[u8] = b"MlsGroupJoinConfig";
const OWN_LEAF_NODES_LABEL: &[u8] = b"OwnLeafNodes";
const GROUP_STATE_LABEL: &[u8] = b"GroupState";
const QUEUED_PROPOSAL_LABEL: &[u8] = b"QueuedProposal";
const PROPOSAL_QUEUE_REFS_LABEL: &[u8] = b"ProposalQueueRefs";
const OWN_LEAF_NODE_INDEX_LABEL: &[u8] = b"OwnLeafNodeIndex";
const EPOCH_SECRETS_LABEL: &[u8] = b"EpochSecrets";
const RESUMPTION_PSK_STORE_LABEL: &[u8] = b"ResumptionPsk";
const MESSAGE_SECRETS_LABEL: &[u8] = b"MessageSecrets";

// ---------------------------------------------------------------------------
// Helper: epoch key pairs composite key
// ---------------------------------------------------------------------------

fn epoch_key_pairs_id(
    group_id: &impl traits::GroupId<CURRENT_VERSION>,
    epoch: &impl traits::EpochKey<CURRENT_VERSION>,
    leaf_index: u32,
) -> Result<Vec<u8>, WasmSqliteError> {
    let mut key = serde_json::to_vec(group_id)?;
    key.extend_from_slice(&serde_json::to_vec(epoch)?);
    key.extend_from_slice(&serde_json::to_vec(&leaf_index)?);
    Ok(key)
}

// ---------------------------------------------------------------------------
// StorageProvider implementation
// ---------------------------------------------------------------------------

impl StorageProvider<CURRENT_VERSION> for WasmSqliteStorage {
    type Error = WasmSqliteError;

    // -- Proposal queue --

    fn queue_proposal<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
        QueuedProposal: traits::QueuedProposal<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
        proposal: &QueuedProposal,
    ) -> Result<(), Self::Error> {
        let key = serde_json::to_vec(&(group_id, proposal_ref))?;
        let value = serde_json::to_vec(proposal)?;
        self.write_kv(QUEUED_PROPOSAL_LABEL, &key, value)?;

        let key = serde_json::to_vec(group_id)?;
        let value = serde_json::to_vec(proposal_ref)?;
        self.append_to_list(PROPOSAL_QUEUE_REFS_LABEL, &key, value)
    }

    fn queued_proposal_refs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<ProposalRef>, Self::Error> {
        self.read_list(
            PROPOSAL_QUEUE_REFS_LABEL,
            &serde_json::to_vec(group_id)?,
        )
    }

    fn queued_proposals<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
        QueuedProposal: traits::QueuedProposal<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<(ProposalRef, QueuedProposal)>, Self::Error> {
        let refs: Vec<ProposalRef> =
            self.read_list(PROPOSAL_QUEUE_REFS_LABEL, &serde_json::to_vec(group_id)?)?;

        refs.into_iter()
            .map(|proposal_ref| {
                let key = serde_json::to_vec(&(group_id, &proposal_ref))?;
                let proposal: QueuedProposal = self
                    .read_kv(QUEUED_PROPOSAL_LABEL, &key)?
                    .ok_or_else(|| {
                        WasmSqliteError::Serialization("missing queued proposal".into())
                    })?;
                Ok((proposal_ref, proposal))
            })
            .collect()
    }

    fn clear_proposal_queue<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        let refs: Vec<ProposalRef> =
            self.read_list(PROPOSAL_QUEUE_REFS_LABEL, &serde_json::to_vec(group_id)?)?;
        for proposal_ref in &refs {
            let key = serde_json::to_vec(&(group_id, proposal_ref))?;
            self.delete_kv(QUEUED_PROPOSAL_LABEL, &key)?;
        }
        self.delete_kv(PROPOSAL_QUEUE_REFS_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn remove_proposal<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
    ) -> Result<(), Self::Error> {
        let key = serde_json::to_vec(group_id)?;
        let value = serde_json::to_vec(proposal_ref)?;
        self.remove_from_list(PROPOSAL_QUEUE_REFS_LABEL, &key, value)?;

        let key = serde_json::to_vec(&(group_id, proposal_ref))?;
        self.delete_kv(QUEUED_PROPOSAL_LABEL, &key)
    }

    // -- Tree --

    fn write_tree<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        TreeSync: traits::TreeSync<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        tree: &TreeSync,
    ) -> Result<(), Self::Error> {
        self.write_kv(
            TREE_LABEL,
            &serde_json::to_vec(group_id)?,
            serde_json::to_vec(tree)?,
        )
    }

    fn tree<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        TreeSync: traits::TreeSync<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<TreeSync>, Self::Error> {
        self.read_kv(TREE_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn delete_tree<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_kv(TREE_LABEL, &serde_json::to_vec(group_id)?)
    }

    // -- Group context --

    fn write_context<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupContext: traits::GroupContext<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_context: &GroupContext,
    ) -> Result<(), Self::Error> {
        let key = Self::build_key_ser(GROUP_CONTEXT_LABEL, group_id)?;
        let value = serde_json::to_vec(group_context)?;
        self.conn.put(&key, &value)
    }

    fn group_context<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupContext: traits::GroupContext<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupContext>, Self::Error> {
        let key = Self::build_key_ser(GROUP_CONTEXT_LABEL, group_id)?;
        match self.conn.get(&key)? {
            Some(bytes) => Ok(serde_json::from_slice(&bytes)?),
            None => Ok(None),
        }
    }

    fn delete_context<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_kv(GROUP_CONTEXT_LABEL, &serde_json::to_vec(group_id)?)
    }

    // -- Interim transcript hash --

    fn write_interim_transcript_hash<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        InterimTranscriptHash: traits::InterimTranscriptHash<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        interim_transcript_hash: &InterimTranscriptHash,
    ) -> Result<(), Self::Error> {
        let key = Self::build_key_ser(INTERIM_TRANSCRIPT_HASH_LABEL, group_id)?;
        let value = serde_json::to_vec(interim_transcript_hash)?;
        self.conn.put(&key, &value)
    }

    fn interim_transcript_hash<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        InterimTranscriptHash: traits::InterimTranscriptHash<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<InterimTranscriptHash>, Self::Error> {
        let key = Self::build_key_ser(INTERIM_TRANSCRIPT_HASH_LABEL, group_id)?;
        match self.conn.get(&key)? {
            Some(bytes) => Ok(serde_json::from_slice(&bytes)?),
            None => Ok(None),
        }
    }

    fn delete_interim_transcript_hash<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_kv(
            INTERIM_TRANSCRIPT_HASH_LABEL,
            &serde_json::to_vec(group_id)?,
        )
    }

    // -- Confirmation tag --

    fn write_confirmation_tag<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ConfirmationTag: traits::ConfirmationTag<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        confirmation_tag: &ConfirmationTag,
    ) -> Result<(), Self::Error> {
        let key = Self::build_key_ser(CONFIRMATION_TAG_LABEL, group_id)?;
        let value = serde_json::to_vec(confirmation_tag)?;
        self.conn.put(&key, &value)
    }

    fn confirmation_tag<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ConfirmationTag: traits::ConfirmationTag<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ConfirmationTag>, Self::Error> {
        let key = Self::build_key_ser(CONFIRMATION_TAG_LABEL, group_id)?;
        match self.conn.get(&key)? {
            Some(bytes) => Ok(serde_json::from_slice(&bytes)?),
            None => Ok(None),
        }
    }

    fn delete_confirmation_tag<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_kv(
            CONFIRMATION_TAG_LABEL,
            &serde_json::to_vec(group_id)?,
        )
    }

    // -- Signature key pair --

    fn write_signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
        SignatureKeyPair: traits::SignatureKeyPair<CURRENT_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
        signature_key_pair: &SignatureKeyPair,
    ) -> Result<(), Self::Error> {
        let key = Self::build_key_ser(SIGNATURE_KEY_PAIR_LABEL, public_key)?;
        let value = serde_json::to_vec(signature_key_pair)?;
        self.conn.put(&key, &value)
    }

    fn signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
        SignatureKeyPair: traits::SignatureKeyPair<CURRENT_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
    ) -> Result<Option<SignatureKeyPair>, Self::Error> {
        let key = Self::build_key_ser(SIGNATURE_KEY_PAIR_LABEL, public_key)?;
        match self.conn.get(&key)? {
            Some(bytes) => Ok(serde_json::from_slice(&bytes)?),
            None => Ok(None),
        }
    }

    fn delete_signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
    ) -> Result<(), Self::Error> {
        self.delete_kv(
            SIGNATURE_KEY_PAIR_LABEL,
            &serde_json::to_vec(public_key)?,
        )
    }

    // -- Key package --

    fn write_key_package<
        HashReference: traits::HashReference<CURRENT_VERSION>,
        KeyPackage: traits::KeyPackage<CURRENT_VERSION>,
    >(
        &self,
        hash_ref: &HashReference,
        key_package: &KeyPackage,
    ) -> Result<(), Self::Error> {
        let key = serde_json::to_vec(hash_ref)?;
        let value = serde_json::to_vec(key_package)?;
        self.write_kv(KEY_PACKAGE_LABEL, &key, value)
    }

    fn key_package<
        KeyPackageRef: traits::HashReference<CURRENT_VERSION>,
        KeyPackage: traits::KeyPackage<CURRENT_VERSION>,
    >(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<Option<KeyPackage>, Self::Error> {
        self.read_kv(KEY_PACKAGE_LABEL, &serde_json::to_vec(hash_ref)?)
    }

    fn delete_key_package<KeyPackageRef: traits::HashReference<CURRENT_VERSION>>(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<(), Self::Error> {
        self.delete_kv(KEY_PACKAGE_LABEL, &serde_json::to_vec(hash_ref)?)
    }

    // -- PSK --

    fn write_psk<
        PskId: traits::PskId<CURRENT_VERSION>,
        PskBundle: traits::PskBundle<CURRENT_VERSION>,
    >(
        &self,
        psk_id: &PskId,
        psk: &PskBundle,
    ) -> Result<(), Self::Error> {
        self.write_kv(
            PSK_LABEL,
            &serde_json::to_vec(psk_id)?,
            serde_json::to_vec(psk)?,
        )
    }

    fn psk<
        PskBundle: traits::PskBundle<CURRENT_VERSION>,
        PskId: traits::PskId<CURRENT_VERSION>,
    >(
        &self,
        psk_id: &PskId,
    ) -> Result<Option<PskBundle>, Self::Error> {
        self.read_kv(PSK_LABEL, &serde_json::to_vec(psk_id)?)
    }

    fn delete_psk<PskKey: traits::PskId<CURRENT_VERSION>>(
        &self,
        psk_id: &PskKey,
    ) -> Result<(), Self::Error> {
        self.delete_kv(PSK_LABEL, &serde_json::to_vec(psk_id)?)
    }

    // -- Encryption key pair --

    fn write_encryption_key_pair<
        EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        public_key: &EncryptionKey,
        key_pair: &HpkeKeyPair,
    ) -> Result<(), Self::Error> {
        self.write_kv(
            ENCRYPTION_KEY_PAIR_LABEL,
            &serde_json::to_vec(public_key)?,
            serde_json::to_vec(key_pair)?,
        )
    }

    fn encryption_key_pair<
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
        EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>,
    >(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<Option<HpkeKeyPair>, Self::Error> {
        self.read_kv(
            ENCRYPTION_KEY_PAIR_LABEL,
            &serde_json::to_vec(public_key)?,
        )
    }

    fn delete_encryption_key_pair<EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>>(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<(), Self::Error> {
        self.delete_kv(
            ENCRYPTION_KEY_PAIR_LABEL,
            &serde_json::to_vec(public_key)?,
        )
    }

    // -- Group state --

    fn write_group_state<
        GroupState: traits::GroupState<CURRENT_VERSION>,
        GroupId: traits::GroupId<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_state: &GroupState,
    ) -> Result<(), Self::Error> {
        self.write_kv(
            GROUP_STATE_LABEL,
            &serde_json::to_vec(group_id)?,
            serde_json::to_vec(group_state)?,
        )
    }

    fn group_state<
        GroupState: traits::GroupState<CURRENT_VERSION>,
        GroupId: traits::GroupId<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupState>, Self::Error> {
        self.read_kv(GROUP_STATE_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn delete_group_state<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_kv(GROUP_STATE_LABEL, &serde_json::to_vec(group_id)?)
    }

    // -- Message secrets --

    fn write_message_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MessageSecrets: traits::MessageSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        message_secrets: &MessageSecrets,
    ) -> Result<(), Self::Error> {
        self.write_kv(
            MESSAGE_SECRETS_LABEL,
            &serde_json::to_vec(group_id)?,
            serde_json::to_vec(message_secrets)?,
        )
    }

    fn message_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MessageSecrets: traits::MessageSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<MessageSecrets>, Self::Error> {
        self.read_kv(MESSAGE_SECRETS_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn delete_message_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_kv(MESSAGE_SECRETS_LABEL, &serde_json::to_vec(group_id)?)
    }

    // -- Resumption PSK store --

    fn write_resumption_psk_store<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ResumptionPskStore: traits::ResumptionPskStore<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        resumption_psk_store: &ResumptionPskStore,
    ) -> Result<(), Self::Error> {
        self.write_kv(
            RESUMPTION_PSK_STORE_LABEL,
            &serde_json::to_vec(group_id)?,
            serde_json::to_vec(resumption_psk_store)?,
        )
    }

    fn resumption_psk_store<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ResumptionPskStore: traits::ResumptionPskStore<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ResumptionPskStore>, Self::Error> {
        self.read_kv(
            RESUMPTION_PSK_STORE_LABEL,
            &serde_json::to_vec(group_id)?,
        )
    }

    fn delete_all_resumption_psk_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_kv(
            RESUMPTION_PSK_STORE_LABEL,
            &serde_json::to_vec(group_id)?,
        )
    }

    // -- Own leaf index --

    fn write_own_leaf_index<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNodeIndex: traits::LeafNodeIndex<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        own_leaf_index: &LeafNodeIndex,
    ) -> Result<(), Self::Error> {
        self.write_kv(
            OWN_LEAF_NODE_INDEX_LABEL,
            &serde_json::to_vec(group_id)?,
            serde_json::to_vec(own_leaf_index)?,
        )
    }

    fn own_leaf_index<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNodeIndex: traits::LeafNodeIndex<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<LeafNodeIndex>, Self::Error> {
        self.read_kv(OWN_LEAF_NODE_INDEX_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn delete_own_leaf_index<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_kv(
            OWN_LEAF_NODE_INDEX_LABEL,
            &serde_json::to_vec(group_id)?,
        )
    }

    // -- Group epoch secrets --

    fn write_group_epoch_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupEpochSecrets: traits::GroupEpochSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_epoch_secrets: &GroupEpochSecrets,
    ) -> Result<(), Self::Error> {
        self.write_kv(
            EPOCH_SECRETS_LABEL,
            &serde_json::to_vec(group_id)?,
            serde_json::to_vec(group_epoch_secrets)?,
        )
    }

    fn group_epoch_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupEpochSecrets: traits::GroupEpochSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupEpochSecrets>, Self::Error> {
        self.read_kv(EPOCH_SECRETS_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn delete_group_epoch_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_kv(EPOCH_SECRETS_LABEL, &serde_json::to_vec(group_id)?)
    }

    // -- Encryption epoch key pairs --

    fn write_encryption_epoch_key_pairs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        EpochKey: traits::EpochKey<CURRENT_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
        key_pairs: &[HpkeKeyPair],
    ) -> Result<(), Self::Error> {
        let key = epoch_key_pairs_id(group_id, epoch, leaf_index)?;
        let value = serde_json::to_vec(key_pairs)?;
        self.write_kv(EPOCH_KEY_PAIRS_LABEL, &key, value)
    }

    fn encryption_epoch_key_pairs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        EpochKey: traits::EpochKey<CURRENT_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
    ) -> Result<Vec<HpkeKeyPair>, Self::Error> {
        let key = epoch_key_pairs_id(group_id, epoch, leaf_index)?;
        let storage_key = Self::build_key(EPOCH_KEY_PAIRS_LABEL, key);
        match self.conn.get(&storage_key)? {
            Some(bytes) => Ok(serde_json::from_slice(&bytes)?),
            None => Ok(vec![]),
        }
    }

    fn delete_encryption_epoch_key_pairs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        EpochKey: traits::EpochKey<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
    ) -> Result<(), Self::Error> {
        let key = epoch_key_pairs_id(group_id, epoch, leaf_index)?;
        self.delete_kv(EPOCH_KEY_PAIRS_LABEL, &key)
    }

    // -- MLS group join config --

    fn write_mls_join_config<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MlsGroupJoinConfig: traits::MlsGroupJoinConfig<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        config: &MlsGroupJoinConfig,
    ) -> Result<(), Self::Error> {
        self.write_kv(
            JOIN_CONFIG_LABEL,
            &serde_json::to_vec(group_id)?,
            serde_json::to_vec(config)?,
        )
    }

    fn mls_group_join_config<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MlsGroupJoinConfig: traits::MlsGroupJoinConfig<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<MlsGroupJoinConfig>, Self::Error> {
        self.read_kv(JOIN_CONFIG_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn delete_group_config<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_kv(JOIN_CONFIG_LABEL, &serde_json::to_vec(group_id)?)
    }

    // -- Own leaf nodes --

    fn append_own_leaf_node<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNode: traits::LeafNode<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        leaf_node: &LeafNode,
    ) -> Result<(), Self::Error> {
        let key = serde_json::to_vec(group_id)?;
        let value = serde_json::to_vec(leaf_node)?;
        self.append_to_list(OWN_LEAF_NODES_LABEL, &key, value)
    }

    fn own_leaf_nodes<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNode: traits::LeafNode<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<LeafNode>, Self::Error> {
        self.read_list(OWN_LEAF_NODES_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn delete_own_leaf_nodes<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_kv(OWN_LEAF_NODES_LABEL, &serde_json::to_vec(group_id)?)
    }
}

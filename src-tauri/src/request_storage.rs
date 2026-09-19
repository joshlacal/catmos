//! Replayable host projections only; canonical request authority lives in MLS storage.
use super::SqliteStorage;
use crate::request_commands::RequestDraft;
use catbird_mls::orchestrator::DirectRequestView;
use rusqlite::{params, OptionalExtension};
use serde::{de::DeserializeOwned, Serialize};

impl SqliteStorage {
    pub(super) fn create_request_tables(&self) -> rusqlite::Result<()> {
        self.conn.lock().unwrap().execute_batch("CREATE TABLE IF NOT EXISTS encrypted_request_projection (owner_did TEXT NOT NULL, record_kind TEXT NOT NULL CHECK(record_kind IN ('draft','view')), record_id TEXT NOT NULL, payload BLOB NOT NULL, PRIMARY KEY(owner_did,record_kind,record_id)); CREATE TABLE IF NOT EXISTS conversation_projection_aliases(owner_did TEXT NOT NULL,alias_id TEXT NOT NULL,canonical_id TEXT NOT NULL,group_id TEXT NOT NULL,payload BLOB NOT NULL,PRIMARY KEY(owner_did,alias_id)); CREATE TABLE IF NOT EXISTS conversation_projection_group_history(owner_did TEXT NOT NULL,conversation_id TEXT NOT NULL,group_id TEXT NOT NULL,epoch INTEGER NOT NULL,PRIMARY KEY(owner_did,conversation_id,group_id));")
    }
    pub(super) fn request_scope(owner: &str, kind: &str, id: &str) -> String {
        format!("catmos-request:{owner}:{kind}:{id}")
    }
    fn put_request<T: Serialize>(
        &self,
        owner: &str,
        kind: &str,
        id: &str,
        value: &T,
    ) -> Result<(), String> {
        let _owner = self.request_owner_guard(owner)?;
        let context = self
            .mls_context_snapshot()
            .ok_or("Protected request storage unavailable")?;
        let plain = serde_json::to_vec(value).map_err(|_| "Invalid request projection")?;
        let sealed = context
            .encrypt_message_payload(Self::request_scope(owner, kind, id), plain)
            .map_err(|_| "Unlock protected storage before saving requests")?;
        self.conn.lock().map_err(|_| "Request storage unavailable")?.execute(
            "INSERT INTO encrypted_request_projection(owner_did,record_kind,record_id,payload) VALUES(?1,?2,?3,?4) ON CONFLICT(owner_did,record_kind,record_id) DO UPDATE SET payload=excluded.payload",
            params![owner,kind,id,sealed]).map_err(|_| "Could not save request projection")?;
        Ok(())
    }
    pub(super) fn decode_request<T: DeserializeOwned>(
        &self,
        owner: &str,
        kind: &str,
        id: &str,
        sealed: Vec<u8>,
    ) -> Result<T, String> {
        let context = self
            .mls_context_snapshot()
            .ok_or("Protected request storage unavailable")?;
        let plain = context
            .decrypt_message_payload(Self::request_scope(owner, kind, id), sealed)
            .map_err(|_| "Request storage is locked or belongs to another account")?;
        serde_json::from_slice(&plain).map_err(|_| "Invalid protected request projection".into())
    }
    pub fn request_draft(&self, owner: &str, id: &str) -> Result<Option<RequestDraft>, String> {
        let _owner = self.request_owner_guard(owner)?;
        let sealed: Option<Vec<u8>> = self.conn.lock().map_err(|_| "Request storage unavailable")?.query_row(
            "SELECT payload FROM encrypted_request_projection WHERE owner_did=?1 AND record_kind='draft' AND record_id=?2",params![owner,id],|row|row.get(0)).optional().map_err(|_| "Could not load request draft")?;
        sealed
            .map(|bytes| self.decode_request(owner, "draft", id, bytes))
            .transpose()
    }
    pub fn request_drafts(&self, owner: &str) -> Result<Vec<RequestDraft>, String> {
        let _owner = self.request_owner_guard(owner)?;
        let rows: Vec<(String, Vec<u8>)> = {
            let conn = self
                .conn
                .lock()
                .map_err(|_| "Request storage unavailable")?;
            let mut statement=conn.prepare("SELECT record_id,payload FROM encrypted_request_projection WHERE owner_did=?1 AND record_kind='draft' ORDER BY record_id").map_err(|_| "Could not load request drafts")?;
            let rows = statement
                .query_map([owner], |r| Ok((r.get(0)?, r.get(1)?)))
                .map_err(|_| "Could not load request drafts")?;
            rows.collect::<rusqlite::Result<_>>()
                .map_err(|_| "Could not load request drafts")?
        };
        rows.into_iter()
            .map(|(id, bytes)| self.decode_request(owner, "draft", &id, bytes))
            .collect()
    }
    pub fn save_request_draft(&self, owner: &str, draft: &RequestDraft) -> Result<(), String> {
        self.put_request(owner, "draft", &draft.input.draft_id, draft)
    }
    pub fn save_request_view(&self, owner: &str, view: &DirectRequestView) -> Result<(), String> {
        self.put_request(owner, "view", &view.conversation_id, view)
    }
}

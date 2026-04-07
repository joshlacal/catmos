//! WasmStorageBackend — implements MLSStorageBackend using encrypted SQLite.
//!
//! Replaces the previous IndexedDB implementation. All data is now stored in
//! the same encrypted SQLite database (OPFS SAH VFS + sqlite3mc ChaCha20) as
//! OpenMLS state, via the shared `SqliteConn` from `sqlite_conn.rs`.
//!
//! # Migration Note
//!
//! No migration from the old IndexedDB database (`catmos-mls`) is performed.
//! Users with existing data will need to re-login. The old IndexedDB databases
//! are intentionally left in place (browser will garbage-collect them or the
//! user can clear site data).
//!
//! # Schema
//!
//! ```sql
//! CREATE TABLE IF NOT EXISTS conversations (...);
//! CREATE TABLE IF NOT EXISTS messages (...);
//! CREATE TABLE IF NOT EXISTS sync_cursors (...);
//! CREATE TABLE IF NOT EXISTS group_states (...);
//! ```

use async_trait::async_trait;
use catbird_mls::orchestrator::error::{OrchestratorError, Result};
use catbird_mls::orchestrator::storage::MLSStorageBackend;
use catbird_mls::orchestrator::types::*;
use std::rc::Rc;

use crate::sqlite_conn::SqliteConn;

pub struct WasmStorageBackend {
    conn: Rc<SqliteConn>,
}

impl WasmStorageBackend {
    /// Create a new storage backend wrapping the shared SQLite connection.
    ///
    /// The caller must have already called `ensure_schema()` on this connection.
    pub fn new(conn: Rc<SqliteConn>) -> Self {
        Self { conn }
    }

    /// Create all required tables on the shared connection.
    pub fn ensure_schema(conn: &SqliteConn) -> std::result::Result<(), String> {
        conn.exec_raw(
            "CREATE TABLE IF NOT EXISTS conversations (
                conversation_id TEXT NOT NULL,
                user_did        TEXT NOT NULL,
                group_id        TEXT NOT NULL,
                join_method     TEXT,
                join_epoch      INTEGER,
                needs_rejoin    INTEGER DEFAULT 0,
                state           TEXT DEFAULT 'active',
                PRIMARY KEY (conversation_id, user_did)
            );",
        )
        .map_err(|e| format!("conversations table: {}", e))?;

        // Migration: add state column for existing databases.
        let _ = conn.exec_raw(
            "ALTER TABLE conversations ADD COLUMN state TEXT DEFAULT 'active';",
        );

        conn.exec_raw(
            "CREATE TABLE IF NOT EXISTS messages (
                id              TEXT PRIMARY KEY,
                conversation_id TEXT NOT NULL,
                sender_did      TEXT NOT NULL,
                text            TEXT NOT NULL,
                sequence_number INTEGER NOT NULL,
                epoch           INTEGER NOT NULL,
                created_at      TEXT NOT NULL,
                is_own          INTEGER DEFAULT 0,
                delivery_status TEXT DEFAULT 'delivered'
            );",
        )
        .map_err(|e| format!("messages table: {}", e))?;

        conn.exec_raw(
            "CREATE INDEX IF NOT EXISTS idx_messages_convo_seq
                ON messages(conversation_id, sequence_number);",
        )
        .map_err(|e| format!("messages index: {}", e))?;

        conn.exec_raw(
            "CREATE TABLE IF NOT EXISTS sync_cursors (
                user_did TEXT PRIMARY KEY,
                conversations_cursor TEXT,
                messages_cursor      TEXT
            );",
        )
        .map_err(|e| format!("sync_cursors table: {}", e))?;

        conn.exec_raw(
            "CREATE TABLE IF NOT EXISTS group_states (
                group_id        TEXT PRIMARY KEY,
                conversation_id TEXT NOT NULL,
                epoch           INTEGER NOT NULL,
                members_json    TEXT NOT NULL
            );",
        )
        .map_err(|e| format!("group_states table: {}", e))?;

        Ok(())
    }

    fn store_err(e: impl std::fmt::Debug) -> OrchestratorError {
        OrchestratorError::Storage(format!("{:?}", e))
    }

    /// List all group IDs from the `group_states` table.
    ///
    /// Returns the group_id strings stored by `set_group_state`.
    pub fn list_group_ids(&self) -> std::result::Result<Vec<String>, String> {
        let rows = self
            .conn
            .query_text("SELECT group_id FROM group_states;", &[], 1)
            .map_err(|e| format!("list_group_ids: {}", e))?;
        Ok(rows
            .into_iter()
            .filter_map(|row| row.into_iter().next().flatten())
            .collect())
    }
}

#[async_trait(?Send)]
impl MLSStorageBackend for WasmStorageBackend {
    async fn ensure_conversation_exists(
        &self,
        user_did: &str,
        conversation_id: &str,
        group_id: &str,
    ) -> Result<()> {
        // Check if exists first
        let exists = self
            .conn
            .exists(
                "SELECT 1 FROM conversations WHERE conversation_id = ?1 AND user_did = ?2",
                &[(1, conversation_id), (2, user_did)],
            )
            .map_err(Self::store_err)?;

        if exists {
            return Ok(());
        }

        self.conn
            .exec_with_text_params(
                "INSERT INTO conversations (conversation_id, user_did, group_id, needs_rejoin)
                 VALUES (?1, ?2, ?3, 0)",
                &[(1, conversation_id), (2, user_did), (3, group_id)],
            )
            .map_err(Self::store_err)
    }

    async fn update_join_info(
        &self,
        conversation_id: &str,
        user_did: &str,
        join_method: JoinMethod,
        join_epoch: u64,
    ) -> Result<()> {
        let method_str = serde_json::to_string(&join_method)
            .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        self.conn
            .exec_with_mixed_params(
                "UPDATE conversations SET join_method = ?1, join_epoch = ?2
                 WHERE conversation_id = ?3 AND user_did = ?4",
                &[(1, &method_str), (3, conversation_id), (4, user_did)],
                &[(2, join_epoch as i64)],
            )
            .map_err(Self::store_err)
    }

    async fn get_conversation(
        &self,
        user_did: &str,
        conversation_id: &str,
    ) -> Result<Option<ConversationView>> {
        // Query: group_id (0)
        let rows = self
            .conn
            .query_text(
                "SELECT group_id FROM conversations
                 WHERE conversation_id = ?1 AND user_did = ?2",
                &[(1, conversation_id), (2, user_did)],
                1,
            )
            .map_err(Self::store_err)?;

        if rows.is_empty() {
            return Ok(None);
        }

        let group_id = rows[0][0].clone().unwrap_or_default();

        // Look up group state for epoch/members
        let gs_rows = self
            .conn
            .query_text(
                "SELECT epoch, members_json FROM group_states WHERE group_id = ?1",
                &[(1, &group_id)],
                2,
            )
            .map_err(Self::store_err)?;

        let (epoch, members) = if gs_rows.is_empty() {
            (0u64, vec![])
        } else {
            let epoch: u64 = gs_rows[0][0]
                .as_ref()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            let members: Vec<MemberView> = gs_rows[0][1]
                .as_ref()
                .and_then(|s| serde_json::from_str(s).ok())
                .unwrap_or_default();
            (epoch, members)
        };

        Ok(Some(ConversationView {
            group_id,
            epoch,
            members,
            metadata: None,
            created_at: None,
            updated_at: None,
        }))
    }

    async fn list_conversations(&self, user_did: &str) -> Result<Vec<ConversationView>> {
        // Get all conversations for this user
        let rows = self
            .conn
            .query_text(
                "SELECT conversation_id, group_id FROM conversations WHERE user_did = ?1",
                &[(1, user_did)],
                2,
            )
            .map_err(Self::store_err)?;

        let mut views = Vec::with_capacity(rows.len());
        for row in rows {
            let group_id = row[1].clone().unwrap_or_default();

            let gs_rows = self
                .conn
                .query_text(
                    "SELECT epoch, members_json FROM group_states WHERE group_id = ?1",
                    &[(1, &group_id)],
                    2,
                )
                .map_err(Self::store_err)?;

            let (epoch, members) = if gs_rows.is_empty() {
                (0u64, vec![])
            } else {
                let epoch: u64 = gs_rows[0][0]
                    .as_ref()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                let members: Vec<MemberView> = gs_rows[0][1]
                    .as_ref()
                    .and_then(|s| serde_json::from_str(s).ok())
                    .unwrap_or_default();
                (epoch, members)
            };

            views.push(ConversationView {
                group_id,
                epoch,
                members,
                metadata: None,
                created_at: None,
                updated_at: None,
            });
        }
        Ok(views)
    }

    async fn delete_conversations(&self, user_did: &str, ids: &[&str]) -> Result<()> {
        for id in ids {
            self.conn
                .exec_with_text_params(
                    "DELETE FROM conversations WHERE conversation_id = ?1 AND user_did = ?2",
                    &[(1, id), (2, user_did)],
                )
                .map_err(Self::store_err)?;
        }
        Ok(())
    }

    async fn set_conversation_state(
        &self,
        conversation_id: &str,
        state: ConversationState,
    ) -> Result<()> {
        let state_str = match state {
            ConversationState::Initializing => "initializing",
            ConversationState::Active => "active",
            ConversationState::NeedsRejoin => "needs_rejoin",
            ConversationState::Failed => "failed",
        };
        self.conn
            .exec_with_text_params(
                "UPDATE conversations SET state = ?1 WHERE conversation_id = ?2",
                &[(1, state_str), (2, conversation_id)],
            )
            .map_err(Self::store_err)
    }

    async fn mark_needs_rejoin(&self, conversation_id: &str) -> Result<()> {
        self.conn
            .exec_with_text_params(
                "UPDATE conversations SET needs_rejoin = 1 WHERE conversation_id = ?1",
                &[(1, conversation_id)],
            )
            .map_err(Self::store_err)
    }

    async fn needs_rejoin(&self, conversation_id: &str) -> Result<bool> {
        let rows = self
            .conn
            .query_text(
                "SELECT needs_rejoin FROM conversations WHERE conversation_id = ?1 LIMIT 1",
                &[(1, conversation_id)],
                1,
            )
            .map_err(Self::store_err)?;

        if rows.is_empty() {
            return Ok(false);
        }
        Ok(rows[0][0].as_deref() == Some("1"))
    }

    async fn clear_rejoin_flag(&self, conversation_id: &str) -> Result<()> {
        self.conn
            .exec_with_text_params(
                "UPDATE conversations SET needs_rejoin = 0 WHERE conversation_id = ?1",
                &[(1, conversation_id)],
            )
            .map_err(Self::store_err)
    }

    async fn store_message(&self, message: &Message) -> Result<()> {
        let delivery_status_str = message
            .delivery_status
            .as_ref()
            .map(|ds| serde_json::to_string(ds).unwrap_or_else(|_| "\"delivered\"".to_string()))
            .unwrap_or_else(|| "\"delivered\"".to_string());

        let timestamp_str = message.timestamp.to_rfc3339();
        let is_own_str = if message.is_own { "1" } else { "0" };

        self.conn
            .exec_with_mixed_params(
                "INSERT OR REPLACE INTO messages
                 (id, conversation_id, sender_did, text, sequence_number, epoch, created_at, is_own, delivery_status)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                &[
                    (1, &*message.id),
                    (2, &*message.conversation_id),
                    (3, &*message.sender_did),
                    (4, &*message.text),
                    (7, &*timestamp_str),
                    (8, is_own_str),
                    (9, &*delivery_status_str),
                ],
                &[
                    (5, message.sequence_number as i64),
                    (6, message.epoch as i64),
                ],
            )
            .map_err(Self::store_err)
    }

    async fn get_messages(
        &self,
        conversation_id: &str,
        limit: u32,
        before_sequence: Option<u64>,
    ) -> Result<Vec<Message>> {
        let limit_str = limit.to_string();

        let rows = if let Some(before) = before_sequence {
            self.conn
                .query_text_mixed(
                    "SELECT id, conversation_id, sender_did, text, sequence_number, epoch,
                            created_at, is_own, delivery_status
                     FROM messages
                     WHERE conversation_id = ?1 AND sequence_number < ?2
                     ORDER BY sequence_number DESC
                     LIMIT ?3",
                    &[(1, conversation_id)],
                    &[(2, before as i64), (3, limit as i64)],
                    9,
                )
                .map_err(Self::store_err)?
        } else {
            self.conn
                .query_text_mixed(
                    "SELECT id, conversation_id, sender_did, text, sequence_number, epoch,
                            created_at, is_own, delivery_status
                     FROM messages
                     WHERE conversation_id = ?1
                     ORDER BY sequence_number DESC
                     LIMIT ?2",
                    &[(1, conversation_id)],
                    &[(2, limit as i64)],
                    9,
                )
                .map_err(Self::store_err)?
        };

        let _ = limit_str; // suppress unused warning

        let mut messages: Vec<Message> = rows
            .into_iter()
            .map(|row| {
                let id = row[0].clone().unwrap_or_default();
                let convo_id = row[1].clone().unwrap_or_default();
                let sender = row[2].clone().unwrap_or_default();
                let text = row[3].clone().unwrap_or_default();
                let seq: u64 = row[4].as_ref().and_then(|s| s.parse().ok()).unwrap_or(0);
                let epoch: u64 = row[5].as_ref().and_then(|s| s.parse().ok()).unwrap_or(0);
                let created_at = row[6].clone().unwrap_or_default();
                let is_own = row[7].as_deref() == Some("1");
                let delivery_status: Option<DeliveryStatus> = row[8]
                    .as_ref()
                    .and_then(|s| serde_json::from_str(s).ok());

                let timestamp = created_at
                    .parse::<chrono::DateTime<chrono::Utc>>()
                    .unwrap_or_else(|_| chrono::Utc::now());

                Message {
                    id,
                    conversation_id: convo_id,
                    sender_did: sender,
                    text,
                    timestamp,
                    epoch,
                    sequence_number: seq,
                    is_own,
                    delivery_status,
                    payload_json: None,
                }
            })
            .collect();

        // Reverse to chronological order (we fetched DESC for LIMIT)
        messages.reverse();
        Ok(messages)
    }

    async fn message_exists(&self, message_id: &str) -> Result<bool> {
        self.conn
            .exists(
                "SELECT 1 FROM messages WHERE id = ?1",
                &[(1, message_id)],
            )
            .map_err(Self::store_err)
    }

    async fn get_sync_cursor(&self, user_did: &str) -> Result<SyncCursor> {
        let rows = self
            .conn
            .query_text(
                "SELECT conversations_cursor, messages_cursor FROM sync_cursors WHERE user_did = ?1",
                &[(1, user_did)],
                2,
            )
            .map_err(Self::store_err)?;

        if rows.is_empty() {
            return Ok(SyncCursor::default());
        }

        Ok(SyncCursor {
            conversations_cursor: rows[0][0].clone(),
            messages_cursor: rows[0][1].clone(),
        })
    }

    async fn set_sync_cursor(&self, user_did: &str, cursor: &SyncCursor) -> Result<()> {
        let convos_cursor = cursor
            .conversations_cursor
            .as_deref()
            .unwrap_or("");
        let msgs_cursor = cursor.messages_cursor.as_deref().unwrap_or("");
        self.conn
            .exec_with_text_params(
                "INSERT OR REPLACE INTO sync_cursors (user_did, conversations_cursor, messages_cursor)
                 VALUES (?1, ?2, ?3)",
                &[(1, user_did), (2, convos_cursor), (3, msgs_cursor)],
            )
            .map_err(Self::store_err)
    }

    async fn set_group_state(&self, state: &GroupState) -> Result<()> {
        let members_json = serde_json::to_string(&state.members)
            .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        self.conn
            .exec_with_mixed_params(
                "INSERT OR REPLACE INTO group_states (group_id, conversation_id, epoch, members_json)
                 VALUES (?1, ?2, ?3, ?4)",
                &[
                    (1, &*state.group_id),
                    (2, &*state.conversation_id),
                    (4, &*members_json),
                ],
                &[(3, state.epoch as i64)],
            )
            .map_err(Self::store_err)
    }

    async fn get_group_state(&self, group_id: &str) -> Result<Option<GroupState>> {
        let rows = self
            .conn
            .query_text(
                "SELECT conversation_id, epoch, members_json FROM group_states WHERE group_id = ?1",
                &[(1, group_id)],
                3,
            )
            .map_err(Self::store_err)?;

        if rows.is_empty() {
            return Ok(None);
        }

        let conversation_id = rows[0][0].clone().unwrap_or_default();
        let epoch: u64 = rows[0][1]
            .as_ref()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let members: Vec<String> = rows[0][2]
            .as_ref()
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or_default();

        Ok(Some(GroupState {
            group_id: group_id.to_string(),
            conversation_id,
            epoch,
            members,
        }))
    }

    async fn delete_group_state(&self, group_id: &str) -> Result<()> {
        self.conn
            .exec_with_text_params(
                "DELETE FROM group_states WHERE group_id = ?1",
                &[(1, group_id)],
            )
            .map_err(Self::store_err)
    }
}

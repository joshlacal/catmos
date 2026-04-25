use async_trait::async_trait;
use rusqlite::Connection;
use std::sync::Mutex;

use catbird_mls::orchestrator::error::{OrchestratorError, Result};
use catbird_mls::orchestrator::storage::MLSStorageBackend;
use catbird_mls::orchestrator::types::*;

/// SQLite-backed storage for Catmos desktop.
pub struct SqliteStorage {
    conn: Mutex<Connection>,
}

impl SqliteStorage {
    pub fn new(db_path: &str, encryption_key: &str) -> std::result::Result<Self, rusqlite::Error> {
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
        let storage = Self {
            conn: Mutex::new(conn),
        };
        storage.create_tables()?;
        Ok(storage)
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
                created_at TEXT,
                updated_at TEXT,
                reset_new_group_id TEXT,
                reset_generation INTEGER,
                reset_notified_at_ms INTEGER,
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
            ",
        )?;
        Self::ensure_messages_delivery_status_column(&conn)?;
        Self::ensure_conversations_reset_pending_columns(&conn)?;
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
        .and_then(
            |(new_group_id, reset_generation, notified_at_ms)| match (
                new_group_id,
                reset_generation,
                notified_at_ms,
            ) {
                (Some(new_group_id), Some(reset_generation), Some(notified_at_ms)) => {
                    Some(ConversationState::ResetPending {
                        new_group_id,
                        reset_generation: reset_generation as i32,
                        notified_at_ms,
                    })
                }
                _ => None,
            },
        )
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
                "SELECT conversation_id, group_id, epoch, members_json, metadata_json, created_at, updated_at
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
                })
            })
            .ok();

        Ok(result)
    }

    async fn list_conversations(&self, user_did: &str) -> Result<Vec<ConversationView>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT conversation_id, group_id, epoch, members_json, metadata_json, created_at, updated_at
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
            "UPDATE conversations SET state = ?1 WHERE conversation_id = ?2",
            rusqlite::params![state_str, conversation_id],
        )
        .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        Ok(())
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
        serde_json::from_str::<ConversationState>(&s)
            .map(Some)
            .map_err(|e| OrchestratorError::Storage(e.to_string()))
    }

    async fn mark_needs_rejoin(&self, conversation_id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE conversations SET needs_rejoin = 1 WHERE conversation_id = ?1",
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

    async fn clear_reset_pending(&self, conversation_id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE conversations
             SET reset_new_group_id = NULL,
                 reset_generation = NULL,
                 reset_notified_at_ms = NULL
             WHERE conversation_id = ?1",
            rusqlite::params![conversation_id],
        )
        .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn store_message(&self, message: &Message) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let delivery_status_json = message
            .delivery_status
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        conn.execute(
            "INSERT OR REPLACE INTO messages (id, conversation_id, sender_did, text, timestamp, epoch, sequence_number, is_own, delivery_status_json, payload_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            rusqlite::params![
                message.id,
                message.conversation_id,
                message.sender_did,
                message.text,
                message.timestamp.to_rfc3339(),
                message.epoch,
                message.sequence_number,
                message.is_own as i32,
                delivery_status_json,
                message.payload_json,
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
        let conn = self.conn.lock().unwrap();
        let mut result = Vec::new();

        if let Some(before) = before_sequence {
            let mut stmt = conn
                .prepare(
                    "SELECT id, conversation_id, sender_did, text, timestamp, epoch, sequence_number, is_own, delivery_status_json, payload_json
                     FROM messages WHERE conversation_id = ?1 AND sequence_number < ?2
                     ORDER BY sequence_number DESC LIMIT ?3",
                )
                .map_err(|e| OrchestratorError::Storage(e.to_string()))?;

            let rows = stmt
                .query_map(rusqlite::params![conversation_id, before, limit], |row| {
                    row_to_message(row)
                })
                .map_err(|e| OrchestratorError::Storage(e.to_string()))?;

            for row in rows {
                result.push(row.map_err(|e| OrchestratorError::Storage(e.to_string()))?);
            }
        } else {
            let mut stmt = conn
                .prepare(
                    "SELECT id, conversation_id, sender_did, text, timestamp, epoch, sequence_number, is_own, delivery_status_json, payload_json
                     FROM messages WHERE conversation_id = ?1
                     ORDER BY sequence_number DESC LIMIT ?2",
                )
                .map_err(|e| OrchestratorError::Storage(e.to_string()))?;

            let rows = stmt
                .query_map(rusqlite::params![conversation_id, limit], |row| {
                    row_to_message(row)
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

    async fn store_pending_message(
        &self,
        conversation_id: &str,
        message_id: &str,
    ) -> Result<()> {
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
}

fn row_to_message(row: &rusqlite::Row) -> rusqlite::Result<Message> {
    let id: String = row.get(0)?;
    let conversation_id: String = row.get(1)?;
    let sender_did: String = row.get(2)?;
    let text: String = row.get(3)?;
    let timestamp_str: String = row.get(4)?;
    let epoch: u64 = row.get(5)?;
    let sequence_number: u64 = row.get(6)?;
    let is_own: i32 = row.get(7)?;
    let delivery_status_json: Option<String> = row.get(8)?;
    let payload_json: Option<String> = row.get(9)?;

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

    Ok(Message {
        id,
        conversation_id,
        sender_did,
        text,
        timestamp,
        epoch,
        sequence_number,
        is_own: is_own != 0,
        delivery_status,
        payload_json,
    })
}

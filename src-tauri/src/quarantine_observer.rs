//! Layer 3 MLS quarantine event observer for the Tauri host.
//!
//! Bridges the orchestrator's [`OrchestratorEventObserver`] callbacks
//! (`on_conversation_quarantined` / `on_conversation_quarantine_cleared`) to
//! Tauri events the SvelteKit frontend listens for. The frontend uses these
//! to:
//!
//! - Show a "Conversation paused" banner in the conversation view.
//! - Disable the message composer.
//! - Surface suspected DIDs in the info panel.
//!
//! The observer is registered once during Tauri's `setup` hook so we have an
//! [`tauri::AppHandle`] available to emit events from. Persistence already
//! happens inside the orchestrator via `MLSStorageBackend::mark_quarantined`
//! / `clear_quarantine` (implemented in [`crate::storage`]); this observer is
//! purely the wire between Rust and the renderer.
//!
//! See: catbird-mls `src/orchestrator/event_observer.rs`,
//! catbird-mls Layer 3 plan §3 in `~/.claude/plans/rippling-greeting-whale.md`.
use catbird_mls::orchestrator::event_observer::OrchestratorEventObserver;
use catbird_mls::orchestrator::types::{QuarantineExitReason, QuarantineReason};
use serde::Serialize;
use tauri::{AppHandle, Emitter};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuarantineEnteredPayload {
    pub convo_id: String,
    /// snake_case tag from `QuarantineReason::tag()`. Stable wire format.
    pub reason_tag: String,
    /// DIDs Signal C identified as the source of repeated peer-bad commits.
    /// Empty when only Signal D (framing-failure burst) tripped quarantine.
    pub suspected_dids: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuarantineClearedPayload {
    pub convo_id: String,
    /// snake_case tag from `QuarantineExitReason::tag()`.
    pub via_tag: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryStorageWriteFailedPayload {
    pub convo_id: String,
    /// Storage-trait method name that failed (e.g. `mark_needs_rejoin`).
    pub operation: String,
    pub error: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialBindingWarningPayload {
    /// `"<none>"` when no conversation is in scope yet (e.g. key-package
    /// fetch during group creation).
    pub convo_id: String,
    /// ADR-009 D5 operation tag (`fetch`, `message`, ...).
    pub operation: String,
    pub expected_did: String,
    pub claimed_identity: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SequencerEquivocationPayload {
    pub convo_id: String,
    pub epoch: i32,
    /// Hex-encoded commit hashes from the two conflicting receipts.
    pub stored_commit_hash_hex: String,
    pub new_commit_hash_hex: String,
    pub sequencer_did: String,
}

/// Tauri-side observer. Cheap to clone (just an `AppHandle`), and
/// `tauri::AppHandle` is `Send + Sync`, satisfying the orchestrator's
/// non-WASM observer trait bound.
pub struct QuarantineObserver {
    app: AppHandle,
}

impl QuarantineObserver {
    pub fn new(app: AppHandle) -> Self {
        Self { app }
    }
}

impl OrchestratorEventObserver for QuarantineObserver {
    fn on_conversation_quarantined(
        &self,
        convo_id: &str,
        reason: QuarantineReason,
        suspected_dids: Vec<String>,
    ) {
        let payload = QuarantineEnteredPayload {
            convo_id: convo_id.to_string(),
            reason_tag: reason.tag().to_string(),
            suspected_dids,
        };
        if let Err(e) = self.app.emit("mls://quarantined", &payload) {
            tracing::warn!(
                convo_id,
                error = %e,
                "Failed to emit mls://quarantined to renderer"
            );
        }
    }

    fn on_conversation_quarantine_cleared(&self, convo_id: &str, via: QuarantineExitReason) {
        let payload = QuarantineClearedPayload {
            convo_id: convo_id.to_string(),
            via_tag: via.tag().to_string(),
        };
        if let Err(e) = self.app.emit("mls://quarantine-cleared", &payload) {
            tracing::warn!(
                convo_id,
                error = %e,
                "Failed to emit mls://quarantine-cleared to renderer"
            );
        }
    }

    fn on_recovery_storage_write_failed(&self, convo_id: &str, operation: &str, error: &str) {
        // WS-5.2: a failed recovery-critical storage write silently cancels
        // deferred recovery across restart — never let it vanish.
        tracing::error!(
            convo_id,
            operation,
            error,
            "Recovery-critical storage write failed in orchestrator"
        );
        let payload = RecoveryStorageWriteFailedPayload {
            convo_id: convo_id.to_string(),
            operation: operation.to_string(),
            error: error.to_string(),
        };
        if let Err(e) = self
            .app
            .emit("mls://recovery-storage-write-failed", &payload)
        {
            tracing::warn!(
                convo_id,
                error = %e,
                "Failed to emit mls://recovery-storage-write-failed to renderer"
            );
        }
    }

    fn on_credential_binding_warning(
        &self,
        convo_id: &str,
        operation: &str,
        expected_did: &str,
        claimed_identity: &str,
        reason: &str,
    ) {
        // WS-3 stage 1 (ADR-009 D5): warn-and-allow — the operation
        // continued, but field data on these warnings gates the enforce
        // flip. Never let one vanish.
        tracing::error!(
            convo_id,
            operation,
            expected_did,
            claimed_identity,
            reason,
            "Credential-binding check failed in warn-and-allow mode"
        );
        let payload = CredentialBindingWarningPayload {
            convo_id: convo_id.to_string(),
            operation: operation.to_string(),
            expected_did: expected_did.to_string(),
            claimed_identity: claimed_identity.to_string(),
            reason: reason.to_string(),
        };
        if let Err(e) = self.app.emit("mls://credential-binding-warning", &payload) {
            tracing::warn!(
                convo_id,
                error = %e,
                "Failed to emit mls://credential-binding-warning to renderer"
            );
        }
    }

    fn on_sequencer_equivocation(
        &self,
        convo_id: &str,
        epoch: i32,
        stored_commit_hash_hex: &str,
        new_commit_hash_hex: &str,
        sequencer_did: &str,
    ) {
        // WS-3 stage 1 (ADR-009 D8 / E3): detection-only — two receipts for
        // the same (conversation, epoch) carried different commit hashes.
        tracing::error!(
            convo_id,
            epoch,
            stored_commit_hash_hex,
            new_commit_hash_hex,
            sequencer_did,
            "Sequencer equivocation detected"
        );
        let payload = SequencerEquivocationPayload {
            convo_id: convo_id.to_string(),
            epoch,
            stored_commit_hash_hex: stored_commit_hash_hex.to_string(),
            new_commit_hash_hex: new_commit_hash_hex.to_string(),
            sequencer_did: sequencer_did.to_string(),
        };
        if let Err(e) = self.app.emit("mls://sequencer-equivocation", &payload) {
            tracing::warn!(
                convo_id,
                error = %e,
                "Failed to emit mls://sequencer-equivocation to renderer"
            );
        }
    }
}

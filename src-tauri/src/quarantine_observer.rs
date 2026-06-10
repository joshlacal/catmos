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
}

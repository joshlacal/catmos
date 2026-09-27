//! Desktop request adapter. The shared engine alone owns intent, crypto and consent.
use crate::AppState;
use catbird_mls::orchestrator::{
    direct_requests::DirectRequestIntent, CredentialStore, DirectRequestInput, DirectRequestOutcome,
    DirectRequestView, GroupInvitationReference, MlsCryptoContext, OrchestratorError, RequestConsent,
};
use catbird_mls::MLSError;
use serde::{Deserialize, Serialize};
use tauri::State;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestDraft {
    pub input: DirectRequestInput,
    pub recipient_label: String,
    pub phase: String,
    pub outcome: Option<DirectRequestOutcome>,
    pub archived: bool,
    #[serde(default)]
    pub note_delivery: Option<NoteDelivery>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NoteDelivery {
    pub conversation_id: String,
    pub message_id: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestWorkspace {
    pub owner_did: String,
    pub delivery_enabled: Option<bool>,
    pub discovery_error: Option<String>,
    pub drafts: Vec<RequestDraft>,
    pub requests: Vec<DirectRequestView>,
}

#[tauri::command]
pub async fn get_request_workspace(
    state: State<'_, AppState>,
    owner_did: String,
    owner_revision: String,
) -> Result<RequestWorkspace, String> {
    let _scope = capture_effect_owner(&state.request_scope, &owner_did, &owner_revision, || {
        state
            .api_client
            .current_session()
            .map_err(|_| "Sign in to continue".to_string())
    })
    .await?;
    let session = state
        .api_client
        .current_session()
        .map_err(|_| "Sign in to view requests")?;
    if session.actor_did != owner_did {
        return Err("Account changed".into());
    }
    // Shared synchronization imports and verifies whole request/control entries;
    // it alone changes consent. Retained views remain readable while offline.
    let discovery_error = state
        .orchestrator
        .sync_with_server(false)
        .await
        .err()
        .map(|_| {
            "New requests could not be checked. Showing verified requests already on this device."
                .to_string()
        });
    let requests = state
        .orchestrator
        .list_direct_request_views()
        .await
        .map_err(|_| "Request history is unavailable")?;
    for view in &requests {
        state
            .orchestrator
            .storage()
            .save_request_view(&session.actor_did, view)?;
    }
    let drafts = state
        .orchestrator
        .storage()
        .request_drafts(&session.actor_did)?;
    state
        .api_client
        .ensure_session_current(&session)
        .map_err(|_| "Account changed")?;
    let delivery_enabled = state
        .orchestrator
        .get_direct_request_delivery_enabled()
        .await
        .map_err(|_| "Request delivery preference is unavailable")?;
    state
        .api_client
        .ensure_session_current(&session)
        .map_err(|_| "Account changed")?;
    Ok(RequestWorkspace {
        delivery_enabled,
        discovery_error,
        owner_did: session.actor_did,
        drafts,
        requests,
    })
}

#[tauri::command]
pub async fn save_request_draft(
    state: State<'_, AppState>,
    owner_did: String,
    owner_revision: String,
    input: DirectRequestInput,
    recipient_label: String,
) -> Result<RequestDraft, String> {
    let _scope = capture_effect_owner(&state.request_scope, &owner_did, &owner_revision, || {
        state
            .api_client
            .current_session()
            .map_err(|_| "Sign in to continue".to_string())
    })
    .await?;
    let session = state
        .api_client
        .current_session()
        .map_err(|_| "Sign in to save a draft")?;
    if session.actor_did != owner_did {
        return Err("Account changed".into());
    }
    if uuid::Uuid::parse_str(&input.draft_id).is_err()
        || input.recipient_did == session.actor_did
        || !input.recipient_did.starts_with("did:")
        || input.text.len()
            > catbird_mls::chat_v2::transcript::direct_request::MAX_REQUEST_TEXT_UTF8_BYTES
        || recipient_label.len() > 256
    {
        return Err("Invalid request draft".into());
    }
    let storage = state.orchestrator.storage();
    if let Some(existing) = storage.request_draft(&session.actor_did, &input.draft_id)? {
        if existing.phase != "draft" {
            if existing.input == input {
                return Ok(existing);
            }
            return Err("This request has already been attempted. Keep its text unchanged while checking delivery.".into());
        }
    }
    let draft = RequestDraft {
        input,
        recipient_label,
        phase: "draft".into(),
        outcome: None,
        archived: false,
        note_delivery: None,
    };
    storage.save_request_draft(&session.actor_did, &draft)?;
    Ok(draft)
}

async fn operate(
    state: &AppState,
    owner_did: &str,
    owner_revision: &str,
    draft_id: &str,
    action: &str,
) -> Result<RequestDraft, String> {
    let _scope = capture_effect_owner(&state.request_scope, &owner_did, &owner_revision, || {
        state
            .api_client
            .current_session()
            .map_err(|_| "Sign in to continue".to_string())
    })
    .await?;
    let session = state
        .api_client
        .current_session()
        .map_err(|_| "Sign in to continue")?;
    if session.actor_did != owner_did {
        return Err("Account changed".into());
    }
    let mut draft = state
        .orchestrator
        .storage()
        .request_draft(&session.actor_did, draft_id)?
        .ok_or("Draft not found for this account")?;
    if draft.archived {
        return Err("Draft is archived".into());
    }
    if action == "cancel" && draft.phase == "draft" {
        draft.archived = true;
        state
            .orchestrator
            .storage()
            .save_request_draft(&session.actor_did, &draft)?;
        return Ok(draft);
    }
    if action == "send" && draft.input.text.trim().is_empty() {
        return Err("Write a message before sending this request".into());
    }
    // Persist before the first network effect. Retry uses this exact input/id;
    // never mint another candidate in response to an ambiguous transport error.
    draft.phase = "attempted".into();
    state
        .orchestrator
        .storage()
        .save_request_draft(&session.actor_did, &draft)?;
    let result = match action {
        "send" => {
            state
                .orchestrator
                .start_direct_request(draft.input.clone())
                .await
        }
        "resume" => state.orchestrator.resume_direct_request(draft_id).await,
        "cancel" => state.orchestrator.cancel_direct_request(draft_id).await,
        _ => unreachable!(),
    };
    state
        .api_client
        .ensure_session_current(&session)
        .map_err(|_| "Account changed; delivery will be reconciled when you return")?;
    match result {
        Ok(outcome) => {
            draft.phase = if matches!(outcome, DirectRequestOutcome::OutcomeUnknown { .. }) { "checking" } else { "resolved" }.into();
            draft.outcome = Some(outcome);
            state.orchestrator.storage().save_request_draft(&session.actor_did, &draft)?;
            Ok(draft)
        }
        Err(error) => {
            eprintln!("operate error: {:?}", error);
            // A signed terminal refusal ends the attempt even though the
            // native intent retains its authenticated receipt and tombstone.
            // Unknown delivery still has no terminal receipt and stays immutable.
            let retained = state
                .orchestrator
                .mls_context()
                .read_direct_request_intent(draft_id)
                .map_err(|_| "Request delivery state is unavailable; keep this draft unchanged")?;
            let terminal_not_published = if let Some(raw) = retained.as_deref() {
                match state
                    .orchestrator
                    .credentials()
                    .get_device_uuid(&session.actor_did)
                    .await
                {
                    Ok(Some(device)) => DirectRequestIntent::decode(raw, &session.actor_did, &device)
                        .is_ok_and(|intent| {
                            intent.input == draft.input
                                && intent.terminal_response.is_some()
                                && !intent.publication_attempted
                        }),
                    _ => false,
                }
            } else {
                false
            };
            if terminal_not_published || (retained.is_none() && draft.outcome.is_none()) {
                draft.phase = "draft".into();
                if terminal_not_published {
                    draft.outcome = None;
                }
                if action == "cancel" {
                    draft.archived = true;
                }
                state.orchestrator.storage().save_request_draft(&session.actor_did, &draft)?;
                if action == "cancel" {
                    return Ok(draft);
                }
            }
            if let OrchestratorError::Mls(MLSError::OperationNotSupported { reason }) = error {
                return Err(format!("{reason}. No legacy delivery was attempted."));
            }
            if retained.is_none() {
                return Err("Request was not attempted. Your draft remains editable and cancellable.".into());
            }
            Err("Delivery is not confirmed. Your draft is saved; check delivery or retry the same request.".into())
        }
    }
}
#[tauri::command]
pub async fn submit_request_draft(
    state: State<'_, AppState>,
    owner_did: String,
    owner_revision: String,
    draft_id: String,
) -> Result<RequestDraft, String> {
    operate(&state, &owner_did, &owner_revision, &draft_id, "send").await
}
#[tauri::command]
pub async fn resume_request_draft(
    state: State<'_, AppState>,
    owner_did: String,
    owner_revision: String,
    draft_id: String,
) -> Result<RequestDraft, String> {
    operate(&state, &owner_did, &owner_revision, &draft_id, "resume").await
}
#[tauri::command]
pub async fn cancel_request_draft(
    state: State<'_, AppState>,
    owner_did: String,
    owner_revision: String,
    draft_id: String,
) -> Result<RequestDraft, String> {
    operate(&state, &owner_did, &owner_revision, &draft_id, "cancel").await
}

#[tauri::command]
pub async fn refresh_direct_request(
    state: State<'_, AppState>,
    owner_did: String,
    owner_revision: String,
    conversation_id: String,
) -> Result<DirectRequestView, String> {
    let _scope = capture_effect_owner(&state.request_scope, &owner_did, &owner_revision, || {
        state
            .api_client
            .current_session()
            .map_err(|_| "Sign in to continue".to_string())
    })
    .await?;
    let session = state
        .api_client
        .current_session()
        .map_err(|_| "Sign in to view the request")?;
    if session.actor_did != owner_did {
        return Err("Account changed".into());
    }
    let view = state
        .orchestrator
        .refresh_request_preview(&conversation_id)
        .await
        .map_err(|_| "Request content is unavailable. Retry when connected.")?;
    state
        .api_client
        .ensure_session_current(&session)
        .map_err(|_| "Account changed")?;
    state
        .orchestrator
        .storage()
        .save_request_view(&session.actor_did, &view)?;
    Ok(view)
}
#[tauri::command]
pub async fn accept_direct_request(
    state: State<'_, AppState>,
    owner_did: String,
    owner_revision: String,
    conversation_id: String,
) -> Result<DirectRequestView, String> {
    let _scope = capture_effect_owner(&state.request_scope, &owner_did, &owner_revision, || {
        state
            .api_client
            .current_session()
            .map_err(|_| "Sign in to continue".to_string())
    })
    .await?;
    let session = state
        .api_client
        .current_session()
        .map_err(|_| "Sign in to accept")?;
    if session.actor_did != owner_did {
        return Err("Account changed".into());
    }
    let view = state
        .orchestrator
        .list_direct_request_views()
        .await
        .map_err(|_| "Request history unavailable")?
        .into_iter()
        .find(|v| v.conversation_id == conversation_id)
        .ok_or("Verified request not found")?;
    if view.consent != RequestConsent::IncomingPending || !view.capabilities.can_accept {
        return Err("This request cannot be accepted".into());
    }
    state
        .orchestrator
        .accept_conversation(&conversation_id)
        .await
        .map_err(|_| "Acceptance is not confirmed. Refresh before retrying.")?;
    let view = state
        .orchestrator
        .refresh_request_preview(&conversation_id)
        .await
        .map_err(|_| "Acceptance was submitted. Refresh to check its result.")?;
    state
        .api_client
        .ensure_session_current(&session)
        .map_err(|_| "Account changed")?;
    state
        .orchestrator
        .storage()
        .save_request_view(&session.actor_did, &view)?;
    Ok(view)
}

/// Capture initiating account after acquiring the same lock used by every auth
/// transition. The returned guard must remain live through the complete effect.
pub(crate) async fn capture_effect_owner<'a>(
    scope: &'a tokio::sync::Mutex<()>,
    expected_owner: &str,
    expected_revision: &str,
    current_session: impl Fn() -> Result<crate::api_client::ChatSessionSnapshot, String>,
) -> Result<tokio::sync::MutexGuard<'a, ()>, String> {
    // Snapshot before the first await: a same-DID login is a new authority.
    let captured = current_session()?;
    if expected_owner.is_empty()
        || captured.actor_did != expected_owner
        || captured.revision.to_string() != expected_revision
    {
        return Err("Account session changed; reopen the conversation before continuing".into());
    }
    let guard = scope.lock().await;
    if current_session()? != captured {
        return Err("Account session changed while the operation was queued".into());
    }
    Ok(guard)
}

/// Supplement shared Rust permission checks at IPC boundaries that historically
/// called transport directly (cursor/media). Never turn absent consent into acceptance.
pub(crate) async fn require_ordinary_activity(
    state: &AppState,
    conversation_id: &str,
) -> Result<catbird_atproto::blue_catbird::chat::ConversationState, String> {
    let views = state
        .orchestrator
        .list_direct_request_views()
        .await
        .map_err(|_| "Request consent could not be checked")?;
    if let Some(view) = views.iter().find(|v| v.conversation_id == conversation_id) {
        if !view.capabilities.can_send || !view.capabilities.can_emit_receipts {
            return Err("Accept this request before sending messages or activity".into());
        }
    }
    // Absence of a locally imported request is not acceptance. Canonical server
    // policy is mandatory before transport-only operations (media/cursors).
    let canonical = state
        .api_client
        .request_conversation_policy(conversation_id)
        .await
        .map_err(|error| format!("Conversation policy is unavailable: {error}"))?;
    let owner = state
        .api_client
        .current_session()
        .map_err(|_| "Sign in to continue")?
        .actor_did;
    if policy_blocks_activity(&canonical, &owner) {
        return Err("Conversation is awaiting consent".into());
    }
    Ok(canonical)
}

/// Device-local receive preference is explicit; background maintenance never opts in.
#[tauri::command]
pub async fn set_request_delivery_enabled(
    state: State<'_, AppState>,
    owner_did: String,
    owner_revision: String,
    enabled: bool,
) -> Result<(), String> {
    let _scope = capture_effect_owner(&state.request_scope, &owner_did, &owner_revision, || {
        state
            .api_client
            .current_session()
            .map_err(|_| "Sign in to continue".to_string())
    })
    .await?;
    let session = state
        .api_client
        .current_session()
        .map_err(|_| "Sign in to change request delivery")?;
    if session.actor_did != owner_did {
        return Err("Account changed".into());
    }
    state
        .orchestrator
        .set_direct_request_delivery_enabled(enabled)
        .await
        .map_err(|_| {
            "Request delivery change is not confirmed. Retry the same choice.".to_string()
        })?;
    state
        .api_client
        .ensure_session_current(&session)
        .map_err(|_| "Account changed".to_string())
}

#[tauri::command]
pub async fn close_direct_request(
    state: State<'_, AppState>,
    owner_did: String,
    owner_revision: String,
    conversation_id: String,
) -> Result<DirectRequestView, String> {
    let _scope = capture_effect_owner(&state.request_scope, &owner_did, &owner_revision, || {
        state
            .api_client
            .current_session()
            .map_err(|_| "Sign in to continue".to_string())
    })
    .await?;
    let session = state
        .api_client
        .current_session()
        .map_err(|_| "Sign in to close requests")?;
    if session.actor_did != owner_did {
        return Err("Account changed".into());
    }
    let view = state
        .orchestrator
        .close_direct_request(&conversation_id)
        .await
        .map_err(|_| "Close is not confirmed. Refresh or retry this request.".to_string())?;
    state
        .api_client
        .ensure_session_current(&session)
        .map_err(|_| "Account changed".to_string())?;
    state
        .orchestrator
        .storage()
        .save_request_view(&owner_did, &view)?;
    Ok(view)
}

#[tauri::command]
pub async fn block_request_sender(
    state: State<'_, AppState>,
    owner_did: String,
    owner_revision: String,
    conversation_id: String,
) -> Result<(), String> {
    let _scope = capture_effect_owner(&state.request_scope, &owner_did, &owner_revision, || {
        state
            .api_client
            .current_session()
            .map_err(|_| "Sign in to continue".to_string())
    })
    .await?;
    let session = state
        .api_client
        .current_session()
        .map_err(|_| "Sign in to block request senders")?;
    if session.actor_did != owner_did {
        return Err("Account changed".into());
    }
    let views = state
        .orchestrator
        .list_direct_request_views()
        .await
        .map_err(|_| "Request authority unavailable")?;
    let view = views
        .iter()
        .find(|v| {
            v.conversation_id == conversation_id
                && matches!(v.consent, RequestConsent::IncomingPending)
        })
        .ok_or("No incoming request for this account")?;
    let sender = view
        .introduction
        .as_ref()
        .map(|i| i.sender_did.clone())
        .ok_or("Request sender proof is unavailable")?;
    if sender == owner_did {
        return Err("Cannot block yourself".into());
    }
    crate::commands::create_block_for_captured_owner(state.clone(), sender)
        .await
        .map_err(|_| "Block is not confirmed".to_string())?;
    state
        .api_client
        .ensure_session_current(&session)
        .map_err(|_| "Account changed".to_string())
}

pub(crate) fn policy_blocks_activity(
    canonical: &catbird_atproto::blue_catbird::chat::ConversationState,
    owner: &str,
) -> bool {
    canonical.coordinates.lifecycle != "active"
        || !canonical
            .participants
            .iter()
            .any(|p| p.user_did.to_string() == owner && p.status == "active")
        || (canonical.conversation_kind == "direct"
            && canonical.participants.iter().any(|p| p.status == "pending"))
}

/// Resolve only the shared engine's authenticated, currently pending invitation.
#[tauri::command]
pub async fn get_group_invitation_reference(
    state: State<'_, AppState>,
    owner_did: String,
    owner_revision: String,
    conversation_id: String,
    recipient_did: String,
) -> Result<Option<GroupInvitationReference>, String> {
    let _scope = capture_effect_owner(&state.request_scope, &owner_did, &owner_revision, || {
        state
            .api_client
            .current_session()
            .map_err(|_| "Sign in to continue".to_string())
    })
    .await?;
    let session = state
        .api_client
        .current_session()
        .map_err(|_| "Sign in to write an invitation note")?;
    if session.actor_did != owner_did {
        return Err("Account changed".into());
    }
    let reference = state.orchestrator.get_group_invitation_reference(&conversation_id, &recipient_did).await.map_err(|_| "Invitation could not be verified. The invitation may still be delivered; no note was sent.")?;
    state
        .api_client
        .ensure_session_current(&session)
        .map_err(|_| "Account changed")?;
    Ok(reference)
}

/// Explicit second operation after a signed ExistingDirect result. An uncertain
/// ordinary send is retained for inspection and is never retried with a new ID.
#[tauri::command]
pub async fn send_existing_invitation_note(
    state: State<'_, AppState>,
    owner_did: String,
    owner_revision: String,
    draft_id: String,
) -> Result<RequestDraft, String> {
    let _scope = capture_effect_owner(&state.request_scope, &owner_did, &owner_revision, || {
        state
            .api_client
            .current_session()
            .map_err(|_| "Sign in to continue".to_string())
    })
    .await?;
    let session = state
        .api_client
        .current_session()
        .map_err(|_| "Sign in to send this note")?;
    if session.actor_did != owner_did {
        return Err("Account changed".into());
    }
    let mut draft = state
        .orchestrator
        .storage()
        .request_draft(&owner_did, &draft_id)?
        .ok_or("Draft not found")?;
    if draft.archived || draft.note_delivery.is_some() {
        return Err(
            "This note was already attempted. Open the conversation to check delivery.".into(),
        );
    }
    let cid = match &draft.outcome {
        Some(DirectRequestOutcome::ExistingDirect {
            conversation_id, ..
        }) => conversation_id.clone(),
        _ => return Err("An existing direct conversation is required; no note was sent".into()),
    };
    let reference = draft
        .input
        .invitation
        .clone()
        .ok_or("This draft has no group invitation")?;
    if reference.recipient_did != draft.input.recipient_did {
        return Err("Invitation recipient changed".into());
    }
    let policy = require_ordinary_activity(&state, &cid).await?;
    validate_note_policy(&policy, &owner_did, &draft.input.recipient_did, &cid)?;
    let embed = catbird_mls::orchestrator::MLSEmbedData::group_invitation(reference)
        .map_err(|_| "Invalid invitation reference")?;
    // The core repeats the fresh recipient/invitation check immediately before
    // encryption. This durable marker prevents duplicate ordinary sends on retry.
    draft.note_delivery = Some(NoteDelivery {
        conversation_id: cid.clone(),
        message_id: None,
    });
    state
        .orchestrator
        .storage()
        .save_request_draft(&owner_did, &draft)?;
    let sent = state
        .orchestrator
        .send_message_with_embed(&cid, &draft.input.text, embed)
        .await;
    state
        .api_client
        .ensure_session_current(&session)
        .map_err(|_| "Account changed; review this note when you return")?;
    match sent {
        Ok(message)=>{
            draft.note_delivery.as_mut().unwrap().message_id=Some(message.id);
            draft.archived=true;
            state.orchestrator.storage().save_request_draft(&owner_did,&draft)?;
            Ok(draft)
        },
        Err(_)=>Err("Invitation note delivery is not confirmed. Your text is retained; open the conversation before composing another note.".into()),
    }
}

fn validate_note_policy(
    policy: &catbird_atproto::blue_catbird::chat::ConversationState,
    owner: &str,
    recipient: &str,
    conversation: &str,
) -> Result<(), String> {
    if policy.coordinates.conversation_id != conversation
        || policy.conversation_kind != "direct"
        || policy_blocks_activity(policy, owner)
        || policy.participants.len() != 2
        || !policy
            .participants
            .iter()
            .any(|p| p.user_did.as_str() == recipient && p.status == "active")
        || owner == recipient
    {
        return Err(
            "Accept the exact direct conversation before sending this invitation note".into(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod authority_tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[tokio::test]
    async fn paused_effect_keeps_original_account_until_completion() {
        let scope = Arc::new(tokio::sync::Mutex::new(()));
        let owner = Arc::new(Mutex::new(crate::api_client::ChatSessionSnapshot {
            actor_did: "alice".into(),
            token: "first".into(),
            revision: 1,
        }));
        let captured =
            capture_effect_owner(&scope, "alice", "1", || Ok(owner.lock().unwrap().clone()))
                .await
                .unwrap();
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let next_scope = scope.clone();
        let next_owner = owner.clone();
        let transition = tokio::spawn(async move {
            entered_tx.send(()).unwrap();
            let _guard = next_scope.lock().await;
            next_owner.lock().unwrap().actor_did = "bob".into();
        });
        entered_rx.await.unwrap();
        tokio::task::yield_now().await;
        assert!(!transition.is_finished());
        assert_eq!(owner.lock().unwrap().actor_did, "alice"); // policy and network effect use this session
        drop(captured);
        transition.await.unwrap();
        assert_eq!(owner.lock().unwrap().actor_did, "bob");
        assert!(
            capture_effect_owner(&scope, "alice", "1", || Ok(owner.lock().unwrap().clone()))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn queued_old_owner_is_rejected_after_auth_transition() {
        let scope = Arc::new(tokio::sync::Mutex::new(()));
        let owner = Arc::new(Mutex::new(crate::api_client::ChatSessionSnapshot {
            actor_did: "alice".into(),
            token: "first".into(),
            revision: 1,
        }));
        let transition = scope.lock().await;
        let queued_scope = scope.clone();
        let queued_owner = owner.clone();
        let queued = tokio::spawn(async move {
            capture_effect_owner(&queued_scope, "alice", "1", || {
                Ok(queued_owner.lock().unwrap().clone())
            })
            .await
            .is_ok()
        });
        tokio::task::yield_now().await;
        owner.lock().unwrap().actor_did = "bob".into();
        drop(transition);
        assert!(!queued.await.unwrap());
    }

    #[tokio::test]
    async fn queued_same_did_rebind_rejects_old_session_and_ipc_revision() {
        let scope = Arc::new(tokio::sync::Mutex::new(()));
        let api = Arc::new(crate::api_client::ReqwestApiClient::new(
            "https://example.invalid".into(),
        ));
        api.set_auth("alice".into(), "first-session".into());
        let revision = api.current_session().unwrap().revision.to_string();
        let transition = scope.lock().await;
        let queued_scope = scope.clone();
        let queued_api = api.clone();
        let queued_revision = revision.clone();
        let (captured_tx, captured_rx) = tokio::sync::oneshot::channel();
        let captured = std::sync::Mutex::new(Some(captured_tx));
        let queued = tokio::spawn(async move {
            capture_effect_owner(&queued_scope, "alice", &queued_revision, || {
                let result = queued_api
                    .current_session()
                    .map_err(|_| "No session".to_string());
                if let Some(tx) = captured.lock().unwrap().take() {
                    let _ = tx.send(());
                }
                result
            })
            .await
            .is_ok()
        });
        captured_rx.await.unwrap();
        api.clear_auth();
        api.set_auth("alice".into(), "second-session".into());
        drop(transition);
        assert!(!queued.await.unwrap());
        // An IPC invocation dispatched before the switch but polled only now
        // must also fail: its explicit browser-side revision is immutable.
        assert!(capture_effect_owner(&scope, "alice", &revision, || api
            .current_session()
            .map_err(|_| "No session".into()))
        .await
        .is_err());
        let current = api.current_session().unwrap().revision.to_string();
        assert!(capture_effect_owner(&scope, "alice", &current, || api
            .current_session()
            .map_err(|_| "No session".into()))
        .await
        .is_ok());
    }

    #[test]
    fn historical_pending_hint_does_not_override_fresh_note_consent() {
        let mut policy = catbird_mls::orchestrator::canonical_transport::decode_conversation_state(
            serde_json::from_str::<serde_json::Value>(include_str!(
                "../tests/fixtures/canonical-conversation-state.json"
            ))
            .unwrap()
            .to_string()
            .as_bytes(),
        )
        .unwrap();
        policy.conversation_kind = "direct".into();
        let owner = policy.participants[0].user_did.to_string();
        let recipient = policy.participants[1].user_did.to_string();
        let cid = policy.coordinates.conversation_id.to_string();
        let outcome = DirectRequestOutcome::ExistingDirect {
            conversation_id: cid.clone(),
            requires_acceptance: true,
        };
        let original = serde_json::to_vec(&outcome).unwrap();
        assert!(validate_note_policy(&policy, &owner, &recipient, &cid).is_err());
        policy.participants[1].status = "active".into();
        assert!(validate_note_policy(&policy, &owner, &recipient, &cid).is_ok());
        assert!(
            validate_note_policy(&policy, &owner, "did:plc:cccccccccccccccccccccccc", &cid)
                .is_err()
        );
        assert_eq!(serde_json::to_vec(&outcome).unwrap(), original);
    }
}

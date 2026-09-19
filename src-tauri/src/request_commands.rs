//! Desktop request adapter. The shared engine alone owns intent, crypto and consent.
use crate::AppState;
use catbird_mls::orchestrator::{
    DirectRequestInput, DirectRequestOutcome, DirectRequestView, GroupInvitationReference,
    RequestConsent,
};
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
) -> Result<RequestWorkspace, String> {
    let _scope = state.request_scope.lock().await;
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
    input: DirectRequestInput,
    recipient_label: String,
) -> Result<RequestDraft, String> {
    let _scope = state.request_scope.lock().await;
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
    draft_id: &str,
    action: &str,
) -> Result<RequestDraft, String> {
    let _scope = state.request_scope.lock().await;
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
        Err(_) => Err("Delivery is not confirmed. Your draft is saved; check delivery or retry the same request.".into()),
    }
}
#[tauri::command]
pub async fn submit_request_draft(
    state: State<'_, AppState>,
    owner_did: String,
    draft_id: String,
) -> Result<RequestDraft, String> {
    operate(&state, &owner_did, &draft_id, "send").await
}
#[tauri::command]
pub async fn resume_request_draft(
    state: State<'_, AppState>,
    owner_did: String,
    draft_id: String,
) -> Result<RequestDraft, String> {
    operate(&state, &owner_did, &draft_id, "resume").await
}
#[tauri::command]
pub async fn cancel_request_draft(
    state: State<'_, AppState>,
    owner_did: String,
    draft_id: String,
) -> Result<RequestDraft, String> {
    operate(&state, &owner_did, &draft_id, "cancel").await
}

#[tauri::command]
pub async fn refresh_direct_request(
    state: State<'_, AppState>,
    owner_did: String,
    conversation_id: String,
) -> Result<DirectRequestView, String> {
    let _scope = state.request_scope.lock().await;
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
    conversation_id: String,
) -> Result<DirectRequestView, String> {
    let _scope = state.request_scope.lock().await;
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

/// Supplement shared Rust permission checks at IPC boundaries that historically
/// called transport directly (cursor/media). Never turn absent consent into acceptance.
pub(crate) async fn require_ordinary_activity(
    state: &AppState,
    conversation_id: &str,
) -> Result<(), String> {
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
        .map_err(|_| "Conversation policy is unavailable")?;
    let owner = state
        .api_client
        .current_session()
        .map_err(|_| "Sign in to continue")?
        .actor_did;
    if policy_blocks_activity(&canonical, &owner) {
        return Err("Conversation is awaiting consent".into());
    }
    Ok(())
}

/// Device-local receive preference is explicit; background maintenance never opts in.
#[tauri::command]
pub async fn set_request_delivery_enabled(
    state: State<'_, AppState>,
    owner_did: String,
    enabled: bool,
) -> Result<(), String> {
    let _scope = state.request_scope.lock().await;
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
    conversation_id: String,
) -> Result<DirectRequestView, String> {
    let _scope = state.request_scope.lock().await;
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
    conversation_id: String,
) -> Result<(), String> {
    let _scope = state.request_scope.lock().await;
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
    crate::commands::create_block(state.clone(), sender)
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
    conversation_id: String,
    recipient_did: String,
) -> Result<Option<GroupInvitationReference>, String> {
    let _scope = state.request_scope.lock().await;
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
    draft_id: String,
) -> Result<RequestDraft, String> {
    let _scope = state.request_scope.lock().await;
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
            conversation_id,
            requires_acceptance: false,
        }) => conversation_id.clone(),
        _ => return Err("An accepted direct conversation is required; no note was sent".into()),
    };
    let reference = draft
        .input
        .invitation
        .clone()
        .ok_or("This draft has no group invitation")?;
    if reference.recipient_did != draft.input.recipient_did {
        return Err("Invitation recipient changed".into());
    }
    require_ordinary_activity(&state, &cid).await?;
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

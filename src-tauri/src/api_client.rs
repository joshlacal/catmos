use async_trait::async_trait;
use catbird_atproto::blue_catbird;
use catbird_atproto::jacquard_common::IntoStatic;
use reqwest::Client;
use std::sync::RwLock;

use catbird_mls::orchestrator::api_client::MLSAPIClient;
use catbird_mls::orchestrator::error::{OrchestratorError, Result};
use catbird_mls::orchestrator::types::*;

use crate::types::string::Did;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

fn parse_did(s: &str) -> Did {
    Did::new_owned(s.to_string()).unwrap_or_else(|_| panic!("invalid DID: {}", s))
}

fn parse_lexicon_json<'de, T>(body: &'de [u8]) -> Result<T::Output>
where
    T: serde::Deserialize<'de> + IntoStatic,
{
    let parsed: T =
        serde_json::from_slice(body).map_err(|e| OrchestratorError::Api(e.to_string()))?;
    Ok(parsed.into_static())
}

fn canonical_conversation_view(
    state: &catbird_atproto::blue_catbird::chat::ConversationState,
) -> ConversationView {
    ConversationView {
        canonical_state: Some(state.clone()),
        group_id: hex::encode(state.coordinates.group_id.as_ref()),
        conversation_id: state.coordinates.conversation_id.to_string(),
        epoch: state.coordinates.epoch as u64,
        members: state
            .participants
            .iter()
            .map(|participant| MemberView {
                did: participant.user_did.to_string(),
                role: if participant.role == "admin" {
                    MemberRole::Admin
                } else {
                    MemberRole::Member
                },
            })
            .collect(),
        metadata: None,
        created_at: None,
        updated_at: None,
        sequencer_did: None,
    }
}

fn decode_hex_bytes(input: &str) -> std::result::Result<Vec<u8>, String> {
    let trimmed = input.trim_start_matches("0x").trim_start_matches("0X");
    if trimmed.len() % 2 != 0 {
        return Err("hex string length must be even".to_string());
    }
    let mut out = Vec::with_capacity(trimmed.len() / 2);
    let chars: Vec<char> = trimmed.chars().collect();
    for idx in (0..chars.len()).step_by(2) {
        let pair: String = [chars[idx], chars[idx + 1]].iter().collect();
        let byte = u8::from_str_radix(&pair, 16)
            .map_err(|_| format!("invalid hex byte at position {}", idx))?;
        out.push(byte);
    }
    Ok(out)
}

/// Resolve the one registered `deviceId` matching the durable client UUID.
/// The canonical device contract uses the client-generated UUIDv4 as
/// `deviceId`; `keyId` is a signing-key thumbprint and is never an identity
/// correlation field. Zero or duplicate matches fail closed.
fn is_strict_uuid_v4(value: &str) -> bool {
    let Ok(parsed) = uuid::Uuid::parse_str(value) else {
        return false;
    };
    parsed.get_version() == Some(uuid::Version::Random)
        && parsed.get_variant() == uuid::Variant::RFC4122
        && parsed.to_string() == value
}

fn resolve_unique_server_device_id(
    devices: &[DeviceInfo],
    local_device_uuid: &str,
) -> Result<String> {
    let local_device_uuid = local_device_uuid.trim();
    if !is_strict_uuid_v4(local_device_uuid) {
        return Err(OrchestratorError::Api(
            "cannot resolve device identity without a canonical local UUIDv4".to_string(),
        ));
    }

    let matches: Vec<&DeviceInfo> = devices
        .iter()
        .filter(|device| device.device_uuid.trim() == local_device_uuid)
        .collect();
    if matches.len() != 1 {
        return Err(OrchestratorError::Api(format!(
            "expected exactly one listDevices match for local device UUID, found {}",
            matches.len()
        )));
    }

    let server_device_id = matches[0].device_id.trim();
    if server_device_id.is_empty() {
        return Err(OrchestratorError::Api(
            "listDevices matched the local UUID but returned an empty server device ID".to_string(),
        ));
    }
    Ok(server_device_id.to_string())
}

fn parse_receipt_bytes_data<S: catbird_atproto::jacquard_common::BosStr>(
    field: &str,
    value: &catbird_atproto::jacquard_common::types::value::Data<S>,
) -> std::result::Result<Vec<u8>, String> {
    use catbird_atproto::jacquard_common::types::value::Data;

    match value {
        Data::Bytes(bytes) => Ok(bytes.to_vec()),
        Data::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for (idx, item) in items.iter().enumerate() {
                let n = item
                    .as_integer()
                    .ok_or_else(|| format!("{field}[{idx}] is not an integer"))?;
                let byte =
                    u8::try_from(n).map_err(|_| format!("{field}[{idx}] is out of byte range"))?;
                out.push(byte);
            }
            Ok(out)
        }
        _ => {
            if let Some(encoded) = value.as_str() {
                if let Ok(decoded) = B64.decode(encoded) {
                    return Ok(decoded);
                }
                if let Ok(decoded) = base64::engine::general_purpose::URL_SAFE.decode(encoded) {
                    return Ok(decoded);
                }
                if let Ok(decoded) =
                    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(encoded)
                {
                    return Ok(decoded);
                }
                if let Ok(decoded) = decode_hex_bytes(encoded) {
                    return Ok(decoded);
                }
                return Err(format!(
                    "{field} was a string but not valid base64/base64url/hex"
                ));
            }
            Err(format!(
                "{field} must be bytes, an array of integers, or an encoded string"
            ))
        }
    }
}

fn parse_sequencer_receipt_data<S: catbird_atproto::jacquard_common::BosStr>(
    value: &catbird_atproto::jacquard_common::types::value::Data<S>,
) -> std::result::Result<SequencerReceipt, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "receipt is not an ATProto object".to_string())?;

    let convo_id = object
        .get("convo_id")
        .or_else(|| object.get("convoId"))
        .and_then(|value| value.as_str())
        .map(ToString::to_string)
        .ok_or_else(|| "missing convo_id/convoId".to_string())?;
    let epoch = object
        .get("epoch")
        .and_then(|value| value.as_integer())
        .ok_or_else(|| "missing epoch".to_string())
        .and_then(|value| i32::try_from(value).map_err(|_| "epoch out of i32 range".to_string()))?;
    let commit_hash = parse_receipt_bytes_data(
        "commit_hash",
        object
            .get("commit_hash")
            .or_else(|| object.get("commitHash"))
            .ok_or_else(|| "missing commit_hash/commitHash".to_string())?,
    )?;
    let sequencer_did = object
        .get("sequencer_did")
        .or_else(|| object.get("sequencerDid"))
        .and_then(|value| value.as_str())
        .map(ToString::to_string)
        .ok_or_else(|| "missing sequencer_did/sequencerDid".to_string())?;
    let issued_at = object
        .get("issued_at")
        .or_else(|| object.get("issuedAt"))
        .and_then(|value| value.as_integer())
        .ok_or_else(|| "missing issued_at/issuedAt".to_string())?;
    let signature = parse_receipt_bytes_data(
        "signature",
        object
            .get("signature")
            .ok_or_else(|| "missing signature".to_string())?,
    )?;
    let sequencer_term = object
        .get("sequencer_term")
        .or_else(|| object.get("sequencerTerm"))
        .and_then(|value| value.as_integer())
        .map(|v| v as u64)
        .unwrap_or(0);

    Ok(SequencerReceipt {
        convo_id,
        epoch,
        sequencer_term,
        commit_hash,
        sequencer_did,
        issued_at,
        signature,
    })
}

/// Errors returned when a canonical clean-chat request cannot be authorized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChatAuthError {
    MissingSession,
    SessionChanged,
    MissingLocalDeviceUuid,
    MissingDevice,
    MissingDeviceBinding,
    MissingAuthGeneration,
    AuthGenerationMismatch { expected: u64, observed: u64 },
    DeviceBindingMismatch,
}

impl std::fmt::Display for ChatAuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::MissingSession => "chat auth session is missing",
            Self::SessionChanged => "chat auth session changed while the request was in flight",
            Self::MissingLocalDeviceUuid => "local chat device UUID is missing",
            Self::MissingDevice => "registered chat device is missing",
            Self::MissingDeviceBinding => "completed chat device binding is missing",
            Self::MissingAuthGeneration => "current chat auth generation is missing",
            Self::AuthGenerationMismatch { expected, observed } => {
                return write!(
                    f,
                    "chat auth generation changed (expected {expected}, observed {observed})"
                )
            }
            Self::DeviceBindingMismatch => "chat device binding does not match the server device",
        };
        f.write_str(message)
    }
}

/// Headers needed by canonical reads. Nest authenticates these reads with
/// Authorization plus the registered server device ID. The provider admits
/// the completed device/generation binding before constructing this context.
/// Standard AppView service authentication remains opaque to this adapter.
pub(crate) struct CanonicalReadContext {
    /// Actor DID captured with the immutable authority snapshot. This is used
    /// only to reject late responses after an account switch.
    actor_did: String,
    pub(crate) authorization: String,
    pub(crate) device_id: String,
    pub(crate) auth_generation: u64,
    session: ChatSessionSnapshot,
}

impl std::fmt::Debug for CanonicalReadContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CanonicalReadContext")
            .field("actor_did", &self.actor_did)
            .field("device_id", &self.device_id)
            .field("auth_generation", &self.auth_generation)
            .finish_non_exhaustive()
    }
}

/// Evidence extracted from one immutable, session-fenced getOwnDevices
/// response after its row and durable signer agree.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct DeviceAuthorityEvidence {
    pub(crate) local_device_uuid: String,
    pub(crate) server_device_id: String,
    pub(crate) auth_generation: u64,
}

#[derive(Clone, PartialEq, Eq)]
struct CompletedDeviceBinding {
    server_device_id: String,
    auth_generation: u64,
}

impl std::fmt::Debug for CompletedDeviceBinding {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CompletedDeviceBinding")
            .field("server_device_id", &self.server_device_id)
            .field("auth_generation", &self.auth_generation)
            .finish_non_exhaustive()
    }
}

struct ChatAuthSnapshot {
    actor_did: Option<String>,
    session_token: Option<String>,
    session_revision: u64,
    local_device_uuid: Option<String>,
    server_device_id: Option<String>,
    binding: Option<CompletedDeviceBinding>,
}

impl Default for ChatAuthSnapshot {
    fn default() -> Self {
        Self {
            actor_did: None,
            session_token: None,
            session_revision: 0,
            local_device_uuid: None,
            server_device_id: None,
            binding: None,
        }
    }
}

/// Immutable actor/token/revision captured for one asynchronous operation.
///
/// The bearer is intentionally kept out of `Debug`; callers must carry this
/// value through every await and revalidate it before a durable or runtime
/// mutation so a late response cannot cross an account switch.
#[derive(Clone, PartialEq, Eq)]
pub struct ChatSessionSnapshot {
    pub actor_did: String,
    pub token: String,
    pub revision: u64,
}

impl std::fmt::Debug for ChatSessionSnapshot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ChatSessionSnapshot")
            .field("actor_did", &self.actor_did)
            .field("revision", &self.revision)
            .finish_non_exhaustive()
    }
}

/// Runtime-owned clean-chat capabilities.
///
/// Session tokens are intentionally kept behind this provider. Callers receive
/// only a transport context, and `Debug` never exposes persisted secret
/// material.
pub(crate) struct ChatAuthProvider {
    /// One lock protects the actor DID, bearer, local UUID, server ID, and
    /// completed binding. Every read clones one immutable snapshot, so an
    /// account switch cannot mix token and device state.
    state: std::sync::RwLock<ChatAuthSnapshot>,
}

impl Default for ChatAuthProvider {
    fn default() -> Self {
        Self {
            state: std::sync::RwLock::new(ChatAuthSnapshot::default()),
        }
    }
}
impl ChatAuthProvider {
    pub(crate) fn set_session(&self, did: String, session_token: String) {
        let mut state = self.state.write().unwrap();
        if state.actor_did.as_deref() != Some(did.as_str()) {
            let revision = state.session_revision.saturating_add(1).max(1);
            *state = ChatAuthSnapshot::default();
            state.session_revision = revision;
        } else if state.session_token.as_deref() != Some(session_token.as_str()) {
            // A fresh session for the same DID may have a different gateway
            // binding. Keep durable identity for reconciliation, but do not
            // reuse authority across opaque gateway-session generations.
            let revision = state.session_revision.saturating_add(1).max(1);
            Self::clear_runtime_state(&mut state);
            state.session_revision = revision;
        }
        if state.session_revision == 0 {
            state.session_revision = 1;
        }
        state.actor_did = Some(did);
        state.session_token = Some(session_token);
    }

    pub(crate) fn session_snapshot(
        &self,
    ) -> std::result::Result<ChatSessionSnapshot, ChatAuthError> {
        let state = self.state.read().unwrap();
        let actor_did = state
            .actor_did
            .clone()
            .filter(|value| !value.trim().is_empty())
            .ok_or(ChatAuthError::MissingSession)?;
        let token = state
            .session_token
            .clone()
            .filter(|value| !value.trim().is_empty())
            .ok_or(ChatAuthError::MissingSession)?;
        if state.session_revision == 0 {
            return Err(ChatAuthError::MissingSession);
        }
        Ok(ChatSessionSnapshot {
            actor_did,
            token,
            revision: state.session_revision,
        })
    }

    pub(crate) fn session_is_current(&self, session: &ChatSessionSnapshot) -> bool {
        let state = self.state.read().unwrap();
        state.session_revision == session.revision
            && state.actor_did.as_deref() == Some(session.actor_did.as_str())
            && state.session_token.as_deref() == Some(session.token.as_str())
    }

    /// Set the client-generated UUID. This value is not accepted as a server
    /// device identity; it is only the lookup key for `listDevices`.
    #[cfg(test)]
    pub(crate) fn set_local_device_uuid(
        &self,
        actor_did: &str,
        local_device_uuid: String,
    ) -> std::result::Result<(), ChatAuthError> {
        let local_device_uuid = local_device_uuid.trim().to_string();
        if local_device_uuid.is_empty() {
            return Err(ChatAuthError::MissingLocalDeviceUuid);
        }
        let mut state = self.state.write().unwrap();
        if state.actor_did.as_deref() != Some(actor_did) || state.session_token.is_none() {
            return Err(ChatAuthError::SessionChanged);
        }
        if state.local_device_uuid.as_deref() != Some(local_device_uuid.as_str()) {
            state.server_device_id = None;
            state.binding = None;
        }
        state.local_device_uuid = Some(local_device_uuid);
        Ok(())
    }

    pub(crate) fn set_local_device_uuid_for_session(
        &self,
        session: &ChatSessionSnapshot,
        local_device_uuid: String,
    ) -> std::result::Result<(), ChatAuthError> {
        let local_device_uuid = local_device_uuid.trim().to_string();
        if local_device_uuid.is_empty() {
            return Err(ChatAuthError::MissingLocalDeviceUuid);
        }
        let mut state = self.state.write().unwrap();
        if state.session_revision != session.revision
            || state.actor_did.as_deref() != Some(session.actor_did.as_str())
            || state.session_token.as_deref() != Some(session.token.as_str())
        {
            return Err(ChatAuthError::SessionChanged);
        }
        if state.local_device_uuid.as_deref() != Some(local_device_uuid.as_str()) {
            state.server_device_id = None;
            state.binding = None;
        }
        state.local_device_uuid = Some(local_device_uuid);
        Ok(())
    }

    /// Install the server-minted ID only after an exact `listDevices` match.
    #[cfg(test)]
    fn set_resolved_server_device_id(
        &self,
        actor_did: &str,
        server_device_id: String,
    ) -> std::result::Result<(), ChatAuthError> {
        let server_device_id = server_device_id.trim().to_string();
        if server_device_id.is_empty() {
            return Err(ChatAuthError::MissingDevice);
        }
        let mut state = self.state.write().unwrap();
        if state.actor_did.as_deref() != Some(actor_did) || state.session_token.is_none() {
            return Err(ChatAuthError::SessionChanged);
        }
        let changed = state.server_device_id.as_deref() != Some(server_device_id.as_str());
        state.server_device_id = Some(server_device_id);
        if changed {
            state.binding = None;
        }
        Ok(())
    }

    pub(crate) fn set_resolved_server_device_id_for_session(
        &self,
        session: &ChatSessionSnapshot,
        server_device_id: String,
    ) -> std::result::Result<(), ChatAuthError> {
        let server_device_id = server_device_id.trim().to_string();
        if server_device_id.is_empty() {
            return Err(ChatAuthError::MissingDevice);
        }
        let mut state = self.state.write().unwrap();
        if state.session_revision != session.revision
            || state.actor_did.as_deref() != Some(session.actor_did.as_str())
            || state.session_token.as_deref() != Some(session.token.as_str())
        {
            return Err(ChatAuthError::SessionChanged);
        }
        let changed = state.server_device_id.as_deref() != Some(server_device_id.as_str());
        state.server_device_id = Some(server_device_id);
        if changed {
            state.binding = None;
        }
        Ok(())
    }

    /// Atomically publish a completed binding after one immutable
    /// getOwnDevices response has matched the local signer. Device identity
    /// is not made visible piecemeal while that response is in flight.
    pub(crate) fn admit_device_authority_for_session(
        &self,
        session: &ChatSessionSnapshot,
        evidence: DeviceAuthorityEvidence,
    ) -> std::result::Result<(), ChatAuthError> {
        let mut state = self.state.write().unwrap();
        if state.session_revision != session.revision
            || state.actor_did.as_deref() != Some(session.actor_did.as_str())
            || state.session_token.as_deref() != Some(session.token.as_str())
        {
            return Err(ChatAuthError::SessionChanged);
        }
        let local_device_uuid = evidence.local_device_uuid.trim().to_string();
        if !is_strict_uuid_v4(&local_device_uuid) {
            return Err(ChatAuthError::MissingLocalDeviceUuid);
        }
        if state
            .local_device_uuid
            .as_ref()
            .is_some_and(|configured| configured != &local_device_uuid)
        {
            return Err(ChatAuthError::DeviceBindingMismatch);
        }

        let server_device_id = evidence.server_device_id.trim().to_string();
        if !is_strict_uuid_v4(&server_device_id) {
            return Err(ChatAuthError::MissingDevice);
        }
        if local_device_uuid != server_device_id
            || state
                .server_device_id
                .as_ref()
                .is_some_and(|configured| configured != &server_device_id)
        {
            return Err(ChatAuthError::DeviceBindingMismatch);
        }

        if evidence.auth_generation == 0 {
            return Err(ChatAuthError::MissingAuthGeneration);
        }
        let binding = CompletedDeviceBinding {
            server_device_id,
            auth_generation: evidence.auth_generation,
        };
        state.local_device_uuid = Some(local_device_uuid);
        state.server_device_id = Some(binding.server_device_id.clone());
        state.binding = Some(binding);
        Ok(())
    }

    /// Clear runtime binding state while retaining local and server identity.
    /// Durable identity deletion is an explicit account-removal operation.
    #[cfg(test)]
    pub(crate) fn clear_device_authority(&self) {
        let mut state = self.state.write().unwrap();
        Self::clear_runtime_state(&mut state);
    }

    fn clear_runtime_state(state: &mut ChatAuthSnapshot) {
        state.binding = None;
    }

    pub(crate) fn clear_runtime_state_for_session(
        &self,
        session: &ChatSessionSnapshot,
    ) -> std::result::Result<(), ChatAuthError> {
        let mut state = self.state.write().unwrap();
        if state.session_revision != session.revision
            || state.actor_did.as_deref() != Some(session.actor_did.as_str())
            || state.session_token.as_deref() != Some(session.token.as_str())
        {
            return Err(ChatAuthError::SessionChanged);
        }
        Self::clear_runtime_state(&mut state);
        Ok(())
    }

    /// Invalidate a binding when the server reports a newer generation.
    #[cfg(test)]
    pub(crate) fn invalidate_for_generation(
        &self,
        actor_did: &str,
        observed_generation: u64,
    ) -> std::result::Result<(), ChatAuthError> {
        let mut state = self.state.write().unwrap();
        if state.actor_did.as_deref() != Some(actor_did) {
            return Err(ChatAuthError::SessionChanged);
        }
        let expected = state
            .binding
            .as_ref()
            .map(|binding| binding.auth_generation);
        if let Some(expected) = expected {
            if observed_generation != expected {
                Self::clear_runtime_state(&mut state);
                return Err(ChatAuthError::AuthGenerationMismatch {
                    expected,
                    observed: observed_generation,
                });
            }
        }
        Ok(())
    }

    pub(crate) fn clear(&self) {
        let mut state = self.state.write().unwrap();
        let revision = state.session_revision.saturating_add(1).max(1);
        *state = ChatAuthSnapshot::default();
        state.session_revision = revision;
    }

    /// Build canonical-read headers only after the exact device has completed
    /// service-auth admission and its positive generation still agrees with
    /// that binding.
    pub(crate) fn canonical_read_context(
        &self,
    ) -> std::result::Result<CanonicalReadContext, ChatAuthError> {
        let state = self.state.read().unwrap();
        let actor_did = state
            .actor_did
            .clone()
            .ok_or(ChatAuthError::MissingSession)?;
        let session_token = state
            .session_token
            .clone()
            .ok_or(ChatAuthError::MissingSession)?;
        let session = ChatSessionSnapshot {
            actor_did: actor_did.clone(),
            token: session_token.clone(),
            revision: state.session_revision,
        };
        let local_device_uuid = state
            .local_device_uuid
            .clone()
            .filter(|value| !value.trim().is_empty())
            .ok_or(ChatAuthError::MissingLocalDeviceUuid)?;
        let device_id = state
            .server_device_id
            .clone()
            .filter(|value| !value.trim().is_empty())
            .ok_or(ChatAuthError::MissingDevice)?;
        let binding = state
            .binding
            .clone()
            .ok_or(ChatAuthError::MissingDeviceBinding)?;
        if !is_strict_uuid_v4(&local_device_uuid)
            || !is_strict_uuid_v4(&device_id)
            || local_device_uuid != device_id
            || binding.server_device_id != device_id
        {
            return Err(ChatAuthError::DeviceBindingMismatch);
        }
        if binding.auth_generation == 0 {
            return Err(ChatAuthError::MissingAuthGeneration);
        }
        Ok(CanonicalReadContext {
            actor_did,
            authorization: format!("Bearer {session_token}"),
            device_id,
            auth_generation: binding.auth_generation,
            session,
        })
    }

    #[cfg(test)]
    fn set_session_for_tests(&self, did: &str, session_token: &str) {
        self.set_session(did.to_string(), session_token.to_string());
    }

    #[cfg(test)]
    fn set_device_for_tests(&self, device_id: &str) {
        let actor_did = self
            .state
            .read()
            .unwrap()
            .actor_did
            .clone()
            .expect("test session must be set before device");
        self.set_resolved_server_device_id(&actor_did, device_id.to_string())
            .expect("test device should install");
    }

    #[cfg(test)]
    fn set_local_device_for_tests(&self, device_uuid: &str) {
        let actor_did = self
            .state
            .read()
            .unwrap()
            .actor_did
            .clone()
            .expect("test session must be set before local UUID");
        self.set_local_device_uuid(&actor_did, device_uuid.to_string())
            .expect("test local UUID should install");
    }

    #[cfg(test)]
    fn admit_for_tests(&self, generation: u64) {
        let session = self
            .session_snapshot()
            .expect("test session must be current before admission");
        let state = self.state.read().unwrap();
        let local_device_uuid = state
            .local_device_uuid
            .clone()
            .expect("test local UUID must be configured before admission");
        let server_device_id = state
            .server_device_id
            .clone()
            .expect("test server device ID must be configured before admission");
        drop(state);
        self.admit_device_authority_for_session(
            &session,
            DeviceAuthorityEvidence {
                local_device_uuid,
                server_device_id,
                auth_generation: generation,
            },
        )
        .expect("test device authority should admit");
    }
}

struct OwnDevicesSnapshot {
    devices: Vec<DeviceInfo>,
}

#[cfg(test)]
const TEST_AUTH_DEVICE_A: &str = "00000000-0000-4000-8000-000000000001";
#[cfg(test)]
const TEST_AUTH_DEVICE_B: &str = "00000000-0000-4000-8000-000000000002";

pub struct ReqwestApiClient {
    client: Client,
    base_url: String,
    mls_context: RwLock<Option<std::sync::Arc<catbird_mls::MLSContext>>>,
    chat_auth: std::sync::Arc<ChatAuthProvider>,
    #[cfg(test)]
    publish_device_id_override: RwLock<Option<String>>,
}

impl ReqwestApiClient {
    pub fn new(base_url: String) -> Self {
        let client = Client::builder()
            .default_headers(crate::mls_proxy::mls_default_headers())
            .timeout(std::time::Duration::from_secs(30))
            .connect_timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap_or_else(|_| Client::new());
        Self {
            client,
            base_url,
            mls_context: RwLock::new(None),
            chat_auth: std::sync::Arc::new(ChatAuthProvider::default()),
            #[cfg(test)]
            publish_device_id_override: RwLock::new(None),
        }
    }

    /// Create a clone of this API client sharing the same HTTP client, base_url, and chat_auth provider,
    /// but with its own independent local `mls_context` (allowing provisional isolation).
    pub fn clone_with_local_mls_context(&self) -> Self {
        Self {
            client: self.client.clone(),
            base_url: self.base_url.clone(),
            mls_context: RwLock::new(None),
            chat_auth: self.chat_auth.clone(),
            #[cfg(test)]
            publish_device_id_override: RwLock::new(None),
        }
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }
    pub fn set_mls_context(&self, ctx: std::sync::Arc<catbird_mls::MLSContext>) {
        *self.mls_context.write().unwrap() = Some(ctx);
    }

    /// Clear the MLS context when the account runtime drops.
    pub fn clear_mls_context(&self) {
        *self.mls_context.write().unwrap() = None;
    }

    /// Get the base64-encoded confirmation tag for a conversation, or None if unavailable.
    fn get_confirmation_tag_b64(&self, convo_id: &str) -> Option<String> {
        let ctx = self.mls_context.read().unwrap();
        let ctx = ctx.as_ref()?;
        let group_id_bytes = decode_hex_bytes(convo_id).ok()?;
        ctx.get_confirmation_tag(group_id_bytes)
            .map(|tag| B64.encode(&tag))
            .ok()
    }

    /// Get the raw (un-encoded) confirmation tag bytes for a conversation.
    ///
    /// Use this on `commitGroupChange` call sites that construct
    /// `CommitGroupChange<'static>` directly (where `confirmation_tag` is
    /// `Option<bytes::Bytes>` and the lexicon serializer base64-encodes
    /// once). Do NOT use with the `InputData` adapter — that adapter expects
    /// a pre-base64 string and re-encodes as UTF-8 bytes, producing
    /// double-encoded wire output (see `build_commit_group_change` docs).
    fn get_confirmation_tag_raw(&self, convo_id: &str) -> Option<Vec<u8>> {
        let ctx = self.mls_context.read().unwrap();
        let ctx = ctx.as_ref()?;
        let group_id_bytes = decode_hex_bytes(convo_id).ok()?;
        ctx.get_confirmation_tag(group_id_bytes).ok()
    }

    pub fn set_auth(&self, did: String, token: String) {
        self.chat_auth.set_session(did, token);
    }

    pub fn current_session(&self) -> std::result::Result<ChatSessionSnapshot, ChatAuthError> {
        self.chat_auth.session_snapshot()
    }

    pub(crate) fn ensure_session_current(
        &self,
        session: &ChatSessionSnapshot,
    ) -> std::result::Result<(), OrchestratorError> {
        if self.chat_auth.session_is_current(session) {
            Ok(())
        } else {
            Err(OrchestratorError::Api(
                ChatAuthError::SessionChanged.to_string(),
            ))
        }
    }

    pub(crate) fn chat_auth_provider(&self) -> std::sync::Arc<ChatAuthProvider> {
        self.chat_auth.clone()
    }

    /// Require the server-admitted device binding before starting a
    /// clean-chat subscription. A local UUID, bearer token, or legacy ticket
    /// is not sufficient authority for the canonical stream.
    pub(crate) fn require_canonical_admission(&self) -> std::result::Result<(), ChatAuthError> {
        self.chat_auth.canonical_read_context().map(|_| ())
    }

    /// Every legacy MLS mutation is deliberately stopped at this boundary.
    /// The canonical signed adapter is not available in catmos yet, so a
    /// bearer-only request must never reach the network.
    pub(crate) fn reject_legacy_mutation<T>(&self, operation: &str) -> Result<T> {
        Err(OrchestratorError::Api(crate::recovery::actionable_error(
            format!("canonical signed {operation} is not wired; rebind required before mutation"),
        )))
    }

    pub fn clear_auth(&self) {
        self.chat_auth.clear();
    }

    async fn invalidate_device_authority_for_session(&self, session: &ChatSessionSnapshot) {
        // A late response from a previous account may not invalidate the
        // current account's runtime snapshot.
        let _ = self.chat_auth.clear_runtime_state_for_session(session);
    }

    pub fn get_auth_token(&self) -> Option<String> {
        self.chat_auth
            .session_snapshot()
            .ok()
            .map(|session| session.token)
    }

    #[cfg(test)]
    fn set_publish_device_id_for_tests(&self, device_id: impl Into<String>) {
        *self.publish_device_id_override.write().unwrap() = Some(device_id.into());
    }

    async fn current_publish_device_id(&self) -> Result<String> {
        #[cfg(test)]
        if let Some(device_id) = self.publish_device_id_override.read().unwrap().clone() {
            let device_id = device_id.trim().to_string();
            if !device_id.is_empty() {
                return Ok(device_id);
            }
        }

        let session = self
            .chat_auth
            .session_snapshot()
            .map_err(|_| OrchestratorError::NotAuthenticated)?;
        let store = crate::credentials::KeyringCredentialStore::try_new()?;
        let device_id = store
            .get_server_device_id(&session.actor_did)
            .await?
            .map(|device_id| device_id.trim().to_string())
            .filter(|device_id| !device_id.is_empty())
            .ok_or_else(|| {
                OrchestratorError::Api(
                    "Cannot publish key package before MLS device registration".to_string(),
                )
            })?;
        self.ensure_session_current(&session)?;
        Ok(device_id)
    }

    /// Reconcile the client-generated UUID with exactly one server device
    /// record and persist the minted server ID separately. This is the only
    /// production path that installs `server_device_id` into chat authority.
    #[cfg(test)]
    pub(crate) async fn resolve_server_device_id_for_local_uuid(
        &self,
        local_device_uuid: &str,
        expected_public_key: &[u8],
    ) -> Result<String> {
        let session = self
            .current_session()
            .map_err(|error| OrchestratorError::Api(error.to_string()))?;
        self.resolve_server_device_id_for_local_uuid_with_session(
            &session,
            local_device_uuid,
            expected_public_key,
        )
        .await
    }

    pub(crate) async fn list_devices_readonly(
        &self,
        session: &ChatSessionSnapshot,
        actor_device_id: &str,
    ) -> Result<Vec<DeviceInfo>> {
        self.ensure_session_current(session)?;
        self.list_devices_for_session(session, actor_device_id)
            .await
            .map(|snapshot| snapshot.devices)
    }

    pub(crate) async fn resolve_server_device_id_for_local_uuid_with_session(
        &self,
        session: &ChatSessionSnapshot,
        local_device_uuid: &str,
        expected_public_key: &[u8],
    ) -> Result<String> {
        let result = async {
            self.ensure_session_current(session)?;
            if !is_strict_uuid_v4(local_device_uuid) {
                return Err(OrchestratorError::Api(
                    "device reconciliation requires a canonical local UUIDv4".to_string(),
                ));
            }
            let expected_public_key = <[u8; 32]>::try_from(expected_public_key).map_err(|_| {
                OrchestratorError::Api(
                    "durable Ed25519 signer must expose a 32-byte public key".to_string(),
                )
            })?;
            let snapshot = self
                .list_devices_for_session(session, local_device_uuid)
                .await?;
            let server_device_id =
                resolve_unique_server_device_id(&snapshot.devices, local_device_uuid)?;
            let matching_rows = snapshot
                .devices
                .iter()
                .filter(|row| row.device_id == server_device_id)
                .collect::<Vec<_>>();
            if matching_rows.len() != 1 {
                return Err(OrchestratorError::Api(
                    "getOwnDevices binding row was not unique".to_string(),
                ));
            }
            let row = matching_rows[0];
            if row.status.as_deref() != Some("active") {
                return Err(OrchestratorError::Api(
                    "registered device is not active".to_string(),
                ));
            }
            let auth_generation = row
                .auth_generation
                .and_then(|value| u64::try_from(value).ok())
                .filter(|value| *value > 0)
                .ok_or_else(|| {
                    OrchestratorError::Api(
                        "registered device has no positive authGeneration".to_string(),
                    )
                })?;
            if row.signature_public_key.as_deref() != Some(expected_public_key.as_slice()) {
                return Err(OrchestratorError::Api(
                    "registered device public key does not match durable local signer".to_string(),
                ));
            }
            let key_id = row.key_id.as_deref().ok_or_else(|| {
                OrchestratorError::Api("registered device omitted keyId".to_string())
            })?;
            let parsed_key_id = catbird_mls::chat_v2::ids::KeyId::parse(key_id)
                .map_err(|error| OrchestratorError::Api(error.to_string()))?;
            if !parsed_key_id.matches_public_key(&expected_public_key) {
                return Err(OrchestratorError::Api(
                    "registered device keyId does not match durable local signer".to_string(),
                ));
            }
            self.ensure_session_current(session)?;
            self.chat_auth
                .admit_device_authority_for_session(
                    session,
                    DeviceAuthorityEvidence {
                        local_device_uuid: local_device_uuid.to_string(),
                        server_device_id: server_device_id.clone(),
                        auth_generation,
                    },
                )
                .map_err(|error| OrchestratorError::Api(error.to_string()))?;
            self.ensure_session_current(session)?;

            let store = crate::credentials::KeyringCredentialStore::try_new()?;
            store
                .store_server_device_id(&session.actor_did, &server_device_id)
                .await?;
            self.ensure_session_current(session)?;
            Ok(server_device_id)
        }
        .await;
        if result.is_err() {
            self.invalidate_device_authority_for_session(session).await;
        }
        result
    }

    /// Check if the current user is opted into MLS chat.
    pub async fn get_opt_in_status(&self, did: &str) -> Result<bool> {
        let token = self.auth_header()?;
        let did_parsed: Did = parse_did(did);
        let url = self.xrpc_url("blue.catbird.chat.getDevices");
        let resp = self
            .client
            .get(&url)
            .query(&[("userDids", did_parsed.as_str())])
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(self.handle_error(resp).await);
        }

        let body = resp
            .bytes()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        let output = parse_lexicon_json::<blue_catbird::chat::get_devices::GetDevicesOutput<String>>(
            body.as_ref(),
        )?;

        Ok(output
            .devices
            .iter()
            .any(|device| device.user_did.as_str() == did_parsed.as_str()))
    }

    /// Opt the current user into MLS chat.
    #[allow(unused_variables, unused_assignments, unreachable_code)]
    pub async fn opt_in(&self, device_id: Option<String>) -> Result<()> {
        let _ = device_id;
        self.reject_legacy_mutation("optIn")
    }

    /// Upload an encrypted group metadata blob keyed by a client-generated locator.
    #[allow(unused_variables, unused_assignments, unreachable_code)]
    pub async fn put_group_metadata_blob(
        &self,
        blob_locator: &str,
        group_id: &str,
        encrypted_blob: &[u8],
    ) -> Result<(String, usize)> {
        let _ = (blob_locator, group_id, encrypted_blob);
        self.reject_legacy_mutation("putGroupMetadataBlob")
    }

    /// Fetch an encrypted group metadata blob by locator.
    pub async fn get_group_metadata_blob(
        &self,
        blob_locator: &str,
        group_id: &str,
        kind: Option<&str>,
    ) -> Result<Vec<u8>> {
        let _ = (group_id, kind);
        self.get_blob(blob_locator).await
    }

    /// Fetch the latest encrypted group metadata blob for a group.
    pub async fn get_latest_group_metadata_blob(&self, group_id: &str) -> Result<Vec<u8>> {
        let _ = group_id;
        Err(OrchestratorError::ServerError {
            status: 404,
            body: r#"{"error":"NotFound","message":"No group metadata available"}"#.to_string(),
        })
    }

    /// Upload a generic opaque blob. The server assigns the final blob ID.
    pub async fn upload_blob(&self, data: &[u8], convo_id: &str) -> Result<(String, usize)> {
        let _ = (data, convo_id);
        self.require_canonical_admission()
            .map_err(|error| OrchestratorError::Api(crate::recovery::actionable_error(error)))?;
        Err(OrchestratorError::Api(crate::recovery::actionable_error(
            "canonical blob upload requires the shared signed prepareBlobUpload and upload-ticket adapter",
        )))
    }

    /// Fetch a clean-chat opaque blob by blob ID using the admitted canonical
    /// device identity. Blob bytes remain opaque and are never JSON-decoded.
    pub async fn get_blob(&self, blob_id: &str) -> Result<Vec<u8>> {
        let auth = self
            .chat_auth
            .canonical_read_context()
            .map_err(|error| OrchestratorError::Api(error.to_string()))?;
        let route = catbird_mls::orchestrator::canonical_route(
            catbird_mls::orchestrator::CanonicalOperation::GetBlob,
        );
        let path = format!(
            "{}?actorDeviceId={}&blobId={}",
            route.path,
            urlencoding::encode(&auth.device_id),
            urlencoding::encode(blob_id)
        );
        let resp = self
            .client
            .get(self.canonical_url(&path))
            .header(reqwest::header::AUTHORIZATION, &auth.authorization)
            .header("x-catbird-chat-device-id", &auth.device_id)
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(self.handle_error_for_session(resp, &auth.session).await);
        }

        let body = resp
            .bytes()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        self.ensure_session_current(&auth.session)?;
        Ok(body.to_vec())
    }

    fn xrpc_url(&self, nsid: &str) -> String {
        format!("{}/xrpc/{}", self.base_url, nsid)
    }

    fn auth_header(&self) -> Result<String> {
        self.current_session()
            .map(|session| session.token)
            .map_err(|_| OrchestratorError::NotAuthenticated)
    }

    async fn list_devices_for_session(
        &self,
        session: &ChatSessionSnapshot,
        actor_device_id: &str,
    ) -> Result<OwnDevicesSnapshot> {
        if !is_strict_uuid_v4(actor_device_id) {
            return Err(OrchestratorError::Api(
                "getOwnDevices requires the exact canonical actorDeviceId UUIDv4".to_string(),
            ));
        }
        let params = blue_catbird::chat::get_own_devices::GetOwnDevices::<String> {
            actor_device_id: actor_device_id.to_string(),
            limit: Some(100),
            page_cursor: None,
        };
        let resp = self
            .client
            .get(self.xrpc_url("blue.catbird.chat.getOwnDevices"))
            .query(&params)
            .bearer_auth(&session.token)
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(self.handle_error_for_session(resp, session).await);
        }

        let body = resp
            .bytes()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        let output = parse_lexicon_json::<
            blue_catbird::chat::get_own_devices::GetOwnDevicesOutput<String>,
        >(body.as_ref())?;
        self.ensure_session_current(session)?;

        let devices = output
            .items
            .iter()
            .map(|item| -> Result<DeviceInfo> {
                let device_id = item.device.device_id.to_string();
                Ok(DeviceInfo {
                    device_id: device_id.clone(),
                    // MLS device identity is scoped to one registered
                    // device, never the actor's bare DID.
                    mls_did: format!("{}#{}", session.actor_did, device_id),
                    // deviceId is the client-generated UUIDv4 used to
                    // reconcile a durable local signer with this row.
                    device_uuid: device_id,
                    created_at: item.device.created_at.to_string().parse().ok(),
                    key_id: Some(item.device.key_id.to_string()),
                    signature_public_key: Some(item.device.signature_public_key.to_vec()),
                    auth_generation: Some(item.device.auth_generation),
                    status: Some(item.device.status.to_string()),
                    available_package_count: u32::try_from(item.device.available_package_count)
                        .ok(),
                    reserved_package_count: u32::try_from(item.device.reserved_package_count).ok(),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(OwnDevicesSnapshot { devices })
    }

    async fn send_message_request(
        &self,
        convo_id: &str,
        ciphertext: &[u8],
        epoch: u64,
        msg_id: &str,
    ) -> Result<SendMessageResponse> {
        let _ = (convo_id, ciphertext, epoch, msg_id);
        Err(OrchestratorError::Api(crate::recovery::actionable_error(
            "legacy mlsChat sendMessage is disabled; canonical signed application transport is not wired for the generic MLS caller",
        )))
    }

    /// Internal helper that POSTs a recovery failure report to the server.
    /// Matches the `MLSAPIClient::report_recovery_failure` impl but lives on the
    /// concrete struct so it can be reused by `opt_in` / admin flows later.
    #[allow(unused_variables, unused_assignments, unreachable_code)]
    async fn post_recovery_failure(
        &self,
        convo_id: &str,
        failure_type: &str,
        epoch_authenticator: Option<&str>,
        failure_mode: Option<&str>,
    ) -> Result<()> {
        let session = self
            .current_session()
            .map_err(|error| OrchestratorError::Api(error.to_string()))?;
        self.ensure_session_current(&session)?;

        let mut body = serde_json::json!({
            "convoId": convo_id,
            "failureType": failure_type,
        });
        if let Some(auth) = epoch_authenticator {
            body["epochAuthenticator"] = serde_json::Value::String(auth.to_string());
        }
        if let Some(mode) = failure_mode {
            body["failureMode"] = serde_json::Value::String(mode.to_string());
        }

        let resp = self
            .client
            .post(self.xrpc_url("blue.catbird.chat.requestLeafRecovery"))
            .bearer_auth(&session.token)
            .json(&body)
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;

        let status = resp.status();
        if status.is_success() {
            return Ok(());
        }

        let status_code = status.as_u16();
        let body_text = resp.text().await.unwrap_or_default();

        if status_code == 403 {
            tracing::info!(
                convo_id,
                failure_type,
                body = %body_text,
                "report_recovery_failure: 403 (stale membership) — ignoring"
            );
            return Ok(());
        }

        tracing::warn!(
            convo_id,
            failure_type,
            status = status_code,
            body = %body_text,
            "report_recovery_failure: server rejected report"
        );
        Err(OrchestratorError::ServerError {
            status: status_code,
            body: body_text,
        })
    }

    /// Report a member as spam in an MLS conversation.
    pub async fn report_spam(
        &self,
        convo_id: &str,
        reported_did: &str,
        reason: Option<&str>,
    ) -> Result<()> {
        let session = self
            .current_session()
            .map_err(|error| OrchestratorError::Api(error.to_string()))?;
        self.ensure_session_current(&session)?;

        let mut body = serde_json::json!({
            "convoId": convo_id,
            "reportedDid": reported_did,
        });
        if let Some(r) = reason {
            body["reason"] = serde_json::Value::String(r.to_string());
        }

        let resp = self
            .client
            .post(self.xrpc_url("blue.catbird.chat.reportSpam"))
            .bearer_auth(&session.token)
            .json(&body)
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(self.handle_error_for_session(resp, &session).await);
        }
        Ok(())
    }

    /// Persist the read cursor using the generated lexicon DTO.
    ///
    /// This endpoint is intentionally kept separate from `MLSAPIClient`: read
    /// receipts do not affect MLS state and the orchestrator has no cursor
    /// abstraction yet. Keeping the request here still gives the desktop
    /// command the same authenticated, typed transport boundary as the other
    /// API calls.
    pub async fn update_cursor(&self, convo_id: &str, cursor: &str) -> Result<()> {
        let _ = (convo_id, cursor);
        Err(OrchestratorError::Api(crate::recovery::actionable_error(
            "legacy mlsChat updateCursor is disabled until a canonical subscription cursor adapter is available",
        )))
    }

    fn canonical_url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    async fn canonical_get_conversations(
        &self,
        limit: u32,
        cursor: Option<&str>,
    ) -> Result<ConversationListPage> {
        let auth = self
            .chat_auth
            .canonical_read_context()
            .map_err(|error| OrchestratorError::Api(error.to_string()))?;
        let route = catbird_mls::orchestrator::canonical_route(
            catbird_mls::orchestrator::CanonicalOperation::GetConversations,
        );
        let mut path = format!(
            "{}?actorDeviceId={}&limit={limit}",
            route.path,
            urlencoding::encode(&auth.device_id)
        );
        if let Some(cursor) = cursor {
            path.push_str("&pageCursor=");
            path.push_str(&urlencoding::encode(cursor));
        }

        let response = self
            .client
            .get(self.canonical_url(&path))
            .header(reqwest::header::AUTHORIZATION, &auth.authorization)
            .header("x-catbird-chat-device-id", &auth.device_id)
            .send()
            .await
            .map_err(|error| OrchestratorError::Api(error.to_string()))?;
        if !response.status().is_success() {
            return Err(self.handle_error_for_session(response, &auth.session).await);
        }
        let body = response
            .bytes()
            .await
            .map_err(|error| OrchestratorError::Api(error.to_string()))?;
        self.ensure_session_current(&auth.session)?;
        let output =
            catbird_mls::orchestrator::canonical_transport::decode_conversations_inventory(&body)
                .map_err(|error| {
                OrchestratorError::Api(format!("Canonical getConversations decode: {error}"))
            })?;

        let conversations = output
            .items
            .into_iter()
            .filter_map(|item| match item {
                catbird_atproto::blue_catbird::chat::ConversationInventoryItem::ConversationInventoryState(state) => {
                    Some(canonical_conversation_view(&state.state))
                }
                _ => None,
            })
            .collect();

        Ok(ConversationListPage {
            conversations,
            cursor: output.next_page_cursor.map(|value| value.to_string()),
        })
    }

    async fn canonical_get_entries(
        &self,
        convo_id: &str,
        cursor: Option<&str>,
        limit: u32,
        message_type: Option<&str>,
    ) -> Result<(Vec<IncomingEnvelope>, Option<String>)> {
        let auth = self
            .chat_auth
            .canonical_read_context()
            .map_err(|error| OrchestratorError::Api(error.to_string()))?;
        let after_seq = cursor
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(0);
        let route = catbird_mls::orchestrator::canonical_route(
            catbird_mls::orchestrator::CanonicalOperation::GetEntries,
        );
        let path = format!(
            "{}?actorDeviceId={}&afterSeq={after_seq}&conversationId={}&limit={limit}",
            route.path,
            urlencoding::encode(&auth.device_id),
            urlencoding::encode(convo_id)
        );
        let response = self
            .client
            .get(self.canonical_url(&path))
            .header(reqwest::header::AUTHORIZATION, &auth.authorization)
            .header("x-catbird-chat-device-id", &auth.device_id)
            .send()
            .await
            .map_err(|error| OrchestratorError::Api(error.to_string()))?;
        if !response.status().is_success() {
            return Err(self.handle_error_for_session(response, &auth.session).await);
        }
        let body = response
            .bytes()
            .await
            .map_err(|error| OrchestratorError::Api(error.to_string()))?;
        self.ensure_session_current(&auth.session)?;
        let output = parse_lexicon_json::<
            catbird_atproto::blue_catbird::chat::get_entries::GetEntriesOutput<String>,
        >(body.as_ref())?;
        let entries = output
            .entries
            .into_iter()
            .filter(|entry| canonical_entry_matches_type(entry, message_type))
            .map(|entry| map_canonical_entry(entry, convo_id))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .flatten()
            .collect();
        let next = if output.has_more {
            Some(output.next_after_seq.to_string())
        } else {
            None
        };
        Ok((entries, next))
    }

    async fn handle_error(&self, resp: reqwest::Response) -> OrchestratorError {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        OrchestratorError::ServerError { status, body }
    }

    async fn handle_error_for_session(
        &self,
        resp: reqwest::Response,
        session: &ChatSessionSnapshot,
    ) -> OrchestratorError {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        let normalized = body.to_ascii_lowercase();
        if matches!(status, 401 | 403)
            || normalized.contains("revoked")
            || normalized.contains("generation mismatch")
            || normalized.contains("auth_generation")
            || normalized.contains("device inactive")
        {
            self.invalidate_device_authority_for_session(session).await;
        }
        OrchestratorError::ServerError { status, body }
    }
}

fn canonical_entry_matches_type(
    entry: &catbird_atproto::blue_catbird::chat::ConversationEntry<String>,
    message_type: Option<&str>,
) -> bool {
    match message_type {
        Some("commit") => matches!(
            entry,
            catbird_atproto::blue_catbird::chat::ConversationEntry::CommitEntry(_)
                | catbird_atproto::blue_catbird::chat::ConversationEntry::LeafRecoveryFulfillmentEntry(_)
                | catbird_atproto::blue_catbird::chat::ConversationEntry::LeaveCommitFulfillmentEntry(_)
        ),
        Some("app") => matches!(
            entry,
            catbird_atproto::blue_catbird::chat::ConversationEntry::ApplicationEntry(_)
        ),
        Some("control") => !matches!(
            entry,
            catbird_atproto::blue_catbird::chat::ConversationEntry::ApplicationEntry(_)
                | catbird_atproto::blue_catbird::chat::ConversationEntry::CommitEntry(_)
                | catbird_atproto::blue_catbird::chat::ConversationEntry::LeafRecoveryFulfillmentEntry(_)
                | catbird_atproto::blue_catbird::chat::ConversationEntry::LeaveCommitFulfillmentEntry(_)
        ),
        _ => true,
    }
}

fn map_canonical_entry(
    entry: catbird_atproto::blue_catbird::chat::ConversationEntry<String>,
    expected_conversation_id: &str,
) -> Result<Option<IncomingEnvelope>> {
    let row =
        serde_json::to_value(entry).map_err(|error| OrchestratorError::Api(error.to_string()))?;
    IncomingEnvelope::from_canonical_entry(&row, expected_conversation_id)
}

#[async_trait]
impl MLSAPIClient for ReqwestApiClient {
    async fn is_authenticated_as(&self, did: &str) -> bool {
        self.chat_auth
            .session_snapshot()
            .is_ok_and(|session| session.actor_did == did)
    }

    async fn current_did(&self) -> Option<String> {
        self.chat_auth
            .session_snapshot()
            .ok()
            .map(|session| session.actor_did)
    }

    async fn submit_prepared_request(
        &self,
        request: catbird_mls::orchestrator::canonical_transport::PreparedRequest,
    ) -> Result<catbird_mls::orchestrator::canonical_transport::GatewayResponse> {
        let auth = self
            .chat_auth
            .canonical_read_context()
            .map_err(|error| OrchestratorError::Api(error.to_string()))?;
        let session = auth.session.clone();
        self.ensure_session_current(&session)?;

        use catbird_mls::orchestrator::canonical_transport::CanonicalOperation;
        let expected_path = request.operation.path();
        let request_base_path = request.path.split('?').next().unwrap_or_default();
        if request_base_path != expected_path {
            return Err(OrchestratorError::Api(format!(
                "prepared clean-chat route mismatch: operation {:?} requires {expected_path}, got {}",
                request.operation, request.path
            )));
        }
        let expected_method = match request.operation {
            CanonicalOperation::GetConversations
            | CanonicalOperation::GetBlob
            | CanonicalOperation::GetBlobUsage
            | CanonicalOperation::GetConversationState
            | CanonicalOperation::GetDevices
            | CanonicalOperation::GetEntries
            | CanonicalOperation::GetLeafRecoveryInbox
            | CanonicalOperation::GetOwnDevices
            | CanonicalOperation::GetPendingWelcomes
            | CanonicalOperation::GetSubscriptionTicket
            | CanonicalOperation::SubscribeEvents => "GET",
            _ => "POST",
        };
        if request.method != expected_method {
            return Err(OrchestratorError::Api(format!(
                "prepared clean-chat method mismatch: operation {:?} requires {expected_method}, got {}",
                request.operation, request.method
            )));
        }

        let url = self.canonical_url(&request.path);
        let mut builder = match request.method.as_str() {
            "POST" => self.client.post(&url),
            "GET" => self.client.get(&url),
            _ => unreachable!("method was checked against canonical operation"),
        };
        builder = builder.bearer_auth(&session.token);
        builder = builder.header("x-catbird-chat-device-id", &auth.device_id);
        if let Some(body) = request.body {
            builder = builder
                .body(body)
                .header(reqwest::header::CONTENT_TYPE, "application/json");
        }

        let resp = builder
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;

        let status = resp.status().as_u16();
        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(ToString::to_string);

        if matches!(status, 401 | 403) {
            self.invalidate_device_authority_for_session(&session).await;
        }

        let body = resp
            .bytes()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?
            .to_vec();

        self.ensure_session_current(&session)?;

        Ok(
            catbird_mls::orchestrator::canonical_transport::GatewayResponse {
                status,
                content_type,
                body,
            },
        )
    }

    async fn get_conversations(
        &self,
        limit: u32,
        cursor: Option<&str>,
    ) -> Result<ConversationListPage> {
        self.canonical_get_conversations(limit, cursor).await
    }

    async fn get_messages(
        &self,
        convo_id: &str,
        cursor: Option<&str>,
        limit: u32,
        message_type: Option<&str>,
        from_epoch: Option<u32>,
        to_epoch: Option<u32>,
    ) -> Result<(Vec<IncomingEnvelope>, Option<String>)> {
        let (mut entries, next_cursor) = self
            .canonical_get_entries(convo_id, cursor, limit, message_type)
            .await?;
        entries.retain(|entry| {
            let epoch = entry.server_epoch.unwrap_or_default();
            from_epoch
                .map(|from| epoch >= u64::from(from))
                .unwrap_or(true)
                && to_epoch.map(|to| epoch <= u64::from(to)).unwrap_or(true)
        });
        Ok((entries, next_cursor))
    }

    async fn get_key_packages(
        &self,
        actor_device_id: &str,
        dids: &[String],
    ) -> Result<Vec<KeyPackageRef>> {
        let authority = self
            .chat_auth
            .canonical_read_context()
            .map_err(|error| OrchestratorError::Api(error.to_string()))?;
        if actor_device_id != authority.device_id {
            return Err(OrchestratorError::Api(
                "getDevices actorDeviceId does not match admitted device authority".to_string(),
            ));
        }
        self.ensure_session_current(&authority.session)?;

        let mut query_params: Vec<(&str, &str)> = vec![("actorDeviceId", actor_device_id)];
        for did in dids {
            query_params.push(("userDids", did.as_str()));
        }
        let url = self.xrpc_url("blue.catbird.chat.getDevices");

        let resp = self
            .client
            .get(&url)
            .query(&query_params)
            .header(reqwest::header::AUTHORIZATION, &authority.authorization)
            .header("x-catbird-chat-device-id", &authority.device_id)
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(self
                .handle_error_for_session(resp, &authority.session)
                .await);
        }

        let body = resp
            .bytes()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        self.ensure_session_current(&authority.session)?;
        let output = parse_lexicon_json::<blue_catbird::chat::get_devices::GetDevicesOutput<String>>(
            body.as_ref(),
        )?;

        Ok(output
            .devices
            .iter()
            .map(|kp| KeyPackageRef {
                did: kp.user_did.to_string(),
                key_package_data: vec![],
                hash: Some(kp.key_id.to_string()),
                cipher_suite: "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519".to_string(),
            })
            .collect())
    }

    async fn get_key_package_stats(&self) -> Result<KeyPackageStats> {
        let authority = self
            .chat_auth
            .canonical_read_context()
            .map_err(|error| OrchestratorError::Api(error.to_string()))?;
        let snapshot = self
            .list_devices_for_session(&authority.session, &authority.device_id)
            .await?;
        let available: u32 = snapshot
            .devices
            .iter()
            .filter(|row| row.device_id == authority.device_id)
            .filter_map(|row| row.available_package_count)
            .sum();
        Ok(KeyPackageStats {
            available,
            total: available,
        })
    }

    async fn sync_key_packages(
        &self,
        _local_hashes: &[String],
        _device_id: &str,
    ) -> Result<KeyPackageSyncResult> {
        Ok(KeyPackageSyncResult {
            orphaned_count: 0,
            deleted_count: 0,
        })
    }

    async fn list_devices(&self, actor_device_id: &str) -> Result<Vec<DeviceInfo>> {
        let session = self
            .current_session()
            .map_err(|error| OrchestratorError::Api(error.to_string()))?;
        self.ensure_session_current(&session)?;
        self.list_devices_for_session(&session, actor_device_id)
            .await
            .map(|snapshot| snapshot.devices)
    }

    async fn get_group_info(&self, convo_id: &str) -> Result<Vec<u8>> {
        let auth = self
            .chat_auth
            .canonical_read_context()
            .map_err(|error| OrchestratorError::Api(error.to_string()))?;

        let resp = self
            .client
            .get(self.xrpc_url("blue.catbird.chat.getConversationState"))
            .header(reqwest::header::AUTHORIZATION, &auth.authorization)
            .header("x-catbird-chat-device-id", &auth.device_id)
            .query(&[
                ("actorDeviceId", auth.device_id.as_str()),
                ("conversationId", convo_id),
            ])
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(self.handle_error_for_session(resp, &auth.session).await);
        }

        let body = resp
            .bytes()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        self.ensure_session_current(&auth.session)?;
        let output = parse_lexicon_json::<
            blue_catbird::chat::get_conversation_state::GetConversationStateOutput<String>,
        >(body.as_ref())?;
        Ok(output.state.coordinates.group_id.as_ref().to_vec())
    }

    async fn get_welcome(&self, _convo_id: &str) -> Result<Vec<u8>> {
        Err(OrchestratorError::ServerError {
            status: 404,
            body: r#"{"error":"NotFound","message":"No welcome available"}"#.to_string(),
        })
    }

    async fn get_delivery_status(
        &self,
        _convo_id: &str,
        _message_ids: &[String],
    ) -> Result<Vec<(String, DeliveryStatus)>> {
        Ok(vec![])
    }

    async fn get_group_metadata_blob(
        &self,
        _convo_id: &str,
        _group_id_hex: &str,
        blob_locator: &str,
    ) -> Result<Vec<u8>> {
        self.get_blob(blob_locator).await
    }
}

#[cfg(test)]
mod tests {
    //! Wire-level regression tests for the double-base64 bug (task #66).
    //!
    //! History: catmos Tauri was constructing `commitGroupChange` inputs via
    //! the `catbird_atproto::catbird::mls_chat::commit_group_change::InputData`
    //! adapter. That adapter types byte fields as `Option<String>` and maps
    //! them to the generated `CommitGroupChange<'static>` struct via
    //! `bytes::Bytes::from(String)`, which copies the UTF-8 bytes of the
    //! string verbatim. Callers that pre-base64-encoded their commit bytes
    //! (the `Some(B64.encode(data))` pattern) therefore ended up with
    //! `Bytes(<ASCII-of-base64>)`, which Jacquard then base64-encoded AGAIN
    //! on the wire — yielding `{"$bytes": "<BASE64(ASCII-OF-BASE64)>"}`
    //! instead of `{"$bytes": "<BASE64(RAW)>"}`.
    //!
    //! The fix is `build_commit_group_change`, which constructs
    //! `CommitGroupChange<'static>` directly with
    //! `bytes::Bytes::from(Vec<u8>)`. These tests assert the wire output
    //! is singly-encoded (good) and explicitly check the old double-encoded
    //! output the buggy adapter would have produced (regression protection).
    use super::canonical_admission_projection_tests::{test_device_key_id, TEST_DEVICE_PUBLIC_KEY};
    use super::*;
    use catbird_mls::orchestrator::credentials::CredentialStore;

    // -------------------------------------------------------------------
    // reportRecoveryFailure wire test (Phase 1 / plan task 15)
    // -------------------------------------------------------------------
    //
    // Verifies that ReqwestApiClient::report_recovery_failure produces a
    // POST against the right xrpc path with the correct camelCase body
    // (including the optional epochAuthenticator + failureMode discriminators
    // from spec §8.6 / ADR-008 D1) and a Bearer auth header. Spawns an
    // in-process loopback HTTP listener so we exercise the actual reqwest
    // client end-to-end without bringing in wiremock.
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;

    pub(super) struct CapturedRequest {
        pub(super) method: String,
        pub(super) path: String,
        pub(super) headers: Vec<(String, String)>,
        pub(super) body: Vec<u8>,
    }

    /// Spawn a single-shot loopback HTTP server. Returns (base_url, recv).
    /// The server accepts ONE connection, parses one request, replies 200,
    /// and forwards the captured request to the channel. Bind to port 0 so
    /// tests run in parallel without collisions.
    pub(super) fn spawn_capture_server() -> (String, mpsc::Receiver<CapturedRequest>) {
        spawn_capture_server_with_status(200)
    }

    fn spawn_capture_server_with_status(status: u16) -> (String, mpsc::Receiver<CapturedRequest>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let port = listener.local_addr().expect("local_addr").port();
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            // Read until we see the end-of-headers marker, then drain
            // Content-Length more bytes for the body.
            let mut buf = Vec::with_capacity(4096);
            let mut chunk = [0u8; 1024];
            let header_end = loop {
                let n = stream.read(&mut chunk).expect("read headers");
                if n == 0 {
                    break buf.len();
                }
                buf.extend_from_slice(&chunk[..n]);
                if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    break pos + 4;
                }
            };
            let mut headers_buf = [httparse::EMPTY_HEADER; 32];
            let mut req = httparse::Request::new(&mut headers_buf);
            req.parse(&buf[..header_end]).expect("parse request");
            let method = req.method.unwrap_or("").to_string();
            let path = req.path.unwrap_or("").to_string();
            let mut content_length = 0usize;
            let headers: Vec<(String, String)> = req
                .headers
                .iter()
                .map(|h| {
                    let name = h.name.to_string();
                    let value = std::str::from_utf8(h.value).unwrap_or("").to_string();
                    if name.eq_ignore_ascii_case("content-length") {
                        content_length = value.parse().unwrap_or(0);
                    }
                    (name, value)
                })
                .collect();
            let mut body = buf[header_end..].to_vec();
            while body.len() < content_length {
                let n = stream.read(&mut chunk).expect("read body");
                if n == 0 {
                    break;
                }
                body.extend_from_slice(&chunk[..n]);
            }
            body.truncate(content_length);
            let reason = match status {
                401 => "Unauthorized",
                403 => "Forbidden",
                _ => "OK",
            };
            let response = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Length: 2\r\nContent-Type: application/json\r\n\r\n{{}}"
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = tx.send(CapturedRequest {
                method,
                path,
                headers,
                body,
            });
        });
        (format!("http://127.0.0.1:{port}"), rx)
    }

    pub(super) fn spawn_scripted_json_server(
        responses: Vec<(u16, String, std::time::Duration)>,
    ) -> (String, mpsc::Receiver<CapturedRequest>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let port = listener.local_addr().expect("local_addr").port();
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            for (status, body_text, delay) in responses {
                let (mut stream, _) = listener.accept().expect("accept");
                let captured = read_captured_request(&mut stream);
                tx.send(captured).expect("send captured request");
                std::thread::sleep(delay);
                let reason = match status {
                    401 => "Unauthorized",
                    403 => "Forbidden",
                    _ => "OK",
                };
                let response = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n{}",
                    body_text.len(),
                    body_text
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        (format!("http://127.0.0.1:{port}"), rx)
    }

    fn read_captured_request(stream: &mut std::net::TcpStream) -> CapturedRequest {
        let mut buf = Vec::with_capacity(4096);
        let mut chunk = [0u8; 1024];
        let header_end = loop {
            let n = stream.read(&mut chunk).expect("read headers");
            if n == 0 {
                break buf.len();
            }
            buf.extend_from_slice(&chunk[..n]);
            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break pos + 4;
            }
        };
        let mut headers_buf = [httparse::EMPTY_HEADER; 32];
        let mut req = httparse::Request::new(&mut headers_buf);
        req.parse(&buf[..header_end]).expect("parse request");
        let method = req.method.unwrap_or("").to_string();
        let path = req.path.unwrap_or("").to_string();
        let mut content_length = 0usize;
        let headers: Vec<(String, String)> = req
            .headers
            .iter()
            .map(|h| {
                let name = h.name.to_string();
                let value = std::str::from_utf8(h.value).unwrap_or("").to_string();
                if name.eq_ignore_ascii_case("content-length") {
                    content_length = value.parse().unwrap_or(0);
                }
                (name, value)
            })
            .collect();
        let mut body = buf[header_end..].to_vec();
        while body.len() < content_length {
            let n = stream.read(&mut chunk).expect("read body");
            if n == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..n]);
        }
        body.truncate(content_length);
        CapturedRequest {
            method,
            path,
            headers,
            body,
        }
    }

    pub(super) fn list_devices_body(did: &str, device_id: &str) -> String {
        let _ = did;
        let key_id = test_device_key_id();
        let public_key = base64::engine::general_purpose::STANDARD.encode(TEST_DEVICE_PUBLIC_KEY);
        format!(
            r#"{{"hasMore":false,"items":[{{"device":{{"authGeneration":1,"availablePackageCount":1,"createdAt":"2026-08-17T00:00:00.000Z","deviceId":"{device_id}","keyId":"{key_id}","reservedPackageCount":0,"signaturePublicKey":{{"$bytes":"{public_key}"}},"status":"active","updatedAt":"2026-08-17T00:00:00.000Z"}}}}],"snapshotExpiresAt":"2026-08-17T00:00:00.000Z"}}"#
        )
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn delayed_reconciliation_does_not_persist_after_account_switch() {
        let did_a = "did:plc:delayed-reconcile-a";
        let did_b = "did:plc:delayed-reconcile-b";
        let store = crate::credentials::KeyringCredentialStore::try_new()
            .expect("credential store should initialize");
        store
            .clear_all(did_a)
            .await
            .expect("clear account A fixture");
        store
            .clear_all(did_b)
            .await
            .expect("clear account B fixture");
        let device_id = "00000000-0000-4000-8000-00000000000a";

        let (base_url, requests) = spawn_scripted_json_server(vec![(
            200,
            list_devices_body(did_a, device_id),
            std::time::Duration::from_millis(150),
        )]);
        let client = std::sync::Arc::new(ReqwestApiClient::new(base_url));
        client.set_auth(did_a.to_string(), "token-a".to_string());
        let task_client = client.clone();
        let task = tokio::spawn(async move {
            task_client
                .resolve_server_device_id_for_local_uuid(device_id, &TEST_DEVICE_PUBLIC_KEY)
                .await
        });

        let request = requests
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("delayed listDevices request");
        assert!(request
            .headers
            .iter()
            .any(|(name, value)| name.eq_ignore_ascii_case("authorization")
                && value == "Bearer token-a"));
        client.set_auth(did_b.to_string(), "token-b".to_string());

        let error = task
            .await
            .expect("reconciliation task should join")
            .expect_err("old reconciliation must fail after account switch");
        assert!(
            error.to_string().contains("session changed"),
            "unexpected error: {error}"
        );
        assert!(
            store
                .get_server_device_id(did_a)
                .await
                .expect("read account A server ID")
                .is_none(),
            "stale account A response must not persist device authority"
        );
        assert!(
            store
                .get_server_device_id(did_b)
                .await
                .expect("read account B server ID")
                .is_none(),
            "account B must not receive account A device authority"
        );
        store
            .clear_all(did_a)
            .await
            .expect("clear account A fixture");
        store
            .clear_all(did_b)
            .await
            .expect("clear account B fixture");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn delayed_reconciliation_success_persists_only_for_captured_actor() {
        let did = "did:plc:delayed-reconcile-success";
        let store = crate::credentials::KeyringCredentialStore::try_new()
            .expect("credential store should initialize");
        store.clear_all(did).await.expect("clear success fixture");
        let device_id = "00000000-0000-4000-8000-00000000000b";
        let (base_url, requests) = spawn_scripted_json_server(vec![(
            200,
            list_devices_body(did, device_id),
            std::time::Duration::from_millis(100),
        )]);
        let client = std::sync::Arc::new(ReqwestApiClient::new(base_url));
        client.set_auth(did.to_string(), "token-success".to_string());
        let task_client = client.clone();
        let task = tokio::spawn(async move {
            task_client
                .resolve_server_device_id_for_local_uuid(device_id, &TEST_DEVICE_PUBLIC_KEY)
                .await
        });
        let request = requests
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("delayed listDevices request");
        assert!(request
            .headers
            .iter()
            .any(|(name, value)| name.eq_ignore_ascii_case("authorization")
                && value == "Bearer token-success"));
        assert_eq!(
            task.await
                .expect("reconciliation task should join")
                .expect("captured actor should reconcile successfully"),
            device_id
        );
        assert_eq!(
            store
                .get_server_device_id(did)
                .await
                .expect("read reconciled server ID")
                .as_deref(),
            Some(device_id)
        );
        store.clear_all(did).await.expect("clear success fixture");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn delayed_reconciliation_error_does_not_invalidate_new_account() {
        let did_a = "did:plc:delayed-error-a";
        let did_b = "did:plc:delayed-error-b";
        let (base_url, requests) = spawn_scripted_json_server(vec![(
            401,
            "{}".to_string(),
            std::time::Duration::from_millis(150),
        )]);
        let client = std::sync::Arc::new(ReqwestApiClient::new(base_url));
        client.set_auth(did_a.to_string(), "token-a".to_string());
        let device_a = "00000000-0000-4000-8000-00000000000c";
        let device_b = "00000000-0000-4000-8000-00000000000d";
        client.chat_auth.set_local_device_for_tests(device_a);
        client.chat_auth.set_device_for_tests(device_a);
        client.chat_auth.admit_for_tests(1);
        let task_client = client.clone();
        let task = tokio::spawn(async move {
            task_client
                .resolve_server_device_id_for_local_uuid(device_a, &TEST_DEVICE_PUBLIC_KEY)
                .await
        });

        requests
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("delayed listDevices request");
        client.set_auth(did_b.to_string(), "token-b".to_string());
        client.chat_auth.set_local_device_for_tests(device_b);
        client.chat_auth.set_device_for_tests(device_b);
        client.chat_auth.admit_for_tests(1);

        let error = task
            .await
            .expect("reconciliation task should join")
            .expect_err("401 reconciliation must fail");
        assert!(error.to_string().contains("401"));
        assert!(
            client.chat_auth.canonical_read_context().is_ok(),
            "account B authority must survive account A's delayed 401"
        );
    }

    #[tokio::test]
    async fn canonical_read_blocks_before_completed_binding() {
        let client = ReqwestApiClient::new("http://127.0.0.1:1".to_string());
        client.set_auth("did:plc:catmos-test".to_string(), "test-token".to_string());
        client
            .chat_auth
            .set_local_device_uuid(
                "did:plc:catmos-test",
                "00000000-0000-4000-8000-000000000001".to_string(),
            )
            .expect("test local UUID should install");
        client
            .chat_auth
            .set_resolved_server_device_id("did:plc:catmos-test", "server-device-1".to_string())
            .expect("test server device should install");

        let error = <ReqwestApiClient as MLSAPIClient>::get_messages(
            &client,
            "conversation-id",
            None,
            10,
            None,
            None,
            None,
        )
        .await
        .expect_err("canonical reads must not reach HTTP before binding admission");
        assert!(
            error
                .to_string()
                .contains("completed chat device binding is missing"),
            "unexpected error: {error:?}"
        );
    }

    #[tokio::test]
    async fn unauthorized_recovery_invalidates_runtime_only_for_401_and_403() {
        for status in [401, 403] {
            let (base_url, rx) = spawn_capture_server_with_status(status);
            let client = ReqwestApiClient::new(base_url);
            client.set_auth("did:plc:catmos-test".to_string(), "test-token".to_string());
            client
                .chat_auth
                .set_local_device_for_tests(TEST_AUTH_DEVICE_A);
            client.chat_auth.set_device_for_tests(TEST_AUTH_DEVICE_A);
            client.chat_auth.admit_for_tests(1);

            let error = <ReqwestApiClient as MLSAPIClient>::get_conversations(&client, 10, None)
                .await
                .expect_err("401/403 must reject the canonical read");
            assert!(error.to_string().contains(&status.to_string()));
            let _ = rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .expect("server received canonical request");

            let state = client.chat_auth.state.read().unwrap();
            assert_eq!(state.local_device_uuid.as_deref(), Some(TEST_AUTH_DEVICE_A));
            assert_eq!(state.server_device_id.as_deref(), Some(TEST_AUTH_DEVICE_A));
            assert!(state.binding.is_none());
        }
    }

    #[tokio::test]
    async fn every_legacy_mutation_gate_stops_before_bearer_http() {
        let (base_url, rx) = spawn_capture_server();
        let client = ReqwestApiClient::new(base_url);
        client.set_auth("did:plc:catmos-test".to_string(), "test-token".to_string());

        let error = client
            .opt_in(None)
            .await
            .expect_err("legacy opt-in must not use bearer-only HTTP");
        assert!(error.to_string().contains("canonical signed"));
        assert!(
            rx.recv_timeout(std::time::Duration::from_millis(100))
                .is_err(),
            "legacy mutation gate must reject before network"
        );
    }

    #[tokio::test]
    async fn get_blob_uses_canonical_route_and_admitted_server_device() {
        let (base_url, rx) = spawn_capture_server();
        let client = ReqwestApiClient::new(base_url);
        client.set_auth("did:plc:catmos-test".to_string(), "test-token".to_string());
        client
            .chat_auth
            .set_local_device_for_tests(TEST_AUTH_DEVICE_A);
        client.chat_auth.set_device_for_tests(TEST_AUTH_DEVICE_A);
        client.chat_auth.admit_for_tests(1);

        let body = client
            .get_blob("blob-1")
            .await
            .expect("admitted canonical blob read should accept opaque bytes");
        assert_eq!(body, b"{}".to_vec());

        let captured = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("server received canonical blob request");
        assert_eq!(
            captured.path,
            "/xrpc/blue.catbird.chat.getBlob?actorDeviceId=00000000-0000-4000-8000-000000000001&blobId=blob-1"
        );
        let device_header = captured
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("x-catbird-chat-device-id"))
            .expect("canonical blob request must carry the server device ID");
        assert_eq!(device_header.1, TEST_AUTH_DEVICE_A);
    }
}

#[test]
fn canonical_read_requires_session_before_http() {
    let provider = ChatAuthProvider::default();
    let error = provider
        .canonical_read_context()
        .expect_err("missing session must fail closed");
    assert_eq!(error, ChatAuthError::MissingSession);
}

#[test]
fn canonical_context_debug_redacts_bearer_material() {
    let context = CanonicalReadContext {
        actor_did: "did:plc:redaction".to_string(),
        authorization: "Bearer bearer-secret-for-red-test".to_string(),
        device_id: "server-device-1".to_string(),
        auth_generation: 7,
        session: ChatSessionSnapshot {
            actor_did: "did:plc:redaction".to_string(),
            token: "bearer-secret-for-red-test".to_string(),
            revision: 1,
        },
    };
    let rendered = format!("{context:?}");
    assert!(
        !rendered.contains("bearer-secret-for-red-test"),
        "Debug must not expose bearer material"
    );
    assert!(
        !rendered.contains("jkt-secret-for-red-test"),
        "Debug must not expose DPoP JKT material"
    );
}

#[cfg(test)]
fn test_device_info(device_id: &str, key_id: &str) -> DeviceInfo {
    DeviceInfo {
        device_id: device_id.to_string(),
        mls_did: format!("did:plc:catmos#{device_id}"),
        device_uuid: device_id.to_string(),
        created_at: None,
        key_id: Some(key_id.to_string()),
        signature_public_key: Some(vec![1, 2, 3]),
        auth_generation: Some(1),
        status: Some("active".to_string()),
        available_package_count: Some(0),
        reserved_package_count: Some(0),
    }
}

#[test]
fn list_devices_resolution_requires_exactly_one_local_uuid_match() {
    let device_id = "00000000-0000-4000-8000-000000000010";
    let devices = vec![test_device_info(device_id, "thumbprint-1")];
    assert_eq!(
        resolve_unique_server_device_id(&devices, device_id)
            .expect("one matching server row should resolve"),
        device_id
    );
    assert!(resolve_unique_server_device_id(&devices, "missing-local-device").is_err());

    let duplicate = vec![
        test_device_info(device_id, "thumbprint-1"),
        test_device_info(device_id, "thumbprint-2"),
    ];
    assert!(resolve_unique_server_device_id(&duplicate, device_id).is_err());
}

#[test]
fn local_uuid_cannot_authorize_without_server_id_and_binding() {
    let provider = ChatAuthProvider::default();
    provider.set_session_for_tests("did:plc:catmos", "opaque-session");
    provider.set_local_device_for_tests("local-device-1");
    let error = provider
        .canonical_read_context()
        .expect_err("local UUID must never authorize a canonical request");
    assert_eq!(error, ChatAuthError::MissingDevice);
}

#[test]
fn authority_lifecycle_clears_on_account_switch_and_generation_mismatch() {
    let provider = ChatAuthProvider::default();
    provider.set_session_for_tests("did:plc:first", "opaque-session");
    provider.set_local_device_for_tests(TEST_AUTH_DEVICE_A);
    provider.set_device_for_tests(TEST_AUTH_DEVICE_A);
    let first_session = provider.session_snapshot().unwrap();
    assert!(provider
        .admit_device_authority_for_session(
            &first_session,
            DeviceAuthorityEvidence {
                local_device_uuid: TEST_AUTH_DEVICE_A.to_string(),
                server_device_id: TEST_AUTH_DEVICE_A.to_string(),
                auth_generation: 7,
            },
        )
        .is_ok());
    assert!(provider.canonical_read_context().is_ok());

    provider.set_session_for_tests("did:plc:second", "opaque-session");
    assert_eq!(
        provider
            .canonical_read_context()
            .expect_err("account switch clears authority"),
        ChatAuthError::MissingLocalDeviceUuid
    );

    provider.set_session_for_tests("did:plc:second", "opaque-session");
    provider.set_local_device_for_tests(TEST_AUTH_DEVICE_B);
    provider.set_device_for_tests(TEST_AUTH_DEVICE_B);
    let second_session = provider.session_snapshot().unwrap();
    provider
        .admit_device_authority_for_session(
            &second_session,
            DeviceAuthorityEvidence {
                local_device_uuid: TEST_AUTH_DEVICE_B.to_string(),
                server_device_id: TEST_AUTH_DEVICE_B.to_string(),
                auth_generation: 2,
            },
        )
        .expect("test binding should admit");
    let error = provider
        .invalidate_for_generation("did:plc:second", 3)
        .expect_err("generation mismatch invalidates authority");
    assert_eq!(
        error,
        ChatAuthError::AuthGenerationMismatch {
            expected: 2,
            observed: 3
        }
    );
    assert_eq!(
        provider
            .canonical_read_context()
            .expect_err("invalidated authority must not authorize"),
        ChatAuthError::MissingDeviceBinding
    );
}

#[test]
fn authority_snapshot_rejects_late_evidence_from_an_old_actor() {
    let provider = ChatAuthProvider::default();
    provider.set_session_for_tests("did:plc:first", "first-token");
    provider.set_local_device_for_tests(TEST_AUTH_DEVICE_A);
    provider.set_device_for_tests(TEST_AUTH_DEVICE_A);
    provider.admit_for_tests(7);
    let old_session = provider.session_snapshot().unwrap();
    let first = provider
        .canonical_read_context()
        .expect("first actor should have a complete test snapshot");
    assert_eq!(first.actor_did, "did:plc:first");
    assert_eq!(first.authorization, "Bearer first-token");

    provider.set_session_for_tests("did:plc:second", "second-token");
    assert_eq!(
        provider
            .admit_device_authority_for_session(
                &old_session,
                DeviceAuthorityEvidence {
                    local_device_uuid: TEST_AUTH_DEVICE_A.to_string(),
                    server_device_id: TEST_AUTH_DEVICE_A.to_string(),
                    auth_generation: 7,
                },
            )
            .expect_err("old actor evidence must not mutate the new snapshot"),
        ChatAuthError::SessionChanged
    );
    assert_eq!(
        provider
            .canonical_read_context()
            .expect_err("new actor has no mixed device state"),
        ChatAuthError::MissingLocalDeviceUuid
    );
}

#[test]
fn concurrent_account_updates_keep_one_actor_bound_snapshot() {
    let provider = std::sync::Arc::new(ChatAuthProvider::default());
    let first = provider.clone();
    let first_thread = std::thread::spawn(move || {
        for _ in 0..64 {
            first.set_session("did:plc:first".to_string(), "first-token".to_string());
            let _ = first.set_local_device_uuid("did:plc:first", "local-device-1".to_string());
            let _ =
                first.set_resolved_server_device_id("did:plc:first", "server-device-1".to_string());
        }
    });
    let second = provider.clone();
    let second_thread = std::thread::spawn(move || {
        for _ in 0..64 {
            second.set_session("did:plc:second".to_string(), "second-token".to_string());
            let _ = second.set_local_device_uuid("did:plc:second", "local-device-2".to_string());
            let _ = second
                .set_resolved_server_device_id("did:plc:second", "server-device-2".to_string());
        }
    });
    first_thread.join().expect("first account update thread");
    second_thread.join().expect("second account update thread");

    let state = provider.state.read().unwrap();
    match state.actor_did.as_deref() {
        Some("did:plc:first") => {
            assert!(state
                .local_device_uuid
                .as_deref()
                .is_none_or(|value| value == "local-device-1"));
            assert!(state
                .server_device_id
                .as_deref()
                .is_none_or(|value| value == "server-device-1"));
        }
        Some("did:plc:second") => {
            assert!(state
                .local_device_uuid
                .as_deref()
                .is_none_or(|value| value == "local-device-2"));
            assert!(state
                .server_device_id
                .as_deref()
                .is_none_or(|value| value == "server-device-2"));
        }
        actor => panic!("unexpected actor snapshot: {actor:?}"),
    }
}

#[test]
fn session_revision_rejects_late_mutation_after_token_refresh() {
    let provider = ChatAuthProvider::default();
    provider.set_session_for_tests("did:plc:revision", "token-one");
    let first = provider
        .session_snapshot()
        .expect("first immutable session snapshot");
    provider.set_session_for_tests("did:plc:revision", "token-two");
    assert!(!provider.session_is_current(&first));
    assert_eq!(
        provider
            .set_local_device_uuid_for_session(&first, "local-stale".to_string())
            .expect_err("stale session must not mutate current authority"),
        ChatAuthError::SessionChanged
    );
    let current = provider
        .session_snapshot()
        .expect("refreshed immutable session snapshot");
    provider
        .set_local_device_uuid_for_session(&current, "local-current".to_string())
        .expect("current session may mutate authority");
    assert_eq!(
        provider.state.read().unwrap().local_device_uuid.as_deref(),
        Some("local-current")
    );
}

#[test]
fn admitted_context_survives_login_restore_and_requires_re_admission_on_relogin() {
    let provider = ChatAuthProvider::default();
    provider.set_session_for_tests("did:plc:activation", "token-one");
    let first = provider.session_snapshot().unwrap();
    provider
        .admit_device_authority_for_session(
            &first,
            DeviceAuthorityEvidence {
                local_device_uuid: TEST_AUTH_DEVICE_A.to_string(),
                server_device_id: TEST_AUTH_DEVICE_A.to_string(),
                auth_generation: 5,
            },
        )
        .expect("login should atomically publish admitted authority");
    assert_eq!(
        provider
            .canonical_read_context()
            .expect("completed login must retain canonical authority")
            .auth_generation,
        5
    );

    // Restoring the exact same opaque session must be idempotent and must not
    // clear the tuple that reconciliation just admitted.
    provider.set_session_for_tests("did:plc:activation", "token-one");
    assert!(provider.canonical_read_context().is_ok());

    // A new opaque session for the same account revokes runtime authority;
    // the same exact device row can then be re-admitted under that snapshot.
    provider.set_session_for_tests("did:plc:activation", "token-two");
    assert_eq!(
        provider
            .canonical_read_context()
            .expect_err("relogin must not inherit the prior gateway session"),
        ChatAuthError::MissingDeviceBinding
    );
    let second = provider.session_snapshot().unwrap();
    provider
        .admit_device_authority_for_session(
            &second,
            DeviceAuthorityEvidence {
                local_device_uuid: TEST_AUTH_DEVICE_A.to_string(),
                server_device_id: TEST_AUTH_DEVICE_A.to_string(),
                auth_generation: 6,
            },
        )
        .expect("relogin should re-admit the exact device row");
    assert_eq!(
        provider
            .canonical_read_context()
            .expect("relogin activation must publish canonical authority")
            .auth_generation,
        6
    );
}

#[test]
fn runtime_invalidation_retains_identity_for_exact_reconciliation() {
    let provider = ChatAuthProvider::default();
    provider.set_session_for_tests("did:plc:catmos", "opaque-session");
    provider.set_local_device_for_tests(TEST_AUTH_DEVICE_A);
    provider.set_device_for_tests(TEST_AUTH_DEVICE_A);
    provider.admit_for_tests(1);

    provider.clear_device_authority();
    let state = provider.state.read().unwrap();
    assert_eq!(state.local_device_uuid.as_deref(), Some(TEST_AUTH_DEVICE_A));
    assert_eq!(state.server_device_id.as_deref(), Some(TEST_AUTH_DEVICE_A));
    assert!(state.binding.is_none());
    drop(state);
    assert_eq!(
        provider
            .canonical_read_context()
            .expect_err("runtime invalidation must remove authority"),
        ChatAuthError::MissingDeviceBinding
    );

    provider.set_session_for_tests("did:plc:catmos", "refreshed-session");
    let state = provider.state.read().unwrap();
    assert_eq!(state.local_device_uuid.as_deref(), Some(TEST_AUTH_DEVICE_A));
    assert_eq!(state.server_device_id.as_deref(), Some(TEST_AUTH_DEVICE_A));
    assert!(state.binding.is_none());
}

#[test]
fn canonical_read_requires_registered_device_before_http() {
    let provider = ChatAuthProvider::default();
    provider.set_session_for_tests("did:plc:catmos", "opaque-session");
    provider.set_local_device_for_tests("00000000-0000-4000-8000-000000000001");
    let error = provider
        .canonical_read_context()
        .expect_err("missing device must fail closed");
    assert_eq!(error, ChatAuthError::MissingDevice);
}

#[test]
fn canonical_read_requires_completed_device_authority_before_http() {
    let provider = ChatAuthProvider::default();
    provider.set_session_for_tests("did:plc:catmos", "opaque-session");
    provider.set_local_device_for_tests("00000000-0000-4000-8000-000000000001");
    provider.set_device_for_tests("00000000-0000-4000-8000-000000000001");
    let error = provider.canonical_read_context().expect_err(
        "a local UUID and server device ID without a completed binding must fail closed",
    );
    assert_eq!(error, ChatAuthError::MissingDeviceBinding);
}

#[test]
fn canonical_read_requires_current_auth_generation_before_http() {
    let provider = ChatAuthProvider::default();
    provider.set_session_for_tests("did:plc:catmos", "opaque-session");
    provider.set_local_device_for_tests(TEST_AUTH_DEVICE_A);
    provider.set_device_for_tests(TEST_AUTH_DEVICE_A);
    provider.state.write().unwrap().binding = Some(CompletedDeviceBinding {
        server_device_id: TEST_AUTH_DEVICE_A.to_string(),
        auth_generation: 0,
    });
    let error = provider
        .canonical_read_context()
        .expect_err("missing current generation must fail before HTTP");
    assert_eq!(error, ChatAuthError::MissingAuthGeneration);
}

#[test]
fn canonical_entries_preserve_commit_epochs() {
    let conversation_id = "00000000-0000-4000-8000-000000000001";
    let envelope = IncomingEnvelope::from_canonical_entry(&serde_json::json!({
        "$type": "blue.catbird.chat.defs#commitEntry",
        "conversationId": conversation_id,
        "entryId": "00000000-0000-4000-8000-000000000002",
        "seq": 51,
        "receivedAt": "2026-08-16T12:00:00.000Z",
        "signedRequest": {"body": {"actorDid": "did:plc:sender",
            "prior": {"conversationId": conversation_id}, "next": {"conversationId": conversation_id, "epoch": 5},
            "commit": {"bytes": "AQI="}
        }}
    }), conversation_id).unwrap().unwrap();
    assert_eq!(envelope.server_epoch, Some(5));
    assert_eq!(envelope.server_sequence, Some(51));
    assert_eq!(envelope.ciphertext, vec![1, 2]);
}

#[cfg(test)]
mod canonical_admission_projection_tests {
    use super::tests::{list_devices_body, spawn_capture_server, spawn_scripted_json_server};
    use super::*;
    use catbird_mls::orchestrator::canonical_transport::{
        decode_conversation_state, decode_conversations_inventory, encode_conversation_state,
    };

    fn inventory(wire: serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "items": [{"$type": "blue.catbird.chat.defs#conversationInventoryState", "state": wire}],
            "hasMore": true, "nextPageCursor": "page-2", "inventorySessionId": "inventory-session",
            "snapshotEventCursor": "event-fence", "snapshotExpiresAt": "2026-09-05T12:00:00.000Z"
        })).unwrap()
    }

    #[test]
    fn canonical_pending_and_accepted_leafless_views_keep_exact_snapshot() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/canonical-conversation-state.json"
        ))
        .unwrap();
        for (status, version) in [("pending", 41), ("active", 42)] {
            let mut wire = fixture.clone();
            wire["participants"][1]["status"] = serde_json::json!(status);
            wire["coordinates"]["stateVersion"] = serde_json::json!(version);
            wire["snapshotSeq"] = serde_json::json!(version + 4);
            let expected = decode_conversation_state(wire.to_string().as_bytes()).unwrap();
            let mut page = decode_conversations_inventory(&inventory(wire)).unwrap();
            assert_eq!(page.next_page_cursor.as_deref(), Some("page-2"));
            assert_eq!(page.inventory_session_id, "inventory-session");
            assert_eq!(page.snapshot_event_cursor, "event-fence");
            let catbird_atproto::blue_catbird::chat::ConversationInventoryItem::ConversationInventoryState(item) = page.items.remove(0) else { panic!("missing canonical state") };
            let state = item.state;
            assert_eq!(state, expected);
            let view = canonical_conversation_view(&state);
            assert_eq!(view.canonical_state.as_ref(), Some(&state));
            assert_eq!(view.epoch, state.coordinates.epoch as u64);
            assert_eq!(
                view.group_id,
                hex::encode(state.coordinates.group_id.as_ref())
            );
            let persisted: ConversationView =
                serde_json::from_slice(&serde_json::to_vec(&view).unwrap()).unwrap();
            let retained = persisted.canonical_state.unwrap();
            assert_eq!(
                decode_conversation_state(&encode_conversation_state(&retained).unwrap()).unwrap(),
                state
            );
            assert_eq!(retained.participants[1].status, status);
            assert_eq!(retained.participants[1].leaf_count, 0);
            assert_eq!(
                retained.participants[1].invitation_provenance,
                state.participants[1].invitation_provenance
            );
            assert!(view.created_at.is_none());
            assert!(view.metadata.is_none());
        }
    }

    #[test]
    fn legacy_view_is_unknown_and_malformed_canonical_state_is_rejected() {
        let mut wire: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/canonical-conversation-state.json"
        ))
        .unwrap();
        let state = decode_conversation_state(wire.to_string().as_bytes()).unwrap();
        let view = canonical_conversation_view(&state);
        let mut old_view = serde_json::to_value(view).unwrap();
        assert!(old_view
            .as_object_mut()
            .unwrap()
            .remove("canonicalState")
            .is_some());
        let legacy: ConversationView = serde_json::from_value(old_view).unwrap();
        assert!(legacy.canonical_state.is_none());
        wire["participants"][1]["status"] = serde_json::json!("unknown");
        assert!(decode_conversations_inventory(&inventory(wire)).is_err());
    }
    pub(super) const TEST_DEVICE_PUBLIC_KEY: [u8; 32] = [7; 32];

    pub(super) fn test_device_key_id() -> String {
        catbird_mls::chat_v2::ids::KeyId::from_public_key(&TEST_DEVICE_PUBLIC_KEY).to_string()
    }

    #[tokio::test]
    async fn own_device_view_populates_complete_scoped_device_identity() {
        let did = "did:plc:device-view-owner";
        let device_id = "00000000-0000-4000-8000-000000000001";
        let key_id = test_device_key_id();
        let (base_url, requests) = spawn_scripted_json_server(vec![(
            200,
            list_devices_body(did, device_id),
            std::time::Duration::ZERO,
        )]);
        let client = ReqwestApiClient::new(base_url);
        client.set_auth(did.to_string(), "device-view-token".to_string());
        let session = client.current_session().unwrap();

        let snapshot = client
            .list_devices_for_session(&session, device_id)
            .await
            .unwrap();
        let request = requests
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("getOwnDevices should reach the gateway");
        assert!(request
            .path
            .contains("actorDeviceId=00000000-0000-4000-8000-000000000001"));
        assert_eq!(snapshot.devices.len(), 1);
        let device = &snapshot.devices[0];
        assert_eq!(device.device_id, device_id);
        assert_eq!(device.mls_did, format!("{did}#{device_id}"));
        assert_eq!(device.device_uuid, device_id);
        assert!(device.created_at.is_some());
        assert_eq!(device.key_id.as_deref(), Some(key_id.as_str()));
        assert_eq!(
            device.signature_public_key.as_deref(),
            Some(TEST_DEVICE_PUBLIC_KEY.as_slice())
        );
        assert_eq!(device.auth_generation, Some(1));
        assert_eq!(device.status.as_deref(), Some("active"));
        assert_eq!(device.available_package_count, Some(1));
        assert_eq!(device.reserved_package_count, Some(0));
    }

    fn prepared_reset_request(
        body: Vec<u8>,
    ) -> catbird_mls::orchestrator::canonical_transport::PreparedRequest {
        catbird_mls::orchestrator::canonical_transport::PreparedRequest {
            operation:
                catbird_mls::orchestrator::canonical_transport::CanonicalOperation::RequestReset,
            method: "POST".to_string(),
            path: "/xrpc/blue.catbird.chat.requestReset".to_string(),
            body: Some(body),
        }
    }

    fn admit_test_client(client: &ReqwestApiClient, actor_did: &str, token: &str) {
        client.set_auth(actor_did.to_string(), token.to_string());
        client
            .chat_auth
            .set_local_device_for_tests(TEST_AUTH_DEVICE_A);
        client.chat_auth.set_device_for_tests(TEST_AUTH_DEVICE_A);
        client.chat_auth.admit_for_tests(1);
    }

    #[tokio::test]
    async fn prepared_transport_keeps_gateway_auth_out_of_the_request_value() {
        let (base_url, requests) = spawn_capture_server();
        let client = ReqwestApiClient::new(base_url);
        let bearer = "opaque-session-token";
        admit_test_client(&client, "did:plc:prepared-owner", bearer);
        let body = br#"{"convoId":"00000000-0000-4000-8000-000000000001"}"#.to_vec();
        let request = prepared_reset_request(body.clone());

        let rendered = format!("{request:?}");
        assert!(!rendered.contains(bearer));

        let response = client
            .submit_prepared_request(request)
            .await
            .expect("gateway should submit prepared request");
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"{}".to_vec());

        let captured = requests
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("server should receive prepared request");
        assert_eq!(captured.method, "POST");
        assert_eq!(captured.path, "/xrpc/blue.catbird.chat.requestReset");
        assert_eq!(captured.body, body);
        assert!(captured.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("authorization") && value == &format!("Bearer {bearer}")
        }));
    }

    #[tokio::test]
    async fn prepared_transport_rejects_route_or_method_confusion_before_http() {
        let (base_url, requests) = spawn_capture_server();
        let client = ReqwestApiClient::new(base_url);
        admit_test_client(&client, "did:plc:prepared-route", "opaque-route-token");

        let mut wrong_path = prepared_reset_request(b"{}".to_vec());
        wrong_path.path = "/xrpc/blue.catbird.chat.sendMessage".to_string();
        assert!(client.submit_prepared_request(wrong_path).await.is_err());

        let mut wrong_method = prepared_reset_request(b"{}".to_vec());
        wrong_method.method = "PATCH".to_string();
        assert!(client.submit_prepared_request(wrong_method).await.is_err());

        assert!(requests
            .recv_timeout(std::time::Duration::from_millis(100))
            .is_err());
    }

    #[tokio::test]
    async fn prepared_transport_preserves_non_success_status_content_type_and_body() {
        let response_body = r#"{"error":"projectionFenceMismatch"}"#.to_string();
        let (base_url, requests) = spawn_scripted_json_server(vec![(
            409,
            response_body.clone(),
            std::time::Duration::ZERO,
        )]);
        let client = ReqwestApiClient::new(base_url);
        admit_test_client(&client, "did:plc:prepared-status", "opaque-status-token");

        let response = client
            .submit_prepared_request(prepared_reset_request(b"{}".to_vec()))
            .await
            .expect("gateway response status is data, not a transport error");
        assert_eq!(response.status, 409);
        assert_eq!(response.content_type.as_deref(), Some("application/json"));
        assert_eq!(response.body, response_body.as_bytes());
        requests
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("server should receive prepared request");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn delayed_prepared_response_is_rejected_after_account_switch() {
        let (base_url, requests) = spawn_scripted_json_server(vec![(
            200,
            "{}".to_string(),
            std::time::Duration::from_millis(150),
        )]);
        let client = std::sync::Arc::new(ReqwestApiClient::new(base_url));
        admit_test_client(&client, "did:plc:prepared-a", "token-a");
        let task_client = client.clone();
        let task = tokio::spawn(async move {
            task_client
                .submit_prepared_request(prepared_reset_request(b"{}".to_vec()))
                .await
        });

        let captured = requests
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("account A request should reach gateway");
        assert!(captured.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("authorization") && value == "Bearer token-a"
        }));
        client.set_auth("did:plc:prepared-b".to_string(), "token-b".to_string());

        let error = task
            .await
            .expect("prepared request task should join")
            .expect_err("account A response cannot complete under account B");
        assert!(error.to_string().contains("session changed"));
    }

    #[tokio::test]
    async fn get_devices_binds_exact_admitted_actor_device_before_http() {
        let (base_url, requests) = spawn_scripted_json_server(vec![(
            200,
            r#"{"devices":[]}"#.to_string(),
            std::time::Duration::ZERO,
        )]);
        let client = ReqwestApiClient::new(base_url);
        admit_test_client(&client, "did:plc:get-devices-owner", "get-devices-token");

        let mismatch = <ReqwestApiClient as MLSAPIClient>::get_key_packages(
            &client,
            TEST_AUTH_DEVICE_B,
            &["did:plc:target".to_string()],
        )
        .await
        .expect_err("a caller-supplied cross-device coordinate must fail before HTTP");
        assert!(mismatch.to_string().contains("does not match admitted"));
        assert!(requests
            .recv_timeout(std::time::Duration::from_millis(100))
            .is_err());

        let packages = <ReqwestApiClient as MLSAPIClient>::get_key_packages(
            &client,
            TEST_AUTH_DEVICE_A,
            &["did:plc:target".to_string()],
        )
        .await
        .expect("the exact admitted device may reach getDevices");
        assert!(packages.is_empty());
        let captured = requests
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("getDevices should reach the gateway once");
        assert!(captured
            .path
            .contains(&format!("actorDeviceId={TEST_AUTH_DEVICE_A}")));
        assert!(captured.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("x-catbird-chat-device-id") && value == TEST_AUTH_DEVICE_A
        }));
    }
}

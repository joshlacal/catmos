use async_trait::async_trait;
use catbird_atproto::blue_catbird;
use catbird_atproto::jacquard_common::IntoStatic;
use reqwest::Client;
use std::sync::RwLock;

use catbird_mls::orchestrator::api_client::MLSAPIClient;
use catbird_mls::orchestrator::error::{OrchestratorError, Result};
use catbird_mls::orchestrator::types::*;

// Generated lexicon types
use crate::catbird::mls_chat as lexicon;
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

/// Resolve one server-minted device ID from the client-generated UUID.
///
/// A UUID is only a correlation key: it is not itself accepted as the
/// device authority. Zero matches, duplicate matches, or an empty server ID
/// are all ambiguous and fail closed.
fn resolve_unique_server_device_id(
    devices: &[DeviceInfo],
    local_device_uuid: &str,
) -> Result<String> {
    let local_device_uuid = local_device_uuid.trim();
    if local_device_uuid.is_empty() {
        return Err(OrchestratorError::Api(
            "cannot resolve server device ID without a local device UUID".to_string(),
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

fn parse_commit_group_change_receipt<S: catbird_atproto::jacquard_common::BosStr>(
    output: &blue_catbird::mlsChat::commit_group_change::CommitGroupChangeOutput<S>,
    op: &str,
) -> Option<SequencerReceipt> {
    let receipt = output.extra_data.as_ref().and_then(|extra| {
        extra.get("receipt").or_else(|| {
            extra
                .values()
                .find_map(|value| value.as_object().and_then(|object| object.get("receipt")))
        })
    });

    let receipt = match receipt {
        Some(value) => value,
        None => return None,
    };

    match parse_sequencer_receipt_data(receipt) {
        Ok(receipt) => Some(receipt),
        Err(error) => {
            tracing::warn!(
                operation = op,
                error = %error,
                "Failed to parse sequencer receipt; continuing without receipt"
            );
            None
        }
    }
}

/// Build a `CommitGroupChange<'static>` for the wire **without** going through
/// the buggy `InputData → Input` adapter in `catbird-atproto`.
///
/// Why not use `crate::catbird::mls_chat::commit_group_change::InputData`?
/// That adapter types `commit` / `welcome` / `group_info` / `confirmation_tag`
/// as `Option<String>`, and its `From<InputData> for Input` impl maps them via
/// `String → bytes::Bytes`. `bytes::Bytes::from(String)` takes the UTF-8 bytes
/// of the string verbatim — so when callers pass a pre-base64 string, the
/// bytes field ends up containing the ASCII of the base64 text and the
/// jacquard serializer then wraps it as `{"$bytes": base64(ASCII-base64)}`,
/// producing double-encoded commits the server rejects or silently
/// mis-decodes. Building the lexicon struct directly lets us pass raw
/// `bytes::Bytes::from(Vec<u8>)` so the single serializer layer does the one
/// correct base64 encode.
///
/// Bug tracking: catmos task #66 (April 2026). See catmos-cli commit
/// `1ecf9e4` for the reference fix pattern.
#[allow(clippy::too_many_arguments)]
fn build_commit_group_change(
    convo_id: &str,
    action: &str,
    commit: Option<Vec<u8>>,
    welcome: Option<Vec<u8>>,
    group_info: Option<Vec<u8>>,
    confirmation_tag: Option<Vec<u8>>,
    member_dids: Option<Vec<Did>>,
    idempotency_key: Option<String>,
) -> blue_catbird::mlsChat::commit_group_change::CommitGroupChange {
    blue_catbird::mlsChat::commit_group_change::CommitGroupChange {
        action: blue_catbird::mlsChat::commit_group_change::CommitGroupChangeAction::from_value(
            action.to_string().into(),
        ),
        commit: commit.map(bytes::Bytes::from),
        confirmation_tag: confirmation_tag.map(bytes::Bytes::from),
        convo_id: convo_id.to_string().into(),
        device_id: None,
        epoch_authenticator: None,
        group_info: group_info.map(bytes::Bytes::from),
        idempotency_key: idempotency_key.map(Into::into),
        key_package_hashes: None,
        member_dids,
        pending_addition_id: None,
        welcome: welcome.map(bytes::Bytes::from),
        ..Default::default()
    }
}

/// Errors returned when a canonical clean-chat request cannot be authorized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ChatAuthError {
    MissingSession,
    SessionChanged,
    MissingLocalDeviceUuid,
    MissingDevice,
    MissingDeviceBinding,
    MissingDpopJkt,
    MissingAuthGeneration,
    AuthGenerationMismatch {
        expected: u64,
        observed: u64,
    },
    DeviceBindingMismatch,
    DpopJktMismatch,
    #[allow(dead_code)]
    MissingDpopProof,
    MissingSigner,
}

impl std::fmt::Display for ChatAuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::MissingSession => "chat auth session is missing",
            Self::SessionChanged => "chat auth session changed while the request was in flight",
            Self::MissingLocalDeviceUuid => "local chat device UUID is missing",
            Self::MissingDevice => "registered chat device is missing",
            Self::MissingDeviceBinding => "completed chat device binding is missing",
            Self::MissingDpopJkt => "observed chat DPoP JKT is missing",
            Self::MissingAuthGeneration => "current chat auth generation is missing",
            Self::AuthGenerationMismatch { expected, observed } => {
                return write!(
                    f,
                    "chat auth generation changed (expected {expected}, observed {observed})"
                )
            }
            Self::DeviceBindingMismatch => "chat device binding does not match the server device",
            Self::DpopJktMismatch => "observed chat DPoP JKT does not match the completed binding",
            Self::MissingDpopProof => "real chat DPoP proof is unavailable",
            Self::MissingSigner => "clean-chat application signer is unavailable",
        };
        f.write_str(message)
    }
}

/// Headers needed by canonical reads. Nest authenticates these reads with
/// Authorization plus the registered server device ID. The provider admits
/// the completed binding/JKT/generation before constructing this context; no
/// client-side proof is fabricated here.
pub(crate) struct CanonicalReadContext {
    /// Actor DID captured with the immutable authority snapshot. This is used
    /// only to reject late responses after an account switch.
    actor_did: String,
    pub(crate) authorization: String,
    pub(crate) device_id: String,
    #[allow(dead_code)]
    pub(crate) dpop_jkt: String,
    #[allow(dead_code)]
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

/// Evidence returned by a completed device-auth binding operation.
///
/// The evidence is deliberately data-only. Catmos does not construct a
/// DPoP proof or an MLS/device signature here; a future Nest binding flow
/// must supply the server-issued device ID, observed JKT, generation, and
/// binding version after it has verified those cryptographic operations.
#[cfg(test)]
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct DeviceAuthorityEvidence {
    pub(crate) local_device_uuid: String,
    pub(crate) server_device_id: String,
    pub(crate) dpop_jkt: String,
    pub(crate) auth_generation: u64,
    pub(crate) binding_version: u16,
}

#[derive(Clone, PartialEq, Eq)]
struct CompletedDeviceBinding {
    server_device_id: String,
    dpop_jkt: String,
    auth_generation: u64,
    binding_version: u16,
}

impl std::fmt::Debug for CompletedDeviceBinding {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CompletedDeviceBinding")
            .field("server_device_id", &self.server_device_id)
            .field("auth_generation", &self.auth_generation)
            .field("binding_version", &self.binding_version)
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
    observed_dpop_jkt: Option<String>,
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
            observed_dpop_jkt: None,
        }
    }
}

/// Immutable actor/token/revision captured for one asynchronous operation.
///
/// The bearer is intentionally kept out of `Debug`; callers must carry this
/// value through every await and revalidate it before a durable or runtime
/// mutation so a late response cannot cross an account switch.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ChatSessionSnapshot {
    pub(crate) actor_did: String,
    pub(crate) token: String,
    pub(crate) revision: u64,
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
/// Session tokens and the DPoP binding are intentionally kept behind this
/// provider. Callers receive only a transport context or an opaque signer
/// capability; neither capability exposes persisted secret material through
/// `Debug` or log formatting.
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
/// Opaque marker for the application signer. The current catbird-mls FFI does
/// not expose clean-chat application signing, so no instance can be issued.
#[derive(Debug)]
pub(crate) struct ChatSigningCapability {
    _private: (),
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
            // reuse proof/JKT authority across token generations.
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
            state.observed_dpop_jkt = None;
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
            state.observed_dpop_jkt = None;
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
            state.observed_dpop_jkt = None;
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
            state.observed_dpop_jkt = None;
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn observe_dpop_jkt(
        &self,
        actor_did: &str,
        jkt: String,
    ) -> std::result::Result<(), ChatAuthError> {
        let jkt = jkt.trim().to_string();
        if jkt.is_empty() {
            return Err(ChatAuthError::MissingDpopJkt);
        }
        let mut state = self.state.write().unwrap();
        if state.actor_did.as_deref() != Some(actor_did) || state.session_token.is_none() {
            return Err(ChatAuthError::SessionChanged);
        }
        if state
            .binding
            .as_ref()
            .is_some_and(|binding| binding.dpop_jkt != jkt)
        {
            Self::clear_runtime_state(&mut state);
            return Err(ChatAuthError::DpopJktMismatch);
        }
        state.observed_dpop_jkt = Some(jkt);
        Ok(())
    }

    pub(crate) fn observe_dpop_jkt_for_session(
        &self,
        session: &ChatSessionSnapshot,
        jkt: String,
    ) -> std::result::Result<(), ChatAuthError> {
        let jkt = jkt.trim().to_string();
        if jkt.is_empty() {
            return Err(ChatAuthError::MissingDpopJkt);
        }
        let mut state = self.state.write().unwrap();
        if state.session_revision != session.revision
            || state.actor_did.as_deref() != Some(session.actor_did.as_str())
            || state.session_token.as_deref() != Some(session.token.as_str())
        {
            return Err(ChatAuthError::SessionChanged);
        }
        if state
            .binding
            .as_ref()
            .is_some_and(|binding| binding.dpop_jkt != jkt)
        {
            Self::clear_runtime_state(&mut state);
            return Err(ChatAuthError::DpopJktMismatch);
        }
        state.observed_dpop_jkt = Some(jkt);
        Ok(())
    }

    /// Admit a completed binding only when it is anchored to the local UUID
    /// and the exact server ID already resolved from `listDevices`.
    #[cfg(test)]
    pub(crate) fn admit_device_authority(
        &self,
        evidence: DeviceAuthorityEvidence,
    ) -> std::result::Result<(), ChatAuthError> {
        let mut state = self.state.write().unwrap();
        if state.session_token.is_none() {
            return Err(ChatAuthError::MissingSession);
        }
        let local_device_uuid = evidence.local_device_uuid.trim();
        if local_device_uuid.is_empty() {
            return Err(ChatAuthError::MissingLocalDeviceUuid);
        }
        let configured_local = state
            .local_device_uuid
            .clone()
            .filter(|value| !value.trim().is_empty())
            .ok_or(ChatAuthError::MissingLocalDeviceUuid)?;
        if configured_local != local_device_uuid {
            return Err(ChatAuthError::DeviceBindingMismatch);
        }

        let server_device_id = evidence.server_device_id.trim().to_string();
        if server_device_id.is_empty() {
            return Err(ChatAuthError::MissingDevice);
        }
        let configured_server = state
            .server_device_id
            .clone()
            .filter(|value| !value.trim().is_empty())
            .ok_or(ChatAuthError::MissingDevice)?;
        if configured_server != server_device_id {
            return Err(ChatAuthError::DeviceBindingMismatch);
        }

        let dpop_jkt = evidence.dpop_jkt.trim().to_string();
        if dpop_jkt.is_empty() {
            return Err(ChatAuthError::MissingDpopJkt);
        }
        if evidence.auth_generation == 0 {
            return Err(ChatAuthError::MissingAuthGeneration);
        }
        if evidence.binding_version == 0 {
            return Err(ChatAuthError::MissingDeviceBinding);
        }

        let binding = CompletedDeviceBinding {
            server_device_id,
            dpop_jkt: dpop_jkt.clone(),
            auth_generation: evidence.auth_generation,
            binding_version: evidence.binding_version,
        };
        state.binding = Some(binding);
        // The binding response is the observed JKT evidence. No proof or
        // signature is generated by this admission step.
        state.observed_dpop_jkt = Some(dpop_jkt);
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
        state.observed_dpop_jkt = None;
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

    pub(crate) fn invalidate_for_generation_for_session(
        &self,
        session: &ChatSessionSnapshot,
        observed_generation: u64,
    ) -> std::result::Result<(), ChatAuthError> {
        let mut state = self.state.write().unwrap();
        if state.session_revision != session.revision
            || state.actor_did.as_deref() != Some(session.actor_did.as_str())
            || state.session_token.as_deref() != Some(session.token.as_str())
        {
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
    /// binding and its observed JKT/generation still agree with that binding.
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
        if binding.server_device_id != device_id || local_device_uuid.trim().is_empty() {
            return Err(ChatAuthError::DeviceBindingMismatch);
        }
        if binding.binding_version == 0 {
            return Err(ChatAuthError::MissingDeviceBinding);
        }
        let dpop_jkt = state
            .observed_dpop_jkt
            .clone()
            .filter(|value| !value.trim().is_empty())
            .ok_or(ChatAuthError::MissingDpopJkt)?;
        if dpop_jkt != binding.dpop_jkt {
            return Err(ChatAuthError::DpopJktMismatch);
        }
        if binding.auth_generation == 0 {
            return Err(ChatAuthError::MissingAuthGeneration);
        }
        Ok(CanonicalReadContext {
            actor_did,
            authorization: format!("Bearer {session_token}"),
            device_id,
            dpop_jkt,
            auth_generation: binding.auth_generation,
            session,
        })
    }

    /// Build a proof-required Rust context only when all material is real.
    #[allow(dead_code)]
    pub(crate) fn canonical_context(
        &self,
    ) -> std::result::Result<catbird_mls::orchestrator::CleanChatAuthContext, ChatAuthError> {
        let _ = self.canonical_read_context()?;
        Err(ChatAuthError::MissingDpopProof)
    }

    pub(crate) fn signing_capability(
        &self,
    ) -> std::result::Result<ChatSigningCapability, ChatAuthError> {
        Err(ChatAuthError::MissingSigner)
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
    fn set_jkt_for_tests(&self, jkt: &str) {
        let actor_did = self
            .state
            .read()
            .unwrap()
            .actor_did
            .clone()
            .expect("test session must be set before JKT");
        let _ = self.observe_dpop_jkt(&actor_did, jkt.to_string());
    }

    #[cfg(test)]
    fn admit_for_tests(&self, generation: u64) {
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
        let _ = self.admit_device_authority(DeviceAuthorityEvidence {
            local_device_uuid,
            server_device_id,
            dpop_jkt: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
            auth_generation: generation,
            binding_version: 1,
        });
    }
}

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

    /// Set the MLS context so the API client can derive confirmation tags.
    pub fn set_mls_context(&self, ctx: std::sync::Arc<catbird_mls::MLSContext>) {
        *self.mls_context.write().unwrap() = Some(ctx);
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

    pub(crate) fn current_session(
        &self,
    ) -> std::result::Result<ChatSessionSnapshot, ChatAuthError> {
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

    pub(crate) fn require_signing_capability(
        &self,
    ) -> std::result::Result<ChatSigningCapability, ChatAuthError> {
        self.chat_auth.signing_capability()
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
    ) -> Result<String> {
        let session = self
            .current_session()
            .map_err(|error| OrchestratorError::Api(error.to_string()))?;
        self.resolve_server_device_id_for_local_uuid_with_session(&session, local_device_uuid)
            .await
    }

    pub(crate) async fn resolve_server_device_id_for_local_uuid_with_session(
        &self,
        session: &ChatSessionSnapshot,
        local_device_uuid: &str,
    ) -> Result<String> {
        self.ensure_session_current(session)?;
        let devices = match self.list_devices_for_session(session).await {
            Ok(devices) => devices,
            Err(error) => {
                self.invalidate_device_authority_for_session(session).await;
                return Err(error);
            }
        };
        let server_device_id = match resolve_unique_server_device_id(&devices, local_device_uuid) {
            Ok(server_device_id) => server_device_id,
            Err(error) => {
                self.invalidate_device_authority_for_session(session).await;
                return Err(error);
            }
        };
        let store = crate::credentials::KeyringCredentialStore::try_new()?;
        self.ensure_session_current(session)?;
        if let Err(error) = store
            .store_server_device_id(&session.actor_did, &server_device_id)
            .await
        {
            self.invalidate_device_authority_for_session(session).await;
            return Err(error);
        }
        self.ensure_session_current(session)?;
        self.chat_auth
            .set_resolved_server_device_id_for_session(session, server_device_id.clone())
            .map_err(|error| OrchestratorError::Api(error.to_string()))?;
        self.ensure_session_current(session)?;
        Ok(server_device_id)
    }

    /// Check if the current user is opted into MLS chat.
    pub async fn get_opt_in_status(&self, did: &str) -> Result<bool> {
        let token = self.auth_header()?;
        let did =
            Did::new_owned(did.to_string()).map_err(|e| OrchestratorError::Api(e.to_string()))?;
        let input: lexicon::get_opt_in_status::Input = lexicon::get_opt_in_status::InputData {
            dids: vec![did.clone()],
        }
        .into();
        let resp = self
            .client
            .post(self.xrpc_url(lexicon::get_opt_in_status::NSID))
            .bearer_auth(&token)
            .json(&input)
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
        let output = parse_lexicon_json::<blue_catbird::mlsChat::opt_in::OptInOutput<String>>(
            body.as_ref(),
        )?;

        let statuses = output.statuses.unwrap_or_default();

        Ok(statuses
            .iter()
            .any(|status| status.did.as_str() == did.as_str() && status.opted_in))
    }

    /// Opt the current user into MLS chat.
    #[allow(unused_variables, unused_assignments, unreachable_code)]
    pub async fn opt_in(&self, device_id: Option<String>) -> Result<()> {
        return self.reject_legacy_mutation("optIn");
        #[allow(unreachable_code)]
        let _ = device_id;
        let token = self.auth_header()?;
        let input: lexicon::opt_in::Input = lexicon::opt_in::InputData {
            action: "optIn".into(),
            allow_followers_bypass: None,
            allow_following_bypass: None,
            auto_expire_days: None,
            device_id: device_id.filter(|id| !id.trim().is_empty()).map(Into::into),
            dids: None,
        }
        .into();

        let resp = self
            .client
            .post(self.xrpc_url(lexicon::opt_in::NSID))
            .bearer_auth(&token)
            .json(&input)
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(self.handle_error(resp).await);
        }
        Ok(())
    }

    /// Upload an encrypted group metadata blob keyed by a client-generated locator.
    #[allow(unused_variables, unused_assignments, unreachable_code)]
    pub async fn put_group_metadata_blob(
        &self,
        blob_locator: &str,
        group_id: &str,
        encrypted_blob: &[u8],
    ) -> Result<(String, usize)> {
        return self.reject_legacy_mutation("putGroupMetadataBlob");
        #[allow(unreachable_code)]
        let _ = (blob_locator, group_id, encrypted_blob);
        let token = self.auth_header()?;
        let resp = self
            .client
            .post(self.xrpc_url(lexicon::put_group_metadata_blob::NSID))
            .bearer_auth(&token)
            .query(&[("blobLocator", blob_locator), ("groupId", group_id)])
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .body(encrypted_blob.to_vec())
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
        let output = parse_lexicon_json::<
            blue_catbird::mlsChat::put_group_metadata_blob::PutGroupMetadataBlobOutput<String>,
        >(body.as_ref())?;
        let size = usize::try_from(output.size)
            .map_err(|_| OrchestratorError::Api("metadata blob size out of range".into()))?;

        Ok((output.blob_locator.to_string(), size))
    }

    /// Fetch an encrypted group metadata blob by locator. The `kind` arg is
    /// forwarded as the lexicon's `kind` query param (`metadata` vs
    /// `avatar`); pass `None` to fall back to the server's default
    /// (currently "metadata"). Avatars MUST set `Some("avatar")` so the
    /// server returns the correct ciphertext — and so the AAD-bound
    /// decryption below uses the matching domain separator.
    pub async fn get_group_metadata_blob(
        &self,
        blob_locator: &str,
        group_id: &str,
        kind: Option<&str>,
    ) -> Result<Vec<u8>> {
        let token = self.auth_header()?;
        let mut req = self
            .client
            .get(self.xrpc_url(lexicon::get_group_metadata_blob::NSID))
            .bearer_auth(&token)
            .query(&[("blobLocator", blob_locator), ("groupId", group_id)]);
        if let Some(k) = kind {
            req = req.query(&[("kind", k)]);
        }
        let resp = req
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
        Ok(body.to_vec())
    }

    /// Fetch the latest encrypted group metadata blob for a group.
    pub async fn get_latest_group_metadata_blob(&self, group_id: &str) -> Result<Vec<u8>> {
        let token = self.auth_header()?;
        let resp = self
            .client
            .get(self.xrpc_url(lexicon::get_group_metadata_blob::NSID))
            .bearer_auth(&token)
            .query(&[("groupId", group_id)])
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
        Ok(body.to_vec())
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
        let path = format!("{}?blobId={}", route.path, urlencoding::encode(blob_id));
        let resp = self
            .client
            .get(self.canonical_url(&path))
            .header(reqwest::header::AUTHORIZATION, &auth.authorization)
            .header("x-catbird-chat-device-id", &auth.device_id)
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;

        if let Err(error) = self.observe_chat_binding(&resp, &auth.session) {
            self.invalidate_device_authority_for_session(&auth.session)
                .await;
            return Err(OrchestratorError::Api(error.to_string()));
        }

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
    ) -> Result<Vec<DeviceInfo>> {
        let resp = self
            .client
            .get(self.xrpc_url(lexicon::list_devices::NSID))
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
            blue_catbird::mlsChat::list_devices::ListDevicesOutput<String>,
        >(body.as_ref())?;
        self.ensure_session_current(session)?;

        Ok(output
            .devices
            .iter()
            .map(|d| DeviceInfo {
                device_id: d.device_id.to_string(),
                mls_did: d.credential_did.to_string(),
                device_uuid: d
                    .device_uuid
                    .as_ref()
                    .map(|uuid| uuid.to_string())
                    .unwrap_or_default(),
                created_at: d.registered_at.as_ref().to_string().parse().ok(),
            })
            .collect())
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
        return self.reject_legacy_mutation("reportRecoveryFailure");
        #[allow(unreachable_code)]
        let _ = (convo_id, failure_type, epoch_authenticator, failure_mode);
        let token = self.auth_header()?;

        let mut body = serde_json::json!({
            "convoId": convo_id,
            "failureType": failure_type,
        });
        // TODO(ADR-002 A7): once task #26 lands (`epochAuthenticator` in the
        // `reportRecoveryFailure` lexicon + generated type), switch to the
        // typed lexicon input instead of a raw JSON map. For now we only send
        // the field when the orchestrator produced one so pre-A7 servers keep
        // accepting our reports unchanged.
        if let Some(auth) = epoch_authenticator {
            body["epochAuthenticator"] = serde_json::Value::String(auth.to_string());
        }
        // ADR-008 D1 (spec §8.6.1): include failureMode when the orchestrator
        // produced one. Servers without D1 enforcement ignore the field;
        // servers with D1 enforcement use it to filter Mode A from quorum.
        if let Some(mode) = failure_mode {
            body["failureMode"] = serde_json::Value::String(mode.to_string());
        }

        let resp = self
            .client
            .post(self.xrpc_url("blue.catbird.mlsChat.reportRecoveryFailure"))
            .bearer_auth(&token)
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

        // 403 = caller is no longer a member (stale membership state on this
        // device). There's nothing actionable server-side; treat as a soft
        // ack so we don't spin the retry loop.
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
    #[allow(unused_variables, unused_assignments, unreachable_code)]
    pub async fn report_spam(
        &self,
        convo_id: &str,
        reported_did: &str,
        reason: Option<&str>,
    ) -> Result<()> {
        return self.reject_legacy_mutation("reportSpam");
        #[allow(unreachable_code)]
        let _ = (convo_id, reported_did, reason);
        let token = self.auth_header()?;

        let mut body = serde_json::json!({
            "convoId": convo_id,
            "reportedDid": reported_did,
        });
        if let Some(r) = reason {
            body["reason"] = serde_json::Value::String(r.to_string());
        }

        let resp = self
            .client
            .post(self.xrpc_url("blue.catbird.mlsChat.reportSpam"))
            .bearer_auth(&token)
            .json(&body)
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(self.handle_error(resp).await);
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

    fn observe_chat_binding(
        &self,
        response: &reqwest::Response,
        session: &ChatSessionSnapshot,
    ) -> std::result::Result<(), ChatAuthError> {
        if let Some(value) = response.headers().get("x-catbird-chat-dpop-jkt") {
            if let Ok(jkt) = value.to_str() {
                self.chat_auth
                    .observe_dpop_jkt_for_session(session, jkt.to_string())?;
            }
        }
        if let Some(value) = response.headers().get("x-catbird-chat-auth-generation") {
            let generation = value
                .to_str()
                .ok()
                .and_then(|value| value.trim().parse::<u64>().ok())
                .ok_or(ChatAuthError::MissingAuthGeneration)?;
            self.chat_auth
                .invalidate_for_generation_for_session(session, generation)?;
        }
        Ok(())
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
        let mut path = format!("{}?limit={limit}", route.path);
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
        if let Err(error) = self.observe_chat_binding(&response, &auth.session) {
            self.invalidate_device_authority_for_session(&auth.session)
                .await;
            return Err(OrchestratorError::Api(error.to_string()));
        }
        if !response.status().is_success() {
            return Err(self.handle_error_for_session(response, &auth.session).await);
        }
        let body = response
            .bytes()
            .await
            .map_err(|error| OrchestratorError::Api(error.to_string()))?;
        self.ensure_session_current(&auth.session)?;
        let output = parse_lexicon_json::<
            catbird_atproto::blue_catbird::chat::get_conversations::GetConversationsOutput<String>,
        >(body.as_ref())?;

        let conversations = output
            .items
            .into_iter()
            .filter_map(|item| match item {
                catbird_atproto::blue_catbird::chat::ConversationInventoryItem::ConversationInventoryState(state) => {
                    let state = state.state;
                    Some(ConversationView {
                        group_id: hex::encode(&state.coordinates.group_id),
                        conversation_id: state.coordinates.conversation_id.to_string(),
                        epoch: state.coordinates.epoch.max(0) as u64,
                        members: state
                            .participants
                            .into_iter()
                            .map(|member| MemberView {
                                did: member.user_did.to_string(),
                                role: if member.role.to_string() == "admin" {
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
                    })
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
            "{}?afterSeq={after_seq}&conversationId={}&limit={limit}",
            route.path,
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
        if let Err(error) = self.observe_chat_binding(&response, &auth.session) {
            self.invalidate_device_authority_for_session(&auth.session)
                .await;
            return Err(OrchestratorError::Api(error.to_string()));
        }
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
            .filter_map(map_canonical_entry)
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
        ),
        Some("app") => matches!(
            entry,
            catbird_atproto::blue_catbird::chat::ConversationEntry::ApplicationEntry(_)
        ),
        _ => true,
    }
}

fn map_commit_entry(
    conversation_id: String,
    entry_id: String,
    sender_did: String,
    received_at: String,
    ciphertext: Vec<u8>,
    epoch: i64,
) -> Option<IncomingEnvelope> {
    Some(IncomingEnvelope {
        conversation_id,
        sender_did,
        ciphertext,
        timestamp: received_at.parse().ok()?,
        server_message_id: Some(entry_id),
        server_epoch: Some(epoch.max(0) as u64),
    })
}

fn map_canonical_entry(
    entry: catbird_atproto::blue_catbird::chat::ConversationEntry<String>,
) -> Option<IncomingEnvelope> {
    match entry {
        catbird_atproto::blue_catbird::chat::ConversationEntry::ApplicationEntry(application) => {
            let body = application.signed_request.body;
            Some(IncomingEnvelope {
                conversation_id: application.conversation_id.to_string(),
                sender_did: body.actor_did.to_string(),
                ciphertext: body.application_message.bytes.to_vec(),
                timestamp: application.received_at.as_ref().to_string().parse().ok()?,
                server_message_id: Some(application.entry_id.to_string()),
                server_epoch: Some(body.prior.epoch.max(0) as u64),
            })
        }
        catbird_atproto::blue_catbird::chat::ConversationEntry::CommitEntry(commit) => {
            let body = commit.signed_request.body;
            map_commit_entry(
                commit.conversation_id.to_string(),
                commit.entry_id.to_string(),
                body.actor_did.to_string(),
                commit.received_at.as_ref().to_string(),
                body.commit.bytes.to_vec(),
                body.next.epoch,
            )
        }
        _ => None,
    }
}
/// Convert a generated ConvoView to orchestrator ConversationView.
fn convo_view_to_conversation<S: catbird_atproto::jacquard_common::BosStr + ToString>(
    c: &blue_catbird::mlsChat::ConvoView<S>,
) -> ConversationView {
    ConversationView {
        group_id: c.group_id.to_string(),
        conversation_id: c.group_id.to_string(),
        epoch: c.epoch as u64,

        members: c
            .members
            .iter()
            .map(|m| MemberView {
                did: m.user_did.to_string(),
                role: if m.is_admin {
                    MemberRole::Admin
                } else {
                    MemberRole::Member
                },
            })
            .collect(),
        metadata: None,
        created_at: c.created_at.as_ref().to_string().parse().ok(),
        updated_at: None,
        sequencer_did: c.sequencer_did.as_ref().map(|d| d.as_str().to_string()),
    }
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

    async fn get_conversations(
        &self,
        limit: u32,
        cursor: Option<&str>,
    ) -> Result<ConversationListPage> {
        self.canonical_get_conversations(limit, cursor).await
    }

    #[allow(unused_variables, unused_assignments, unreachable_code)]
    async fn create_conversation(
        &self,
        group_id: &str,
        initial_members: Option<&[String]>,
        _metadata: Option<&ConversationMetadata>,
        _commit_data: Option<&[u8]>,
        welcome_data: Option<&[u8]>,
    ) -> Result<CreateConversationResult> {
        return self.reject_legacy_mutation("createConvo");
        #[allow(unreachable_code)]
        let _ = (
            group_id,
            initial_members,
            _metadata,
            _commit_data,
            welcome_data,
        );
        // Encrypted-metadata cutover (Phase C): catmos no longer sends
        // plaintext title/description on createConvo. The orchestrator
        // already passes `metadata = None` here, but we drop the
        // server-bound field unconditionally so a future regression cannot
        // re-introduce a leak. Authoritative metadata flows through
        // `putGroupMetadataBlob` after the new group's first epoch is
        // established.
        let token = self.auth_header()?;
        // Build the generated lexicon struct directly so byte fields stay raw.
        // The local InputData convenience shim models `welcome_message` as a
        // String and converts it to bytes as UTF-8, which double-encodes the
        // Welcome in the same way the old commitGroupChange adapter did.
        let input = blue_catbird::mlsChat::create_convo::CreateConvo {
            group_id: group_id.to_string().into(),
            cipher_suite: blue_catbird::mlsChat::create_convo::CreateConvoCipherSuite::from_value(
                "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519"
                    .to_string()
                    .into(),
            ),
            initial_members: initial_members.map(|m| m.iter().map(|d| parse_did(d)).collect()),
            welcome_message: welcome_data.map(bytes::Bytes::copy_from_slice),
            current_epoch: Some(if welcome_data.is_some() { 1 } else { 0 }),
            key_package_hashes: None,
            ..Default::default()
        };

        let resp = self
            .client
            .post(self.xrpc_url(lexicon::create_convo::NSID))
            .bearer_auth(&token)
            .json(&input)
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
        let output = parse_lexicon_json::<
            blue_catbird::mlsChat::create_convo::CreateConvoOutput<String>,
        >(body.as_ref())?;

        Ok(CreateConversationResult {
            conversation: convo_view_to_conversation(&output.convo),
            commit_data: None,
            welcome_data: None,
        })
    }

    #[allow(unused_variables, unused_assignments, unreachable_code)]
    async fn bootstrap_reset_group(
        &self,
        original_convo_id: &str,
        new_group_id: &str,
        cipher_suite: &str,
        group_info: &[u8],
        members: &[String],
        welcome_message: Option<&[u8]>,
    ) -> Result<CreateConversationResult> {
        return self.reject_legacy_mutation("bootstrapResetGroup");
        #[allow(unreachable_code)]
        let _ = (
            original_convo_id,
            new_group_id,
            cipher_suite,
            group_info,
            members,
            welcome_message,
        );
        let token = self.auth_header()?;

        // Build the request body directly. catmos-cli-impl's notes on
        // ad50a0d/7bb8565 flag that going through the catbird-atproto
        // InputData adapter double-encodes byte fields; constructing JSON
        // directly is the safe path until a per-endpoint shim lands.
        // Mirrors the pattern catmos itself uses for commitGroupChange
        // (see task #66 fix `catmos: fix double-base64 bug in
        // commitGroupChange wire encoding`).
        let body = serde_json::json!({
            "originalConvoId": original_convo_id,
            "newGroupId": new_group_id,
            "cipherSuite": cipher_suite,
            "groupInfo": B64.encode(group_info),
            "members": members
                .iter()
                .map(|d| serde_json::Value::String(d.clone()))
                .collect::<Vec<_>>(),
            "welcomeMessage": welcome_message.map(|w| B64.encode(w)),
            // Bootstrap epoch is always 1 (fresh group at epoch 1); server
            // hard-sets current_epoch = 1 anyway, this is telemetry per the
            // lexicon.
            "currentEpoch": 1,
        });

        let resp = self
            .client
            .post(self.xrpc_url("blue.catbird.mlsChat.bootstrapResetGroup"))
            .bearer_auth(&token)
            .json(&body)
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(self.handle_error(resp).await);
        }

        let body_bytes = resp
            .bytes()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        let output = parse_lexicon_json::<
            blue_catbird::mlsChat::bootstrap_reset_group::BootstrapResetGroupOutput<String>,
        >(body_bytes.as_ref())?;

        Ok(CreateConversationResult {
            conversation: convo_view_to_conversation(&output.convo),
            commit_data: None,
            welcome_data: None,
        })
    }

    #[allow(unused_variables, unused_assignments, unreachable_code)]
    async fn leave_conversation(&self, convo_id: &str) -> Result<()> {
        return self.reject_legacy_mutation("leaveConvo");
        #[allow(unreachable_code)]
        let _ = convo_id;
        let token = self.auth_header()?;
        let input: lexicon::leave_convo::Input = lexicon::leave_convo::InputData {
            convo_id: convo_id.to_string(),
            commit: None,
            target_did: None,
        }
        .into();

        let resp = self
            .client
            .post(self.xrpc_url(lexicon::leave_convo::NSID))
            .bearer_auth(&token)
            .json(&input)
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(self.handle_error(resp).await);
        }
        Ok(())
    }

    #[allow(unused_variables, unused_assignments, unreachable_code)]
    async fn add_members(
        &self,
        convo_id: &str,
        member_dids: &[String],
        commit_data: &[u8],
        welcome_data: Option<&[u8]>,
    ) -> Result<AddMembersServerResult> {
        return self.reject_legacy_mutation("commitGroupChange.addMembers");
        #[allow(unreachable_code)]
        let _ = (convo_id, member_dids, commit_data, welcome_data);
        let token = self.auth_header()?;
        // Bypass the buggy `InputData → Input` adapter that double-encodes
        // byte fields. Build the lexicon struct directly with raw bytes.
        // See `build_commit_group_change` docs for the full bug writeup.
        // TODO(ADR-002 A7.4): thread the real hex epoch_authenticator
        // (RFC 9420 §8.7) once catmos migrates to the orchestrator's
        // commit path that exposes it. Desktop doesn't have a direct
        // authenticator source today; pre-A7 servers accept None.
        let input = build_commit_group_change(
            convo_id,
            "addMembers",
            Some(commit_data.to_vec()),
            welcome_data.map(|data| data.to_vec()),
            None,
            self.get_confirmation_tag_raw(convo_id),
            Some(member_dids.iter().map(|did| parse_did(did)).collect()),
            Some(uuid::Uuid::new_v4().to_string()),
        );

        let resp = self
            .client
            .post(self.xrpc_url(lexicon::commit_group_change::NSID))
            .bearer_auth(&token)
            .json(&input)
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
        let output = parse_lexicon_json::<
            blue_catbird::mlsChat::commit_group_change::CommitGroupChangeOutput<String>,
        >(body.as_ref())?;

        Ok(AddMembersServerResult {
            success: output.success,
            new_epoch: output
                .new_epoch
                .and_then(|epoch| u64::try_from(epoch).ok())
                .unwrap_or(0),
            receipt: parse_commit_group_change_receipt(&output, "add_members"),
        })
    }

    #[allow(unused_variables, unused_assignments, unreachable_code)]
    async fn remove_members(
        &self,
        convo_id: &str,
        member_dids: &[String],
        commit_data: &[u8],
    ) -> Result<()> {
        return self.reject_legacy_mutation("commitGroupChange.removeMember");
        #[allow(unreachable_code)]
        let _ = (convo_id, member_dids, commit_data);
        let token = self.auth_header()?;
        // Bypass the buggy `InputData → Input` adapter (see
        // `build_commit_group_change` docs).
        // TODO(ADR-002 A7.4): see addMembers note above.
        let input = build_commit_group_change(
            convo_id,
            "removeMember",
            Some(commit_data.to_vec()),
            None,
            None,
            self.get_confirmation_tag_raw(convo_id),
            Some(member_dids.iter().map(|did| parse_did(did)).collect()),
            Some(uuid::Uuid::new_v4().to_string()),
        );

        let resp = self
            .client
            .post(self.xrpc_url(lexicon::commit_group_change::NSID))
            .bearer_auth(&token)
            .json(&input)
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(self.handle_error(resp).await);
        }
        Ok(())
    }

    async fn send_message(
        &self,
        convo_id: &str,
        ciphertext: &[u8],
        epoch: u64,
    ) -> Result<SendMessageResponse> {
        let msg_id = uuid::Uuid::new_v4().to_string();
        self.send_message_request(convo_id, ciphertext, epoch, &msg_id)
            .await
    }

    async fn send_message_with_id(
        &self,
        convo_id: &str,
        ciphertext: &[u8],
        epoch: u64,
        msg_id: &str,
    ) -> Result<SendMessageResponse> {
        self.send_message_request(convo_id, ciphertext, epoch, msg_id)
            .await
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

    #[allow(unused_variables, unused_assignments, unreachable_code)]
    async fn publish_key_package(
        &self,
        key_package: &[u8],
        cipher_suite: &str,
        expires_at: &str,
        device_id: Option<&str>,
    ) -> Result<()> {
        return self.reject_legacy_mutation("publishKeyPackages");
        #[allow(unreachable_code)]
        let _ = (key_package, cipher_suite, expires_at, device_id);
        let token = self.auth_header()?;
        let device_id = match device_id {
            Some(id) if !id.trim().is_empty() => id.trim().to_string(),
            _ => self.current_publish_device_id().await?,
        };
        let expires = chrono::DateTime::parse_from_rfc3339(expires_at)
            .map(crate::types::string::Datetime::new)
            .map_err(|e| OrchestratorError::Api(format!("Invalid expires timestamp: {e}")))?;
        let input: lexicon::publish_key_packages::Input =
            lexicon::publish_key_packages::InputData {
                action: "publish".to_string(),
                convo_id: None,
                device_id: Some(device_id),
                key_packages: Some(vec![lexicon::publish_key_packages::KeyPackageItemData {
                    cipher_suite: cipher_suite.to_string(),
                    expires,
                    key_package: key_package.to_vec(),
                }
                .into()]),
                local_hashes: None,
                reason: None,
                target_dids: None,
            }
            .into();

        let resp = self
            .client
            .post(self.xrpc_url(lexicon::publish_key_packages::NSID))
            .bearer_auth(&token)
            .json(&input)
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(self.handle_error(resp).await);
        }
        Ok(())
    }

    async fn get_key_packages(&self, dids: &[String]) -> Result<Vec<KeyPackageRef>> {
        let token = self.auth_header()?;
        let dids_param = dids.join(",");
        let url = format!(
            "{}?dids={}",
            self.xrpc_url(lexicon::get_key_packages::NSID),
            dids_param
        );

        let resp = self
            .client
            .get(&url)
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
        let output = parse_lexicon_json::<
            blue_catbird::mlsChat::get_key_packages::GetKeyPackagesOutput<String>,
        >(body.as_ref())?;

        Ok(output
            .key_packages
            .iter()
            .map(|kp| KeyPackageRef {
                did: kp.did.to_string(),
                key_package_data: kp.key_package.to_vec(),
                hash: kp.key_package_hash.as_ref().map(|hash| hash.to_string()),
                cipher_suite: kp.cipher_suite.to_string(),
            })
            .collect())
    }

    async fn get_key_package_stats(&self) -> Result<KeyPackageStats> {
        let token = self.auth_header()?;
        let resp = self
            .client
            .get(self.xrpc_url(lexicon::get_key_package_status::NSID))
            .bearer_auth(&token)
            .query(&[("include", "stats")])
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
        let output = parse_lexicon_json::<
            blue_catbird::mlsChat::get_key_package_status::GetKeyPackageStatusOutput<String>,
        >(body.as_ref())?;
        let stats = output.stats.ok_or_else(|| {
            OrchestratorError::Api("missing stats in key package response".into())
        })?;
        let available = u32::try_from(stats.total_available.max(0)).unwrap_or(u32::MAX);
        let total_consumed = u32::try_from(stats.total_consumed.max(0)).unwrap_or(u32::MAX);
        let total = available.saturating_add(total_consumed);

        Ok(KeyPackageStats { available, total })
    }

    async fn sync_key_packages(
        &self,
        _local_hashes: &[String],
        _device_id: &str,
    ) -> Result<KeyPackageSyncResult> {
        // TODO: Implement when mls-ds supports this endpoint
        Ok(KeyPackageSyncResult {
            orphaned_count: 0,
            deleted_count: 0,
        })
    }

    #[allow(unused_variables, unused_assignments, unreachable_code)]
    async fn register_device(
        &self,
        device_uuid: &str,
        device_name: &str,
        mls_did: &str,
        signature_key: &[u8],
        key_packages: &[Vec<u8>],
    ) -> Result<DeviceInfo> {
        return self.reject_legacy_mutation("registerDevice");
        #[allow(unreachable_code)]
        let _ = (
            device_uuid,
            device_name,
            mls_did,
            signature_key,
            key_packages,
        );
        let session = self
            .current_session()
            .map_err(|error| OrchestratorError::Api(error.to_string()))?;
        if mls_did != session.actor_did {
            return Err(OrchestratorError::Api(
                ChatAuthError::SessionChanged.to_string(),
            ));
        }
        let kp_items: Vec<lexicon::register_device::KeyPackageItem> = key_packages
            .iter()
            .map(|kp_bytes| {
                lexicon::register_device::KeyPackageItemData {
                    cipher_suite: "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519".to_string(),
                    expires: crate::types::string::Datetime::new(
                        (chrono::Utc::now() + chrono::Duration::days(90)).fixed_offset(),
                    ),
                    key_package: kp_bytes.clone(),
                }
                .into()
            })
            .collect();
        let input: lexicon::register_device::Input = lexicon::register_device::InputData {
            device_uuid: Some(device_uuid.to_string()),
            device_name: device_name.to_string(),
            signature_public_key: signature_key.to_vec(),
            key_packages: kp_items,
        }
        .into();

        let resp = self
            .client
            .post(self.xrpc_url(lexicon::register_device::NSID))
            .bearer_auth(&session.token)
            .json(&input)
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(self.handle_error_for_session(resp, &session).await);
        }

        let body = resp
            .bytes()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        let output = parse_lexicon_json::<
            blue_catbird::mlsChat::register_device::RegisterDeviceOutput<String>,
        >(body.as_ref())?;

        self.ensure_session_current(&session)?;

        // Keep the client-generated correlation UUID before the external MLS
        // credential trait stores the server-minted ID under its historical
        // `device_uuid` method name.
        let store = crate::credentials::KeyringCredentialStore::try_new()?;
        store
            .store_local_device_uuid(&session.actor_did, device_uuid)
            .await?;

        self.ensure_session_current(&session)?;

        // Reconcile the server's authoritative row before returning a
        // registration result. The response ID is not accepted on its own;
        // the exact local UUID match must be unique and byte-equal.
        let devices = self.list_devices_for_session(&session).await?;
        let resolved_device_id = resolve_unique_server_device_id(&devices, device_uuid)?;
        if resolved_device_id != output.device_id.trim() {
            return Err(OrchestratorError::Api(
                "registerDevice response disagrees with its exact listDevices row".to_string(),
            ));
        }
        self.ensure_session_current(&session)?;
        store
            .store_server_device_id(&session.actor_did, &resolved_device_id)
            .await?;
        self.ensure_session_current(&session)?;

        Ok(DeviceInfo {
            device_id: resolved_device_id,
            mls_did: output.mls_did.to_string(),
            device_uuid: device_uuid.to_string(),
            created_at: None,
        })
    }

    async fn list_devices(&self) -> Result<Vec<DeviceInfo>> {
        let session = self
            .current_session()
            .map_err(|error| OrchestratorError::Api(error.to_string()))?;
        self.list_devices_for_session(&session).await
    }

    async fn remove_device(&self, _device_id: &str) -> Result<()> {
        Err(OrchestratorError::Api(
            "Device removal not yet supported by server".to_string(),
        ))
    }

    #[allow(unused_variables, unused_assignments, unreachable_code)]
    async fn publish_group_info(&self, convo_id: &str, group_info: &[u8]) -> Result<()> {
        return self.reject_legacy_mutation("commitGroupChange.updateGroupInfo");
        #[allow(unreachable_code)]
        let _ = (convo_id, group_info);
        let token = self.auth_header()?;
        // Bypass the buggy `InputData → Input` adapter (see
        // `build_commit_group_change` docs).
        // TODO(ADR-002 A7.4): updateGroupInfo does not advance the
        // epoch, so no authenticator is required on this path — but
        // the struct field is mandatory. Leaving None is correct.
        let input = build_commit_group_change(
            convo_id,
            "updateGroupInfo",
            None,
            None,
            Some(group_info.to_vec()),
            self.get_confirmation_tag_raw(convo_id),
            None,
            None,
        );

        let resp = self
            .client
            .post(self.xrpc_url(lexicon::commit_group_change::NSID))
            .bearer_auth(&token)
            .json(&input)
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(self.handle_error(resp).await);
        }
        Ok(())
    }

    async fn get_group_info(&self, convo_id: &str) -> Result<Vec<u8>> {
        let token = self.auth_header()?;

        let resp = self
            .client
            .get(self.xrpc_url(lexicon::get_group_state::NSID))
            .bearer_auth(&token)
            .query(&[("convoId", convo_id), ("include", "groupInfo,epoch")])
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
        let output = parse_lexicon_json::<
            blue_catbird::mlsChat::get_group_state::GetGroupStateOutput<String>,
        >(body.as_ref())?;
        output
            .group_info
            .map(|value| value.to_vec())
            .ok_or_else(|| OrchestratorError::Api("missing groupInfo in group state".into()))
    }

    async fn get_welcome(&self, convo_id: &str) -> Result<Vec<u8>> {
        let token = self.auth_header()?;

        let resp = self
            .client
            .get(self.xrpc_url(lexicon::get_group_state::NSID))
            .bearer_auth(&token)
            .query(&[("convoId", convo_id), ("include", "welcome")])
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
        let output = parse_lexicon_json::<
            blue_catbird::mlsChat::get_group_state::GetGroupStateOutput<String>,
        >(body.as_ref())?;

        match output.welcome {
            Some(welcome) => Ok(welcome.to_vec()),
            None => Err(OrchestratorError::ServerError {
                status: 404,
                body: r#"{"error":"NotFound","message":"No welcome available"}"#.to_string(),
            }),
        }
    }

    async fn get_delivery_status(
        &self,
        convo_id: &str,
        message_ids: &[String],
    ) -> Result<Vec<(String, DeliveryStatus)>> {
        let _ = (convo_id, message_ids);
        Ok(vec![])
    }

    async fn report_recovery_failure(
        &self,
        convo_id: &str,
        failure_type: &str,
        epoch_authenticator: Option<&str>,
        failure_mode: Option<&str>,
    ) -> Result<()> {
        self.post_recovery_failure(convo_id, failure_type, epoch_authenticator, failure_mode)
            .await
    }

    #[allow(unused_variables, unused_assignments, unreachable_code)]
    async fn process_external_commit(
        &self,
        convo_id: &str,
        commit_data: &[u8],
        group_info: Option<&[u8]>,
        confirmation_tag: Option<&str>,
    ) -> Result<ProcessExternalCommitResult> {
        return self.reject_legacy_mutation("commitGroupChange.externalCommit");
        #[allow(unreachable_code)]
        let _ = (convo_id, commit_data, group_info, confirmation_tag);
        let token = self.auth_header()?;
        // Caller-supplied `confirmation_tag` is a base64-encoded string (kept
        // as-is for the public signature); decode it back to raw bytes so the
        // Jacquard serializer does the single correct base64 encode on the
        // wire. If the caller didn't provide one, fall back to the MLS-derived
        // raw bytes for this conversation.
        let confirmation_tag_raw: Option<Vec<u8>> = match confirmation_tag {
            Some(s) => B64.decode(s).ok(),
            None => self.get_confirmation_tag_raw(convo_id),
        };

        // Bypass the buggy `InputData → Input` adapter (see
        // `build_commit_group_change` docs).
        // TODO(ADR-002 A7.4): see addMembers note above.
        let input = build_commit_group_change(
            convo_id,
            "externalCommit",
            Some(commit_data.to_vec()),
            None,
            group_info.map(|v| v.to_vec()),
            confirmation_tag_raw,
            None,
            Some(uuid::Uuid::new_v4().to_string()),
        );

        let resp = self
            .client
            .post(self.xrpc_url(lexicon::commit_group_change::NSID))
            .bearer_auth(&token)
            .json(&input)
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
        let output = parse_lexicon_json::<
            blue_catbird::mlsChat::commit_group_change::CommitGroupChangeOutput<String>,
        >(body.as_ref())?;
        let epoch = output
            .new_epoch
            .and_then(|value| u64::try_from(value).ok())
            .unwrap_or(0);
        let rejoined_at = output
            .rejoined_at
            .as_ref()
            .map(|value| value.as_ref().to_string())
            .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());

        Ok(ProcessExternalCommitResult {
            epoch,
            rejoined_at,
            receipt: parse_commit_group_change_receipt(&output, "process_external_commit"),
        })
    }

    #[allow(unused_variables, unused_assignments, unreachable_code)]
    async fn put_group_metadata_blob(
        &self,
        convo_id: &str,
        group_id_hex: &str,
        blob_locator: &str,
        ciphertext: &[u8],
        kind: &str,
        metadata_version: u64,
        reset_generation: Option<i32>,
    ) -> Result<()> {
        return self.reject_legacy_mutation("putGroupMetadataBlob");
        #[allow(unreachable_code)]
        let _ = (
            convo_id,
            group_id_hex,
            blob_locator,
            ciphertext,
            kind,
            metadata_version,
            reset_generation,
        );
        let token = self.auth_header()?;
        let metadata_version_str = metadata_version.to_string();
        let reset_generation_str = reset_generation.map(|n| n.to_string());

        let mut req = self
            .client
            .post(self.xrpc_url(lexicon::put_group_metadata_blob::NSID))
            .bearer_auth(&token)
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream");
        let mut params: Vec<(&str, &str)> = vec![
            ("blobLocator", blob_locator),
            ("groupId", group_id_hex),
            ("convoId", convo_id),
            ("kind", kind),
            ("metadataVersion", metadata_version_str.as_str()),
        ];
        if let Some(gen) = reset_generation_str.as_deref() {
            params.push(("resetGeneration", gen));
        }
        req = req.query(&params);

        let resp = req
            .body(ciphertext.to_vec())
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(self.handle_error(resp).await);
        }
        Ok(())
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
    use super::*;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;
    use catbird_mls::orchestrator::credentials::CredentialStore;

    /// Nine bytes containing both printable-ASCII low values and non-ASCII
    /// high values so the single-encode vs double-encode distinction shows
    /// up unambiguously in base64.
    const KNOWN_BYTES: &[u8] = &[0, 1, 2, 3, 4, 0xde, 0xad, 0xbe, 0xef];
    /// Standard base64 of KNOWN_BYTES. This is what the wire should carry
    /// under `{"$bytes": ...}` after a single correct encode.
    const SINGLE_ENCODED: &str = "AAECAwTerb7v";
    /// Standard base64 of the ASCII bytes of SINGLE_ENCODED — the bogus
    /// output the old `InputData` path would produce (regression tripwire).
    const DOUBLE_ENCODED: &str = "QUFFQ0F3VGVyYjd2";

    #[test]
    fn build_commit_group_change_produces_single_base64_on_wire() {
        // Sanity-check the oracle.
        assert_eq!(B64.encode(KNOWN_BYTES), SINGLE_ENCODED);
        assert_eq!(B64.encode(SINGLE_ENCODED.as_bytes()), DOUBLE_ENCODED);

        let input = build_commit_group_change(
            "deadbeef",
            "addMembers",
            Some(KNOWN_BYTES.to_vec()),
            Some(KNOWN_BYTES.to_vec()),
            Some(KNOWN_BYTES.to_vec()),
            Some(KNOWN_BYTES.to_vec()),
            None,
            Some("idem-key".to_string()),
        );

        let json = serde_json::to_value(&input).expect("serialize CommitGroupChange");
        for field in ["commit", "welcome", "groupInfo", "confirmationTag"] {
            let wrapped = json
                .get(field)
                .unwrap_or_else(|| panic!("missing field {field}"));
            let encoded = wrapped
                .get("$bytes")
                .and_then(|v| v.as_str())
                .unwrap_or_else(|| panic!("field {field} is not a $bytes envelope: {wrapped}"));
            assert_eq!(
                encoded, SINGLE_ENCODED,
                "field {field} was double-encoded (got {encoded}, want {SINGLE_ENCODED})"
            );
            assert_ne!(
                encoded, DOUBLE_ENCODED,
                "field {field} matched the known bad output — regression!"
            );
        }
    }

    #[test]
    fn create_convo_welcome_message_uses_raw_bytes() {
        let input = blue_catbird::mlsChat::create_convo::CreateConvo::<String> {
            group_id: "deadbeef".to_string().into(),
            cipher_suite: blue_catbird::mlsChat::create_convo::CreateConvoCipherSuite::from_value(
                "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519"
                    .to_string()
                    .into(),
            ),
            welcome_message: Some(bytes::Bytes::copy_from_slice(KNOWN_BYTES)),
            current_epoch: Some(1),
            ..Default::default()
        };
        let json = serde_json::to_value(&input).expect("serialize CreateConvo");
        let encoded = json["welcomeMessage"]["$bytes"]
            .as_str()
            .expect("welcomeMessage $bytes envelope");
        assert_eq!(encoded, SINGLE_ENCODED);
        assert_ne!(encoded, DOUBLE_ENCODED);
    }

    #[test]
    fn convo_view_mapper_preserves_sequencer_did() {
        let raw = r#"{
            "conversationId": "conv-sequencer",
            "groupId": "group-sequencer",
            "creator": "did:plc:creator",
            "members": [
                {
                    "did": "did:plc:alice",
                    "userDid": "did:plc:alice",
                    "joinedAt": "2026-06-13T00:00:00Z",
                    "isAdmin": true
                }
            ],
            "epoch": 7,
            "cipherSuite": "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
            "createdAt": "2026-06-13T00:00:00Z",
            "sequencerDid": "did:web:ds-b.example"
        }"#;
        let parsed: blue_catbird::mlsChat::ConvoView =
            serde_json::from_str(raw).expect("deserialize ConvoView");
        let generated: lexicon::defs::ConvoViewData = parsed.into_static();

        let mapped = convo_view_to_conversation(&generated);

        assert_eq!(
            mapped.sequencer_did.as_deref(),
            Some("did:web:ds-b.example")
        );
    }

    /// Demonstrates the bug the new path fixes: construct through the
    /// `InputData` adapter with a `B64.encode` string and observe the
    /// double-encoded wire output. If this ever starts producing
    /// `SINGLE_ENCODED` it means the upstream `InputData` adapter was fixed
    /// and the workaround helper is no longer load-bearing.
    #[test]
    fn legacy_inputdata_adapter_still_double_encodes() {
        let input: lexicon::commit_group_change::Input = lexicon::commit_group_change::InputData {
            action: "addMembers".to_string(),
            commit: Some(B64.encode(KNOWN_BYTES)),
            confirmation_tag: None,
            convo_id: "deadbeef".to_string(),
            device_id: None,
            epoch_authenticator: None,
            group_info: None,
            idempotency_key: None,
            key_package_hashes: None,
            member_dids: None,
            pending_addition_id: None,
            transition_challenge_id: None,
            transition_signature: None,
            welcome: None,
        }
        .into();
        let json = serde_json::to_value(&input).expect("serialize InputData path");
        let encoded = json["commit"]["$bytes"]
            .as_str()
            .expect("commit $bytes envelope");
        assert_eq!(
            encoded, DOUBLE_ENCODED,
            "legacy InputData path no longer double-encodes — re-evaluate fix"
        );
    }

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

    struct CapturedRequest {
        method: String,
        path: String,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    }

    /// Spawn a single-shot loopback HTTP server. Returns (base_url, recv).
    /// The server accepts ONE connection, parses one request, replies 200,
    /// and forwards the captured request to the channel. Bind to port 0 so
    /// tests run in parallel without collisions.
    fn spawn_capture_server() -> (String, mpsc::Receiver<CapturedRequest>) {
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

    fn spawn_scripted_json_server(
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

    fn list_devices_body(did: &str, device_id: &str, device_uuid: &str) -> String {
        format!(
            r#"{{"devices":[{{"credentialDid":"{did}","deviceId":"{device_id}","deviceName":"test","deviceUuid":"{device_uuid}","keyPackageCount":1,"lastSeenAt":"2026-08-17T00:00:00.000Z","registeredAt":"2026-08-17T00:00:00.000Z"}}]}}"#
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

        let (base_url, requests) = spawn_scripted_json_server(vec![(
            200,
            list_devices_body(did_a, "server-device-a", "local-device-a"),
            std::time::Duration::from_millis(150),
        )]);
        let client = std::sync::Arc::new(ReqwestApiClient::new(base_url));
        client.set_auth(did_a.to_string(), "token-a".to_string());
        let task_client = client.clone();
        let task = tokio::spawn(async move {
            task_client
                .resolve_server_device_id_for_local_uuid("local-device-a")
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
        let (base_url, requests) = spawn_scripted_json_server(vec![(
            200,
            list_devices_body(did, "server-device-success", "local-device-success"),
            std::time::Duration::from_millis(100),
        )]);
        let client = std::sync::Arc::new(ReqwestApiClient::new(base_url));
        client.set_auth(did.to_string(), "token-success".to_string());
        let task_client = client.clone();
        let task = tokio::spawn(async move {
            task_client
                .resolve_server_device_id_for_local_uuid("local-device-success")
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
            "server-device-success"
        );
        assert_eq!(
            store
                .get_server_device_id(did)
                .await
                .expect("read reconciled server ID")
                .as_deref(),
            Some("server-device-success")
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
        client.chat_auth.set_local_device_for_tests("local-a");
        client.chat_auth.set_device_for_tests("server-a");
        client.chat_auth.admit_for_tests(1);
        let task_client = client.clone();
        let task = tokio::spawn(async move {
            task_client
                .resolve_server_device_id_for_local_uuid("local-a")
                .await
        });

        requests
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("delayed listDevices request");
        client.set_auth(did_b.to_string(), "token-b".to_string());
        client.chat_auth.set_local_device_for_tests("local-b");
        client.chat_auth.set_device_for_tests("server-b");
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(unreachable_code)]
    async fn delayed_registration_does_not_write_under_switched_account() {
        let (base_url, requests) = spawn_capture_server();
        let client = ReqwestApiClient::new(base_url);
        client.set_auth(
            "did:plc:delayed-register-a".to_string(),
            "token-a".to_string(),
        );
        let error = <ReqwestApiClient as MLSAPIClient>::register_device(
            &client,
            "local-device-a",
            "test-device",
            "did:plc:delayed-register-a",
            &[],
            &[],
        )
        .await
        .expect_err("legacy registration must fail closed");
        assert!(error.to_string().contains("canonical signed"));
        assert!(requests
            .recv_timeout(std::time::Duration::from_millis(100))
            .is_err());
        return;
        let did_a = "did:plc:delayed-register-a";
        let did_b = "did:plc:delayed-register-b";
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
        let responses = vec![
            (
                200,
                r#"{"deviceId":"server-device-a","mlsDid":"did:plc:delayed-register-a","autoJoinedConvos":[]}"#
                    .to_string(),
                std::time::Duration::from_millis(150),
            ),
        ];
        let (base_url, requests) = spawn_scripted_json_server(responses);
        let client = std::sync::Arc::new(ReqwestApiClient::new(base_url));
        client.set_auth(did_a.to_string(), "token-a".to_string());
        let task_client = client.clone();
        let task = tokio::spawn(async move {
            <ReqwestApiClient as MLSAPIClient>::register_device(
                &*task_client,
                "local-device-a",
                "test-device",
                did_a,
                &[],
                &[],
            )
            .await
        });

        let first = requests
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("delayed registerDevice request");
        assert!(first.path.contains("registerDevice"));
        client.set_auth(did_b.to_string(), "token-b".to_string());

        let error = task
            .await
            .expect("registration task should join")
            .expect_err("registration must fail after account switch");
        assert!(
            error.to_string().contains("session changed"),
            "unexpected error: {error}"
        );
        assert!(store
            .get_local_device_uuid(did_a)
            .await
            .expect("read account A local UUID")
            .is_none());
        assert!(
            store
                .get_local_device_uuid(did_b)
                .await
                .expect("read account B local UUID")
                .is_none(),
            "account B must not receive account A registration identity"
        );
        assert!(
            store
                .get_server_device_id(did_b)
                .await
                .expect("read account B server ID")
                .is_none(),
            "account B must not receive account A server device ID"
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
    #[allow(unreachable_code)]
    async fn delayed_registration_error_does_not_invalidate_new_account() {
        let (base_url, requests) = spawn_capture_server();
        let client = ReqwestApiClient::new(base_url);
        client.set_auth(
            "did:plc:delayed-registration-error-a".to_string(),
            "token-a".to_string(),
        );
        let error = <ReqwestApiClient as MLSAPIClient>::register_device(
            &client,
            "local-a",
            "test-device",
            "did:plc:delayed-registration-error-a",
            &[],
            &[],
        )
        .await
        .expect_err("legacy registration must fail closed");
        assert!(error.to_string().contains("canonical signed"));
        assert!(requests
            .recv_timeout(std::time::Duration::from_millis(100))
            .is_err());
        return;
        let did_a = "did:plc:delayed-registration-error-a";
        let did_b = "did:plc:delayed-registration-error-b";
        let (base_url, requests) = spawn_scripted_json_server(vec![(
            401,
            "{}".to_string(),
            std::time::Duration::from_millis(150),
        )]);
        let client = std::sync::Arc::new(ReqwestApiClient::new(base_url));
        client.set_auth(did_a.to_string(), "token-a".to_string());
        client.chat_auth.set_local_device_for_tests("local-a");
        client.chat_auth.set_device_for_tests("server-a");
        client.chat_auth.admit_for_tests(1);
        let task_client = client.clone();
        let task = tokio::spawn(async move {
            <ReqwestApiClient as MLSAPIClient>::register_device(
                &*task_client,
                "local-a",
                "test-device",
                did_a,
                &[],
                &[],
            )
            .await
        });
        requests
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("delayed registerDevice request");
        client.set_auth(did_b.to_string(), "token-b".to_string());
        client.chat_auth.set_local_device_for_tests("local-b");
        client.chat_auth.set_device_for_tests("server-b");
        client.chat_auth.admit_for_tests(1);

        let error = task
            .await
            .expect("registration task should join")
            .expect_err("delayed registration 401 must fail");
        assert!(error.to_string().contains("401"));
        assert!(
            client.chat_auth.canonical_read_context().is_ok(),
            "account B authority must survive account A's delayed registration error"
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
                .set_local_device_for_tests("local-device-1");
            client.chat_auth.set_device_for_tests("server-device-1");
            client.chat_auth.admit_for_tests(1);

            let error = <ReqwestApiClient as MLSAPIClient>::get_conversations(&client, 10, None)
                .await
                .expect_err("401/403 must reject the canonical read");
            assert!(error.to_string().contains(&status.to_string()));
            let _ = rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .expect("server received canonical request");

            let state = client.chat_auth.state.read().unwrap();
            assert_eq!(state.local_device_uuid.as_deref(), Some("local-device-1"));
            assert_eq!(state.server_device_id.as_deref(), Some("server-device-1"));
            assert!(state.binding.is_none());
            assert!(state.observed_dpop_jkt.is_none());
        }
    }

    #[tokio::test]
    async fn publish_key_package_fails_closed_without_signed_adapter() {
        let (base_url, rx) = spawn_capture_server();
        let client = ReqwestApiClient::new(base_url);
        client.set_auth("did:plc:catmos-test".to_string(), "test-token".to_string());
        client.set_publish_device_id_for_tests("device-uuid-123");

        let error = client
            .publish_key_package(
                b"test-key-package",
                "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
                "2099-01-01T00:00:00Z",
                None,
            )
            .await
            .expect_err("legacy key-package publishing must fail closed");
        assert!(error.to_string().contains("canonical signed"));
        assert!(rx
            .recv_timeout(std::time::Duration::from_millis(100))
            .is_err());
    }

    #[tokio::test]
    async fn generic_send_message_fails_closed_without_canonical_signed_adapter() {
        let (base_url, rx) = spawn_capture_server();
        let client = ReqwestApiClient::new(base_url);
        client.set_auth("did:plc:catmos-test".to_string(), "test-token".to_string());

        let error = <ReqwestApiClient as MLSAPIClient>::send_message(
            &client,
            "conversation-id",
            b"cipher",
            7,
        )
        .await
        .expect_err("generic MLS sends must not use an unsigned legacy route");
        assert!(error
            .to_string()
            .contains("legacy mlsChat sendMessage is disabled"));
        assert!(
            rx.recv_timeout(std::time::Duration::from_millis(100))
                .is_err(),
            "fail-closed send must not reach the legacy HTTP endpoint"
        );
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
            .set_local_device_for_tests("local-device-1");
        client.chat_auth.set_device_for_tests("server-device-1");
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
            "/xrpc/blue.catbird.chat.getBlob?blobId=blob-1"
        );
        let device_header = captured
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("x-catbird-chat-device-id"))
            .expect("canonical blob request must carry the server device ID");
        assert_eq!(device_header.1, "server-device-1");
    }

    #[tokio::test]
    async fn report_recovery_failure_fails_closed_without_signed_adapter() {
        let (base_url, rx) = spawn_capture_server();
        let client = ReqwestApiClient::new(base_url);
        client.set_auth("did:plc:catmos-test".to_string(), "test-token".to_string());

        let error = client
            .report_recovery_failure(
                "convo-x",
                "external_commit_exhausted",
                Some("deadbeefcafe1234"),
                Some("local_state_loss"),
            )
            .await
            .expect_err("legacy recovery report must fail closed");
        assert!(error.to_string().contains("canonical signed"));
        assert!(rx
            .recv_timeout(std::time::Duration::from_millis(100))
            .is_err());
    }

    #[tokio::test]
    async fn report_recovery_failure_without_fields_fails_closed() {
        let (base_url, rx) = spawn_capture_server();
        let client = ReqwestApiClient::new(base_url);
        client.set_auth("did:plc:catmos-test".to_string(), "test-token".to_string());

        let error = client
            .report_recovery_failure("convo-y", "remote_data_error", None, None)
            .await
            .expect_err("legacy recovery report must fail closed");
        assert!(error.to_string().contains("canonical signed"));
        assert!(rx
            .recv_timeout(std::time::Duration::from_millis(100))
            .is_err());
    }
}

#[test]
fn canonical_read_requires_session_before_http() {
    let provider = ChatAuthProvider::default();
    let error = provider
        .canonical_context()
        .expect_err("missing session must fail closed");
    assert_eq!(error, ChatAuthError::MissingSession);
}

#[test]
fn canonical_context_debug_redacts_bearer_and_jkt_material() {
    let context = CanonicalReadContext {
        actor_did: "did:plc:redaction".to_string(),
        authorization: "Bearer bearer-secret-for-red-test".to_string(),
        device_id: "server-device-1".to_string(),
        dpop_jkt: "jkt-secret-for-red-test".to_string(),
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
fn test_device_info(device_id: &str, device_uuid: &str) -> DeviceInfo {
    DeviceInfo {
        device_id: device_id.to_string(),
        mls_did: "did:plc:catmos".to_string(),
        device_uuid: device_uuid.to_string(),
        created_at: None,
    }
}

#[test]
fn list_devices_resolution_requires_exactly_one_local_uuid_match() {
    let devices = vec![test_device_info("server-device-1", "local-device-1")];
    assert_eq!(
        resolve_unique_server_device_id(&devices, "local-device-1")
            .expect("one matching server row should resolve"),
        "server-device-1"
    );
    assert!(resolve_unique_server_device_id(&devices, "missing-local-device").is_err());

    let duplicate = vec![
        test_device_info("server-device-1", "local-device-1"),
        test_device_info("server-device-2", "local-device-1"),
    ];
    assert!(resolve_unique_server_device_id(&duplicate, "local-device-1").is_err());
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
    provider.set_local_device_for_tests("local-device-1");
    provider.set_device_for_tests("server-device-1");
    assert!(provider
        .admit_device_authority(DeviceAuthorityEvidence {
            local_device_uuid: "local-device-1".to_string(),
            server_device_id: "server-device-1".to_string(),
            dpop_jkt: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
            auth_generation: 7,
            binding_version: 1,
        })
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
    provider.set_local_device_for_tests("local-device-2");
    provider.set_device_for_tests("server-device-2");
    provider
        .admit_device_authority(DeviceAuthorityEvidence {
            local_device_uuid: "local-device-2".to_string(),
            server_device_id: "server-device-2".to_string(),
            dpop_jkt: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_string(),
            auth_generation: 2,
            binding_version: 1,
        })
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
    provider.set_local_device_for_tests("local-device-1");
    provider.set_device_for_tests("server-device-1");
    provider.admit_for_tests(7);
    let first = provider
        .canonical_read_context()
        .expect("first actor should have a complete test snapshot");
    assert_eq!(first.actor_did, "did:plc:first");
    assert_eq!(first.authorization, "Bearer first-token");

    provider.set_session_for_tests("did:plc:second", "second-token");
    assert_eq!(
        provider
            .observe_dpop_jkt(
                "did:plc:first",
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
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
fn runtime_invalidation_retains_identity_for_exact_reconciliation() {
    let provider = ChatAuthProvider::default();
    provider.set_session_for_tests("did:plc:catmos", "opaque-session");
    provider.set_local_device_for_tests("local-device-1");
    provider.set_device_for_tests("server-device-1");
    provider.admit_for_tests(1);

    provider.clear_device_authority();
    let state = provider.state.read().unwrap();
    assert_eq!(state.local_device_uuid.as_deref(), Some("local-device-1"));
    assert_eq!(state.server_device_id.as_deref(), Some("server-device-1"));
    assert!(state.binding.is_none());
    assert!(state.observed_dpop_jkt.is_none());
    drop(state);
    assert_eq!(
        provider
            .canonical_read_context()
            .expect_err("runtime invalidation must remove authority"),
        ChatAuthError::MissingDeviceBinding
    );

    provider.set_session_for_tests("did:plc:catmos", "refreshed-session");
    let state = provider.state.read().unwrap();
    assert_eq!(state.local_device_uuid.as_deref(), Some("local-device-1"));
    assert_eq!(state.server_device_id.as_deref(), Some("server-device-1"));
    assert!(state.binding.is_none());
}

#[test]
fn canonical_read_requires_registered_device_before_http() {
    let provider = ChatAuthProvider::default();
    provider.set_session_for_tests("did:plc:catmos", "opaque-session");
    provider.set_local_device_for_tests("00000000-0000-4000-8000-000000000001");
    let error = provider
        .canonical_context()
        .expect_err("missing device must fail closed");
    assert_eq!(error, ChatAuthError::MissingDevice);
}

#[test]
fn canonical_read_requires_observed_jkt_before_http() {
    let provider = ChatAuthProvider::default();
    provider.set_session_for_tests("did:plc:catmos", "opaque-session");
    provider.set_local_device_for_tests("00000000-0000-4000-8000-000000000001");
    provider.set_device_for_tests("00000000-0000-4000-8000-000000000001");
    provider.state.write().unwrap().binding = Some(CompletedDeviceBinding {
        server_device_id: "00000000-0000-4000-8000-000000000001".to_string(),
        dpop_jkt: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
        auth_generation: 1,
        binding_version: 1,
    });
    let error = provider
        .canonical_context()
        .expect_err("missing JKT must fail closed");
    assert_eq!(error, ChatAuthError::MissingDpopJkt);
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
    provider.set_local_device_for_tests("local-device-1");
    provider.set_device_for_tests("server-device-1");
    provider.state.write().unwrap().binding = Some(CompletedDeviceBinding {
        server_device_id: "server-device-1".to_string(),
        dpop_jkt: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
        auth_generation: 0,
        binding_version: 1,
    });
    provider.set_jkt_for_tests("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    let error = provider
        .canonical_read_context()
        .expect_err("missing current generation must fail before HTTP");
    assert_eq!(error, ChatAuthError::MissingAuthGeneration);
}

#[test]
fn canonical_context_rejects_requests_without_real_dpop_proof() {
    let provider = ChatAuthProvider::default();
    provider.set_session_for_tests("did:plc:catmos", "opaque-session");
    provider.set_local_device_for_tests("00000000-0000-4000-8000-000000000001");
    provider.set_device_for_tests("server-device-1");
    provider.admit_for_tests(1);
    let error = provider
        .canonical_context()
        .expect_err("canonical proof-required context must fail closed");
    assert_eq!(error, ChatAuthError::MissingDpopProof);
}

#[test]
fn canonical_entries_preserve_commit_epochs() {
    let envelope = map_commit_entry(
        "00000000-0000-4000-8000-000000000001".to_owned(),
        "00000000-0000-4000-8000-000000000002".to_owned(),
        "did:plc:sender".to_owned(),
        "2026-08-16T12:00:00.000Z".to_owned(),
        vec![1, 2],
        5,
    )
    .expect("commit entry should map");
    assert_eq!(envelope.server_epoch, Some(5));
    assert_eq!(envelope.ciphertext, vec![1, 2]);
}

#[test]
fn signed_mutation_requires_runtime_signer_before_http() {
    let provider = ChatAuthProvider::default();
    provider.set_session_for_tests("did:plc:catmos", "opaque-session");
    provider.set_device_for_tests("00000000-0000-4000-8000-000000000001");
    provider.set_jkt_for_tests("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    let error = provider
        .signing_capability()
        .expect_err("missing signer must fail closed");
    assert_eq!(error, ChatAuthError::MissingSigner);
}

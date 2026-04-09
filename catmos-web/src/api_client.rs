//! WasmApiClient -- implements MLSAPIClient for browser using reqwest (fetch-backed)
//!
//! Port of catmos/src-tauri/src/api_client.rs (ReqwestApiClient) for WASM.
//! reqwest with WASM features uses the browser fetch API under the hood.
//! Uses shared catbird-atproto types for request/response serialization.
//! Non-lexicon delivery status lookups intentionally degrade to a local fallback.

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use catbird_atproto::blue_catbird;
use catbird_atproto::jacquard_common::IntoStatic;
use reqwest::Client;
use std::sync::RwLock;

use catbird_mls::orchestrator::api_client::MLSAPIClient;
use catbird_mls::orchestrator::error::{OrchestratorError, Result};
use catbird_mls::orchestrator::types::*;

use catbird_atproto::catbird::mls_chat as lexicon;
use catbird_atproto::types::string::{Datetime, Did};

fn parse_did(s: &str) -> Did<'static> {
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

// -- Helper parsers (ported from ReqwestApiClient) ----------------------------

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

fn parse_receipt_bytes_data(
    field: &str,
    value: &catbird_atproto::jacquard_common::types::value::Data<'_>,
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

fn parse_sequencer_receipt_data(
    value: &catbird_atproto::jacquard_common::types::value::Data<'_>,
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

    Ok(SequencerReceipt {
        convo_id,
        epoch,
        commit_hash,
        sequencer_did,
        issued_at,
        signature,
    })
}

fn parse_commit_group_change_receipt(
    output: &lexicon::commit_group_change::Output,
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

/// Convert a lexicon ConvoView to an orchestrator ConversationView.
fn convo_view_to_conversation(c: &lexicon::defs::ConvoView) -> ConversationView {
    ConversationView {
        group_id: c.group_id.to_string(),
        epoch: c.epoch as u64,
        members: c
            .members
            .iter()
            .map(|m| MemberView {
                did: m.user_did.as_str().to_string(),
                role: if m.is_admin {
                    MemberRole::Admin
                } else {
                    MemberRole::Member
                },
            })
            .collect(),
        metadata: c.metadata.as_ref().map(|m| ConversationMetadata {
            name: m.name.as_ref().map(|name| name.to_string()),
            description: m
                .description
                .as_ref()
                .map(|description| description.to_string()),
            avatar_url: None,
        }),
        created_at: Some(c.created_at.as_ref().with_timezone(&chrono::Utc)),
        updated_at: None,
    }
}

// -- WasmApiClient ------------------------------------------------------------

/// Provides confirmation-tag retrieval for group state divergence detection.
pub trait ConfirmationTagProvider {
    fn get_confirmation_tag(&self, group_id_bytes: Vec<u8>) -> Option<Vec<u8>>;
}

pub struct WasmApiClient {
    client: Client,
    base_url: String,
    auth_token: RwLock<Option<String>>,
    current_did: RwLock<Option<String>>,
    confirmation_tag_provider: std::cell::RefCell<Option<std::rc::Rc<dyn ConfirmationTagProvider>>>,
}

// WASM is single-threaded; the RefCell<Rc<dyn ...>> is never accessed from
// multiple threads.  Provide Send + Sync so the type can live inside Arc on
// the WASM target.
#[cfg(target_arch = "wasm32")]
unsafe impl Send for WasmApiClient {}
#[cfg(target_arch = "wasm32")]
unsafe impl Sync for WasmApiClient {}

impl WasmApiClient {
    pub fn new(base_url: String) -> Self {
        Self {
            client: Client::new(),
            base_url,
            auth_token: RwLock::new(None),
            current_did: RwLock::new(None),
            confirmation_tag_provider: std::cell::RefCell::new(None),
        }
    }

    /// Set the provider used to derive confirmation tags from MLS group state.
    pub fn set_confirmation_tag_provider(&self, provider: std::rc::Rc<dyn ConfirmationTagProvider>) {
        *self.confirmation_tag_provider.borrow_mut() = Some(provider);
    }

    /// Get the base64-encoded confirmation tag for a conversation, or None if unavailable.
    fn get_confirmation_tag_b64(&self, convo_id: &str) -> Option<String> {
        let provider = self.confirmation_tag_provider.borrow();
        let provider = provider.as_ref()?;
        let group_id_bytes = decode_hex_bytes(convo_id).ok()?;
        provider
            .get_confirmation_tag(group_id_bytes)
            .map(|tag| B64.encode(&tag))
    }

    pub fn set_auth(&self, did: String, token: String) {
        *self.auth_token.write().unwrap() = Some(token);
        *self.current_did.write().unwrap() = Some(did);
    }

    pub fn clear_auth(&self) {
        *self.auth_token.write().unwrap() = None;
        *self.current_did.write().unwrap() = None;
    }

    pub fn get_auth_token(&self) -> Option<String> {
        self.auth_token.read().unwrap().clone()
    }

    fn xrpc_url(&self, nsid: &str) -> String {
        format!("{}/xrpc/{}", self.base_url, nsid)
    }

    fn auth_header(&self) -> Result<String> {
        self.auth_token
            .read()
            .unwrap()
            .clone()
            .ok_or(OrchestratorError::NotAuthenticated)
    }

    async fn handle_error(&self, resp: reqwest::Response) -> OrchestratorError {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        OrchestratorError::ServerError { status, body }
    }

    async fn send_message_request(
        &self,
        convo_id: &str,
        ciphertext: &[u8],
        epoch: u64,
        msg_id: &str,
    ) -> Result<SendMessageResponse> {
        let token = self.auth_header()?;
        let padded_size = ciphertext.len() as u32;
        let input: lexicon::send_message::Input = lexicon::send_message::InputData {
            convo_id: convo_id.to_string(),
            ciphertext: ciphertext.to_vec(),
            epoch: epoch as usize,
            msg_id: msg_id.to_string(),
            padded_size: i64::from(padded_size),
            delivery: None,
            confirmation_tag: self.get_confirmation_tag_b64(convo_id),
        }
        .into();
        let resp = self
            .client
            .post(self.xrpc_url(lexicon::send_message::NSID))
            .bearer_auth(&token)
            .json(&input)
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            if status == 409 {
                tracing::error!(
                    convo_id,
                    client_epoch = epoch,
                    "409 Conflict: epoch mismatch — server has different epoch"
                );
            }
            return Err(self.handle_error(resp).await);
        }
        let body = resp
            .bytes()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        let json: serde_json::Value =
            serde_json::from_slice(&body).map_err(|e| OrchestratorError::Api(e.to_string()))?;
        Ok(SendMessageResponse {
            message_id: json["messageId"].as_str().unwrap_or(msg_id).to_string(),
            seq: json["seq"].as_u64().unwrap_or(0),
            epoch: json["epoch"].as_u64().unwrap_or(epoch),
        })
    }

    /// Check opt-in status for a DID.
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
        let output =
            parse_lexicon_json::<blue_catbird::mlsChat::opt_in::OptInOutput<'_>>(body.as_ref())?;
        let statuses = output.statuses.unwrap_or_default();
        Ok(statuses
            .iter()
            .any(|s| s.did.as_str() == did.as_str() && s.opted_in))
    }

    /// Opt the current user into MLS chat.
    pub async fn opt_in(&self, device_id: Option<String>) -> Result<()> {
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
    pub async fn put_group_metadata_blob(
        &self,
        blob_locator: &str,
        group_id: &str,
        encrypted_blob: &[u8],
    ) -> Result<(String, usize)> {
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
            blue_catbird::mlsChat::put_group_metadata_blob::PutGroupMetadataBlobOutput<'_>,
        >(body.as_ref())?;
        let size = usize::try_from(output.size)
            .map_err(|_| OrchestratorError::Api("metadata blob size out of range".into()))?;

        Ok((output.blob_locator.to_string(), size))
    }

    /// Fetch an encrypted group metadata blob by locator.
    pub async fn get_group_metadata_blob(
        &self,
        blob_locator: &str,
        group_id: &str,
    ) -> Result<Vec<u8>> {
        let token = self.auth_header()?;
        let resp = self
            .client
            .get(self.xrpc_url(lexicon::get_group_metadata_blob::NSID))
            .bearer_auth(&token)
            .query(&[("blobLocator", blob_locator), ("groupId", group_id)])
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
        let token = self.auth_header()?;
        let resp = self
            .client
            .post(self.xrpc_url(lexicon::upload_blob::NSID))
            .bearer_auth(&token)
            .query(&[("convoId", convo_id)])
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .body(data.to_vec())
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
        let output = parse_lexicon_json::<blue_catbird::mlsChat::upload_blob::UploadBlobOutput<'_>>(
            body.as_ref(),
        )?;
        let size = usize::try_from(output.size)
            .map_err(|_| OrchestratorError::Api("blob size out of range".into()))?;

        Ok((output.blob_id.to_string(), size))
    }

    /// Fetch a generic opaque blob by blob ID.
    pub async fn get_blob(&self, blob_id: &str) -> Result<Vec<u8>> {
        let token = self.auth_header()?;
        let resp = self
            .client
            .get(self.xrpc_url(lexicon::get_blob::NSID))
            .bearer_auth(&token)
            .query(&[("blobId", blob_id)])
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
}

// -- MLSAPIClient impl --------------------------------------------------------

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl MLSAPIClient for WasmApiClient {
    async fn is_authenticated_as(&self, did: &str) -> bool {
        self.current_did.read().unwrap().as_deref() == Some(did)
    }

    async fn current_did(&self) -> Option<String> {
        self.current_did.read().unwrap().clone()
    }

    async fn get_conversations(
        &self,
        limit: u32,
        cursor: Option<&str>,
    ) -> Result<ConversationListPage> {
        let token = self.auth_header()?;
        let mut url = format!(
            "{}?limit={}",
            self.xrpc_url(lexicon::get_convos::NSID),
            limit
        );
        if let Some(c) = cursor {
            url.push_str(&format!("&cursor={}", c));
        }

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
        let output = parse_lexicon_json::<blue_catbird::mlsChat::get_convos::GetConvosOutput<'_>>(
            body.as_ref(),
        )?;

        let conversations = output
            .conversations
            .iter()
            .map(convo_view_to_conversation)
            .collect();

        Ok(ConversationListPage {
            conversations,
            cursor: output.cursor.as_ref().map(|cursor| cursor.to_string()),
        })
    }

    async fn create_conversation(
        &self,
        group_id: &str,
        initial_members: Option<&[String]>,
        metadata: Option<&ConversationMetadata>,
        _commit_data: Option<&[u8]>,
        welcome_data: Option<&[u8]>,
    ) -> Result<CreateConversationResult> {
        let token = self.auth_header()?;
        let input: lexicon::create_convo::Input = lexicon::create_convo::InputData {
            group_id: group_id.to_string(),
            cipher_suite: "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519".to_string(),
            initial_members: initial_members
                .map(|members| members.iter().map(|d| parse_did(d)).collect()),
            metadata: metadata.map(|m| {
                lexicon::create_convo::MetadataInputData {
                    name: m.name.clone(),
                    description: m.description.clone(),
                }
                .into()
            }),
            welcome_message: welcome_data.map(|w| B64.encode(w)),
            current_epoch: None,
            key_package_hashes: None,
        }
        .into();

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
            blue_catbird::mlsChat::create_convo::CreateConvoOutput<'_>,
        >(body.as_ref())?;

        let conversation = convo_view_to_conversation(&output.convo);
        Ok(CreateConversationResult {
            conversation,
            commit_data: None,
            welcome_data: None,
        })
    }

    async fn leave_conversation(&self, convo_id: &str) -> Result<()> {
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

    async fn add_members(
        &self,
        convo_id: &str,
        member_dids: &[String],
        commit_data: &[u8],
        welcome_data: Option<&[u8]>,
    ) -> Result<AddMembersServerResult> {
        let token = self.auth_header()?;
        let input: lexicon::commit_group_change::Input = lexicon::commit_group_change::InputData {
            action: "addMembers".to_string(),
            commit: Some(B64.encode(commit_data)),
            convo_id: convo_id.to_string(),
            device_id: None,
            group_info: None,
            idempotency_key: Some(uuid::Uuid::new_v4().to_string()),
            key_package_hashes: None,
            member_dids: Some(member_dids.iter().map(|did| parse_did(did)).collect()),
            pending_addition_id: None,
            welcome: welcome_data.map(|data| B64.encode(data)),
            confirmation_tag: self.get_confirmation_tag_b64(convo_id),
        }
        .into();
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
            blue_catbird::mlsChat::commit_group_change::CommitGroupChangeOutput<'_>,
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

    async fn remove_members(
        &self,
        convo_id: &str,
        member_dids: &[String],
        commit_data: &[u8],
    ) -> Result<()> {
        let token = self.auth_header()?;
        // v2 removal flows through leaveConvo with targetDid set per member.
        for did in member_dids {
            let input: lexicon::leave_convo::Input = lexicon::leave_convo::InputData {
                convo_id: convo_id.to_string(),
                commit: Some(B64.encode(commit_data)),
                target_did: Some(parse_did(did)),
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
    ) -> Result<(Vec<IncomingEnvelope>, Option<String>)> {
        let token = self.auth_header()?;
        let mut url = format!(
            "{}?convoId={}&limit={}",
            self.xrpc_url(lexicon::get_messages::NSID),
            convo_id,
            limit
        );
        if let Some(c) = cursor {
            url.push_str(&format!("&sinceSeq={}", c));
        }
        if let Some(t) = message_type {
            url.push_str(&format!("&type={}", t));
        }

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
            blue_catbird::mlsChat::get_messages::GetMessagesOutput<'_>,
        >(body.as_ref())?;

        let envelopes = output
            .messages
            .iter()
            .map(|m| {
                let timestamp = m.created_at.as_ref().with_timezone(&chrono::Utc);
                IncomingEnvelope {
                    conversation_id: m.convo_id.to_string(),
                    sender_did: String::new(), // Dumb DS — sender unknown
                    ciphertext: m.ciphertext.to_vec(),
                    timestamp,
                    server_message_id: Some(m.id.to_string()),
                }
            })
            .collect();

        let next_cursor = output.last_seq.map(|seq| seq.to_string());
        Ok((envelopes, next_cursor))
    }

    async fn publish_key_package(
        &self,
        key_package: &[u8],
        cipher_suite: &str,
        expires_at: &str,
    ) -> Result<()> {
        let token = self.auth_header()?;
        let expires = chrono::DateTime::parse_from_rfc3339(expires_at)
            .map(Datetime::new)
            .map_err(|e| OrchestratorError::Api(format!("Invalid expires timestamp: {e}")))?;
        let input: lexicon::publish_key_packages::Input =
            lexicon::publish_key_packages::InputData {
                action: "publish".to_string(),
                device_id: None,
                key_packages: Some(vec![lexicon::publish_key_packages::KeyPackageItemData {
                    cipher_suite: cipher_suite.to_string(),
                    expires,
                    key_package: key_package.to_vec(),
                }
                .into()]),
                local_hashes: None,
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
        let url = format!(
            "{}?dids={}",
            self.xrpc_url(lexicon::get_key_packages::NSID),
            dids.join(",")
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
            blue_catbird::mlsChat::get_key_packages::GetKeyPackagesOutput<'_>,
        >(body.as_ref())?;
        Ok(output
            .key_packages
            .iter()
            .filter_map(|kp| {
                let kp_data = B64.decode(kp.key_package.as_str()).ok()?;
                Some(KeyPackageRef {
                    did: kp.did.as_str().to_string(),
                    key_package_data: kp_data,
                    hash: kp.key_package_hash.as_ref().map(|hash| hash.to_string()),
                    cipher_suite: kp.cipher_suite.to_string(),
                })
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
            blue_catbird::mlsChat::get_key_package_status::GetKeyPackageStatusOutput<'_>,
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
        // Not implemented on server yet
        Ok(KeyPackageSyncResult {
            orphaned_count: 0,
            deleted_count: 0,
        })
    }

    async fn register_device(
        &self,
        device_uuid: &str,
        device_name: &str,
        _mls_did: &str,
        signature_key: &[u8],
        key_packages: &[Vec<u8>],
    ) -> Result<DeviceInfo> {
        let token = self.auth_header()?;
        let kp_items: Vec<lexicon::register_device::KeyPackageItem> = key_packages
            .iter()
            .map(|kp| {
                lexicon::register_device::KeyPackageItemData {
                    cipher_suite: "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519".to_string(),
                    expires: Datetime::new(
                        (chrono::Utc::now() + chrono::Duration::days(90)).fixed_offset(),
                    ),
                    key_package: kp.clone(),
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
        // DEBUG: Log serialized JSON to browser console via web_sys
        match serde_json::to_string(&input) {
            Ok(json_str) => {
                let msg = format!(
                    "[DEBUG registerDevice] JSON body ({} bytes): {}",
                    json_str.len(),
                    &json_str[..json_str.len().min(500)]
                );
                web_sys::console::log_1(&msg.into());
                if let Some(idx) = json_str.find("signaturePublicKey") {
                    let end = (idx + 200).min(json_str.len());
                    let msg2 = format!(
                        "[DEBUG registerDevice] signaturePublicKey region: {}",
                        &json_str[idx..end]
                    );
                    web_sys::console::log_1(&msg2.into());
                }
            }
            Err(e) => {
                let msg = format!("[DEBUG registerDevice] Failed to serialize: {}", e);
                web_sys::console::error_1(&msg.into());
            }
        }
        let resp = self
            .client
            .post(self.xrpc_url(lexicon::register_device::NSID))
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
            blue_catbird::mlsChat::register_device::RegisterDeviceOutput<'_>,
        >(body.as_ref())?;
        Ok(DeviceInfo {
            device_id: output.device_id.to_string(),
            mls_did: output.mls_did.to_string(),
            device_uuid: device_uuid.to_string(),
            created_at: None,
        })
    }

    async fn list_devices(&self) -> Result<Vec<DeviceInfo>> {
        let token = self.auth_header()?;
        let resp = self
            .client
            .get(self.xrpc_url(lexicon::list_devices::NSID))
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
            blue_catbird::mlsChat::list_devices::ListDevicesOutput<'_>,
        >(body.as_ref())?;
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
                created_at: Some(d.registered_at.as_ref().with_timezone(&chrono::Utc)),
            })
            .collect())
    }

    async fn remove_device(&self, device_id: &str) -> Result<()> {
        let token = self.auth_header()?;
        let resp = self
            .client
            .request(
                reqwest::Method::DELETE,
                self.xrpc_url(lexicon::list_devices::NSID),
            )
            .bearer_auth(&token)
            .query(&[("deviceId", device_id)])
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(self.handle_error(resp).await);
        }
        Ok(())
    }

    async fn publish_group_info(&self, convo_id: &str, group_info: &[u8]) -> Result<()> {
        let token = self.auth_header()?;
        let input: lexicon::commit_group_change::Input = lexicon::commit_group_change::InputData {
            action: "updateGroupInfo".to_string(),
            commit: None,
            convo_id: convo_id.to_string(),
            device_id: None,
            group_info: Some(B64.encode(group_info)),
            idempotency_key: None,
            key_package_hashes: None,
            member_dids: None,
            pending_addition_id: None,
            welcome: None,
            confirmation_tag: self.get_confirmation_tag_b64(convo_id),
        }
        .into();
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
            blue_catbird::mlsChat::get_group_state::GetGroupStateOutput<'_>,
        >(body.as_ref())?;
        let b64 = output
            .group_info
            .as_ref()
            .map(|value| value.as_str())
            .ok_or_else(|| OrchestratorError::Api("missing groupInfo in group state".into()))?;
        B64.decode(b64)
            .map_err(|e| OrchestratorError::Api(e.to_string()))
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
            blue_catbird::mlsChat::get_group_state::GetGroupStateOutput<'_>,
        >(body.as_ref())?;
        match output.welcome.as_ref().map(|value| value.as_str()) {
            Some(b64) => B64
                .decode(b64)
                .map_err(|e| OrchestratorError::Api(format!("Invalid base64 in Welcome: {e}"))),
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

    async fn commit_group_change(
        &self,
        convo_id: &str,
        commit_data: &[u8],
        action: &str,
    ) -> Result<()> {
        let token = self.auth_header()?;
        let input: lexicon::commit_group_change::Input = lexicon::commit_group_change::InputData {
            action: action.to_string(),
            commit: Some(B64.encode(commit_data)),
            convo_id: convo_id.to_string(),
            device_id: None,
            group_info: None,
            idempotency_key: Some(uuid::Uuid::new_v4().to_string()),
            key_package_hashes: None,
            member_dids: None,
            pending_addition_id: None,
            welcome: None,
            confirmation_tag: self.get_confirmation_tag_b64(convo_id),
        }
        .into();
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

    async fn process_external_commit(
        &self,
        convo_id: &str,
        commit_data: &[u8],
        group_info: Option<&[u8]>,
    ) -> Result<ProcessExternalCommitResult> {
        let token = self.auth_header()?;
        let input: lexicon::commit_group_change::Input = lexicon::commit_group_change::InputData {
            action: "externalCommit".to_string(),
            commit: Some(B64.encode(commit_data)),
            convo_id: convo_id.to_string(),
            device_id: None,
            group_info: group_info.map(|value| B64.encode(value)),
            idempotency_key: Some(uuid::Uuid::new_v4().to_string()),
            key_package_hashes: None,
            member_dids: None,
            pending_addition_id: None,
            welcome: None,
            confirmation_tag: self.get_confirmation_tag_b64(convo_id),
        }
        .into();
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
            blue_catbird::mlsChat::commit_group_change::CommitGroupChangeOutput<'_>,
        >(body.as_ref())?;
        Ok(ProcessExternalCommitResult {
            epoch: output
                .new_epoch
                .and_then(|value| u64::try_from(value).ok())
                .unwrap_or(0),
            rejoined_at: output
                .rejoined_at
                .as_ref()
                .map(|value| value.as_ref().to_string())
                .unwrap_or_else(|| chrono::Utc::now().to_rfc3339()),
            receipt: parse_commit_group_change_receipt(&output, "process_external_commit"),
        })
    }
}

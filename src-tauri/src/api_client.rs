use async_trait::async_trait;
use catbird_atproto::blue_catbird;
use catbird_atproto::jacquard_common::IntoStatic;
use reqwest::Client;
use std::sync::RwLock;

use catbird_mls::orchestrator::api_client::MLSAPIClient;
use catbird_mls::orchestrator::credentials::CredentialStore;
use catbird_mls::orchestrator::error::{OrchestratorError, Result};
use catbird_mls::orchestrator::types::*;

// Generated lexicon types
use crate::catbird::mls_chat as lexicon;
use crate::chat_routes;
use crate::types::string::Did;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

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
    member_dids: Option<Vec<Did<'static>>>,
    idempotency_key: Option<String>,
) -> blue_catbird::mlsChat::commit_group_change::CommitGroupChange<'static> {
    blue_catbird::mlsChat::commit_group_change::CommitGroupChange {
        action: action.to_string().into(),
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

/// HTTP API client for the mls-ds delivery service using reqwest.
pub struct ReqwestApiClient {
    client: Client,
    base_url: String,
    auth_token: RwLock<Option<String>>,
    current_did: RwLock<Option<String>>,
    mls_context: RwLock<Option<std::sync::Arc<catbird_mls::MLSContext>>>,
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
            auth_token: RwLock::new(None),
            current_did: RwLock::new(None),
            mls_context: RwLock::new(None),
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

        let user_did = self
            .current_did
            .read()
            .unwrap()
            .clone()
            .ok_or(OrchestratorError::NotAuthenticated)?;
        let store = crate::credentials::KeyringCredentialStore::try_new()?;
        store
            .get_device_uuid(&user_did)
            .await?
            .map(|device_id| device_id.trim().to_string())
            .filter(|device_id| !device_id.is_empty())
            .ok_or_else(|| {
                OrchestratorError::Api(
                    "Cannot publish key package before MLS device registration".to_string(),
                )
            })
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
            .post(self.xrpc_url(chat_routes::GET_OPT_IN_STATUS))
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
            .any(|status| status.did.as_str() == did.as_str() && status.opted_in))
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
            .post(self.xrpc_url(chat_routes::OPT_IN))
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
            .post(self.xrpc_url(chat_routes::PUT_GROUP_METADATA_BLOB))
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
            .get(self.xrpc_url(chat_routes::GET_GROUP_METADATA_BLOB))
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
            .get(self.xrpc_url(chat_routes::GET_GROUP_METADATA_BLOB))
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
            .post(self.xrpc_url(chat_routes::UPLOAD_BLOB))
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
            .get(self.xrpc_url(chat_routes::GET_BLOB))
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

    async fn send_message_request(
        &self,
        convo_id: &str,
        ciphertext: &[u8],
        epoch: u64,
        msg_id: &str,
    ) -> Result<SendMessageResponse> {
        let token = self.auth_header()?;
        // Ciphertext is already padded by catbird-mls encrypt_message.
        // padded_size == ciphertext.len() since it's padded to bucket.
        let padded_size = ciphertext.len() as u32;
        tracing::info!(convo_id, epoch, padded_size, "Sending message to server");
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
            .post(self.xrpc_url(chat_routes::SEND_MESSAGE))
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

    /// Internal helper that POSTs a recovery failure report to the server.
    /// Matches the `MLSAPIClient::report_recovery_failure` impl but lives on the
    /// concrete struct so it can be reused by `opt_in` / admin flows later.
    async fn post_recovery_failure(
        &self,
        convo_id: &str,
        failure_type: &str,
        epoch_authenticator: Option<&str>,
        failure_mode: Option<&str>,
    ) -> Result<()> {
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
            .post(self.xrpc_url(chat_routes::REPORT_RECOVERY_FAILURE))
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
    pub async fn report_spam(
        &self,
        convo_id: &str,
        reported_did: &str,
        reason: Option<&str>,
    ) -> Result<()> {
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
            .post(self.xrpc_url(chat_routes::REPORT_SPAM))
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

    async fn handle_error(&self, resp: reqwest::Response) -> OrchestratorError {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        OrchestratorError::ServerError { status, body }
    }
}

/// Convert a generated ConvoView to orchestrator ConversationView.
fn convo_view_to_conversation(c: &lexicon::defs::ConvoViewData) -> ConversationView {
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
            self.xrpc_url(chat_routes::GET_CONVERSATIONS),
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
            .map(|c| convo_view_to_conversation(c))
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
        _metadata: Option<&ConversationMetadata>,
        _commit_data: Option<&[u8]>,
        welcome_data: Option<&[u8]>,
    ) -> Result<CreateConversationResult> {
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
            cipher_suite: "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519".into(),
            initial_members: initial_members.map(|m| m.iter().map(|d| parse_did(d)).collect()),
            welcome_message: welcome_data.map(bytes::Bytes::copy_from_slice),
            current_epoch: Some(if welcome_data.is_some() { 1 } else { 0 }),
            key_package_hashes: None,
            ..Default::default()
        };

        let resp = self
            .client
            .post(self.xrpc_url(chat_routes::CREATE_CONVERSATION))
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

        Ok(CreateConversationResult {
            conversation: convo_view_to_conversation(&output.convo),
            commit_data: None,
            welcome_data: None,
        })
    }

    async fn bootstrap_reset_group(
        &self,
        original_convo_id: &str,
        new_group_id: &str,
        cipher_suite: &str,
        group_info: &[u8],
        members: &[String],
        welcome_message: Option<&[u8]>,
    ) -> Result<CreateConversationResult> {
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
            .post(self.xrpc_url(chat_routes::RESET_GROUP))
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
            blue_catbird::mlsChat::bootstrap_reset_group::BootstrapResetGroupOutput<'_>,
        >(body_bytes.as_ref())?;

        Ok(CreateConversationResult {
            conversation: convo_view_to_conversation(&output.convo),
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
            .post(self.xrpc_url(chat_routes::LEAVE_CONVERSATION))
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
            .post(self.xrpc_url(chat_routes::SUBMIT_TRANSITION))
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
            .post(self.xrpc_url(chat_routes::SUBMIT_TRANSITION))
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
        let token = self.auth_header()?;
        let mut url = format!(
            "{}?convoId={}&limit={}",
            self.xrpc_url(chat_routes::GET_ENTRIES),
            convo_id,
            limit
        );
        if let Some(c) = cursor {
            url.push_str(&format!("&sinceSeq={}", c));
        }
        if let Some(t) = message_type {
            url.push_str(&format!("&type={}", t));
        }
        if let Some(from) = from_epoch {
            url.push_str(&format!("&fromEpoch={}", from));
        }
        if let Some(to) = to_epoch {
            url.push_str(&format!("&toEpoch={}", to));
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
            .map(|m| IncomingEnvelope {
                conversation_id: m.convo_id.to_string(),
                sender_did: String::new(), // Dumb DS - sender unknown
                ciphertext: m.ciphertext.to_vec(),
                timestamp: m
                    .created_at
                    .as_ref()
                    .to_string()
                    .parse()
                    .unwrap_or_else(|_| chrono::Utc::now()),
                server_message_id: Some(m.id.to_string()),
                server_epoch: Some(m.epoch as u64),
            })
            .collect();

        let next_cursor = output.last_seq.map(|s| s.to_string());
        Ok((envelopes, next_cursor))
    }

    async fn publish_key_package(
        &self,
        key_package: &[u8],
        cipher_suite: &str,
        expires_at: &str,
    ) -> Result<()> {
        let token = self.auth_header()?;
        let device_id = self.current_publish_device_id().await?;
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
            .post(self.xrpc_url(chat_routes::REPLENISH_KEY_PACKAGES))
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
            self.xrpc_url(chat_routes::GET_PENDING_WELCOMES),
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
            blue_catbird::mlsChat::get_key_packages::GetKeyPackagesOutput<'_>,
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
            .get(self.xrpc_url(chat_routes::GET_OWN_DEVICES))
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
        // TODO: Implement when mls-ds supports this endpoint
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
            .post(self.xrpc_url(chat_routes::ENROLL_DEVICE))
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
            .get(self.xrpc_url(chat_routes::GET_DEVICES))
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
                created_at: d.registered_at.as_ref().to_string().parse().ok(),
            })
            .collect())
    }

    async fn remove_device(&self, _device_id: &str) -> Result<()> {
        Err(OrchestratorError::Api(
            "Device removal not yet supported by server".to_string(),
        ))
    }

    async fn publish_group_info(&self, convo_id: &str, group_info: &[u8]) -> Result<()> {
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
            .post(self.xrpc_url(chat_routes::SUBMIT_TRANSITION))
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
            .get(self.xrpc_url(chat_routes::GET_CONVERSATION_STATE))
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
        output
            .group_info
            .map(|value| value.to_vec())
            .ok_or_else(|| OrchestratorError::Api("missing groupInfo in group state".into()))
    }

    async fn get_welcome(&self, convo_id: &str) -> Result<Vec<u8>> {
        let token = self.auth_header()?;

        let resp = self
            .client
            .get(self.xrpc_url(chat_routes::GET_CONVERSATION_STATE))
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

    async fn process_external_commit(
        &self,
        convo_id: &str,
        commit_data: &[u8],
        group_info: Option<&[u8]>,
        confirmation_tag: Option<&str>,
    ) -> Result<ProcessExternalCommitResult> {
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
            .post(self.xrpc_url(chat_routes::SUBMIT_TRANSITION))
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
        let token = self.auth_header()?;
        let metadata_version_str = metadata_version.to_string();
        let reset_generation_str = reset_generation.map(|n| n.to_string());

        let mut req = self
            .client
            .post(self.xrpc_url(chat_routes::PUT_GROUP_METADATA_BLOB))
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
        let input = blue_catbird::mlsChat::create_convo::CreateConvo {
            group_id: "deadbeef".into(),
            cipher_suite: "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519".into(),
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
        let parsed: blue_catbird::mlsChat::ConvoView<'_> =
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
            let _ = stream.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: application/json\r\n\r\n{}",
            );
            let _ = tx.send(CapturedRequest {
                method,
                path,
                headers,
                body,
            });
        });
        (format!("http://127.0.0.1:{port}"), rx)
    }

    #[tokio::test]
    async fn publish_key_package_posts_registered_device_id() {
        let (base_url, rx) = spawn_capture_server();
        let client = ReqwestApiClient::new(base_url);
        client.set_auth("did:plc:catmos-test".to_string(), "test-token".to_string());
        client.set_publish_device_id_for_tests("device-uuid-123");

        client
            .publish_key_package(
                b"test-key-package",
                "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
                "2099-01-01T00:00:00Z",
            )
            .await
            .expect("publish_key_package should succeed against 200 OK");

        let captured = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("server received request");

        assert_eq!(captured.method, "POST");
        assert_eq!(
            captured.path, "/xrpc/blue.catbird.chat.replenishKeyPackages",
            "must POST to the publishKeyPackages XRPC NSID"
        );

        let body: serde_json::Value = serde_json::from_slice(&captured.body).expect("body is JSON");
        assert_eq!(body["action"], "publish");
        assert_eq!(body["deviceId"], "device-uuid-123");
        assert_eq!(
            body["keyPackages"][0]["cipherSuite"],
            "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519"
        );
    }

    #[tokio::test]
    async fn report_recovery_failure_posts_correct_xrpc_request() {
        let (base_url, rx) = spawn_capture_server();
        let client = ReqwestApiClient::new(base_url);
        client.set_auth("did:plc:catmos-test".to_string(), "test-token".to_string());

        client
            .report_recovery_failure(
                "convo-x",
                "external_commit_exhausted",
                Some("deadbeefcafe1234"),
                Some("local_state_loss"),
            )
            .await
            .expect("report_recovery_failure should succeed against 200 OK");

        let captured = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("server received request");

        assert_eq!(captured.method, "POST");
        assert_eq!(
            captured.path, "/xrpc/blue.catbird.chat.reportRecoveryFailure",
            "must POST to the reportRecoveryFailure XRPC NSID"
        );

        let auth_header = captured
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
            .expect("Authorization header must be present");
        assert_eq!(auth_header.1, "Bearer test-token");

        let body: serde_json::Value = serde_json::from_slice(&captured.body).expect("body is JSON");
        assert_eq!(body["convoId"], "convo-x");
        assert_eq!(body["failureType"], "external_commit_exhausted");
        // ADR-002 / spec §8.6: epoch_authenticator is hex-encoded and bound
        // to the reporter's current epoch so stale clients can't forge votes.
        assert_eq!(body["epochAuthenticator"], "deadbeefcafe1234");
        // ADR-008 D1 / spec §8.6.1: failureMode discriminator. Must round-trip
        // verbatim so the server-side D1 filter can exclude Mode A votes from
        // quorum auto-reset.
        assert_eq!(body["failureMode"], "local_state_loss");
    }

    #[tokio::test]
    async fn report_recovery_failure_omits_optional_fields_when_none() {
        let (base_url, rx) = spawn_capture_server();
        let client = ReqwestApiClient::new(base_url);
        client.set_auth("did:plc:catmos-test".to_string(), "test-token".to_string());

        client
            .report_recovery_failure("convo-y", "remote_data_error", None, None)
            .await
            .expect("report_recovery_failure should succeed against 200 OK");

        let captured = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("server received request");

        let body: serde_json::Value = serde_json::from_slice(&captured.body).expect("body is JSON");
        assert_eq!(body["convoId"], "convo-y");
        assert_eq!(body["failureType"], "remote_data_error");
        // Both optional discriminators must be absent (not null) when not
        // supplied — matches the lexicon's `skip_serializing_if = is_none`.
        assert!(
            body.get("epochAuthenticator").is_none(),
            "epochAuthenticator must be omitted when caller passes None"
        );
        assert!(
            body.get("failureMode").is_none(),
            "failureMode must be omitted when caller passes None"
        );
    }
}

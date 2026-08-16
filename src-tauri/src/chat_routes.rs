//! Canonical clean-chat XRPC route names used by the desktop boundary.
//!
//! The generated `catbird-atproto` types in this checkout still expose the
//! pre-clean-chat `mlsChat` Rust module. Network routing is deliberately kept
//! separate from those generated types so the client can adopt the canonical
//! `blue.catbird.chat.*` protocol without hand-editing generated bindings.
//!
//! The shared Nest/mls-ds adapter must accept the legacy wire payloads at
//! these canonical NSIDs until the generated clean-chat consumers land. That
//! is an upstream dependency; this module is the tested, reversible client
//! seam for the route migration.

pub(crate) const GET_OPT_IN_STATUS: &str = "blue.catbird.chat.getOptInStatus";
pub(crate) const OPT_IN: &str = "blue.catbird.chat.optIn";
pub(crate) const PUT_GROUP_METADATA_BLOB: &str = "blue.catbird.chat.submitTransition";
pub(crate) const GET_GROUP_METADATA_BLOB: &str = "blue.catbird.chat.getConversationState";
pub(crate) const UPLOAD_BLOB: &str = "blue.catbird.chat.uploadBlob";
pub(crate) const GET_BLOB: &str = "blue.catbird.chat.getBlob";
pub(crate) const SEND_MESSAGE: &str = "blue.catbird.chat.sendMessage";
pub(crate) const REPORT_RECOVERY_FAILURE: &str = "blue.catbird.chat.reportRecoveryFailure";
pub(crate) const REPORT_SPAM: &str = "blue.catbird.chat.reportSpam";
pub(crate) const RESET_GROUP: &str = "blue.catbird.chat.resetGroup";
pub(crate) const GET_CONVERSATIONS: &str = "blue.catbird.chat.getConversations";
pub(crate) const CREATE_CONVERSATION: &str = "blue.catbird.chat.createConversation";
pub(crate) const LEAVE_CONVERSATION: &str = "blue.catbird.chat.requestLeave";
pub(crate) const SUBMIT_TRANSITION: &str = "blue.catbird.chat.submitTransition";
pub(crate) const GET_ENTRIES: &str = "blue.catbird.chat.getEntries";
pub(crate) const REPLENISH_KEY_PACKAGES: &str = "blue.catbird.chat.replenishKeyPackages";
pub(crate) const GET_PENDING_WELCOMES: &str = "blue.catbird.chat.getPendingWelcomes";
pub(crate) const GET_OWN_DEVICES: &str = "blue.catbird.chat.getOwnDevices";
pub(crate) const ENROLL_DEVICE: &str = "blue.catbird.chat.enrollDevice";
pub(crate) const GET_DEVICES: &str = "blue.catbird.chat.getDevices";
pub(crate) const GET_CONVERSATION_STATE: &str = "blue.catbird.chat.getConversationState";
pub(crate) const GET_SUBSCRIPTION_TICKET: &str = "blue.catbird.chat.getSubscriptionTicket";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_client_route_uses_the_clean_chat_namespace() {
        let routes = [
            GET_OPT_IN_STATUS,
            OPT_IN,
            PUT_GROUP_METADATA_BLOB,
            GET_GROUP_METADATA_BLOB,
            UPLOAD_BLOB,
            GET_BLOB,
            SEND_MESSAGE,
            REPORT_RECOVERY_FAILURE,
            REPORT_SPAM,
            RESET_GROUP,
            GET_CONVERSATIONS,
            CREATE_CONVERSATION,
            LEAVE_CONVERSATION,
            SUBMIT_TRANSITION,
            GET_ENTRIES,
            REPLENISH_KEY_PACKAGES,
            GET_PENDING_WELCOMES,
            GET_OWN_DEVICES,
            ENROLL_DEVICE,
            GET_DEVICES,
            GET_CONVERSATION_STATE,
            GET_SUBSCRIPTION_TICKET,
        ];
        assert!(routes
            .iter()
            .all(|route| route.starts_with("blue.catbird.chat.")));
        assert!(routes.iter().all(|route| !route.contains("mlsChat")));
    }
}

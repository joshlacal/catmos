//! Session-restore failure classification shared by the desktop auth command.

/// Returns true only when Nest definitively rejected the saved credential.
/// Transport failures and upstream outages are retryable and must not erase
/// the keychain entry that anchors the user's persisted MLS state.
pub(crate) fn session_error_invalidates_credentials(error: &str) -> bool {
    error.contains("Session rejected by nest (401")
        || error.contains("Session rejected by nest (403")
}

#[cfg(test)]
mod tests {
    use super::session_error_invalidates_credentials;

    #[test]
    fn transient_restore_failure_keeps_saved_credentials() {
        assert!(!session_error_invalidates_credentials(
            "Failed to fetch session info: connection reset by peer"
        ));
        assert!(!session_error_invalidates_credentials(
            "Session rejected by nest (500 Internal Server Error): upstream unavailable"
        ));
    }

    #[test]
    fn rejected_restore_session_clears_saved_credentials() {
        assert!(session_error_invalidates_credentials(
            "Session rejected by nest (401 Unauthorized): expired"
        ));
        assert!(session_error_invalidates_credentials(
            "Session rejected by nest (403 Forbidden): revoked"
        ));
    }
}

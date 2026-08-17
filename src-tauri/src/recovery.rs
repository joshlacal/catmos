//! Shared recovery categories for the desktop transport and UI boundary.
//!
//! These values deliberately describe the next safe user/system action. They
//! are not authorization decisions: the server-issued session, device
//! binding, and MLS state remain the authorities for whether an operation may
//! proceed.

use std::fmt;

/// Stable machine-readable category understood by the Svelte client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecoveryCategory {
    /// The transport may be retried without changing credentials or MLS state.
    Retry,
    /// The saved session is no longer accepted; the user must authenticate.
    Reauthenticate,
    /// The session remains present but the server/device binding must be
    /// admitted again before canonical reads or writes can proceed.
    Rebind,
    /// Local MLS state needs the explicit join/rejoin flow.
    Rejoin,
    /// The server ended access or membership; do not spin on reconnect.
    AccessEnded,
}

impl RecoveryCategory {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Retry => "retry",
            Self::Reauthenticate => "reauthenticate",
            Self::Rebind => "rebind",
            Self::Rejoin => "rejoin",
            Self::AccessEnded => "access-ended",
        }
    }
}

impl fmt::Display for RecoveryCategory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

const PREFIX: &str = "catmos-recovery";

/// Classify an error without treating a local identifier as authority.
///
/// This is intentionally conservative: unknown failures remain retryable and
/// never cause keychain deletion. Explicit access/session failures are the
/// only categories that should stop automatic reconnect attempts.
pub(crate) fn classify_error(error: &str) -> RecoveryCategory {
    let lower = error.to_ascii_lowercase();

    if lower.contains("session rejected by nest (401")
        || lower.contains("unauthorized")
        || lower.contains("invalid session")
        || lower.contains("session expired")
    {
        return RecoveryCategory::Reauthenticate;
    }

    if lower.contains("access ended")
        || lower.contains("device revoked")
        || lower.contains("not a member")
        || lower.contains("not_member")
    {
        return RecoveryCategory::AccessEnded;
    }

    if lower.contains("binding")
        || lower.contains("dpop")
        || lower.contains("server device")
        || lower.contains("device authority")
        || lower.contains("signer")
        || lower.contains("reauthenticate")
        || lower.contains("rebind")
        || lower.contains("403")
        || lower.contains("forbidden")
        || lower.contains("not wired")
        || lower.contains("canonical subscription ticket transport is unavailable")
        || lower.contains("requires the shared signed")
    {
        return RecoveryCategory::Rebind;
    }

    if lower.contains("not joined")
        || lower.contains("needsrejoin")
        || lower.contains("needs rejoin")
        || lower.contains("rejoin")
        || lower.contains("epoch mismatch")
        || lower.contains("quarantined")
    {
        return RecoveryCategory::Rejoin;
    }

    RecoveryCategory::Retry
}

/// Prefix an error with its stable recovery category. The message remains
/// human-readable after the second delimiter and must not contain secrets.
pub(crate) fn actionable_error(error: impl fmt::Display) -> String {
    let message = error.to_string();
    if message.starts_with(PREFIX) {
        return message;
    }
    format!("{PREFIX}:{}:{}", classify_error(&message), message)
}

/// Extract the category marker from an already formatted backend error.
/// Primarily useful for tests and diagnostics; malformed input is retryable.
#[cfg(test)]
pub(crate) fn parse_category(error: &str) -> RecoveryCategory {
    error
        .strip_prefix(PREFIX)
        .and_then(|rest| rest.strip_prefix(':'))
        .and_then(|rest| rest.split(':').next())
        .map(|category| match category {
            "reauthenticate" => RecoveryCategory::Reauthenticate,
            "rebind" => RecoveryCategory::Rebind,
            "rejoin" => RecoveryCategory::Rejoin,
            "access-ended" => RecoveryCategory::AccessEnded,
            _ => RecoveryCategory::Retry,
        })
        .unwrap_or(RecoveryCategory::Retry)
}

#[cfg(test)]
mod tests {
    use super::{actionable_error, classify_error, parse_category, RecoveryCategory};

    #[test]
    fn categories_map_to_one_recoverable_action() {
        assert_eq!(
            classify_error("Failed to fetch session info: connection reset"),
            RecoveryCategory::Retry
        );
        assert_eq!(
            classify_error("Session rejected by nest (401 Unauthorized): expired"),
            RecoveryCategory::Reauthenticate
        );
        assert_eq!(
            classify_error("completed chat device binding is missing"),
            RecoveryCategory::Rebind
        );
        assert_eq!(
            classify_error("canonical subscription ticket transport is unavailable"),
            RecoveryCategory::Rebind
        );
        assert_eq!(
            classify_error("Group not joined locally for conversation c"),
            RecoveryCategory::Rejoin
        );
        assert_eq!(
            classify_error("server says access ended for this conversation"),
            RecoveryCategory::AccessEnded
        );
        assert_eq!(
            classify_error("403 Forbidden from canonical chat endpoint"),
            RecoveryCategory::Rebind
        );
    }

    #[test]
    fn actionable_error_round_trips_category_without_secrets() {
        let error = actionable_error("connection reset by peer");
        assert_eq!(parse_category(&error), RecoveryCategory::Retry);
        assert!(error.starts_with("catmos-recovery:retry:"));
        assert!(!error.contains("Bearer "));
    }
}

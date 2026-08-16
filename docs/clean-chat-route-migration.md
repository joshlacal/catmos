# Catmos clean-chat boundary

Catmos-owned desktop and browser direct MLS XRPC calls now go through the
canonical `blue.catbird.chat.*` route table in `src-tauri/src/chat_routes.rs`
and the matching browser constants in `src/lib/wasm.ts`. The generated
`catbird-atproto` Rust types are intentionally unchanged: this lane does not
hand-edit generated bindings.

The exact upstream dependency is the shared Nest/mls-ds compatibility seam:
it must expose the canonical routes and translate the current Catmos payloads
and response shapes until the clean-chat generated consumer types are
propagated. In particular, `getEntries`/`getConversationState`,
`submitTransition`, `enrollDevice`, and the compatibility aliases for
`getOptInStatus`, `reportRecoveryFailure`, `reportSpam`, `resetGroup`, and
`updateCursor` need an explicit server-side contract. The route constants are
therefore a reversible client boundary, not a claim that production rollout
or deploy has happened.

Session restoration is fail-closed for rejected credentials (401/403) but
retryable for transport and upstream failures. A retry preserves the keychain
session and the per-DID content-root key, so an outage cannot force a fresh
OAuth login that forks encrypted transcript persistence.

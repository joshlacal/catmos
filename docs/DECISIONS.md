# Catmos local implementation decisions

## 2026-09-19 · Encrypted requests · Protected replayable desktop projections
Chose: keep immutable MLS intent and consent authority in shared Rust; store desktop draft text and replayable request views in a separate owner-scoped SQLCipher table whose payload is additionally encrypted with the active account content-root key (provisional). Missing key fails closed. Because the frontend cannot safely persist outcomeUnknown or infer acceptance. Rejected: localStorage request text and UI-only pending records. Reversible until merge of the encrypted-request work. Override by replacing the host journal while retaining every unresolved shared-core intent and first-message identity.

## 2026-09-19 · Encrypted requests · Browser capability and reproducible UI evidence
Chose: keep browser request production explicitly unavailable until T11 provider parity is qualified; reuse the Svelte UI with native IPC now (provisional). Use Playwright as a development dependency with a localhost-only fixture route, guarded by SvelteKit dev mode, to capture render evidence and assert no pending-link preview requests. Because current browser exports do not establish protected request custody or server publication. Rejected: routing browser requests through old create/Add/send operations. Reversible until merge; override by wiring and qualifying T11 exports, not removing the gate alone. Fixture screenshots prove rendering only.

## 2026-09-19 · Encrypted requests · Separate block and authenticated close
Chose: Block sender publishes the existing authenticated account block; Decline/Close uses the shared Rust verified close operation. Block confirmation never fabricates closed consent (provisional). Because these are distinct durable operations and either may fail independently. Reversible until merge; override by composing both operations with explicit partial-success handling.

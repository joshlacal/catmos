# Encrypted group invitation notes

A group invitation and its optional direct note are separate operations. The existing invitation remains sent even if its note fails. A note never accepts a request or joins the group. This shared contract applies to desktop, browser, mobile, and command-line clients; each client must retain truthful delivery state and qualify its own storage/runtime.

## Shared representation and authority

The existing `MLSOrchestrator::send_message_with_embed`, `MLSOrchestratorBridge::send_payload_json` (or `send_payload_result_json`), and `Engine::send_payload` carry an MLS version-1 text payload with `embed.type = "groupInvitation"`. The embed data is exactly the camel-case `GroupInvitationReference`: `authorityDid`, `conversationId`, `invitationTransitionId`, `invitedByDid`, `invitedByDeviceId`, `recipientDid`. Authority is `did:web:chat.catbird.blue`; UUIDs and DIDs are canonical, no extra fields. Note text is nonblank and at most 16384 UTF-8 bytes. Reactions and control fields cannot be combined with this envelope.

Obtain the reference with `get_group_invitation_reference(group, recipient)` after the ordinary group invitation succeeds. This fetches authenticated current group policy and checks its exact pending invitation against the signed creation/policy entry and historical device key. Sending through the shared payload path repeats that lookup, requires an exact accepted direct recipient and active participants, and preserves the ordinary pending/reset/closed/quarantine send gates. A host-created reference is not authority.

The unified `CatbirdClient` / `CatbirdClientBridge` did not yet expose payload sending at the initial audit; mobile callers using that facade require a coordinated thin forwarding addition before final generated bindings. There is no existing `send_message_with_embed_json` symbol in the isolated shared source. Do not substitute a JSON string inside an ordinary text message.

## Client flow

1. Invite the member using the normal group operation. Present the invitation result independently.
2. Offer **Write note** as a separate action; selecting it resolves the authenticated reference and creates a protected local draft.
3. If there is no direct conversation, explicit first Send uses `start_direct_request` with that reference in the encrypted introduction. Keep the same unresolved intent on retry.
4. If `ExistingDirect` is returned, retain the text. For pending consent, open/review the existing request and do not send. For an accepted direct conversation, offer a separate **Send invitation note** action using the structured embed; never automatically fall back to sending.
5. An uncertain ordinary note send must not automatically mint another message ID. Catmos records the attempt before calling the existing send facade, retains the text, and requires inspection of the conversation. A confirmed note stores the returned message identity. This is not an exactly-once claim for generic ordinary sends.

## Display and navigation

Render the note as escaped literal text and a **View group invitation** button. Do not fetch previews or treat the authority DID as a user-selected network endpoint. Clicking selects the canonical group conversation for an independent, authenticated review; it does not accept either conversation. Decrypted payload structure is not itself proof of current group eligibility. The destination view must fetch/check current policy, including revocation or already-accepted invitations.

Pending request previews retain their separate structured invitation reference and stable first-message identity. Accepted notes are ordinary encrypted applications and have their own message identity. Never synthesize a signed application entry from an introduction.

## Evidence

Shared focused shape/destination tests: `/tmp/t15-shared-note-tests.log` (3 passed at initial implementation). Catmos store, native storage, and local browser fixture evidence is recorded in the adjacent T12 report. Fixture rendering proves no service publication or cryptographic receipt authority. Real cross-client note and production-provider push qualification remain separate gates.

/**
 * Plain-language messages for refusals from the chat delivery service.
 *
 * The WASM client reports a refused request as
 * `POST <nsid> returned HTTP <status>: {"error":"<Code>",...}`, often behind
 * an `Internal error: ` prefix. This module finds the protocol code in that
 * text and says what happened and what the person can do about it.
 */

export type ConversationKind = 'direct' | 'group';

export interface ChatErrorDescription {
	/** Protocol error code, when one was found. */
	code: string | null;
	message: string;
	/** True when the same request may succeed if sent again unchanged. */
	retryable: boolean;
}

const RETRYABLE_CODES = new Set(['RelationshipPolicyUnavailable', 'CapacityUnavailable', 'RateLimited']);

function rawMessage(err: unknown): string {
	if (typeof err === 'string') return err;
	if (err && typeof err === 'object' && 'message' in err) {
		const message = (err as { message?: unknown }).message;
		if (typeof message === 'string') return message;
	}
	return '';
}

/** The protocol error code carried by a delivery service refusal, if any. */
export function chatErrorCode(err: unknown): string | null {
	const text = rawMessage(err);
	const marker = text.indexOf(' returned HTTP ');
	if (marker === -1) return null;
	const bodyStart = text.indexOf('{', marker);
	if (bodyStart === -1) return null;
	try {
		const body: unknown = JSON.parse(text.slice(bodyStart));
		if (body && typeof body === 'object' && 'error' in body) {
			const code = (body as { error?: unknown }).error;
			if (typeof code === 'string' && /^[A-Za-z]+$/.test(code)) return code;
		}
	} catch {
		// Not JSON: fall through to the pattern below.
	}
	const match = /"error"\s*:\s*"([A-Za-z]+)"/.exec(text.slice(marker));
	return match ? match[1] : null;
}

function messageForCode(code: string, kind: ConversationKind): string | null {
	const who = kind === 'direct' ? 'this person' : 'one of these people';
	switch (code) {
		case 'RelationshipPolicyUnavailable':
			return `Catbird could not check whether ${who} accepts new chats, because one of the services it asks did not answer. Nothing was sent. Try again in a moment.`;
		case 'CapacityUnavailable':
			return 'The chat service is busy right now. Nothing was sent. Try again in a moment.';
		case 'RateLimited':
			return 'Too many requests in a short time. Wait a moment, then try again.';
		case 'MessagesDisabled':
			return 'This person is not accepting new chats on Catbird.';
		case 'GroupInvitesDisabled':
			return 'One of these people is not accepting group invitations on Catbird.';
		case 'NotFollowedByRecipient':
			return kind === 'direct'
				? 'This person only accepts new chats from people they follow.'
				: 'One of these people only accepts invitations from people they follow.';
		case 'BlockedRelationship':
			return kind === 'direct'
				? 'You cannot start a chat with this person.'
				: 'You cannot start a chat with one of these people.';
		case 'InvitationLimitReached':
			return 'You have reached the limit for new chat invitations for now. Try again later.';
		case 'RecipientNotReady':
			return kind === 'direct'
				? 'This person has not set up encrypted chat on Catbird yet.'
				: 'One of these people has not set up encrypted chat on Catbird yet.';
		case 'ConversationAlreadyExists':
			return 'This conversation already exists. Reload to see it.';
		default:
			return null;
	}
}

/** What to show when creating a conversation fails. */
export function describeCreateConversationError(
	err: unknown,
	kind: ConversationKind
): ChatErrorDescription {
	const code = chatErrorCode(err);
	if (code) {
		const message = messageForCode(code, kind);
		if (message) return { code, message, retryable: RETRYABLE_CODES.has(code) };
	}
	const raw = rawMessage(err).replace(/^Internal error:\s*/, '');
	return {
		code,
		message: raw || 'Could not create conversation.',
		retryable: false
	};
}

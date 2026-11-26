import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { chatErrorCode, describeCreateConversationError } from '../src/lib/chat-errors.ts';

const POLICY_503 =
	'Internal error: POST blue.catbird.chat.createConversation returned HTTP 503: {"error":"RelationshipPolicyUnavailable","message":"RelationshipPolicyUnavailable"}';

describe('chat delivery service refusals', () => {
	it('finds the protocol code in a refused request', () => {
		assert.equal(chatErrorCode(new Error(POLICY_503)), 'RelationshipPolicyUnavailable');
		assert.equal(chatErrorCode(POLICY_503), 'RelationshipPolicyUnavailable');
		assert.equal(chatErrorCode(new Error('network down')), null);
		assert.equal(
			chatErrorCode(new Error('POST x returned HTTP 502: <html>Bad Gateway</html>')),
			null
		);
	});

	it('explains an unanswered policy check as retryable, without the raw response', () => {
		const described = describeCreateConversationError(new Error(POLICY_503), 'direct');
		assert.equal(described.code, 'RelationshipPolicyUnavailable');
		assert.equal(described.retryable, true);
		assert.match(described.message, /Nothing was sent\. Try again in a moment\./);
		assert.doesNotMatch(described.message, /HTTP|POST|Internal error|\{/);
	});

	it('explains a refusal as final and words it for the conversation kind', () => {
		const error = new Error(
			'POST blue.catbird.chat.createConversation returned HTTP 403: {"error":"NotFollowedByRecipient"}'
		);
		const direct = describeCreateConversationError(error, 'direct');
		assert.equal(direct.retryable, false);
		assert.match(direct.message, /^This person only accepts/);
		assert.match(describeCreateConversationError(error, 'group').message, /^One of these people/);
	});

	it('keeps an unrecognised failure readable', () => {
		assert.equal(
			describeCreateConversationError(new Error('Internal error: key store locked'), 'group')
				.message,
			'key store locked'
		);
		assert.equal(
			describeCreateConversationError(undefined, 'group').message,
			'Could not create conversation.'
		);
		const unknown = describeCreateConversationError(
			new Error('POST x returned HTTP 400: {"error":"SomethingNew"}'),
			'direct'
		);
		assert.equal(unknown.code, 'SomethingNew');
		assert.equal(unknown.retryable, false);
	});
});

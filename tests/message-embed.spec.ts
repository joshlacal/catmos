import assert from 'node:assert/strict';
import test from 'node:test';
import { extractMessageDetails } from '../src/lib/message-embed.ts';

// Payloads in the exact shape catbird-mls `MLSMessagePayload` serializes and
// Catbird iOS sends: embed = { type, data: { ...snake_case... } }.
const SPACE_LOCATOR =
	'at://did:web:chat.catbird.blue/space/blue.catbird.labyrinth.conversation/abc|did:plc:alice|bafyreiimg';

test('image embed in wire shape keeps the blob locator, keys and size', () => {
	const json = JSON.stringify({
		version: 1,
		messageType: 'text',
		text: 'Look!',
		embed: {
			type: 'image',
			data: {
				blob_id: SPACE_LOCATOR,
				key: 'ERERERERERERERERERERERERERERERERERERERERERE=',
				iv: 'IiIiIiIiIiIiIiIi',
				sha256: 'aa'.repeat(32),
				content_type: 'image/png',
				size: 1024,
				width: 640,
				height: 480,
				alt_text: 'sunset'
			}
		}
	});
	const d = extractMessageDetails(json);
	assert.equal(d.messageType, 'image');
	assert.equal(d.content, 'Look!');
	assert.ok(d.image);
	assert.equal(d.image.blobId, SPACE_LOCATOR);
	assert.equal(d.image.keyB64, 'ERERERERERERERERERERERERERERERERERERERERERE=');
	assert.equal(d.image.contentType, 'image/png');
	assert.equal(d.image.width, 640);
	assert.equal(d.image.height, 480);
	assert.equal(d.image.altText, 'sunset');
});

test('audio embed in wire shape decodes key, iv and duration', () => {
	const json = JSON.stringify({
		version: 1,
		messageType: 'text',
		embed: {
			type: 'audio',
			data: {
				blob_id: SPACE_LOCATOR,
				key: 'AQID',
				iv: 'BAUG',
				sha256: 'bb'.repeat(32),
				content_type: 'audio/mp4',
				size: 2048,
				duration_ms: 3500,
				waveform: [0.1, 0.5, 0.9]
			}
		}
	});
	const d = extractMessageDetails(json);
	assert.equal(d.messageType, 'voice');
	assert.ok(d.audio);
	assert.equal(d.audio.blobId, SPACE_LOCATOR);
	assert.deepEqual(Array.from(d.audio.key), [1, 2, 3]);
	assert.deepEqual(Array.from(d.audio.iv), [4, 5, 6]);
	assert.equal(d.audio.durationMs, 3500);
	assert.equal(d.audio.contentType, 'audio/mp4');
});

test('legacy flat camelCase image embed still parses', () => {
	const d = extractMessageDetails(
		JSON.stringify({
			text: '',
			embed: { type: 'image', blobId: 'b1', key: 'k', iv: 'i', contentType: 'image/gif', width: 2 }
		})
	);
	assert.equal(d.image?.blobId, 'b1');
	assert.equal(d.image?.contentType, 'image/gif');
	assert.equal(d.image?.width, 2);
});

test('post embed with no text surfaces as a card, not an empty bubble', () => {
	const d = extractMessageDetails(
		JSON.stringify({
			version: 1,
			messageType: 'text',
			embed: {
				type: 'post',
				data: { uri: 'at://did:plc:carol/app.bsky.feed.post/3kabc', author_did: 'did:plc:carol' }
			}
		})
	);
	assert.equal(d.content, '');
	assert.deepEqual(d.embed, {
		type: 'post',
		data: { uri: 'at://did:plc:carol/app.bsky.feed.post/3kabc', author_did: 'did:plc:carol' }
	});
});

test('link and gif embeds pass through; other kinds do not', () => {
	const link = extractMessageDetails(
		JSON.stringify({ text: 'see', embed: { type: 'link', data: { url: 'https://example.com' } } })
	);
	assert.equal(link.embed?.type, 'link');
	assert.equal(link.content, 'see');

	const gif = extractMessageDetails(
		JSON.stringify({ embed: { type: 'gif', data: { mp4_url: 'https://media.tenor.com/x.mp4' } } })
	);
	assert.equal(gif.embed?.data.mp4_url, 'https://media.tenor.com/x.mp4');

	const invite = extractMessageDetails(
		JSON.stringify({ text: 'hi', embed: { type: 'groupInvitation', data: {} } })
	);
	assert.equal(invite.embed, undefined);
	assert.equal(invite.content, 'hi');
});

test('plain text and malformed JSON are unchanged', () => {
	assert.deepEqual(extractMessageDetails(JSON.stringify({ messageType: 'text', text: 'hello' })), {
		messageType: 'text',
		content: 'hello'
	});
	assert.deepEqual(extractMessageDetails('not json'), { messageType: 'text', content: 'not json' });
});

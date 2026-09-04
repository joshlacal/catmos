// Run: node --experimental-vm-modules --test tests/message-ordering.test.mjs
// Execute the actual TypeScript store with only its transport replaced. No
// browser, Tauri runtime, generated WASM package, or live account is required.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import vm from 'node:vm';
import ts from 'typescript';
import { get, writable } from 'svelte/store';

const source = await readFile(new URL('../src/lib/stores/messages.ts', import.meta.url), 'utf8');
const compiled = ts.transpileModule(source, {
	compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext }
}).outputText;

async function storeWith(api = {}) {
	const context = vm.createContext({ console, Uint8Array });
	const transport = {
		getMessages: async () => [],
		fetchNewMessages: async () => [],
		sendMessage: async () => { throw new Error('Unexpected send'); },
		sendImage: async () => { throw new Error('Unexpected image send'); },
		sendVoice: async () => { throw new Error('Unexpected voice send'); },
		...api
	};
	const mockTransport = new vm.SyntheticModule(Object.keys(transport), function () {
		for (const [key, value] of Object.entries(transport)) this.setExport(key, value);
	}, { context });
	const svelte = new vm.SyntheticModule(['writable'], function () {
		this.setExport('writable', writable);
	}, { context });
	const subject = new vm.SourceTextModule(compiled, { context });
	await subject.link((specifier) => {
		if (specifier === 'svelte/store') return svelte;
		if (specifier === '$lib/wasm') return mockTransport;
		throw new Error(`Unexpected store dependency: ${specifier}`);
	});
	await subject.evaluate();
	return subject.namespace.messages;
}

const conversationId = 'fixture-conversation';
function message(id, sequenceNumber, timestamp = '2026-09-05T12:00:00.000Z') {
	return { id, sequenceNumber, timestamp, conversationId, senderDid: 'did:web:peer.example.com',
		senderHandle: '', content: id, status: 'delivered', messageType: 'text' };
}
const own10 = message('own-10', 10, '2026-09-05T12:00:02.000Z');
const peer11 = message('peer-11', 11, '2026-09-05T12:00:01.000Z');
const ids = (store) => Array.from(get(store).byConversation.get(conversationId) ?? [], (m) => m.id);

test('load preserves confirmed server sequence despite a later local ACK timestamp', async () => {
	const store = await storeWith({ getMessages: async () => [peer11, own10, own10] });
	await store.load(conversationId);
	assert.deepEqual(ids(store), ['own-10', 'peer-11']);
});

test('server merge and incoming events preserve canonical order and deduplication', async () => {
	const store = await storeWith({
		getMessages: async () => [own10],
		fetchNewMessages: async () => [peer11, peer11]
	});
	await store.load(conversationId);
	await store.fetchFromServer(conversationId);
	assert.deepEqual(ids(store), ['own-10', 'peer-11']);
	store.addIncoming(message('peer-12', 12, '2026-09-05T11:59:00.000Z'));
	store.addIncoming(peer11);
	assert.deepEqual(ids(store), ['own-10', 'peer-11', 'peer-12']);
});

test('missing and zero sequence stay after confirmed rows, with timestamp then ID ties', async () => {
	const input = [message('pending-z', 0), own10, message('legacy-a', undefined),
		message('pending-early', 0, '2020-01-01T00:00:00.000Z'), peer11];
	const store = await storeWith({ getMessages: async () => input });
	await store.load(conversationId);
	assert.deepEqual(ids(store), ['own-10', 'peer-11', 'pending-early', 'legacy-a', 'pending-z']);
});

test('malformed or unsafe sequence values cannot become confirmed by coercion', async () => {
	const invalid = [undefined, 0, -1, NaN, Infinity, 1.5, Number.MAX_SAFE_INTEGER + 1, '1', null];
	const rows = invalid.map((value, i) => message(`pending-${i}`, value, '2020-01-01T00:00:00.000Z'));
	const store = await storeWith({ getMessages: async () => [...rows.reverse(), peer11, own10] });
	await store.load(conversationId);
	assert.deepEqual(ids(store), ['own-10', 'peer-11', ...invalid.map((_, i) => `pending-${i}`)]);
});

test('equal confirmed sequence uses timestamp then ID deterministically across arrival orders', async () => {
	const rows = [message('b', 10), message('a', 10),
		message('earlier', 10, '2026-09-05T11:59:00.000Z')];
	for (const order of [rows, [...rows].reverse(), [rows[1], rows[2], rows[0]]]) {
		const store = await storeWith();
		for (const row of order) store.addIncoming(row);
		assert.deepEqual(ids(store), ['earlier', 'a', 'b']);
	}
});

test('mixed confirmed and unconfirmed rows have a transitive order for every arrival permutation', async () => {
	const pending = message('pending', 0, '2026-09-05T12:00:01.500Z');
	for (const order of [
		[own10, peer11, pending], [own10, pending, peer11], [peer11, own10, pending],
		[peer11, pending, own10], [pending, own10, peer11], [pending, peer11, own10]
	]) {
		const store = await storeWith();
		for (const row of order) store.addIncoming(row);
		assert.deepEqual(ids(store), ['own-10', 'peer-11', 'pending']);
	}
});

for (const kind of ['text', 'image', 'voice']) {
	test(`${kind} send ACK immediately moves its former pending row before a later incoming sequence`, async () => {
		let acknowledge;
		const response = new Promise((resolve) => { acknowledge = resolve; });
		const store = await storeWith({
			sendMessage: () => response, sendImage: () => response, sendVoice: () => response
		});
		const sending = kind === 'text' ? store.send(conversationId, 'hello')
			: kind === 'image' ? store.sendImage(conversationId, 'photo', {
				data: new Uint8Array([1]), contentType: 'image/png', width: 1, height: 1,
				previewUrl: 'data:image/png;base64,AQ=='
			}) : store.sendVoice(conversationId, new Uint8Array([1]), 100, [1]);
		store.addIncoming(peer11);
		assert.equal(ids(store)[0], 'peer-11');
		assert.match(ids(store)[1], /^temp-/);
		acknowledge({ ...own10, status: 'sent', messageType: kind });
		await sending;
		assert.deepEqual(ids(store), ['own-10', 'peer-11']);
	});
}

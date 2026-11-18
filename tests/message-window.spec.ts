import assert from 'node:assert/strict';
import { test } from 'node:test';
import { get } from 'svelte/store';
import { readMessageWindow } from '../src/lib/message-window.ts';
import { messages } from '../src/lib/stores/messages.ts';
import { __setWorkerFactoryForTests, searchMessages } from '../src/lib/wasm.ts';
import type { Message } from '../src/lib/tauri.ts';

function row(seq: number, room = 'room'): Message {
	return { id: String(seq), sequenceNumber: seq, conversationId: room, senderDid: 'did:example:bob',
		senderHandle: 'bob', content: 'receipt-' + seq, timestamp: new Date(seq * 1000).toISOString(), status: 'sent' };
}

test('refresh reads past the first page through the oldest message on screen', async () => {
	const current = [row(2), row(10), row(70)];
	const stored = Array.from({ length: 120 }, (_, i) => row(i + 1)).filter((m) => m.sequenceNumber !== 10);
	const page = (before: number) => stored.filter((m) => m.sequenceNumber! < before).slice(-50);
	const reads: string[] = [];
	const result = await readMessageWindow(current, page(Infinity), async (before) => {
		reads.push(before);
		return page(Number(before));
	});
	assert.deepEqual(reads, ['71', '21']);
	assert.equal(result.length, 119);
	assert.ok(result.some((m) => m.id === '2'));
	assert.ok(!result.some((m) => m.id === '10'));
});

test('open and background rooms, search, late reads and sends follow the committed store', async () => {
	const source = new Map([['a', [row(10, 'a'), row(12, 'a')]], ['b', [row(10, 'b')]]]);
	let read: (room: string) => Promise<Message[]> = async (room) => source.get(room) ?? [];
	const sent = Promise.withResolvers<Message>();
	const marks: boolean[] = [];
	__setWorkerFactoryForTests(() => ({ worker: {
		getMessages: (cid: string, _before: string, mark: boolean) => { marks.push(mark); return read(cid); },
		sendMessage: () => sent.promise
	} as never }));
	messages.setAccount('did:example:alice');
	await messages.load('a');
	await messages.load('b');
	assert.equal((await searchMessages('receipt-10')).length, 2);
	const lateRead = Promise.withResolvers<Message[]>();
	read = () => lateRead.promise;
	const loading = messages.refreshLocal('a');
	read = async (cid) => source.get(cid) ?? [];
	source.set('a', [row(12, 'a')]);
	source.set('b', []);
	await messages.refreshCached('a');
	lateRead.resolve([row(10, 'a')]);
	await loading;
	assert.deepEqual(get(messages).byConversation.get('a')?.map((m) => m.id), ['12']);
	assert.deepEqual(get(messages).byConversation.get('b'), []);
	assert.deepEqual(await searchMessages('receipt-10'), []);
	assert.deepEqual(marks, [true, true, false, false, false]);
	const pending = messages.send('a', 'local draft');
	await messages.refreshCached('a');
	assert.equal(get(messages).byConversation.get('a')?.filter((m) => m.status === 'sending').length, 1);
	messages.setAccount('did:example:other');
	sent.resolve(row(10, 'a'));
	await pending;
	assert.equal(get(messages).byConversation.size, 0);
});

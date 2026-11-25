import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { beforeEach, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { get } from 'svelte/store';

import { validateLoginIdentifier } from '../src/lib/stores/auth.ts';
import { conversations, extractMessagePreview } from '../src/lib/stores/conversations.ts';
import { drafts } from '../src/lib/stores/drafts.ts';
import { resolveProfileName, shortDid } from '../src/lib/stores/profiles.ts';
import { quarantineReasonCopy } from '../src/lib/stores/quarantine.ts';
import {
	isMuted,
	isPinned,
	preferences,
	setAccent,
	setActiveDid,
	setContrast,
	setDensity,
	setScheme,
	toggleMute,
	togglePin
} from '../src/lib/stores/preferences.ts';
import {
	formatClockTime,
	formatDayDivider,
	formatDuration,
	formatSidebarTime,
	isSameCalendarDay
} from '../src/lib/utils/time.ts';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CATMOS_ROOT = path.resolve(__dirname, '..');

class MemoryStorage implements Storage {
	#map = new Map<string, string>();
	get length(): number {
		return this.#map.size;
	}
	clear(): void {
		this.#map.clear();
	}
	getItem(key: string): string | null {
		return this.#map.get(key) ?? null;
	}
	key(index: number): string | null {
		return Array.from(this.#map.keys())[index] ?? null;
	}
	removeItem(key: string): void {
		this.#map.delete(key);
	}
	setItem(key: string, value: string): void {
		this.#map.set(key, String(value));
	}
}

describe('Redesigned Catmos stores, validation, formatting, and CSP-safe bootstrap', () => {
	let fakeLocal: MemoryStorage;
	let fakeSession: MemoryStorage;

	beforeEach(() => {
		fakeLocal = new MemoryStorage();
		fakeSession = new MemoryStorage();
		Object.defineProperty(globalThis, 'localStorage', {
			value: fakeLocal,
			configurable: true,
			writable: true
		});
		Object.defineProperty(globalThis, 'sessionStorage', {
			value: fakeSession,
			configurable: true,
			writable: true
		});
		Object.defineProperty(globalThis, 'window', {
			value: {
				localStorage: fakeLocal,
				sessionStorage: fakeSession,
				matchMedia: () => ({
					matches: true,
					addEventListener: () => {},
					removeEventListener: () => {}
				})
			},
			configurable: true,
			writable: true
		});
		drafts.reset();
		conversations.reset();
	});

	it('validates Bluesky handles and DIDs while rejecting blanks, spaces, and email addresses', () => {
		assert.deepEqual(validateLoginIdentifier('  @Alice.Bsky.Social  '), {
			ok: true,
			identifier: 'alice.bsky.social'
		});
		assert.deepEqual(validateLoginIdentifier('did:plc:abcdefghijklmnopqrstuvwx'), {
			ok: true,
			identifier: 'did:plc:abcdefghijklmnopqrstuvwx'
		});
		assert.deepEqual(validateLoginIdentifier('did:web:catbird.blue'), {
			ok: true,
			identifier: 'did:web:catbird.blue'
		});

		for (const bad of ['', '   ', 'alice@example.com', 'not a handle', 'singleword', 'did:key:z123']) {
			const res = validateLoginIdentifier(bad);
			assert.equal(res.ok, false, `expected invalid for "${bad}"`);
		}
	});

	it('unwraps reply envelopes and embed payloads cleanly for conversation previews', () => {
		assert.equal(
			extractMessagePreview(
				JSON.stringify({
					text: 'Looks great!',
					reply: { messageId: 'm1', senderDid: 'did:plc:bob', preview: 'Ready?' }
				})
			),
			'Looks great!'
		);
		assert.equal(
			extractMessagePreview(JSON.stringify({ embed: { type: 'image', data: {} } })),
			'Photo'
		);
		assert.equal(
			extractMessagePreview(JSON.stringify({ embed: { type: 'audio', data: {} } })),
			'Voice message'
		);
		assert.equal(extractMessagePreview('Plain text message'), 'Plain text message');
		assert.equal(extractMessagePreview('{not valid json'), '{not valid json');
	});

	it('updates conversation previews, unread counts, and recency ordering live', () => {
		conversations.setItems(
			[
				{
					id: 'c1',
					displayName: 'Alpha',
					members: ['did:plc:alice', 'did:plc:bob'],
					unreadCount: 0,
					isGroup: false,
					lastMessageAt: '2026-11-25T10:00:00Z'
				},
				{
					id: 'c2',
					displayName: 'Beta',
					members: ['did:plc:alice', 'did:plc:carol'],
					unreadCount: 1,
					isGroup: false,
					lastMessageAt: '2026-11-25T09:00:00Z'
				}
			],
			'c1'
		);

		conversations.applyMessageActivity('c2', {
			text: JSON.stringify({ text: 'Ping from Carol', reply: { messageId: 'x' } }),
			timestamp: '2026-11-25T11:00:00Z',
			isOwn: false
		});

		const state = get(conversations);
		assert.equal(state.items[0]?.id, 'c2');
		assert.equal(state.items[0]?.lastMessage, 'Ping from Carol');
		assert.equal(state.items[0]?.unreadCount, 2);
	});

	it('keeps drafts immediately readable before debounce flush and isolates accounts by DID', () => {
		drafts.setActiveDid('did:plc:alice0001#dev-1');
		drafts.setDraft('room-1', 'Draft for Alice');
		assert.equal(drafts.getDraft('room-1'), 'Draft for Alice');
		assert.equal(drafts.hasDraft('room-1'), true);

		drafts.setActiveDid('did:plc:bob0002#dev-2');
		assert.equal(drafts.getDraft('room-1'), '');
		drafts.setDraft('room-1', 'Draft for Bob');
		assert.equal(drafts.getDraft('room-1'), 'Draft for Bob');
		drafts.clearDraft('room-1');
		assert.equal(drafts.hasDraft('room-1'), false);
	});

	it('persists Catbird appearance preferences and per-DID pin/mute state', () => {
		setActiveDid('did:plc:alice0001');
		setScheme('dim');
		setAccent('aurora');
		setContrast('more');
		setDensity('compact');
		togglePin('c-eng');
		toggleMute('c-rel');

		const p = get(preferences);
		assert.equal(p.scheme, 'dim');
		assert.equal(p.accent, 'aurora');
		assert.equal(p.contrast, 'more');
		assert.equal(p.density, 'compact');
		assert.equal(isPinned('c-eng'), true);
		assert.equal(isMuted('c-rel'), true);

		setActiveDid('did:plc:bob0002');
		assert.equal(isPinned('c-eng'), false);
		assert.equal(isMuted('c-rel'), false);
	});

	it('resolves multi-device profile names cleanly and formats times without em-dashes', () => {
		const cache = new Map([
			[
				'did:plc:maya0002',
				{ did: 'did:plc:maya0002', handle: 'maya.catbird.blue', displayName: 'Maya Lin' }
			]
		]);
		assert.equal(resolveProfileName(cache, 'did:plc:maya0002#dev-99'), 'Maya Lin');
		assert.equal(resolveProfileName(cache, 'did:plc:unknown99999999999999', 'devon.studio'), '@devon.studio');
		assert.ok(!shortDid('did:plc:abcdefghijklmnopqrstuvwx').includes('—'));

		const now = new Date('2026-11-25T15:00:00Z');
		assert.equal(isSameCalendarDay('2026-11-25T09:00:00Z', now), true);
		assert.equal(formatDayDivider('2026-11-25T09:00:00Z', now), 'Today');
		assert.equal(formatDuration(125_000), '2:05');
		assert.ok(formatClockTime('2026-11-25T09:15:00Z').length > 0);
		assert.ok(formatSidebarTime('2026-11-25T09:15:00Z', now).length > 0);
		assert.ok(!quarantineReasonCopy('repeated_framing_failures').includes('—'));
	});

	it('loads pre-paint theme bootstrap from external static/theme-init.js with zero inline script or third-party fonts', () => {
		const appHtml = fs.readFileSync(path.join(CATMOS_ROOT, 'src/app.html'), 'utf8');
		assert.ok(appHtml.includes('<script src="/theme-init.js"></script>'));
		assert.ok(!/<script(?![^>]*\bsrc=)/i.test(appHtml), 'app.html must not contain inline <script> under strict CSP');
		assert.ok(!appHtml.includes('rsms.me'));
		assert.ok(fs.existsSync(path.join(CATMOS_ROOT, 'static/theme-init.js')));
		assert.ok(fs.statSync(path.join(CATMOS_ROOT, 'static/favicon.png')).size > 0);
		assert.ok(fs.statSync(path.join(CATMOS_ROOT, 'static/icon-192.png')).size > 0);
		assert.ok(fs.statSync(path.join(CATMOS_ROOT, 'static/icon-512.png')).size > 0);
	});
});

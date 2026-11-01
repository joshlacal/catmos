import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { describe, it, beforeEach } from 'node:test';
import { fileURLToPath } from 'node:url';

import { acquireTabLock } from '../src/lib/tab-lock.ts';
import {
	loadOrCreateDbKeyHex,
	inspectWrappingCryptoKey,
	resetKeyStoreMemoryFallbackForTests
} from '../src/lib/webcrypto-keystore.ts';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CATMOS_ROOT = path.resolve(__dirname, '..');

class MemoryStorage implements Storage {
	private map = new Map<string, string>();
	get length(): number {
		return this.map.size;
	}
	clear(): void {
		this.map.clear();
	}
	getItem(key: string): string | null {
		return this.map.has(key) ? (this.map.get(key) ?? null) : null;
	}
	key(index: number): string | null {
		return Array.from(this.map.keys())[index] ?? null;
	}
	removeItem(key: string): void {
		this.map.delete(key);
	}
	setItem(key: string, value: string): void {
		this.map.set(key, String(value));
	}
}

class FakeNavigatorLocks {
	public requestedOptions: Array<{ name: string; options: Record<string, unknown> }> = [];
	private held = new Map<string, Array<() => void>>();

	async request<T>(
		name: string,
		optionsOrCallback: Record<string, unknown> | ((lock: { name: string } | null) => Promise<T>),
		maybeCallback?: (lock: { name: string } | null) => Promise<T>
	): Promise<T> {
		const options = typeof optionsOrCallback === 'function' ? {} : optionsOrCallback;
		const callback =
			typeof optionsOrCallback === 'function' ? optionsOrCallback : maybeCallback!;
		this.requestedOptions.push({ name, options });

		if (options.steal === true) {
			throw new Error('Gate 9 violation: navigator.locks called with { steal: true }');
		}

		if (options.ifAvailable === true) {
			if (this.held.has(name)) {
				return callback(null);
			}
			this.held.set(name, []);
			try {
				return await callback({ name });
			} finally {
				this.releaseNext(name);
			}
		}

		if (this.held.has(name)) {
			await new Promise<void>((resolve) => {
				this.held.get(name)!.push(resolve);
			});
		} else {
			this.held.set(name, []);
		}

		try {
			return await callback({ name });
		} finally {
			this.releaseNext(name);
		}
	}

	private releaseNext(name: string): void {
		const queue = this.held.get(name);
		if (!queue || queue.length === 0) {
			this.held.delete(name);
			return;
		}
		const next = queue.shift()!;
		next();
	}
}

describe('Gate 9 Web Worker tab-lock and non-extractable WebCrypto keystore', () => {
	let sessionStore: MemoryStorage;
	let localStore: MemoryStorage;
	let fakeLocks: FakeNavigatorLocks;

	beforeEach(() => {
		sessionStore = new MemoryStorage();
		localStore = new MemoryStorage();
		fakeLocks = new FakeNavigatorLocks();
		Object.defineProperty(globalThis, 'sessionStorage', {
			value: sessionStore,
			configurable: true,
			writable: true
		});
		Object.defineProperty(globalThis, 'localStorage', {
			value: localStore,
			configurable: true,
			writable: true
		});
		Object.defineProperty(globalThis, 'navigator', {
			value: { locks: fakeLocks },
			configurable: true,
			writable: true
		});
		resetKeyStoreMemoryFallbackForTests();
	});

	it('awaits navigator.locks without steal:true and surfaces "Chat active in another tab"', async () => {
		const didHash = 'a'.repeat(64);
		const tab1Handle = await acquireTabLock(didHash);
		assert.equal(tab1Handle.status, 'acquired');

		const waitingMessages: string[] = [];
		let tab2Acquired = false;
		const tab2Promise = acquireTabLock(didHash, {
			onWaiting: (msg) => waitingMessages.push(msg)
		}).then((handle) => {
			tab2Acquired = true;
			return handle;
		});

		// Yield microtasks so Tab 2 probes availability and enters exclusive wait
		await new Promise((r) => setTimeout(r, 20));
		assert.deepEqual(waitingMessages, ['Chat active in another tab']);
		assert.equal(tab2Acquired, false);

		for (const call of fakeLocks.requestedOptions) {
			assert.notEqual(call.options.steal, true, 'must NEVER pass { steal: true }');
			assert.equal(call.name, `catbird-mls:${didHash}`);
		}

		tab1Handle.release();
		const tab2Handle = await tab2Promise;
		assert.equal(tab2Acquired, true);
		assert.equal(tab2Handle.status, 'acquired');
		tab2Handle.release();
	});

	it('contains zero { steal: true } calls anywhere in catmos/src', () => {
		const filesToScan = [
			'src/lib/tab-lock.ts',
			'src/lib/stores/tab-lock.ts',
			'src/lib/components/TabBlockedMessage.svelte',
			'src/routes/+layout.svelte'
		];
		for (const rel of filesToScan) {
			const src = fs.readFileSync(path.join(CATMOS_ROOT, rel), 'utf8');
			assert.equal(
				/steal\s*:\s*true/.test(src),
				false,
				`Found forbidden { steal: true } in ${rel}`
			);
		}
	});

	it('stores non-extractable AES-GCM CryptoKey and leaves zero DB keys in sessionStorage/localStorage', async () => {
		const didHash = 'b'.repeat(64);
		// Seed legacy pre-cutover storage artifacts to verify they get purged
		sessionStore.setItem('catmos:did:plc:alice:mls_db_key', 'deadbeef'.repeat(8));
		localStore.setItem('catmos_content_root_key_did:plc:alice', 'cafebabe'.repeat(8));

		const keyHex1 = await loadOrCreateDbKeyHex(didHash);
		assert.match(keyHex1, /^[0-9a-f]{64}$/);

		const keyHex2 = await loadOrCreateDbKeyHex(didHash);
		assert.equal(keyHex2, keyHex1, 'must unwrap the same durable 32-byte DB key across reloads');

		const kek = await inspectWrappingCryptoKey(didHash);
		assert.ok(kek, 'wrapping CryptoKey must exist');
		assert.equal(kek.extractable, false, 'wrapping CryptoKey MUST have extractable === false');
		assert.equal(kek.algorithm.name, 'AES-GCM');

		// Verify zero hex/base64 DB keys remain in sessionStorage or localStorage
		for (let i = 0; i < sessionStore.length; i++) {
			const k = sessionStore.key(i)!;
			assert.equal(/mls_db_key|content_root_key/i.test(k), false, `leaked key in sessionStorage: ${k}`);
		}
		for (let i = 0; i < localStore.length; i++) {
			const k = localStore.key(i)!;
			assert.equal(/mls_db_key|content_root_key/i.test(k), false, `leaked key in localStorage: ${k}`);
		}
	});
});

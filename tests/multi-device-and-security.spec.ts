import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { describe, it, beforeEach } from 'node:test';
import { fileURLToPath } from 'node:url';

import {
	applyReactionToMap,
	extractDidDeviceFragment,
	foldGroupMembersByAccount,
	foldReactionsByAccount,
	hasAccountReacted,
	isSameAccountDid,
	normalizeAccountDid,
	stripDidFragment
} from '../src/lib/did.ts';
import {
	parseTauriOAuthCallbackPayload,
	validateCatmosDeepLinkCallback,
	validateWebOAuthCallbackUrl,
	validateWebPermissionCallbackUrl
} from '../src/lib/oauth-callback.ts';
import {
	CATMOS_SVELTEKIT_CSP_DIRECTIVES,
	CATMOS_WEB_CONNECT_ORIGINS
} from '../src/lib/csp.ts';
import {
	accountDidHashHex,
	inspectWrappingCryptoKey,
	resetKeyStoreMemoryFallbackForTests
} from '../src/lib/webcrypto-keystore.ts';
import {
	isMlsOptedInForDid,
	REQUIRED_LABYRINTH_OAUTH_SCOPES,
	setMlsOptedInForDid
} from '../src/lib/labyrinth-ui.ts';
import {
	__setWorkerFactoryForTests,
	BROWSER_DEVICE_ID_PREFIX,
	completeLogin,
	completeOAuthScopeUpgrade,
	consumePendingUpgradeReturnPath,
	deleteAccountData,
	enableMlsAndEnroll,
	getOrCreateBrowserDeviceId,
	getOrCreateMlsDbKey,
	initWasm,
	logout,
	persistBrowserAuth,
	probePdsSpacesSupport,
	readBrowserAuth,
	readBrowserDeviceId,
	startOAuthScopeUpgrade,
	tryRestoreSession
} from '../src/lib/wasm.ts';
import type { WorkerApi } from '../src/lib/mls-worker.ts';
import type { Remote } from 'comlink';

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

function makeSahPoolHeaderBytes(associatedPath: string): Uint8Array {
	const buf = new Uint8Array(4096);
	const encoded = new TextEncoder().encode(associatedPath);
	buf.set(encoded.subarray(0, 511), 0);
	buf[encoded.length] = 0;
	return buf;
}

function createFakeOpfsHierarchy(initial: {
	rootFiles?: string[];
	catbirdMlsFiles?: string[];
	sahPoolSlots?: Record<string, string>;
}) {
	const rootFiles = new Set(initial.rootFiles ?? []);
	const subDirFiles = new Set(initial.catbirdMlsFiles ?? []);
	const sahPoolSlots = new Map<string, Uint8Array>();
	for (const [slotName, headerPath] of Object.entries(initial.sahPoolSlots ?? {})) {
		sahPoolSlots.set(slotName, makeSahPoolHeaderBytes(headerPath));
	}

	const opaqueDir = {
		kind: 'directory',
		name: '.opaque',
		async getDirectoryHandle(): Promise<never> {
			throw new Error('NotFoundError');
		},
		async removeEntry(name: string): Promise<void> {
			if (!sahPoolSlots.delete(name)) {
				throw new Error('NotFoundError');
			}
		},
		async *entries() {
			for (const [slotName, data] of Array.from(sahPoolSlots.entries())) {
				yield [
					slotName,
					{
						kind: 'file',
						name: slotName,
						async getFile() {
							return {
								slice(start = 0, end = data.byteLength) {
									const view = data.slice(start, end);
									return {
										async arrayBuffer() {
											return view.buffer;
										}
									};
								}
							};
						}
					}
				] as const;
			}
		}
	};

	const poolDir = {
		kind: 'directory',
		name: '.opfs-sahpool',
		async getDirectoryHandle(name: string) {
			if (name === '.opaque') return opaqueDir;
			throw new Error('NotFoundError');
		},
		async removeEntry(): Promise<void> {
			throw new Error('NotFoundError');
		}
	};

	const catbirdMlsDir = {
		kind: 'directory',
		name: 'catbird-mls',
		async getDirectoryHandle(): Promise<never> {
			throw new Error('NotFoundError');
		},
		async removeEntry(name: string): Promise<void> {
			if (!subDirFiles.delete(name)) {
				throw new Error('NotFoundError');
			}
		}
	};

	const rootDir = {
		kind: 'directory',
		name: '',
		async getDirectoryHandle(name: string) {
			if (name === '.opfs-sahpool') return poolDir;
			if (name === 'catbird-mls') return catbirdMlsDir;
			throw new Error('NotFoundError');
		},
		async removeEntry(name: string): Promise<void> {
			if (!rootFiles.delete(name)) {
				throw new Error('NotFoundError');
			}
		}
	};

	return { rootDir, rootFiles, subDirFiles, sahPoolSlots };
}

describe('Multi-device DID fragment normalization, reaction folding, logout/delete cleanup, OAuth & CSP', () => {
	let fakeLocalStorage: MemoryStorage;
	let fakeSessionStorage: MemoryStorage;

	beforeEach(() => {
		fakeLocalStorage = new MemoryStorage();
		fakeSessionStorage = new MemoryStorage();
		Object.defineProperty(globalThis, 'localStorage', {
			value: fakeLocalStorage,
			configurable: true,
			writable: true
		});
		Object.defineProperty(globalThis, 'sessionStorage', {
			value: fakeSessionStorage,
			configurable: true,
			writable: true
		});
		resetKeyStoreMemoryFallbackForTests();
		__setWorkerFactoryForTests(null);
	});

	it('strips #<deviceId> for own-message alignment, profile lookup, and folds sibling-device reactions', () => {
		const aliceBare = 'did:plc:alice0001';
		const aliceDevA = 'did:plc:alice0001#11111111-1111-4111-8111-111111111111';
		const aliceDevB = 'did:plc:alice0001#22222222-2222-4222-8222-222222222222';
		const bobDev1 = 'did:plc:bob0002#33333333-3333-4333-8333-333333333333';

		assert.equal(stripDidFragment(aliceDevA), aliceBare);
		assert.equal(
			extractDidDeviceFragment(aliceDevA),
			'11111111-1111-4111-8111-111111111111'
		);
		assert.equal(isSameAccountDid(aliceDevA, aliceBare), true);
		assert.equal(isSameAccountDid(aliceDevA, aliceDevB), true);
		assert.equal(isSameAccountDid(aliceDevA, bobDev1), false);

		// Fold multi-device reactions (`did#dev-A` + `did#dev-B` -> 1 account reaction)
		const rawReactions = {
			'👍': [aliceDevA, aliceDevB, bobDev1],
			'🔥': [aliceDevB]
		};
		const folded = foldReactionsByAccount(rawReactions);
		assert.deepEqual(folded, {
			'👍': ['did:plc:alice0001', 'did:plc:bob0002'],
			'🔥': ['did:plc:alice0001']
		});
		assert.equal(hasAccountReacted(rawReactions, '👍', aliceBare), true);

		// Removing reaction from device B removes the account's reaction cleanly
		const afterRemove = applyReactionToMap(rawReactions, aliceDevB, '👍', 'remove');
		assert.deepEqual(afterRemove, {
			'👍': ['did:plc:bob0002'],
			'🔥': ['did:plc:alice0001']
		});

		// Adding reaction from device A after device B already reacted does not duplicate
		const afterDuplicateAdd = applyReactionToMap(rawReactions, aliceDevA, '🔥', 'add');
		assert.deepEqual(afterDuplicateAdd['🔥'], ['did:plc:alice0001']);

		// Group member leaf folding promotes admin role across sibling leaves
		const foldedMembers = foldGroupMembersByAccount([
			{ did: aliceDevA, handle: 'alice.bsky.social', role: 'member' },
			{ did: aliceDevB, handle: 'alice.bsky.social', role: 'admin' },
			{ did: bobDev1, handle: 'bob.bsky.social', role: 'member' }
		]);
		assert.equal(foldedMembers.length, 2);
		assert.equal(foldedMembers[0]?.did, aliceBare);
		assert.equal(foldedMembers[0]?.role, 'admin');
	});

	it('wraps SQLCipher DB keys under extractable:false WebCrypto AES-GCM and wipes deviceId + keystore + OPFS on logout()', async () => {
		const aliceDid = 'did:plc:alicewipe01';
		const bobDid = 'did:plc:bobkeep02';
		const aliceHash = await accountDidHashHex(aliceDid);
		const bobHash = await accountDidHashHex(bobDid);

		// Legacy deviceId key migrates to canonical `catmos.mls.deviceId.<didHash>`
		const legacyDeviceId = '44444444-4444-4444-8444-444444444444';
		fakeLocalStorage.setItem(`catmos_mls_device_id_${aliceHash}`, legacyDeviceId);
		const resolvedDeviceId = getOrCreateBrowserDeviceId(aliceHash);
		assert.equal(resolvedDeviceId, legacyDeviceId);
		assert.equal(fakeLocalStorage.getItem(`${BROWSER_DEVICE_ID_PREFIX}${aliceHash}`), legacyDeviceId);
		assert.equal(fakeLocalStorage.getItem(`catmos_mls_device_id_${aliceHash}`), null);

		const bobDeviceId = getOrCreateBrowserDeviceId(bobHash);
		assert.match(bobDeviceId, /^[0-9a-f-]{36}$/);

		persistBrowserAuth(aliceDid, '55555555-5555-4555-8555-555555555555');
		const dbKeyHex1 = await getOrCreateMlsDbKey(aliceDid);
		const dbKeyHex2 = await getOrCreateMlsDbKey(aliceDid);
		assert.equal(dbKeyHex1.length, 64);
		assert.equal(dbKeyHex1, dbKeyHex2);

		const aliceKek = await inspectWrappingCryptoKey(aliceHash);
		assert.ok(aliceKek, 'expected wrapping CryptoKey in keystore');
		assert.equal(aliceKek.extractable, false);

		// Ensure Bob's keystore also exists and survives Alice's logout
		await getOrCreateMlsDbKey(bobDid);
		assert.ok(await inspectWrappingCryptoKey(bobHash));

		const opfs = createFakeOpfsHierarchy({
			catbirdMlsFiles: [`${aliceHash}.db`, `${bobHash}.db`],
			sahPoolSlots: {
				slot_alice_main: `/catbird-mls/${aliceHash}.db`,
				slot_alice_journal: `/catbird-mls/${aliceHash}.db-journal`,
				slot_bob_main: `/catbird-mls/${bobHash}.db`,
				slot_unallocated: ''
			}
		});

		const callOrder: string[] = [];
		__setWorkerFactoryForTests(() => ({
			worker: {
				openUnifiedClient: async () => {
					callOrder.push('openUnifiedClient');
					return { accountDid: aliceDid, accountDidHash: aliceHash };
				},
				stopBackgroundTasks: async () => {
					callOrder.push('stopBackgroundTasks');
				},
				retireCurrentDevice: async () => {
					callOrder.push('retireCurrentDevice');
					return true;
				},
				clearContentRootKey: async () => {
					callOrder.push('clearContentRootKey');
				},
				clearAuth: async () => {
					callOrder.push('clearAuth');
				},
				closeUnifiedClient: async () => {
					callOrder.push('closeUnifiedClient');
				}
			} as unknown as Remote<WorkerApi>,
			rawWorker: {
				terminate() {
					callOrder.push('terminateWorker');
				}
			}
		}));

		setMlsOptedInForDid(aliceDid, true, fakeLocalStorage);
		await initWasm(aliceDid);

		await logout({
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			opfsRootProvider: async () => opfs.rootDir as any,
			retireTimeoutMs: 250
		});

		assert.deepEqual(callOrder, [
			'openUnifiedClient',
			'stopBackgroundTasks',
			'retireCurrentDevice',
			'clearContentRootKey',
			'clearAuth',
			'closeUnifiedClient',
			'terminateWorker'
		]);

		// Alice's deviceId, WebCrypto wrapping keys, and OPFS DB/SAHPool slots are wiped
		assert.equal(readBrowserDeviceId(aliceHash), null);
		assert.equal(fakeLocalStorage.getItem(`${BROWSER_DEVICE_ID_PREFIX}${aliceHash}`), null);
		assert.equal(await inspectWrappingCryptoKey(aliceHash), undefined);
		assert.equal(opfs.subDirFiles.has(`${aliceHash}.db`), false);
		assert.equal(opfs.sahPoolSlots.has('slot_alice_main'), false);
		assert.equal(opfs.sahPoolSlots.has('slot_alice_journal'), false);

		// Bob's deviceId, keystore, and OPFS SAHPool slot are completely untouched
		assert.equal(readBrowserDeviceId(bobHash), bobDeviceId);
		assert.ok(await inspectWrappingCryptoKey(bobHash));
		assert.equal(opfs.subDirFiles.has(`${bobHash}.db`), true);
		assert.equal(opfs.sahPoolSlots.has('slot_bob_main'), true);
		assert.equal(opfs.sahPoolSlots.has('slot_unallocated'), true);
	});

	it('bounds retireCurrentDevice on logout() and wires deleteAccountData() end-to-end', async () => {
		const did = 'did:plc:deleteuser03';
		const didHash = await accountDidHashHex(did);
		setMlsOptedInForDid(did, true, fakeLocalStorage);
		persistBrowserAuth(did, '66666666-6666-4666-8666-666666666666');
		getOrCreateBrowserDeviceId(didHash);
		await getOrCreateMlsDbKey(did);

		const opfs = createFakeOpfsHierarchy({
			sahPoolSlots: {
				slot_target: `/catbird-mls/${didHash}.db`
			}
		});

		let deleteCalled = false;
		let workerTerminated = false;
		__setWorkerFactoryForTests(() => ({
			worker: {
				openUnifiedClient: async () => ({ accountDid: did, accountDidHash: didHash }),
				deleteAccountData: async () => {
					deleteCalled = true;
					return true;
				},
				clearContentRootKey: async () => {},
				clearAuth: async () => {}
			} as unknown as Remote<WorkerApi>,
			rawWorker: {
				terminate() {
					workerTerminated = true;
				}
			}
		}));

		await deleteAccountData(did, {
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			opfsRootProvider: async () => opfs.rootDir as any,
			retireTimeoutMs: 250
		});

		assert.equal(deleteCalled, true);
		assert.equal(workerTerminated, true);
		assert.equal(isMlsOptedInForDid(did, fakeLocalStorage), false);
		assert.equal(readBrowserDeviceId(didHash), null);
		assert.equal(await inspectWrappingCryptoKey(didHash), undefined);
		assert.equal(opfs.sahPoolSlots.has('slot_target'), false);

		// Also verify bounded timeout when retireCurrentDevice hangs indefinitely
		const hungDid = 'did:plc:hunglogout04';
		const hungHash = await accountDidHashHex(hungDid);
		setMlsOptedInForDid(hungDid, true, fakeLocalStorage);
		persistBrowserAuth(hungDid, '88888888-8888-4888-8888-888888888888');
		getOrCreateBrowserDeviceId(hungHash);
		await getOrCreateMlsDbKey(hungDid);

		let hungTerminated = false;
		__setWorkerFactoryForTests(() => ({
			worker: {
				openUnifiedClient: async () => ({ accountDid: hungDid, accountDidHash: hungHash }),
				stopBackgroundTasks: async () => {},
				retireCurrentDevice: () => new Promise<boolean>(() => {}),
				clearContentRootKey: async () => {},
				clearAuth: async () => {},
				closeUnifiedClient: async () => {}
			} as unknown as Remote<WorkerApi>,
			rawWorker: {
				terminate() {
					hungTerminated = true;
				}
			}
		}));
		await initWasm(hungDid);
		const startMs = Date.now();
		await logout({ retireTimeoutMs: 40 });
		const elapsedMs = Date.now() - startMs;
		assert.ok(elapsedMs < 1000, `bounded logout took too long: ${elapsedMs}ms`);
		assert.equal(hungTerminated, true);
		assert.equal(readBrowserDeviceId(hungHash), null);
		assert.equal(await inspectWrappingCryptoKey(hungHash), undefined);
	});

	it('strictly validates catmos://oauth/callback deep links and /auth/callback web redirects', () => {
		const validUuid = '77777777-7777-4777-8777-777777777777';
		const parsedDeepLink = validateCatmosDeepLinkCallback(
			`catmos://oauth/callback?session_id=${validUuid.toUpperCase()}&state=state_token_12345`
		);
		assert.deepEqual(parsedDeepLink, {
			kind: 'session',
			sessionId: validUuid,
			state: 'state_token_12345',
			iss: undefined
		});

		const parsedWebCode = validateWebOAuthCallbackUrl(
			'https://catmos.catbird.blue/auth/callback?code=auth_code_abcdef1234&iss=https%3A%2F%2Fbsky.social',
			'https://catmos.catbird.blue'
		);
		assert.equal(parsedWebCode.kind, 'code');
		if (parsedWebCode.kind === 'code') {
			assert.equal(parsedWebCode.code, 'auth_code_abcdef1234');
		}

		// Adversarial rejections
		const invalidDeepLinks = [
			`https://oauth/callback?session_id=${validUuid}`,
			`javascript://oauth/callback?session_id=${validUuid}`,
			`catmos://evil/callback?session_id=${validUuid}`,
			`catmos://oauth:8080/callback?session_id=${validUuid}`,
			`catmos://user:pass@oauth/callback?session_id=${validUuid}`,
			`catmos://oauth/callback/../admin?session_id=${validUuid}`,
			`catmos://oauth/callback?session_id=${validUuid}#fragment`,
			`catmos://oauth/callback?session_id=${validUuid}&session_id=${validUuid}`,
			`catmos://oauth/callback?session_id=${validUuid}&unexpected=1`,
			`catmos://oauth/callback?session_id=not-a-uuid`,
			`catmos://oauth/callback?session_id=${validUuid}&error=access_denied`
		];
		for (const bad of invalidDeepLinks) {
			assert.throws(() => validateCatmosDeepLinkCallback(bad), `expected rejection for: ${bad}`);
		}

		const invalidWebCallbacks = [
			`http://catmos.catbird.blue/auth/callback?session_id=${validUuid}`,
			`https://evil.example/auth/callback?session_id=${validUuid}`,
			`https://catmos.catbird.blue/other?session_id=${validUuid}`,
			`https://catmos.catbird.blue/auth/callback?session_id=${validUuid}#leak`,
			`https://catmos.catbird.blue/auth/callback?code=<script>alert(1)</script>`
		];
		for (const bad of invalidWebCallbacks) {
			assert.throws(
				() => validateWebOAuthCallbackUrl(bad, 'https://catmos.catbird.blue'),
				`expected web callback rejection for: ${bad}`
			);
		}

		assert.throws(() => parseTauriOAuthCallbackPayload('not-a-uuid'));
		assert.deepEqual(parseTauriOAuthCallbackPayload(validUuid), {
			kind: 'session',
			sessionId: validUuid
		});
	});

	it('enforces strict CSP across SvelteKit, static/_headers, tauri.conf.json, and removes third-party font CDNs', () => {
		assert.deepEqual(CATMOS_SVELTEKIT_CSP_DIRECTIVES['script-src'], [
			'self',
			'wasm-unsafe-eval'
		]);
		assert.deepEqual(CATMOS_SVELTEKIT_CSP_DIRECTIVES['object-src'], ['none']);
		assert.deepEqual(CATMOS_SVELTEKIT_CSP_DIRECTIVES['frame-ancestors'], ['none']);
		assert.ok(CATMOS_WEB_CONNECT_ORIGINS.includes('https://chat.catbird.blue'));
		assert.ok(CATMOS_WEB_CONNECT_ORIGINS.includes('wss://chat.catbird.blue'));

		const appHtml = fs.readFileSync(path.join(CATMOS_ROOT, 'src/app.html'), 'utf8');
		assert.ok(!appHtml.includes('rsms.me'), 'src/app.html must not load third-party rsms.me CSS');

		const headersFile = fs.readFileSync(path.join(CATMOS_ROOT, 'static/_headers'), 'utf8');
		assert.ok(headersFile.includes("frame-ancestors 'none'"));
		assert.ok(headersFile.includes('X-Content-Type-Options: nosniff'));

		const tauriConf = JSON.parse(
			fs.readFileSync(path.join(CATMOS_ROOT, 'src-tauri/tauri.conf.json'), 'utf8')
		) as { app?: { security?: { csp?: string } } };
		const tauriCsp = tauriConf.app?.security?.csp ?? '';
		assert.ok(tauriCsp.includes("'wasm-unsafe-eval'"));
		assert.ok(tauriCsp.includes('https://chat.catbird.blue'));
		assert.ok(tauriCsp.includes('wss://chat.catbird.blue'));
		assert.ok(tauriCsp.includes("object-src 'none'"));
		assert.ok(tauriCsp.includes("frame-ancestors 'none'"));
		assert.ok(!tauriCsp.includes("'unsafe-eval'"));
	});

	it('normalizes DIDs per catbird-mls, fails closed on missing OAuth scopes, and runs progressive /auth/upgrade -> exchange -> commit', async () => {
		assert.equal(normalizeAccountDid('  DID:PLC:AbCdEf987#dev-1 '), 'did:plc:AbCdEf987');
		assert.equal(
			normalizeAccountDid('did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH#dev-2'),
			'did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH'
		);
		assert.equal(
			normalizeAccountDid('DID:WEB:Alice.Example.COM%3A8443#dev-3'),
			'did:web:alice.example.com%3a8443'
		);
		for (const invalidDid of ['', 'alice.bsky.social', 'did:plc:', 'did::abc', 'https://catbird.blue']) {
			assert.throws(() => normalizeAccountDid(invalidDid));
		}

		const aliceDid = 'did:plc:UpgradeUser01';
		const initialSessionId = '77777777-7777-4777-8777-777777777777';
		const candidateSessionId = '88888888-8888-4888-8888-888888888888';

		let workerOpened = false;
		__setWorkerFactoryForTests(() => {
			workerOpened = true;
			const api: Partial<WorkerApi> = {
				openUnifiedClient: async (params) => ({
					accountDid: params.accountDid,
					accountDidHash: await accountDidHashHex(params.accountDid)
				}),
				enrollUnifiedDevice: async () => ({
					mailbox_space_uri: `at:space://${aliceDid}/blue.catbird.labyrinth.mailbox/self`,
					epoch_seq: 1,
					has_recovery_code: false,
					has_passkey_prf: false,
					active_device_ids: ['99999999-9999-4999-8999-999999999999']
				}),
				startBackgroundTasks: async () => {},
				retireCurrentDevice: async () => true,
				clearContentRootKey: async () => {},
				clearAuth: async () => {},
				labyrinthStatus: async () => ({
					mailbox_space_uri: `at:space://${aliceDid}/blue.catbird.labyrinth.mailbox/self`,
					epoch_seq: 1,
					has_recovery_code: false,
					has_passkey_prf: false,
					active_device_ids: ['99999999-9999-4999-8999-999999999999']
				})
			};
			return { worker: api as unknown as Remote<WorkerApi> };
		});

		const origFetch = globalThis.fetch;
		try {
			// 1. Fresh login with base ['atproto'] scope populates grantedScopes on AuthState
			globalThis.fetch = (async (input: RequestInfo | URL) => {
				const url = String(input);
				if (url.endsWith('/auth/session')) {
					return new Response(
						JSON.stringify({
							did: aliceDid,
							handle: 'alice.bsky.social',
							created_at: '2026-11-14T00:00:00Z',
							granted_scopes: ['atproto']
						}),
						{ status: 200, headers: { 'Content-Type': 'application/json' } }
					);
				}
				if (url.endsWith('/auth/logout')) {
					return new Response(JSON.stringify({ success: true }), { status: 200 });
				}
				throw new Error(`Unexpected fetch during login: ${url}`);
			}) as typeof fetch;

			const loggedIn = await completeLogin(initialSessionId);
			assert.equal(loggedIn.did, aliceDid);
			assert.deepEqual(loggedIn.grantedScopes, ['atproto']);

			const restored = await tryRestoreSession();
			assert.deepEqual(restored?.grantedScopes, ['atproto']);

			// 2. Fail-closed enableMlsAndEnroll when called with defaults or missing scopes (zero worker/DB opens)
			await assert.rejects(() => enableMlsAndEnroll(aliceDid), /PDS|Spaces/i);
			await assert.rejects(
				() => enableMlsAndEnroll(aliceDid, true, loggedIn.grantedScopes ?? []),
				/Grant required OAuth scopes/i
			);
			assert.equal(workerOpened, false, 'must not open MLS worker when I15 gate rejects');
			assert.equal(isMlsOptedInForDid(aliceDid), false);

			// 3. PDS Spaces capability probe fails closed on 404/XRPCNotSupported and succeeds on 400 InvalidRequest
			assert.equal(
				await probePdsSpacesSupport(async () =>
					new Response(JSON.stringify({ error: 'XRPCNotSupported' }), { status: 501 })
				),
				false
			);
			assert.equal(
				await probePdsSpacesSupport(async () =>
					new Response(JSON.stringify({ error: 'InvalidRequest' }), { status: 400 })
				),
				true
			);

			// 4. Progressive OAuth upgrade (/auth/upgrade -> /oauth/permission-callback -> exchange -> commit -> session)
			let capturedAdditionalScopes: string[] = [];
			let capturedStartNonce = '';
			let commitAttempts = 0;
			let navigatedTo = '';

			const mockUpgradeFetch: typeof fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
				const url = String(input);
				const headers = new Headers(init?.headers ?? {});
				if (url.endsWith('/auth/upgrade')) {
					assert.equal(headers.get('Authorization'), `Bearer ${initialSessionId}`);
					const body = JSON.parse(String(init?.body ?? '{}')) as {
						additional_scopes: string[];
						browser_nonce: string;
					};
					capturedAdditionalScopes = body.additional_scopes;
					capturedStartNonce = body.browser_nonce;
					return new Response(
						JSON.stringify({
							authorization_url: 'https://bsky.social/oauth/authorize?request_uri=urn:ietf:params:oauth:request_uri:test123'
						}),
						{ status: 200, headers: { 'Content-Type': 'application/json' } }
					);
				}
				if (url.endsWith('/auth/upgrade/exchange')) {
					assert.equal(headers.get('Authorization'), `Bearer ${initialSessionId}`);
					const body = JSON.parse(String(init?.body ?? '{}')) as {
						code: string;
						browser_nonce: string;
					};
					assert.equal(body.code, 'upgrade_code_12345678');
					assert.equal(body.browser_nonce, capturedStartNonce);
					return new Response(
						JSON.stringify({
							candidate_session_id: candidateSessionId,
							did: aliceDid,
							granted_scopes: [...REQUIRED_LABYRINTH_OAUTH_SCOPES]
						}),
						{ status: 200, headers: { 'Content-Type': 'application/json' } }
					);
				}
				if (url.endsWith('/auth/upgrade/commit')) {
					assert.equal(headers.get('Authorization'), `Bearer ${candidateSessionId}`);
					commitAttempts += 1;
					if (commitAttempts === 1) {
						return new Response('Retryable push CAS failure', { status: 500 });
					}
					return new Response(
						JSON.stringify({
							status: 'committed',
							session_id: candidateSessionId,
							did: aliceDid,
							granted_scopes: [...REQUIRED_LABYRINTH_OAUTH_SCOPES]
						}),
						{ status: 200, headers: { 'Content-Type': 'application/json' } }
					);
				}
				if (url.endsWith('/auth/session')) {
					assert.equal(headers.get('Authorization'), `Bearer ${candidateSessionId}`);
					return new Response(
						JSON.stringify({
							did: aliceDid,
							handle: 'alice.bsky.social',
							created_at: '2026-11-14T00:01:00Z',
							granted_scopes: [...REQUIRED_LABYRINTH_OAUTH_SCOPES]
						}),
						{ status: 200, headers: { 'Content-Type': 'application/json' } }
					);
				}
				throw new Error(`Unexpected URL in upgrade flow: ${url}`);
			}) as typeof fetch;

			const authUrl = await startOAuthScopeUpgrade(REQUIRED_LABYRINTH_OAUTH_SCOPES, {
				returnTo: '/settings/labyrinth',
				fetchImpl: mockUpgradeFetch,
				navigate: (url) => {
					navigatedTo = url;
				}
			});
			assert.match(authUrl, /^https:\/\/bsky\.social\/oauth\/authorize/);
			assert.equal(navigatedTo, authUrl);
			assert.ok(!capturedAdditionalScopes.includes('atproto'));
			assert.ok(capturedAdditionalScopes.includes('repo:blue.catbird.labyrinth.mailboxKeys'));
			assert.ok(
				!capturedAdditionalScopes.includes(
					'repo:blue.catbird.labyrinth.mailboxKeys?action=create'
				)
			);

			const permCb = validateWebPermissionCallbackUrl(
				'https://catbird.blue/oauth/permission-callback?code=upgrade_code_12345678',
				'https://catbird.blue'
			);
			assert.equal(permCb.kind, 'code');
			if (permCb.kind !== 'code') throw new Error('expected code');

			const upgradedUser = await completeOAuthScopeUpgrade(permCb.code, {
				fetchImpl: mockUpgradeFetch
			});
			assert.equal(commitAttempts, 2, 'must retry once on transient 500 from /auth/upgrade/commit');
			assert.equal(readBrowserAuth()?.sessionId, candidateSessionId);
			assert.equal(consumePendingUpgradeReturnPath(), '/settings/labyrinth');
			assert.deepEqual(upgradedUser.grantedScopes, [...REQUIRED_LABYRINTH_OAUTH_SCOPES]);

			const enrolledStatus = await enableMlsAndEnroll(
				aliceDid,
				true,
				upgradedUser.grantedScopes ?? []
			);
			assert.equal(workerOpened, true);
			assert.equal(enrolledStatus.epoch_seq, 1);
			assert.equal(isMlsOptedInForDid(aliceDid), true);
			await logout();
		} finally {
			globalThis.fetch = origFetch;
		}
	});
});

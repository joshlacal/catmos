/**
 * catmos WASM bridge — Unified API surface for Tauri desktop and browser WASM.
 *
 * Detects runtime environment via `__TAURI_INTERNALS__` on window.
 * - Tauri desktop: routes calls through `@tauri-apps/api/core` invoke()
 * - Browser: routes calls through a Web Worker (comlink) so that WASM gets
 *   OPFS Synchronous Access Handle for MLS SQLite crypto.
 *
 * Session credentials (did, token) and MLS DB key all live in sessionStorage
 * on the main thread (cleared on tab close to limit XSS exposure).
 * Credential keys are namespaced by DID to prevent data leakage when multiple
 * users log in on the same browser. The Worker receives them via explicit
 * setAuth / init calls.
 */

// Re-export all types from tauri.ts (canonical type definitions)
export type {
	Conversation,
	Message,
	ImageAttachment,
	AudioAttachment,
	PreparedImageUpload,
	ReactionEvent,
	TypingEvent,
	GroupResetEvent,
	AuthState,
	GroupMember,
	ProfileView,
	SearchResult,
	SearchHit,
	OptInStatus,
	GroupMetadataView,
	QuarantineReasonTag,
	QuarantineExitTag,
	QuarantineEnteredEvent,
	QuarantineClearedEvent,
	QuarantineState
} from './tauri';

import type {
	Conversation,
	Message,
	ImageAttachment,
	AudioAttachment,
	PreparedImageUpload,
	AuthState,
	GroupMember,
	ProfileView,
	SearchResult,
	SearchHit,
	OptInStatus,
	GroupMetadataView
} from './tauri';

import { wrap, proxy, type Remote } from 'comlink';
import type { WorkerApi } from './mls-worker';
import {
	accountDidHashHex,
	loadOrCreateDbKeyHex,
	loadOrCreateWrappedSecretBytes
} from './webcrypto-keystore';
import {
	isMlsOptedInForDid,
	REQUIRED_LABYRINTH_OAUTH_SCOPES,
	setMlsOptedInForDid
} from './labyrinth-ui';

// ---------------------------------------------------------------------------
// Environment detection
// ---------------------------------------------------------------------------

declare global {
	interface Window {
		__TAURI_INTERNALS__?: unknown;
	}
}

/**
 * True when running inside Tauri desktop shell.
 * Evaluated once at module load — safe because SSR is disabled (`ssr = false`).
 */
export const isTauri: boolean =
	typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;

// ---------------------------------------------------------------------------
// Backend loaders (lazy, cached)
// ---------------------------------------------------------------------------

/** Lazily import Tauri invoke — only pulled in when running in Tauri. */
async function tauriInvoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
	const { invoke } = await import('@tauri-apps/api/core');
	return invoke<T>(cmd, args);
}

// ---------------------------------------------------------------------------
// Worker singleton (browser mode)
// ---------------------------------------------------------------------------

let _worker: Remote<WorkerApi> | null = null;
let _rawWorker: { terminate(): void } | null = null;
let _workerDid: string | null = null;
let _wasmReady: Promise<void> | null = null;
let _workerFactory: (() => { worker: Remote<WorkerApi>; rawWorker?: { terminate(): void } }) | null = null;

/** Test-only hook allowing Node lifecycle tests to supply a Worker harness. */
export function __setWorkerFactoryForTests(
	factory: (() => { worker: Remote<WorkerApi>; rawWorker?: { terminate(): void } }) | null
): void {
	_workerFactory = factory;
}

/** Test-only hook returning the active worker DID and readiness state. */
export function __getWorkerStateForTests(): {
	hasWorker: boolean;
	workerDid: string | null;
	hasWasmReady: boolean;
} {
	return {
		hasWorker: _worker !== null,
		workerDid: _workerDid,
		hasWasmReady: _wasmReady !== null
	};
}

function terminateWorkerInstance(): void {
	if (_rawWorker) {
		try {
			_rawWorker.terminate();
		} catch (e) {
			console.warn('[catmos] Worker termination notice:', e);
		}
		_rawWorker = null;
	}
	_worker = null;
	_workerDid = null;
	_wasmReady = null;
}

function getWorker(): Remote<WorkerApi> {
	if (!_worker) {
		if (_workerFactory) {
			const created = _workerFactory();
			_worker = created.worker;
			_rawWorker = created.rawWorker ?? { terminate() {} };
		} else {
			const raw = new Worker(new URL('./mls-worker.ts', import.meta.url), { type: 'module' });
			_rawWorker = raw;
			_worker = wrap<WorkerApi>(raw);
		}
	}
	return _worker;
}

// ---------------------------------------------------------------------------
// MLS DB key management: Durable WebCrypto key wrapping with IndexedDB
//
// The 32-byte (256-bit) MLS DB encryption key encrypts SQLite state in OPFS.
// To ensure encrypted OPFS databases persist across tab and session restarts
// without stranding ciphertext:
//   - A non-extractable AES-GCM (256-bit) master Key Encryption Key (KEK) is
//     persisted in IndexedDB ('catbird_mls_keyring', store 'keys').
//   - Each per-DID MLS DB key is wrapped (encrypted with the KEK + 96-bit IV)
//     and durably stored in IndexedDB under `mls_db_key_<sanitized_did>`.
//   - Keyring writes resolve ONLY on `tx.oncomplete` and use atomic
//     insert-if-absent (`idbPutIfAbsent`) + readback inside an exclusive Web
//     Lock (`catmos_mls_keyring_lock`) so concurrent tabs can never clobber
//     either the master KEK or a per-DID wrapped key.
//   - Key restoration failures (IDB open/read/write error, transaction abort,
//     corrupt record shape, or AES-GCM authentication failure) fail closed and
//     NEVER generate an unretained session-only key.
// ---------------------------------------------------------------------------

export const KEYRING_DB_NAME = 'catbird_mls_keyring';
export const KEYRING_STORE_NAME = 'keys';
export const MASTER_KEK_ID = '__mls_master_kek__';
export const KEYRING_LOCK_NAME = 'catmos_mls_keyring_lock';

export interface WrappedKeyRecord {
	iv: Uint8Array;
	ciphertext: Uint8Array;
}

/** Sanitize a DID for deterministic storage keys and database filenames. */
export function sanitizeDid(did: string): string {
	const trimmed = (did ?? '').trim();
	if (!trimmed) {
		throw new Error('Cannot derive MLS storage identity from an empty DID');
	}
	return trimmed.replace(/[:.]/g, '_');
}

/** Return the per-DID `dbPrefix` (`catbird_mls_<sanitized_did>`). */
export function mlsDbPrefixForDid(did: string): string {
	return `catbird_mls_${sanitizeDid(did)}`;
}

/** Return the per-DID SQLite database filename (`catbird_mls_<sanitized_did>-app.db`). */
export function mlsDbFileNameForDid(did: string): string {
	return `${mlsDbPrefixForDid(did)}-app.db`;
}

/** Return the per-DID keyring key ID (`mls_db_key_<sanitized_did>`). */
export function mlsKeyIdForDid(did: string): string {
	return `mls_db_key_${sanitizeDid(did)}`;
}

async function withKeyringLock<T>(fn: () => Promise<T>): Promise<T> {
	if (
		typeof navigator !== 'undefined' &&
		navigator.locks &&
		typeof navigator.locks.request === 'function'
	) {
		return navigator.locks.request(KEYRING_LOCK_NAME, { mode: 'exclusive' }, async () => fn());
	}
	return fn();
}

export function openKeyringDb(): Promise<IDBDatabase> {
	return new Promise((resolve, reject) => {
		if (typeof indexedDB === 'undefined') {
			return reject(new Error('IndexedDB unavailable'));
		}
		const req = indexedDB.open(KEYRING_DB_NAME, 1);
		req.onupgradeneeded = () => {
			const db = req.result;
			if (!db.objectStoreNames.contains(KEYRING_STORE_NAME)) {
				db.createObjectStore(KEYRING_STORE_NAME);
			}
		};
		req.onsuccess = () => resolve(req.result);
		req.onerror = () => reject(req.error || new Error('Failed to open IndexedDB keyring'));
		req.onblocked = () => reject(new Error('IndexedDB keyring open blocked'));
	});
}

export function idbGet<T>(db: IDBDatabase, key: string): Promise<T | undefined> {
	return new Promise((resolve, reject) => {
		let settled = false;
		let result: T | undefined = undefined;
		let hasResult = false;
		const fail = (err: unknown) => {
			if (settled) return;
			settled = true;
			reject(err instanceof Error ? err : new Error(String(err || `Failed to get key: ${key}`)));
		};

		let tx: IDBTransaction;
		try {
			tx = db.transaction(KEYRING_STORE_NAME, 'readonly');
		} catch (err) {
			fail(err);
			return;
		}

		const store = tx.objectStore(KEYRING_STORE_NAME);
		const req = store.get(key);
		req.onsuccess = () => {
			result = req.result as T | undefined;
			hasResult = true;
		};
		req.onerror = () => fail(req.error || new Error(`Failed to get key: ${key}`));
		tx.onabort = () =>
			fail(tx.error || req.error || new Error(`IndexedDB read transaction aborted for key: ${key}`));
		tx.onerror = () =>
			fail(tx.error || req.error || new Error(`IndexedDB read transaction error for key: ${key}`));
		tx.oncomplete = () => {
			if (settled) return;
			if (!hasResult) {
				fail(new Error(`IndexedDB read transaction completed without result for key: ${key}`));
				return;
			}
			settled = true;
			resolve(result);
		};
	});
}

export function idbPut(db: IDBDatabase, key: string, value: unknown): Promise<void> {
	return new Promise((resolve, reject) => {
		let settled = false;
		let requestSucceeded = false;
		const fail = (err: unknown) => {
			if (settled) return;
			settled = true;
			reject(err instanceof Error ? err : new Error(String(err || `Failed to put key: ${key}`)));
		};

		let tx: IDBTransaction;
		try {
			tx = db.transaction(KEYRING_STORE_NAME, 'readwrite');
		} catch (err) {
			fail(err);
			return;
		}

		const store = tx.objectStore(KEYRING_STORE_NAME);
		const req = store.put(value, key);
		req.onsuccess = () => {
			requestSucceeded = true;
		};
		req.onerror = () => fail(req.error || new Error(`Failed to put key: ${key}`));
		tx.onabort = () =>
			fail(tx.error || req.error || new Error(`IndexedDB write transaction aborted for key: ${key}`));
		tx.onerror = () =>
			fail(tx.error || req.error || new Error(`IndexedDB write transaction error for key: ${key}`));
		tx.oncomplete = () => {
			if (settled) return;
			if (!requestSucceeded) {
				fail(new Error(`IndexedDB write transaction completed before request succeeded for key: ${key}`));
				return;
			}
			settled = true;
			resolve();
		};
	});
}

/**
 * Atomically insert `value` under `key` only if `key` is currently absent in a
 * single `readwrite` transaction, waiting for `tx.oncomplete`, and then reading
 * back the committed record. Never overwrites an existing key.
 */
export async function idbPutIfAbsent<T>(
	db: IDBDatabase,
	key: string,
	value: T
): Promise<{ value: T; inserted: boolean }> {
	const inserted = await new Promise<boolean>((resolve, reject) => {
		let settled = false;
		let didInsert = false;
		let opDone = false;
		const fail = (err: unknown) => {
			if (settled) return;
			settled = true;
			reject(
				err instanceof Error
					? err
					: new Error(String(err || `Failed atomic insert-if-absent for key: ${key}`))
			);
		};

		let tx: IDBTransaction;
		try {
			tx = db.transaction(KEYRING_STORE_NAME, 'readwrite');
		} catch (err) {
			fail(err);
			return;
		}

		const store = tx.objectStore(KEYRING_STORE_NAME);
		const getReq = store.get(key);
		getReq.onerror = () => fail(getReq.error || new Error(`Failed to inspect key: ${key}`));
		getReq.onsuccess = () => {
			if (getReq.result !== undefined) {
				didInsert = false;
				opDone = true;
				return;
			}
			const addReq = store.add(value, key);
			addReq.onsuccess = () => {
				didInsert = true;
				opDone = true;
			};
			addReq.onerror = () => fail(addReq.error || new Error(`Failed to add key: ${key}`));
		};

		tx.onabort = () =>
			fail(
				tx.error ||
					getReq.error ||
					new Error(`IndexedDB atomic transaction aborted for key: ${key}`)
			);
		tx.onerror = () =>
			fail(
				tx.error ||
					getReq.error ||
					new Error(`IndexedDB atomic transaction error for key: ${key}`)
			);
		tx.oncomplete = () => {
			if (settled) return;
			if (!opDone) {
				fail(new Error(`IndexedDB atomic transaction completed before operation finished for key: ${key}`));
				return;
			}
			settled = true;
			resolve(didInsert);
		};
	});

	const committed = await idbGet<T>(db, key);
	if (committed === undefined) {
		throw new Error(`IndexedDB readback after commit returned undefined for key: ${key}`);
	}
	return { value: committed, inserted };
}

function isValidCryptoKey(value: unknown): value is CryptoKey {
	return (
		typeof value === 'object' &&
		value !== null &&
		'type' in value &&
		'extractable' in value &&
		'algorithm' in value &&
		'usages' in value
	);
}

function toUint8Array(input: unknown): Uint8Array | null {
	if (input instanceof Uint8Array) {
		return input;
	}
	if (input instanceof ArrayBuffer) {
		return new Uint8Array(input);
	}
	if (ArrayBuffer.isView(input)) {
		return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
	}
	return null;
}

function parseValidatedWrappedRecord(record: unknown, keyId: string): WrappedKeyRecord {
	if (typeof record !== 'object' || record === null) {
		throw new Error(`Corrupt wrapped key record for ${keyId}: expected object`);
	}
	const candidate = record as Record<string, unknown>;
	const iv = toUint8Array(candidate.iv);
	const ciphertext = toUint8Array(candidate.ciphertext);
	if (!iv || iv.byteLength !== 12) {
		throw new Error(`Corrupt wrapped key record for ${keyId}: invalid 12-byte AES-GCM IV`);
	}
	if (!ciphertext || ciphertext.byteLength !== 48) {
		throw new Error(
			`Corrupt wrapped key record for ${keyId}: invalid AES-GCM ciphertext length (${ciphertext?.byteLength ?? 0})`
		);
	}
	return {
		iv: new Uint8Array(iv),
		ciphertext: new Uint8Array(ciphertext)
	};
}

async function getOrCreateMasterKek(db: IDBDatabase): Promise<CryptoKey> {
	const existing = await idbGet<unknown>(db, MASTER_KEK_ID);
	if (existing !== undefined) {
		if (!isValidCryptoKey(existing)) {
			throw new Error('Corrupt master KEK record in IndexedDB keyring');
		}
		return existing;
	}

	const candidateKek = await crypto.subtle.generateKey(
		{ name: 'AES-GCM', length: 256 },
		false, // non-extractable master key encryption key
		['encrypt', 'decrypt']
	);
	const { value: committedKek } = await idbPutIfAbsent<CryptoKey>(db, MASTER_KEK_ID, candidateKek);
	if (!isValidCryptoKey(committedKek)) {
		throw new Error('Corrupt committed master KEK record in IndexedDB keyring');
	}
	return committedKek;
}

/**
 * Get or create the per-DID MLS DB encryption key with durable IndexedDB/WebCrypto
 * key wrapping.
 *
 * Distinguishes key absence (`wrapped === undefined` on a healthy transaction)
 * from key restoration or persistence failures (IndexedDB open/read/write error,
 * transaction abort, corrupt record shape, or AES-GCM authentication error).
 * Any failure throws and NEVER falls back to an unpersisted session key.
 */
export async function getOrCreateMlsDbKey(targetDid?: string): Promise<string> {
	const resolvedDid = (
		targetDid ??
		(typeof sessionStorage !== 'undefined' ? sessionStorage.getItem(SS_ACTIVE_DID) : null) ??
		''
	).trim();
	if (!resolvedDid) {
		throw new Error('getOrCreateMlsDbKey requires a valid authenticated DID');
	}

	const keyId = mlsKeyIdForDid(resolvedDid);
	const legacySessionKey = didKey(resolvedDid, 'mls_db_key');
	if (typeof sessionStorage !== 'undefined') {
		sessionStorage.removeItem(keyId);
		sessionStorage.removeItem(legacySessionKey);
	}

	return withKeyringLock(async () => {
		const db = await openKeyringDb();
		try {
			const kek = await getOrCreateMasterKek(db);
			let wrappedRaw = await idbGet<unknown>(db, keyId);

			if (wrappedRaw === undefined) {
				const rawBytes = new Uint8Array(32);
				crypto.getRandomValues(rawBytes);

				const iv = new Uint8Array(12);
				crypto.getRandomValues(iv);
				const ciphertextBuffer = await crypto.subtle.encrypt(
					{ name: 'AES-GCM', iv: iv as BufferSource },
					kek,
					rawBytes as BufferSource
				);
				const candidateWrapped: WrappedKeyRecord = {
					iv,
					ciphertext: new Uint8Array(ciphertextBuffer)
				};

				const { value: committedWrapped } = await idbPutIfAbsent<WrappedKeyRecord>(
					db,
					keyId,
					candidateWrapped
				);
				wrappedRaw = committedWrapped;
			}

			const wrapped = parseValidatedWrappedRecord(wrappedRaw, keyId);
			let decrypted: ArrayBuffer;
			try {
				decrypted = await crypto.subtle.decrypt(
					{ name: 'AES-GCM', iv: wrapped.iv as BufferSource },
					kek,
					wrapped.ciphertext as BufferSource
				);
			} catch (err) {
				throw new Error(
					`Failed to unwrap durable MLS DB key for ${keyId} (AES-GCM authentication failed): ${
						err instanceof Error ? err.message : String(err)
					}`
				);
			}

			const rawBytes = new Uint8Array(decrypted);
			if (rawBytes.byteLength !== 32) {
				throw new Error(
					`Unwrapped MLS DB key for ${keyId} has invalid length: ${rawBytes.byteLength}`
				);
			}

			return Array.from(rawBytes)
				.map((b) => b.toString(16).padStart(2, '0'))
				.join('');
		} finally {
			try {
				db.close();
			} catch {
				// Ignore close errors
			}
		}
	});
}

// ---------------------------------------------------------------------------
// MLS field-level encryption: per-DID content root key (WebCrypto IndexedDB)
//
// Wrapped under the non-extractable AES-GCM CryptoKey in `webcrypto-keystore.ts`
// (`Gate 9` — zero keys in `localStorage` or `sessionStorage`).
// ---------------------------------------------------------------------------

async function loadOrCreateContentRootKey(userDid: string): Promise<Uint8Array> {
	const didHash = await accountDidHashHex(userDid);
	return loadOrCreateWrappedSecretBytes(didHash, 'content');
}

/**
 * Push the per-DID content root key into the WASM module. Called once per
 * session after `setAuth` resolves so that subsequent `setup()` and any
 * message encrypt/decrypt has the key bound.
 *
 * Propagates errors on failure to enforce fail-closed security (no legacy
 * plaintext fallback).
 */
async function installContentRootKey(did: string): Promise<void> {
	const key = await loadOrCreateContentRootKey(did);
	const w = getWorker();
	await (
		w as unknown as { setContentRootKey: (k: Uint8Array) => Promise<void> }
	).setContentRootKey(key);
}

// ---------------------------------------------------------------------------
// Nest BFF URL
// ---------------------------------------------------------------------------

/** Nest BFF gateway URL — resolve from current hostname. */
const NEST_URL = (() => {
	if (typeof window === 'undefined') return 'https://api.catbird.blue';
	const { hostname } = window.location;
	if (hostname === 'catmos.catbird.blue') return 'https://api.catbird.blue';
	// Cloudflare Pages previews and localhost use dev API
	return 'https://api.catbird.blue';
})();

export async function bffFetch(
	path: string,
	init: RequestInit = {},
	sessionId?: string
): Promise<Response> {
	const headers = new Headers(init.headers ?? {});
	if (sessionId) {
		headers.set('Authorization', `Bearer ${sessionId}`);
	}
	return fetch(`${NEST_URL}${path}`, {
		...init,
		headers
	});
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

/**
 * Initialize the WASM Worker with per-DID MLS config.
 *
 * Requires a non-empty authenticated `did` — never opens a generic
 * `catbird-mls-app.db` with a generic key. If a Worker was already running for
 * a different DID, terminates it and reinitializes for `did` so the Worker
 * opens `catbird_mls_<sanitized_did>-app.db` with `mls_db_key_<sanitized_did>`.
 */
export async function initWasm(did?: string): Promise<void> {
	if (isTauri) return;

	const resolvedDid = (
		did ??
		(typeof sessionStorage !== 'undefined' ? sessionStorage.getItem(SS_ACTIVE_DID) : null) ??
		''
	).trim();
	if (!resolvedDid) {
		throw new Error(
			'initWasm requires a non-empty authenticated DID; refusing to open generic un-namespaced storage'
		);
	}

	if (_workerDid && _workerDid !== resolvedDid) {
		terminateWorkerInstance();
	}

	if (_worker && _workerDid === resolvedDid && _wasmReady) {
		return _wasmReady;
	}

	const runInit = (async () => {
		try {
			const mlsDbKey = await getOrCreateMlsDbKey(resolvedDid);
			const dbPrefix = mlsDbPrefixForDid(resolvedDid);
			const w = getWorker();
			await w.init({ baseUrl: NEST_URL, mlsDbKey, dbPrefix });
			_workerDid = resolvedDid;
		} catch (err) {
			terminateWorkerInstance();
			throw err;
		}
	})();

	_wasmReady = runInit;
	return runInit;
}

// ---------------------------------------------------------------------------
// Event listeners (Tauri IPC events on desktop, no-op in browser)
// ---------------------------------------------------------------------------

export async function listenForEvent<T>(
	event: string,
	handler: (payload: T) => void
): Promise<() => void> {
	if (isTauri) {
		const { listen } = await import('@tauri-apps/api/event');
		return listen<T>(event, (e) => handler(e.payload));
	}
	return () => {};
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Browser session storage helpers (per-DID namespace isolation)
// ---------------------------------------------------------------------------

/** Base keys -- the DID key is unnamespaced (bootstrap). */
const SS_ACTIVE_DID = 'catbird_mls_active_did';
const SS_PENDING_BROWSER_NONCE = 'catbird_mls_pending_browser_nonce';

/** Generate a cryptographically secure 32-byte unpadded base64url challenge nonce (43 chars). */
export function generateBrowserNonce(): string {
	const bytes = new Uint8Array(32);
	crypto.getRandomValues(bytes);
	let binary = '';
	for (let i = 0; i < bytes.length; i++) {
		binary += String.fromCharCode(bytes[i]);
	}
	return btoa(binary)
		.replace(/\+/g, '-')
		.replace(/\//g, '_')
		.replace(/=+$/, '');
}

/** Clear any pending browser OAuth nonce from sessionStorage. */
export function clearPendingOAuthLogin(): void {
	sessionStorage.removeItem(SS_PENDING_BROWSER_NONCE);
}

/** Return a per-DID namespaced key for browser sessionStorage. */
function didKey(did: string, suffix: string): string {
	return `catbird_mls:${did}:${suffix}`;
}

/** Persist auth credentials in sessionStorage, namespaced by DID. */
export function persistBrowserAuth(did: string, sessionId: string): void {
	sessionStorage.setItem(SS_ACTIVE_DID, did);
	sessionStorage.setItem(didKey(did, 'session_id'), sessionId);
}

/** Read stored session for the active DID. Returns null if nothing saved. */
export function readBrowserAuth(): { did: string; sessionId: string } | null {
	if (typeof sessionStorage === 'undefined') return null;
	const did = sessionStorage.getItem(SS_ACTIVE_DID);
	if (!did) return null;
	const sessionId = sessionStorage.getItem(didKey(did, 'session_id'));
	if (!sessionId) return null;
	return { did, sessionId };
}

/** Clear the active DID's credentials from sessionStorage. */
export function clearBrowserAuth(): void {
	if (typeof sessionStorage === 'undefined') return;
	const did = sessionStorage.getItem(SS_ACTIVE_DID);
	if (did) {
		sessionStorage.removeItem(didKey(did, 'session_id'));
	}
	sessionStorage.removeItem(SS_ACTIVE_DID);
}

export async function startLogin(identifier: string): Promise<void> {
	if (isTauri) {
		return tauriInvoke('start_login', { identifier });
	}
	const redirectTo = `${window.location.origin}/auth/callback`;
	const browserNonce = generateBrowserNonce();
	sessionStorage.setItem(SS_PENDING_BROWSER_NONCE, browserNonce);

	const loginUrl =
		`${NEST_URL}/auth/login` +
		`?identifier=${encodeURIComponent(identifier)}` +
		`&client=catmos` +
		`&redirect_to=${encodeURIComponent(redirectTo)}` +
		`&browser_nonce=${encodeURIComponent(browserNonce)}`;
	window.location.href = loginUrl;
}

/**
 * Exchange a one-time OAuth code for a session ID using the single-use browser nonce.
 * Consumes and clears the pending nonce immediately upon attempt.
 */
export async function exchangeOAuthCode(code: string): Promise<string> {
	const browserNonce = sessionStorage.getItem(SS_PENDING_BROWSER_NONCE);
	// Single-use: clear pending nonce immediately
	clearPendingOAuthLogin();

	if (!browserNonce) {
		throw new Error('Missing or expired browser login nonce. Please try signing in again.');
	}

	const resp = await fetch(`${NEST_URL}/auth/exchange`, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json'
		},
		body: JSON.stringify({
			code,
			browser_nonce: browserNonce
		})
	});

	if (!resp.ok) {
		const errText = await resp.text().catch(() => '');
		throw new Error(`Authentication exchange failed (${resp.status}): ${errText || resp.statusText}`);
	}

	const data = await resp.json();
	if (!data || typeof data.session_id !== 'string' || !data.session_id.trim()) {
		throw new Error('Invalid exchange response from auth gateway: missing session_id');
	}

	return data.session_id;
}

export async function completeLogin(sessionId: string): Promise<AuthState> {
	if (isTauri) {
		return tauriInvoke('complete_login', { sessionId });
	}
	const resp = await bffFetch('/auth/session', { method: 'GET' }, sessionId);
	if (!resp.ok) throw new Error(`Failed to fetch session: ${resp.status}`);
	const info = await resp.json();
	const did: string = typeof info?.did === 'string' ? info.did.trim() : '';
	if (!did) {
		throw new Error('Invalid session response from auth gateway: missing did');
	}
	const handle: string = info.handle ?? did;

	try {
		// 1. Persist browser auth first so active DID is established
		persistBrowserAuth(did, sessionId);
		// ctl #2: Chat/Spaces off by default — zero MLS DB opens, PDS/DS calls, or KeyPackage uploads on fresh sign-in
		if (!isMlsOptedInForDid(did)) {
			return { did, handle };
		}
		// 2. Initialize WASM Worker for `did` (terminating any Worker bound to a different DID)
		await initWasm(did);
		// 3. Push credentials and complete MLS setup on the DID-scoped Worker
		const w = getWorker();
		await w.setAuth(did, sessionId);
		await installContentRootKey(did);
		await w.setup();

		replenishKeyPackages();
		startKeyPackageReplenishment();

		return { did, handle };
	} catch (error) {
		if (_replenishInterval) {
			clearInterval(_replenishInterval);
			_replenishInterval = null;
		}
		clearBrowserAuth();
		try {
			if (_worker) {
				try {
					await (
						_worker as unknown as { clearContentRootKey: () => Promise<void> }
					).clearContentRootKey();
				} catch (e) {
					console.warn('[catmos] clearContentRootKey failed during activation rollback:', e);
				}
				await _worker.clearAuth();
			}
		} finally {
			terminateWorkerInstance();
		}
		throw error;
	}
}
/**
 * Set auth credentials for the WASM MLS module.
 * Called by catmos's auth store after completing OAuth.
 */
export async function setAuth(did: string, token: string): Promise<void> {
	if (isTauri) return;
	try {
		persistBrowserAuth(did, token);
		await initWasm(did);
		const w = getWorker();
		await w.setAuth(did, token);
		// Install the per-DID content root key after auth so the field-level
		// encryption layer is bound before any subsequent message flow.
		await installContentRootKey(did);
	} catch (error) {
		clearBrowserAuth();
		try {
			if (_worker) {
				try {
					await (
						_worker as unknown as { clearContentRootKey: () => Promise<void> }
					).clearContentRootKey();
				} catch (e) {
					console.warn('[catmos] clearContentRootKey failed during setAuth rollback:', e);
				}
				await _worker.clearAuth();
			}
		} finally {
			terminateWorkerInstance();
		}
		throw error;
	}
}

/** Run one deferred reset/history recovery pass in the browser worker. */
export async function runDeferredRecovery(): Promise<unknown> {
	if (isTauri) throw new Error('deferred recovery is owned by the Tauri orchestrator');
	const w = getWorker();
	return w.runDeferredRecovery();
}

/** Start the crate-owned browser recovery timer after setup/auth. */
export async function startBackgroundRecovery(intervalMs = 30_000): Promise<void> {
	if (isTauri) return;
	const w = getWorker();
	await w.startBackgroundTasks(intervalMs);
}

/** Stop the crate-owned browser recovery timer before logout/tenant switch. */
export async function stopBackgroundRecovery(): Promise<void> {
	if (isTauri) return;
	const w = getWorker();
	await w.stopBackgroundTasks();
}

/**
 * Install a browser-owned non-exporting Ed25519 signer for canonical chat
 * preparation. The CryptoKey is passed to the worker as a structured-clone
 * handle and never converted to private key bytes. WASM receives only the
 * public binding and a callback that returns a 64-byte signature.
 */
export async function installBrowserSigner(params: {
	actorDid: string;
	deviceId: string;
	dpopJkt: string;
	publicKey: Uint8Array;
	key: CryptoKey;
	authGeneration?: number;
}): Promise<void> {
	if (isTauri) {
		throw new Error('browser signer is unsupported in Tauri runtime');
	}
	const w = getWorker();
	await w.setSignerBridge(
		params.actorDid,
		params.deviceId,
		params.dpopJkt,
		params.publicKey,
		params.key,
		params.authGeneration
	);
}

/** Prepare an unsigned generated clean-chat request without returning auth. */
export async function prepareUnsignedRequest(
	operation: string,
	requestJson: string
): Promise<unknown> {
	if (isTauri) throw new Error('browser unsigned preparation is unsupported in Tauri runtime');
	return getWorker().prepareUnsignedRequest(operation, requestJson);
}

export interface PreparedGatewayRequest {
	operation: string;
	method: string;
	path: string;
	body?: string;
}

export interface GatewayResponse {
	status: number;
	contentType?: string | null;
	body: string;
}

/** Prepare a signed generated clean-chat request through the worker WASM. */
export async function prepareSignedRequest(
	operation: string,
	requestJson: string
): Promise<unknown> {
	if (isTauri) throw new Error('browser signed preparation is unsupported in Tauri runtime');
	return getWorker().prepareSignedRequest(operation, requestJson);
}

/**
 * Submit an exact WASM-prepared request over the opaque session transport.
 * Fenced to the active session DID; verifies that session has not switched.
 */
export async function submitPreparedRequest(
	prepared: PreparedGatewayRequest,
	expectedDid?: string
): Promise<GatewayResponse> {
	if (isTauri) {
		throw new Error('submitPreparedRequest is a browser transport; desktop routes via Rust');
	}
	const saved = readBrowserAuth();
	if (!saved) {
		throw new Error('Not authenticated');
	}
	if (expectedDid && saved.did !== expectedDid) {
		throw new Error('Session changed: prepared request actor DID does not match current session');
	}

	const url = `${NEST_URL}${prepared.path}`;
	const headers: Record<string, string> = {
		Authorization: `Bearer ${saved.sessionId}`,
		'atproto-proxy': 'did:web:chat.catbird.blue#atproto_mls'
	};
	if (prepared.body) {
		headers['Content-Type'] = 'application/json';
	}

	const resp = await fetch(url, {
		method: prepared.method,
		headers,
		body: prepared.body
	});

	// Re-verify session has not changed while request was in-flight
	const current = readBrowserAuth();
	if (!current || current.did !== saved.did || current.sessionId !== saved.sessionId) {
		throw new Error('Session changed during request execution');
	}

	const bodyText = await resp.text();
	const contentType = resp.headers.get('content-type');

	return {
		status: resp.status,
		contentType,
		body: bodyText
	};
}

/**
 * Clear auth credentials from the WASM MLS module.
 */
export async function clearAuth(): Promise<void> {
	if (isTauri) return;
	clearBrowserAuth();
	if (!_worker) return;
	const w = _worker;
	// Drop the in-memory content root key from the WASM layer first; the
	// localStorage entry is intentionally preserved so re-login from the
	// same browser profile resumes the same HMAC chain seed.
	try {
		await (
			w as unknown as { clearContentRootKey: () => Promise<void> }
		).clearContentRootKey();
	} catch (e) {
		console.warn('[catmos] clearContentRootKey failed:', e);
	}
	await w.clearAuth();
}

export async function tryRestoreSession(): Promise<AuthState | null> {
	if (isTauri) {
		return tauriInvoke('try_restore_session');
	}
	const saved = readBrowserAuth();
	if (!saved) return null;
	const { sessionId } = saved;

	try {
		const resp = await bffFetch('/auth/session', { method: 'GET' }, sessionId);
		if (!resp.ok) {
			if (resp.status === 401 || resp.status === 403) {
				clearBrowserAuth();
				terminateWorkerInstance();
				return null;
			}
			throw new Error(`Failed to restore session: ${resp.status}`);
		}
		const info = await resp.json();
		const restoredDid: string = typeof info?.did === 'string' ? info.did.trim() : '';
		if (!restoredDid) {
			throw new Error('Invalid restored session response: missing did');
		}

		persistBrowserAuth(restoredDid, sessionId);
		if (!isMlsOptedInForDid(restoredDid)) {
			return { did: restoredDid, handle: info.handle ?? restoredDid };
		}
		await initWasm(restoredDid);

		// Push restored credentials to Worker
		const w = getWorker();
		await w.setAuth(restoredDid, sessionId);
		await installContentRootKey(restoredDid);
		await w.setup();

		replenishKeyPackages();
		startKeyPackageReplenishment();

		return { did: restoredDid, handle: info.handle ?? restoredDid };
	} catch (error) {
		if (_replenishInterval) {
			clearInterval(_replenishInterval);
			_replenishInterval = null;
		}
		clearBrowserAuth();
		try {
			if (_worker) {
				try {
					await (
						_worker as unknown as { clearContentRootKey: () => Promise<void> }
					).clearContentRootKey();
				} catch (e) {
					console.warn('[catmos] clearContentRootKey failed during restore rollback:', e);
				}
				await _worker.clearAuth();
			}
		} finally {
			terminateWorkerInstance();
		}
		throw error;
	}
}

export async function logout(): Promise<void> {
	if (isTauri) {
		return tauriInvoke('logout');
	}
	clearBrowserAuth();

	// Clear key package replenishment interval
	if (_replenishInterval) {
		clearInterval(_replenishInterval);
		_replenishInterval = null;
	}

	// Clear auth in worker, then terminate it and reset wasmReady/worker state
	try {
		if (_worker) {
			try {
				await (
					_worker as unknown as { clearContentRootKey: () => Promise<void> }
				).clearContentRootKey();
			} catch (e) {
				console.warn('[catmos] clearContentRootKey failed during logout:', e);
			}
			await _worker.clearAuth();
		}
	} finally {
		terminateWorkerInstance();
	}
}

// ---------------------------------------------------------------------------
// Key package replenishment (browser only)
// ---------------------------------------------------------------------------

let _replenishInterval: ReturnType<typeof setInterval> | null = null;

/** Replenish MLS key packages if running low. No-op in Tauri (desktop has its own monitor). */
export async function replenishKeyPackages(): Promise<void> {
	if (isTauri) return;
	const w = getWorker();
	try {
		await w.replenishKeyPackages();
	} catch (e) {
		console.warn('[catmos] key package replenishment failed:', e);
	}
}

/** Start periodic key package replenishment (every 5 minutes). */
function startKeyPackageReplenishment(): void {
	if (_replenishInterval) return;
	_replenishInterval = setInterval(() => {
		replenishKeyPackages();
	}, 5 * 60 * 1000);
}

// ---------------------------------------------------------------------------
// Conversations
// ---------------------------------------------------------------------------

export async function getConversations(): Promise<Conversation[]> {
	if (isTauri) {
		return tauriInvoke('get_conversations');
	}
	const w = getWorker();
	return w.listConversations() as Promise<Conversation[]>;
}

export async function createGroup(
	name: string,
	memberDids: string[],
	description?: string
): Promise<Conversation> {
	if (isTauri) {
		return tauriInvoke('create_group', { name, memberDids, description });
	}
	// Ensure fresh key packages before group creation
	await replenishKeyPackages();
	const w = getWorker();
	return w.createConversation(name, memberDids) as Promise<Conversation>;
}

export async function subscribeConversation(
	conversationId: string,
	onMessage?: (msg: unknown) => void,
	onEvent?: (event: unknown) => void,
	onStatus?: (status: unknown) => void,
	cursor?: string
): Promise<void> {
	if (isTauri) {
		return tauriInvoke('subscribe_conversation', { conversationId, cursor });
	}
	const w = getWorker();
	await w.subscribe(
		conversationId,
		proxy(onMessage ?? (() => {})),
		proxy(onEvent ?? (() => {})),
		proxy(onStatus ?? (() => {})),
		cursor
	);
}

export async function unsubscribeConversation(conversationId: string): Promise<void> {
	if (isTauri) {
		return tauriInvoke('unsubscribe_conversation', { conversationId });
	}
	const w = getWorker();
	await w.unsubscribe(conversationId);
}

/**
 * Open a global WebSocket that receives events for every conversation the
 * signed-in user belongs to. Only supported on Tauri — the WASM target still
 * relies on per-convo subscriptions. Call once after login.
 */
export async function subscribeAllEvents(): Promise<void> {
	if (isTauri) {
		return tauriInvoke('subscribe_all_events');
	}
	// Browser/WASM: no-op for now. Per-convo subscribe still works; full
	// parity is tracked separately.
}

export async function unsubscribeAllEvents(): Promise<void> {
	if (isTauri) {
		return tauriInvoke('unsubscribe_all_events');
	}
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

export async function sendMessage(conversationId: string, content: string): Promise<Message> {
	if (isTauri) {
		return tauriInvoke('send_message', { conversationId, content });
	}
	const w = getWorker();
	return w.sendMessage(conversationId, content) as Promise<Message>;
}

export async function sendImage(
	conversationId: string,
	content: string,
	data: Uint8Array,
	contentType: string,
	width: number,
	height: number,
	altText?: string
): Promise<Message> {
	if (isTauri) {
		return tauriInvoke('send_image', {
			conversationId,
			content,
			data: Array.from(data),
			contentType,
			width,
			height,
			altText
		});
	}
	const w = getWorker();
	return w.sendImage(conversationId, content, data, contentType, width, height, altText) as Promise<Message>;
}

export async function getMessages(conversationId: string, before?: string): Promise<Message[]> {
	if (isTauri) {
		return tauriInvoke('get_messages', { conversationId, before });
	}
	const w = getWorker();
	return w.getMessages(conversationId, before) as Promise<Message[]>;
}

export async function getImageAttachment(
	image: import('./tauri').ImageAttachment
): Promise<string> {
	if (isTauri) {
		return tauriInvoke('get_image_attachment', {
			blobId: image.blobId,
			keyB64: image.keyB64,
			ivB64: image.ivB64,
			sha256: image.sha256,
			contentType: image.contentType
		});
	}
	const w = getWorker();
	return w.getImageAttachment(
		image.blobId,
		image.keyB64,
		image.ivB64,
		image.sha256,
		image.contentType
	) as Promise<string>;
}

export async function fetchNewMessages(conversationId: string): Promise<Message[]> {
	if (isTauri) {
		return tauriInvoke('fetch_new_messages', { conversationId });
	}
	const w = getWorker();
	return w.fetchNewMessages(conversationId) as Promise<Message[]>;
}

export async function sendReaction(
	conversationId: string,
	messageId: string,
	emoji: string,
	action: 'add' | 'remove'
): Promise<void> {
	if (isTauri) {
		return tauriInvoke('send_reaction', { conversationId, messageId, emoji, action });
	}
	const w = getWorker();
	return w.sendReaction(conversationId, messageId, emoji, action) as Promise<void>;
}

export async function sendTyping(conversationId: string, isTyping: boolean): Promise<void> {
	if (isTauri) {
		return tauriInvoke('send_typing', { conversationId, isTyping });
	}
	const w = getWorker();
	return w.sendTyping(conversationId, isTyping) as Promise<void>;
}

export async function updateCursor(conversationId: string, cursor: string): Promise<void> {
	if (isTauri) {
		return tauriInvoke('update_cursor', { conversationId, cursor });
	}
	const w = getWorker();
	return w.updateCursor(conversationId, cursor) as Promise<void>;
}

// ---------------------------------------------------------------------------
// Members
// ---------------------------------------------------------------------------

export async function addGroupMembers(conversationId: string, memberDids: string[]): Promise<void> {
	if (isTauri) {
		return tauriInvoke('add_group_members', { conversationId, memberDids });
	}
	const w = getWorker();
	return w.addGroupMembers(conversationId, memberDids) as Promise<void>;
}

export async function getGroupMembers(conversationId: string): Promise<GroupMember[]> {
	if (isTauri) {
		return tauriInvoke('get_group_members', { conversationId });
	}
	const w = getWorker();
	return w.getMembers(conversationId) as Promise<GroupMember[]>;
}

export async function promoteMember(conversationId: string, targetDid: string): Promise<void> {
	if (isTauri) {
		return tauriInvoke('promote_member', { conversationId, targetDid });
	}
	const w = getWorker();
	return w.promoteMember(conversationId, targetDid) as Promise<void>;
}

export async function demoteMember(conversationId: string, targetDid: string): Promise<void> {
	if (isTauri) {
		return tauriInvoke('demote_member', { conversationId, targetDid });
	}
	const w = getWorker();
	return w.demoteMember(conversationId, targetDid) as Promise<void>;
}

export async function removeGroupMember(
	conversationId: string,
	targetDid: string
): Promise<void> {
	if (isTauri) {
		return tauriInvoke('remove_group_member', { conversationId, targetDid });
	}
	const w = getWorker();
	return w.removeParticipants(conversationId, targetDid) as Promise<void>;
}

// ---------------------------------------------------------------------------
// Profiles & Search
// ---------------------------------------------------------------------------

export async function getProfiles(dids: string[]): Promise<ProfileView[]> {
	if (isTauri) {
		return tauriInvoke('get_profiles', { dids });
	}
	const w = getWorker();
	return w.getProfiles(dids) as Promise<ProfileView[]>;
}

export async function searchUsers(query: string): Promise<SearchResult[]> {
	if (isTauri) {
		return tauriInvoke('search_users', { query });
	}
	const w = getWorker();
	return w.searchUsers(query) as Promise<SearchResult[]>;
}

export async function searchMessages(query: string): Promise<SearchHit[]> {
	if (isTauri) {
		return tauriInvoke('search_messages', { query });
	}
	// Web fallback: client-side search through loaded messages
	const { get } = await import('svelte/store');
	const { messages } = await import('#lib/stores/messages.ts');
	const { conversations } = await import('#lib/stores/conversations.ts');
	const state = get(messages);
	const convoState = get(conversations);
	const lowerQuery = query.toLowerCase();
	const hits: SearchHit[] = [];

	for (const [conversationId, msgs] of state.byConversation) {
		const convo = convoState.items.find((c) => c.id === conversationId);
		const conversationName = convo?.displayName ?? conversationId;
		for (const msg of msgs) {
			if (msg.content.toLowerCase().includes(lowerQuery)) {
				hits.push({
					messageId: msg.id,
					conversationId,
					conversationName,
					senderDid: msg.senderDid,
					content: msg.content,
					timestamp: msg.timestamp
				});
			}
		}
	}

	return hits.sort(
		(a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
	);
}

export async function checkOptInStatus(dids: string[]): Promise<OptInStatus[]> {
	if (isTauri) {
		return tauriInvoke('check_opt_in_status', { dids });
	}
	const w = getWorker();
	return w.checkOptInStatus(dids) as Promise<OptInStatus[]>;
}

// ---------------------------------------------------------------------------
// Group Metadata
// ---------------------------------------------------------------------------

export async function getGroupMetadata(
	conversationId: string
): Promise<GroupMetadataView | null> {
	if (isTauri) {
		return tauriInvoke('get_group_metadata', { conversationId });
	}
	const w = getWorker();
	const result = await w.getGroupMetadata(conversationId);
	if (!result) return null;
	const parsed = typeof result === 'string' ? JSON.parse(result) : result;
	// MLS metadata cutover: WASM now returns `title` / `avatarBytesBase64`;
	// remap to the legacy `GroupMetadataView` shape for shared UI compat.
	if (parsed && typeof parsed === 'object') {
		return {
			name: parsed.title ?? parsed.name,
			description: parsed.description,
			avatarHash: parsed.avatarBytesBase64 ?? parsed.avatarHash
		} as GroupMetadataView;
	}
	return parsed;
}

/**
 * Bootstrap group metadata after a Welcome / external join / merged commit.
 * Browser-only — Tauri desktop has its own metadata bootstrap path inside
 * the Rust backend.
 *
 * Hosts SHOULD call this after every operation that could change metadata
 * (Welcome processed, incoming commit merged, post-rejoin merge). Returns
 * `null` if there's no metadata yet for the group.
 */
export async function bootstrapGroupMetadata(
	groupIdHex: string
): Promise<{ title: string; description: string; avatarBytesBase64: string | null; avatarContentType: string | null; metadataVersion: number; epoch: number } | null> {
	if (isTauri) {
		// Desktop already bootstraps inline via Rust. JS no-op.
		return null;
	}
	const w = getWorker();
	const result = await (w as unknown as {
		bootstrapGroupMetadata: (g: string) => Promise<unknown>;
	}).bootstrapGroupMetadata(groupIdHex);
	return result as never;
}

/**
 * Re-publish encrypted metadata after a server-initiated group reset.
 * Browser-only.
 */
export async function republishMetadataAfterReset(
	newGroupIdHex: string,
	resetGeneration?: number
): Promise<unknown> {
	if (isTauri) {
		return null;
	}
	const w = getWorker();
	return (w as unknown as {
		republishMetadataAfterReset: (g: string, r?: number) => Promise<unknown>;
	}).republishMetadataAfterReset(newGroupIdHex, resetGeneration);
}

export async function leaveConversation(conversationId: string): Promise<void> {
	if (isTauri) {
		return tauriInvoke('leave_conversation', { conversationId });
	}
	const w = getWorker();
	return w.leaveConversation(conversationId) as Promise<void>;
}

export async function updateGroupMetadata(
	conversationId: string,
	name?: string,
	description?: string,
	avatarHash?: string,
	avatarBlobLocator?: string,
	avatarContentType?: string
): Promise<void> {
	if (isTauri) {
		// Tauri now uses Phase A.2 encrypted update — accepts avatar
		// locator + content-type, not a content-addressed hash. Old
		// callers passing only `avatarHash` get null avatar fields
		// (rename / description still work; avatar must be uploaded
		// via a separate flow once available on desktop).
		void avatarHash;
		return tauriInvoke('update_group_metadata', {
			conversationId,
			name,
			description,
			avatarBlobLocator: avatarBlobLocator ?? null,
			avatarContentType: avatarContentType ?? null
		});
	}
	// MLS metadata cutover: WASM `update_group_metadata` takes the richer
	// (title, description, avatarBlobLocator, avatarContentType, avatarBytes)
	// shape. The legacy `avatarHash` arg was a content-addressed locator hint
	// that's no longer meaningful — the encrypted blob path uses fresh UUID
	// locators per upload. We pass it through as the locator so callers
	// that still send a hash work, but new callers should pass the avatar
	// bytes directly via the worker `updateGroupMetadata` method.
	const w = getWorker();
	void avatarHash;
	await (w as unknown as {
		updateGroupMetadata: (
			c: string,
			t: string | null,
			d: string | null,
			al: string | null,
			act: string | null,
			ab: Uint8Array | null
		) => Promise<unknown>;
	}).updateGroupMetadata(
		conversationId,
		name ?? null,
		description ?? null,
		null,
		null,
		null
	);
}

// ---------------------------------------------------------------------------
// Group Reset
// ---------------------------------------------------------------------------

export async function resetGroup(
	conversationId: string,
	reason?: string
): Promise<Record<string, unknown>> {
	if (isTauri) {
		return tauriInvoke('reset_group', { conversationId, reason });
	}
	const saved = readBrowserAuth();
	if (!saved) throw new Error('Not authenticated');
	const requestJson = JSON.stringify({
		convoId: conversationId,
		reason: reason ?? undefined
	});
	const prepared = (await prepareSignedRequest(
		'requestReset',
		requestJson
	)) as PreparedGatewayRequest;
	const resp = await submitPreparedRequest(prepared, saved.did);
	if (resp.status < 200 || resp.status >= 300) {
		throw new Error(`Reset group failed: ${resp.status} ${resp.body}`);
	}
	return resp.body ? JSON.parse(resp.body) : {};
}

// ---------------------------------------------------------------------------
// Spam Reporting
// ---------------------------------------------------------------------------

export async function reportSpam(
	conversationId: string,
	reportedDid: string,
	reason?: string
): Promise<void> {
	if (isTauri) {
		return tauriInvoke('report_spam', { conversationId, reportedDid, reason });
	}
	const saved = readBrowserAuth();
	if (!saved) throw new Error('Not authenticated');
	const body: Record<string, string> = { convoId: conversationId, reportedDid };
	if (reason) body.reason = reason;
	const resp = await fetch(`${NEST_URL}/xrpc/blue.catbird.chat.reportSpam`, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			Authorization: `Bearer ${saved.sessionId}`,
			'atproto-proxy': 'did:web:chat.catbird.blue#atproto_mls'
		},
		body: JSON.stringify(body)
	});
	if (!resp.ok) {
		const text = await resp.text();
		throw new Error(`Report spam failed: ${resp.status} ${text}`);
	}
}

// ---------------------------------------------------------------------------
// Blocks (app.bsky.graph.block)
//
// Both runtimes call `com.atproto.repo.createRecord` / `listRecords` via the
// nest BFF. Browser mode uses the session bearer directly from sessionStorage;
// Tauri mode routes through dedicated IPC commands that use the keychained
// session on the Rust side.
// ---------------------------------------------------------------------------

/**
 * Publish an `app.bsky.graph.block` record for `targetDid`.
 * Uses `com.atproto.repo.createRecord` via the nest BFF. Returns the AT-URI.
 */
export async function createBlock(targetDid: string): Promise<void> {
	if (isTauri) {
		await tauriInvoke<string>('create_block', { subjectDid: targetDid });
		return;
	}
	const saved = readBrowserAuth();
	if (!saved) throw new Error('Not authenticated');
	const body = {
		repo: saved.did,
		collection: 'app.bsky.graph.block',
		record: {
			$type: 'app.bsky.graph.block',
			subject: targetDid,
			createdAt: new Date().toISOString()
		}
	};
	const resp = await fetch(`${NEST_URL}/xrpc/com.atproto.repo.createRecord`, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			Authorization: `Bearer ${saved.sessionId}`
		},
		body: JSON.stringify(body)
	});
	if (!resp.ok) {
		const text = await resp.text();
		throw new Error(`createBlock failed: ${resp.status} ${text}`);
	}
}

/**
 * List every DID currently blocked by the authenticated user by paginating
 * `com.atproto.repo.listRecords` over the `app.bsky.graph.block` collection.
 * Returns a unique Set of subject DIDs.
 */
export async function listOwnBlocks(): Promise<Set<string>> {
	const blocked = new Set<string>();
	if (isTauri) {
		const dids = await tauriInvoke<string[]>('list_own_blocks');
		for (const d of dids) blocked.add(d);
		return blocked;
	}
	const saved = readBrowserAuth();
	if (!saved) return blocked;

	let cursor: string | undefined;
	// Safety cap to prevent runaway pagination (1000 entries * 100 per page = 100k DIDs).
	for (let page = 0; page < 1000; page++) {
		const params = new URLSearchParams({
			repo: saved.did,
			collection: 'app.bsky.graph.block',
			limit: '100'
		});
		if (cursor) params.set('cursor', cursor);
		const resp = await fetch(
			`${NEST_URL}/xrpc/com.atproto.repo.listRecords?${params.toString()}`,
			{ headers: { Authorization: `Bearer ${saved.sessionId}` } }
		);
		if (!resp.ok) {
			const text = await resp.text();
			throw new Error(`listOwnBlocks failed: ${resp.status} ${text}`);
		}
		const data = (await resp.json()) as {
			records?: Array<{ value?: { subject?: string } }>;
			cursor?: string;
		};
		for (const rec of data.records ?? []) {
			const subj = rec.value?.subject;
			if (typeof subj === 'string') blocked.add(subj);
		}
		if (!data.cursor || (data.records?.length ?? 0) === 0) break;
		cursor = data.cursor;
	}
	return blocked;
}

// ---------------------------------------------------------------------------
// Voice Messages
// ---------------------------------------------------------------------------

export async function catbird_mls_prepare_voice(pcmPath: string, sampleRate: number): Promise<any> {
	if (isTauri) {
		return tauriInvoke('prepare_voice_message', { pcmPath, sampleRate });
	}
	const w = getWorker();
	return w.prepareVoice(pcmPath, sampleRate);
}

export async function catbird_mls_decode_opus(opusData: Uint8Array): Promise<Uint8Array> {
	if (isTauri) {
		return tauriInvoke('decode_opus_to_pcm', { opusData: Array.from(opusData) });
	}
	const w = getWorker();
	return w.decodeOpus(opusData) as Promise<Uint8Array>;
}

export async function sendVoice(
	conversationId: string,
	audioData: Uint8Array,
	contentType: string,
	durationMs: number,
	waveform: number[],
	transcript?: string
): Promise<Message> {
	if (isTauri) {
		return tauriInvoke('send_voice', {
			conversationId,
			audioData: Array.from(audioData),
			contentType,
			durationMs,
			waveform,
			transcript
		});
	}
	const w = getWorker();
	return w.sendVoice(
		conversationId,
		audioData,
		contentType,
		durationMs,
		waveform,
		transcript
	) as Promise<Message>;
}

export async function fetchAndDecryptBlob(
	blobId: string,
	key: Uint8Array,
	iv: Uint8Array,
	sha256: string
): Promise<Uint8Array> {
	if (isTauri) {
		return tauriInvoke('fetch_and_decrypt_blob', {
			blobId,
			key: Array.from(key),
			iv: Array.from(iv),
			sha256
		});
	}
	const w = getWorker();
	return w.fetchAndDecryptBlob(blobId, key, iv, sha256) as Promise<Uint8Array>;
}

// ---------------------------------------------------------------------------
// Layer 3 quarantine (Tauri-only; catbird-mls-web hasn't shipped this surface)
// ---------------------------------------------------------------------------

import type { QuarantineState } from './tauri';

/**
 * Snapshot quarantine state for a conversation, used by the conversation
 * view to gate the composer + show the banner on first paint after restart.
 * Returns `null` when the conversation is not quarantined.
 *
 * Browser/WASM: returns `null` until catbird-mls-web exposes the same
 * surface — quarantine cascades cannot harm a browser tab today since the
 * WASM client doesn't run the orchestrator (catmos web uses a thinner facade).
 */
export async function getQuarantineState(
	conversationId: string
): Promise<QuarantineState | null> {
	if (isTauri) {
		return tauriInvoke('get_quarantine_state', { conversationId });
	}
	return null;
}

/**
 * User-confirmed manual reset. Reports the deliberate vote to the server's
 * A7 reset pyramid AND clears local quarantine state. The follow-up
 * server-pushed `groupResetEvent` is handled by the existing
 * `mls:group-reset` listener in `+page.svelte`.
 */
export async function confirmManualReset(conversationId: string): Promise<void> {
	if (isTauri) {
		return tauriInvoke('confirm_manual_reset', { conversationId });
	}
	throw new Error('confirmManualReset is not yet implemented in browser builds');
}

// ---------------------------------------------------------------------------
// Unified Clean-Slate Labyrinth 1.1 & Spaces Eligibility (`Spec §6.3`, `D4`, `I15`, `I16`)
// ---------------------------------------------------------------------------

export interface LabyrinthBackupStatusView {
	backup_enabled: boolean;
	mailbox_space_uri: string;
	has_recovery_code: boolean;
	has_passkey_prf: boolean;
	epoch_seq: number;
	active_device_ids: string[];
}

export interface OtcPairingOfferView {
	six_digit_code: string;
	formatted_code: string;
}

export interface OtcPairingCompletionView {
	session_id: number[];
	initiator_mlkem768_ek_len: number;
	responder_mlkem768_ct_len: number;
	new_epoch_seq: number;
}

async function ensureUnifiedBrowserClientOpen(did: string): Promise<Remote<WorkerApi>> {
	const didHash = await accountDidHashHex(did);
	const dbKeyHex = await loadOrCreateDbKeyHex(didHash);
	const w = getWorker();
	await w.openUnifiedClient({
		accountDid: did,
		deviceId: `web-${didHash.slice(0, 12)}`,
		homeDsDid: 'did:web:mlschat.catbird.blue',
		homeDsEndpoint: 'https://mlschat.catbird.blue',
		pdsEndpoint: 'https://bsky.social',
		dbKeyHex
	});
	return w;
}

export async function enableMlsAndEnroll(
	did: string,
	pdsSupportsSpaces = true,
	grantedScopes: string[] = [...REQUIRED_LABYRINTH_OAUTH_SCOPES]
): Promise<LabyrinthBackupStatusView> {
	if (isTauri) {
		return tauriInvoke('labyrinth_enable_and_enroll', {
			did,
			grantedScopes
		});
	}
	setMlsOptedInForDid(did, true);
	const w = await ensureUnifiedBrowserClientOpen(did);
	await w.enrollUnifiedDevice(pdsSupportsSpaces, grantedScopes);
	return (await w.labyrinthStatus()) as LabyrinthBackupStatusView;
}

export async function getLabyrinthStatus(did: string): Promise<LabyrinthBackupStatusView | null> {
	if (isTauri) {
		return tauriInvoke('labyrinth_status', { did });
	}
	if (!isMlsOptedInForDid(did)) return null;
	const w = await ensureUnifiedBrowserClientOpen(did);
	return (await w.labyrinthStatus()) as LabyrinthBackupStatusView;
}

export async function setupLabyrinthRecoveryCode(did: string): Promise<string> {
	if (isTauri) {
		return tauriInvoke('labyrinth_setup_recovery_code', { did });
	}
	const w = await ensureUnifiedBrowserClientOpen(did);
	return w.setupRecoveryCode();
}

export async function restoreWithLabyrinthRecoveryCode(
	did: string,
	recoveryCodeInput: string
): Promise<LabyrinthBackupStatusView> {
	if (isTauri) {
		return tauriInvoke('labyrinth_restore_recovery_code', { did, recoveryCodeInput });
	}
	const w = await ensureUnifiedBrowserClientOpen(did);
	return (await w.restoreWithRecoveryCode(recoveryCodeInput)) as LabyrinthBackupStatusView;
}

export async function registerLabyrinthPasskeyPrf(
	did: string,
	credentialId: Uint8Array,
	prfOutput32: Uint8Array
): Promise<LabyrinthBackupStatusView> {
	if (isTauri) {
		return tauriInvoke('labyrinth_register_passkey_prf', {
			did,
			credentialId: Array.from(credentialId),
			prfOutput32: Array.from(prfOutput32)
		});
	}
	const w = await ensureUnifiedBrowserClientOpen(did);
	return (await w.registerPasskeyPrf(credentialId, prfOutput32)) as LabyrinthBackupStatusView;
}

export async function initiateLabyrinthOtcPairing(did: string): Promise<OtcPairingOfferView> {
	if (isTauri) {
		return tauriInvoke('labyrinth_initiate_otc', { did });
	}
	const w = await ensureUnifiedBrowserClientOpen(did);
	return (await w.initiateOtcPairing()) as OtcPairingOfferView;
}

export async function completeLabyrinthOtcPairing(
	did: string,
	sixDigitCode: string
): Promise<OtcPairingCompletionView> {
	if (isTauri) {
		return tauriInvoke('labyrinth_complete_otc', { did, sixDigitCode });
	}
	const w = await ensureUnifiedBrowserClientOpen(did);
	return (await w.completeOtcPairing(sixDigitCode)) as OtcPairingCompletionView;
}

export async function revokeLabyrinthDevice(
	did: string,
	targetDeviceId: string
): Promise<LabyrinthBackupStatusView> {
	if (isTauri) {
		return tauriInvoke('labyrinth_revoke_device', { did, targetDeviceId });
	}
	const w = await ensureUnifiedBrowserClientOpen(did);
	return (await w.revokeLabyrinthDevice(targetDeviceId)) as LabyrinthBackupStatusView;
}

/**
 * catmos WASM bridge — Unified API surface for Tauri desktop and browser WASM.
 *
 * Detects runtime environment via `__TAURI_INTERNALS__` on window.
 * - Tauri desktop: routes calls through `@tauri-apps/api/core` invoke()
 * - Browser: routes calls through a Web Worker (comlink) so that WASM gets
 *   OPFS Synchronous Access Handle for MLS SQLite crypto.
 *
 * Session credentials remain in sessionStorage. The per-account database key
 * is wrapped by a non-exportable CryptoKey retained in IndexedDB.
 * Credential keys are namespaced by DID to prevent data leakage when multiple
 * users log in on the same browser. The Worker receives them via explicit
 * setAuth / init calls.
 */

// Re-export all types from tauri.ts (canonical type definitions)
export type {
	Conversation,
	ConversationMember,
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
import { captureNativeAuthority, recordNativeAuthority, clearNativeAuthority } from './native-authority';

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
	const capturedArgs = captureNativeAuthority(args);
	const { invoke } = await import('@tauri-apps/api/core');
	return invoke<T>(cmd, capturedArgs);
}

// ---------------------------------------------------------------------------
// Worker singleton (browser mode)
// ---------------------------------------------------------------------------

let _worker: Remote<WorkerApi> | null = null;
let _rawWorker: Worker | null = null;

function getWorker(): Remote<WorkerApi> {
	if (!_worker) {
		_rawWorker = new Worker(new URL('./mls-worker.ts', import.meta.url), { type: 'module' });
		_worker = wrap<WorkerApi>(_rawWorker);
	}
	return _worker;
}

// ---------------------------------------------------------------------------
// Protected per-account MLS database key custody
// ---------------------------------------------------------------------------

/**
 * Get the per-account database key through its persistent wrapping key.
 * Legacy session keys are migrated without replacing existing database custody.
 */
async function getOrCreateMlsDbKey(did: string): Promise<{ key: string; dbPrefix: string; contentRootKey: Uint8Array }> {
	if (!did.startsWith('did:') || !navigator.locks || !globalThis.indexedDB) throw new Error('Protected persistent browser storage is unavailable.');
	return navigator.locks.request('catbird-protected-database-keys-v1', async () => {
		const db = await new Promise<IDBDatabase>((resolve, reject) => {
			const request = indexedDB.open('catbird-protected-database-keys-v1', 1);
			request.onupgradeneeded = () => request.result.createObjectStore('keys');
			request.onsuccess = () => resolve(request.result);
			request.onerror = () => reject(new Error('Protected key store could not be opened.'));
			request.onblocked = () => reject(new Error('Protected key store is locked by another tab.'));
		});
		const read = (key: string) => new Promise<unknown>((resolve, reject) => {
			const request = db.transaction('keys', 'readonly').objectStore('keys').get(key);
			request.onsuccess = () => resolve(request.result);
			request.onerror = () => reject(new Error('Protected key read failed.'));
		});
		const write = (key: string, value: unknown) => new Promise<void>((resolve, reject) => {
			const transaction = db.transaction('keys', 'readwrite');
			transaction.objectStore('keys').put(value, key);
			transaction.oncomplete = () => resolve();
			transaction.onerror = transaction.onabort = () => reject(new Error('Protected key commit failed.'));
		});
		try {
			const id = await sha256Hex(did);
			const directory = await navigator.storage.getDirectory();
			const markerName = `catbird-key-custody-${id}.json`;
			let marker: { version: number; dbPrefix: string; contentKeyCreated: boolean } | undefined;
			try {
				const file = await directory.getFileHandle(markerName);
				const contents = await file.getFile();
				if (contents.size > 1024) throw new Error('Invalid protected key custody marker.');
				marker = JSON.parse(await contents.text());
				if (marker?.version !== 1 || !marker.dbPrefix || typeof marker.contentKeyCreated !== 'boolean') throw new Error('Invalid protected key custody marker.');
			} catch (error) {
				if (!(error instanceof DOMException && error.name === 'NotFoundError')) throw error;
			}
			let wrapping = await read('wrapping-key') as CryptoKey | undefined;
			if (!wrapping) {
				const count = await new Promise<number>((resolve, reject) => {
					const request = db.transaction('keys', 'readonly').objectStore('keys').count();
					request.onsuccess = () => resolve(request.result);
					request.onerror = () => reject(new Error('Protected key inventory failed.'));
				});
				if (count !== 0 || marker) throw new Error('Existing protected keys are unavailable; restore browser storage before continuing.');
				wrapping = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
				await write('wrapping-key', wrapping);
			}
			if (wrapping.extractable || wrapping.algorithm.name !== 'AES-GCM') throw new Error('Invalid protected key custody.');
			const aad = new TextEncoder().encode(`catbird.opfs.key.v1:${did}`);
			const stored = await read(id) as { iv: Uint8Array; ciphertext: ArrayBuffer; dbPrefix: string } | undefined;
			let bytes: Uint8Array;
			let dbPrefix = `catbird_mls_${id}`;
			if (stored) {
				if (!stored.dbPrefix || !/^[a-zA-Z0-9_-]+$/.test(stored.dbPrefix)) throw new Error('Invalid protected database identity.');
				dbPrefix = stored.dbPrefix;
				bytes = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: stored.iv as BufferSource, additionalData: aad }, wrapping, stored.ciphertext));
			} else {
				if (marker) throw new Error('The account database key is missing; existing custody was retained.');
				const old = sessionStorage.getItem(didKey(did, 'mls_db_key')) || (sessionStorage.getItem(SS_ACTIVE_DID) === did ? sessionStorage.getItem('catbird_mls_mls_db_key') : null);
				if (old && !/^[0-9a-f]{64}$/i.test(old)) throw new Error('Existing database key is invalid; custody was retained.');
				bytes = old ? Uint8Array.from(old.match(/../g)!, byte => parseInt(byte, 16)) : crypto.getRandomValues(new Uint8Array(32));
				const iv = crypto.getRandomValues(new Uint8Array(12));
				const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, wrapping, bytes as BufferSource);
				// Earlier clients always used the default DB because they sent db_prefix.
				// Retain that database and its existing enrollment for explicit validation.
				if (old) dbPrefix = 'catbird-mls';
				await write(id, { iv, ciphertext, dbPrefix });
			}
			if (bytes.byteLength !== 32) throw new Error('Protected database key has invalid length.');
			const contentId = `content:${id}`;
			const contentAad = new TextEncoder().encode(`catbird.content.key.v1:${did}`);
			const contentRecord = await read(contentId) as { iv: Uint8Array; ciphertext: ArrayBuffer } | undefined;
			let contentRootKey: Uint8Array;
			if (contentRecord) {
				contentRootKey = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: contentRecord.iv as BufferSource, additionalData: contentAad }, wrapping, contentRecord.ciphertext));
			} else {
				if (marker?.contentKeyCreated) throw new Error('The account content key is missing; existing custody was retained.');
				const legacy = localStorage.getItem(CONTENT_ROOT_PREFIX + id);
				contentRootKey = legacy ? Uint8Array.from(atob(legacy), value => value.charCodeAt(0)) : crypto.getRandomValues(new Uint8Array(32));
				if (contentRootKey.byteLength !== 32) throw new Error('Existing content key is invalid; custody was retained.');
				const iv = crypto.getRandomValues(new Uint8Array(12));
				const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: contentAad }, wrapping, contentRootKey as BufferSource);
				await write(contentId, { iv, ciphertext });
			}
			if (contentRootKey.byteLength !== 32) throw new Error('Protected content key has invalid length.');
			if (marker && marker.dbPrefix !== dbPrefix) throw new Error('Protected database identity changed.');
			if (!marker || !marker.contentKeyCreated) {
				const file = await directory.getFileHandle(markerName, { create: true });
				const stream = await file.createWritable();
				await stream.write(JSON.stringify({ version: 1, dbPrefix, contentKeyCreated: true }));
				await stream.close();
			}
			return { key: Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join(''), dbPrefix, contentRootKey };
		} finally { db.close(); }
	});
}

// ---------------------------------------------------------------------------
// MLS field-level content keys use the same persistent wrapping vault. Legacy
// plaintext keys are imported once without replacing incompatible custody.
// ---------------------------------------------------------------------------

const CONTENT_ROOT_PREFIX = 'mls.content.root.';

async function sha256Hex(input: string): Promise<string> {
	const bytes = new TextEncoder().encode(input);
	const digest = await crypto.subtle.digest('SHA-256', bytes);
	return Array.from(new Uint8Array(digest))
		.map((b) => b.toString(16).padStart(2, '0'))
		.join('');
}

async function loadOrCreateContentRootKey(userDid: string): Promise<Uint8Array> {
	return (await getOrCreateMlsDbKey(userDid)).contentRootKey;
}

/**
 * Push the per-DID content root key into the WASM module. Called once per
 * session after `setAuth` resolves so that subsequent `setup()` and any
 * message encrypt/decrypt has the key bound.
 *
 * Propagates errors on failure to enforce fail-closed security (no legacy
 * plaintext fallback).
 */
async function installContentRootKey(did: string, w: Remote<WorkerApi>, check: () => void): Promise<void> {
	const key = await loadOrCreateContentRootKey(did);
    check();
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

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

/**
 * Initialize the WASM Worker with MLS config.
 * Releases the account database key from protected persistent storage and
 * passes it only to the worker that owns that account database.
 */
let workerAccount: string | null = null;
let browserSessionRevision = 0;
function invalidateBrowserSession(): void { browserSessionRevision++; }
function checkBrowserRevision(revision: number, w?: Remote<WorkerApi>): void {
    if (browserSessionRevision !== revision || (w && _worker !== w)) throw new Error('Browser session changed');
}
async function bindWorkerAuth(w: Remote<WorkerApi>, did: string, token: string, revision: number): Promise<void> {
    checkBrowserRevision(revision, w);
    await w.setAuth(did, token);
    checkBrowserRevision(revision, w);
}
function discardBrowserSession(revision: number): void {
    if (revision !== browserSessionRevision) return;
    invalidateBrowserSession();
    clearBrowserAuth();
    if (_replenishInterval) clearInterval(_replenishInterval);
    _replenishInterval = null;
    _rawWorker?.terminate();
    _rawWorker = null; _worker = null; workerAccount = null;
}
function effectOwner(ownerDid?: string, ownerRevision?: string): string {
    if (!isTauri && ownerRevision !== undefined && ownerRevision !== `browser:${browserSessionRevision}`) throw new Error('Chat effect session changed');
    if (!ownerDid || (!isTauri && workerAccount !== ownerDid)) throw new Error('Chat effect account changed');
    return ownerDid;
}
async function browserEffect<T>(ownerDid: string | undefined, operation: (w: Remote<WorkerApi>, check: () => void) => Promise<T>): Promise<T> {
    const owner = effectOwner(ownerDid), revision = browserSessionRevision, w = getWorker();
    const check = () => {
        if (_worker !== w || workerAccount !== owner || browserSessionRevision !== revision) throw new Error('Chat effect session changed');
    };
    check();
    const result = await operation(w, check);
    check();
    return result;
}
function sessionCallback<T>(w: Remote<WorkerApi>, owner: string, revision: number, callback?: (value: T) => void): (value: T) => void {
    return value => {
        if (_worker === w && workerAccount === owner && browserSessionRevision === revision) callback?.(value);
    };
}
let workerInitTail: Promise<void> = Promise.resolve();
export async function initWasm(did?: string, expectedRevision?: number): Promise<void> {
	if (isTauri) return;
	const activeDid = did || (typeof sessionStorage !== 'undefined' ? sessionStorage.getItem(SS_ACTIVE_DID) : null);
	if (!activeDid) return;
    if (expectedRevision === undefined && workerAccount !== activeDid) invalidateBrowserSession();
    const revision = expectedRevision ?? browserSessionRevision;
    checkBrowserRevision(revision);
	const initialization = workerInitTail.catch(() => {}).then(async () => {
        checkBrowserRevision(revision);
		if (workerAccount === activeDid && _worker) return;
		const { key: mlsDbKey, dbPrefix } = await getOrCreateMlsDbKey(activeDid);
        checkBrowserRevision(revision);
		if (_rawWorker) _rawWorker.terminate();
		_rawWorker = null; _worker = null; workerAccount = null;
		const w = getWorker();
		try {
			await w.init({ baseUrl: NEST_URL, mlsDbKey, dbPrefix });
            checkBrowserRevision(revision, w);
			workerAccount = activeDid;
		} catch (error) {
			if (_worker === w && revision === browserSessionRevision) { (_rawWorker as Worker | null)?.terminate(); _rawWorker = null; _worker = null; }
			throw error;
		}
	});
	workerInitTail = initialization;
	await initialization;
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
function persistBrowserAuth(did: string, sessionId: string): void {
	sessionStorage.setItem(SS_ACTIVE_DID, did);
	sessionStorage.setItem(didKey(did, 'session_id'), sessionId);
}

/** Read stored session for the active DID. Returns null if nothing saved. */
function readBrowserAuth(): { did: string; sessionId: string } | null {
	const did = sessionStorage.getItem(SS_ACTIVE_DID);
	if (!did) return null;
	const sessionId = sessionStorage.getItem(didKey(did, 'session_id'));
	if (!sessionId) return null;
	return { did, sessionId };
}

/** Clear the active DID's credentials from sessionStorage. */
function clearBrowserAuth(): void {
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
        const result = await tauriInvoke<AuthState>('complete_login', { sessionId });
        recordNativeAuthority(result); return result;
    }
    invalidateBrowserSession();
    const revision = browserSessionRevision;
    try {
        await _worker?.clearAuth(); checkBrowserRevision(revision);
        const resp = await fetch(`${NEST_URL}/auth/session`, { headers: { Authorization: `Bearer ${sessionId}` } });
        checkBrowserRevision(revision);
        if (!resp.ok) throw new Error(`Failed to fetch session: ${resp.status}`);
        const info = await resp.json(); checkBrowserRevision(revision);
        const did: string = info.did;
        await initWasm(did, revision); checkBrowserRevision(revision);
        const w = getWorker(), check = () => checkBrowserRevision(revision, w);
        await bindWorkerAuth(w, did, sessionId, revision);
        await installContentRootKey(did, w, check); check();
        await w.setup(); check();
        persistBrowserAuth(did, sessionId);
        startKeyPackageReplenishment();
        return { did, handle: info.handle ?? did, authRevision: `browser:${revision}` };
    } catch (error) { discardBrowserSession(revision); throw error; }
}
/**
 * Set auth credentials for the WASM MLS module.
 * Called by catmos's auth store after completing OAuth.
 */
export async function setAuth(did: string, token: string): Promise<void> {
    if (isTauri) return;
    invalidateBrowserSession();
    const revision = browserSessionRevision, w = getWorker();
    const check = () => checkBrowserRevision(revision, w);
    try {
        await bindWorkerAuth(w, did, token, revision);
        await installContentRootKey(did, w, check); check();
        persistBrowserAuth(did, token);
    } catch (error) { discardBrowserSession(revision); throw error; }
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
    invalidateBrowserSession();
	if (isTauri) return;
	clearBrowserAuth();
	const w = getWorker();
    const revision = browserSessionRevision;
    await w.clearAuth();
    checkBrowserRevision(revision, w);
	// Cancel prior-session work before clearing the cached content key.
    // Protected persistent custody remains available for a later login.
	try {
		await (
			w as unknown as { clearContentRootKey: () => Promise<void> }
		).clearContentRootKey();
	} catch (e) {
		console.warn('[catmos] clearContentRootKey failed:', e);
	}
}

export async function tryRestoreSession(): Promise<AuthState | null> {
    if (isTauri) {
        const result = await tauriInvoke<AuthState | null>('try_restore_session');
        recordNativeAuthority(result); return result;
    }
    const saved = readBrowserAuth();
    if (!saved) return null;
    const { did, sessionId } = saved;
    invalidateBrowserSession();
    const revision = browserSessionRevision;
    try {
        await _worker?.clearAuth(); checkBrowserRevision(revision);
        const resp = await fetch(`${NEST_URL}/auth/session`, { headers: { Authorization: `Bearer ${sessionId}` } });
        checkBrowserRevision(revision);
        if (!resp.ok) {
            if (resp.status === 401 || resp.status === 403) { discardBrowserSession(revision); return null; }
            throw new Error(`Failed to restore session: ${resp.status}`);
        }
        const info = await resp.json(); checkBrowserRevision(revision);
        if (info.did !== did) throw new Error('Restored account does not match saved session');
        await initWasm(did, revision); checkBrowserRevision(revision);
        const w = getWorker(), check = () => checkBrowserRevision(revision, w);
        await bindWorkerAuth(w, did, sessionId, revision);
        await installContentRootKey(did, w, check); check();
        await w.setup(); check();
        startKeyPackageReplenishment();
        return { did, handle: info.handle ?? did, authRevision: `browser:${revision}` };
    } catch (error) { discardBrowserSession(revision); throw error; }
}

export async function logout(): Promise<void> {
    if (isTauri) { clearNativeAuthority(); return tauriInvoke('logout'); }
    discardBrowserSession(browserSessionRevision);
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
, ownerDid?: string, ownerRevision?: string): Promise<Conversation> {
    if (!isTauri) effectOwner(ownerDid, ownerRevision);
    const expectedOwner = effectOwner(ownerDid);
	if (isTauri) {
		return tauriInvoke('create_group', { name, memberDids, description , ownerDid: expectedOwner, ownerRevision });
	}
    return browserEffect(expectedOwner, async (w, check) => {
	// Ensure fresh key packages before group creation
	await w.replenishKeyPackages();
	check();
	return w.createConversation(name, memberDids) as Promise<Conversation>;

    });
}

export async function subscribeConversation(
	conversationId: string,
	onMessage?: (msg: unknown) => void,
	onEvent?: (event: unknown) => void,
	onStatus?: (status: unknown) => void,
	cursor?: string,
    ownerDid?: string, ownerRevision?: string
): Promise<void> {
    if (!isTauri) effectOwner(ownerDid, ownerRevision);
	if (isTauri) {
		return tauriInvoke('subscribe_conversation', { conversationId, cursor, ownerDid: effectOwner(ownerDid), ownerRevision });
	}
	const w = getWorker();
    const owner = effectOwner(ownerDid);
    const revision = browserSessionRevision;
	await w.subscribe(
		conversationId,
		proxy(sessionCallback(w, owner, revision, onMessage)),
		proxy(sessionCallback(w, owner, revision, onEvent)),
		proxy(sessionCallback(w, owner, revision, onStatus)),
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

export async function sendMessage(conversationId: string, content: string, ownerDid?: string, ownerRevision?: string): Promise<Message> {
    if (!isTauri) effectOwner(ownerDid, ownerRevision);
	if (isTauri) {
		return tauriInvoke('send_message', { conversationId, content, ownerDid: effectOwner(ownerDid), ownerRevision });
	}
    return browserEffect(ownerDid, w => w.sendMessage(conversationId, content) as Promise<Message>);
}

export async function sendImage(
	conversationId: string,
	content: string,
	data: Uint8Array,
	contentType: string,
	width: number,
	height: number,
	altText?: string,
    ownerDid?: string, ownerRevision?: string
): Promise<Message> {
    if (!isTauri) effectOwner(ownerDid, ownerRevision);
	if (isTauri) {
		return tauriInvoke('send_image', {
			conversationId,
			content,
			data: Array.from(data),
			contentType,
			width,
			height,
			altText,
            ownerDid: effectOwner(ownerDid), ownerRevision
		});
	}
    return browserEffect(ownerDid, w => w.sendImage(conversationId, content, data, contentType, width, height, altText) as Promise<Message>);
}

export async function getMessages(conversationId: string, before?: string, ownerDid?: string, ownerRevision?: string): Promise<Message[]> {
    if (!isTauri) effectOwner(ownerDid, ownerRevision);
	if (isTauri) {
		return tauriInvoke('get_messages', { conversationId, before, ownerDid: effectOwner(ownerDid), ownerRevision });
	}
    return browserEffect(ownerDid, w => w.getMessages(conversationId, before) as Promise<Message[]>);
}

export async function getImageAttachment(
	image: import('./tauri').ImageAttachment, conversationId: string, ownerDid?: string, ownerRevision?: string
): Promise<string> {
    if (!isTauri) effectOwner(ownerDid, ownerRevision);
	if (isTauri) {
		return tauriInvoke('get_image_attachment', {
            conversationId, ownerDid: effectOwner(ownerDid),
			blobId: image.blobId,
			keyB64: image.keyB64,
			ivB64: image.ivB64,
			sha256: image.sha256,
			contentType: image.contentType, ownerRevision
		});
	}
    return browserEffect(ownerDid, w => w.getImageAttachment(
        conversationId,
		image.blobId,
		image.keyB64,
		image.ivB64,
		image.sha256,
		image.contentType
	) as Promise<string>);
}

export async function fetchNewMessages(conversationId: string, ownerDid?: string, ownerRevision?: string): Promise<Message[]> {
    if (!isTauri) effectOwner(ownerDid, ownerRevision);
	if (isTauri) {
		return tauriInvoke('fetch_new_messages', { conversationId, ownerDid: effectOwner(ownerDid), ownerRevision });
	}
    return browserEffect(ownerDid, w => w.fetchNewMessages(conversationId) as Promise<Message[]>);
}

export async function sendReaction(
	conversationId: string,
	messageId: string,
	emoji: string,
	action: 'add' | 'remove',
    ownerDid?: string, ownerRevision?: string
): Promise<void> {
    if (!isTauri) effectOwner(ownerDid, ownerRevision);
	if (isTauri) {
		return tauriInvoke('send_reaction', { conversationId, messageId, emoji, action, ownerDid: effectOwner(ownerDid), ownerRevision });
	}
    return browserEffect(ownerDid, w => w.sendReaction(conversationId, messageId, emoji, action) as Promise<void>);
}

export async function sendTyping(conversationId: string, isTyping: boolean): Promise<void> {
	if (isTauri) {
		return tauriInvoke('send_typing', { conversationId, isTyping });
	}
	const w = getWorker();
	return w.sendTyping(conversationId, isTyping) as Promise<void>;
}

export async function updateCursor(conversationId: string, cursor: string, ownerDid?: string, ownerRevision?: string): Promise<void> {
    if (!isTauri) effectOwner(ownerDid, ownerRevision);
	if (isTauri) {
		return tauriInvoke('update_cursor', { conversationId, cursor, ownerDid: effectOwner(ownerDid), ownerRevision });
	}
    return browserEffect(ownerDid, w => w.updateCursor(conversationId, cursor) as Promise<void>);
}

// ---------------------------------------------------------------------------
// Members
// ---------------------------------------------------------------------------

export async function addGroupMembers(conversationId: string, memberDids: string[], ownerDid?: string, ownerRevision?: string): Promise<void> {
    if (!isTauri) effectOwner(ownerDid, ownerRevision);
    const expectedOwner = effectOwner(ownerDid);
	if (isTauri) {
		return tauriInvoke('add_group_members', { conversationId, memberDids , ownerDid: expectedOwner, ownerRevision });
	}
    return browserEffect(expectedOwner, async (w, check) => {
	return w.addGroupMembers(conversationId, memberDids) as Promise<void>;

    });
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
, ownerDid?: string, ownerRevision?: string): Promise<void> {
    if (!isTauri) effectOwner(ownerDid, ownerRevision);
    const expectedOwner = effectOwner(ownerDid);
	if (isTauri) {
		return tauriInvoke('remove_group_member', { conversationId, targetDid , ownerDid: expectedOwner, ownerRevision });
	}
    return browserEffect(expectedOwner, async (w, check) => {
	return w.removeParticipants(conversationId, targetDid) as Promise<void>;

    });
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
	const { messages } = await import('$lib/stores/messages');
	const { conversations } = await import('$lib/stores/conversations');
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
, ownerDid?: string, ownerRevision?: string): Promise<unknown> {
    if (!isTauri) effectOwner(ownerDid, ownerRevision);
    const expectedOwner = effectOwner(ownerDid);
	if (isTauri) {
		return null;
	}
    return browserEffect(expectedOwner, async (w, check) => {
	return (w as unknown as {
		republishMetadataAfterReset: (g: string, r?: number) => Promise<unknown>;
	}).republishMetadataAfterReset(newGroupIdHex, resetGeneration);

    });
}

export async function leaveConversation(conversationId: string, ownerDid?: string, ownerRevision?: string): Promise<void> {
    if (!isTauri) effectOwner(ownerDid, ownerRevision);
    const expectedOwner = effectOwner(ownerDid);
	if (isTauri) {
		return tauriInvoke('leave_conversation', { conversationId , ownerDid: expectedOwner, ownerRevision });
	}
    return browserEffect(expectedOwner, async (w, check) => {
	return w.leaveConversation(conversationId) as Promise<void>;

    });
}

export async function updateGroupMetadata(
	conversationId: string,
	name?: string,
	description?: string,
	avatarHash?: string,
	avatarBlobLocator?: string,
	avatarContentType?: string
, ownerDid?: string, ownerRevision?: string): Promise<void> {
    if (!isTauri) effectOwner(ownerDid, ownerRevision);
    const expectedOwner = effectOwner(ownerDid);
	if (isTauri) {
		// Tauri now uses Phase A.2 encrypted update — accepts avatar
		// locator + content-type, not a content-addressed hash. Old
		// callers passing only `avatarHash` get null avatar fields
		// (rename / description still work; avatar must be uploaded
		// via a separate flow once available on desktop).
		void avatarHash;
		return tauriInvoke('update_group_metadata', { ownerDid: expectedOwner,
			conversationId,
			name,
			description,
			avatarBlobLocator: avatarBlobLocator ?? null,
			avatarContentType: avatarContentType ?? null, ownerRevision
		});
	}
    return browserEffect(expectedOwner, async (w, check) => {
	// MLS metadata cutover: WASM `update_group_metadata` takes the richer
	// (title, description, avatarBlobLocator, avatarContentType, avatarBytes)
	// shape. The legacy `avatarHash` arg was a content-addressed locator hint
	// that's no longer meaningful — the encrypted blob path uses fresh UUID
	// locators per upload. We pass it through as the locator so callers
	// that still send a hash work, but new callers should pass the avatar
	// bytes directly via the worker `updateGroupMetadata` method.
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

    });
}

// ---------------------------------------------------------------------------
// Group Reset
// ---------------------------------------------------------------------------

export async function resetGroup(
	conversationId: string,
	reason?: string
, ownerDid?: string, ownerRevision?: string): Promise<Record<string, unknown>> {
    if (!isTauri) effectOwner(ownerDid, ownerRevision);
    const expectedOwner = effectOwner(ownerDid);
	if (isTauri) {
		return tauriInvoke('reset_group', { conversationId, reason , ownerDid: expectedOwner, ownerRevision });
	}
    return browserEffect(expectedOwner, async (w, check) => {
	const saved = readBrowserAuth();
	if (!saved) throw new Error('Not authenticated');
	const requestJson = JSON.stringify({
		convoId: conversationId,
		reason: reason ?? undefined
	});
	const prepared = (await w.prepareSignedRequest(
		'requestReset',
		requestJson
	)) as PreparedGatewayRequest;
	check();
	const resp = await submitPreparedRequest(prepared, saved.did);
	if (resp.status < 200 || resp.status >= 300) {
		throw new Error(`Reset group failed: ${resp.status} ${resp.body}`);
	}
	return resp.body ? JSON.parse(resp.body) : {};

    });
}

// ---------------------------------------------------------------------------
// Spam Reporting
// ---------------------------------------------------------------------------

export async function reportSpam(
	conversationId: string,
	reportedDid: string,
	reason?: string
, ownerDid?: string, ownerRevision?: string): Promise<void> {
    if (!isTauri) effectOwner(ownerDid, ownerRevision);
    const expectedOwner = effectOwner(ownerDid);
	if (isTauri) {
		return tauriInvoke('report_spam', { conversationId, reportedDid, reason , ownerDid: expectedOwner, ownerRevision });
	}
    return browserEffect(expectedOwner, async (w, check) => {
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

    });
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
export async function createBlock(targetDid: string, ownerDid?: string, ownerRevision?: string): Promise<void> {
    if (!isTauri) effectOwner(ownerDid, ownerRevision);
    const expectedOwner = effectOwner(ownerDid);
	if (isTauri) {
		await tauriInvoke<string>('create_block', { subjectDid: targetDid , ownerDid: expectedOwner, ownerRevision });
		return;
	}
    return browserEffect(expectedOwner, async (w, check) => {
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

    });
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
 * browser quarantine presentation adapter has not yet been connected.
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
export async function confirmManualReset(conversationId: string, ownerDid?: string, ownerRevision?: string): Promise<void> {
    if (!isTauri) effectOwner(ownerDid, ownerRevision);
    const expectedOwner = effectOwner(ownerDid);
	if (isTauri) {
		return tauriInvoke('confirm_manual_reset', { conversationId , ownerDid: expectedOwner, ownerRevision });
	}
    return browserEffect(expectedOwner, async (w, check) => {
	throw new Error('confirmManualReset is not yet implemented in browser builds');

    });
}

// Request provider parity is a separate qualification gate. Never route a v2
// request to legacy browser create/send or persist its plaintext in web storage.
export const requestBackendAvailable = isTauri;
async function requestInvoke<T>(command: string, args: Record<string, unknown>): Promise<T> {
	if (isTauri) return tauriInvoke<T>(command, args);
	effectOwner(args.ownerDid as string, args.ownerRevision as string | undefined);
	const { ownerRevision: _nativeRevision, ...browserArgs } = args;
	return browserEffect(args.ownerDid as string, w => w.requestCommand(command, browserArgs) as Promise<T>);
}
export async function getRequestWorkspace(ownerDid: string, ownerRevision?: string): Promise<import('./request-types').RequestWorkspace> {
    if (!isTauri) effectOwner(ownerDid, ownerRevision);
	return requestInvoke('get_request_workspace', { ownerDid, ownerRevision });
}
export async function saveRequestDraft(ownerDid: string, input: import('./request-types').DirectRequestInput, recipientLabel: string, ownerRevision?: string): Promise<import('./request-types').RequestDraft> {
    if (!isTauri) effectOwner(ownerDid, ownerRevision);
	return requestInvoke('save_request_draft', { ownerDid, input, recipientLabel, ownerRevision });
}
export async function submitRequestDraft(ownerDid: string, draftId: string, ownerRevision?: string): Promise<import('./request-types').RequestDraft> {
    if (!isTauri) effectOwner(ownerDid, ownerRevision);
	return requestInvoke('submit_request_draft', { ownerDid, draftId, ownerRevision });
}
export async function resumeRequestDraft(ownerDid: string, draftId: string, ownerRevision?: string): Promise<import('./request-types').RequestDraft> {
    if (!isTauri) effectOwner(ownerDid, ownerRevision);
	return requestInvoke('resume_request_draft', { ownerDid, draftId, ownerRevision });
}
export async function cancelRequestDraft(ownerDid: string, draftId: string, ownerRevision?: string): Promise<import('./request-types').RequestDraft> {
    if (!isTauri) effectOwner(ownerDid, ownerRevision);
	return requestInvoke('cancel_request_draft', { ownerDid, draftId, ownerRevision });
}
export async function refreshDirectRequest(ownerDid: string, conversationId: string, ownerRevision?: string): Promise<import('./request-types').DirectRequestView> {
    if (!isTauri) effectOwner(ownerDid, ownerRevision);
	return requestInvoke('refresh_direct_request', { ownerDid, conversationId, ownerRevision });
}
export async function acceptDirectRequest(ownerDid: string, conversationId: string, ownerRevision?: string): Promise<import('./request-types').DirectRequestView> {
    if (!isTauri) effectOwner(ownerDid, ownerRevision);
	return requestInvoke('accept_direct_request', { ownerDid, conversationId, ownerRevision });
}

export const setRequestDeliveryEnabled = (ownerDid: string, enabled: boolean, ownerRevision?: string) => requestInvoke<void>('set_request_delivery_enabled', { ownerDid, enabled, ownerRevision });

export const closeDirectRequest = (ownerDid: string, conversationId: string, ownerRevision?: string) => requestInvoke<import('./request-types').DirectRequestView>('close_direct_request', { ownerDid, conversationId, ownerRevision });
export async function blockRequestSender(ownerDid: string, conversationId: string, ownerRevision?: string): Promise<void> {
    if (!isTauri) effectOwner(ownerDid, ownerRevision);
	if (isTauri) return requestInvoke<void>('block_request_sender', { ownerDid, conversationId, ownerRevision });
	await browserEffect(ownerDid, async (w, check) => {
		const sender = await requestInvoke<string>('request_sender', { ownerDid, conversationId, ownerRevision });
		check();
		await createBlock(sender, ownerDid);
	});
}

export const getGroupInvitationReference = (ownerDid: string, conversationId: string, recipientDid: string, ownerRevision?: string) => requestInvoke<import('./request-types').GroupInvitationReference | null>('get_group_invitation_reference', { ownerDid, conversationId, recipientDid, ownerRevision });

export async function sendExistingInvitationNote(ownerDid: string, draftId: string, ownerRevision?: string): Promise<import('./request-types').RequestDraft> {
    if (!isTauri) effectOwner(ownerDid, ownerRevision);
	return requestInvoke('send_existing_invitation_note', { ownerDid, draftId, ownerRevision });
}

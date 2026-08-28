/**
 * catmos WASM bridge — Unified API surface for Tauri desktop and browser WASM.
 *
 * Detects runtime environment via `__TAURI_INTERNALS__` on window.
 * - Tauri desktop: routes calls through `@tauri-apps/api/core` invoke()
 * - Browser: routes calls through a Web Worker (comlink) so that WASM gets
 *   OPFS Synchronous Access Handle for MLS SQLite crypto.
 *
 * Session credentials (did, token) live in sessionStorage
 * on the main thread (cleared on tab close to limit XSS exposure).
 * MLS DB encryption key and content root key live exclusively in durable localStorage
 * and are bound to the DID-scoped CleanStorageRecord.
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
	clearAllCursorsForDid,
	setAuthoritativeActiveDid,
	clearAuthoritativeActiveDid
} from './stores/cursors';
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
let _rawWorker: Worker | null = null;

function getWorker(): Remote<WorkerApi> {
	if (!_worker) {
		_rawWorker = new Worker(new URL('./mls-worker.ts', import.meta.url), { type: 'module' });
		_worker = wrap<WorkerApi>(_rawWorker);
	}
	return _worker;
}

/** Terminate the MLS worker and drop both handles. */
function terminateWorker(): void {
	_rawWorker?.terminate();
	_rawWorker = null;
	_worker = null;
}

// ---------------------------------------------------------------------------
// Clean storage constants & generation derivation
// ---------------------------------------------------------------------------

export const CLEAN_STORAGE_GENERATION_TOKEN = 'mls-state-clean-v2-openmls-v09';
export const CLEAN_STORAGE_SUFFIX = '-clean-v2-openmls-v09';
export const STORAGE_PREFIX = `catbird_mls${CLEAN_STORAGE_SUFFIX}`;
export const DB_PREFIX = `catbird-mls${CLEAN_STORAGE_SUFFIX}`;
export const MLS_DB_KEY_PREFIX = `${STORAGE_PREFIX}_mls_db_key`;
export const INIT_RECORD_PREFIX = `${STORAGE_PREFIX}_init_record`;
export const SS_ACTIVE_DID = `catbird_mls_active_did${CLEAN_STORAGE_SUFFIX}`;
export const CONTENT_ROOT_PREFIX = 'mls.content.root.';

export interface CleanStorageRecord {
	generation: string;
	normalizedDid: string;
	didDigest: string;
	storagePrefix: string;
	dbPrefix: string;
	dbIdentity: string;
	mlsDbKeyLabel: string;
	mlsDbKeyVerifier: string;
	contentRootKeyLabel: string;
	contentRootKeyVerifier: string;
	creatorToken: string;
	state: 'creating' | 'complete';
	createdAt: number;
	completedAt?: number;
}

/** Return a per-DID namespaced key for browser storage. */
export function didKey(did: string, suffix: string): string {
	return `catbird_mls:${did}:${suffix}${CLEAN_STORAGE_SUFFIX}`;
}

export async function sha256Hex(input: string): Promise<string> {
	const bytes = new TextEncoder().encode(input);
	const digest = await crypto.subtle.digest('SHA-256', bytes);
	return Array.from(new Uint8Array(digest))
		.map((b) => b.toString(16).padStart(2, '0'))
		.join('');
}

export async function sha256HexBytes(bytes: Uint8Array): Promise<string> {
	const digest = await crypto.subtle.digest('SHA-256', bytes as BufferSource);
	return Array.from(new Uint8Array(digest))
		.map((b) => b.toString(16).padStart(2, '0'))
		.join('');
}

export async function contentRootStorageKey(userDid: string): Promise<string> {
	const normalizedDid = userDid.trim();
	return `${CONTENT_ROOT_PREFIX}${await sha256Hex(normalizedDid)}${CLEAN_STORAGE_SUFFIX}`;
}

export async function deriveDidStorageCoordinates(did: string): Promise<{
	normalizedDid: string;
	didDigest: string;
	storagePrefix: string;
	dbPrefix: string;
	dbIdentity: string;
	recordKey: string;
	mlsDbKeyLabel: string;
	contentRootKeyLabel: string;
	cursorRegistryKey: string;
}> {
	const normalizedDid = did.trim();
	const didDigest = await sha256Hex(normalizedDid);
	const storagePrefix = `catbird_mls_${didDigest}${CLEAN_STORAGE_SUFFIX}`;
	const dbPrefix = `catbird-mls-${didDigest}${CLEAN_STORAGE_SUFFIX}`;
	const dbIdentity = `${dbPrefix}-app.db`;
	const recordKey = didKey(normalizedDid, 'init_record');
	const mlsDbKeyLabel = didKey(normalizedDid, 'mls_db_key');
	const contentRootKeyLabel = `${CONTENT_ROOT_PREFIX}${didDigest}${CLEAN_STORAGE_SUFFIX}`;
	const cursorRegistryKey = didKey(normalizedDid, 'cursor_registry');

	return {
		normalizedDid,
		didDigest,
		storagePrefix,
		dbPrefix,
		dbIdentity,
		recordKey,
		mlsDbKeyLabel,
		contentRootKeyLabel,
		cursorRegistryKey
	};
}

async function withDidLock<T>(normalizedDid: string, fn: () => Promise<T>): Promise<T> {
	if (typeof navigator === 'undefined' || !navigator.locks) {
		throw new Error(
			'Web Locks API is required for browser MLS storage coordination; fail closed without mutation'
		);
	}
	const didDigest = await sha256Hex(normalizedDid);
	const lockName = `catbird_mls_init_lock_${didDigest}${CLEAN_STORAGE_SUFFIX}`;
	return new Promise<T>((resolve, reject) => {
		navigator.locks.request(lockName, { mode: 'exclusive' }, async () => {
			try {
				const res = await fn();
				resolve(res);
			} catch (err) {
				reject(err);
			}
		});
	});
}

let _activeDid: string | null = null;
let _lastAttemptedDid: string | null = null;
let _initializedDid: string | null = null;

export async function ensureMlsInitialized(did: string): Promise<void> {
	if (isTauri) return;
	const coords = await deriveDidStorageCoordinates(did);
	const {
		normalizedDid,
		recordKey,
		mlsDbKeyLabel,
		contentRootKeyLabel,
		storagePrefix,
		dbPrefix,
		dbIdentity,
		didDigest
	} = coords;

	_lastAttemptedDid = normalizedDid;

	await withDidLock(normalizedDid, async () => {
		const rawRecord = typeof window !== 'undefined' ? localStorage.getItem(recordKey) : null;
		let record: CleanStorageRecord | null = null;
		if (rawRecord !== null) {
			try {
				record = JSON.parse(rawRecord) as CleanStorageRecord;
			} catch {
				throw new Error(
					'Clean storage invalid initialization record format; explicit reset required'
				);
			}
		}

		if (record) {
			if (record.state === 'creating') {
				throw new Error(
					'Clean storage initialization incomplete (creating marker present); explicit reset required'
				);
			}
			if (record.state === 'complete') {
				if (
					record.generation !== CLEAN_STORAGE_GENERATION_TOKEN ||
					record.normalizedDid !== normalizedDid ||
					record.didDigest !== didDigest ||
					record.storagePrefix !== storagePrefix ||
					record.dbPrefix !== dbPrefix ||
					record.dbIdentity !== dbIdentity ||
					record.mlsDbKeyLabel !== mlsDbKeyLabel ||
					record.contentRootKeyLabel !== contentRootKeyLabel ||
					!record.mlsDbKeyVerifier ||
					typeof record.mlsDbKeyVerifier !== 'string' ||
					!record.contentRootKeyVerifier ||
					typeof record.contentRootKeyVerifier !== 'string' ||
					!record.creatorToken ||
					typeof record.creatorToken !== 'string' ||
					typeof record.createdAt !== 'number' ||
					record.state !== 'complete'
				) {
					throw new Error('Clean storage record binding mismatch; explicit reset required');
				}
				const dbKey =
					typeof window !== 'undefined' ? localStorage.getItem(record.mlsDbKeyLabel) : null;
				if (!dbKey || dbKey.length !== 64 || !/^[0-9a-fA-F]{64}$/.test(dbKey)) {
					throw new Error(
						'Clean storage mixed state: complete record but missing or invalid key material; explicit reset required'
					);
				}
				const computedDbKeyVerifier = await sha256Hex(dbKey);
				if (computedDbKeyVerifier !== record.mlsDbKeyVerifier) {
					throw new Error(
						'Clean storage mixed state: database key verifier mismatch; explicit reset required'
					);
				}

				const contentRootB64 =
					typeof window !== 'undefined'
						? localStorage.getItem(record.contentRootKeyLabel)
						: null;
				if (!contentRootB64) {
					throw new Error(
						'Clean storage mixed state: complete record but missing content root key; explicit reset required'
					);
				}
				let contentRootBytes: Uint8Array;
				try {
					contentRootBytes = Uint8Array.from(atob(contentRootB64), (c) => c.charCodeAt(0));
				} catch {
					throw new Error(
						'Clean storage corrupted content root key: fail closed without mutation'
					);
				}
				if (contentRootBytes.length !== 32) {
					throw new Error(`Invalid content root key length: ${contentRootBytes.length}`);
				}
				const computedCrVerifier = await sha256HexBytes(contentRootBytes);
				if (computedCrVerifier !== record.contentRootKeyVerifier) {
					throw new Error(
						'Clean storage mixed state: content root key verifier mismatch; explicit reset required'
					);
				}

				const w = getWorker();
				await w.init({
					baseUrl: NEST_URL,
					storagePrefix: record.storagePrefix,
					dbPrefix: record.dbPrefix,
					mlsDbKey: dbKey,
					initRecord: 'complete',
					actorDid: normalizedDid,
					boundDid: normalizedDid,
					record
				});

				await w.setContentRootKey(contentRootBytes);
				_initializedDid = normalizedDid;
				_activeDid = normalizedDid;
				return;
			}
			throw new Error(`Clean storage invalid initialization record state: ${(record as CleanStorageRecord).state}`);
		}

		// Record absent: verify no orphaned keys exist
		const existingDbKey =
			typeof window !== 'undefined' ? localStorage.getItem(mlsDbKeyLabel) : null;
		if (existingDbKey !== null) {
			throw new Error(
				'Clean storage mixed state: key material exists without initialization record; explicit reset required'
			);
		}
		const existingCrKey =
			typeof window !== 'undefined' ? localStorage.getItem(contentRootKeyLabel) : null;
		if (existingCrKey !== null) {
			throw new Error(
				'Clean storage mixed state: content root key exists without initialization record; explicit reset required'
			);
		}

		// Read-only preflight probe in worker BEFORE any localStorage/key mutation
		const w = getWorker();
		await w.probeFreshCreation(storagePrefix, dbPrefix);

		// Fresh first creation
		const creatorToken = crypto.randomUUID();

		const dbKeyBytes = new Uint8Array(32);
		crypto.getRandomValues(dbKeyBytes);
		const dbKey = Array.from(dbKeyBytes)
			.map((b) => b.toString(16).padStart(2, '0'))
			.join('');

		const contentRootBytes = new Uint8Array(32);
		crypto.getRandomValues(contentRootBytes);
		const contentRootB64 = btoa(String.fromCharCode(...contentRootBytes));

		const mlsDbKeyVerifier = await sha256Hex(dbKey);
		const contentRootKeyVerifier = await sha256HexBytes(contentRootBytes);

		const newRecord: CleanStorageRecord = {
			generation: CLEAN_STORAGE_GENERATION_TOKEN,
			normalizedDid,
			didDigest,
			storagePrefix,
			dbPrefix,
			dbIdentity,
			mlsDbKeyLabel,
			mlsDbKeyVerifier,
			contentRootKeyLabel,
			contentRootKeyVerifier,
			creatorToken,
			state: 'creating',
			createdAt: Date.now()
		};

		if (typeof window !== 'undefined') {
			localStorage.setItem(recordKey, JSON.stringify(newRecord));
			localStorage.setItem(mlsDbKeyLabel, dbKey);
			localStorage.setItem(contentRootKeyLabel, contentRootB64);
		}

		await w.init({
			baseUrl: NEST_URL,
			storagePrefix,
			dbPrefix,
			mlsDbKey: dbKey,
			initRecord: 'creating',
			creatorToken,
			actorDid: normalizedDid,
			boundDid: normalizedDid,
			record: newRecord
		});

		await w.setContentRootKey(contentRootBytes);

		newRecord.state = 'complete';
		newRecord.completedAt = Date.now();
		if (typeof window !== 'undefined') {
			localStorage.setItem(recordKey, JSON.stringify(newRecord));
		}

		_initializedDid = normalizedDid;
		_activeDid = normalizedDid;
	});
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
 * Initialize the WASM Worker with MLS config and verify clean storage.
 */
export async function initWasm(did?: string): Promise<void> {
	if (isTauri) return;
	if (did) {
		await ensureMlsInitialized(did);
		return;
	}
	const saved = readBrowserAuth();
	if (saved?.did) {
		await ensureMlsInitialized(saved.did);
		return;
	}
	getWorker();
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
	const { hostname, port } = window.location;
	let callbackBase: string;
	if (hostname === 'localhost' || hostname === '127.0.0.1') {
		callbackBase = `http://127.0.0.1:${port || '80'}`;
	} else {
		callbackBase = window.location.origin;
	}
	const redirectTo = `${callbackBase}/auth/callback`;
	const loginUrl =
		`${NEST_URL}/auth/login` +
		`?identifier=${encodeURIComponent(identifier)}` +
		`&client=catmos` +
		`&redirect_to=${encodeURIComponent(redirectTo)}`;
	window.location.href = loginUrl;
}

export async function completeLogin(sessionId: string): Promise<AuthState> {
	if (isTauri) {
		const state = await tauriInvoke<AuthState>('complete_login', { sessionId });
		setAuthoritativeActiveDid(state.did);
		return state;
	}
	const resp = await fetch(`${NEST_URL}/auth/session`, {
		headers: { Authorization: `Bearer ${sessionId}` }
	});
	if (!resp.ok) throw new Error(`Failed to fetch session: ${resp.status}`);
	const info = await resp.json();
	const did: string = info.did;
	const handle: string = info.handle ?? did;

	// Ensure MLS DB is initialized under Web Lock for this DID
	await ensureMlsInitialized(did);

	// Push credentials to Worker and run MLS setup
	const w = getWorker();
	await w.setAuth(did, sessionId);
	await w.setup();

	// Persist session on main thread only after clean init & setup succeed
	persistBrowserAuth(did, sessionId);
	replenishKeyPackages();
	startKeyPackageReplenishment();

	return { did, handle };
}

/**
 * Set auth credentials for the WASM MLS module.
 * Called by catmos's auth store after completing OAuth.
 */
export async function setAuth(did: string, token: string): Promise<void> {
	if (isTauri) return;
	await ensureMlsInitialized(did);
	const w = getWorker();
	await w.setAuth(did, token);
	persistBrowserAuth(did, token);
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
	await getWorker().clearAuth();
	clearBrowserAuth();
}

export async function tryRestoreSession(): Promise<AuthState | null> {
	if (isTauri) {
		const state = await tauriInvoke<AuthState | null>('try_restore_session');
		if (state?.did) {
			setAuthoritativeActiveDid(state.did);
		} else {
			clearAuthoritativeActiveDid();
		}
		return state;
	}
	const saved = readBrowserAuth();
	if (!saved) return null;
	const { did, sessionId } = saved;

	try {
		const resp = await fetch(`${NEST_URL}/auth/session`, {
			headers: { Authorization: `Bearer ${sessionId}` }
		});
		if (!resp.ok) {
			if (resp.status === 401 || resp.status === 403) {
				clearBrowserAuth();
				return null;
			}
			throw new Error(`Failed to restore session: ${resp.status}`);
		}
		const info = await resp.json();

		// Ensure MLS DB is initialized under Web Lock for this DID
		await ensureMlsInitialized(info.did);

		// Push restored credentials to Worker
		const w = getWorker();
		await w.setAuth(info.did, sessionId);
		await w.setup();

		// Replenish key packages (setup skips upload on returning sessions)
		replenishKeyPackages();
		startKeyPackageReplenishment();

		return { did: info.did, handle: info.handle ?? info.did };
	} catch (error) {
		throw error;
	}
}

export async function logout(): Promise<void> {
	if (isTauri) {
		clearAuthoritativeActiveDid();
		return tauriInvoke('logout');
	}

	const restartReplenishmentOnFailure = stopKeyPackageReplenishment();

	try {
		if (_worker) await _worker.clearAuth();
	} catch (error) {
		if (restartReplenishmentOnFailure) startKeyPackageReplenishment();
		throw error;
	}

	clearAuthoritativeActiveDid();
	clearBrowserAuth();
	terminateWorker();
	_activeDid = null;
	_initializedDid = null;
}

/**
 * Explicit reset of Clean Chat / OpenMLS 0.9 browser storage.
 * Awaits worker reset & OPFS database unlink, terminates the worker,
 * clears exact clean keys for the bound DID, and deletes the initialization record marker last.
 */
export async function resetCleanStorage(did?: string): Promise<void> {
	if (isTauri) return;

	const restartReplenishmentOnFailure = stopKeyPackageReplenishment();

	const targetDid =
		did ??
		_lastAttemptedDid ??
		_activeDid ??
		readBrowserAuth()?.did ??
		(typeof window !== 'undefined' ? sessionStorage.getItem(SS_ACTIVE_DID) : null);
	if (!targetDid) {
		terminateWorker();
		_activeDid = null;
		_initializedDid = null;
		return;
	}

	const {
		normalizedDid,
		recordKey,
		mlsDbKeyLabel,
		contentRootKeyLabel,
		storagePrefix,
		dbPrefix
	} = await deriveDidStorageCoordinates(targetDid);

	await withDidLock(normalizedDid, async () => {
		// Reset is the gate: a busy Rust database lease rejects before auth,
		// content-key, signer, or OPFS state is changed.
		const w = getWorker();
		try {
			await w.resetCleanStorage({
				storagePrefix,
				dbPrefix,
				boundDid: normalizedDid
			});
		} catch (error) {
			if (restartReplenishmentOnFailure) startKeyPackageReplenishment();
			throw error;
		}

		terminateWorker();

		// Delete exact keys for this DID ONLY
		if (typeof window !== 'undefined') {
			localStorage.removeItem(contentRootKeyLabel);
			localStorage.removeItem(mlsDbKeyLabel);
			localStorage.removeItem(didKey(normalizedDid, 'session_id'));
			sessionStorage.removeItem(didKey(normalizedDid, 'session_id'));
			sessionStorage.removeItem(didKey(normalizedDid, 'mls_db_key'));

			// Exact cursor cleanup via cursor registry (no Storage enumeration)
			clearAllCursorsForDid(normalizedDid);

			if (sessionStorage.getItem(SS_ACTIVE_DID) === normalizedDid) {
				sessionStorage.removeItem(SS_ACTIVE_DID);
			}

			// Remove initialization record marker LAST
			localStorage.removeItem(recordKey);
		}

		if (_lastAttemptedDid === normalizedDid) {
			_lastAttemptedDid = null;
		}
		if (_activeDid === normalizedDid) {
			_activeDid = null;
		}
		if (_initializedDid === normalizedDid) {
			_initializedDid = null;
		}
	});
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

/** Stop periodic replenishment; returns whether it had been running. */
function stopKeyPackageReplenishment(): boolean {
	if (!_replenishInterval) return false;
	clearInterval(_replenishInterval);
	_replenishInterval = null;
	return true;
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

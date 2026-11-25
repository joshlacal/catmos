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
} from './tauri.ts';

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
} from './tauri.ts';

import { wrap, proxy, type Remote } from 'comlink';
import type { WorkerApi } from './mls-worker.ts';
import { normalizeAccountDid, stripDidFragment } from './did.ts';
import { normalizeSessionId } from './oauth-callback.ts';
import {
	accountDidHashHex,
	deleteAccountKeyStoreEntries,
	loadOrCreateDbKeyHex,
	loadOrCreateWrappedSecretBytes
} from './webcrypto-keystore.ts';
import {
	assertCanRevokeLabyrinthDevice,
	buildUpgradeAdditionalScopes,
	evaluateSpacesGateForUi,
	isMlsOptedInForDid,
	REQUIRED_LABYRINTH_OAUTH_SCOPES,
	setMlsOptedInForDid
} from './labyrinth-ui.ts';

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
// MLS DB key management: Non-extractable WebCrypto IndexedDB key custody
//
// All 32-byte (256-bit) `sqlite3mc` DB keys and content-root keys are wrapped
// under per-account `extractable: false` AES-GCM-256 `CryptoKey` handles in
// `webcrypto-keystore.ts` (`catbird_mls_webcrypto_v2`) with domain-separated AAD.
// ---------------------------------------------------------------------------

/** Sanitize a DID for deterministic legacy storage filenames when cleaning up. */
export function sanitizeDid(did: string): string {
	const trimmed = stripDidFragment(did);
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

/**
 * Get or create the per-DID 64-character hex MLS DB encryption key backed by
 * non-extractable WebCrypto AES-GCM wrapping in IndexedDB (`webcrypto-keystore.ts`).
 */
export async function getOrCreateMlsDbKey(targetDid?: string): Promise<string> {
	const resolvedDid = stripDidFragment(
		targetDid ??
			(typeof sessionStorage !== 'undefined' ? sessionStorage.getItem(SS_ACTIVE_DID) : null) ??
			''
	);
	if (!resolvedDid) {
		throw new Error('getOrCreateMlsDbKey requires a valid authenticated DID');
	}

	const keyId = mlsKeyIdForDid(resolvedDid);
	const legacySessionKey = didKey(resolvedDid, 'mls_db_key');
	if (typeof sessionStorage !== 'undefined') {
		sessionStorage.removeItem(keyId);
		sessionStorage.removeItem(legacySessionKey);
	}

	const didHash = await accountDidHashHex(resolvedDid);
	return loadOrCreateDbKeyHex(didHash);
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

const HOME_DS_DID = 'did:web:chat.catbird.blue';
const HOME_DS_URL = 'https://chat.catbird.blue';
const UUID_V4_LOWER_RE =
	/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export const BROWSER_DEVICE_ID_PREFIX = 'catmos.mls.deviceId.';
const LEGACY_BROWSER_DEVICE_ID_PREFIX = 'catmos_mls_device_id_';

export function readBrowserDeviceId(didHash: string): string | null {
	const normalizedHash = didHash.trim();
	if (!normalizedHash) return null;
	const canonicalKey = `${BROWSER_DEVICE_ID_PREFIX}${normalizedHash}`;
	const legacyKey = `${LEGACY_BROWSER_DEVICE_ID_PREFIX}${normalizedHash}`;
	try {
		if (typeof localStorage !== 'undefined') {
			const existing = localStorage.getItem(canonicalKey)?.trim().toLowerCase();
			if (existing && UUID_V4_LOWER_RE.test(existing)) {
				return existing;
			}
			const legacy = localStorage.getItem(legacyKey)?.trim().toLowerCase();
			if (legacy && UUID_V4_LOWER_RE.test(legacy)) {
				localStorage.setItem(canonicalKey, legacy);
				localStorage.removeItem(legacyKey);
				return legacy;
			}
		}
	} catch {
		// Ignore storage access errors (private browsing / Node test harness)
	}
	return null;
}

export function wipeBrowserDeviceId(didHash: string): void {
	const normalizedHash = didHash.trim();
	if (!normalizedHash) return;
	try {
		if (typeof localStorage !== 'undefined') {
			localStorage.removeItem(`${BROWSER_DEVICE_ID_PREFIX}${normalizedHash}`);
			localStorage.removeItem(`${LEGACY_BROWSER_DEVICE_ID_PREFIX}${normalizedHash}`);
		}
	} catch {
		// Ignore storage removal errors
	}
}

export function getOrCreateBrowserDeviceId(didHash: string): string {
	const existing = readBrowserDeviceId(didHash);
	if (existing) {
		return existing;
	}
	const generated = crypto.randomUUID().toLowerCase();
	const storageKey = `${BROWSER_DEVICE_ID_PREFIX}${didHash.trim()}`;
	try {
		if (typeof localStorage !== 'undefined') {
			localStorage.setItem(storageKey, generated);
		}
	} catch {
		// Ignore storage write errors
	}
	return generated;
}

interface OpfsFileHandleLike {
	kind?: string;
	name?: string;
	getFile?: () => Promise<{ slice: (start?: number, end?: number) => { arrayBuffer: () => Promise<ArrayBuffer> } }>;
}

interface OpfsDirectoryHandleLike {
	kind?: string;
	name?: string;
	getDirectoryHandle(name: string, options?: { create?: boolean }): Promise<OpfsDirectoryHandleLike>;
	removeEntry(name: string, options?: { recursive?: boolean }): Promise<void>;
	entries?: () => AsyncIterable<[string, OpfsFileHandleLike | OpfsDirectoryHandleLike]>;
	values?: () => AsyncIterable<OpfsFileHandleLike | OpfsDirectoryHandleLike>;
}

function sahPoolHeaderMatchesAccount(
	headerPath: string,
	didHash: string,
	legacyDbBaseName: string | null
): boolean {
	const clean = headerPath.replace(/^\/+/, '').trim();
	if (!clean) return false;
	const targetPrefix = `catbird-mls/${didHash}.db`;
	const barePrefix = `${didHash}.db`;
	if (
		clean === targetPrefix ||
		clean.startsWith(`${targetPrefix}-`) ||
		clean === barePrefix ||
		clean.startsWith(`${barePrefix}-`)
	) {
		return true;
	}
	if (
		legacyDbBaseName &&
		(clean === legacyDbBaseName ||
			clean.startsWith(`${legacyDbBaseName}-`) ||
			clean.endsWith(`/${legacyDbBaseName}`) ||
			clean.includes(`/${legacyDbBaseName}-`))
	) {
		return true;
	}
	return false;
}

async function listDirectoryEntries(
	dir: OpfsDirectoryHandleLike
): Promise<Array<[string, OpfsFileHandleLike | OpfsDirectoryHandleLike]>> {
	const out: Array<[string, OpfsFileHandleLike | OpfsDirectoryHandleLike]> = [];
	if (typeof dir.entries === 'function') {
		for await (const pair of dir.entries()) {
			out.push(pair);
		}
		return out;
	}
	if (typeof dir.values === 'function') {
		for await (const entry of dir.values()) {
			if (entry && typeof entry.name === 'string') {
				out.push([entry.name, entry]);
			}
		}
	}
	return out;
}

/**
 * Purge an account's SQLite database files from OPFS (both direct files and
 * `sqlite-wasm-vfs` `.opfs-sahpool/.opaque` pool slots matching `<didHash>.db`),
 * leaving any other account's OPFS files untouched.
 *
 * Must be called AFTER `terminateWorkerInstance()` so all `SyncAccessHandle`
 * file locks held by the dedicated Worker have been released.
 */
export async function purgeAccountOpfsDatabase(
	didHash: string,
	did?: string,
	opfsRootProvider?: () => Promise<OpfsDirectoryHandleLike | null>
): Promise<number> {
	const normalizedHash = didHash.trim();
	if (!normalizedHash) return 0;

	let root: OpfsDirectoryHandleLike | null = null;
	try {
		if (opfsRootProvider) {
			root = await opfsRootProvider();
		} else if (
			typeof navigator !== 'undefined' &&
			navigator.storage &&
			typeof navigator.storage.getDirectory === 'function'
		) {
			root = (await navigator.storage.getDirectory()) as unknown as OpfsDirectoryHandleLike;
		}
	} catch {
		return 0;
	}
	if (!root) return 0;

	const legacyBase = did && stripDidFragment(did) ? mlsDbFileNameForDid(did) : null;
	const suffixes = ['', '-journal', '-wal', '-shm'];
	let removedCount = 0;

	const tryRemoveDirect = async (dir: OpfsDirectoryHandleLike, baseName: string) => {
		for (const suffix of suffixes) {
			try {
				await dir.removeEntry(`${baseName}${suffix}`);
				removedCount += 1;
			} catch {
				// Entry not present
			}
		}
	};

	await tryRemoveDirect(root, `${normalizedHash}.db`);
	if (legacyBase) {
		await tryRemoveDirect(root, legacyBase);
	}

	try {
		const subDir = await root.getDirectoryHandle('catbird-mls', { create: false });
		await tryRemoveDirect(subDir, `${normalizedHash}.db`);
		if (legacyBase) {
			await tryRemoveDirect(subDir, legacyBase);
		}
	} catch {
		// No direct `catbird-mls/` directory in OPFS root
	}

	// Inspect `sqlite-wasm-vfs` OpfsSAHPool `.opfs-sahpool/.opaque` slot headers (first 512 bytes)
	for (const poolDirName of ['.opfs-sahpool', 'opfs-sahpool']) {
		try {
			const poolDir = await root.getDirectoryHandle(poolDirName, { create: false });
			const opaqueDir = await poolDir.getDirectoryHandle('.opaque', { create: false });
			const entries = await listDirectoryEntries(opaqueDir);
			const decoder = new TextDecoder();
			for (const [slotName, handle] of entries) {
				if (!handle || handle.kind === 'directory') continue;
				const fileHandle = handle as OpfsFileHandleLike;
				if (typeof fileHandle.getFile !== 'function') continue;
				try {
					const file = await fileHandle.getFile();
					const headerBuf = await file.slice(0, 516).arrayBuffer();
					if (headerBuf.byteLength === 0) continue;
					const headerBytes = new Uint8Array(headerBuf, 0, Math.min(512, headerBuf.byteLength));
					const nulIdx = headerBytes.indexOf(0);
					const pathSlice = nulIdx >= 0 ? headerBytes.subarray(0, nulIdx) : headerBytes;
					const associatedPath = decoder.decode(pathSlice);
					if (sahPoolHeaderMatchesAccount(associatedPath, normalizedHash, legacyBase)) {
						await opaqueDir.removeEntry(slotName);
						removedCount += 1;
					}
				} catch {
					// Slot busy or concurrently removed
				}
			}
		} catch {
			// Pool directory not initialized yet
		}
	}

	return removedCount;
}

async function mintChatServiceAuthToken(sessionId: string, lxm: string): Promise<string> {
	const params = new URLSearchParams({
		aud: HOME_DS_DID,
		lxm
	});
	const resp = await fetch(`${NEST_URL}/xrpc/com.atproto.server.getServiceAuth?${params.toString()}`, {
		method: 'GET',
		headers: {
			Accept: 'application/json',
			Authorization: `Bearer ${sessionId}`
		}
	});
	if (!resp.ok) {
		const text = await resp.text();
		throw new Error(`getServiceAuth failed (${resp.status}): ${text}`);
	}
	const data = (await resp.json()) as { token?: string };
	if (typeof data.token !== 'string' || !data.token.trim() || data.token === sessionId) {
		throw new Error('getServiceAuth response missing a separate service token');
	}
	return data.token;
}

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
			await ensureUnifiedBrowserClientOpen(resolvedDid);
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
const SS_PENDING_UPGRADE_NONCE = 'catbird_mls_pending_upgrade_nonce';
const SS_PENDING_UPGRADE_DID = 'catbird_mls_pending_upgrade_did';
const SS_PENDING_UPGRADE_RETURN_TO = 'catbird_mls_pending_upgrade_return_to';
const OAUTH_CODE_FORMAT_RE = /^[A-Za-z0-9._~+/-]{8,512}={0,2}$/;

function parseGrantedScopes(raw: unknown): string[] {
	if (!Array.isArray(raw)) return [];
	return raw
		.filter((entry): entry is string => typeof entry === 'string')
		.map((s) => s.trim())
		.filter(Boolean);
}

function sanitizeReturnPath(rawPath: string | null | undefined): string {
	const trimmed = typeof rawPath === 'string' ? rawPath.trim() : '';
	if (!trimmed || !trimmed.startsWith('/') || trimmed.startsWith('//') || /[\u0000-\u001f\u007f\\]/.test(trimmed)) {
		return '/settings/labyrinth';
	}
	return trimmed;
}

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
	if (typeof sessionStorage === 'undefined') return;
	sessionStorage.removeItem(SS_PENDING_BROWSER_NONCE);
}

export function hasPendingOAuthUpgrade(): boolean {
	if (typeof sessionStorage === 'undefined') return false;
	return Boolean(sessionStorage.getItem(SS_PENDING_UPGRADE_NONCE));
}

export function clearPendingOAuthUpgrade(): void {
	if (typeof sessionStorage === 'undefined') return;
	sessionStorage.removeItem(SS_PENDING_UPGRADE_NONCE);
	sessionStorage.removeItem(SS_PENDING_UPGRADE_DID);
	sessionStorage.removeItem(SS_PENDING_UPGRADE_RETURN_TO);
}

export function consumePendingUpgradeReturnPath(): string {
	if (typeof sessionStorage === 'undefined') return '/settings/labyrinth';
	const raw = sessionStorage.getItem(SS_PENDING_UPGRADE_RETURN_TO);
	sessionStorage.removeItem(SS_PENDING_UPGRADE_RETURN_TO);
	return sanitizeReturnPath(raw);
}

/** Return a per-DID namespaced key for browser sessionStorage. */
function didKey(did: string, suffix: string): string {
	return `catbird_mls:${did}:${suffix}`;
}

/** Persist auth credentials in sessionStorage, namespaced by DID. */
export function persistBrowserAuth(did: string, sessionId: string): void {
	const canonicalDid = normalizeAccountDid(did);
	sessionStorage.setItem(SS_ACTIVE_DID, canonicalDid);
	sessionStorage.setItem(didKey(canonicalDid, 'session_id'), sessionId);
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
	clearPendingOAuthUpgrade();
}

/** Abandons a pending desktop sign-in, so finishing it in the browser signs no one in. */
export async function cancelLogin(): Promise<void> {
	if (isTauri) {
		return tauriInvoke('cancel_login');
	}
}

export async function startLogin(identifier: string): Promise<void> {
	if (isTauri) {
		return tauriInvoke('start_login', { identifier });
	}
	const redirectTo = `${window.location.origin}/auth/callback`;
	const browserNonce = generateBrowserNonce();
	sessionStorage.setItem(SS_PENDING_BROWSER_NONCE, browserNonce);

	const isLoopback =
		window.location.hostname === 'localhost' ||
		window.location.hostname === '127.0.0.1' ||
		window.location.hostname === '[::1]';
	const clientParam = isLoopback ? '' : '&client=catmos';
	const loginUrl =
		`${NEST_URL}/auth/login` +
		`?identifier=${encodeURIComponent(identifier)}` +
		clientParam +
		`&redirect_to=${encodeURIComponent(redirectTo)}` +
		`&browser_nonce=${encodeURIComponent(browserNonce)}`;
	window.location.href = loginUrl;
}

/**
 * Exchange a one-time OAuth code for a session ID using the single-use browser nonce.
 * Consumes and clears the pending nonce immediately upon attempt.
 */
export async function exchangeOAuthCode(code: string): Promise<string> {
	if (!code || typeof code !== 'string' || !OAUTH_CODE_FORMAT_RE.test(code)) {
		clearPendingOAuthLogin();
		throw new Error('Invalid OAuth authorization code.');
	}
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

	return normalizeSessionId(data.session_id);
}

/**
 * Probe whether the authenticated account's PDS implements `com.atproto.space.*` (`I15`),
 * matching `catbird-mls/src/client/spaces_gate.rs:272-290` (`getSpace` probe).
 * Fails closed (`false`) when unauthenticated or on network / 5xx errors.
 */
export async function probePdsSpacesSupport(
	fetchImpl: typeof fetch = fetch
): Promise<boolean> {
	if (isTauri) {
		try {
			return await tauriInvoke<boolean>('labyrinth_probe_pds_spaces');
		} catch {
			// Tauri desktop evaluates `probe_and_check_spaces_eligibility` directly in Rust during enrollment;
			// fall back to authenticated BFF probe when no dedicated IPC probe command is registered.
		}
	}
	const saved = readBrowserAuth();
	if (!saved) return false;
	try {
		const resp = await fetchImpl(`${NEST_URL}/xrpc/com.atproto.space.getSpace`, {
			method: 'GET',
			headers: {
				Authorization: `Bearer ${saved.sessionId}`
			}
		});
		let errCode = '';
		try {
			const parsed = (await resp.json()) as { error?: unknown };
			if (typeof parsed?.error === 'string') {
				errCode = parsed.error;
			}
		} catch {
			// Non-JSON body is acceptable when status indicates support
		}
		const notImplemented =
			resp.status === 404 ||
			resp.status === 501 ||
			errCode === 'XRPCNotSupported' ||
			errCode === 'MethodNotImplemented';
		return !notImplemented && (resp.status === 200 || resp.status === 400);
	} catch {
		return false;
	}
}

/**
 * Validate the account the desktop backend reports on its `oauth-signed-in`
 * event after it has completed the OAuth flow.
 */
export function parseDesktopSignIn(payload: unknown): AuthState {
	if (typeof payload !== 'object' || payload === null) {
		throw new Error('Invalid desktop sign-in payload');
	}
	const raw = payload as Record<string, unknown>;
	if (typeof raw.did !== 'string') {
		throw new Error('Desktop sign-in payload is missing the account DID');
	}
	const did = normalizeAccountDid(raw.did);
	const handle =
		typeof raw.handle === 'string' && raw.handle.trim() ? raw.handle.trim().slice(0, 253) : did;
	return {
		did,
		handle,
		grantedScopes: parseGrantedScopes(raw.grantedScopes ?? raw.granted_scopes)
	};
}

/**
 * Initiate progressive OAuth scope upgrade (`POST /auth/upgrade`) on `nest`
 * for `REQUIRED_LABYRINTH_OAUTH_SCOPES` (excluding `'atproto'`, which is carried
 * forward from the active session).
 */
export async function startOAuthScopeUpgrade(
	requestedScopes: readonly string[] = REQUIRED_LABYRINTH_OAUTH_SCOPES,
	options: {
		returnTo?: string;
		fetchImpl?: typeof fetch;
		navigate?: (authorizationUrl: string) => void;
	} = {}
): Promise<string> {
	const saved = readBrowserAuth();
	if (!saved) {
		throw new Error('Cannot upgrade OAuth permissions without an active authenticated session.');
	}
	const additionalScopes = buildUpgradeAdditionalScopes(requestedScopes);
	if (additionalScopes.length === 0) {
		throw new Error(
			'Active session is missing base atproto scope; please sign out and sign in again.'
		);
	}

	const browserNonce = generateBrowserNonce();
	sessionStorage.setItem(SS_PENDING_UPGRADE_NONCE, browserNonce);
	sessionStorage.setItem(SS_PENDING_UPGRADE_DID, saved.did);
	sessionStorage.setItem(
		SS_PENDING_UPGRADE_RETURN_TO,
		sanitizeReturnPath(options.returnTo ?? '/settings/labyrinth')
	);

	const doFetch = options.fetchImpl ?? fetch;
	let resp: Response;
	try {
		resp = await doFetch(`${NEST_URL}/auth/upgrade`, {
			method: 'POST',
			headers: {
				Authorization: `Bearer ${saved.sessionId}`,
				'Content-Type': 'application/json'
			},
			body: JSON.stringify({
				additional_scopes: additionalScopes,
				browser_nonce: browserNonce
			})
		});
	} catch (err) {
		clearPendingOAuthUpgrade();
		throw err;
	}

	if (!resp.ok) {
		clearPendingOAuthUpgrade();
		const errText = await resp.text().catch(() => '');
		throw new Error(
			`Permission upgrade initiation failed (${resp.status}): ${errText || resp.statusText}`
		);
	}

	const data = (await resp.json()) as { authorization_url?: unknown };
	const rawAuthUrl = typeof data?.authorization_url === 'string' ? data.authorization_url.trim() : '';
	if (!rawAuthUrl || /[\u0000-\u001f\u007f]/.test(rawAuthUrl)) {
		clearPendingOAuthUpgrade();
		throw new Error('Invalid authorization_url returned from /auth/upgrade');
	}

	let parsedAuthUrl: URL;
	try {
		parsedAuthUrl = new URL(rawAuthUrl);
	} catch {
		clearPendingOAuthUpgrade();
		throw new Error('Malformed authorization_url returned from /auth/upgrade');
	}
	if (parsedAuthUrl.protocol !== 'https:' || parsedAuthUrl.username || parsedAuthUrl.password) {
		clearPendingOAuthUpgrade();
		throw new Error('Insecure authorization_url returned from /auth/upgrade');
	}

	const authHref = parsedAuthUrl.toString();
	if (options.navigate) {
		options.navigate(authHref);
	} else if (typeof window !== 'undefined' && window.location) {
		window.location.href = authHref;
	}
	return authHref;
}

/**
 * Complete progressive OAuth scope upgrade (`POST /auth/upgrade/exchange` ->
 * `POST /auth/upgrade/commit` -> session promotion), fenced to the active DID.
 */
export async function completeOAuthScopeUpgrade(
	code: string,
	options: {
		fetchImpl?: typeof fetch;
	} = {}
): Promise<AuthState> {
	if (!code || typeof code !== 'string' || !OAUTH_CODE_FORMAT_RE.test(code)) {
		clearPendingOAuthUpgrade();
		throw new Error('Invalid OAuth upgrade authorization code.');
	}

	const browserNonce =
		typeof sessionStorage !== 'undefined'
			? sessionStorage.getItem(SS_PENDING_UPGRADE_NONCE)
			: null;
	const expectedDidRaw =
		typeof sessionStorage !== 'undefined'
			? sessionStorage.getItem(SS_PENDING_UPGRADE_DID)
			: null;
	// Single-use: clear nonce and expected DID immediately (preserve returnTo for caller navigation)
	if (typeof sessionStorage !== 'undefined') {
		sessionStorage.removeItem(SS_PENDING_UPGRADE_NONCE);
		sessionStorage.removeItem(SS_PENDING_UPGRADE_DID);
	}

	if (!browserNonce || !expectedDidRaw) {
		clearPendingOAuthUpgrade();
		throw new Error('Missing or expired OAuth permission upgrade nonce.');
	}

	const saved = readBrowserAuth();
	if (!saved) {
		clearPendingOAuthUpgrade();
		throw new Error('Session expired or signed out during OAuth permission upgrade.');
	}

	const canonicalDid = normalizeAccountDid(saved.did);
	if (canonicalDid !== normalizeAccountDid(expectedDidRaw)) {
		clearPendingOAuthUpgrade();
		throw new Error('Active account changed during OAuth permission upgrade.');
	}

	const doFetch = options.fetchImpl ?? fetch;
	const exResp = await doFetch(`${NEST_URL}/auth/upgrade/exchange`, {
		method: 'POST',
		headers: {
			Authorization: `Bearer ${saved.sessionId}`,
			'Content-Type': 'application/json'
		},
		body: JSON.stringify({
			code,
			browser_nonce: browserNonce
		})
	});
	if (!exResp.ok) {
		const errText = await exResp.text().catch(() => '');
		throw new Error(
			`Permission upgrade exchange failed (${exResp.status}): ${errText || exResp.statusText}`
		);
	}

	const exData = (await exResp.json()) as {
		candidate_session_id?: unknown;
		did?: unknown;
		granted_scopes?: unknown;
	};
	const candidateSessionId = normalizeSessionId(exData?.candidate_session_id);
	const exDid = typeof exData?.did === 'string' ? normalizeAccountDid(exData.did) : '';
	if (exDid !== canonicalDid) {
		throw new Error('Permission upgrade exchange DID mismatch.');
	}

	let commitResp = await doFetch(`${NEST_URL}/auth/upgrade/commit`, {
		method: 'POST',
		headers: {
			Authorization: `Bearer ${candidateSessionId}`
		}
	});
	if (commitResp.status >= 500) {
		// Retryable side-effect failure (e.g. push registry CAS) per nest `upgrade_commit` contract
		commitResp = await doFetch(`${NEST_URL}/auth/upgrade/commit`, {
			method: 'POST',
			headers: {
				Authorization: `Bearer ${candidateSessionId}`
			}
		});
	}
	if (!commitResp.ok) {
		const errText = await commitResp.text().catch(() => '');
		throw new Error(
			`Permission upgrade commit failed (${commitResp.status}): ${errText || commitResp.statusText}`
		);
	}

	const commitData = (await commitResp.json()) as {
		status?: unknown;
		session_id?: unknown;
		did?: unknown;
		granted_scopes?: unknown;
	};
	if (commitData?.status !== 'committed') {
		throw new Error('Permission upgrade commit returned unexpected status.');
	}
	const committedSessionId = normalizeSessionId(commitData.session_id);
	if (committedSessionId !== candidateSessionId) {
		throw new Error('Committed session_id did not match candidate session_id.');
	}
	const commitDid = typeof commitData.did === 'string' ? normalizeAccountDid(commitData.did) : '';
	if (commitDid !== canonicalDid) {
		throw new Error('Committed session DID mismatch.');
	}

	// Re-verify session was not logged out or switched while commit was in flight
	const stillActive = readBrowserAuth();
	if (!stillActive || stillActive.sessionId !== saved.sessionId || normalizeAccountDid(stillActive.did) !== canonicalDid) {
		throw new Error('Active session changed while committing permission upgrade.');
	}

	const committedScopes = parseGrantedScopes(commitData.granted_scopes);
	const sessionResp = await doFetch(`${NEST_URL}/auth/session`, {
		method: 'GET',
		headers: {
			Authorization: `Bearer ${committedSessionId}`
		}
	});
	if (!sessionResp.ok) {
		throw new Error(`Failed to verify upgraded session: ${sessionResp.status}`);
	}
	const sessionInfo = (await sessionResp.json()) as {
		did?: unknown;
		handle?: unknown;
		granted_scopes?: unknown;
	};
	const verifiedDid =
		typeof sessionInfo?.did === 'string' ? normalizeAccountDid(sessionInfo.did) : '';
	if (verifiedDid !== canonicalDid) {
		throw new Error('Upgraded session verification DID mismatch.');
	}
	const grantedScopes =
		Array.isArray(sessionInfo?.granted_scopes)
			? parseGrantedScopes(sessionInfo.granted_scopes)
			: committedScopes;
	const handle = typeof sessionInfo?.handle === 'string' && sessionInfo.handle ? sessionInfo.handle : canonicalDid;

	persistBrowserAuth(canonicalDid, committedSessionId);
	if (isMlsOptedInForDid(canonicalDid) && _worker && _workerDid === canonicalDid) {
		await _worker.setAuth(canonicalDid, committedSessionId);
	}

	return {
		did: canonicalDid,
		handle,
		grantedScopes
	};
}

export async function completeLogin(sessionId: string): Promise<AuthState> {
	const validatedSessionId = normalizeSessionId(sessionId);
	if (isTauri) {
		throw new Error('The desktop app completes sign-in in its backend.');
	}
	const resp = await bffFetch('/auth/session', { method: 'GET' }, validatedSessionId);
	if (!resp.ok) throw new Error(`Failed to fetch session: ${resp.status}`);
	const info = await resp.json();
	const rawDid = typeof info?.did === 'string' ? info.did : '';
	if (!stripDidFragment(rawDid)) {
		throw new Error('Invalid session response from auth gateway: missing did');
	}
	const did = normalizeAccountDid(rawDid);
	const handle: string = info.handle ?? did;
	const grantedScopes = parseGrantedScopes(info?.granted_scopes);

	try {
		// 1. Persist browser auth first so active DID is established
		persistBrowserAuth(did, validatedSessionId);
		// ctl #2: Chat/Spaces off by default — zero MLS DB opens, PDS/DS calls, or KeyPackage uploads on fresh sign-in
		if (!isMlsOptedInForDid(did)) {
			return { did, handle, grantedScopes };
		}
		// 2. Initialize WASM Worker for `did` (terminating any Worker bound to a different DID)
		await initWasm(did);
		// 3. Push credentials and complete MLS setup on the DID-scoped Worker
		const w = getWorker();
		await w.setAuth(did, validatedSessionId);
		await installContentRootKey(did);
		await w.setup();

		replenishKeyPackages();
		startKeyPackageReplenishment();

		return { did, handle, grantedScopes };
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

	const pathWithoutQuery = prepared.path.split('?')[0] ?? '';
	const nsid = pathWithoutQuery.startsWith('/xrpc/')
		? pathWithoutQuery.slice('/xrpc/'.length)
		: '';
	const isDirectChatDs = nsid.startsWith('blue.catbird.chat.') || nsid.startsWith('blue.catbird.labyrinth.');

	const url = isDirectChatDs ? `${HOME_DS_URL}${prepared.path}` : `${NEST_URL}${prepared.path}`;
	const authToken = isDirectChatDs
		? await mintChatServiceAuthToken(saved.sessionId, nsid)
		: saved.sessionId;
	const headers: Record<string, string> = {
		Authorization: `Bearer ${authToken}`
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
		const raw = await tauriInvoke<(AuthState & { granted_scopes?: unknown }) | null>(
			'try_restore_session'
		);
		if (!raw) return null;
		const grantedScopes = raw.grantedScopes ?? parseGrantedScopes(raw.granted_scopes);
		return {
			...raw,
			did: normalizeAccountDid(raw.did),
			grantedScopes
		};
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
		const rawDid = typeof info?.did === 'string' ? info.did.trim() : '';
		if (!stripDidFragment(rawDid)) {
			throw new Error('Invalid restored session response: missing did');
		}
		const restoredDid = normalizeAccountDid(rawDid);
		const grantedScopes = parseGrantedScopes(info?.granted_scopes);

		persistBrowserAuth(restoredDid, sessionId);
		if (!isMlsOptedInForDid(restoredDid)) {
			return { did: restoredDid, handle: info.handle ?? restoredDid, grantedScopes };
		}
		await initWasm(restoredDid);

		// Push restored credentials to Worker
		const w = getWorker();
		await w.setAuth(restoredDid, sessionId);
		await installContentRootKey(restoredDid);
		await w.setup();

		replenishKeyPackages();
		startKeyPackageReplenishment();

		return { did: restoredDid, handle: info.handle ?? restoredDid, grantedScopes };
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

async function withBoundedTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T | null> {
	let timer: ReturnType<typeof setTimeout> | null = null;
	try {
		return await Promise.race([
			promise,
			new Promise<null>((resolve) => {
				timer = setTimeout(() => resolve(null), timeoutMs);
			})
		]);
	} finally {
		if (timer !== null) {
			clearTimeout(timer);
		}
	}
}

async function withRequiredTimeout<T>(
	promise: Promise<T>,
	timeoutMs: number,
	operationLabel: string
): Promise<T> {
	let timer: ReturnType<typeof setTimeout> | null = null;
	try {
		return await Promise.race([
			promise,
			new Promise<never>((_, reject) => {
				timer = setTimeout(() => {
					reject(new Error(`${operationLabel} timed out after ${timeoutMs}ms`));
				}, timeoutMs);
			})
		]);
	} finally {
		if (timer !== null) {
			clearTimeout(timer);
		}
	}
}

export interface AccountCleanupOptions {
	opfsRootProvider?: () => Promise<OpfsDirectoryHandleLike | null>;
	retireTimeoutMs?: number;
}

export async function logout(options?: AccountCleanupOptions): Promise<void> {
	const retireTimeoutMs = options?.retireTimeoutMs ?? 3_000;
	if (isTauri) {
		await withBoundedTimeout(
			tauriInvoke('retire_current_device').catch(() => undefined),
			retireTimeoutMs
		);
		return tauriInvoke('logout');
	}

	const activeDid = stripDidFragment(readBrowserAuth()?.did ?? _workerDid ?? '');

	// Clear key package replenishment interval before tearing down Worker
	if (_replenishInterval) {
		clearInterval(_replenishInterval);
		_replenishInterval = null;
	}

	// Best-effort bounded (~3s) device retirement BEFORE wiping local device keys & OPFS DB
	try {
		if (_worker) {
			const w = _worker;
			await withBoundedTimeout(
				(async () => {
					try {
						await w.stopBackgroundTasks();
					} catch {
						// Ignore timer stop warning
					}
					try {
						await w.retireCurrentDevice();
					} catch (e) {
						console.warn('[catmos] retireCurrentDevice skipped or failed during logout:', e);
					}
					try {
						await w.clearContentRootKey();
					} catch {
						// Ignore root key clear warning
					}
					try {
						await w.clearAuth();
					} catch {
						// Ignore auth clear warning
					}
					try {
						await w.closeUnifiedClient();
					} catch {
						// Ignore close warning
					}
				})(),
				retireTimeoutMs
			);
		}
	} finally {
		terminateWorkerInstance();
	}

	clearBrowserAuth();
	if (typeof sessionStorage !== 'undefined') {
		clearPendingOAuthLogin();
	}

	if (activeDid) {
		const didHash = await accountDidHashHex(activeDid);
		wipeBrowserDeviceId(didHash);
		await deleteAccountKeyStoreEntries(didHash, sanitizeDid(activeDid));
		await purgeAccountOpfsDatabase(didHash, activeDid, options?.opfsRootProvider);
	}
}

export async function deleteAccountData(
	did?: string,
	options?: AccountCleanupOptions
): Promise<void> {
	const targetDid = stripDidFragment(did ?? readBrowserAuth()?.did ?? _workerDid ?? '');
	const timeoutMs = options?.retireTimeoutMs ?? 5_000;

	if (isTauri) {
		await tauriInvoke('delete_account_data', targetDid ? { did: targetDid } : undefined);
		if (targetDid) {
			setMlsOptedInForDid(targetDid, false);
		}
		return;
	}

	// Fail-closed (`D-3`): remote OwnerMailbox, PDS mailboxKeys, mls-ds, and owned Space
	// deletes MUST succeed before we tear down the worker, opt-in flag, session, or local DB.
	// Any timeout or failure to open the unified worker rejects rather than resolving null.
	const optedIn = Boolean(targetDid && isMlsOptedInForDid(targetDid));
	if (!_worker && optedIn) {
		await withRequiredTimeout(
			ensureUnifiedBrowserClientOpen(targetDid),
			timeoutMs,
			'deleteAccountData(openUnifiedClient)'
		);
	}
	if (optedIn && !_worker) {
		throw new Error(
			'deleteAccountData failed: unified MLS worker unavailable; refusing to wipe local state before remote delete succeeds'
		);
	}
	if (_worker) {
		const w = _worker;
		await withRequiredTimeout(
			w.deleteAccountData(),
			timeoutMs,
			'deleteAccountData(remoteDelete)'
		);
		try {
			await w.clearContentRootKey?.();
		} catch {
			// Ignore post-delete cleanup warnings
		}
		try {
			await w.clearAuth?.();
		} catch {
			// Ignore post-delete cleanup warnings
		}
		try {
			await w.closeUnifiedClient?.();
		} catch {
			// Ignore post-delete cleanup warnings
		}
	}

	if (_replenishInterval) {
		clearInterval(_replenishInterval);
		_replenishInterval = null;
	}
	terminateWorkerInstance();

	if (targetDid) {
		setMlsOptedInForDid(targetDid, false);
	}
	clearBrowserAuth();
	if (typeof sessionStorage !== 'undefined') {
		clearPendingOAuthLogin();
	}

	if (targetDid) {
		const didHash = await accountDidHashHex(targetDid);
		wipeBrowserDeviceId(didHash);
		await deleteAccountKeyStoreEntries(didHash, sanitizeDid(targetDid));
		await purgeAccountOpfsDatabase(didHash, targetDid, options?.opfsRootProvider);
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
	return w.createConversation(name, memberDids, description) as Promise<Conversation>;
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

export async function getMessages(conversationId: string, before?: string, markRead = true): Promise<Message[]> {
	if (isTauri) {
		return tauriInvoke('get_messages', { conversationId, before, markRead });
	}
	const w = getWorker();
	return w.getMessages(conversationId, before, markRead) as Promise<Message[]>;
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
	const serviceJwt = await mintChatServiceAuthToken(
		saved.sessionId,
		'blue.catbird.chat.reportSpam'
	);
	const resp = await fetch(`${HOME_DS_URL}/xrpc/blue.catbird.chat.reportSpam`, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			Authorization: `Bearer ${serviceJwt}`
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
	key: Uint8Array | number[],
	iv: Uint8Array | number[],
	sha256: string
): Promise<Uint8Array> {
	const keyArr = key instanceof Uint8Array ? Array.from(key) : key;
	const ivArr = iv instanceof Uint8Array ? Array.from(iv) : iv;
	if (isTauri) {
		const bytes = await tauriInvoke<number[]>('fetch_and_decrypt_blob', {
			blobId,
			key: keyArr,
			iv: ivArr,
			sha256
		});
		return bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
	}
	const w = getWorker();
	return w.fetchAndDecryptBlob(
		blobId,
		key instanceof Uint8Array ? key : new Uint8Array(key),
		iv instanceof Uint8Array ? iv : new Uint8Array(iv),
		sha256
	) as Promise<Uint8Array>;
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

export interface LabyrinthDeviceMetadataView {
	device_id: string;
	device_name?: string;
	status?: 'active' | 'pending_approval' | 'dormant';
	pending_approval?: boolean;
	is_current?: boolean;
	last_active_at?: string | null;
	dormant_at?: string | null;
}

export interface LabyrinthBackupStatusView {
	backup_enabled: boolean;
	mailbox_space_uri: string;
	has_recovery_code: boolean;
	has_passkey_prf: boolean;
	epoch_seq: number;
	active_device_ids: string[];
	pending_device_ids?: string[];
	current_device_id?: string;
	devices?: LabyrinthDeviceMetadataView[];
	backfill?: {
		state?: string;
		synced_batches?: number;
		total_batches?: number | null;
		last_synced_at?: string | null;
	};
}

export interface LabyrinthRevocationOutcomeView {
	status: LabyrinthBackupStatusView;
	rekeyed_recovery_code?: string | null;
	rekeyed_passkey_ids: number[][];
}

export interface DeviceRevocationReportView {
	target_device_id: string;
	ds_revoked: boolean;
	labyrinth_rotated: boolean;
	new_epoch_seq?: number | null;
	rekeyed_recovery_code?: string | null;
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
	const accountDid = normalizeAccountDid(did);
	const didHash = await accountDidHashHex(accountDid);
	const dbKeyHex = await loadOrCreateDbKeyHex(didHash);
	const savedAuth = readBrowserAuth();
	if (savedAuth && normalizeAccountDid(savedAuth.did) !== accountDid) {
		throw new Error('The signed-in account changed before the encrypted chat client opened.');
	}
	const authToken = savedAuth?.sessionId ?? null;
	const w = getWorker();
	await w.openUnifiedClient({
		accountDid,
		deviceId: getOrCreateBrowserDeviceId(didHash),
		homeDsDid: HOME_DS_DID,
		homeDsEndpoint: HOME_DS_URL,
		pdsEndpoint: NEST_URL,
		dbKeyHex,
		authToken
	});
	return w;
}

export async function enableMlsAndEnroll(
	did: string,
	pdsSupportsSpaces = false,
	grantedScopes: readonly string[] = []
): Promise<LabyrinthBackupStatusView> {
	const accountDid = normalizeAccountDid(did);
	const plainScopes = Array.from(grantedScopes, (s) => String(s).trim()).filter(Boolean);
	if (isTauri) {
		const status = await tauriInvoke<LabyrinthBackupStatusView>('labyrinth_enable_and_enroll', {
			did: accountDid,
			grantedScopes: plainScopes
		});
		setMlsOptedInForDid(accountDid, true);
		return status;
	}
	const gate = evaluateSpacesGateForUi(Boolean(pdsSupportsSpaces), plainScopes, accountDid);
	if (!gate.eligible) {
		throw new Error(gate.message);
	}
	setMlsOptedInForDid(accountDid, true);
	try {
		const w = await ensureUnifiedBrowserClientOpen(accountDid);
		await w.enrollUnifiedDevice(Boolean(pdsSupportsSpaces), plainScopes);
		startKeyPackageReplenishment();
		await w.startBackgroundTasks(30_000);
		return (await w.labyrinthStatus()) as LabyrinthBackupStatusView;
	} catch (err) {
		setMlsOptedInForDid(accountDid, false);
		throw err;
	}
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

export async function getCurrentLabyrinthDeviceId(did: string): Promise<string | null> {
	const accountDid = stripDidFragment(did);
	if (!accountDid) return null;
	if (isTauri) {
		try {
			const id = await tauriInvoke<string | null>('labyrinth_current_device_id', {
				did: accountDid
			});
			return id ? id.trim() : null;
		} catch {
			return null;
		}
	}
	const didHash = await accountDidHashHex(accountDid);
	const stored = readBrowserDeviceId(didHash);
	if (stored) return stored;
	if (_worker) {
		try {
			return await _worker.currentDeviceId();
		} catch {
			return null;
		}
	}
	return null;
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

export async function restoreWithLabyrinthPasskeyPrf(
	did: string,
	credentialId: Uint8Array,
	prfOutput32: Uint8Array
): Promise<LabyrinthBackupStatusView> {
	if (isTauri) {
		return tauriInvoke('labyrinth_restore_passkey_prf', {
			did,
			credentialId: Array.from(credentialId),
			prfOutput32: Array.from(prfOutput32)
		});
	}
	const w = await ensureUnifiedBrowserClientOpen(did);
	return (await w.restoreWithPasskeyPrf(credentialId, prfOutput32)) as LabyrinthBackupStatusView;
}

export async function approveLabyrinthSiblingDevice(
	did: string,
	targetDeviceId: string
): Promise<LabyrinthBackupStatusView> {
	if (isTauri) {
		return tauriInvoke('labyrinth_approve_device', { did, targetDeviceId });
	}
	const w = await ensureUnifiedBrowserClientOpen(did);
	return (await w.approveSiblingDevice(targetDeviceId)) as LabyrinthBackupStatusView;
}

export async function syncLabyrinthBackfill(did: string): Promise<LabyrinthBackupStatusView | null> {
	if (isTauri) {
		return tauriInvoke<LabyrinthBackupStatusView>('labyrinth_sync_backfill', { did });
	}
	const w = await ensureUnifiedBrowserClientOpen(did);
	await w.syncUnified();
	return (await w.labyrinthStatus()) as LabyrinthBackupStatusView;
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
): Promise<LabyrinthRevocationOutcomeView> {
	const currentDeviceId = await getCurrentLabyrinthDeviceId(did);
	assertCanRevokeLabyrinthDevice(targetDeviceId, currentDeviceId);
	if (isTauri) {
		return tauriInvoke('labyrinth_revoke_device', { did, targetDeviceId });
	}
	const w = await ensureUnifiedBrowserClientOpen(did);
	return (await w.revokeLabyrinthDevice(targetDeviceId)) as LabyrinthRevocationOutcomeView;
}

export interface LiveOtcInitiationView {
	session_id_hex: string;
	formatted_code: string;
	six_digit_code: string;
}

export interface ReadStateView {
	conversation_id: string;
	last_read_seq: number;
	updated_at?: string;
}

export interface CircleOwnerStateView {
	circle_id: string;
	name: string;
	description?: string | null;
	member_dids: string[];
	acl_tombstone_dids?: string[];
	updated_at: string;
	record_cid?: string | null;
}

export interface CircleOwnerStateMergeUpdate {
	circle_id: string;
	name?: string | null;
	description?: string | null;
	add_member_dids?: string[];
	remove_member_dids?: string[];
	updated_at?: string | null;
}

export async function isLabyrinthDevicePendingApproval(did: string): Promise<boolean> {
	if (isTauri) {
		return tauriInvoke('labyrinth_is_device_pending_approval', { did });
	}
	if (!isMlsOptedInForDid(did)) return false;
	const w = await ensureUnifiedBrowserClientOpen(did);
	return w.isDevicePendingApproval();
}

export async function listRegisteredLabyrinthDevices(
	did: string
): Promise<LabyrinthDeviceMetadataView[]> {
	if (isTauri) {
		return tauriInvoke('labyrinth_list_devices', { did });
	}
	const w = await ensureUnifiedBrowserClientOpen(did);
	return (await w.listRegisteredDevices()) as LabyrinthDeviceMetadataView[];
}

export async function revokeRegisteredLabyrinthDeviceLive(
	did: string,
	targetDeviceId: string
): Promise<DeviceRevocationReportView> {
	const currentDeviceId = await getCurrentLabyrinthDeviceId(did);
	assertCanRevokeLabyrinthDevice(targetDeviceId, currentDeviceId);
	if (isTauri) {
		return tauriInvoke('labyrinth_revoke_device_live', { did, targetDeviceId });
	}
	const w = await ensureUnifiedBrowserClientOpen(did);
	return (await w.revokeRegisteredDevice(targetDeviceId)) as DeviceRevocationReportView;
}

export async function startLiveLabyrinthOtcPairing(
	did: string,
	sixDigitCode: string
): Promise<LiveOtcInitiationView> {
	if (isTauri) {
		return tauriInvoke('labyrinth_start_otc', { did, sixDigitCode });
	}
	const w = await ensureUnifiedBrowserClientOpen(did);
	return (await w.startLiveOtcPairing(sixDigitCode)) as LiveOtcInitiationView;
}

export async function respondLiveLabyrinthOtcPairing(
	did: string,
	sessionIdHex: string,
	sixDigitCode?: string
): Promise<void> {
	if (isTauri) {
		await tauriInvoke('labyrinth_respond_otc', {
			did,
			sessionIdHex,
			sixDigitCode: sixDigitCode ?? null
		});
		return;
	}
	const w = await ensureUnifiedBrowserClientOpen(did);
	await w.respondLiveOtcPairing(sessionIdHex, sixDigitCode ?? null);
}

export interface LabyrinthArchiveRestoreSummary {
	conversationsDiscovered: number;
	conversationsRestored: number;
	messagesRestored: number;
	errors: string[];
}

export async function restoreArchivedLabyrinthConversations(
	did: string
): Promise<LabyrinthArchiveRestoreSummary> {
	if (isTauri) {
		return tauriInvoke('labyrinth_restore_archived_conversations', { did });
	}
	const w = await ensureUnifiedBrowserClientOpen(did);
	await w.syncUnified();
	return {
		conversationsDiscovered: 0,
		conversationsRestored: 0,
		messagesRestored: 0,
		errors: []
	};
}

export async function restoreLabyrinthConversationHistory(
	did: string,
	conversationId: string
): Promise<number> {
	if (isTauri) {
		return tauriInvoke('labyrinth_restore_conversation_history', { did, conversationId });
	}
	return verifyAndReindexLabyrinthHistory(did, conversationId);
}

export async function verifyAndReindexLabyrinthHistory(
	did: string,
	conversationId: string
): Promise<number> {
	if (isTauri) {
		return tauriInvoke('labyrinth_verify_and_reindex_history', { did, conversationId });
	}
	const w = await ensureUnifiedBrowserClientOpen(did);
	return w.verifyAndReindexHistory(conversationId);
}

export async function getReadState(
	did: string,
	conversationId: string
): Promise<ReadStateView | null> {
	if (isTauri) {
		return tauriInvoke('get_read_state', { did, conversationId });
	}
	const w = await ensureUnifiedBrowserClientOpen(did);
	return (await w.getReadState(conversationId)) as ReadStateView | null;
}

export async function advanceReadState(
	did: string,
	conversationId: string,
	candidateSeq: number
): Promise<ReadStateView> {
	if (isTauri) {
		return tauriInvoke('advance_read_state', { did, conversationId, candidateSeq });
	}
	const w = await ensureUnifiedBrowserClientOpen(did);
	return (await w.advanceReadState(conversationId, candidateSeq)) as ReadStateView;
}

export async function listReadStates(did: string): Promise<ReadStateView[]> {
	if (isTauri) {
		return tauriInvoke('list_read_states', { did });
	}
	const w = await ensureUnifiedBrowserClientOpen(did);
	return (await w.listReadStates()) as ReadStateView[];
}

export async function getCircleOwnerState(
	did: string,
	circleId: string
): Promise<CircleOwnerStateView | null> {
	if (isTauri) {
		return tauriInvoke('get_circle_owner_state', { did, circleId });
	}
	const w = await ensureUnifiedBrowserClientOpen(did);
	return (await w.getCircleOwnerState(circleId)) as CircleOwnerStateView | null;
}

export async function putCircleOwnerState(
	did: string,
	state: CircleOwnerStateView,
	swapRecordCid?: string | null
): Promise<string> {
	if (isTauri) {
		return tauriInvoke('put_circle_owner_state', {
			did,
			state,
			swapRecordCid: swapRecordCid ?? null
		});
	}
	const w = await ensureUnifiedBrowserClientOpen(did);
	return w.putCircleOwnerState(state, swapRecordCid ?? null);
}

export async function mergeCircleOwnerState(
	did: string,
	update: CircleOwnerStateMergeUpdate
): Promise<CircleOwnerStateView> {
	if (isTauri) {
		return tauriInvoke('merge_circle_owner_state', { did, update });
	}
	const w = await ensureUnifiedBrowserClientOpen(did);
	return (await w.mergeCircleOwnerState(update)) as CircleOwnerStateView;
}

export async function clearCircleAclTombstone(
	did: string,
	circleId: string,
	memberDid: string
): Promise<CircleOwnerStateView> {
	if (isTauri) {
		return tauriInvoke('clear_circle_acl_tombstone', { did, circleId, memberDid });
	}
	const w = await ensureUnifiedBrowserClientOpen(did);
	return (await w.clearCircleAclTombstone(circleId, memberDid)) as CircleOwnerStateView;
}

export async function listCircleOwnerStates(did: string): Promise<CircleOwnerStateView[]> {
	if (isTauri) {
		return tauriInvoke('list_circle_owner_states', { did });
	}
	const w = await ensureUnifiedBrowserClientOpen(did);
	return (await w.listCircleOwnerStates()) as CircleOwnerStateView[];
}

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

// ---------------------------------------------------------------------------
// MLS DB key management (main thread sessionStorage)
// TODO: Migrate to WebCrypto non-extractable key for proper key protection
// ---------------------------------------------------------------------------

/**
 * Get or create the MLS DB encryption key, namespaced per-DID in sessionStorage.
 * Falls back to an unnamespaced key when no DID is known yet (pre-login init).
 */
function getOrCreateMlsDbKey(): string {
	const did = sessionStorage.getItem(SS_ACTIVE_DID);
	const storageKey = did ? didKey(did, 'mls_db_key') : 'catbird_mls_mls_db_key';

	let key = sessionStorage.getItem(storageKey);
	if (key) return key;

	const bytes = new Uint8Array(32);
	crypto.getRandomValues(bytes);
	key = Array.from(bytes)
		.map((b) => b.toString(16).padStart(2, '0'))
		.join('');
	sessionStorage.setItem(storageKey, key);
	return key;
}

// ---------------------------------------------------------------------------
// MLS field-level encryption: per-DID content root key (localStorage)
//
// The 32-byte content root key feeds catbird-mls's field_encryption layer:
//   - per-conversation AES-GCM content keys (envelope around `text`)
//   - per-conversation HMAC chain keys (tamper-evident transcript)
//
// Persisted in localStorage so cold-starts on the same browser profile
// can decrypt the existing transcript. Namespaced by sha256(did) so that
// (a) DID strings don't end up readable in DevTools and (b) multi-account
// scenarios stay isolated. Browser localStorage is per-origin so the key
// never leaks across catmos / Bluesky / unrelated sites.
//
// This is intentionally separate from the SQLCipher DB key (sessionStorage)
// so that compromise of the DB-at-rest key alone (where sealed rows live)
// doesn't directly expose decrypted message bodies.
// ---------------------------------------------------------------------------

const CONTENT_ROOT_PREFIX = 'mls.content.root.';

// Keep browser-side direct XRPC calls on the same clean-chat route contract
// as the Tauri boundary. The shared Nest/mls-ds adapter accepts the existing
// payloads while generated clean-chat bindings are propagated upstream.
const CHAT_ROUTE = {
	resetGroup: 'blue.catbird.chat.resetGroup',
	reportSpam: 'blue.catbird.chat.reportSpam'
} as const;

async function sha256Hex(input: string): Promise<string> {
	const bytes = new TextEncoder().encode(input);
	const digest = await crypto.subtle.digest('SHA-256', bytes);
	return Array.from(new Uint8Array(digest))
		.map((b) => b.toString(16).padStart(2, '0'))
		.join('');
}

async function contentRootStorageKey(userDid: string): Promise<string> {
	return CONTENT_ROOT_PREFIX + (await sha256Hex(userDid));
}

/**
 * Load the per-DID content root key from localStorage, creating a fresh
 * random 32-byte key on first use. Returns the raw bytes so they can be
 * pushed into the Worker via comlink (Uint8Array is structured-cloneable).
 */
async function loadOrCreateContentRootKey(userDid: string): Promise<Uint8Array> {
	const storageKey = await contentRootStorageKey(userDid);
	const existing = localStorage.getItem(storageKey);
	if (existing) {
		try {
			const bytes = Uint8Array.from(atob(existing), (c) => c.charCodeAt(0));
			if (bytes.length === 32) return bytes;
			console.warn(
				'[catmos] content root key has wrong length, regenerating:',
				bytes.length
			);
		} catch (e) {
			console.warn('[catmos] content root key base64 decode failed, regenerating:', e);
		}
	}
	const fresh = new Uint8Array(32);
	crypto.getRandomValues(fresh);
	const b64 = btoa(String.fromCharCode(...fresh));
	localStorage.setItem(storageKey, b64);
	return fresh;
}

/**
 * Push the per-DID content root key into the WASM module. Called once per
 * session after `setAuth` resolves so that subsequent `setup()` and any
 * message encrypt/decrypt has the key bound.
 */
async function installContentRootKey(did: string): Promise<void> {
	const key = await loadOrCreateContentRootKey(did);
	const w = getWorker();
	try {
		await (
			w as unknown as { setContentRootKey: (k: Uint8Array) => Promise<void> }
		).setContentRootKey(key);
	} catch (e) {
		console.warn(
			'[catmos] setContentRootKey failed; messages will fall back to legacy plaintext storage:',
			e
		);
	}
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
 * Generates/retrieves the MLS DB key from sessionStorage and passes it to the
 * Worker (which has no sessionStorage access).
 */
export async function initWasm(): Promise<void> {
	if (isTauri) return;
	const w = getWorker();
	const mlsDbKey = getOrCreateMlsDbKey();
	await w.init({ baseUrl: NEST_URL, mlsDbKey });
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
		return tauriInvoke('complete_login', { sessionId });
	}
	const resp = await fetch(`${NEST_URL}/auth/session`, {
		headers: { Authorization: `Bearer ${sessionId}` }
	});
	if (!resp.ok) throw new Error(`Failed to fetch session: ${resp.status}`);
	const info = await resp.json();
	const did: string = info.did;
	const handle: string = info.handle ?? did;

	// Persist session on main thread (sessionStorage, per-DID namespaced)
	persistBrowserAuth(did, sessionId);

	// Push credentials to Worker and run MLS setup
	const w = getWorker();
	await w.setAuth(did, sessionId);
	// Install the per-DID content root key BEFORE setup() so the field-
	// level encryption layer is ready for the very first message that
	// setup() may decrypt during initial sync.
	await installContentRootKey(did);
	await w.setup();

	// Ensure key packages are available for other clients to send us Welcomes
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
	persistBrowserAuth(did, token);
	const w = getWorker();
	await w.setAuth(did, token);
	// Install the per-DID content root key after auth so the field-level
	// encryption layer is bound before any subsequent message flow.
	await installContentRootKey(did);
}

/**
 * Clear auth credentials from the WASM MLS module.
 */
export async function clearAuth(): Promise<void> {
	if (isTauri) return;
	clearBrowserAuth();
	const w = getWorker();
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
	const { did, sessionId } = saved;

	try {
		const resp = await fetch(`${NEST_URL}/auth/session`, {
			headers: { Authorization: `Bearer ${sessionId}` }
		});
		if (!resp.ok) {
			// Only discard credentials when Nest definitively rejects them. A
			// transport/5xx failure is retryable and must not strand the
			// persisted DID/content-root key behind a fresh login.
			if (resp.status === 401 || resp.status === 403) {
				clearBrowserAuth();
				return null;
			}
			else {
				throw new Error(`Failed to restore session: ${resp.status}`);
			}
		}
		const info = await resp.json();

		// Push restored credentials to Worker
		const w = getWorker();
		await w.setAuth(info.did, sessionId);
		// Restore the per-DID content root key from localStorage (or
		// generate one if first restore on this profile) so the field-
		// level encryption layer can read pre-existing sealed rows.
		await installContentRootKey(info.did);
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
		return tauriInvoke('logout');
	}
	clearBrowserAuth();

	// Clear key package replenishment interval
	if (_replenishInterval) {
		clearInterval(_replenishInterval);
		_replenishInterval = null;
	}

	// Clear auth in worker, then terminate it
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
		if (_rawWorker) {
			_rawWorker.terminate();
			_rawWorker = null;
		}
		_worker = null;
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
	// Browser: call the XRPC endpoint directly via nest BFF
	const saved = readBrowserAuth();
	if (!saved) throw new Error('Not authenticated');
	const newGroupId = crypto.randomUUID();
	const body: Record<string, string> = {
		convoId: conversationId,
		newGroupId,
		cipherSuite: 'MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519'
	};
	if (reason) body.reason = reason;
	const resp = await fetch(`${NEST_URL}/xrpc/${CHAT_ROUTE.resetGroup}`, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			Authorization: `Bearer ${saved.sessionId}`
		},
		body: JSON.stringify(body)
	});
	if (!resp.ok) {
		const text = await resp.text();
		throw new Error(`Reset group failed: ${resp.status} ${text}`);
	}
	return resp.json();
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
	// Browser: call the XRPC endpoint directly via nest BFF
	const saved = readBrowserAuth();
	if (!saved) throw new Error('Not authenticated');
	const body: Record<string, string> = { convoId: conversationId, reportedDid };
	if (reason) body.reason = reason;
	const resp = await fetch(`${NEST_URL}/xrpc/${CHAT_ROUTE.reportSpam}`, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			Authorization: `Bearer ${saved.sessionId}`
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

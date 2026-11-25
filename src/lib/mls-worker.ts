// Runs inside a dedicated Worker — has access to OPFS SAH for synchronous SQLite I/O.
import { expose } from 'comlink';
import init, * as wasm from 'catbird-mls-web';
import { decodeBase64Bytes, extractMessageDetails } from './message-embed.ts';

// Initialize the WASM binary when the worker starts.
// Stored as a module-level promise — each exposed method awaits it before calling WASM.
// NOT exposed as a property (Promises can't be structured-cloned across the Worker boundary).
// Runtime returns `InitOutput`, but the worker only awaits readiness — discard the value.
const wasmReady = init().then(() => undefined);

// Active WebSocket subscriptions keyed by conversation ID.
// WsSubscription structs can't cross the Worker boundary, so we track them here.
const subscriptions = new Map<string, { close(): void }>();

let unifiedClient: wasm.WasmMlsClient | null = null;
let unifiedDeviceId: string | null = null;
let latestAuthToken: string | null = null;
let backgroundSyncTimer: ReturnType<typeof setInterval> | null = null;

export interface BrowserOAuthConfig {
	clientId?: string;
	redirectUri?: string;
	cabUrl?: string;
	deliveryServiceDid?: string;
}

export interface BrowserSignedInAccount {
	did: string;
	handle: string;
	pds: string;
	grantedScopes: string[];
}

export interface BrowserPdsExchangeResponse {
	status: number;
	contentType?: string | null;
	headers: Array<[string, string]>;
	body: Uint8Array;
}

let petrelAuthClient: wasm.WasmAuthClient | null = null;
let petrelAuthConfigKey: string | null = null;
let activeOAuthDid: string | null = null;
let activeOAuthPds: string | null = null;

const OAUTH_IDB_NAME = 'catmos-oauth-v1';
const OAUTH_IDB_VERSION = 1;
const OAUTH_SECRETS_STORE = 'secrets';
const OAUTH_DPOP_KEYS_STORE = 'dpop_keys';

let oauthDbPromise: Promise<IDBDatabase> | null = null;

function openOAuthIdb(): Promise<IDBDatabase> {
	if (oauthDbPromise) return oauthDbPromise;
	oauthDbPromise = new Promise<IDBDatabase>((resolve, reject) => {
		const req = indexedDB.open(OAUTH_IDB_NAME, OAUTH_IDB_VERSION);
		req.onupgradeneeded = () => {
			const db = req.result;
			if (!db.objectStoreNames.contains(OAUTH_SECRETS_STORE)) {
				db.createObjectStore(OAUTH_SECRETS_STORE);
			}
			if (!db.objectStoreNames.contains(OAUTH_DPOP_KEYS_STORE)) {
				db.createObjectStore(OAUTH_DPOP_KEYS_STORE);
			}
		};
		req.onsuccess = () => resolve(req.result);
		req.onerror = () => {
			oauthDbPromise = null;
			reject(req.error ?? new Error('Failed to open catmos-oauth-v1 IndexedDB'));
		};
	});
	return oauthDbPromise;
}

function idbRequest<T>(req: IDBRequest<T>): Promise<T> {
	return new Promise<T>((resolve, reject) => {
		req.onsuccess = () => resolve(req.result);
		req.onerror = () => reject(req.error ?? new Error('IndexedDB request failed'));
	});
}

function idbTxComplete(tx: IDBTransaction): Promise<void> {
	return new Promise<void>((resolve, reject) => {
		tx.oncomplete = () => resolve();
		tx.onerror = () => reject(tx.error ?? new Error('IndexedDB transaction failed'));
		tx.onabort = () => reject(tx.error ?? new Error('IndexedDB transaction aborted'));
	});
}

function toUint8ArrayOrNull(value: unknown): Uint8Array | null {
	if (value == null) return null;
	if (value instanceof Uint8Array) return new Uint8Array(value);
	if (value instanceof ArrayBuffer) return new Uint8Array(value);
	if (ArrayBuffer.isView(value)) {
		return new Uint8Array(value.buffer, value.byteOffset, value.byteLength).slice();
	}
	return null;
}

async function oauthSecretDispatch(
	op: string,
	ns: string,
	key: string | null,
	value: Uint8Array | null
): Promise<Uint8Array | null | undefined> {
	const db = await openOAuthIdb();
	const prefix = `${ns}\0`;
	const compoundKey = key != null ? `${prefix}${key}` : '';

	if (op === 'get') {
		const tx = db.transaction(OAUTH_SECRETS_STORE, 'readonly');
		const done = idbTxComplete(tx);
		const raw = await idbRequest(tx.objectStore(OAUTH_SECRETS_STORE).get(compoundKey));
		await done;
		return toUint8ArrayOrNull(raw);
	}
	if (op === 'put') {
		if (!value) throw new Error('OAuth secret store put requires bytes');
		const tx = db.transaction(OAUTH_SECRETS_STORE, 'readwrite');
		const done = idbTxComplete(tx);
		tx.objectStore(OAUTH_SECRETS_STORE).put(new Uint8Array(value), compoundKey);
		await done;
		return undefined;
	}
	if (op === 'delete') {
		const tx = db.transaction(OAUTH_SECRETS_STORE, 'readwrite');
		const done = idbTxComplete(tx);
		tx.objectStore(OAUTH_SECRETS_STORE).delete(compoundKey);
		await done;
		return undefined;
	}
	if (op === 'take') {
		const tx = db.transaction(OAUTH_SECRETS_STORE, 'readwrite');
		const done = idbTxComplete(tx);
		const store = tx.objectStore(OAUTH_SECRETS_STORE);
		const raw = await new Promise<unknown>((resolve, reject) => {
			const req = store.get(compoundKey);
			req.onsuccess = () => {
				const found = req.result;
				if (found !== undefined) {
					store.delete(compoundKey);
				}
				resolve(found);
			};
			req.onerror = () => reject(req.error ?? new Error('IndexedDB take get failed'));
		});
		await done;
		return toUint8ArrayOrNull(raw);
	}
	if (op === 'delete_namespace') {
		const tx = db.transaction(OAUTH_SECRETS_STORE, 'readwrite');
		const done = idbTxComplete(tx);
		const store = tx.objectStore(OAUTH_SECRETS_STORE);
		const range = IDBKeyRange.bound(prefix, `${ns}\x01`, false, true);
		await new Promise<void>((resolve, reject) => {
			const cursorReq = store.openCursor(range);
			cursorReq.onsuccess = () => {
				const cursor = cursorReq.result;
				if (cursor) {
					cursor.delete();
					cursor.continue();
				} else {
					resolve();
				}
			};
			cursorReq.onerror = () => reject(cursorReq.error ?? new Error('Cursor delete failed'));
		});
		await done;
		return undefined;
	}
	throw new Error(`Unsupported OAuth secret store operation: ${op}`);
}

async function oauthDpopKeyDispatch(
	op: string,
	id: string,
	value: { key: CryptoKey; x: string; y: string } | null
): Promise<{ key: CryptoKey; x: string; y: string } | null | undefined> {
	const db = await openOAuthIdb();
	if (op === 'get') {
		const tx = db.transaction(OAUTH_DPOP_KEYS_STORE, 'readonly');
		const done = idbTxComplete(tx);
		const raw = await idbRequest(tx.objectStore(OAUTH_DPOP_KEYS_STORE).get(id));
		await done;
		return raw ?? null;
	}
	if (op === 'put') {
		if (!value) throw new Error('DPoP key store put requires entry');
		const tx = db.transaction(OAUTH_DPOP_KEYS_STORE, 'readwrite');
		const done = idbTxComplete(tx);
		tx.objectStore(OAUTH_DPOP_KEYS_STORE).put(
			{ key: value.key, x: value.x, y: value.y },
			id
		);
		await done;
		return undefined;
	}
	if (op === 'delete') {
		const tx = db.transaction(OAUTH_DPOP_KEYS_STORE, 'readwrite');
		const done = idbTxComplete(tx);
		tx.objectStore(OAUTH_DPOP_KEYS_STORE).delete(id);
		await done;
		return undefined;
	}
	throw new Error(`Unsupported DPoP key store operation: ${op}`);
}

async function ensurePetrelAuthClient(config?: BrowserOAuthConfig): Promise<wasm.WasmAuthClient> {
	await wasmReady;
	const key = JSON.stringify({
		clientId: config?.clientId ?? null,
		redirectUri: config?.redirectUri ?? null,
		cabUrl: config?.cabUrl ?? null,
		deliveryServiceDid: config?.deliveryServiceDid ?? null
	});
	if (petrelAuthClient && petrelAuthConfigKey === key) {
		return petrelAuthClient;
	}
	if (petrelAuthClient) {
		try {
			petrelAuthClient.free();
		} catch {
			// Ignore free error
		}
		petrelAuthClient = null;
	}
	petrelAuthClient = new wasm.WasmAuthClient(
		config?.clientId ?? null,
		config?.redirectUri ?? null,
		config?.cabUrl ?? null,
		config?.deliveryServiceDid ?? null,
		oauthSecretDispatch as unknown as (...args: unknown[]) => unknown,
		oauthDpopKeyDispatch as unknown as (...args: unknown[]) => unknown
	);
	petrelAuthConfigKey = key;
	return petrelAuthClient;
}

function hasLiveAuth(): boolean {
	return Boolean(activeOAuthDid || latestAuthToken);
}

// WASM return values may contain non-cloneable JsValue handles or BigInt (from Rust i64).
// Strip them to plain JSON-safe objects for structured clone across Worker boundary.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const plain = (v: any) =>
	v === undefined || v === null
		? v
		: JSON.parse(
				JSON.stringify(v, (_k, val) => {
					if (typeof val === 'bigint') return Number(val);
					if (val instanceof Uint8Array) return Array.from(val);
					return val;
				})
			);

function bytesToHex(bytes: number[] | Uint8Array | undefined | null): string {
	if (!bytes) return '';
	const arr = bytes instanceof Uint8Array ? Array.from(bytes) : bytes;
	return arr.map((b) => Number(b & 0xff).toString(16).padStart(2, '0')).join('');
}

function encodeBase64Bytes(bytes: Uint8Array | number[]): string {
	const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
	let bin = '';
	const chunkSize = 0x8000;
	for (let i = 0; i < arr.length; i += chunkSize) {
		bin += String.fromCharCode(...arr.subarray(i, i + chunkSize));
	}
	return btoa(bin);
}

function decodeSha256Bytes(sha256: string): Uint8Array | null {
	const trimmed = sha256.trim();
	if (!trimmed) return null;
	if (/^[0-9a-fA-F]{64}$/.test(trimmed)) {
		const out = new Uint8Array(32);
		for (let i = 0; i < 32; i += 1) {
			out[i] = Number.parseInt(trimmed.slice(i * 2, i * 2 + 2), 16);
		}
		return out;
	}
	try {
		const decoded = decodeBase64Bytes(trimmed);
		return decoded.byteLength === 32 ? decoded : null;
	} catch {
		return null;
	}
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function mapMessageRowToUi(rawRow: any) {
	const row = plain(rawRow);
	const { messageType, content, image, audio, embed } = extractMessageDetails(
		String(row.plaintext_json ?? '')
	);
	const createdMs = Number(row.created_at_ms ?? Date.now());
	const isOwn = Boolean(row.is_own);
	return {
		id: String(row.message_id ?? ''),
		conversationId: String(row.conversation_id ?? ''),
		senderDid: String(row.sender_did ?? ''),
		senderHandle: '',
		content,
		timestamp: new Date(createdMs).toISOString(),
		sequenceNumber: Math.max(0, Number(row.seq ?? 0)),
		status: isOwn ? 'sent' : 'delivered',
		isOwn,
		messageType,
		...(image ? { image } : {}),
		...(audio ? { audio, audioAttachment: audio } : {}),
		...(embed ? { embed } : {})
	};
}

function bestEffortAdvanceReadState(convoId: string, maxSeq: number) {
	if (!unifiedClient || !hasLiveAuth() || maxSeq < 1) return;
	unifiedClient.advanceReadState(convoId, BigInt(Math.trunc(maxSeq))).catch(() => {});
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function mapConversationRowToUi(rawRow: any, members: string[], rawMeta: any, rawLastMsg: any) {
	const row = plain(rawRow);
	const meta = rawMeta ? plain(rawMeta) : null;
	const lastMsg = rawLastMsg ? plain(rawLastMsg) : null;
	const metaTitle = typeof meta?.title === 'string' && meta.title.trim() ? meta.title : null;
	const rowTitle = typeof row?.title === 'string' && row.title.trim() ? row.title : null;
	const displayName =
		metaTitle ??
		rowTitle ??
		(members.length > 0 ? members.join(', ') : String(row.conversation_id ?? ''));
	const description =
		typeof meta?.description === 'string' && meta.description.trim()
			? meta.description
			: undefined;
	let lastMessage: string | undefined;
	let lastMessageAt: string | undefined;
	if (lastMsg) {
		lastMessage = extractMessageDetails(String(lastMsg.plaintext_json ?? '')).content;
		lastMessageAt = new Date(Number(lastMsg.created_at_ms ?? Date.now())).toISOString();
	}
	return {
		id: String(row.conversation_id ?? ''),
		groupId: bytesToHex(row.group_id),
		displayName,
		description,
		members,
		lastMessage,
		lastMessageAt,
		unreadCount: Math.max(0, Number(row.unread_count ?? 0)),
		isGroup: members.length > 2 || meta !== null
	};
}

function requireUnified(): wasm.WasmMlsClient {
	if (!unifiedClient) {
		throw new Error('WasmMlsClient is not open');
	}
	return unifiedClient;
}

const api = {
	// Keep background orchestration in the worker that owns the WASM instance.
	runDeferredRecovery: async () => {
		await wasmReady;
		if (unifiedClient) {
			return unifiedClient.sync();
		}
		return 0;
	},
	startBackgroundTasks: async (intervalMs: number) => {
		await wasmReady;
		if (backgroundSyncTimer) {
			clearInterval(backgroundSyncTimer);
		}
		backgroundSyncTimer = setInterval(() => {
			if (unifiedClient) {
				unifiedClient.sync().catch((e) => console.warn('[catmos] background sync warning:', e));
				unifiedClient
					.fulfillPendingGroupLeaves()
					.catch((e) => console.warn('[catmos] background group leave warning:', e));
				unifiedClient
					.flushLabyrinthQueue()
					.catch((e) => console.warn('[catmos] background labyrinth flush warning:', e));
			}
		}, Math.max(5_000, intervalMs));
	},
	stopBackgroundTasks: async () => {
		await wasmReady;
		if (backgroundSyncTimer) {
			clearInterval(backgroundSyncTimer);
			backgroundSyncTimer = null;
		}
	},
	// Petrel direct OAuth via Client Assertion Backend (CAB)
	oauthStartLogin: async (identifier: string, config?: BrowserOAuthConfig): Promise<string> => {
		const client = await ensurePetrelAuthClient(config);
		return client.startLogin(identifier);
	},
	oauthCompleteLogin: async (
		callbackUrl: string,
		config?: BrowserOAuthConfig
	): Promise<BrowserSignedInAccount> => {
		const client = await ensurePetrelAuthClient(config);
		const result = plain(await client.completeLogin(callbackUrl)) as BrowserSignedInAccount;
		activeOAuthDid = result.did;
		activeOAuthPds = result.pds;
		if (unifiedClient && unifiedClient.accountDid() === result.did.trim().toLowerCase()) {
			unifiedClient.bindPetrelAuth(client);
		}
		return result;
	},
	oauthRestoreSession: async (
		config?: BrowserOAuthConfig
	): Promise<BrowserSignedInAccount | null> => {
		const client = await ensurePetrelAuthClient(config);
		const raw = await client.restoreSession();
		if (!raw) {
			activeOAuthDid = null;
			activeOAuthPds = null;
			return null;
		}
		const result = plain(raw) as BrowserSignedInAccount;
		activeOAuthDid = result.did;
		activeOAuthPds = result.pds;
		if (unifiedClient && unifiedClient.accountDid() === result.did.trim().toLowerCase()) {
			unifiedClient.bindPetrelAuth(client);
		}
		return result;
	},
	oauthLogout: async (did: string, config?: BrowserOAuthConfig): Promise<void> => {
		const client = await ensurePetrelAuthClient(config);
		try {
			await client.logout(did);
		} finally {
			activeOAuthDid = null;
			activeOAuthPds = null;
			if (unifiedClient) {
				unifiedClient.clearPetrelAuth();
			}
		}
	},
	oauthServiceToken: async (
		did: string,
		audience: string,
		method: string,
		config?: BrowserOAuthConfig
	): Promise<string> => {
		const client = await ensurePetrelAuthClient(config);
		return client.serviceToken(did, audience, method);
	},
	oauthPdsExchange: async (
		did: string,
		method: string,
		path: string,
		headers?: Array<[string, string]>,
		body?: Uint8Array | null,
		contentType?: string | null,
		config?: BrowserOAuthConfig
	): Promise<BrowserPdsExchangeResponse> => {
		const client = await ensurePetrelAuthClient(config);
		const raw = (await client.pdsExchange(
			did,
			method,
			path,
			headers ?? null,
			body ?? null,
			contentType ?? null
		)) as {
			status: number;
			contentType?: string | null;
			headers?: Array<[string, string]>;
			body?: number[] | Uint8Array;
		};
		const bodyBytes =
			raw.body instanceof Uint8Array
				? raw.body
				: new Uint8Array(Array.isArray(raw.body) ? raw.body : []);
		return {
			status: Number(raw.status),
			contentType: raw.contentType ?? null,
			headers: Array.isArray(raw.headers) ? raw.headers : [],
			body: bodyBytes
		};
	},
	// Init & auth — void returns, discard WASM internals
	init: async (_config: object) => {
		await wasmReady;
	},
	setAuth: (_did: string, token: string) => {
		latestAuthToken = token;
		if (unifiedClient) {
			unifiedClient.setAuthToken(token);
		}
	},
	clearAuth: () => {
		latestAuthToken = null;
		activeOAuthDid = null;
		activeOAuthPds = null;
		if (backgroundSyncTimer) {
			clearInterval(backgroundSyncTimer);
			backgroundSyncTimer = null;
		}
		if (unifiedClient) {
			unifiedClient.setAuthToken(null);
			unifiedClient.clearPetrelAuth();
		}
	},
	setSignerBridge: async (
		actorDid: string,
		deviceId: string,
		dpopJkt: string,
		publicKey: Uint8Array,
		key: CryptoKey,
		authGeneration?: number
	) => {
		const sign = (transcript: Uint8Array) =>
			crypto.subtle
				.sign({ name: 'Ed25519' }, key, transcript as BufferSource)
				.then((signature) => new Uint8Array(signature));
		(wasm as unknown as {
			catbird_mls_set_signer_bridge: (
				callback: (transcript: Uint8Array) => Promise<Uint8Array>,
				actorDid: string,
				deviceId: string,
				dpopJkt: string,
				publicKey: Uint8Array,
				authGeneration?: number
			) => void;
		}).catbird_mls_set_signer_bridge(
			sign,
			actorDid,
			deviceId,
			dpopJkt,
			publicKey,
			authGeneration
		);
	},
	hasSignerBridge: () =>
		(wasm as unknown as { catbird_mls_has_signer_bridge: () => boolean }).catbird_mls_has_signer_bridge(),
	prepareUnsignedRequest: (operation: string, requestJson: string) =>
		plain(
			(wasm as unknown as {
				catbird_mls_prepare_unsigned_request: (
					operation: string,
					requestJson: string
				) => unknown;
			}).catbird_mls_prepare_unsigned_request(operation, requestJson)
		),
	prepareSignedRequest: async (operation: string, requestJson: string) =>
		plain(
			await (wasm as unknown as {
				catbird_mls_prepare_signed_request: (
					operation: string,
					requestJson: string
				) => Promise<unknown>;
			}).catbird_mls_prepare_signed_request(operation, requestJson)
		),
	setContentRootKey: async (key: Uint8Array) => {
		await wasmReady;
		const mod = wasm as unknown as { setContentRootKey?: (k: Uint8Array) => void };
		mod.setContentRootKey?.(key);
	},
	clearContentRootKey: async () => {
		await wasmReady;
		const mod = wasm as unknown as { clearContentRootKey?: () => void };
		mod.clearContentRootKey?.();
	},
	setup: async () => {
		await wasmReady;
		if (unifiedClient) {
			try {
				await unifiedClient.sync();
			} catch (e) {
				console.warn('[catmos] initial unified sync warning:', e);
			}
		}
	},
	replenishKeyPackages: async () => {
		await wasmReady;
		if (unifiedClient) {
			await unifiedClient.replenishKeyPackages(10);
		}
	},
	ping: () => wasm.catbird_mls_ping(),

	// Conversations — unified WasmMlsClient (`Spec §4` single DB)
	listConversations: async () => {
		await wasmReady;
		if (!unifiedClient) return [];
		try {
			await unifiedClient.sync();
		} catch (e) {
			console.warn('[catmos] listConversations sync warning:', e);
		}
		const rows = plain(unifiedClient.listConversations(null, 100)) as unknown[];
		return rows.map((row) => {
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			const convoId = String((row as any).conversation_id ?? '');
			const rawMembers = (plain(unifiedClient!.listMembers(convoId)) as unknown[]) ?? [];
			const members = rawMembers
				// eslint-disable-next-line @typescript-eslint/no-explicit-any
				.map((m: any) => (typeof m === 'string' ? m : String(m?.did ?? '')))
				.filter((d) => d.length > 0);
			const meta = unifiedClient!.getGroupMetadata(convoId);
			const msgs = (plain(unifiedClient!.listMessages(convoId, null, 1)) as unknown[]) ?? [];
			const lastMsg = msgs.length > 0 ? msgs[0] : null;
			return mapConversationRowToUi(row, members, meta, lastMsg);
		});
	},
	createConversation: async (name: string, memberDids: string[], description?: string) => {
		await wasmReady;
		const client = requireUnified();
		const convoId = crypto.randomUUID().toLowerCase();
		const titleOpt = name.trim() ? name : null;
		const descOpt = description && description.trim() ? description : null;
		const row = await client.createGroup(
			convoId,
			client.homeDsDid(),
			memberDids,
			titleOpt,
			descOpt
		);
		const rawMembers = (plain(client.listMembers(convoId)) as unknown[]) ?? [];
		const members = rawMembers
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			.map((m: any) => (typeof m === 'string' ? m : String(m?.did ?? '')))
			.filter((d) => d.length > 0);
		const meta = client.getGroupMetadata(convoId);
		return mapConversationRowToUi(row, members, meta, null);
	},
	joinGroup: async (convoId: string) => {
		await wasmReady;
		const client = requireUnified();
		await client.sync();
		const rows = (plain(client.listConversations(null, 100)) as unknown[]) ?? [];
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const found = rows.find((r: any) => r.conversation_id === convoId);
		if (!found) throw new Error(`Conversation ${convoId} not found after sync`);
		const rawMembers = (plain(client.listMembers(convoId)) as unknown[]) ?? [];
		const members = rawMembers
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			.map((m: any) => (typeof m === 'string' ? m : String(m?.did ?? '')))
			.filter((d) => d.length > 0);
		const meta = client.getGroupMetadata(convoId);
		return mapConversationRowToUi(found, members, meta, null);
	},

	// Messages
	sendMessage: async (convoId: string, content: string) => {
		await wasmReady;
		const client = requireUnified();
		const msgId = crypto.randomUUID().toLowerCase();
		const row = await client.sendMessage(convoId, msgId, content);
		client.flushLabyrinthQueue().catch(() => {});
		return mapMessageRowToUi(row);
	},
	sendImage: async (
		convoId: string,
		content: string,
		data: Uint8Array,
		contentType: string,
		width: number,
		height: number,
		altText?: string
	) => {
		await wasmReady;
		const client = requireUnified();
		const uploaded = await client.uploadConversationAttachment(
			convoId,
			data,
			contentType || 'image/jpeg'
		);
		const msgId = crypto.randomUUID().toLowerCase();
		const row = await client.sendMediaAttachmentMessage(
			convoId,
			msgId,
			content,
			uploaded,
			width,
			height,
			altText ?? null,
			null,
			null,
			null
		);
		client.flushLabyrinthQueue().catch(() => {});
		return mapMessageRowToUi(row);
	},
	getMessages: async (convoId: string, before?: string, markRead = true) => {
		await wasmReady;
		if (!unifiedClient) return [];
		const beforeSeq = before && /^\d+$/.test(before) ? BigInt(before) : null;
		const rows = (plain(unifiedClient.listMessages(convoId, beforeSeq, 50)) as unknown[]) ?? [];
		const mapped = rows.map(mapMessageRowToUi);
		mapped.sort((a, b) => a.sequenceNumber - b.sequenceNumber);
		const maxSeq = mapped.reduce((acc, m) => Math.max(acc, m.sequenceNumber), 0);
		if (markRead && !before) bestEffortAdvanceReadState(convoId, maxSeq);
		return mapped;
	},
	getImageAttachment: async (
		blobId: string,
		keyB64: string,
		ivB64: string,
		sha256: string,
		contentType: string,
		_convoId = ''
	) => {
		await wasmReady;
		const client = requireUnified();
		const keyBytes = decodeBase64Bytes(keyB64);
		const ivBytes = decodeBase64Bytes(ivB64);
		const shaBytes = decodeSha256Bytes(sha256);
		const bytes = await client.downloadConversationAttachment(
			blobId,
			keyBytes,
			ivBytes,
			shaBytes
		);
		const mime = contentType || 'image/jpeg';
		return `data:${mime};base64,${encodeBase64Bytes(bytes)}`;
	},
	fetchNewMessages: async (convoId: string) => {
		await wasmReady;
		if (!unifiedClient) return [];
		try {
			await unifiedClient.sync();
		} catch (e) {
			console.warn('[catmos] fetchNewMessages sync warning:', e);
		}
		const rows = (plain(unifiedClient.listMessages(convoId, null, 50)) as unknown[]) ?? [];
		const mapped = rows.map(mapMessageRowToUi);
		mapped.sort((a, b) => a.sequenceNumber - b.sequenceNumber);
		const maxSeq = mapped.reduce((acc, m) => Math.max(acc, m.sequenceNumber), 0);
		bestEffortAdvanceReadState(convoId, maxSeq);
		return mapped;
	},
	sendReaction: async (convoId: string, msgId: string, emoji: string, action: string) => {
		await wasmReady;
		const client = requireUnified();
		const reactionMsgId = crypto.randomUUID().toLowerCase();
		const payload = JSON.stringify({
			messageType: 'reaction',
			reaction: {
				messageId: msgId,
				emoji,
				action: action === 'remove' ? 'remove' : 'add'
			}
		});
		await client.sendMessage(convoId, reactionMsgId, payload);
		client.flushLabyrinthQueue().catch(() => {});
	},
	updateCursor: async (convoId: string, cursor: string) => {
		await wasmReady;
		if (!unifiedClient) return;
		const trimmed = cursor.trim();
		if (/^\d+$/.test(trimmed)) {
			const seq = BigInt(trimmed);
			if (seq >= 1n) {
				await unifiedClient.acknowledgeEntriesUpTo(convoId, seq);
				bestEffortAdvanceReadState(convoId, Number(seq));
			}
		} else {
			const rows = (plain(unifiedClient.listMessages(convoId, null, 1)) as unknown[]) ?? [];
			if (rows.length > 0) {
				// eslint-disable-next-line @typescript-eslint/no-explicit-any
				const latestSeq = Number((rows[0] as any)?.seq ?? 0);
				bestEffortAdvanceReadState(convoId, latestSeq);
			}
		}
	},

	subscribe: async (
		convoId: string,
		onMessage: (data: unknown) => void,
		onEvent: (data: unknown) => void,
		onStatus: (status: unknown) => void,
		_cursor?: string
	) => {
		await wasmReady;
		subscriptions.get(convoId)?.close();
		subscriptions.delete(convoId);
		if (!unifiedClient) return;

		const seenIds = new Set<string>();
		const seedConvo = (cid: string) => {
			try {
				const initial = (plain(unifiedClient!.listMessages(cid, null, 50)) as unknown[]) ?? [];
				for (const row of initial) {
					// eslint-disable-next-line @typescript-eslint/no-explicit-any
					const id = String((row as any)?.message_id ?? '');
					if (id) seenIds.add(`${cid}:${id}`);
				}
			} catch {
				// Ignore seeding errors on empty/unjoined conversations
			}
		};

		if (convoId === '*') {
			const convos = (plain(unifiedClient.listConversations(null, 100)) as unknown[]) ?? [];
			for (const c of convos) {
				// eslint-disable-next-line @typescript-eslint/no-explicit-any
				const cid = String((c as any)?.conversation_id ?? '');
				if (cid) seedConvo(cid);
			}
		} else {
			seedConvo(convoId);
		}

		onStatus('connected');
		let closed = false;
		let running = false;
		const timer = setInterval(async () => {
			if (closed || running || !unifiedClient) return;
			running = true;
			try {
				await unifiedClient.sync();
				unifiedClient.fulfillPendingGroupLeaves().catch(() => {});
				const targetIds: string[] =
					convoId === '*'
						? ((plain(unifiedClient.listConversations(null, 100)) as unknown[]) ?? [])
								// eslint-disable-next-line @typescript-eslint/no-explicit-any
								.map((c: any) => String(c?.conversation_id ?? ''))
								.filter((id) => id.length > 0)
						: [convoId];
				for (const cid of targetIds) {
					const rows = (plain(unifiedClient.listMessages(cid, null, 20)) as unknown[]) ?? [];
					const ordered = rows.map(mapMessageRowToUi).sort((a, b) => a.sequenceNumber - b.sequenceNumber);
					for (const msg of ordered) {
						const key = `${cid}:${msg.id}`;
						if (msg.id && !seenIds.has(key)) {
							seenIds.add(key);
							onMessage(msg);
						}
					}
				}
			} catch (err) {
				console.warn('[catmos] unified subscription sync warning:', err);
			} finally {
				// Sync can commit a verified deletion before another conversation fails.
				if (!closed) onEvent({ type: 'messagesChanged' });
				running = false;
			}
		}, 3000);

		subscriptions.set(convoId, {
			close() {
				closed = true;
				clearInterval(timer);
			}
		});
	},
	unsubscribe: (convoId: string) => {
		subscriptions.get(convoId)?.close();
		subscriptions.delete(convoId);
	},

	// Members
	getMembers: async (convoId: string) => {
		await wasmReady;
		if (!unifiedClient) return [];
		const rawMembers = (plain(unifiedClient.listMembers(convoId)) as unknown[]) ?? [];
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		return rawMembers.map((m: any) =>
			typeof m === 'string'
				? {
						did: m,
						handle: '',
						displayName: undefined,
						role: 'Member'
					}
				: {
						did: String(m?.did ?? ''),
						handle: typeof m?.handle === 'string' ? m.handle : '',
						displayName:
							typeof m?.displayName === 'string' && m.displayName ? m.displayName : undefined,
						role: typeof m?.role === 'string' && m.role ? m.role : 'Member'
					}
		);
	},
	addParticipants: async (convoId: string, did: string) => {
		await wasmReady;
		const client = requireUnified();
		await client.addGroupMembers(convoId, [did]);
	},
	addGroupMembers: async (convoId: string, memberDids: string[]) => {
		await wasmReady;
		const client = requireUnified();
		await client.addGroupMembers(convoId, memberDids);
	},
	demoteMember: async (_convoId: string, _did: string) => {
		throw new Error('Member role demotion is not supported in Clean-Slate v1');
	},
	sendTyping: async (_convoId: string, _isTyping: boolean) => {
		// Signed ephemeral typing transport is not yet wired in Clean-Slate v1.
	},
	promoteMember: async (_convoId: string, _did: string) => {
		throw new Error('Member role promotion is not supported in Clean-Slate v1');
	},
	removeParticipants: async (convoId: string, did: string) => {
		await wasmReady;
		const client = requireUnified();
		await client.removeGroupMember(true, convoId, did);
	},
	leaveConversation: async (convoId: string) => {
		await wasmReady;
		const client = requireUnified();
		const requests = (plain(client.listRequests(null)) as unknown[]) ?? [];
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const pending = requests.find((r: any) => {
			const matchesId = r?.conversation_id === convoId || r?.request_id === convoId;
			const consent = String(r?.consent ?? '');
			const isPending =
				consent === 'incomingPending' ||
				consent === 'outgoingPending' ||
				consent === 'incoming_pending' ||
				consent === 'outgoing_pending';
			return matchesId && isPending;
		});
		if (pending) {
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			await client.declineDirectRequest(String((pending as any).request_id));
		} else {
			await client.leaveConversation(convoId);
		}
	},

	// Profiles & search
	getProfiles: async (dids: string[]) => {
		await wasmReady;
		return plain(await wasm.catbird_mls_get_profiles(dids));
	},
	searchUsers: async (query: string) => {
		await wasmReady;
		return plain(await wasm.catbird_mls_search_users(query));
	},
	checkOptInStatus: async (
		dids: string[],
		opts?: {
			did?: string;
			homeDsDid?: string;
			homeDsEndpoint?: string;
			oauthConfig?: BrowserOAuthConfig;
		}
	) => {
		await wasmReady;
		const actorDid = opts?.did ?? activeOAuthDid;
		if (actorDid && (petrelAuthClient || opts?.oauthConfig)) {
			const client = await ensurePetrelAuthClient(opts?.oauthConfig);
			return plain(
				await client.checkOptInStatus(
					actorDid,
					opts?.homeDsDid ?? 'did:web:chat.catbird.blue',
					opts?.homeDsEndpoint ?? 'https://chat.catbird.blue',
					dids
				)
			);
		}
		return plain(await wasm.catbird_mls_check_opt_in_status(dids));
	},

	// Group metadata
	getGroupMetadata: async (convoId: string) => {
		await wasmReady;
		if (!unifiedClient) return null;
		const result = unifiedClient.getGroupMetadata(convoId);
		return result ? plain(result) : null;
	},
	updateGroupMetadata: async (
		convoId: string,
		title: string | null,
		description: string | null,
		_avatarBlobLocator: string | null,
		_avatarContentType: string | null,
		_avatarBytes: Uint8Array | null
	) => {
		await wasmReady;
		const client = requireUnified();
		const existing = client.getGroupMetadata(convoId);
		const existingPlain = existing ? plain(existing) : null;
		const nextTitle = title ?? existingPlain?.title ?? '';
		const nextDesc = description ?? existingPlain?.description ?? '';
		const result = await client.updateGroupMetadata(convoId, nextTitle, nextDesc);
		return result ? plain(result) : null;
	},
	bootstrapGroupMetadata: async (groupIdHex: string) => {
		const result = await (wasm as any).wasm_bootstrap_group_metadata(groupIdHex);
		return result ? plain(result) : null;
	},
	republishMetadataAfterReset: async (newGroupIdHex: string, resetGeneration?: number) => {
		const result = await (wasm as any).wasm_republish_metadata_after_reset(
			newGroupIdHex,
			resetGeneration
		);
		return result ? plain(result) : null;
	},

	// Voice messages
	prepareVoice: async (pcmPath: string, sampleRate: number) =>
		plain(await (wasm as any).catbird_mls_prepare_voice(pcmPath, sampleRate)),
	decodeOpus: async (opusData: Uint8Array) =>
		await (wasm as any).catbird_mls_decode_opus(opusData),
	sendVoice: async (
		convoId: string,
		audioData: Uint8Array,
		contentType: string,
		durationMs: number,
		waveform: number[],
		transcript?: string
	) => {
		await wasmReady;
		const client = requireUnified();
		const mime = contentType || 'audio/webm;codecs=opus';
		const uploaded = await client.uploadConversationAttachment(convoId, audioData, mime);
		const msgId = crypto.randomUUID().toLowerCase();
		const row = await client.sendMediaAttachmentMessage(
			convoId,
			msgId,
			'',
			uploaded,
			null,
			null,
			null,
			BigInt(Math.max(1, Math.round(durationMs))),
			waveform,
			transcript ?? null
		);
		client.flushLabyrinthQueue().catch(() => {});
		return mapMessageRowToUi(row);
	},
	fetchAndDecryptBlob: async (
		blobId: string,
		key: Uint8Array | number[],
		iv: Uint8Array | number[],
		sha256: string
	) => {
		await wasmReady;
		const client = requireUnified();
		const keyBytes = key instanceof Uint8Array ? key : new Uint8Array(key);
		const ivBytes = iv instanceof Uint8Array ? iv : new Uint8Array(iv);
		const shaBytes = decodeSha256Bytes(sha256);
		return client.downloadConversationAttachment(blobId, keyBytes, ivBytes, shaBytes);
	},

	// -----------------------------------------------------------------------
	// Unified Clean-Slate WasmMlsClient (`catbird-mls/<did_hash>.db`, `G2`, `D4`, `I15`, `I16`)
	// -----------------------------------------------------------------------
	openUnifiedClient: async (params: {
		accountDid: string;
		deviceId: string;
		homeDsDid: string;
		homeDsEndpoint: string;
		pdsEndpoint: string;
		dbKeyHex: string;
		authToken?: string | null;
		oauthConfig?: BrowserOAuthConfig;
	}) => {
		await wasmReady;
		if (params.authToken !== undefined) {
			latestAuthToken = params.authToken;
		}
		const effectivePds = params.pdsEndpoint.trim() || activeOAuthPds || '';
		const authClient =
			petrelAuthClient ??
			(params.oauthConfig ? await ensurePetrelAuthClient(params.oauthConfig) : null);
		const normalizedTarget = params.accountDid.trim().toLowerCase();
		if (unifiedClient && unifiedClient.accountDid() === normalizedTarget) {
			unifiedDeviceId = params.deviceId;
			if (authClient && activeOAuthDid?.trim().toLowerCase() === normalizedTarget) {
				unifiedClient.bindPetrelAuth(authClient);
			}
			if (latestAuthToken !== null) {
				unifiedClient.setAuthToken(latestAuthToken);
			}
			return {
				accountDid: unifiedClient.accountDid(),
				accountDidHash: unifiedClient.accountDidHash()
			};
		}
		if (unifiedClient) {
			try {
				unifiedClient.close();
			} catch {
				// Ignore prior handle close
			}
			unifiedClient = null;
			unifiedDeviceId = null;
		}
		unifiedClient = await wasm.WasmMlsClient.openAsync(
			params.accountDid,
			params.deviceId,
			params.homeDsDid,
			params.homeDsEndpoint,
			effectivePds,
			params.dbKeyHex
		);
		unifiedDeviceId = params.deviceId;
		if (authClient && activeOAuthDid?.trim().toLowerCase() === normalizedTarget) {
			unifiedClient.bindPetrelAuth(authClient);
		}
		if (latestAuthToken !== null) {
			unifiedClient.setAuthToken(latestAuthToken);
		}
		return {
			accountDid: unifiedClient.accountDid(),
			accountDidHash: unifiedClient.accountDidHash()
		};
	},
	currentDeviceId: async () => {
		await wasmReady;
		if (unifiedClient) {
			const dynamicClient = unifiedClient as unknown as { deviceId?: () => string };
			if (typeof dynamicClient.deviceId === 'function') {
				return dynamicClient.deviceId();
			}
		}
		return unifiedDeviceId;
	},
	syncUnified: async () => {
		await wasmReady;
		if (!unifiedClient) return 0;
		return unifiedClient.sync();
	},
	evaluateSpacesEligibility: async (pdsSupportsSpaces: boolean, grantedScopes: string[]) => {
		await wasmReady;
		if (!unifiedClient) throw new Error('WasmMlsClient is not open');
		return plain(unifiedClient.evaluateSpacesEligibility(pdsSupportsSpaces, grantedScopes));
	},
	enrollUnifiedDevice: async (pdsSupportsSpaces: boolean, grantedScopes: string[]) => {
		await wasmReady;
		if (!unifiedClient) throw new Error('WasmMlsClient is not open');
		return plain(await unifiedClient.enrollDevice(pdsSupportsSpaces, grantedScopes));
	},
	labyrinthStatus: async () => {
		await wasmReady;
		if (!unifiedClient) throw new Error('WasmMlsClient is not open');
		return plain(unifiedClient.labyrinthStatus());
	},
	enableLabyrinthLive: async () => {
		await wasmReady;
		const client = requireUnified();
		return plain(await client.enableLabyrinthLive());
	},
	isDevicePendingApproval: async () => {
		await wasmReady;
		return requireUnified().isDevicePendingApproval();
	},
	setupRecoveryCode: async () => {
		await wasmReady;
		const client = requireUnified();
		if (hasLiveAuth()) {
			return client.createRecoveryCodeLive();
		}
		return client.setupRecoveryCode();
	},
	restoreWithRecoveryCode: async (recoveryCodeInput: string) => {
		await wasmReady;
		const client = requireUnified();
		if (hasLiveAuth()) {
			return plain(await client.restoreWithRecoveryCodeLive(recoveryCodeInput));
		}
		return plain(client.restoreWithRecoveryCode(recoveryCodeInput));
	},
	registerPasskeyPrf: async (credentialId: Uint8Array, prfOutput32: Uint8Array) => {
		await wasmReady;
		const client = requireUnified();
		if (hasLiveAuth()) {
			return plain(await client.registerPasskeyPrfLive(credentialId, prfOutput32));
		}
		return plain(client.registerPasskeyPrf(credentialId, prfOutput32));
	},
	restoreWithPasskeyPrf: async (credentialId: Uint8Array, prfOutput32: Uint8Array) => {
		await wasmReady;
		const client = requireUnified();
		return plain(await client.restoreWithPasskeyPrf(credentialId, prfOutput32));
	},
	approveSiblingDevice: async (targetDeviceId: string) => {
		await wasmReady;
		const client = requireUnified();
		await client.approveDevice(targetDeviceId);
		return plain(client.labyrinthStatus());
	},
	listRegisteredDevices: async () => {
		await wasmReady;
		return plain(await requireUnified().listDevices());
	},
	revokeRegisteredDevice: async (targetDeviceId: string) => {
		await wasmReady;
		return plain(await requireUnified().revokeDevice(targetDeviceId));
	},
	retireCurrentDevice: async () => {
		await wasmReady;
		if (!unifiedClient) return false;
		await unifiedClient.retireCurrentDevice();
		return true;
	},
	deleteAccountData: async () => {
		await wasmReady;
		const client = requireUnified();
		await client.deleteAccountData();
		if (backgroundSyncTimer) {
			clearInterval(backgroundSyncTimer);
			backgroundSyncTimer = null;
		}
		for (const sub of subscriptions.values()) {
			sub.close();
		}
		subscriptions.clear();
		try {
			client.close();
		} catch {
			// Ignore handle close failure after wipe
		}
		unifiedClient = null;
		unifiedDeviceId = null;
		latestAuthToken = null;
		return true;
	},
	initiateOtcPairing: async () => {
		await wasmReady;
		return plain(await requireUnified().initiateOtcPairing());
	},
	startLiveOtcPairing: async (sixDigitCode: string) => {
		await wasmReady;
		return plain(await requireUnified().startOtcPairing(sixDigitCode));
	},
	respondLiveOtcPairing: async (sessionIdHex: string, sixDigitCode?: string | null) => {
		await wasmReady;
		await requireUnified().respondOtcPairing(sessionIdHex, sixDigitCode ?? null);
	},
	completeLiveOtcPairing: async (sixDigitCode: string) => {
		await wasmReady;
		return plain(await requireUnified().completeLiveOtcPairing(sixDigitCode));
	},
	completeOtcPairing: async (sixDigitCode: string) => {
		await wasmReady;
		const client = requireUnified();
		if (hasLiveAuth()) {
			return plain(await client.completeLiveOtcPairing(sixDigitCode));
		}
		return plain(client.completeOtcPairing(sixDigitCode));
	},
	revokeLabyrinthDevice: async (targetDeviceId: string) => {
		await wasmReady;
		const client = requireUnified();
		return plain(await client.revokeLabyrinthDevice(targetDeviceId));
	},
	verifyAndReindexHistory: async (conversationId: string) => {
		await wasmReady;
		return Number(await requireUnified().verifyAndReindexHistory(conversationId));
	},
	getReadState: async (conversationId: string) => {
		await wasmReady;
		return plain(await requireUnified().getReadState(conversationId));
	},
	advanceReadState: async (conversationId: string, candidateSeq: number) => {
		await wasmReady;
		return plain(
			await requireUnified().advanceReadState(
				conversationId,
				BigInt(Math.max(0, Math.trunc(candidateSeq)))
			)
		);
	},
	listReadStates: async () => {
		await wasmReady;
		return plain(await requireUnified().listReadStates());
	},
	getCircleOwnerState: async (circleId: string) => {
		await wasmReady;
		return plain(await requireUnified().getCircleOwnerState(circleId));
	},
	putCircleOwnerState: async (stateDto: unknown, swapRecordCid?: string | null) => {
		await wasmReady;
		return requireUnified().putCircleOwnerState(stateDto, swapRecordCid ?? null);
	},
	mergeCircleOwnerState: async (update: unknown) => {
		await wasmReady;
		return plain(await requireUnified().mergeCircleOwnerState(update));
	},
	clearCircleAclTombstone: async (circleId: string, memberDid: string) => {
		await wasmReady;
		return plain(await requireUnified().clearCircleAclTombstone(circleId, memberDid));
	},
	listCircleOwnerStates: async () => {
		await wasmReady;
		return plain(await requireUnified().listCircleOwnerStates());
	},
	listDirectRequests: async (consentFilter?: string | null) => {
		await wasmReady;
		if (!unifiedClient) return [];
		return plain(unifiedClient.listRequests(consentFilter ?? null));
	},
	acceptDirectRequest: async (requestId: string) => {
		await wasmReady;
		const client = requireUnified();
		await client.acceptDirectRequest(requestId);
	},
	declineDirectRequest: async (requestId: string) => {
		await wasmReady;
		const client = requireUnified();
		await client.declineDirectRequest(requestId);
	},
	closeUnifiedClient: async () => {
		await wasmReady;
		if (unifiedClient) {
			unifiedClient.close();
			unifiedClient = null;
		}
		unifiedDeviceId = null;
	}
};

export type WorkerApi = typeof api;
expose(api);

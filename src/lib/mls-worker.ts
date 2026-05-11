// Runs inside a dedicated Worker — has access to OPFS SAH for synchronous SQLite I/O.
import { expose } from 'comlink';
import init, * as wasm from 'catbird-mls-web';

// Initialize the WASM binary when the worker starts.
// Stored as a module-level promise — each exposed method awaits it before calling WASM.
// NOT exposed as a property (Promises can't be structured-cloned across the Worker boundary).
// Runtime returns `InitOutput`, but the worker only awaits readiness — discard the value.
const wasmReady = init().then(() => undefined);

// Active WebSocket subscriptions keyed by conversation ID.
// WsSubscription structs can't cross the Worker boundary, so we track them here.
const subscriptions = new Map<string, { close(): void }>();

// WASM return values may contain non-cloneable JsValue handles.
// Strip them to plain JSON-safe objects for structured clone across Worker boundary.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const plain = (v: any) => (v === undefined || v === null ? v : JSON.parse(JSON.stringify(v)));

const api = {
	// Init & auth — void returns, discard WASM internals
	init: async (config: object) => {
		await wasmReady;
		await wasm.catbird_mls_init(config);
	},
	setAuth: (did: string, token: string) => {
		wasm.catbird_mls_set_auth(did, token);
	},
	clearAuth: () => {
		wasm.catbird_mls_clear_auth();
	},
	// Field-level encryption (Stage 6 / Task 22): install the 32-byte
	// per-DID content root key. Pushed by the main thread after pulling
	// the bytes from localStorage. wasm-bindgen exports the function as
	// `setContentRootKey`/`clearContentRootKey` (see catbird-mls-web/src/lib.rs).
	setContentRootKey: (key: Uint8Array) => {
		(wasm as unknown as { setContentRootKey: (k: Uint8Array) => void }).setContentRootKey(
			key
		);
	},
	clearContentRootKey: () => {
		(wasm as unknown as { clearContentRootKey: () => void }).clearContentRootKey();
	},
	setup: async () => {
		await wasm.catbird_mls_setup();
	},
	replenishKeyPackages: async () => {
		await wasm.catbird_mls_replenish_key_packages();
	},
	ping: () => wasm.catbird_mls_ping(),

	// Conversations — return plain-serializable data
	listConversations: async () => plain(await wasm.catbird_mls_list_conversations()),
	createConversation: async (name: string, memberDids: string[]) =>
		plain(await wasm.catbird_mls_create_conversation(name, memberDids)),
	joinGroup: async (convoId: string) => plain(await wasm.catbird_mls_join_group(convoId)),

	// Messages
	sendMessage: async (convoId: string, content: string) =>
		plain(await wasm.catbird_mls_send_message(convoId, content)),
	sendImage: async (
		convoId: string,
		content: string,
		data: Uint8Array,
		contentType: string,
		width: number,
		height: number,
		altText?: string
	) =>
		plain(
			await wasm.catbird_mls_send_image(
				convoId,
				content,
				data,
				contentType,
				width,
				height,
				altText
			)
		),
	getMessages: async (convoId: string, before?: string) =>
		plain(await wasm.catbird_mls_messages(convoId, before)),
	getImageAttachment: async (
		blobId: string,
		keyB64: string,
		ivB64: string,
		sha256: string,
		contentType: string
	) =>
		wasm.catbird_mls_get_image_attachment(blobId, keyB64, ivB64, sha256, contentType),
	fetchNewMessages: async (convoId: string) =>
		plain(await wasm.catbird_mls_fetch_new_messages(convoId)),
	sendReaction: async (convoId: string, msgId: string, emoji: string, action: string) => {
		await wasm.catbird_mls_send_reaction(convoId, msgId, emoji, action);
	},
	updateCursor: async (convoId: string, cursor: string) => {
		await wasm.catbird_mls_update_cursor(convoId, cursor);
	},

	// Subscribe — callbacks proxied via Comlink.proxy() from main thread.
	// Accepts an optional `cursor` to match the Tauri IPC contract, but the
	// current catbird-mls-web WASM binding does not plumb it through:
	// subscription state is persisted on the Rust side, so the cursor hint
	// is dropped here and the worker relies on that persisted state instead.
	subscribe: async (
		convoId: string,
		onMessage: (data: unknown) => void,
		onEvent: (data: unknown) => void,
		onStatus: (status: unknown) => void,
		_cursor?: string
	) => {
		const sub = await wasm.catbird_mls_subscribe(convoId, onMessage, onEvent, onStatus);
		if (sub) subscriptions.set(convoId, sub);
	},
	unsubscribe: (convoId: string) => {
		subscriptions.get(convoId)?.close();
		subscriptions.delete(convoId);
	},

	// Members
	getMembers: async (convoId: string) =>
		plain(await wasm.catbird_mls_get_members(convoId)),
	addParticipants: async (convoId: string, did: string) => {
		await wasm.catbird_mls_add_participants(convoId, did);
	},
	addGroupMembers: async (convoId: string, memberDids: string[]) => {
		// Batch add — single MLS commit for all members (one epoch advance).
		await wasm.catbird_mls_add_group_members(convoId, memberDids);
	},
	demoteMember: async (convoId: string, did: string) => {
		await wasm.catbird_mls_demote_member(convoId, did);
	},
	sendTyping: async (convoId: string, isTyping: boolean) => {
		await wasm.catbird_mls_send_typing(convoId, isTyping);
	},
	promoteMember: async (convoId: string, did: string) => {
		await wasm.catbird_mls_promote_member(convoId, did);
	},
	removeParticipants: async (convoId: string, did: string) => {
		await wasm.catbird_mls_remove_participants(convoId, did);
	},
	leaveConversation: async (convoId: string) => {
		await wasm.catbird_mls_leave_conversation(convoId);
	},

	// Profiles & search
	getProfiles: async (dids: string[]) =>
		plain(await wasm.catbird_mls_get_profiles(dids)),
	searchUsers: async (query: string) =>
		plain(await wasm.catbird_mls_search_users(query)),
	checkOptInStatus: async (dids: string[]) =>
		plain(await wasm.catbird_mls_check_opt_in_status(dids)),

	// Group metadata (encrypted-only; MLS metadata cutover)
	//
	// Cutover note: post-Wave-1 the WASM `update_group_metadata` returns a
	// rich result object (commit bytes, ciphertext, MetadataReference, version),
	// uploads the encrypted blob internally, and persists the decrypted state
	// to local OPFS-SQLite. `get_group_metadata` reads from that local cache.
	// Hosts MUST call `bootstrapGroupMetadata` after every Welcome / commit
	// merge so titles/descriptions/avatars decode and persist locally.
	getGroupMetadata: async (convoId: string) => {
		const result = wasm.catbird_mls_get_group_metadata(convoId);
		return result ? plain(result) : null;
	},
	updateGroupMetadata: async (
		convoId: string,
		title: string | null,
		description: string | null,
		avatarBlobLocator: string | null,
		avatarContentType: string | null,
		avatarBytes: Uint8Array | null
	) => {
		const result = await wasm.catbird_mls_update_group_metadata(
			convoId,
			title ?? undefined,
			description ?? undefined,
			avatarBlobLocator ?? undefined,
			avatarContentType ?? undefined,
			avatarBytes ?? undefined
		);
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

	// Voice messages (WASM bindings pending Rust implementation)
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
	) =>
		plain(
			await (wasm as any).catbird_mls_send_voice(
				convoId,
				audioData,
				contentType,
				durationMs,
				plain(waveform),
				transcript ?? null
			)
		),
	fetchAndDecryptBlob: async (
		blobId: string,
		key: Uint8Array,
		iv: Uint8Array,
		sha256: string
	) => await (wasm as any).catbird_mls_fetch_and_decrypt_blob(blobId, key, iv, sha256)
};

export type WorkerApi = typeof api;
expose(api);

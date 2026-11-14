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

let unifiedClient: wasm.WasmMlsClient | null = null;
let unifiedDeviceId: string | null = null;
let latestAuthToken: string | null = null;
let backgroundSyncTimer: ReturnType<typeof setInterval> | null = null;

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

function decodeBase64Bytes(input: string): Uint8Array {
	const normalized = input.trim().replace(/-/g, '+').replace(/_/g, '/');
	if (!normalized) return new Uint8Array();
	const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
	const bin = atob(padded);
	const out = new Uint8Array(bin.length);
	for (let i = 0; i < bin.length; i += 1) {
		out[i] = bin.charCodeAt(i);
	}
	return out;
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

function extractMessageDetails(plaintextJson: string): {
	messageType: string;
	content: string;
	image?: {
		blobId: string;
		keyB64: string;
		ivB64: string;
		sha256: string;
		contentType: string;
		size: number;
		width: number;
		height: number;
		altText?: string;
		blurhash?: string;
	};
	audio?: {
		blobId: string;
		key: Uint8Array;
		iv: Uint8Array;
		keyB64: string;
		ivB64: string;
		sha256: string;
		contentType: string;
		size: number;
		durationMs: number;
		waveform: number[];
		transcript?: string;
	};
} {
	try {
		const parsed = JSON.parse(plaintextJson) as Record<string, unknown>;
		let messageType =
			typeof parsed.messageType === 'string'
				? parsed.messageType
				: typeof parsed.type === 'string'
					? parsed.type
					: 'text';
		const content =
			typeof parsed.text === 'string'
				? parsed.text
				: typeof parsed.content === 'string'
					? parsed.content
					: typeof parsed.embed === 'object' && parsed.embed !== null
						? ''
						: plaintextJson;

		const embed =
			typeof parsed.embed === 'object' && parsed.embed !== null
				? (parsed.embed as Record<string, unknown>)
				: null;
		if (embed?.type === 'image') {
			messageType = 'image';
			return {
				messageType,
				content,
				image: {
					blobId: String(embed.blobId ?? ''),
					keyB64: String(embed.key ?? embed.keyB64 ?? ''),
					ivB64: String(embed.iv ?? embed.ivB64 ?? ''),
					sha256: String(embed.sha256 ?? ''),
					contentType: String(embed.contentType ?? 'image/jpeg'),
					size: Number(embed.size ?? 0),
					width: Number(embed.width ?? 0),
					height: Number(embed.height ?? 0),
					altText: typeof embed.altText === 'string' ? embed.altText : undefined,
					blurhash: typeof embed.blurhash === 'string' ? embed.blurhash : undefined
				}
			};
		}
		if (embed?.type === 'audio') {
			messageType = 'voice';
			const keyB64 = String(embed.key ?? embed.keyB64 ?? '');
			const ivB64 = String(embed.iv ?? embed.ivB64 ?? '');
			const waveformRaw = Array.isArray(embed.waveform)
				? embed.waveform.map((n) => Number(n)).filter((n) => Number.isFinite(n))
				: [];
			return {
				messageType,
				content,
				audio: {
					blobId: String(embed.blobId ?? ''),
					key: decodeBase64Bytes(keyB64),
					iv: decodeBase64Bytes(ivB64),
					keyB64,
					ivB64,
					sha256: String(embed.sha256 ?? ''),
					contentType: String(embed.contentType ?? 'audio/webm;codecs=opus'),
					size: Number(embed.size ?? 0),
					durationMs: Number(embed.durationMs ?? 0),
					waveform: waveformRaw,
					transcript: typeof embed.transcript === 'string' ? embed.transcript : undefined
				}
			};
		}
		return { messageType, content };
	} catch {
		return { messageType: 'text', content: plaintextJson };
	}
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function mapMessageRowToUi(rawRow: any) {
	const row = plain(rawRow);
	const { messageType, content, image, audio } = extractMessageDetails(
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
		...(audio ? { audio, audioAttachment: audio } : {})
	};
}

function bestEffortAdvanceReadState(convoId: string, maxSeq: number) {
	if (!unifiedClient || !latestAuthToken || maxSeq < 1) return;
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
		if (backgroundSyncTimer) {
			clearInterval(backgroundSyncTimer);
			backgroundSyncTimer = null;
		}
		if (unifiedClient) {
			unifiedClient.setAuthToken(null);
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
		if (unifiedClient) {
			const uploaded = await unifiedClient.uploadConversationAttachment(
				convoId,
				data,
				contentType || 'image/jpeg'
			);
			const msgId = crypto.randomUUID().toLowerCase();
			const row = await unifiedClient.sendMediaAttachmentMessage(
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
			unifiedClient.flushLabyrinthQueue().catch(() => {});
			return mapMessageRowToUi(row);
		}
		return plain(
			await wasm.catbird_mls_send_image(
				convoId,
				content,
				data,
				contentType,
				width,
				height,
				altText
			)
		);
	},
	getMessages: async (convoId: string, before?: string) => {
		await wasmReady;
		if (!unifiedClient) return [];
		const beforeSeq = before && /^\d+$/.test(before) ? BigInt(before) : null;
		const rows = (plain(unifiedClient.listMessages(convoId, beforeSeq, 50)) as unknown[]) ?? [];
		const mapped = rows.map(mapMessageRowToUi);
		mapped.sort((a, b) => a.sequenceNumber - b.sequenceNumber);
		const maxSeq = mapped.reduce((acc, m) => Math.max(acc, m.sequenceNumber), 0);
		bestEffortAdvanceReadState(convoId, maxSeq);
		return mapped;
	},
	getImageAttachment: async (
		blobId: string,
		keyB64: string,
		ivB64: string,
		sha256: string,
		contentType: string,
		convoId = ''
	) => {
		await wasmReady;
		if (unifiedClient) {
			const keyBytes = decodeBase64Bytes(keyB64);
			const ivBytes = decodeBase64Bytes(ivB64);
			const shaBytes = decodeSha256Bytes(sha256);
			const bytes = await unifiedClient.downloadConversationAttachment(
				blobId,
				keyBytes,
				ivBytes,
				shaBytes
			);
			const mime = contentType || 'image/jpeg';
			return `data:${mime};base64,${encodeBase64Bytes(bytes)}`;
		}
		return wasm.catbird_mls_get_image_attachment(
			convoId,
			blobId,
			keyB64,
			ivB64,
			sha256,
			contentType
		);
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
		_onEvent: (data: unknown) => void,
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
	getProfiles: async (dids: string[]) =>
		plain(await wasm.catbird_mls_get_profiles(dids)),
	searchUsers: async (query: string) =>
		plain(await wasm.catbird_mls_search_users(query)),
	checkOptInStatus: async (dids: string[]) =>
		plain(await wasm.catbird_mls_check_opt_in_status(dids)),

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
		if (unifiedClient) {
			const mime = contentType || 'audio/webm;codecs=opus';
			const uploaded = await unifiedClient.uploadConversationAttachment(convoId, audioData, mime);
			const msgId = crypto.randomUUID().toLowerCase();
			const row = await unifiedClient.sendMediaAttachmentMessage(
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
			unifiedClient.flushLabyrinthQueue().catch(() => {});
			return mapMessageRowToUi(row);
		}
		return plain(
			await (wasm as any).catbird_mls_send_voice(
				convoId,
				audioData,
				contentType,
				durationMs,
				plain(waveform),
				transcript ?? null
			)
		);
	},
	fetchAndDecryptBlob: async (
		blobId: string,
		key: Uint8Array | number[],
		iv: Uint8Array | number[],
		sha256: string
	) => {
		await wasmReady;
		const keyBytes = key instanceof Uint8Array ? key : new Uint8Array(key);
		const ivBytes = iv instanceof Uint8Array ? iv : new Uint8Array(iv);
		if (unifiedClient) {
			const shaBytes = decodeSha256Bytes(sha256);
			return unifiedClient.downloadConversationAttachment(blobId, keyBytes, ivBytes, shaBytes);
		}
		return await (wasm as any).catbird_mls_fetch_and_decrypt_blob(blobId, keyBytes, ivBytes, sha256);
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
	}) => {
		await wasmReady;
		if (params.authToken !== undefined) {
			latestAuthToken = params.authToken;
		}
		const normalizedTarget = params.accountDid.trim().toLowerCase();
		if (unifiedClient && unifiedClient.accountDid() === normalizedTarget) {
			unifiedDeviceId = params.deviceId;
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
			params.pdsEndpoint,
			params.dbKeyHex
		);
		unifiedDeviceId = params.deviceId;
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
		if (latestAuthToken) {
			return client.createRecoveryCodeLive();
		}
		return client.setupRecoveryCode();
	},
	restoreWithRecoveryCode: async (recoveryCodeInput: string) => {
		await wasmReady;
		const client = requireUnified();
		if (latestAuthToken) {
			return plain(await client.restoreWithRecoveryCodeLive(recoveryCodeInput));
		}
		return plain(client.restoreWithRecoveryCode(recoveryCodeInput));
	},
	registerPasskeyPrf: async (credentialId: Uint8Array, prfOutput32: Uint8Array) => {
		await wasmReady;
		const client = requireUnified();
		if (latestAuthToken) {
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
		return plain(requireUnified().initiateOtcPairing());
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
		if (latestAuthToken) {
			return plain(await client.completeLiveOtcPairing(sixDigitCode));
		}
		return plain(client.completeOtcPairing(sixDigitCode));
	},
	revokeLabyrinthDevice: async (targetDeviceId: string) => {
		await wasmReady;
		const client = requireUnified();
		if (latestAuthToken) {
			return plain(await client.revokeDevice(targetDeviceId));
		}
		return plain(client.revokeLabyrinthDevice(targetDeviceId));
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

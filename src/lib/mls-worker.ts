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

function extractMessageTextAndType(plaintextJson: string): { messageType: string; content: string } {
	try {
		const parsed = JSON.parse(plaintextJson) as Record<string, unknown>;
		const messageType =
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
					: plaintextJson;
		return { messageType, content };
	} catch {
		return { messageType: 'text', content: plaintextJson };
	}
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function mapMessageRowToUi(rawRow: any) {
	const row = plain(rawRow);
	const { messageType, content } = extractMessageTextAndType(String(row.plaintext_json ?? ''));
	const createdMs = Number(row.created_at_ms ?? Date.now());
	return {
		id: String(row.message_id ?? ''),
		conversationId: String(row.conversation_id ?? ''),
		senderDid: String(row.sender_did ?? ''),
		senderHandle: '',
		content,
		timestamp: new Date(createdMs).toISOString(),
		sequenceNumber: Math.max(0, Number(row.seq ?? 0)),
		status: row.is_own ? 'sent' : 'delivered',
		messageType
	};
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
		lastMessage = extractMessageTextAndType(String(lastMsg.plaintext_json ?? '')).content;
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
	setContentRootKey: (_key: Uint8Array) => {},
	clearContentRootKey: () => {},
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
	getMessages: async (convoId: string, before?: string) => {
		await wasmReady;
		if (!unifiedClient) return [];
		const beforeSeq = before && /^\d+$/.test(before) ? BigInt(before) : null;
		const rows = (plain(unifiedClient.listMessages(convoId, beforeSeq, 50)) as unknown[]) ?? [];
		const mapped = rows.map(mapMessageRowToUi);
		mapped.sort((a, b) => a.sequenceNumber - b.sequenceNumber);
		return mapped;
	},
	getImageAttachment: async (
		blobId: string,
		keyB64: string,
		ivB64: string,
		sha256: string,
		contentType: string,
		convoId = ''
	) =>
		wasm.catbird_mls_get_image_attachment(
			convoId,
			blobId,
			keyB64,
			ivB64,
			sha256,
			contentType
		),
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
			await client.removeGroupMember(true, convoId, client.accountDid());
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
	) => await (wasm as any).catbird_mls_fetch_and_decrypt_blob(blobId, key, iv, sha256),

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
		}
		unifiedClient = await wasm.WasmMlsClient.openAsync(
			params.accountDid,
			params.deviceId,
			params.homeDsDid,
			params.homeDsEndpoint,
			params.pdsEndpoint,
			params.dbKeyHex
		);
		if (latestAuthToken !== null) {
			unifiedClient.setAuthToken(latestAuthToken);
		}
		return {
			accountDid: unifiedClient.accountDid(),
			accountDidHash: unifiedClient.accountDidHash()
		};
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
	setupRecoveryCode: async () => {
		await wasmReady;
		if (!unifiedClient) throw new Error('WasmMlsClient is not open');
		return unifiedClient.setupRecoveryCode();
	},
	restoreWithRecoveryCode: async (recoveryCodeInput: string) => {
		await wasmReady;
		if (!unifiedClient) throw new Error('WasmMlsClient is not open');
		return plain(unifiedClient.restoreWithRecoveryCode(recoveryCodeInput));
	},
	registerPasskeyPrf: async (credentialId: Uint8Array, prfOutput32: Uint8Array) => {
		await wasmReady;
		if (!unifiedClient) throw new Error('WasmMlsClient is not open');
		return plain(unifiedClient.registerPasskeyPrf(credentialId, prfOutput32));
	},
	initiateOtcPairing: async () => {
		await wasmReady;
		if (!unifiedClient) throw new Error('WasmMlsClient is not open');
		return plain(unifiedClient.initiateOtcPairing());
	},
	completeOtcPairing: async (sixDigitCode: string) => {
		await wasmReady;
		if (!unifiedClient) throw new Error('WasmMlsClient is not open');
		return plain(unifiedClient.completeOtcPairing(sixDigitCode));
	},
	revokeLabyrinthDevice: async (targetDeviceId: string) => {
		await wasmReady;
		if (!unifiedClient) throw new Error('WasmMlsClient is not open');
		return plain(unifiedClient.revokeLabyrinthDevice(targetDeviceId));
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
	}
};

export type WorkerApi = typeof api;
expose(api);

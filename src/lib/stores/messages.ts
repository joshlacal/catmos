import { get, writable } from 'svelte/store';
import type {
	Message,
	AudioAttachment,
	PreparedImageUpload,
	ReactionEvent,
	TypingEvent
} from '#lib/tauri.ts';
import { applyReactionToMap, stripDidFragment } from '#lib/did.ts';
import { readMessageWindow, reconcileMessages } from '../message-window.ts';
import { conversations } from './conversations.ts';
import * as api from '#lib/wasm.ts';

export interface MessagesStore {
	byConversation: Map<string, Message[]>;
	typingByConversation: Map<string, string[]>;
	hasMoreByConversation: Map<string, boolean>;
	loadingOlderByConversation: Map<string, boolean>;
	errorByConversation: Map<string, string | null>;
	loading: boolean;
}

const DEFAULT_PAGE_SIZE = 50;

interface RetryAction {
	kind: 'text' | 'image' | 'voice';
	content: string;
	upload?: PreparedImageUpload;
	audioData?: Uint8Array;
	durationMs?: number;
	waveform?: number[];
	contentType?: string;
	transcript?: string;
}

function createInitialState(): MessagesStore {
	return {
		byConversation: new Map(),
		typingByConversation: new Map(),
		hasMoreByConversation: new Map(),
		loadingOlderByConversation: new Map(),
		errorByConversation: new Map(),
		loading: false
	};
}

function createMessagesStore() {
	const store = writable<MessagesStore>(createInitialState());

	const { subscribe, update } = store;
	const latest = new Map<string, symbol>();
	const retryPayloads = new Map<string, RetryAction>();
	let accountDid: string | undefined;
	let session = Symbol();

	function updateRoom(
		cid: string,
		apply: (rows: Message[]) => Message[],
		opts?: { loading?: boolean; error?: string | null; hasMore?: boolean }
	) {
		update((s) => {
			const byConversation = new Map(s.byConversation);
			byConversation.set(cid, apply(byConversation.get(cid) ?? []));
			const errorByConversation = new Map(s.errorByConversation);
			if (opts && 'error' in opts) {
				errorByConversation.set(cid, opts.error ?? null);
			}
			const hasMoreByConversation = new Map(s.hasMoreByConversation);
			if (opts && typeof opts.hasMore === 'boolean') {
				hasMoreByConversation.set(cid, opts.hasMore);
			}
			return {
				...s,
				byConversation,
				errorByConversation,
				hasMoreByConversation,
				loading: opts?.loading ?? s.loading
			};
		});
	}

	async function refresh(conversationId: string, source: 'local' | 'open' | 'server') {
		const owner = session;
		const request = Symbol();
		latest.set(conversationId, request);
		const previous = get(store).byConversation.get(conversationId) ?? [];
		if (source === 'open') update((s) => ({ ...s, loading: true }));
		try {
			const page =
				source === 'server'
					? await api.fetchNewMessages(conversationId)
					: await api.getMessages(conversationId, undefined, source === 'open');
			const stored = await readMessageWindow(previous, page, (before) =>
				api.getMessages(conversationId, before, false)
			);
			if (latest.get(conversationId) !== request) {
				// A parallel local read may have completed before the server sync committed.
				if (owner === session && source === 'server') await refresh(conversationId, 'local');
				return;
			}
			const hasMore = page.length >= DEFAULT_PAGE_SIZE;
			updateRoom(conversationId, (rows) => reconcileMessages(rows, stored), {
				loading: false,
				error: null,
				hasMore: source === 'open' ? hasMore : undefined
			});
		} catch (error) {
			if (latest.get(conversationId) !== request) return;
			console.warn('[catmos] Could not refresh room messages', error);
			const errMsg = error instanceof Error ? error.message : 'Could not load messages.';
			// A failed read cannot vouch for previously displayed plaintext.
			updateRoom(conversationId, (rows) => reconcileMessages(rows, []), {
				loading: false,
				error: errMsg
			});
		}
	}

	async function submit(
		optimistic: Message,
		send: () => Promise<Message>,
		retryAction: RetryAction
	) {
		const owner = session;
		const cid = optimistic.conversationId;
		retryPayloads.set(optimistic.id, retryAction);
		updateRoom(cid, (rows) => [...rows, optimistic]);
		conversations.applyMessageActivity(cid, {
			text:
				optimistic.content ||
				(optimistic.messageType === 'image'
					? 'Photo'
					: optimistic.messageType === 'voice'
						? 'Voice message'
						: ''),
			timestamp: optimistic.timestamp,
			isOwn: true,
			isSelected: true
		});
		try {
			await send();
		} catch (error) {
			if (owner !== session) return;
			console.error('[catmos] Message send failed', error);
			updateRoom(cid, (rows) =>
				rows.map((row) => (row.id === optimistic.id ? { ...row, status: 'failed' } : row))
			);
			return;
		}
		if (owner !== session) return;
		retryPayloads.delete(optimistic.id);
		updateRoom(cid, (rows) => rows.filter((row) => row.id !== optimistic.id));
		// The send response may precede or follow an erasure. Read the committed rows.
		await refresh(cid, 'local');
	}

	return {
		subscribe,
		setAccount(did: string | undefined) {
			if (did === accountDid) return;
			accountDid = did;
			session = Symbol();
			latest.clear();
			retryPayloads.clear();
			store.set(createInitialState());
		},
		setConversationMessages(cid: string, rows: Message[], hasMore = false) {
			updateRoom(cid, () => rows, { loading: false, error: null, hasMore });
		},
		load: (cid: string) => refresh(cid, 'open'),
		fetchFromServer: (cid: string) => refresh(cid, 'server'),
		refreshLocal: (cid: string) => refresh(cid, 'local'),
		async loadOlder(conversationId: string): Promise<number> {
			const current = get(store);
			if (current.loadingOlderByConversation.get(conversationId)) return 0;
			const existing = current.byConversation.get(conversationId) ?? [];
			const oldest = existing.find((m) => !m.id.startsWith('temp-'));
			if (!oldest) return 0;

			update((s) => {
				const next = new Map(s.loadingOlderByConversation);
				next.set(conversationId, true);
				return { ...s, loadingOlderByConversation: next };
			});

			try {
				const older = await api.getMessages(conversationId, oldest.id, false);
				const hasMore = older.length >= DEFAULT_PAGE_SIZE;
				update((s) => {
					const byConversation = new Map(s.byConversation);
					const cur = byConversation.get(conversationId) ?? [];
					const seen = new Set(cur.map((m) => m.id));
					const uniqueOlder = older.filter((m) => !seen.has(m.id));
					byConversation.set(conversationId, [...uniqueOlder, ...cur]);
					const hasMoreByConversation = new Map(s.hasMoreByConversation);
					hasMoreByConversation.set(conversationId, hasMore);
					const loadingOlderByConversation = new Map(s.loadingOlderByConversation);
					loadingOlderByConversation.set(conversationId, false);
					return {
						...s,
						byConversation,
						hasMoreByConversation,
						loadingOlderByConversation
					};
				});
				return older.length;
			} catch (err) {
				console.warn('[catmos] loadOlder failed:', err);
				update((s) => {
					const loadingOlderByConversation = new Map(s.loadingOlderByConversation);
					loadingOlderByConversation.set(conversationId, false);
					return { ...s, loadingOlderByConversation };
				});
				return 0;
			}
		},
		async refreshCached(active?: string) {
			const rooms = new Set(get(store).byConversation.keys());
			if (active) rooms.add(active);
			await Promise.all(Array.from(rooms, (cid) => refresh(cid, 'local')));
		},
		async send(conversationId: string, content: string) {
			const optimistic: Message = {
				id: `temp-${crypto.randomUUID()}`,
				conversationId,
				senderDid: accountDid ?? '',
				senderHandle: 'You',
				content,
				timestamp: new Date().toISOString(),
				status: 'sending',
				isOwn: true,
				messageType: 'text'
			};
			await submit(
				optimistic,
				() => api.sendMessage(conversationId, content),
				{ kind: 'text', content }
			);
		},
		async sendImage(conversationId: string, content: string, upload: PreparedImageUpload) {
			const optimistic: Message = {
				id: `temp-image-${crypto.randomUUID()}`,
				conversationId,
				senderDid: accountDid ?? '',
				senderHandle: 'You',
				content,
				timestamp: new Date().toISOString(),
				status: 'sending',
				isOwn: true,
				messageType: 'image',
				image: {
					blobId: '',
					keyB64: '',
					ivB64: '',
					sha256: '',
					contentType: upload.contentType,
					size: upload.data.length,
					width: upload.width,
					height: upload.height,
					altText: upload.altText,
					localUrl: upload.previewUrl
				}
			};
			await submit(
				optimistic,
				() =>
					api.sendImage(
						conversationId,
						content,
						upload.data,
						upload.contentType,
						upload.width,
						upload.height,
						upload.altText
					),
				{ kind: 'image', content, upload }
			);
		},
		async sendVoice(
			conversationId: string,
			audioData: Uint8Array,
			durationMs: number,
			waveform: number[],
			contentType = 'audio/webm;codecs=opus',
			transcript?: string
		) {
			const audioPayload: AudioAttachment = {
				blobId: '',
				key: new Uint8Array(),
				iv: new Uint8Array(),
				sha256: '',
				contentType,
				size: audioData.length,
				durationMs,
				waveform,
				transcript
			};
			const optimistic: Message = {
				id: `temp-voice-${crypto.randomUUID()}`,
				conversationId,
				senderDid: accountDid ?? '',
				senderHandle: 'You',
				content: '',
				timestamp: new Date().toISOString(),
				status: 'sending',
				isOwn: true,
				messageType: 'voice',
				audio: audioPayload,
				audioAttachment: audioPayload
			};
			await submit(
				optimistic,
				() =>
					api.sendVoice(
						conversationId,
						audioData,
						contentType,
						durationMs,
						waveform,
						transcript
					),
				{ kind: 'voice', content: '', audioData, durationMs, waveform, contentType, transcript }
			);
		},
		async retryMessage(conversationId: string, messageId: string) {
			const existing = (get(store).byConversation.get(conversationId) ?? []).find(
				(m) => m.id === messageId
			);
			const payload = retryPayloads.get(messageId);
			retryPayloads.delete(messageId);
			updateRoom(conversationId, (rows) => rows.filter((r) => r.id !== messageId));

			if (payload?.kind === 'image' && payload.upload) {
				await this.sendImage(conversationId, payload.content, payload.upload);
			} else if (payload?.kind === 'voice' && payload.audioData) {
				await this.sendVoice(
					conversationId,
					payload.audioData,
					payload.durationMs ?? 0,
					payload.waveform ?? [],
					payload.contentType,
					payload.transcript
				);
			} else if (payload?.kind === 'text') {
				await this.send(conversationId, payload.content);
			} else if (existing?.content) {
				await this.send(conversationId, existing.content);
			}
		},
		deleteFailedMessage(conversationId: string, messageId: string) {
			retryPayloads.delete(messageId);
			updateRoom(conversationId, (rows) => rows.filter((r) => r.id !== messageId));
		},
		applyReaction(event: ReactionEvent) {
			update((s) => {
				const byConversation = new Map(s.byConversation);
				const existing = byConversation.get(event.conversationId);
				if (!existing) return s;

				byConversation.set(
					event.conversationId,
					existing.map((m) => {
						if (m.id !== event.messageId) return m;
						const reactions = applyReactionToMap(
							m.reactions,
							event.senderDid,
							event.emoji,
							event.action
						);
						return { ...m, reactions };
					})
				);
				return { ...s, byConversation };
			});
		},
		applyTyping(event: TypingEvent) {
			const accountDidStr = stripDidFragment(event.senderDid);
			if (!accountDidStr) return;
			update((s) => {
				const typingByConversation = new Map(s.typingByConversation);
				const existing = typingByConversation.get(event.conversationId) ?? [];
				const next = existing.map((did) => stripDidFragment(did)).filter(Boolean);

				if (event.isTyping) {
					if (!next.includes(accountDidStr)) {
						next.push(accountDidStr);
					}
				} else {
					for (let i = next.length - 1; i >= 0; i -= 1) {
						if (next[i] === accountDidStr) next.splice(i, 1);
					}
				}

				if (next.length > 0) {
					typingByConversation.set(event.conversationId, next);
				} else {
					typingByConversation.delete(event.conversationId);
				}

				return { ...s, typingByConversation };
			});
		},
		reset() {
			session = Symbol();
			latest.clear();
			retryPayloads.clear();
			store.set(createInitialState());
		}
	};
}

export const messages = createMessagesStore();

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
import * as api from '#lib/wasm.ts';

interface MessagesStore {
	byConversation: Map<string, Message[]>;
	typingByConversation: Map<string, string[]>;
	loading: boolean;
}

function createMessagesStore() {
	const store = writable<MessagesStore>({
		byConversation: new Map(),
		typingByConversation: new Map(),
		loading: false
	});

	const { subscribe, update } = store;
	const latest = new Map<string, symbol>();
	let accountDid: string | undefined;
	let session = Symbol();

	function updateRoom(cid: string, apply: (rows: Message[]) => Message[], loading?: boolean) {
		update((s) => {
			const byConversation = new Map(s.byConversation);
			byConversation.set(cid, apply(byConversation.get(cid) ?? []));
			return { ...s, byConversation, loading: loading ?? s.loading };
		});
	}

	async function refresh(conversationId: string, source: 'local' | 'open' | 'server') {
		const owner = session;
		const request = Symbol();
		latest.set(conversationId, request);
		const previous = get(store).byConversation.get(conversationId) ?? [];
		if (source === 'open') update((s) => ({ ...s, loading: true }));
		try {
			const page = source === 'server'
				? await api.fetchNewMessages(conversationId)
				: await api.getMessages(conversationId, undefined, source === 'open');
			const stored = await readMessageWindow(previous, page, (before) => api.getMessages(conversationId, before, false));
			if (latest.get(conversationId) !== request) {
				// A parallel local read may have completed before the server sync committed.
				if (owner === session && source === 'server') await refresh(conversationId, 'local');
				return;
			}
			updateRoom(conversationId, (rows) => reconcileMessages(rows, stored), false);
		} catch (error) {
			if (latest.get(conversationId) !== request) return;
			console.warn('[catmos] Could not refresh room messages', error);
			// A failed read cannot vouch for previously displayed plaintext.
			updateRoom(conversationId, (rows) => reconcileMessages(rows, []), false);
		}
	}

	async function submit(optimistic: Message, send: () => Promise<Message>) {
		const owner = session;
		const cid = optimistic.conversationId;
		updateRoom(cid, (rows) => [...rows, optimistic]);
		try {
			await send();
		} catch (error) {
			if (owner !== session) return;
			console.error('[catmos] Message send failed', error);
			updateRoom(cid, (rows) => rows.map((row) => row.id === optimistic.id ? { ...row, status: 'failed' } : row));
			return;
		}
		if (owner !== session) return;
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
			store.set({ byConversation: new Map(), typingByConversation: new Map(), loading: false });
		},
		load: (cid: string) => refresh(cid, 'open'),
		fetchFromServer: (cid: string) => refresh(cid, 'server'),
		refreshLocal: (cid: string) => refresh(cid, 'local'),
		async refreshCached(active?: string) {
			const rooms = new Set(get(store).byConversation.keys());
			if (active) rooms.add(active);
			await Promise.all(Array.from(rooms, (cid) => refresh(cid, 'local')));
		},
		async send(conversationId: string, content: string) {
			const optimistic: Message = {
				id: `temp-${crypto.randomUUID()}`,
				conversationId,
				senderDid: '',
				senderHandle: 'You',
				content,
				timestamp: new Date().toISOString(),
				status: 'sending',
				messageType: 'text'
			};
			await submit(optimistic, () => api.sendMessage(conversationId, content));
		},
		async sendImage(conversationId: string, content: string, upload: PreparedImageUpload) {
			const optimistic: Message = {
				id: `temp-image-${crypto.randomUUID()}`,
				conversationId,
				senderDid: '',
				senderHandle: 'You',
				content,
				timestamp: new Date().toISOString(),
				status: 'sending',
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
			await submit(optimistic, () => api.sendImage(
				conversationId,
				content,
				upload.data,
				upload.contentType,
				upload.width,
				upload.height,
				upload.altText
			));
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
				senderDid: '',
				senderHandle: 'You',
				content: '',
				timestamp: new Date().toISOString(),
				status: 'sending',
				messageType: 'voice',
				audio: audioPayload,
				audioAttachment: audioPayload
			};
			await submit(optimistic, () => api.sendVoice(
				conversationId,
				audioData,
				contentType,
				durationMs,
				waveform,
				transcript
			));
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
			const accountDid = stripDidFragment(event.senderDid);
			if (!accountDid) return;
			update((s) => {
				const typingByConversation = new Map(s.typingByConversation);
				const existing = typingByConversation.get(event.conversationId) ?? [];
				const next = existing.map((did) => stripDidFragment(did)).filter(Boolean);

				if (event.isTyping) {
					if (!next.includes(accountDid)) {
						next.push(accountDid);
					}
				} else {
					for (let i = next.length - 1; i >= 0; i -= 1) {
						if (next[i] === accountDid) next.splice(i, 1);
					}
				}

				if (next.length > 0) {
					typingByConversation.set(event.conversationId, next);
				} else {
					typingByConversation.delete(event.conversationId);
				}

				return { ...s, typingByConversation };
			});
		}
	};
}

export const messages = createMessagesStore();

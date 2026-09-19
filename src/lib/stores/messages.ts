import { writable } from 'svelte/store';
import type {
	Message,
	AudioAttachment,
	PreparedImageUpload,
	ReactionEvent,
	TypingEvent
} from '$lib/tauri';
import * as api from '$lib/wasm';

interface MessagesStore {
	byConversation: Map<string, Message[]>;
	typingByConversation: Map<string, string[]>;
	loading: boolean;
}

function sortMessages(msgs: Message[]): Message[] {
	return msgs.sort((a, b) => {
		// Sequence belongs to the stable conversation. Local ACK timestamps can
		// be later than the timestamp of a subsequent incoming message.
		const aConfirmed = Number.isSafeInteger(a.sequenceNumber) && (a.sequenceNumber ?? 0) > 0;
		const bConfirmed = Number.isSafeInteger(b.sequenceNumber) && (b.sequenceNumber ?? 0) > 0;
		if (aConfirmed !== bConfirmed) return aConfirmed ? -1 : 1;
		if (aConfirmed && bConfirmed && a.sequenceNumber !== b.sequenceNumber) {
			return a.sequenceNumber! - b.sequenceNumber!;
		}
		// Unconfirmed/legacy rows stay at the tail. Treat invalid dates
		// consistently so the comparator remains transitive even for old rows.
		const aTime = Date.parse(a.timestamp);
		const bTime = Date.parse(b.timestamp);
		const timestampOrder = (Number.isFinite(aTime) ? aTime : 0) - (Number.isFinite(bTime) ? bTime : 0);
		if (timestampOrder !== 0) return timestampOrder;
		return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
	});
}

function createMessagesStore() {
	let ownerDid: string | null = null;
	let epoch = 0;
	const { subscribe, update, set } = writable<MessagesStore>({
		byConversation: new Map(),
		typingByConversation: new Map(),
		loading: false
	});

	return {
		subscribe,
		bindAccount(owner: string | null) { if (owner === ownerDid) return; ownerDid = owner; epoch++; set({ byConversation: new Map(), typingByConversation: new Map(), loading: false }); },
		async load(conversationId: string) {
			const revision = epoch;
            const operationOwner = ownerDid;
            if (!operationOwner) return;
			update((s) => ({ ...s, loading: true }));
			try {
				const msgs = await api.getMessages(conversationId, undefined, operationOwner);
				if (revision !== epoch) return;
				// Deduplicate by ID to prevent Svelte {#each} key collisions
				const seen = new Set<string>();
				const deduped = msgs.filter((m) => {
					if (seen.has(m.id)) return false;
					seen.add(m.id);
					return true;
				});
				update((s) => {
					const byConversation = new Map(s.byConversation);
					byConversation.set(conversationId, sortMessages(deduped));
					return { ...s, byConversation, loading: false };
				});
			} catch {
				update((s) => ({ ...s, loading: false }));
			}
		},
		async fetchFromServer(conversationId: string) {
			const revision = epoch;
            const operationOwner = ownerDid;
            if (!operationOwner) return;
			try {
				const msgs = await api.fetchNewMessages(conversationId, operationOwner);
				if (revision !== epoch) return;
				update((s) => {
					const byConversation = new Map(s.byConversation);
					const existing = byConversation.get(conversationId) ?? [];
					// Merge: add any messages not already present (dedup both sides)
					const existingIds = new Set(existing.map((m) => m.id));
					const newMsgs = msgs.filter((m) => {
						if (existingIds.has(m.id)) return false;
						existingIds.add(m.id); // prevent dupes within the batch too
						return true;
					});
					if (newMsgs.length > 0) {
						byConversation.set(conversationId, sortMessages([...existing, ...newMsgs]));
					}
					return { ...s, byConversation };
				});
			} catch (e) {
				console.error('fetchFromServer failed:', e);
			}
		},
		async send(conversationId: string, content: string) {
            const revision = epoch;
            const operationOwner = ownerDid;
            if (!operationOwner) return;
			const optimistic: Message = {
				id: `temp-${Date.now()}`,
				conversationId,
				senderDid: '',
				senderHandle: 'You',
				content,
				timestamp: new Date().toISOString(),
				status: 'sending',
				messageType: 'text'
			};
			update((s) => {
				const byConversation = new Map(s.byConversation);
				const existing = byConversation.get(conversationId) ?? [];
				byConversation.set(conversationId, sortMessages([...existing, optimistic]));
				return { ...s, byConversation };
			});
			try {
				const sent = await api.sendMessage(conversationId, content, operationOwner);
				if (revision !== epoch) return;
				update((s) => {
					const byConversation = new Map(s.byConversation);
					const existing = byConversation.get(conversationId) ?? [];
					byConversation.set(
						conversationId,
						sortMessages(existing.map((m) => (m.id === optimistic.id ? sent : m)))
					);
					return { ...s, byConversation };
				});
			} catch (e) {
				console.error('[catmos] sendMessage failed:', e);
				if (revision !== epoch) return;
				update((s) => {
					const byConversation = new Map(s.byConversation);
					const existing = byConversation.get(conversationId) ?? [];
					byConversation.set(
						conversationId,
						existing.map((m) =>
							m.id === optimistic.id ? { ...m, status: 'failed' as const } : m
						)
					);
					return { ...s, byConversation };
				});
			}
		},
		async sendImage(conversationId: string, content: string, upload: PreparedImageUpload) {
            const revision = epoch;
            const operationOwner = ownerDid;
            if (!operationOwner) return;
			const optimistic: Message = {
				id: `temp-image-${Date.now()}`,
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
			update((s) => {
				const byConversation = new Map(s.byConversation);
				const existing = byConversation.get(conversationId) ?? [];
				byConversation.set(conversationId, sortMessages([...existing, optimistic]));
				return { ...s, byConversation };
			});
			try {
				const sent = await api.sendImage(
					conversationId,
					content,
					upload.data,
					upload.contentType,
					upload.width,
					upload.height,
					upload.altText,
                    operationOwner
				);
				if (revision !== epoch) return;
				update((s) => {
					const byConversation = new Map(s.byConversation);
					const existing = byConversation.get(conversationId) ?? [];
					byConversation.set(
						conversationId,
						sortMessages(existing.map((m) => (m.id === optimistic.id ? sent : m)))
					);
					return { ...s, byConversation };
				});
			} catch (e) {
				console.error('[catmos] sendImage failed:', e);
				if (revision !== epoch) return;
				update((s) => {
					const byConversation = new Map(s.byConversation);
					const existing = byConversation.get(conversationId) ?? [];
					byConversation.set(
						conversationId,
						existing.map((m) =>
							m.id === optimistic.id ? { ...m, status: 'failed' as const } : m
						)
					);
					return { ...s, byConversation };
				});
			}
		},
		async sendVoice(conversationId: string, audioData: Uint8Array, durationMs: number, waveform: number[]) {
            const revision = epoch;
            const operationOwner = ownerDid;
            if (!operationOwner) return;
			const optimistic: Message = {
				id: `temp-voice-${Date.now()}`,
				conversationId,
				senderDid: '',
				senderHandle: 'You',
				content: '',
				timestamp: new Date().toISOString(),
				status: 'sending',
				messageType: 'voice',
				audioAttachment: {
					blobId: '',
					key: new Uint8Array(),
					iv: new Uint8Array(),
					sha256: '',
					contentType: 'audio/webm;codecs=opus',
					size: audioData.length,
					durationMs,
					waveform
				}
			};
			update((s) => {
				const byConversation = new Map(s.byConversation);
				const existing = byConversation.get(conversationId) ?? [];
				byConversation.set(conversationId, sortMessages([...existing, optimistic]));
				return { ...s, byConversation };
			});
			try {
				const sent = await api.sendVoice(
					conversationId,
					audioData,
					'audio/webm;codecs=opus',
					durationMs,
					waveform
				);
				if (revision !== epoch) return;
				update((s) => {
					const byConversation = new Map(s.byConversation);
					const existing = byConversation.get(conversationId) ?? [];
					byConversation.set(
						conversationId,
						sortMessages(existing.map((m) => (m.id === optimistic.id ? sent : m)))
					);
					return { ...s, byConversation };
				});
			} catch (e) {
				console.error('[catmos] sendVoice failed:', e);
				if (revision !== epoch) return;
				update((s) => {
					const byConversation = new Map(s.byConversation);
					const existing = byConversation.get(conversationId) ?? [];
					byConversation.set(
						conversationId,
						existing.map((m) =>
							m.id === optimistic.id ? { ...m, status: 'failed' as const } : m
						)
					);
					return { ...s, byConversation };
				});
			}
		},
		addIncoming(message: Message) {
			update((s) => {
				const byConversation = new Map(s.byConversation);
				const existing = byConversation.get(message.conversationId) ?? [];
				if (!existing.find((m) => m.id === message.id)) {
					byConversation.set(message.conversationId, sortMessages([...existing, message]));
				}
				return { ...s, byConversation };
			});
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
						const reactions = { ...(m.reactions ?? {}) };
						const users = reactions[event.emoji] ? [...reactions[event.emoji]] : [];

						if (event.action === 'add') {
							if (!users.includes(event.senderDid)) {
								users.push(event.senderDid);
							}
						} else {
							const idx = users.indexOf(event.senderDid);
							if (idx >= 0) users.splice(idx, 1);
						}

						if (users.length > 0) {
							reactions[event.emoji] = users;
						} else {
							delete reactions[event.emoji];
						}

						return { ...m, reactions };
					})
				);
				return { ...s, byConversation };
			});
		},
		applyTyping(event: TypingEvent) {
			update((s) => {
				const typingByConversation = new Map(s.typingByConversation);
				const existing = typingByConversation.get(event.conversationId) ?? [];
				const next = [...existing];

				if (event.isTyping) {
					if (!next.includes(event.senderDid)) {
						next.push(event.senderDid);
					}
				} else {
					const idx = next.indexOf(event.senderDid);
					if (idx >= 0) next.splice(idx, 1);
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

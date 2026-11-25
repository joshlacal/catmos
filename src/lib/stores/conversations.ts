import { writable, derived, get } from 'svelte/store';
import type { Conversation } from '#lib/tauri.ts';
import { dedupeAccountDids, isSameAccountDid, stripDidFragment } from '#lib/did.ts';
import * as api from '#lib/wasm.ts';
import { createBlock, listOwnBlocks } from '#lib/wasm.ts';

export interface ConversationsStore {
	items: Conversation[];
	selectedId: string | null;
	loading: boolean;
	error: string | null;
}

export interface MessageActivityUpdate {
	text: string;
	timestamp: string;
	isOwn: boolean;
	isSelected?: boolean;
}

/**
 * Unwrap structured JSON message content (reply envelopes or embeds) into a
 * single-line preview string so raw JSON never leaks into sidebars or search.
 */
export function extractMessagePreview(content: string | undefined | null): string {
	if (!content) return '';
	const trimmed = content.trim();
	if (!trimmed) return '';
	if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
		try {
			const parsed = JSON.parse(trimmed) as Record<string, unknown>;
			if (typeof parsed.text === 'string' && parsed.text.trim()) {
				return parsed.text.trim();
			}
			if (typeof parsed.content === 'string' && parsed.content.trim()) {
				return parsed.content.trim();
			}
			const embed = parsed.embed as { type?: string } | undefined;
			if (embed && typeof embed.type === 'string') {
				switch (embed.type) {
					case 'image':
						return 'Photo';
					case 'audio':
						return 'Voice message';
					case 'gif':
						return 'GIF';
					case 'post':
						return 'Shared post';
					case 'link':
						return 'Shared link';
				}
			}
		} catch {
			// Fall through to raw string
		}
	}
	return trimmed;
}

function sortByRecent(items: Conversation[]): Conversation[] {
	return [...items].sort((a, b) => {
		const ta = a.lastMessageAt ? Date.parse(a.lastMessageAt) : 0;
		const tb = b.lastMessageAt ? Date.parse(b.lastMessageAt) : 0;
		const safeA = Number.isFinite(ta) ? ta : 0;
		const safeB = Number.isFinite(tb) ? tb : 0;
		return safeB - safeA;
	});
}

function createConversationsStore() {
	const { subscribe, set, update } = writable<ConversationsStore>({
		items: [],
		selectedId: null,
		loading: false,
		error: null
	});

	let currentState: ConversationsStore = {
		items: [],
		selectedId: null,
		loading: false,
		error: null
	};
	subscribe((s) => {
		currentState = s;
	});

	return {
		subscribe,
		findDirectConversation(targetDid: string): string | null {
			const targetAccount = stripDidFragment(targetDid);
			if (!targetAccount) return null;
			const match = currentState.items.find((c) => {
				if (c.isGroup) return false;
				const accountMembers = dedupeAccountDids(c.members);
				return accountMembers.length === 2 && accountMembers.includes(targetAccount);
			});
			return match?.id ?? null;
		},
		async load() {
			update((s) => ({ ...s, loading: true, error: null }));
			try {
				const raw = await api.getConversations();
				const seen = new Set<string>();
				const items = raw
					.filter((c) => {
						if (seen.has(c.id)) return false;
						seen.add(c.id);
						return true;
					})
					.map((c) => ({
						...c,
						lastMessage: c.lastMessage ? extractMessagePreview(c.lastMessage) : c.lastMessage
					}));
				update((s) => ({ ...s, items, loading: false, error: null }));
			} catch (err) {
				const message = err instanceof Error ? err.message : 'Unable to load conversations.';
				update((s) => ({ ...s, loading: false, error: message }));
			}
		},
		select(id: string | null) {
			update((s) => ({ ...s, selectedId: id }));
		},
		setItems(items: Conversation[], selectedId?: string | null) {
			update((s) => ({
				...s,
				items,
				selectedId: selectedId === undefined ? s.selectedId : selectedId,
				loading: false,
				error: null
			}));
		},
		async createGroup(name: string, memberDids: string[], description?: string) {
			const conversation = await api.createGroup(name, memberDids, description);
			update((s) => ({
				...s,
				items: s.items.some((c) => c.id === conversation.id)
					? s.items
					: [conversation, ...s.items],
				selectedId: conversation.id,
				error: null
			}));
			return conversation;
		},
		updateConversation(conversation: Conversation) {
			update((s) => ({
				...s,
				items: s.items.map((c) => (c.id === conversation.id ? conversation : c))
			}));
		},
		applyMessageActivity(conversationId: string, activity: MessageActivityUpdate) {
			const preview = extractMessagePreview(activity.text);
			update((s) => {
				const idx = s.items.findIndex((c) => c.id === conversationId);
				if (idx < 0) return s;
				const isSelected = activity.isSelected ?? s.selectedId === conversationId;
				const updated = s.items.map((c) => {
					if (c.id !== conversationId) return c;
					const nextUnread = activity.isOwn || isSelected ? 0 : (c.unreadCount ?? 0) + 1;
					return {
						...c,
						lastMessage: preview || c.lastMessage,
						lastMessageAt: activity.timestamp || c.lastMessageAt,
						unreadCount: nextUnread
					};
				});
				return { ...s, items: sortByRecent(updated) };
			});
		},
		markConversationRead(conversationId: string) {
			if (!currentState.items.find((room) => room.id === conversationId)?.unreadCount) return;
			update((s) => ({
				...s,
				items: s.items.map((c) => (c.id === conversationId ? { ...c, unreadCount: 0 } : c))
			}));
		},
		async leaveConversation(id: string) {
			await api.leaveConversation(id);
			update((s) => ({
				...s,
				items: s.items.filter((c) => c.id !== id),
				selectedId: s.selectedId === id ? null : s.selectedId
			}));
		},
		reset() {
			set({ items: [], selectedId: null, loading: false, error: null });
		}
	};
}

export const conversations = createConversationsStore();

export const selectedConversation = derived(
	conversations,
	($c) => $c.items.find((item) => item.id === $c.selectedId) ?? null
);

export function affectedConversationsFor(did: string): Conversation[] {
	const state = get(conversations);
	return state.items.filter((c) =>
		c.members.some((memberDid) => isSameAccountDid(memberDid, did))
	);
}

export async function blockAndLeave(targetDid: string): Promise<string[]> {
	const affected = affectedConversationsFor(targetDid);
	await createBlock(targetDid);

	const leftIds: string[] = [];
	for (const convo of affected) {
		try {
			await conversations.leaveConversation(convo.id);
			leftIds.push(convo.id);
		} catch (e) {
			console.error(`[catmos] leave ${convo.id} failed after block`, e);
		}
	}
	return leftIds;
}

export async function reconcileBlockedConversations(): Promise<number> {
	let blocked: Set<string>;
	try {
		blocked = await listOwnBlocks();
	} catch (e) {
		console.warn('[catmos] block reconciliation skipped: listOwnBlocks failed', e);
		return 0;
	}
	if (blocked.size === 0) return 0;

	const state = get(conversations);
	const toLeave = state.items.filter((c) =>
		c.members.some((did) => blocked.has(stripDidFragment(did)))
	);

	let leftCount = 0;
	for (const convo of toLeave) {
		try {
			await conversations.leaveConversation(convo.id);
			leftCount += 1;
		} catch (e) {
			console.warn(`[catmos] reconcile leave ${convo.id} failed`, e);
		}
	}
	if (leftCount > 0) {
		console.info(`[catmos] Reconciled: left ${leftCount} group(s) containing blocked users`);
	}
	return leftCount;
}

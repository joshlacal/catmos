import { writable, derived, get } from 'svelte/store';
import type { Conversation } from '$lib/tauri';
import * as api from '$lib/wasm';
import { createBlock, listOwnBlocks } from '$lib/wasm';

interface ConversationsStore {
	items: Conversation[];
	selectedId: string | null;
	loading: boolean;
}

function createConversationsStore() {
	const { subscribe, set, update } = writable<ConversationsStore>({
		items: [],
		selectedId: null,
		loading: false
	});

	let ownerDid: string | null = null;
	let epoch = 0;
	let currentState: ConversationsStore = { items: [], selectedId: null, loading: false };
	subscribe((s) => { currentState = s; });

	return {
		subscribe,
		bindAccount(owner: string | null) { if (owner === ownerDid) return; ownerDid = owner; epoch++; set({ items: [], selectedId: null, loading: false }); },
		findDirectConversation(targetDid: string): string | null {
			const match = currentState.items.find(
				(c) =>
					(c.conversationKind === 'direct' || !c.isGroup) &&
					c.members.length === 2 &&
					c.members.includes(targetDid)
			);
			return match?.id ?? null;
		},
		async load() {
			const revision = epoch;
			update((s) => ({ ...s, loading: true }));
			try {
				const raw = await api.getConversations();
				if (revision !== epoch) return;
				// Deduplicate by ID to prevent Svelte {#each} key collisions
				const seen = new Set<string>();
				const items = raw.filter((c) => {
					if (seen.has(c.id)) return false;
					seen.add(c.id);
					return true;
				});
				update((s) => ({ ...s, items, loading: false }));
			} catch {
				if (revision !== epoch) return;
				update((s) => ({ ...s, loading: false }));
			}
		},
		select(id: string | null) {
			update((s) => ({ ...s, selectedId: id }));
		},
		async createGroup(name: string, memberDids: string[], description?: string) {
			const conversation = await api.createGroup(name, memberDids, description);
			update((s) => ({
				...s,
				// Avoid duplicate if conversation already in list from a prior load()
				items: s.items.some((c) => c.id === conversation.id)
					? s.items
					: [conversation, ...s.items],
				selectedId: conversation.id
			}));
			return conversation;
		},
		updateConversation(conversation: Conversation) {
			update((s) => ({
				...s,
				items: s.items.map((c) => (c.id === conversation.id ? conversation : c))
			}));
		},
		markConversationRead(conversationId: string) {
			update((s) => ({
				...s,
				items: s.items.map((c) =>
					c.id === conversationId ? { ...c, unreadCount: 0 } : c
				)
			}));
		},
		async leaveConversation(id: string) {
			await api.leaveConversation(id);
			update((s) => ({
				...s,
				items: s.items.filter((c) => c.id !== id),
				selectedId: s.selectedId === id ? null : s.selectedId
			}));
		}
	};
}

export const conversations = createConversationsStore();

export const selectedConversation = derived(conversations, ($c) =>
	$c.items.find((item) => item.id === $c.selectedId) ?? null
);

/**
 * Find every conversation whose member list contains `did`.
 * Used to show "blocking will leave N conversations" UX.
 *
 * Note: `Conversation.members` is `string[]` of DIDs in catmos (not
 * `{did: string}[]` like some other clients).
 */
export function affectedConversationsFor(did: string): Conversation[] {
	const state = get(conversations);
	return state.items.filter((c) => c.members.includes(did));
}

/**
 * Publish an `app.bsky.graph.block` for `targetDid`, then leave every shared
 * MLS conversation. The block record is published FIRST so that if a leave
 * fails (or the app crashes mid-flow), the block survives and the startup
 * reconciliation pass (`reconcileBlockedConversations`) will catch up on
 * any remaining groups the next time the app launches.
 *
 * Returns the list of conversation IDs we successfully left.
 */
export async function blockAndLeave(targetDid: string): Promise<string[]> {
	const affected = affectedConversationsFor(targetDid);

	// Publish the block first — a failed leave can be retried by startup
	// reconciliation, but a missing block would leave the UX inconsistent.
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

/**
 * Startup reconciliation: leave any MLS conversation that contains a DID
 * the current user has blocked. Catches up on blocks made from other
 * clients (iOS, another browser session, etc.) and on any leaves that
 * failed during a previous `blockAndLeave` call.
 *
 * Call this ONCE per app launch after the initial `conversations.load()`
 * has populated the store. Safe to call again if new data arrives, but
 * should be guarded by a flag to avoid repeated API traffic.
 */
export async function reconcileBlockedConversations(): Promise<number> {
	let blocked: Set<string>;
	try {
		blocked = await listOwnBlocks();
	} catch (e) {
		console.warn('[catmos] block reconciliation skipped — listOwnBlocks failed', e);
		return 0;
	}
	if (blocked.size === 0) return 0;

	const state = get(conversations);
	const toLeave = state.items.filter((c) =>
		!c.pendingConsent && c.members.some((did) => blocked.has(did))
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

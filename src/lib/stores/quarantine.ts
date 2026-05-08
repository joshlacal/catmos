/**
 * Layer 3 MLS quarantine store.
 *
 * Tracks quarantine state per conversation, sourced from:
 *  - `mls://quarantined` Tauri events (live transitions)
 *  - `mls://quarantine-cleared` Tauri events
 *  - `getQuarantineState()` pull on conversation select / app load
 *    (covers restart with a pre-existing quarantined row, where no event
 *    fires because the state was set in a prior process)
 *
 * Consumers: the `+page.svelte` conversation view (banner + composer gate)
 * and the member info panel (paused-since / suspected DIDs surface).
 */
import { writable, derived } from 'svelte/store';
import type {
	QuarantineState,
	QuarantineEnteredEvent,
	QuarantineClearedEvent
} from '$lib/tauri';
import { getQuarantineState as fetchQuarantineState } from '$lib/wasm';

type QuarantineMap = Record<string, QuarantineState>;

function createQuarantineStore() {
	const { subscribe, update, set } = writable<QuarantineMap>({});

	return {
		subscribe,
		/** Apply a `mls://quarantined` event payload. */
		applyEnteredEvent(event: QuarantineEnteredEvent) {
			update((map) => ({
				...map,
				[event.convoId]: {
					reasonTag: event.reasonTag,
					// Server doesn't send `since_ms` on the event payload (it's
					// only on the persisted state snapshot); use the time we
					// observed the event so the UI has something to render.
					sinceMs: Date.now(),
					suspectedDids: event.suspectedDids
				}
			}));
		},
		/** Apply a `mls://quarantine-cleared` event payload. */
		applyClearedEvent(event: QuarantineClearedEvent) {
			update((map) => {
				if (!(event.convoId in map)) return map;
				const next = { ...map };
				delete next[event.convoId];
				return next;
			});
		},
		/**
		 * Pull-based seed for a conversation's quarantine state. Idempotent.
		 * Call on conversation select (or on app load for the active convo).
		 */
		async refresh(conversationId: string) {
			try {
				const state = await fetchQuarantineState(conversationId);
				update((map) => {
					const next = { ...map };
					if (state) {
						next[conversationId] = state;
					} else {
						delete next[conversationId];
					}
					return next;
				});
			} catch (err) {
				console.warn('[quarantine] refresh failed:', err);
			}
		},
		/** Wipe the entire store, e.g. on logout. */
		reset() {
			set({});
		}
	};
}

export const quarantine = createQuarantineStore();

/**
 * Derived helper: quarantine state for a single conversation, or `null`.
 * Consumers should call this with `derived` themselves when they need
 * reactivity tied to a specific conversation id; this is just a pure helper.
 */
export function isQuarantined(map: QuarantineMap, conversationId: string | null): boolean {
	if (!conversationId) return false;
	return conversationId in map;
}

/** Friendlier copy for each `QuarantineReasonTag`, used in the banner / info panel. */
export function quarantineReasonCopy(reasonTag: string): string {
	switch (reasonTag) {
		case 'peer_bad_commit':
			return 'A participant repeatedly sent invalid commits.';
		case 'multi_peer_bad_commits':
			return 'Multiple participants sent invalid commits.';
		case 'repeated_framing_failures':
			return 'Recent messages could not be decoded — likely a buggy client.';
		default:
			return 'A participant may be sending invalid messages.';
	}
}

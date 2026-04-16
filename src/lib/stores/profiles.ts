import { writable, get } from 'svelte/store';
import type { ProfileView } from '$lib/tauri';
import * as api from '$lib/wasm';

interface ProfilesStore {
	cache: Map<string, ProfileView>;
	pending: Set<string>;
}

function createProfilesStore() {
	const { subscribe, update } = writable<ProfilesStore>({
		cache: new Map(),
		pending: new Set()
	});

	let batchTimeout: ReturnType<typeof setTimeout> | null = null;
	let batchDids: Set<string> = new Set();

	async function flushBatch() {
		batchTimeout = null;
		const dids = Array.from(batchDids);
		batchDids = new Set();
		if (dids.length === 0) return;

		try {
			const profiles = await api.getProfiles(dids);
			update((s) => {
				const cache = new Map(s.cache);
				const pending = new Set(s.pending);
				for (const p of profiles) {
					cache.set(p.did, p);
					pending.delete(p.did);
				}
				// Mark any DIDs that weren't returned as resolved (no profile found)
				for (const did of dids) {
					pending.delete(did);
					if (!cache.has(did)) {
						cache.set(did, { did, handle: did, displayName: undefined, avatar: undefined });
					}
				}
				return { cache, pending };
			});
		} catch (e) {
			console.error('Failed to fetch profiles:', e);
			update((s) => {
				const pending = new Set(s.pending);
				for (const did of dids) {
					pending.delete(did);
				}
				return { ...s, pending };
			});
		}
	}

	return {
		subscribe,
		resolveProfiles(dids: string[]) {
			const store = get({ subscribe });
			const needed = dids.filter((d) => d && !store.cache.has(d) && !store.pending.has(d));
			if (needed.length === 0) return;

			update((s) => {
				const pending = new Set(s.pending);
				for (const did of needed) {
					pending.add(did);
					batchDids.add(did);
				}
				return { ...s, pending };
			});

			// Batch: wait 50ms to collect more DIDs before fetching
			if (batchTimeout) clearTimeout(batchTimeout);
			batchTimeout = setTimeout(flushBatch, 50);
		},
		getProfile(did: string): ProfileView | undefined {
			const store = get({ subscribe });
			return store.cache.get(did);
		},
		/** Manually set a profile (e.g., for the current user after login) */
		setProfile(profile: ProfileView) {
			update((s) => {
				const cache = new Map(s.cache);
				cache.set(profile.did, profile);
				return { ...s, cache };
			});
		}
	};
}

export const profiles = createProfilesStore();

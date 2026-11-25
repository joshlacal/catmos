import { writable, get } from 'svelte/store';
import type { ProfileView } from '#lib/tauri.ts';
import { dedupeAccountDids, stripDidFragment } from '#lib/did.ts';
import * as api from '#lib/wasm.ts';

interface ProfilesStore {
	cache: Map<string, ProfileView>;
	pending: Set<string>;
}

export function shortDid(did: string): string {
	const bare = stripDidFragment(did) || did;
	if (!bare) return 'Unknown';
	if (bare.length <= 22) return bare;
	return `${bare.slice(0, 14)}...${bare.slice(-5)}`;
}

export function resolveProfileName(
	cache: Map<string, ProfileView>,
	did: string,
	fallbackHandle?: string
): string {
	const accountDid = stripDidFragment(did);
	const profile = accountDid ? cache.get(accountDid) : undefined;
	if (profile?.displayName && profile.displayName.trim()) {
		return profile.displayName.trim();
	}
	if (profile?.handle && !profile.handle.startsWith('did:')) {
		return `@${profile.handle}`;
	}
	const cleanFallback = stripDidFragment(fallbackHandle);
	if (cleanFallback && !cleanFallback.startsWith('did:')) {
		return cleanFallback.startsWith('@') ? cleanFallback : `@${cleanFallback}`;
	}
	return shortDid(accountDid || did);
}

function createProfilesStore() {
	const { subscribe, update, set } = writable<ProfilesStore>({
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
			const results = await api.getProfiles(dids);
			update((s) => {
				const cache = new Map(s.cache);
				const pending = new Set(s.pending);
				for (const p of results) {
					const accountDid = stripDidFragment(p.did);
					if (!accountDid) continue;
					const normalizedProfile = { ...p, did: accountDid };
					cache.set(accountDid, normalizedProfile);
					pending.delete(accountDid);
				}
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
			const accountDids = dedupeAccountDids(dids);
			const needed = accountDids.filter((d) => !store.cache.has(d) && !store.pending.has(d));
			if (needed.length === 0) return;

			update((s) => {
				const pending = new Set(s.pending);
				for (const did of needed) {
					pending.add(did);
					batchDids.add(did);
				}
				return { ...s, pending };
			});

			if (batchTimeout) clearTimeout(batchTimeout);
			batchTimeout = setTimeout(flushBatch, 50);
		},
		getProfile(did: string): ProfileView | undefined {
			const accountDid = stripDidFragment(did);
			if (!accountDid) return undefined;
			const store = get({ subscribe });
			return store.cache.get(accountDid);
		},
		setProfile(profile: ProfileView) {
			const accountDid = stripDidFragment(profile.did);
			if (!accountDid) return;
			update((s) => {
				const cache = new Map(s.cache);
				cache.set(accountDid, { ...profile, did: accountDid });
				return { ...s, cache };
			});
		},
		reset() {
			if (batchTimeout) {
				clearTimeout(batchTimeout);
				batchTimeout = null;
			}
			batchDids.clear();
			set({ cache: new Map(), pending: new Set() });
		}
	};
}

export const profiles = createProfilesStore();

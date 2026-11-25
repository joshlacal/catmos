import { writable } from 'svelte/store';
import { stripDidFragment } from '#lib/did.ts';

const STORAGE_PREFIX = 'catmos-drafts';
const DEBOUNCE_MS = 500;

function getStorage(): Storage | null {
	if (typeof window === 'undefined') return null;
	if (typeof (window as unknown as Record<string, unknown>).__TAURI_INTERNALS__ !== 'undefined') {
		return window.localStorage;
	}
	return window.sessionStorage;
}

function keyForDid(did: string | null): string {
	const bare = stripDidFragment(did);
	return bare ? `${STORAGE_PREFIX}:${bare}` : STORAGE_PREFIX;
}

function loadDrafts(storageKey: string): Map<string, string> {
	const storage = getStorage();
	if (!storage) return new Map();
	try {
		const raw = storage.getItem(storageKey);
		if (!raw) return new Map();
		const entries: [string, string][] = JSON.parse(raw);
		return new Map(entries);
	} catch {
		return new Map();
	}
}

function persistDrafts(storageKey: string, map: Map<string, string>): void {
	const storage = getStorage();
	if (!storage) return;
	try {
		storage.setItem(storageKey, JSON.stringify(Array.from(map.entries())));
	} catch {
		// Storage full or unavailable
	}
}

function createDraftsStore() {
	let activeKey = STORAGE_PREFIX;
	let map = loadDrafts(activeKey);
	const { subscribe, set } = writable<Map<string, string>>(new Map(map));
	const debounceTimers = new Map<string, ReturnType<typeof setTimeout>>();

	function clearTimers() {
		for (const timer of debounceTimers.values()) clearTimeout(timer);
		debounceTimers.clear();
	}

	function notify() {
		set(new Map(map));
	}

	return {
		subscribe,
		setActiveDid(did: string | null) {
			const nextKey = keyForDid(did);
			if (nextKey === activeKey) return;
			clearTimers();
			activeKey = nextKey;
			map = loadDrafts(activeKey);
			notify();
		},
		setDraft(convoId: string, text: string): void {
			if (text.trim()) {
				map.set(convoId, text);
			} else {
				map.delete(convoId);
			}
			notify();

			const existing = debounceTimers.get(convoId);
			if (existing) clearTimeout(existing);

			const targetKey = activeKey;
			const timer = setTimeout(() => {
				debounceTimers.delete(convoId);
				if (targetKey === activeKey) {
					persistDrafts(activeKey, map);
				}
			}, DEBOUNCE_MS);
			debounceTimers.set(convoId, timer);
		},
		getDraft(convoId: string): string {
			return map.get(convoId) ?? '';
		},
		clearDraft(convoId: string): void {
			const existing = debounceTimers.get(convoId);
			if (existing) {
				clearTimeout(existing);
				debounceTimers.delete(convoId);
			}
			map.delete(convoId);
			persistDrafts(activeKey, map);
			notify();
		},
		hasDraft(convoId: string): boolean {
			return map.has(convoId) && (map.get(convoId)?.trim().length ?? 0) > 0;
		},
		reset(): void {
			clearTimers();
			activeKey = STORAGE_PREFIX;
			map = new Map();
			notify();
		}
	};
}

export const drafts = createDraftsStore();

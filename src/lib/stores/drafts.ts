import { writable } from 'svelte/store';

const STORAGE_KEY = 'catmos-drafts';
const DEBOUNCE_MS = 500;

function getStorage(): Storage | null {
  if (typeof window === 'undefined') return null;
  // Tauri desktop → localStorage (persists across sessions)
  // Browser → sessionStorage (clears on tab close)
  if (typeof (window as unknown as Record<string, unknown>).__TAURI_INTERNALS__ !== 'undefined') {
    return window.localStorage;
  }
  return window.sessionStorage;
}

function loadDrafts(): Map<string, string> {
  const storage = getStorage();
  if (!storage) return new Map();
  try {
    const raw = storage.getItem(STORAGE_KEY);
    if (!raw) return new Map();
    const entries: [string, string][] = JSON.parse(raw);
    return new Map(entries);
  } catch {
    return new Map();
  }
}

function persistDrafts(drafts: Map<string, string>): void {
  const storage = getStorage();
  if (!storage) return;
  try {
    const entries = Array.from(drafts.entries());
    storage.setItem(STORAGE_KEY, JSON.stringify(entries));
  } catch {
    // Storage full or unavailable — silently ignore
  }
}

function createDraftsStore() {
  const map = loadDrafts();
  const { subscribe, set } = writable<Map<string, string>>(map);

  const debounceTimers = new Map<string, ReturnType<typeof setTimeout>>();

  function notify() {
    set(new Map(map));
  }

  return {
    subscribe,

    setDraft(convoId: string, text: string): void {
      // Clear any pending debounce for this conversation
      const existing = debounceTimers.get(convoId);
      if (existing) clearTimeout(existing);

      const timer = setTimeout(() => {
        debounceTimers.delete(convoId);
        if (text.trim()) {
          map.set(convoId, text);
        } else {
          map.delete(convoId);
        }
        persistDrafts(map);
        notify();
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
      persistDrafts(map);
      notify();
    },

    hasDraft(convoId: string): boolean {
      return map.has(convoId) && (map.get(convoId)?.trim().length ?? 0) > 0;
    }
  };
}

export const drafts = createDraftsStore();

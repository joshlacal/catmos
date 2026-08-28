/**
 * Persists per-conversation WebSocket subscription cursors (last-seen message ID)
 * so that on restart, subscriptions can resume from where they left off.
 *
 * - Desktop (Tauri): persists to localStorage (survives restarts)
 * - Web (browser): persists to sessionStorage (cleared on tab close)
 *
 * Keys are namespaced by DID + convoId to prevent data leakage across accounts.
 */

const CURSOR_PREFIX = 'catbird_ws_cursor-clean-v2-openmls-v09';

/** True when running inside Tauri desktop shell. */
const isTauri: boolean =
  typeof window !== 'undefined' && typeof window.__TAURI_INTERNALS__ !== 'undefined';

function getStorage(): Storage {
  return isTauri ? localStorage : sessionStorage;
}

function storageKey(did: string, convoId: string): string {
  return `${CURSOR_PREFIX}:${did}:${convoId}`;
}

/** Read the current DID from localStorage (set by wasm.ts on login). */
function getCurrentDid(): string | null {
  return localStorage.getItem('catbird_mls-clean-v2-openmls-v09_user_did');
}

/**
 * Save a cursor value for a conversation.
 * No-op if no user is logged in.
 */
export function saveCursor(convoId: string, cursor: string): void {
  const did = getCurrentDid();
  if (!did) return;
  try {
    getStorage().setItem(storageKey(did, convoId), cursor);
  } catch {
    // Storage full or unavailable -- degrade silently
  }
}

/**
 * Retrieve the saved cursor for a conversation, or null if none exists.
 */
export function getCursor(convoId: string): string | null {
  const did = getCurrentDid();
  if (!did) return null;
  try {
    return getStorage().getItem(storageKey(did, convoId));
  } catch {
    return null;
  }
}

/**
 * Remove the saved cursor for a conversation.
 */
export function removeCursor(convoId: string): void {
  const did = getCurrentDid();
  if (!did) return;
  try {
    getStorage().removeItem(storageKey(did, convoId));
  } catch {
    // ignore
  }
}

/**
 * Clear all saved cursors for the current user.
 */
export function clearAllCursors(): void {
  const did = getCurrentDid();
  if (!did) return;
  const storage = getStorage();
  const prefix = `${CURSOR_PREFIX}:${did}:`;
  const keysToRemove: string[] = [];
  for (let i = 0; i < storage.length; i++) {
    const key = storage.key(i);
    if (key?.startsWith(prefix)) {
      keysToRemove.push(key);
    }
  }
  for (const key of keysToRemove) {
    storage.removeItem(key);
  }
}

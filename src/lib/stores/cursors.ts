/**
 * Persists per-conversation WebSocket subscription cursors (last-seen message ID)
 * so that on restart, subscriptions can resume from where they left off.
 *
 * - Desktop (Tauri): persists to localStorage (survives restarts)
 * - Web (browser): persists to sessionStorage (cleared on tab close)
 *
 * Keys are namespaced by DID + convoId to prevent data leakage across accounts.
 */

/**
 * Browser storage generation pin. Bumping this invalidates every browser-side
 * MLS namespace at once (cursors, active DID, MLS storage coordinates, tab lock).
 */
export const CLEAN_STORAGE_SUFFIX = '-clean-v2-openmls-v09-device-identity-v1';
export const CURSOR_PREFIX = `catbird_ws_cursor${CLEAN_STORAGE_SUFFIX}`;
export const SS_ACTIVE_DID = `catbird_mls_active_did${CLEAN_STORAGE_SUFFIX}`;

/** True when running inside Tauri desktop shell. */
const isTauri: boolean =
  typeof window !== 'undefined' && typeof window.__TAURI_INTERNALS__ !== 'undefined';

function getStorage(): Storage | null {
  if (typeof window === 'undefined') return null;
  return isTauri ? localStorage : sessionStorage;
}

function storageKey(did: string, convoId: string): string {
  return `${CURSOR_PREFIX}:${did}:${convoId}`;
}

function cursorRegistryKey(did: string): string {
  return `catbird_mls:${did}:cursor_registry${CLEAN_STORAGE_SUFFIX}`;
}

/** Set the active DID across storage layers for the current runtime. */
export function setAuthoritativeActiveDid(did: string): void {
  if (typeof window === 'undefined') return;
  const normalized = did.trim();
  if (isTauri) {
    localStorage.setItem(SS_ACTIVE_DID, normalized);
  }
  sessionStorage.setItem(SS_ACTIVE_DID, normalized);
}

/** Clear the active DID across storage layers for the current runtime. */
export function clearAuthoritativeActiveDid(): void {
  if (typeof window === 'undefined') return;
  if (isTauri) {
    localStorage.removeItem(SS_ACTIVE_DID);
  }
  sessionStorage.removeItem(SS_ACTIVE_DID);
}

/** Read the current DID from the exact active DID session key (written by persistBrowserAuth / setAuthoritativeActiveDid). */
function getCurrentDid(): string | null {
  if (typeof window === 'undefined') return null;
  if (isTauri) {
    return (
      localStorage.getItem(SS_ACTIVE_DID) ??
      sessionStorage.getItem(SS_ACTIVE_DID)
    );
  }
  return sessionStorage.getItem(SS_ACTIVE_DID);
}

function getRegisteredConvoIds(storage: Storage, did: string): string[] {
  const raw = storage.getItem(cursorRegistryKey(did));
  if (!raw) return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    throw new Error(`Clean storage corrupted cursor registry for ${did}: ${String(e)}`);
  }
  if (!Array.isArray(parsed) || !parsed.every((id) => typeof id === 'string')) {
    throw new Error(`Clean storage invalid cursor registry structure for ${did}`);
  }
  return parsed as string[];
}

function addConvoToRegistry(storage: Storage, did: string, convoId: string): void {
  const list = getRegisteredConvoIds(storage, did);
  if (!list.includes(convoId)) {
    list.push(convoId);
    storage.setItem(cursorRegistryKey(did), JSON.stringify(list));
  }
}

function removeConvoFromRegistry(storage: Storage, did: string, convoId: string): void {
  const list = getRegisteredConvoIds(storage, did);
  const filtered = list.filter((id) => id !== convoId);
  if (filtered.length > 0) {
    storage.setItem(cursorRegistryKey(did), JSON.stringify(filtered));
  } else {
    storage.removeItem(cursorRegistryKey(did));
  }
}

/**
 * Save a cursor value for a conversation.
 * No-op if no user is logged in.
 */
export function saveCursor(convoId: string, cursor: string): void {
  const did = getCurrentDid();
  const storage = getStorage();
  if (!did || !storage) return;
  addConvoToRegistry(storage, did, convoId);
  storage.setItem(storageKey(did, convoId), cursor);
}

/**
 * Retrieve the saved cursor for a conversation, or null if none exists.
 */
export function getCursor(convoId: string): string | null {
  const did = getCurrentDid();
  const storage = getStorage();
  if (!did || !storage) return null;
  return storage.getItem(storageKey(did, convoId));
}

/**
 * Remove the saved cursor for a conversation.
 */
export function removeCursor(convoId: string): void {
  const did = getCurrentDid();
  const storage = getStorage();
  if (!did || !storage) return;
  storage.removeItem(storageKey(did, convoId));
  removeConvoFromRegistry(storage, did, convoId);
}

/**
 * Clear saved cursors for a DID, scanning storage keys only if its registry is corrupt.
 */
export function clearAllCursorsForDid(did: string): void {
  if (typeof window === 'undefined') return;
  for (const s of [sessionStorage, localStorage]) {
    let convoIds: string[] = [];
    try {
      convoIds = getRegisteredConvoIds(s, did);
    } catch {
      const owner = `${CURSOR_PREFIX}:${did}`;
      // A cursor key is `${owner}:${convoId}` and a convoId never contains ':',
      // so trimming the last segment must land exactly on this DID's owner prefix:
      // clearing `did:web:x` must not touch the neighboring `did:web:x:user`.
      // Reverse order: removing index i only shifts down the indices above it,
      // which have already been visited. A forward loop would skip keys.
      for (let index = s.length - 1; index >= 0; index -= 1) {
        const key = s.key(index);
        if (key && key.slice(0, key.lastIndexOf(':')) === owner) {
          s.removeItem(key);
        }
      }
    }
    for (const id of convoIds) {
      s.removeItem(storageKey(did, id));
    }
    s.removeItem(cursorRegistryKey(did));
  }
}

/**
 * Clear all saved cursors for the current user without storage iteration.
 */
export function clearAllCursors(): void {
  const did = getCurrentDid();
  if (!did) return;
  clearAllCursorsForDid(did);
}

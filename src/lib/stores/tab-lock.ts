/**
 * Single-tab enforcement for Catmos Web.
 *
 * Uses the Web Locks API to acquire an exclusive lock named `TAB_LOCK_NAME`.
 * If another tab already holds the lock, the caller is notified so it can show
 * a blocked UI instead of the app (preventing MLS epoch conflicts).
 *
 * Falls back gracefully when the Web Locks API is unavailable (older browsers,
 * Tauri desktop) — the lock is simply granted immediately.
 */

import { CLEAN_STORAGE_SUFFIX } from './cursors';

/** Generation-pinned lock name, so a tab on an older generation never blocks this one. */
export const TAB_LOCK_NAME = `catmos-mls-session${CLEAN_STORAGE_SUFFIX}`;

export type TabLockStatus = 'acquiring' | 'granted' | 'blocked';

type TabLockCallback = (status: TabLockStatus) => void;

/**
 * Attempt to acquire the exclusive tab lock.
 *
 * `onStatusChange` fires with:
 * - `'acquiring'` — initial state while requesting the lock
 * - `'granted'`   — this tab owns the lock (app may proceed)
 * - `'blocked'`   — another tab holds the lock
 *
 * Returns a function that, when called, will steal the lock for this tab
 * (used by the "Use this tab instead" button).
 */
export function acquireTabLock(onStatusChange: TabLockCallback): { steal: () => void } {
  let stealResolver: (() => void) | null = null;

  // No Web Locks API — grant immediately (Tauri, old browser).
  if (typeof navigator === 'undefined' || !navigator.locks) {
    onStatusChange('granted');
    return { steal: () => {} };
  }

  onStatusChange('acquiring');

  // Try to grab the lock without waiting. If unavailable, we know another
  // tab has it and can show the blocked UI right away.
  navigator.locks.request(
    TAB_LOCK_NAME,
    { ifAvailable: true },
    async (lock) => {
      if (lock) {
        // Got the lock — hold it for the lifetime of the tab by returning a
        // promise that never resolves (until the page unloads).
        onStatusChange('granted');
        return new Promise<void>(() => {
          // Hold forever; released automatically on tab close.
        });
      }

      // Lock is held by another tab.
      onStatusChange('blocked');
      return undefined;
    },
  );

  const steal = () => {
    // If there is already a pending steal, bail.
    if (stealResolver) return;

    // Request the lock *with* waiting. When the other tab releases (or the
    // user closes it), this will fire.
    navigator.locks.request(TAB_LOCK_NAME, { steal: true }, async () => {
      onStatusChange('granted');
      stealResolver = null;
      return new Promise<void>((resolve) => {
        stealResolver = resolve;
        // Hold the lock forever (same pattern as above).
      });
    });
  };

  return { steal };
}

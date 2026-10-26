/**
 * Single-tab enforcement for Catmos Web.
 *
 * Uses the Web Locks API to acquire an exclusive lock named "catmos-mls-session".
 * If another tab already holds the lock, the caller is notified so it can show
 * a blocked UI instead of the app (preventing MLS epoch conflicts).
 *
 * Falls back gracefully when the Web Locks API is unavailable (older browsers,
 * Tauri desktop) — the lock is simply granted immediately.
 */

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
export function acquireTabLock(onStatusChange: TabLockCallback): {
  steal: () => void;
  ready: Promise<TabLockStatus>;
} {
  let stealResolver: (() => void) | null = null;
  let resolveReady: ((status: TabLockStatus) => void) | null = null;
  const ready = new Promise<TabLockStatus>((resolve) => {
    resolveReady = resolve;
  });
  const notifyStatus = (status: TabLockStatus) => {
    onStatusChange(status);
    if (status !== 'acquiring' && resolveReady) {
      const r = resolveReady;
      resolveReady = null;
      r(status);
    }
  };

  // No Web Locks API — grant immediately (Tauri, old browser).
  if (typeof navigator === 'undefined' || !navigator.locks) {
    notifyStatus('granted');
    return { steal: () => {}, ready };
  }

  onStatusChange('acquiring');

  // Try to grab the lock without waiting. If unavailable, we know another
  // tab has it and can show the blocked UI right away.
  navigator.locks
    .request(
      'catmos-mls-session',
      { ifAvailable: true },
      async (lock) => {
        if (lock) {
          // Got the lock — hold it for the lifetime of the tab by returning a
          // promise that never resolves (until the page unloads).
          notifyStatus('granted');
          return new Promise<void>(() => {
            // Hold forever; released automatically on tab close.
          });
        }

        // Lock is held by another tab.
        notifyStatus('blocked');
        return undefined;
      },
    )
    .catch(() => {
      notifyStatus('blocked');
    });

  const steal = () => {
    // If there is already a pending steal, bail.
    if (stealResolver) return;

    // Request the lock *with* waiting. When the other tab releases (or the
    // user closes it), this will fire.
    navigator.locks.request('catmos-mls-session', { steal: true }, async () => {
      notifyStatus('granted');
      stealResolver = null;
      return new Promise<void>((resolve) => {
        stealResolver = resolve;
        // Hold the lock forever (same pattern as above).
      });
    });
  };

  return { steal, ready };
}

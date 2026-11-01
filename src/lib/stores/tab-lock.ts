/**
 * Single-tab enforcement store adapter for Catmos Web (`Gate 9`).
 *
 * Delegates to `#lib/tab-lock.ts` (`navigator.locks.request(..., { mode: "exclusive" })`)
 * and NEVER steals an active lock. When another tab holds the lock, this tab
 * surfaces `'blocked'` (`"Chat active in another tab"`) and automatically transitions
 * to `'granted'` once the active tab closes and releases its OPFS `SyncAccessHandle`.
 */

import { acquireTabLock as acquireExclusiveTabLock, type TabLockHandle } from '#lib/tab-lock.ts';

export type TabLockStatus = 'acquiring' | 'granted' | 'blocked';

type TabLockCallback = (status: TabLockStatus) => void;

export function acquireTabLock(
	onStatusChange: TabLockCallback,
	didHash = 'session'
): {
	release: () => void;
	ready: Promise<TabLockStatus>;
} {
	let activeHandle: TabLockHandle | null = null;
	let initialSettled = false;
	let resolveReady: ((status: TabLockStatus) => void) | null = null;

	const ready = new Promise<TabLockStatus>((resolve) => {
		resolveReady = resolve;
	});

	const emit = (status: TabLockStatus) => {
		onStatusChange(status);
		if (status !== 'acquiring' && !initialSettled && resolveReady) {
			initialSettled = true;
			const r = resolveReady;
			resolveReady = null;
			r(status);
		}
	};

	emit('acquiring');

	acquireExclusiveTabLock(didHash, {
		onWaiting: () => {
			emit('blocked');
		}
	})
		.then((handle) => {
			activeHandle = handle;
			emit('granted');
		})
		.catch(() => {
			emit('blocked');
		});

	return {
		release: () => {
			activeHandle?.release();
			activeHandle = null;
		},
		ready
	};
}

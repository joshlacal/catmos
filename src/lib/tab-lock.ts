/**
 * Exclusive per-account Web Worker / OPFS tab mutex (`Spec §6.5`, `Gate 9`).
 *
 * Uses `navigator.locks.request("catbird-mls:" + didHash, { mode: "exclusive" }, ...)`
 * and NEVER steals an active Web Lock. Stealing a Web Lock while another tab's Dedicated
 * Worker still holds an open OPFS `SyncAccessHandle` causes an unrecoverable VFS
 * crash instead of a clean wait.
 */

export const TAB_WAITING_MESSAGE = 'Chat active in another tab';

export interface TabLockHandle {
	readonly status: 'acquired';
	readonly lockName: string;
	release(): void;
}

export interface AcquireTabLockOptions {
	onWaiting?: (message: string) => void;
}

function holdExclusiveLock(
	lockName: string,
	onAcquired: (handle: TabLockHandle) => void,
	onError: (err: unknown) => void
): void {
	navigator.locks
		.request(lockName, { mode: 'exclusive' }, async () => {
			let releaseFn: (() => void) | null = null;
			const holdPromise = new Promise<void>((resolve) => {
				releaseFn = resolve;
			});
			let released = false;
			onAcquired({
				status: 'acquired',
				lockName,
				release() {
					if (released) return;
					released = true;
					releaseFn?.();
				}
			});
			await holdPromise;
		})
		.catch(onError);
}

/**
 * Acquire the exclusive `"catbird-mls:<didHash>"` Web Lock for this tab.
 *
 * If another tab currently holds the lock, `options.onWaiting` fires immediately
 * with `"Chat active in another tab"`, and the returned Promise remains pending
 * until the active tab closes and releases its lock cleanly (never stealing).
 */
export function acquireTabLock(
	didHash: string,
	options: AcquireTabLockOptions = {}
): Promise<TabLockHandle> {
	const normalized = didHash.trim();
	if (!normalized) {
		return Promise.reject(new Error('acquireTabLock requires a non-empty didHash'));
	}
	const lockName = `catbird-mls:${normalized}`;

	if (
		typeof navigator === 'undefined' ||
		!navigator.locks ||
		typeof navigator.locks.request !== 'function'
	) {
		return Promise.resolve({
			status: 'acquired',
			lockName,
			release() {}
		});
	}

	return new Promise<TabLockHandle>((resolve, reject) => {
		navigator.locks
			.request(lockName, { mode: 'exclusive', ifAvailable: true }, async (lock) => {
				if (lock) {
					let releaseFn: (() => void) | null = null;
					const holdPromise = new Promise<void>((res) => {
						releaseFn = res;
					});
					let released = false;
					resolve({
						status: 'acquired',
						lockName,
						release() {
							if (released) return;
							released = true;
							releaseFn?.();
						}
					});
					await holdPromise;
					return true;
				}
				return false;
			})
			.then((acquiredImmediately) => {
				if (acquiredImmediately) return;
				options.onWaiting?.(TAB_WAITING_MESSAGE);
				holdExclusiveLock(lockName, resolve, reject);
			})
			.catch(reject);
	});
}

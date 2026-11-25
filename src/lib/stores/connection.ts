import { get, writable } from 'svelte/store';
import { recoveryNotice, type RecoveryCategory } from '#lib/recovery.ts';

export type ConnectionState =
	| 'connected'
	| 'connecting'
	| 'reconnecting'
	| 'offline'
	| 'error';

export interface ConnectionStore {
	state: ConnectionState;
	retryCount: number;
	lastError: string | null;
	category: RecoveryCategory | null;
}

const MAX_RETRIES = 10;
const BASE_DELAY_MS = 1000;
const MAX_DELAY_MS = 30000;
const JITTER_FACTOR = 0.2;

function backoffDelay(retryCount: number): number {
	const base = Math.min(BASE_DELAY_MS * Math.pow(2, retryCount), MAX_DELAY_MS);
	const jitter = base * JITTER_FACTOR * (Math.random() * 2 - 1);
	return Math.round(base + jitter);
}

function createConnectionStore() {
	const store = writable<ConnectionStore>({
		state: 'connecting',
		retryCount: 0,
		lastError: null,
		category: null
	});
	const { subscribe, set, update } = store;

	let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
	let onReconnectCallback: (() => Promise<void>) | null = null;
	let isOnline = typeof navigator !== 'undefined' ? navigator.onLine : true;

	function clearTimer() {
		if (reconnectTimer !== null) {
			clearTimeout(reconnectTimer);
			reconnectTimer = null;
		}
	}

	function handleOnline() {
		isOnline = true;
		update((s) => {
			if (s.state === 'offline') {
				scheduleReconnect(s.retryCount);
				return { ...s, state: 'reconnecting' };
			}
			return s;
		});
	}

	function handleOffline() {
		isOnline = false;
		clearTimer();
		update((s) => ({ ...s, state: 'offline' }));
	}

	function scheduleReconnect(retryCount: number) {
		clearTimer();
		if (retryCount >= MAX_RETRIES) {
			update((s) => ({
				...s,
				state: 'error',
				lastError: 'Maximum reconnection attempts reached.',
				category: 'retry'
			}));
			return;
		}
		const delay = backoffDelay(retryCount);
		reconnectTimer = setTimeout(async () => {
			reconnectTimer = null;
			if (!isOnline) {
				update((s) => ({ ...s, state: 'offline' }));
				return;
			}
			update((s) => ({ ...s, state: 'reconnecting', retryCount: retryCount + 1 }));
			try {
				if (onReconnectCallback) {
					await onReconnectCallback();
				}
				const after = get(store);
				if (after.state === 'reconnecting' || after.state === 'connecting') {
					set({ state: 'connected', retryCount: 0, lastError: null, category: null });
				}
			} catch (e) {
				const notice = recoveryNotice(e);
				if (notice.category !== 'retry') {
					set({
						state: 'error',
						retryCount: retryCount + 1,
						lastError: notice.message,
						category: notice.category
					});
					return;
				}
				const nextRetry = retryCount + 1;
				update((s) => ({
					...s,
					state: 'reconnecting',
					retryCount: nextRetry,
					lastError: notice.message,
					category: notice.category
				}));
				scheduleReconnect(nextRetry);
			}
		}, delay);
	}

	if (typeof window !== 'undefined') {
		window.addEventListener('online', handleOnline);
		window.addEventListener('offline', handleOffline);
		if (!navigator.onLine) {
			isOnline = false;
			set({ state: 'offline', retryCount: 0, lastError: null, category: null });
		}
	}

	return {
		subscribe,
		onReconnect(cb: () => Promise<void>) {
			onReconnectCallback = cb;
		},
		setConnected() {
			clearTimer();
			set({ state: 'connected', retryCount: 0, lastError: null, category: null });
		},
		setReconnecting(retryCount = 1, lastError: string | null = 'Reconnecting to message stream...') {
			clearTimer();
			set({ state: 'reconnecting', retryCount, lastError, category: 'retry' });
		},
		setError(category: RecoveryCategory, lastError: string) {
			clearTimer();
			set({ state: 'error', retryCount: 0, lastError, category });
		},
		setDisconnected(reason?: string) {
			const notice = recoveryNotice(reason ?? 'Connection lost');
			if (notice.category !== 'retry') {
				clearTimer();
				set({ state: 'error', retryCount: 0, lastError: notice.message, category: notice.category });
				return;
			}
			if (!isOnline) {
				set({ state: 'offline', retryCount: 0, lastError: notice.message, category: notice.category });
				return;
			}
			const existing = get(store);
			update((s) => ({
				...s,
				state: 'reconnecting',
				lastError: notice.message,
				category: notice.category
			}));
			// Preserve an already-scheduled backoff timer instead of resetting it.
			if (reconnectTimer === null) {
				scheduleReconnect(existing.retryCount);
			}
		},
		retryNow() {
			clearTimer();
			update((s) => ({ ...s, state: 'reconnecting', retryCount: 0, category: 'retry' }));
			scheduleReconnect(0);
		},
		reset() {
			clearTimer();
			set({ state: 'connecting', retryCount: 0, lastError: null, category: null });
		}
	};
}

export const connection = createConnectionStore();

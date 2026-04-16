import { writable } from 'svelte/store';

export type ConnectionState =
  | 'connected'
  | 'connecting'
  | 'reconnecting'
  | 'offline'
  | 'error';

interface ConnectionStore {
  state: ConnectionState;
  retryCount: number;
  lastError: string | null;
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
  const { subscribe, set, update } = writable<ConnectionStore>({
    state: 'connecting',
    retryCount: 0,
    lastError: null
  });

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
    // Immediately attempt reconnect when network returns
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
        lastError: 'Max reconnection attempts reached'
      }));
      return;
    }
    const delay = backoffDelay(retryCount);
    reconnectTimer = setTimeout(async () => {
      if (!isOnline) {
        update((s) => ({ ...s, state: 'offline' }));
        return;
      }
      update((s) => ({ ...s, state: 'reconnecting', retryCount: retryCount + 1 }));
      try {
        if (onReconnectCallback) {
          await onReconnectCallback();
        }
        set({ state: 'connected', retryCount: 0, lastError: null });
      } catch (e) {
        const nextRetry = retryCount + 1;
        update((s) => ({
          ...s,
          state: 'reconnecting',
          retryCount: nextRetry,
          lastError: String(e)
        }));
        scheduleReconnect(nextRetry);
      }
    }, delay);
  }

  // Set up browser online/offline listeners
  if (typeof window !== 'undefined') {
    window.addEventListener('online', handleOnline);
    window.addEventListener('offline', handleOffline);
    if (!navigator.onLine) {
      isOnline = false;
      set({ state: 'offline', retryCount: 0, lastError: null });
    }
  }

  return {
    subscribe,

    /** Register a callback invoked on each reconnect attempt. */
    onReconnect(cb: () => Promise<void>) {
      onReconnectCallback = cb;
    },

    /** Mark the connection as successfully established. Resets backoff. */
    setConnected() {
      clearTimer();
      set({ state: 'connected', retryCount: 0, lastError: null });
    },

    /** Signal that the connection was lost. Starts reconnect cycle. */
    setDisconnected(reason?: string) {
      if (!isOnline) {
        set({ state: 'offline', retryCount: 0, lastError: reason ?? null });
        return;
      }
      update((s) => ({
        ...s,
        state: 'reconnecting',
        lastError: reason ?? null
      }));
      // Read current retryCount after update
      let current: ConnectionStore | undefined;
      const unsub = subscribe((s) => { current = s; });
      unsub();
      scheduleReconnect(current?.retryCount ?? 0);
    },

    /** Reset to initial connecting state. */
    reset() {
      clearTimer();
      set({ state: 'connecting', retryCount: 0, lastError: null });
    }
  };
}

export const connection = createConnectionStore();

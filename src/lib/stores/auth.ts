import { writable } from 'svelte/store';
import * as api from '$lib/wasm';
import { listenForEvent, isTauri } from '$lib/wasm';
import type { AuthState } from '$lib/tauri';
import { requests } from './requests';
import { profiles } from './profiles';

interface AuthStore {
	user: AuthState | null;
	loading: boolean;
	error: string | null;
	waitingForOAuth: boolean;
}

const initialState: AuthStore = { user: null, loading: false, error: null, waitingForOAuth: false };

/** Fetch the user's own Bluesky profile and populate displayName/avatar */
async function fetchOwnProfile(user: AuthState, isCurrent: () => boolean) {
	try {
		const results = await api.getProfiles([user.did]);
		if (isCurrent() && results.length > 0) {
			const p = results[0];
			if (p.handle && p.handle !== p.did) user.handle = p.handle;
			user.displayName = p.displayName;
			user.avatar = p.avatar;
			profiles.setProfile(p);
		}
	} catch {
		// Non-fatal: profile fetch can fail silently
	}
}

export function createAuthStore() {
	const { subscribe, set, update } = writable<AuthStore>(initialState);

	let unlistenOAuth: (() => void) | null = null;
	let attempt = 0;
	function beginAttempt() {
		attempt++;
		unlistenOAuth?.();
		unlistenOAuth = null;
		return attempt;
	}

	return {
		subscribe,
		async startLogin(identifier: string) {
			const captured = beginAttempt();
			update((s) => ({ ...s, loading: true, error: null, waitingForOAuth: true }));
			try {
				if (isTauri) {
					// Tauri: listen for oauth-callback IPC event, then completeLogin
					const unlisten = await listenForEvent<string>('oauth-callback', async (sessionId) => {
						if (captured !== attempt) return;
						try {
							const user = await api.completeLogin(sessionId);
							if (captured !== attempt) return;
							await fetchOwnProfile(user, () => captured === attempt);
							if (captured !== attempt) return;
							set({ user, loading: false, error: null, waitingForOAuth: false });
						} catch (e) {
							if (captured !== attempt) return;
							set({ user: null, loading: false, error: String(e), waitingForOAuth: false });
						}
						if (captured === attempt) {
							unlistenOAuth?.();
							unlistenOAuth = null;
						}
					});
					if (captured !== attempt) {
						unlisten();
						return;
					}
					unlistenOAuth = unlisten;
				}
				// Browser: startLogin redirects to nest OAuth — page navigates away.
				await api.startLogin(identifier);
			} catch (e) {
				if (captured !== attempt) return;
				set({ user: null, loading: false, error: String(e), waitingForOAuth: false });
			}
		},
		cancelLogin() {
			beginAttempt();
			set(initialState);
		},
		async logout() {
			const captured = beginAttempt();
			requests.bindAccount(null);
			set(initialState);
			try {
				await api.logout();
			} finally {
				if (captured === attempt) set(initialState);
			}
		},
		async tryRestore() {
			const captured = beginAttempt();
			update((s) => ({ ...s, loading: true, error: null }));
			try {
				const user = await api.tryRestoreSession();
				if (captured !== attempt) return;
				if (user) {
					await fetchOwnProfile(user, () => captured === attempt);
				if (captured !== attempt) return;
					set({ user, loading: false, error: null, waitingForOAuth: false });
				} else {
					set({ ...initialState, loading: false });
				}
			} catch (e) {
				if (captured !== attempt) return;
				// A transient restore failure must be visible and retryable. The
				// desktop backend intentionally keeps the keychained session so a
				// retry can resume the existing encrypted transcript.
				set({ user: null, loading: false, error: String(e), waitingForOAuth: false });
			}
		},
		/** Called from /auth/callback route after browser OAuth completes. */
		async completeOAuthCallback(sessionId: string) {
			const captured = beginAttempt();
			update((s) => ({ ...s, loading: true, error: null }));
			try {
				const user = await api.completeLogin(sessionId);
				if (captured !== attempt) return;
				await fetchOwnProfile(user, () => captured === attempt);
				if (captured !== attempt) return;
				set({ user, loading: false, error: null, waitingForOAuth: false });
			} catch (e) {
				if (captured !== attempt) return;
				set({ user: null, loading: false, error: String(e), waitingForOAuth: false });
			}
		},
		setUser(user: AuthState) {
			beginAttempt();
			set({ user, loading: false, error: null, waitingForOAuth: false });
		}
	};
}

export const auth = createAuthStore();

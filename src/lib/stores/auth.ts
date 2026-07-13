import { writable } from 'svelte/store';
import * as api from '$lib/wasm';
import { listenForEvent, isTauri } from '$lib/wasm';
import type { AuthState } from '$lib/tauri';
import { profiles } from './profiles';

interface AuthStore {
	user: AuthState | null;
	loading: boolean;
	error: string | null;
	waitingForOAuth: boolean;
}

const initialState: AuthStore = { user: null, loading: false, error: null, waitingForOAuth: false };

/** Fetch the user's own Bluesky profile and populate displayName/avatar */
async function fetchOwnProfile(user: AuthState) {
	try {
		const results = await api.getProfiles([user.did]);
		if (results.length > 0) {
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

function createAuthStore() {
	const { subscribe, set, update } = writable<AuthStore>(initialState);

	let unlistenOAuth: (() => void) | null = null;
	let unlistenOAuthError: (() => void) | null = null;
	let activeNativeOriginPromise: Promise<string | null> | null = null;

	function clearOAuthListeners() {
		if (unlistenOAuth) unlistenOAuth();
		if (unlistenOAuthError) unlistenOAuthError();
		unlistenOAuth = null;
		unlistenOAuthError = null;
		activeNativeOriginPromise = null;
	}

	return {
		subscribe,
		async startLogin(identifier: string) {
			update((s) => ({ ...s, loading: true, error: null, waitingForOAuth: true }));
			try {
				if (isTauri) {
					clearOAuthListeners();
					await api.cancelLogin();
					// Tauri: listen for oauth-callback IPC event, then completeLogin
					unlistenOAuth = await listenForEvent<{ code: string; redirectOrigin: string }>('oauth-callback', async (callback) => {
						const expectedOrigin = await activeNativeOriginPromise;
						if (callback.redirectOrigin !== expectedOrigin) return;
						try {
							const user = await api.completeLogin(callback.code, callback.redirectOrigin);
							await fetchOwnProfile(user);
							set({ user, loading: false, error: null, waitingForOAuth: false });
						} catch (e) {
							set({ user: null, loading: false, error: String(e), waitingForOAuth: false });
						}
						clearOAuthListeners();
					});
					unlistenOAuthError = await listenForEvent<{ message: string; redirectOrigin: string }>('oauth-error', async (event) => {
						const expectedOrigin = await activeNativeOriginPromise;
						if (event.redirectOrigin !== expectedOrigin) return;
						set({ user: null, loading: false, error: event.message, waitingForOAuth: false });
						clearOAuthListeners();
					});
					activeNativeOriginPromise = api.startLogin(identifier);
					await activeNativeOriginPromise;
				} else {
					// Browser: startLogin redirects to nest OAuth — page navigates away.
					await api.startLogin(identifier);
				}
			} catch (e) {
				set({ user: null, loading: false, error: String(e), waitingForOAuth: false });
			}
		},
		cancelLogin() {
			clearOAuthListeners();
			void api.cancelLogin();
			set(initialState);
		},
		async logout() {
			try {
				await api.logout();
			} finally {
				set(initialState);
			}
		},
		async tryRestore() {
			try {
				const user = await api.tryRestoreSession();
				if (user) {
					await fetchOwnProfile(user);
					set({ user, loading: false, error: null, waitingForOAuth: false });
				}
			} catch {
				// No saved session, that's fine
			}
		},
		/** Called from /auth/callback route after browser OAuth completes. */
		async completeOAuthCallback(code: string) {
			update((s) => ({ ...s, loading: true, error: null }));
			try {
				const user = await api.completeLogin(code);
				await fetchOwnProfile(user);
				set({ user, loading: false, error: null, waitingForOAuth: false });
			} catch (e) {
				set({ user: null, loading: false, error: String(e), waitingForOAuth: false });
				throw e;
			}
		},
		setUser(user: AuthState) {
			set({ user, loading: false, error: null, waitingForOAuth: false });
		}
	};
}

export const auth = createAuthStore();

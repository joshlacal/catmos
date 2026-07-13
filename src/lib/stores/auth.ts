import { writable } from 'svelte/store';
import * as api from '$lib/wasm';
import { listenForEvent, isTauri } from '$lib/wasm';
import type { AuthState } from '$lib/tauri';
import { profiles } from './profiles';
import { OAuthFlowGeneration } from '$lib/oauth-exchange';

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

	const oauthFlows = new OAuthFlowGeneration();
	let activeCleanup: (() => void) | null = null;

	function invalidateOAuthFlow() {
		oauthFlows.cancel();
		activeCleanup?.();
		activeCleanup = null;
	}

	return {
		subscribe,
		async startLogin(identifier: string) {
			const generation = oauthFlows.begin();
			activeCleanup?.();
			activeCleanup = null;
			update((s) => ({ ...s, loading: true, error: null, waitingForOAuth: true }));
			try {
				if (isTauri) {
					await api.cancelLogin();
					if (!oauthFlows.isActive(generation)) return;
					let unlistenCallback: (() => void) | null = null;
					let unlistenError: (() => void) | null = null;
					let originPromise: Promise<string | null> | null = null;
					const cleanup = () => {
						unlistenCallback?.();
						unlistenError?.();
						unlistenCallback = null;
						unlistenError = null;
					};
					activeCleanup = cleanup;
					// Tauri: listen for oauth-callback IPC event, then completeLogin
					unlistenCallback = await listenForEvent<{ code: string; redirectOrigin: string }>('oauth-callback', async (callback) => {
						const expectedOrigin = await originPromise;
						if (!oauthFlows.isActive(generation) || callback.redirectOrigin !== expectedOrigin || !oauthFlows.claim(generation)) return;
						cleanup();
						try {
							const user = await api.completeLogin(callback.code, callback.redirectOrigin);
							if (!oauthFlows.isActive(generation)) return;
							await fetchOwnProfile(user);
							if (!oauthFlows.isActive(generation)) return;
							set({ user, loading: false, error: null, waitingForOAuth: false });
						} catch (e) {
							if (!oauthFlows.isActive(generation)) return;
							set({ user: null, loading: false, error: String(e), waitingForOAuth: false });
						}
					});
					if (!oauthFlows.isActive(generation)) {
						cleanup();
						return;
					}
					unlistenError = await listenForEvent<{ message: string; redirectOrigin: string }>('oauth-error', async (event) => {
						const expectedOrigin = await originPromise;
						if (!oauthFlows.isActive(generation) || event.redirectOrigin !== expectedOrigin || !oauthFlows.claim(generation)) return;
						cleanup();
						set({ user: null, loading: false, error: event.message, waitingForOAuth: false });
					});
					if (!oauthFlows.isActive(generation)) {
						cleanup();
						return;
					}
					originPromise = api.startLogin(identifier);
					await originPromise;
					if (!oauthFlows.isActive(generation)) cleanup();
				} else {
					// Browser: startLogin redirects to nest OAuth — page navigates away.
					await api.startLogin(identifier);
					if (!oauthFlows.isActive(generation)) return;
				}
			} catch (e) {
				if (!oauthFlows.isActive(generation)) return;
				oauthFlows.claim(generation);
				activeCleanup?.();
				activeCleanup = null;
				set({ user: null, loading: false, error: String(e), waitingForOAuth: false });
			}
		},
		cancelLogin() {
			invalidateOAuthFlow();
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

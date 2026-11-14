import { get, writable } from 'svelte/store';
import * as api from '#lib/wasm.ts';
import { listenForEvent, isTauri } from '#lib/wasm.ts';
import { REQUIRED_LABYRINTH_OAUTH_SCOPES } from '#lib/labyrinth-ui.ts';
import {
	normalizeSessionId,
	parseTauriOAuthCallbackPayload
} from '#lib/oauth-callback.ts';
import type { AuthState } from '#lib/tauri.ts';
import { profiles } from './profiles.ts';

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

	function cleanupOAuthListeners() {
		if (unlistenOAuth) {
			unlistenOAuth();
			unlistenOAuth = null;
		}
		if (unlistenOAuthError) {
			unlistenOAuthError();
			unlistenOAuthError = null;
		}
	}

	return {
		subscribe,
		async startLogin(identifier: string) {
			cleanupOAuthListeners();
			update((s) => ({ ...s, loading: true, error: null, waitingForOAuth: true }));
			try {
				if (isTauri) {
					// Tauri: validate oauth-callback IPC payload before completing login
					unlistenOAuth = await listenForEvent<string>('oauth-callback', async (rawPayload) => {
						try {
							const parsed = parseTauriOAuthCallbackPayload(rawPayload);
							if (parsed.kind === 'error') {
								throw new Error(
									parsed.errorDescription
										? `${parsed.error}: ${parsed.errorDescription}`
										: parsed.error
								);
							}
							const sessionId =
								parsed.kind === 'code'
									? await api.exchangeOAuthCode(parsed.code)
									: parsed.sessionId;
							const user = await api.completeLogin(sessionId);
							await fetchOwnProfile(user);
							set({ user, loading: false, error: null, waitingForOAuth: false });
						} catch (e) {
							set({
								user: null,
								loading: false,
								error: e instanceof Error ? e.message : String(e),
								waitingForOAuth: false
							});
						} finally {
							cleanupOAuthListeners();
						}
					});
					unlistenOAuthError = await listenForEvent<string>('oauth-error', (rawErr) => {
						const safeMessage =
							typeof rawErr === 'string'
								? rawErr.replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, 256)
								: 'OAuth authentication failed';
						set({
							user: null,
							loading: false,
							error: safeMessage || 'OAuth authentication failed',
							waitingForOAuth: false
						});
						cleanupOAuthListeners();
					});
				}
				// Browser: startLogin redirects to nest OAuth — page navigates away.
				await api.startLogin(identifier);
			} catch (e) {
				cleanupOAuthListeners();
				set({ user: null, loading: false, error: String(e), waitingForOAuth: false });
			}
		},
		cancelLogin() {
			cleanupOAuthListeners();
			set(initialState);
		},
		async logout() {
			cleanupOAuthListeners();
			try {
				await api.logout();
			} finally {
				set(initialState);
			}
		},
		async deleteAccountData(did?: string) {
			cleanupOAuthListeners();
			await api.deleteAccountData(did);
			set(initialState);
		},
		async tryRestore() {
			update((s) => ({ ...s, loading: true, error: null }));
			try {
				const user = await api.tryRestoreSession();
				if (user) {
					await fetchOwnProfile(user);
					set({ user, loading: false, error: null, waitingForOAuth: false });
				} else {
					set({ ...initialState, loading: false });
				}
			} catch (e) {
				// A transient restore failure must be visible and retryable. The
				// desktop backend intentionally keeps the keychained session so a
				// retry can resume the existing encrypted transcript.
				set({ user: null, loading: false, error: String(e), waitingForOAuth: false });
			}
		},
		/** Initiate progressive `/auth/upgrade` for missing Spaces/Labyrinth scopes. */
		async upgradeScopes(
			scopes: readonly string[] = REQUIRED_LABYRINTH_OAUTH_SCOPES,
			returnTo = '/settings/labyrinth'
		) {
			const current = get({ subscribe });
			if (!current.user?.did) {
				throw new Error('Cannot upgrade OAuth scopes without an authenticated session.');
			}
			if (isTauri) {
				await this.startLogin(current.user.handle || current.user.did);
				return;
			}
			update((s) => ({ ...s, loading: true, error: null, waitingForOAuth: true }));
			try {
				await api.startOAuthScopeUpgrade(scopes, { returnTo });
			} catch (e) {
				const message = e instanceof Error ? e.message : String(e);
				update((s) => ({ ...s, loading: false, error: message, waitingForOAuth: false }));
				throw e;
			}
		},
		/** Called from `/oauth/permission-callback` after progressive scope upgrade completes. */
		async completeOAuthUpgradeCallback(code: string) {
			update((s) => ({ ...s, loading: true, error: null }));
			try {
				const user = await api.completeOAuthScopeUpgrade(code);
				await fetchOwnProfile(user);
				set({ user, loading: false, error: null, waitingForOAuth: false });
				return user;
			} catch (e) {
				const message = e instanceof Error ? e.message : String(e);
				update((s) => ({ ...s, loading: false, error: message, waitingForOAuth: false }));
				throw e;
			}
		},
		/** Called from /auth/callback route after browser OAuth completes. */
		async completeOAuthCallback(sessionId: string) {
			update((s) => ({ ...s, loading: true, error: null }));
			try {
				const validatedSessionId = normalizeSessionId(sessionId);
				const user = await api.completeLogin(validatedSessionId);
				await fetchOwnProfile(user);
				set({ user, loading: false, error: null, waitingForOAuth: false });
			} catch (e) {
				const message = e instanceof Error ? e.message : String(e);
				set({ user: null, loading: false, error: message, waitingForOAuth: false });
				throw e;
			}
		},
		setUser(user: AuthState) {
			set({ user, loading: false, error: null, waitingForOAuth: false });
		}
	};
}

export const auth = createAuthStore();

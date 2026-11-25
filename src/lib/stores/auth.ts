import { get, writable } from 'svelte/store';
import * as api from '#lib/wasm.ts';
import { listenForEvent, isTauri } from '#lib/wasm.ts';
import { REQUIRED_LABYRINTH_OAUTH_SCOPES } from '#lib/labyrinth-ui.ts';
import { stripDidFragment } from '#lib/did.ts';
import type { AuthState } from '#lib/tauri.ts';
import { profiles } from './profiles.ts';
import { conversations } from './conversations.ts';
import { messages } from './messages.ts';
import { quarantine } from './quarantine.ts';
import { connection } from './connection.ts';
import { drafts } from './drafts.ts';
import { setActiveDid as setPreferencesActiveDid } from './preferences.ts';

export interface AuthStore {
	user: AuthState | null;
	loading: boolean;
	error: string | null;
	waitingForOAuth: boolean;
}

export type LoginIdentifierValidation =
	| { ok: true; identifier: string }
	| { ok: false; error: string };

const HANDLE_RE =
	/^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;
const DID_PLC_RE = /^did:plc:[a-z2-7]{24}$/i;
const DID_WEB_RE =
	/^did:web:[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?(?::[a-zA-Z0-9._%-]+)*$/;

export function validateLoginIdentifier(raw: string): LoginIdentifierValidation {
	const trimmed = raw.trim();
	if (!trimmed) {
		return { ok: false, error: 'Enter your Bluesky handle or DID.' };
	}

	const withoutLeadingAt = trimmed.startsWith('@') ? trimmed.slice(1).trim() : trimmed;
	if (!withoutLeadingAt) {
		return { ok: false, error: 'Enter your Bluesky handle or DID.' };
	}

	if (/\s/.test(withoutLeadingAt)) {
		return { ok: false, error: 'Handles and DIDs cannot contain spaces.' };
	}

	if (withoutLeadingAt.includes('@')) {
		return {
			ok: false,
			error: 'Use your Bluesky handle (such as alice.bsky.social) or DID, not an email address.'
		};
	}

	if (withoutLeadingAt.toLowerCase().startsWith('did:')) {
		const lowerPrefix = withoutLeadingAt.toLowerCase();
		if (lowerPrefix.startsWith('did:plc:')) {
			if (!DID_PLC_RE.test(withoutLeadingAt)) {
				return { ok: false, error: 'Enter a valid did:plc identifier.' };
			}
			return { ok: true, identifier: `did:plc:${withoutLeadingAt.slice(8).toLowerCase()}` };
		}
		if (lowerPrefix.startsWith('did:web:')) {
			if (!DID_WEB_RE.test(withoutLeadingAt)) {
				return { ok: false, error: 'Enter a valid did:web identifier.' };
			}
			return { ok: true, identifier: `did:web:${withoutLeadingAt.slice(8)}` };
		}
		return { ok: false, error: 'Only did:plc and did:web identifiers are supported.' };
	}

	if (!HANDLE_RE.test(withoutLeadingAt)) {
		return {
			ok: false,
			error: 'Enter a full Bluesky handle (for example, alice.bsky.social) or a DID.'
		};
	}

	return { ok: true, identifier: withoutLeadingAt.toLowerCase() };
}

const initialState: AuthStore = {
	user: null,
	loading: false,
	error: null,
	waitingForOAuth: false
};

function syncUserScope(user: AuthState | null) {
	const accountDid = stripDidFragment(user?.did) || null;
	drafts.setActiveDid(accountDid);
	setPreferencesActiveDid(accountDid);
}

function resetClientStores() {
	conversations.reset();
	messages.setAccount(undefined);
	profiles.reset();
	quarantine.reset();
	connection.reset();
	drafts.reset();
	setPreferencesActiveDid(null);
	void api.unsubscribeAllEvents().catch(() => {});
}

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
		clearError() {
			update((s) => ({ ...s, error: null }));
		},
		async startLogin(identifier: string) {
			const validated = validateLoginIdentifier(identifier);
			if (!validated.ok) {
				update((s) => ({
					...s,
					loading: false,
					waitingForOAuth: false,
					error: validated.error
				}));
				return;
			}

			cleanupOAuthListeners();
			update((s) => ({ ...s, loading: true, error: null, waitingForOAuth: true }));
			try {
				if (isTauri) {
					// Tauri: the desktop backend finishes the OAuth flow itself and
					// reports the signed-in account. Validate the IPC payload first.
					unlistenOAuth = await listenForEvent<unknown>('oauth-signed-in', async (rawPayload) => {
						try {
							const user = api.parseDesktopSignIn(rawPayload);
							await fetchOwnProfile(user);
							syncUserScope(user);
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
				// Desktop: opens the account's sign-in page in the system browser.
				// Browser: startLogin redirects to nest OAuth and navigates away.
				await api.startLogin(validated.identifier);
			} catch (e) {
				cleanupOAuthListeners();
				set({
					user: null,
					loading: false,
					error: e instanceof Error ? e.message : String(e),
					waitingForOAuth: false
				});
			}
		},
		async cancelLogin() {
			cleanupOAuthListeners();
			set(initialState);
			await api.cancelLogin().catch(() => undefined);
		},
		async logout() {
			cleanupOAuthListeners();
			try {
				await api.logout();
			} finally {
				resetClientStores();
				set(initialState);
			}
		},
		async deleteAccountData(did?: string) {
			cleanupOAuthListeners();
			// D-3 fail-closed: only clear local auth/UI stores after remote + local deletion succeeds.
			await api.deleteAccountData(did);
			resetClientStores();
			set(initialState);
		},
		async tryRestore() {
			update((s) => ({ ...s, loading: true, error: null }));
			try {
				const user = await api.tryRestoreSession();
				if (user) {
					await fetchOwnProfile(user);
					syncUserScope(user);
					set({ user, loading: false, error: null, waitingForOAuth: false });
				} else {
					syncUserScope(null);
					set({ ...initialState, loading: false });
				}
			} catch (e) {
				// A transient restore failure must be visible and retryable. The
				// desktop backend intentionally keeps the keychained session so a
				// retry can resume the existing encrypted transcript.
				set({
					user: null,
					loading: false,
					error: e instanceof Error ? e.message : String(e),
					waitingForOAuth: false
				});
			}
		},
		/** Re-authorize with Petrel direct OAuth to grant any missing Spaces/Labyrinth scopes. */
		async upgradeScopes(
			_scopes: readonly string[] = REQUIRED_LABYRINTH_OAUTH_SCOPES,
			returnTo = '/settings/labyrinth'
		) {
			const current = get({ subscribe });
			if (!current.user?.did) {
				throw new Error('Cannot upgrade OAuth scopes without an authenticated session.');
			}
			if (
				!isTauri &&
				typeof sessionStorage !== 'undefined' &&
				returnTo.startsWith('/') &&
				!returnTo.startsWith('//')
			) {
				try {
					sessionStorage.setItem('catmos_oauth_return_to', returnTo);
				} catch {
					// Ignore storage errors
				}
			}
			await this.startLogin(current.user.handle || current.user.did);
		},
		/** Complete direct Petrel CAB OAuth redirect callback on `/auth/callback`. */
		async completeOAuthCallbackUrl(callbackUrl: string) {
			update((s) => ({ ...s, loading: true, error: null }));
			try {
				const user = await api.completeOAuthRedirect(callbackUrl);
				await fetchOwnProfile(user);
				syncUserScope(user);
				set({ user, loading: false, error: null, waitingForOAuth: false });
				return user;
			} catch (e) {
				const message = e instanceof Error ? e.message : String(e);
				set({ user: null, loading: false, error: message, waitingForOAuth: false });
				throw e;
			}
		},
		setUser(user: AuthState) {
			syncUserScope(user);
			set({ user, loading: false, error: null, waitingForOAuth: false });
		},
		setError(error: string | null) {
			update((s) => ({ ...s, error, loading: false, waitingForOAuth: false }));
		},
		setWaitingForOAuth(waiting: boolean) {
			update((s) => ({ ...s, waitingForOAuth: waiting, loading: waiting }));
		}
	};
}

export const auth = createAuthStore();

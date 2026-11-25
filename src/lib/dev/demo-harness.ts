/**
 * Zero-prod-leak DEV demo harness for Catmos.
 *
 * Dynamically imported by `+layout.svelte` strictly inside `if (import.meta.env.DEV)`
 * so Rollup removes 100% of demo harness and fixture code from production bundles.
 * Never touches `wasm.ts` directly; uses the already-exported
 * `__setWorkerFactoryForTests`, `persistBrowserAuth`, and `setMlsOptedInForDid`.
 *
 * Supported URL query parameters (in DEV):
 * - `?theme=light|dim|black|system`
 * - `?accent=catbird|twilight|lavender|sunrise|aurora|dusk|midnight`
 * - `?contrast=more|system`
 * - `?density=comfortable|compact`
 * - `?demo=<scenario>`:
 *   `inbox`, `dm`, `empty`, `opt-in`, `auth`, `auth-error`, `oauth-waiting`,
 *   `quarantine`, `members`, `inspector`, `dm-inspector`, `search`,
 *   `new-group`, `settings`, `tab-blocked`, `init-error`,
 *   `reconnecting`, `offline`, `reauth`
 */

import {
	__setWorkerFactoryForTests,
	clearBrowserAuth,
	initWasm,
	persistBrowserAuth
} from '#lib/wasm.ts';
import { REQUIRED_LABYRINTH_OAUTH_SCOPES, setMlsOptedInForDid } from '#lib/labyrinth-ui.ts';
import { auth } from '#lib/stores/auth.ts';
import { conversations } from '#lib/stores/conversations.ts';
import { messages } from '#lib/stores/messages.ts';
import { profiles } from '#lib/stores/profiles.ts';
import { quarantine } from '#lib/stores/quarantine.ts';
import { connection } from '#lib/stores/connection.ts';
import { drafts } from '#lib/stores/drafts.ts';
import {
	setScheme,
	setAccent,
	setContrast,
	setDensity,
	isPinned,
	isMuted,
	togglePin,
	toggleMute,
	type ThemeScheme,
	type AccentPalette,
	type ContrastMode,
	type DensityMode
} from '#lib/stores/preferences.ts';
import {
	openCommandPalette,
	openNewConversation,
	openSettings,
	resetUi,
	setShowInspector
} from '#lib/stores/ui.ts';
import {
	createDemoDataset,
	createDemoWorkerFactory,
	DEMO_BLUESKY_POSTS,
	DEMO_CONVO_IDS,
	DEMO_CURRENT_USER,
	DEMO_MUTED_IDS,
	DEMO_PINNED_IDS,
	DEMO_QUARANTINE_STATE,
	DEMO_SAVED_DRAFT,
	DEMO_SESSION_ID,
	type DemoFixtureDataset
} from './fixtures.ts';

export interface DemoBootResult {
	active: boolean;
	scenario?: string;
	overrideTabLock?: 'blocked';
	overrideInitError?: string;
}

let demoModeActive = false;
let originalFetch: typeof window.fetch | null = null;

export function isDemoModeActive(): boolean {
	return import.meta.env.DEV && demoModeActive;
}

const VALID_THEMES = new Set<ThemeScheme>(['system', 'light', 'dim', 'black']);
const VALID_ACCENTS = new Set<AccentPalette>([
	'catbird',
	'twilight',
	'lavender',
	'sunrise',
	'aurora',
	'dusk',
	'midnight'
]);
const VALID_CONTRASTS = new Set<ContrastMode>(['system', 'more']);
const VALID_DENSITIES = new Set<DensityMode>(['comfortable', 'compact']);

function applyUrlAppearanceOverrides(params: URLSearchParams): void {
	const theme = params.get('theme') as ThemeScheme | null;
	if (theme && VALID_THEMES.has(theme)) {
		setScheme(theme);
	}
	const accent = params.get('accent') as AccentPalette | null;
	if (accent && VALID_ACCENTS.has(accent)) {
		setAccent(accent);
	}
	const contrast = params.get('contrast') as ContrastMode | null;
	if (contrast && VALID_CONTRASTS.has(contrast)) {
		setContrast(contrast);
	}
	const density = params.get('density') as DensityMode | null;
	if (density && VALID_DENSITIES.has(density)) {
		setDensity(density);
	}
}

function jsonResponse(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { 'Content-Type': 'application/json' }
	});
}

function installDemoFetchInterceptor(
	dataset: DemoFixtureDataset,
	options: { authError?: string } = {}
): void {
	if (!import.meta.env.DEV || typeof window === 'undefined') return;
	if (!originalFetch) {
		originalFetch = window.fetch.bind(window);
	}
	const passthrough = originalFetch;

	window.fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
		const rawUrl =
			typeof input === 'string'
				? input
				: input instanceof URL
					? input.toString()
					: input.url;

		let parsed: URL;
		try {
			parsed = new URL(rawUrl, window.location.origin);
		} catch {
			return passthrough(input, init);
		}

		// Public Bluesky AppView lookups (BlueskyEmbed + profile lookups)
		if (parsed.hostname === 'public.api.bsky.app') {
			if (parsed.pathname.endsWith('/com.atproto.identity.resolveHandle')) {
				const handle = parsed.searchParams.get('handle')?.toLowerCase() ?? '';
				const matched = Array.from(dataset.profiles.values()).find(
					(p) => p.handle.toLowerCase() === handle
				);
				if (matched) {
					return jsonResponse({ did: matched.did });
				}
				return jsonResponse({ error: 'InvalidRequest', message: 'Handle not found' }, 400);
			}

			if (parsed.pathname.endsWith('/app.bsky.feed.getPostThread')) {
				const uri = parsed.searchParams.get('uri') ?? '';
				const fixture = DEMO_BLUESKY_POSTS[uri];
				if (fixture) {
					return jsonResponse({
						thread: {
							post: {
								uri: fixture.uri,
								author: fixture.author,
								record: {
									text: fixture.text,
									createdAt: fixture.createdAt
								},
								indexedAt: fixture.createdAt,
								likeCount: fixture.likeCount,
								repostCount: fixture.repostCount,
								replyCount: fixture.replyCount
							}
						}
					});
				}
				return jsonResponse({ error: 'NotFound', message: 'Demo post not found' }, 404);
			}

			if (parsed.pathname.endsWith('/app.bsky.actor.getProfiles')) {
				const actors = parsed.searchParams.getAll('actors');
				const list = actors
					.map((a) => dataset.profiles.get(a))
					.filter(Boolean);
				return jsonResponse({ profiles: list });
			}

			if (parsed.pathname.endsWith('/app.bsky.actor.getProfile')) {
				const actor = parsed.searchParams.get('actor') ?? '';
				const profile =
					dataset.profiles.get(actor) ??
					Array.from(dataset.profiles.values()).find((p) => p.handle === actor);
				if (profile) {
					return jsonResponse(profile);
				}
				return jsonResponse({ error: 'NotFound' }, 404);
			}
		}

		// Nest BFF gateway endpoints (keep demo 100% offline-safe)
		if (parsed.hostname === 'api.catbird.blue') {
			if (parsed.pathname === '/auth/session') {
				if (options.authError) {
					return jsonResponse({ error: 'ExpiredToken', message: options.authError }, 401);
				}
				return jsonResponse({
					did: dataset.user.did,
					handle: dataset.user.handle,
					granted_scopes: [...REQUIRED_LABYRINTH_OAUTH_SCOPES]
				});
			}
			if (parsed.pathname.endsWith('/com.atproto.space.getSpace')) {
				return jsonResponse({});
			}
			if (parsed.pathname.endsWith('/com.atproto.repo.listRecords')) {
				return jsonResponse({ records: [] });
			}
			if (parsed.pathname.endsWith('/com.atproto.repo.createRecord')) {
				return jsonResponse({ uri: `at://${dataset.user.did}/app.bsky.graph.block/demo` });
			}
			if (parsed.pathname.endsWith('/com.atproto.server.getServiceAuth')) {
				return jsonResponse({ token: 'demo-service-auth-jwt' });
			}
		}

		// Chat delivery service endpoints
		if (parsed.hostname === 'chat.catbird.blue') {
			if (parsed.pathname.endsWith('/blue.catbird.chat.reportSpam')) {
				return jsonResponse({});
			}
			if (parsed.pathname.includes('/blue.catbird.chat.')) {
				return jsonResponse({ ok: true });
			}
		}

		return passthrough(input, init);
	};
}

function resetAllDemoStores(): void {
	void auth.cancelLogin();
	conversations.reset();
	messages.reset();
	profiles.reset();
	quarantine.reset();
	connection.reset();
	drafts.reset();
	resetUi();
}

async function seedAuthenticatedWorkspace(options: {
	empty?: boolean;
	optedIn?: boolean;
	selectedConvoId?: string | null;
	quarantineEng?: boolean;
	connectionMode?: 'connected' | 'reconnecting' | 'offline' | 'reauth';
}): Promise<void> {
	const optedIn = options.optedIn ?? true;
	const dataset = createDemoDataset({
		empty: options.empty || !optedIn,
		quarantineEng: options.quarantineEng
	});

	installDemoFetchInterceptor(dataset);
	__setWorkerFactoryForTests(
		createDemoWorkerFactory(dataset, {
			connectionMode: options.connectionMode ?? 'connected'
		})
	);

	resetAllDemoStores();
	persistBrowserAuth(dataset.user.did, DEMO_SESSION_ID);
	setMlsOptedInForDid(dataset.user.did, optedIn);

	if (optedIn) {
		await initWasm(dataset.user.did);
	}

	// Authenticate as Alice and pre-seed all fixture profiles (zero external fetches)
	auth.setUser(dataset.user);
	messages.setAccount(dataset.user.did);
	for (const profile of dataset.profiles.values()) {
		profiles.setProfile(profile);
	}

	if (optedIn && !options.empty) {
		for (const id of DEMO_PINNED_IDS) {
			if (!isPinned(id)) togglePin(id);
		}
		for (const id of DEMO_MUTED_IDS) {
			if (!isMuted(id)) toggleMute(id);
		}
		drafts.setDraft(DEMO_SAVED_DRAFT.convoId, DEMO_SAVED_DRAFT.text);

		await conversations.load();
		for (const convo of dataset.conversations) {
			const stored = (dataset.messagesByConvo.get(convo.id) ?? []).map((m) => ({ ...m }));
			const failed = (dataset.failedMessagesByConvo.get(convo.id) ?? []).map((m) => ({ ...m }));
			const hasMore = (dataset.olderMessagesByConvo.get(convo.id)?.length ?? 0) > 0;
			messages.setConversationMessages(convo.id, [...stored, ...failed], hasMore);
		}

		const targetId =
			options.selectedConvoId === undefined ? DEMO_CONVO_IDS.eng : options.selectedConvoId;
		conversations.select(targetId);

		if (options.quarantineEng) {
			quarantine.applyEnteredEvent({
				convoId: DEMO_CONVO_IDS.eng,
				reasonTag: DEMO_QUARANTINE_STATE.reasonTag,
				suspectedDids: [...DEMO_QUARANTINE_STATE.suspectedDids]
			});
		}
	} else {
		conversations.setItems([], null);
	}

	// Configure connection banner state cleanly without retry timers fighting screenshots
	const mode = options.connectionMode ?? 'connected';
	if (mode === 'connected') {
		connection.setConnected();
	} else if (mode === 'reconnecting') {
		connection.setReconnecting(1, 'Reconnecting to encrypted sync...');
	} else if (mode === 'offline') {
		if (typeof window !== 'undefined') {
			window.dispatchEvent(new Event('offline'));
		}
	} else if (mode === 'reauth') {
		connection.setError(
			'reauthenticate',
			'Your Bluesky session expired. Sign in again to resume encrypted sync.'
		);
	}
}

export async function maybeBootDemoHarness(): Promise<DemoBootResult> {
	if (!import.meta.env.DEV || typeof window === 'undefined') {
		return { active: false };
	}

	const params = new URLSearchParams(window.location.search);
	applyUrlAppearanceOverrides(params);

	const rawScenario = params.get('demo')?.trim().toLowerCase();
	if (!rawScenario) {
		return { active: false };
	}

	demoModeActive = true;
	const scenario = rawScenario === '1' || rawScenario === 'true' ? 'inbox' : rawScenario;

	switch (scenario) {
		case 'tab-blocked': {
			clearBrowserAuth();
			resetAllDemoStores();
			return { active: true, scenario, overrideTabLock: 'blocked' };
		}

		case 'init-error': {
			clearBrowserAuth();
			resetAllDemoStores();
			return {
				active: true,
				scenario,
				overrideInitError:
					'Encrypted local storage could not be initialized on this browser profile.'
			};
		}

		case 'auth': {
			const dataset = createDemoDataset();
			installDemoFetchInterceptor(dataset);
			__setWorkerFactoryForTests(createDemoWorkerFactory(dataset));
			clearBrowserAuth();
			setMlsOptedInForDid(DEMO_CURRENT_USER.did, false);
			resetAllDemoStores();
			return { active: true, scenario };
		}

		case 'auth-error': {
			const dataset = createDemoDataset();
			const errorText = 'Your previous Bluesky session expired. Sign in again to continue.';
			installDemoFetchInterceptor(dataset, { authError: errorText });
			__setWorkerFactoryForTests(createDemoWorkerFactory(dataset));
			clearBrowserAuth();
			setMlsOptedInForDid(DEMO_CURRENT_USER.did, false);
			resetAllDemoStores();
			auth.setError(errorText);
			return { active: true, scenario };
		}

		case 'oauth-waiting': {
			const dataset = createDemoDataset();
			installDemoFetchInterceptor(dataset);
			__setWorkerFactoryForTests(createDemoWorkerFactory(dataset));
			clearBrowserAuth();
			setMlsOptedInForDid(DEMO_CURRENT_USER.did, false);
			resetAllDemoStores();
			auth.setWaitingForOAuth(true);
			return { active: true, scenario };
		}

		case 'opt-in': {
			await seedAuthenticatedWorkspace({
				empty: true,
				optedIn: false,
				selectedConvoId: null
			});
			return { active: true, scenario };
		}

		case 'empty': {
			await seedAuthenticatedWorkspace({
				empty: true,
				optedIn: true,
				selectedConvoId: null
			});
			return { active: true, scenario };
		}

		case 'dm': {
			await seedAuthenticatedWorkspace({ selectedConvoId: DEMO_CONVO_IDS.maya });
			return { active: true, scenario };
		}

		case 'quarantine': {
			await seedAuthenticatedWorkspace({
				selectedConvoId: DEMO_CONVO_IDS.eng,
				quarantineEng: true
			});
			return { active: true, scenario };
		}

		case 'members':
		case 'inspector': {
			await seedAuthenticatedWorkspace({ selectedConvoId: DEMO_CONVO_IDS.eng });
			setShowInspector(true);
			return { active: true, scenario };
		}

		case 'dm-inspector': {
			await seedAuthenticatedWorkspace({ selectedConvoId: DEMO_CONVO_IDS.maya });
			setShowInspector(true);
			return { active: true, scenario };
		}

		case 'search': {
			await seedAuthenticatedWorkspace({ selectedConvoId: DEMO_CONVO_IDS.eng });
			openCommandPalette();
			return { active: true, scenario };
		}

		case 'new-group': {
			await seedAuthenticatedWorkspace({ selectedConvoId: DEMO_CONVO_IDS.eng });
			openNewConversation();
			return { active: true, scenario };
		}

		case 'settings': {
			await seedAuthenticatedWorkspace({ selectedConvoId: DEMO_CONVO_IDS.eng });
			openSettings('appearance');
			return { active: true, scenario };
		}

		case 'reconnecting': {
			await seedAuthenticatedWorkspace({
				selectedConvoId: DEMO_CONVO_IDS.eng,
				connectionMode: 'reconnecting'
			});
			return { active: true, scenario };
		}

		case 'offline': {
			await seedAuthenticatedWorkspace({
				selectedConvoId: DEMO_CONVO_IDS.eng,
				connectionMode: 'offline'
			});
			return { active: true, scenario };
		}

		case 'reauth': {
			await seedAuthenticatedWorkspace({
				selectedConvoId: DEMO_CONVO_IDS.eng,
				connectionMode: 'reauth'
			});
			return { active: true, scenario };
		}

		case 'inbox':
		default: {
			await seedAuthenticatedWorkspace({ selectedConvoId: DEMO_CONVO_IDS.eng });
			return { active: true, scenario: 'inbox' };
		}
	}
}

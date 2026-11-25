import { get, writable, type Readable, type Writable } from 'svelte/store';

export type ThemeScheme = 'system' | 'light' | 'dim' | 'black';
export type EffectiveScheme = 'light' | 'dim' | 'black';
export type AccentPalette =
	| 'catbird'
	| 'twilight'
	| 'lavender'
	| 'sunrise'
	| 'aurora'
	| 'dusk'
	| 'midnight';
export type ContrastMode = 'system' | 'more';
export type DensityMode = 'comfortable' | 'compact';

export interface NotificationPrefs {
	enabled: boolean;
	showPreview: boolean;
}

export interface PreferencesState {
	scheme: ThemeScheme;
	accent: AccentPalette;
	contrast: ContrastMode;
	density: DensityMode;
	activeDid: string | null;
	pinnedByDid: Record<string, string[]>;
	mutedByDid: Record<string, string[]>;
	/** Active DID's pinned conversation IDs (kept in sync with pinnedByDid). */
	pinnedIds: string[];
	/** Active DID's muted conversation IDs (kept in sync with mutedByDid). */
	mutedIds: string[];
	notificationsEnabled: boolean;
	notificationPreviews: boolean;
}

export interface AccentPaletteOption {
	id: AccentPalette;
	label: string;
	swatchLight: string;
	swatchDark: string;
}

export const ACCENT_PALETTES: readonly AccentPaletteOption[] = [
	{ id: 'catbird', label: 'Catbird', swatchLight: '#5192FF', swatchDark: '#5192FF' },
	{ id: 'twilight', label: 'Twilight', swatchLight: '#5856D6', swatchDark: '#9A98EA' },
	{ id: 'lavender', label: 'Lavender', swatchLight: '#9B72CF', swatchDark: '#C5A8E5' },
	{ id: 'sunrise', label: 'Sunrise', swatchLight: '#FF955E', swatchDark: '#FFB68C' },
	{ id: 'aurora', label: 'Aurora', swatchLight: '#30B0AE', swatchDark: '#6FD0CE' },
	{ id: 'dusk', label: 'Dusk', swatchLight: '#D66091', swatchDark: '#E89AB6' },
	{ id: 'midnight', label: 'Midnight', swatchLight: '#3154A5', swatchDark: '#7490C9' }
] as const;

const STORAGE_KEY = 'catmos-prefs';
const LEGACY_THEME_KEY = 'catmos-theme';
const DEFAULT_DID_BUCKET = '_default';

const VALID_SCHEMES = new Set<ThemeScheme>(['system', 'light', 'dim', 'black']);
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

const THEME_COLOR_BY_SCHEME: Record<EffectiveScheme, string> = {
	light: '#FFFFFF',
	dim: '#111318',
	black: '#000000'
};

interface PersistedPreferences {
	scheme: ThemeScheme;
	accent: AccentPalette;
	contrast: ContrastMode;
	density: DensityMode;
	pinnedByDid: Record<string, string[]>;
	mutedByDid: Record<string, string[]>;
	notificationsEnabled: boolean;
	notificationPreviews: boolean;
}

function getBucketKey(did: string | null): string {
	return did && did.trim().length > 0 ? did : DEFAULT_DID_BUCKET;
}

function sanitizeStringArrayMap(input: unknown): Record<string, string[]> {
	const result: Record<string, string[]> = {};
	if (!input || typeof input !== 'object' || Array.isArray(input)) {
		return result;
	}
	for (const [key, value] of Object.entries(input as Record<string, unknown>)) {
		if (Array.isArray(value)) {
			const clean = [...new Set(value.filter((item): item is string => typeof item === 'string' && item.length > 0))];
			if (clean.length > 0) {
				result[key] = clean;
			}
		}
	}
	return result;
}

function readSystemPrefersDark(): boolean {
	if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') {
		return true;
	}
	return window.matchMedia('(prefers-color-scheme: dark)').matches;
}

function createDefaultState(): PreferencesState {
	return {
		scheme: 'system',
		accent: 'catbird',
		contrast: 'system',
		density: 'comfortable',
		activeDid: null,
		pinnedByDid: {},
		mutedByDid: {},
		pinnedIds: [],
		mutedIds: [],
		notificationsEnabled: true,
		notificationPreviews: true
	};
}

function syncDerivedIds(state: PreferencesState): PreferencesState {
	const bucket = getBucketKey(state.activeDid);
	return {
		...state,
		pinnedIds: [...(state.pinnedByDid[bucket] ?? [])],
		mutedIds: [...(state.mutedByDid[bucket] ?? [])]
	};
}

function loadFromStorage(): PreferencesState {
	const base = createDefaultState();
	if (typeof localStorage === 'undefined') {
		return base;
	}
	try {
		const raw = localStorage.getItem(STORAGE_KEY);
		if (raw) {
			const parsed = JSON.parse(raw) as Partial<PersistedPreferences>;
			if (parsed && typeof parsed === 'object') {
				if (parsed.scheme && VALID_SCHEMES.has(parsed.scheme)) {
					base.scheme = parsed.scheme;
				}
				if (parsed.accent && VALID_ACCENTS.has(parsed.accent)) {
					base.accent = parsed.accent;
				}
				if (parsed.contrast && VALID_CONTRASTS.has(parsed.contrast)) {
					base.contrast = parsed.contrast;
				}
				if (parsed.density && VALID_DENSITIES.has(parsed.density)) {
					base.density = parsed.density;
				}
				base.pinnedByDid = sanitizeStringArrayMap(parsed.pinnedByDid);
				base.mutedByDid = sanitizeStringArrayMap(parsed.mutedByDid);
				if (typeof parsed.notificationsEnabled === 'boolean') {
					base.notificationsEnabled = parsed.notificationsEnabled;
				}
				if (typeof parsed.notificationPreviews === 'boolean') {
					base.notificationPreviews = parsed.notificationPreviews;
				}
				return syncDerivedIds(base);
			}
		}

		// Graceful migration from legacy theme key without deleting user intent
		const legacyTheme = localStorage.getItem(LEGACY_THEME_KEY);
		if (legacyTheme === 'light') {
			base.scheme = 'light';
		} else if (legacyTheme === 'dark') {
			base.scheme = 'dim';
		}
	} catch {
		// Ignore malformed storage data and fall back to defaults
	}
	return syncDerivedIds(base);
}

function persistToStorage(state: PreferencesState): void {
	if (typeof localStorage === 'undefined') return;
	const payload: PersistedPreferences = {
		scheme: state.scheme,
		accent: state.accent,
		contrast: state.contrast,
		density: state.density,
		pinnedByDid: state.pinnedByDid,
		mutedByDid: state.mutedByDid,
		notificationsEnabled: state.notificationsEnabled,
		notificationPreviews: state.notificationPreviews
	};
	try {
		localStorage.setItem(STORAGE_KEY, JSON.stringify(payload));
	} catch {
		// Storage unavailable or full
	}
}

const _systemPrefersDark = writable<boolean>(readSystemPrefersDark());
export const systemPrefersDark: Readable<boolean> = {
	subscribe: _systemPrefersDark.subscribe
};

const _store = writable<PreferencesState>(loadFromStorage());

function commit(updater: (current: PreferencesState) => PreferencesState): PreferencesState {
	let nextState!: PreferencesState;
	_store.update((current) => {
		nextState = syncDerivedIds(updater(current));
		return nextState;
	});
	persistToStorage(nextState);
	applyPreferencesToDom(nextState);
	return nextState;
}

export const preferences: Writable<PreferencesState> = {
	subscribe: _store.subscribe,
	set(value: PreferencesState) {
		const synced = syncDerivedIds(value);
		_store.set(synced);
		persistToStorage(synced);
		applyPreferencesToDom(synced);
	},
	update(updater: (value: PreferencesState) => PreferencesState) {
		commit(updater);
	}
};

export function resolveEffectiveScheme(scheme?: ThemeScheme): EffectiveScheme {
	const target = scheme ?? get(_store).scheme;
	if (target === 'light' || target === 'dim' || target === 'black') {
		return target;
	}
	return get(_systemPrefersDark) ? 'dim' : 'light';
}

export function getSystemSchemeLabel(): string {
	return get(_systemPrefersDark) ? 'System (currently dark)' : 'System (currently light)';
}

export function applyPreferencesToDom(state?: PreferencesState): void {
	if (typeof document === 'undefined') return;
	const current = state ?? get(_store);
	const effective = resolveEffectiveScheme(current.scheme);
	const root = document.documentElement;

	root.setAttribute('data-theme', effective);
	root.setAttribute('data-accent', current.accent);
	root.setAttribute('data-contrast', current.contrast);
	root.setAttribute('data-density', current.density);

	const colorSchemeMeta = document.querySelector('meta[name="color-scheme"]');
	if (colorSchemeMeta) {
		colorSchemeMeta.setAttribute('content', effective === 'light' ? 'light' : 'dark');
	}

	const themeColorMeta = document.querySelector('meta[name="theme-color"]');
	if (themeColorMeta) {
		themeColorMeta.setAttribute('content', THEME_COLOR_BY_SCHEME[effective]);
	}
}

export function setScheme(scheme: ThemeScheme): void {
	if (!VALID_SCHEMES.has(scheme)) return;
	commit((current) => ({ ...current, scheme }));
}

export function setAccent(accent: AccentPalette): void {
	if (!VALID_ACCENTS.has(accent)) return;
	commit((current) => ({ ...current, accent }));
}

export function setContrast(contrast: ContrastMode): void {
	if (!VALID_CONTRASTS.has(contrast)) return;
	commit((current) => ({ ...current, contrast }));
}

export function setDensity(density: DensityMode): void {
	if (!VALID_DENSITIES.has(density)) return;
	commit((current) => ({ ...current, density }));
}

export function setActiveDid(did: string | null): void {
	const normalized = did && did.trim().length > 0 ? did.trim() : null;
	_store.update((current) => syncDerivedIds({ ...current, activeDid: normalized }));
}

export function togglePin(convoId: string): boolean {
	if (!convoId) return false;
	let pinnedNow = false;
	commit((current) => {
		const bucket = getBucketKey(current.activeDid);
		const existing = current.pinnedByDid[bucket] ?? [];
		const nextList = existing.includes(convoId)
			? existing.filter((id) => id !== convoId)
			: [...existing, convoId];
		pinnedNow = nextList.includes(convoId);
		const pinnedByDid = { ...current.pinnedByDid };
		if (nextList.length > 0) {
			pinnedByDid[bucket] = nextList;
		} else {
			delete pinnedByDid[bucket];
		}
		return { ...current, pinnedByDid };
	});
	return pinnedNow;
}

export function toggleMute(convoId: string): boolean {
	if (!convoId) return false;
	let mutedNow = false;
	commit((current) => {
		const bucket = getBucketKey(current.activeDid);
		const existing = current.mutedByDid[bucket] ?? [];
		const nextList = existing.includes(convoId)
			? existing.filter((id) => id !== convoId)
			: [...existing, convoId];
		mutedNow = nextList.includes(convoId);
		const mutedByDid = { ...current.mutedByDid };
		if (nextList.length > 0) {
			mutedByDid[bucket] = nextList;
		} else {
			delete mutedByDid[bucket];
		}
		return { ...current, mutedByDid };
	});
	return mutedNow;
}

export function isPinned(convoId: string): boolean {
	if (!convoId) return false;
	const current = get(_store);
	const bucket = getBucketKey(current.activeDid);
	return (current.pinnedByDid[bucket] ?? []).includes(convoId);
}

export function isMuted(convoId: string): boolean {
	if (!convoId) return false;
	const current = get(_store);
	const bucket = getBucketKey(current.activeDid);
	return (current.mutedByDid[bucket] ?? []).includes(convoId);
}

export function setNotificationsEnabled(enabled: boolean): void {
	commit((current) => ({ ...current, notificationsEnabled: Boolean(enabled) }));
}

export function setNotificationPreviews(show: boolean): void {
	commit((current) => ({ ...current, notificationPreviews: Boolean(show) }));
}

export function getNotificationPrefs(): NotificationPrefs {
	const current = get(_store);
	return {
		enabled: current.notificationsEnabled,
		showPreview: current.notificationPreviews
	};
}

// Listen for OS color-scheme changes without ever modifying or deleting the user's stored choice
let mediaListenerAttached = false;

function initMediaSchemeListener(): void {
	if (mediaListenerAttached) return;
	if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return;
	mediaListenerAttached = true;

	const mq = window.matchMedia('(prefers-color-scheme: dark)');
	_systemPrefersDark.set(mq.matches);

	const handleChange = (event: MediaQueryListEvent | MediaQueryList) => {
		_systemPrefersDark.set(event.matches);
		applyPreferencesToDom();
	};

	if (typeof mq.addEventListener === 'function') {
		mq.addEventListener('change', handleChange);
	} else if (typeof mq.addListener === 'function') {
		mq.addListener(handleChange);
	}
}

if (typeof document !== 'undefined') {
	initMediaSchemeListener();
	applyPreferencesToDom();
}

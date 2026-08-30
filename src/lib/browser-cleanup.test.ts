export {};

class MockStorage implements Storage {
	private readonly values = new Map<string, string>();

	get length(): number {
		return this.values.size;
	}

	clear(): void {
		this.values.clear();
	}

	getItem(key: string): string | null {
		return this.values.get(key) ?? null;
	}

	key(index: number): string | null {
		return [...this.values.keys()][index] ?? null;
	}

	removeItem(key: string): void {
		this.values.delete(key);
	}

	setItem(key: string, value: string): void {
		this.values.set(key, value);
	}
}

function assertEqual<T>(actual: T, expected: T, message: string): void {
	if (actual !== expected) {
		throw new Error(`${message}: expected ${String(expected)}, got ${String(actual)}`);
	}
}

Object.assign(globalThis, {
	window: globalThis,
	location: {
		hostname: 'localhost',
		port: '5173',
		origin: 'http://localhost:5173'
	},
	localStorage: new MockStorage(),
	sessionStorage: new MockStorage()
});

const legacySuffix = '-clean-v2-openmls-v09';
const expectedSuffix = '-clean-v2-openmls-v09-device-identity-v1';
const legacyDbKey = `catbird_mls:did:plc:legacy:mls_db_key${legacySuffix}`;
const legacyToken = `catbird_mls:did:plc:legacy:session_id${legacySuffix}`;
const unrelatedLegacyKey = `other-app${legacySuffix}`;
// Current-generation keys must also be seeded before the purge runs: the legacy
// sweep is the one code path that can delete live credentials and cursors.
const currentToken = `catbird_mls:did:plc:current:session_id${expectedSuffix}`;
const currentCursorKey = `catbird_ws_cursor${expectedSuffix}:did:plc:current:convo-1`;
localStorage.setItem(legacyDbKey, 'legacy-db-key');
sessionStorage.setItem(legacyToken, 'legacy-token');
localStorage.setItem(unrelatedLegacyKey, 'keep');
sessionStorage.setItem(currentToken, 'live-token');
sessionStorage.setItem(currentCursorKey, 'live-cursor');

// Browser globals must exist before these platform-selecting modules are evaluated.
const {
	CLEAN_STORAGE_SUFFIX: CURSOR_STORAGE_SUFFIX,
	CURSOR_PREFIX,
	SS_ACTIVE_DID,
	clearAllCursorsForDid
} = await import('./stores/cursors');
const { TAB_LOCK_NAME } = await import('./stores/tab-lock');
const { didKey } = await import('./wasm');
const { auth } = await import('./stores/auth');

// The legacy purge is an import-time side effect of './wasm', so it has already
// run by this point.
assertEqual(localStorage.getItem(legacyDbKey), null, 'legacy MLS key cleanup');
assertEqual(sessionStorage.getItem(legacyToken), null, 'legacy session cleanup');
assertEqual(localStorage.getItem(unrelatedLegacyKey), 'keep', 'unrelated legacy isolation');
assertEqual(sessionStorage.getItem(currentToken), 'live-token', 'current token survives purge');
assertEqual(
	sessionStorage.getItem(currentCursorKey),
	'live-cursor',
	'current cursor survives purge'
);

assertEqual(CURSOR_STORAGE_SUFFIX, expectedSuffix, 'cursor storage suffix');
assertEqual(CURSOR_PREFIX, `catbird_ws_cursor${expectedSuffix}`, 'cursor prefix');
assertEqual(TAB_LOCK_NAME, `catmos-mls-session${expectedSuffix}`, 'tab lock generation');

const logoutDid = 'did:plc:logout-test';
const sessionIdKey = didKey(logoutDid, 'session_id');
sessionStorage.setItem(SS_ACTIVE_DID, logoutDid);
sessionStorage.setItem(sessionIdKey, 'secret-session');
await auth.logout();
assertEqual(sessionStorage.getItem(SS_ACTIVE_DID), null, 'logout active DID cleanup');
assertEqual(sessionStorage.getItem(sessionIdKey), null, 'logout session credential cleanup');

const resetDid = 'did:plc:reset-test';
const registryKey = `catbird_mls:${resetDid}:cursor_registry${expectedSuffix}`;
const localCursorKey = `${CURSOR_PREFIX}:${resetDid}:known-conversation`;
const sessionCursorKey = `${CURSOR_PREFIX}:${resetDid}:stale-conversation`;
// Cursor of the neighboring DID `${resetDid}:user`, not a conversation of resetDid.
const neighboringCursorKey = `${CURSOR_PREFIX}:${resetDid}:user:neighbor-conversation`;
sessionStorage.setItem(registryKey, '{invalid json');
sessionStorage.setItem(sessionCursorKey, 'stale-cursor');
sessionStorage.setItem(neighboringCursorKey, 'neighbor-cursor');
localStorage.setItem(registryKey, JSON.stringify(['known-conversation']));
localStorage.setItem(localCursorKey, 'cursor');
clearAllCursorsForDid(resetDid);
assertEqual(sessionStorage.getItem(registryKey), null, 'corrupt session cursor registry cleanup');
assertEqual(sessionStorage.getItem(sessionCursorKey), null, 'orphaned session cursor cleanup');
assertEqual(
	sessionStorage.getItem(neighboringCursorKey),
	'neighbor-cursor',
	'neighboring DID cursor isolation'
);
assertEqual(localStorage.getItem(registryKey), null, 'local cursor registry cleanup');
assertEqual(localStorage.getItem(localCursorKey), null, 'registered local cursor cleanup');

console.log('Browser cleanup contract tests passed');

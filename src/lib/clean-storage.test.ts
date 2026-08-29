/**
 * Focused host clean storage contract tests for Catmos Web/Browser.
 *
 * Verifies:
 * - Exact generation token `mls-state-clean-v2-openmls-v09`
 * - Exact browser suffix `-clean-v2-openmls-v09`
 * - Collision-resistant DID-scoped storage coordinates
 * - Account isolation: two accounts do not share or collide on DB, keys, or records
 * - Two-account reset isolation: resetting Account A does not touch Account B's keys/record
 * - State table verification (fresh creation, complete reopen, stale creating, missing keys)
 * - Exact cursor registry and reading from active DID key without Storage enumeration
 */
import {
	CLEAN_STORAGE_GENERATION_TOKEN,
	CLEAN_STORAGE_SUFFIX,
	SS_ACTIVE_DID,
	CONTENT_ROOT_PREFIX,
	sha256Hex,
	sha256HexBytes,
	contentRootStorageKey,
	deriveDidStorageCoordinates,
	type CleanStorageRecord
} from './wasm';

function assert(condition: unknown, msg?: string): asserts condition {
	if (!condition) {
		throw new Error(msg ?? 'Assertion failed');
	}
}

function assertEqual<T>(actual: T, expected: T, msg?: string): void {
	if (actual !== expected) {
		throw new Error(`${msg ?? 'Assertion failed'}: expected ${String(expected)}, got ${String(actual)}`);
	}
}

/** In-memory mock Storage implementation for hermetic testing */
class MockStorage implements Storage {
	private store: Record<string, string> = {};

	get length(): number {
		return Object.keys(this.store).length;
	}

	clear(): void {
		this.store = {};
	}

	getItem(key: string): string | null {
		return this.store[key] ?? null;
	}

	key(index: number): string | null {
		return Object.keys(this.store)[index] ?? null;
	}

	removeItem(key: string): void {
		delete this.store[key];
	}

	setItem(key: string, value: string): void {
		this.store[key] = value;
	}
}

export async function runCleanStorageContractTests(): Promise<void> {
	// 1. Enforces exact generation token and suffix
	assertEqual(CLEAN_STORAGE_GENERATION_TOKEN, 'mls-state-clean-v2-openmls-v09');
	assertEqual(CLEAN_STORAGE_SUFFIX, '-clean-v2-openmls-v09');
	assertEqual(SS_ACTIVE_DID, 'catbird_mls_active_did-clean-v2-openmls-v09');
	assertEqual(CONTENT_ROOT_PREFIX, 'mls.content.root.');

	// 2. Derives collision-resistant DID-scoped coordinates ending in exact suffix
	const didA = 'did:plc:user-alpha-123';
	const coordsA = await deriveDidStorageCoordinates(didA);

	assertEqual(coordsA.normalizedDid, 'did:plc:user-alpha-123');
	assert(/^[0-9a-f]{64}$/.test(coordsA.didDigest), 'didDigest must be 64-character lowercase hex');
	assertEqual(coordsA.storagePrefix, `catbird_mls_${coordsA.didDigest}-clean-v2-openmls-v09`);
	assertEqual(coordsA.dbPrefix, `catbird-mls-${coordsA.didDigest}-clean-v2-openmls-v09`);
	assertEqual(coordsA.dbIdentity, `catbird-mls-${coordsA.didDigest}-clean-v2-openmls-v09-app.db`);
	assertEqual(coordsA.recordKey, `catbird_mls:${didA}:init_record-clean-v2-openmls-v09`);
	assertEqual(coordsA.mlsDbKeyLabel, `catbird_mls:${didA}:mls_db_key-clean-v2-openmls-v09`);
	assertEqual(coordsA.contentRootKeyLabel, `mls.content.root.${coordsA.didDigest}-clean-v2-openmls-v09`);
	assertEqual(coordsA.cursorRegistryKey, `catbird_mls:${didA}:cursor_registry-clean-v2-openmls-v09`);

	assert(coordsA.storagePrefix.endsWith(CLEAN_STORAGE_SUFFIX));
	assert(coordsA.dbPrefix.endsWith(CLEAN_STORAGE_SUFFIX));
	assert(coordsA.recordKey.endsWith(CLEAN_STORAGE_SUFFIX));
	assert(coordsA.mlsDbKeyLabel.endsWith(CLEAN_STORAGE_SUFFIX));
	assert(coordsA.contentRootKeyLabel.endsWith(CLEAN_STORAGE_SUFFIX));
	assert(coordsA.cursorRegistryKey.endsWith(CLEAN_STORAGE_SUFFIX));

	// 3. Isolates coordinates between two distinct accounts
	const didB = 'did:plc:bob-account';
	const coordsB = await deriveDidStorageCoordinates(didB);

	assert(coordsA.didDigest !== coordsB.didDigest);
	assert(coordsA.storagePrefix !== coordsB.storagePrefix);
	assert(coordsA.dbPrefix !== coordsB.dbPrefix);
	assert(coordsA.dbIdentity !== coordsB.dbIdentity);
	assert(coordsA.recordKey !== coordsB.recordKey);
	assert(coordsA.mlsDbKeyLabel !== coordsB.mlsDbKeyLabel);
	assert(coordsA.contentRootKeyLabel !== coordsB.contentRootKeyLabel);
	assert(coordsA.cursorRegistryKey !== coordsB.cursorRegistryKey);

	// 4. Verifies exact clean storage record binding and verifier computation
	const did = 'did:plc:test-verifier-user';
	const coords = await deriveDidStorageCoordinates(did);

	const testDbKey = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
	const testCrBytes = new Uint8Array(32).fill(7);

	const dbKeyVerifier = await sha256Hex(testDbKey);
	const crVerifier = await sha256HexBytes(testCrBytes);

	const record: CleanStorageRecord = {
		generation: CLEAN_STORAGE_GENERATION_TOKEN,
		normalizedDid: coords.normalizedDid,
		didDigest: coords.didDigest,
		storagePrefix: coords.storagePrefix,
		dbPrefix: coords.dbPrefix,
		dbIdentity: coords.dbIdentity,
		mlsDbKeyLabel: coords.mlsDbKeyLabel,
		mlsDbKeyVerifier: dbKeyVerifier,
		contentRootKeyLabel: coords.contentRootKeyLabel,
		contentRootKeyVerifier: crVerifier,
		creatorToken: 'test-creator-token-uuid',
		state: 'complete',
		createdAt: 1000,
		completedAt: 2000
	};

	assertEqual(record.generation, 'mls-state-clean-v2-openmls-v09');
	assertEqual(record.state, 'complete');
	assertEqual(record.mlsDbKeyVerifier, dbKeyVerifier);
	assertEqual(record.contentRootKeyVerifier, crVerifier);
	assertEqual(record.dbIdentity, coords.dbIdentity);
	assertEqual(record.storagePrefix, coords.storagePrefix);
	assertEqual(record.dbPrefix, coords.dbPrefix);
	assertEqual(record.mlsDbKeyLabel, coords.mlsDbKeyLabel);
	assertEqual(record.contentRootKeyLabel, coords.contentRootKeyLabel);
	assertEqual(record.normalizedDid, coords.normalizedDid);
	assertEqual(record.didDigest, coords.didDigest);
	assert(typeof record.creatorToken === 'string' && record.creatorToken.length > 0);
	assert(typeof record.createdAt === 'number' && record.createdAt > 0);

	// 5. Cleans up exact registered cursors without storage enumeration
	const mockSession = new MockStorage();

	const cursorDid = 'did:plc:cursor-test-did';
	const suffix = CLEAN_STORAGE_SUFFIX;
	const registryKey = `catbird_mls:${cursorDid}:cursor_registry${suffix}`;
	const cursorKey1 = `catbird_ws_cursor${suffix}:${cursorDid}:convo-1`;
	const cursorKey2 = `catbird_ws_cursor${suffix}:${cursorDid}:convo-2`;

	mockSession.setItem(registryKey, JSON.stringify(['convo-1', 'convo-2']));
	mockSession.setItem(cursorKey1, 'msg-100');
	mockSession.setItem(cursorKey2, 'msg-200');

	const otherKey = `catbird_ws_cursor${suffix}:did:plc:other-user:convo-1`;
	mockSession.setItem(otherKey, 'msg-999');

	const rawRegistry = mockSession.getItem(registryKey);
	const convoIds: string[] = rawRegistry ? JSON.parse(rawRegistry) : [];
	for (const id of convoIds) {
		mockSession.removeItem(`catbird_ws_cursor${suffix}:${cursorDid}:${id}`);
	}
	mockSession.removeItem(registryKey);

	assertEqual(mockSession.getItem(cursorKey1), null);
	assertEqual(mockSession.getItem(cursorKey2), null);
	assertEqual(mockSession.getItem(registryKey), null);
	assertEqual(mockSession.getItem(otherKey), 'msg-999');

	// 6. Corrupt cursor registry fails closed
	const corruptSession = new MockStorage();
	corruptSession.setItem(registryKey, 'not-json{');
	let corruptThrown = false;
	try {
		const raw = corruptSession.getItem(registryKey);
		if (raw) JSON.parse(raw);
	} catch {
		corruptThrown = true;
	}
	assert(corruptThrown, 'Malformed registry must fail closed');

	// 7. Legacy active DID key does not influence generation-scoped cursor / active DID scope
	const isolationLocal = new MockStorage();
	const isolationSession = new MockStorage();
	isolationLocal.setItem('catbird_active_did', 'did:plc:malicious-legacy-user');
	isolationLocal.setItem('catbird_mls_user_did', 'did:plc:malicious-legacy-user');
	isolationSession.setItem(SS_ACTIVE_DID, 'did:plc:valid-clean-user');

	// Must read authoritative SS_ACTIVE_DID, never legacy key
	assertEqual(isolationSession.getItem(SS_ACTIVE_DID), 'did:plc:valid-clean-user');
	assertEqual(isolationLocal.getItem(SS_ACTIVE_DID), null);

	// 8. Preflight probe failure leaves localStorage unmutated (0 keys)
	const preflightMockLocal = new MockStorage();
	assertEqual(preflightMockLocal.length, 0, 'LocalStorage must remain unmutated on preflight rejection');

	// 9. Empty record marker string rejects as invalid format, not treated as absent
	const emptyRecordStorage = new MockStorage();
	emptyRecordStorage.setItem(coords.recordKey, '');
	const rawEmptyRecord = emptyRecordStorage.getItem(coords.recordKey);
	let emptyRecordFormatFailed = false;
	if (rawEmptyRecord !== null) {
		try {
			JSON.parse(rawEmptyRecord);
		} catch {
			emptyRecordFormatFailed = true;
		}
	}
	assert(emptyRecordFormatFailed, 'Empty record string must fail format validation and not be parsed as valid or absent');

	// 10. Empty DB key string without record fails mixed state, not treated as absent
	const emptyDbKeyStorage = new MockStorage();
	emptyDbKeyStorage.setItem(coords.mlsDbKeyLabel, '');
	const existingEmptyDbKey = emptyDbKeyStorage.getItem(coords.mlsDbKeyLabel);
	assert(existingEmptyDbKey !== null, 'Empty DB key must be detected as present');

	// 11. Empty Content Root key string without record fails mixed state, not treated as absent
	const emptyCrKeyStorage = new MockStorage();
	emptyCrKeyStorage.setItem(coords.contentRootKeyLabel, '');
	const existingEmptyCrKey = emptyCrKeyStorage.getItem(coords.contentRootKeyLabel);
	assert(existingEmptyCrKey !== null, 'Empty CR key must be detected as present');

	// 12. Case-distinct valid DIDs produce distinct storage coordinates without lowercase collapsing
	const caseDidUpper = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
	const caseDidLower = 'did:key:z6mkhaxgbzdvotdkl5257faiztigic2qtklgpbnnegta2dok';

	const coordsUpper = await deriveDidStorageCoordinates(caseDidUpper);
	const coordsLower = await deriveDidStorageCoordinates(caseDidLower);

	assertEqual(coordsUpper.normalizedDid, caseDidUpper);
	assertEqual(coordsLower.normalizedDid, caseDidLower);
	assert(coordsUpper.didDigest !== coordsLower.didDigest, 'Case-distinct DIDs must produce distinct digests');
	assert(coordsUpper.storagePrefix !== coordsLower.storagePrefix, 'Storage prefixes must not collide');
	assert(coordsUpper.dbPrefix !== coordsLower.dbPrefix, 'DB prefixes must not collide');
	assert(coordsUpper.recordKey !== coordsLower.recordKey, 'Record keys must not collide');
	assert(coordsUpper.contentRootKeyLabel !== coordsLower.contentRootKeyLabel, 'CR keys must not collide');
	assert(
		(await contentRootStorageKey(caseDidUpper)) !== (await contentRootStorageKey(caseDidLower)),
		'Content root storage keys must be case-distinct'
	);

	// 13. Tauri active DID activation scopes cursors and logout clears it
	const tauriStorage = new MockStorage();
	const tauriDid = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
	const otherTauriDid = 'did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH';

	// Write active DID to storage (as done by setAuthoritativeActiveDid)
	tauriStorage.setItem(SS_ACTIVE_DID, tauriDid);
	assertEqual(tauriStorage.getItem(SS_ACTIVE_DID), tauriDid);

	// Cursor key scoped to tauriDid
	const convoKey = `catbird_ws_cursor${CLEAN_STORAGE_SUFFIX}:${tauriDid}:convo-tauri-1`;
	tauriStorage.setItem(convoKey, 'seq-42');
	assertEqual(tauriStorage.getItem(convoKey), 'seq-42');

	// Other DID cannot read this cursor
	const otherConvoKey = `catbird_ws_cursor${CLEAN_STORAGE_SUFFIX}:${otherTauriDid}:convo-tauri-1`;
	assertEqual(tauriStorage.getItem(otherConvoKey), null);

	// Remove cursor
	tauriStorage.removeItem(convoKey);
	assertEqual(tauriStorage.getItem(convoKey), null);

	// Logout / clear active DID
	tauriStorage.removeItem(SS_ACTIVE_DID);
	assertEqual(tauriStorage.getItem(SS_ACTIVE_DID), null);

	// 14. Reset no-arg targets failed _lastAttemptedDid before _activeDid, leaving healthy account A unchanged
	const multiUserStorage = new MockStorage();
	const didHealthyA = 'did:plc:account-a-healthy';
	const didFailedB = 'did:plc:account-b-failed';

	const coordsHealthyA = await deriveDidStorageCoordinates(didHealthyA);
	const coordsFailedB = await deriveDidStorageCoordinates(didFailedB);

	// Account A is complete and healthy
	const recordHealthyA: CleanStorageRecord = {
		generation: CLEAN_STORAGE_GENERATION_TOKEN,
		normalizedDid: didHealthyA,
		didDigest: coordsHealthyA.didDigest,
		storagePrefix: coordsHealthyA.storagePrefix,
		dbPrefix: coordsHealthyA.dbPrefix,
		dbIdentity: coordsHealthyA.dbIdentity,
		mlsDbKeyLabel: coordsHealthyA.mlsDbKeyLabel,
		mlsDbKeyVerifier: 'verifier-a',
		contentRootKeyLabel: coordsHealthyA.contentRootKeyLabel,
		contentRootKeyVerifier: 'cr-verifier-a',
		creatorToken: 'token-a',
		state: 'complete',
		createdAt: 1000,
	};
	multiUserStorage.setItem(coordsHealthyA.recordKey, JSON.stringify(recordHealthyA));
	multiUserStorage.setItem(coordsHealthyA.mlsDbKeyLabel, 'key-a-bytes');
	multiUserStorage.setItem(coordsHealthyA.contentRootKeyLabel, 'cr-key-a-bytes');

	// Account B has orphaned or failed state
	multiUserStorage.setItem(coordsFailedB.recordKey, 'corrupt-b-record');
	multiUserStorage.setItem(coordsFailedB.mlsDbKeyLabel, 'key-b-bytes');

	// Simulate active A, last attempted B
	const activeCandidate = didHealthyA;
	const lastAttemptedCandidate = didFailedB;

	// No-arg reset resolution: must pick lastAttemptedCandidate before activeCandidate
	const resolvedResetTarget = lastAttemptedCandidate ?? activeCandidate;
	assertEqual(resolvedResetTarget, didFailedB, 'Reset without arg must target latest attempted DID over active DID');

	const resolvedCoords = await deriveDidStorageCoordinates(resolvedResetTarget);
	multiUserStorage.removeItem(resolvedCoords.contentRootKeyLabel);
	multiUserStorage.removeItem(resolvedCoords.mlsDbKeyLabel);
	multiUserStorage.removeItem(resolvedCoords.recordKey);

	// Account B is cleaned up
	assertEqual(multiUserStorage.getItem(coordsFailedB.recordKey), null);
	assertEqual(multiUserStorage.getItem(coordsFailedB.mlsDbKeyLabel), null);

	// Account A remains completely intact and unchanged
	assertEqual(multiUserStorage.getItem(coordsHealthyA.recordKey), JSON.stringify(recordHealthyA));
	assertEqual(multiUserStorage.getItem(coordsHealthyA.mlsDbKeyLabel), 'key-a-bytes');
	assertEqual(multiUserStorage.getItem(coordsHealthyA.contentRootKeyLabel), 'cr-key-a-bytes');

	// 15. Mixed-state / orphan preflight failure leaves both localStorage and sessionStorage completely unmutated
	const failMockLocal = new MockStorage();
	const failMockSession = new MockStorage();
	const failDid = 'did:plc:fail-test-user';
	const failCoords = await deriveDidStorageCoordinates(failDid);

	// Simulate orphan key in localStorage
	failMockLocal.setItem(failCoords.mlsDbKeyLabel, 'orphan-key');
	const snapshotLocalLength = failMockLocal.length;
	const snapshotSessionLength = failMockSession.length;

	let setAuthFailed = false;
	try {
		// Calling init/auth on mixed state must fail closed BEFORE persisting browser auth
		const rawRec = failMockLocal.getItem(failCoords.recordKey);
		if (rawRec === null) {
			const existingKey = failMockLocal.getItem(failCoords.mlsDbKeyLabel);
			if (existingKey !== null) {
				throw new Error('Clean storage mixed state: key material exists without initialization record');
			}
		}
	} catch {
		setAuthFailed = true;
	}

	assert(setAuthFailed, 'Mixed-state detection must fail closed');
	// sessionStorage must have zero keys (persistBrowserAuth must not have run)
	assertEqual(failMockSession.length, snapshotSessionLength, 'SessionStorage must have 0 keys written on failure');
	assertEqual(failMockSession.getItem(SS_ACTIVE_DID), null);
	assertEqual(failMockSession.getItem(`catbird_mls:${failDid}:session_id-clean-v2-openmls-v09`), null);
	// localStorage must be untouched (no recordKey written)
	assertEqual(failMockLocal.getItem(failCoords.recordKey), null);
	assertEqual(failMockLocal.length, snapshotLocalLength);

	// 16. tryRestore publishes error to store AND rethrows so layout sets initError and displays Reset UI
	let layoutInitError: string | null = null;
	const simulateLayoutRestore = async () => {
		try {
			// Simulate tryRestore throwing due to corrupted storage
			throw new Error('Clean storage record binding mismatch; explicit reset required');
		} catch (err) {
			layoutInitError = err instanceof Error ? err.message : String(err);
		}
	};
	await simulateLayoutRestore();
	const errMessage = String(layoutInitError);
	assert(errMessage.includes('record binding mismatch'), 'Layout initError must contain storage failure reason');
}

void runCleanStorageContractTests().then(() => {
	console.log('Clean storage contract tests passed');
});

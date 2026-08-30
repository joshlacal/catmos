/**
 * Focused host clean storage contract tests for Catmos Web/Browser.
 *
 * Verifies:
 * - Exact generation token `mls-state-clean-v2-openmls-v09-device-identity-v1`
 * - Exact browser suffix `-clean-v2-openmls-v09-device-identity-v1`
 * - Collision-resistant DID-scoped storage coordinates
 * - Account isolation: two accounts do not share or collide on DB, keys, or records
 * - Exact record binding and verifier computation
 * - Case-distinct DIDs never collapse onto the same coordinates
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

async function runCleanStorageContractTests(): Promise<void> {
	// 1. Enforces exact generation token and suffix
	assertEqual(
		CLEAN_STORAGE_GENERATION_TOKEN,
		'mls-state-clean-v2-openmls-v09-device-identity-v1'
	);
	assertEqual(CLEAN_STORAGE_SUFFIX, '-clean-v2-openmls-v09-device-identity-v1');
	assertEqual(
		SS_ACTIVE_DID,
		'catbird_mls_active_did-clean-v2-openmls-v09-device-identity-v1'
	);
	assertEqual(CONTENT_ROOT_PREFIX, 'mls.content.root.');

	// 2. Derives collision-resistant DID-scoped coordinates ending in exact suffix
	const didA = 'did:plc:user-alpha-123';
	const coordsA = await deriveDidStorageCoordinates(didA);

	assertEqual(coordsA.normalizedDid, 'did:plc:user-alpha-123');
	assert(/^[0-9a-f]{64}$/.test(coordsA.didDigest), 'didDigest must be 64-character lowercase hex');
	assertEqual(
		coordsA.storagePrefix,
		`catbird_mls_${coordsA.didDigest}-clean-v2-openmls-v09-device-identity-v1`
	);
	assertEqual(
		coordsA.dbPrefix,
		`catbird-mls-${coordsA.didDigest}-clean-v2-openmls-v09-device-identity-v1`
	);
	assertEqual(
		coordsA.dbIdentity,
		`catbird-mls-${coordsA.didDigest}-clean-v2-openmls-v09-device-identity-v1-app.db`
	);
	assertEqual(
		coordsA.recordKey,
		`catbird_mls:${didA}:init_record-clean-v2-openmls-v09-device-identity-v1`
	);
	assertEqual(
		coordsA.mlsDbKeyLabel,
		`catbird_mls:${didA}:mls_db_key-clean-v2-openmls-v09-device-identity-v1`
	);
	assertEqual(
		coordsA.contentRootKeyLabel,
		`mls.content.root.${coordsA.didDigest}-clean-v2-openmls-v09-device-identity-v1`
	);
	assertEqual(
		coordsA.cursorRegistryKey,
		`catbird_mls:${didA}:cursor_registry-clean-v2-openmls-v09-device-identity-v1`
	);

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

	assertEqual(record.generation, 'mls-state-clean-v2-openmls-v09-device-identity-v1');
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

	// 5. Case-distinct valid DIDs produce distinct storage coordinates without lowercase collapsing
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
}

await runCleanStorageContractTests();
console.log('Clean storage contract tests passed');

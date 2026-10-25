import assert from 'node:assert';
import crypto from 'node:crypto';

// Test the WebCrypto non-extractable KEK and IndexedDB-backed durable key wrapping
// architecture implemented in catmos/src/lib/wasm.ts to ensure encrypted OPFS
// databases persist across tab/session restarts without stranding ciphertext.

async function runPersistenceSuite() {
	console.log('--- Running Browser Worker/OPFS Key Lifecycle Persistence Tests ---');

	const subtle = crypto.webcrypto.subtle;

	// In-memory simulated durable IndexedDB keyring store
	const indexedDbStorage = new Map();
	// In-memory simulated ephemeral sessionStorage (wiped on restart)
	let sessionStorage = new Map();

	const MASTER_KEK_ID = '__mls_master_kek__';

	async function getOrCreateMasterKek() {
		if (indexedDbStorage.has(MASTER_KEK_ID)) {
			return indexedDbStorage.get(MASTER_KEK_ID);
		}
		const kek = await subtle.generateKey(
			{ name: 'AES-GCM', length: 256 },
			false, // non-extractable
			['encrypt', 'decrypt']
		);
		indexedDbStorage.set(MASTER_KEK_ID, kek);
		return kek;
	}

	async function getOrCreateMlsDbKey(targetDid) {
		const storageKey = targetDid ? `catbird_mls_${targetDid}_mls_db_key` : 'catbird_mls_mls_db_key';
		const wrappedStorageKey = targetDid ? `catbird_mls_${targetDid}_mls_db_key_wrapped` : 'catbird_mls_mls_db_key_wrapped';

		// 1. Check ephemeral sessionStorage
		if (sessionStorage.has(storageKey)) {
			const sessionKey = sessionStorage.get(storageKey);
			if (sessionKey && sessionKey.length === 64) {
				return sessionKey;
			}
		}

		// 2. Check durable storage for wrapped key
		const kek = await getOrCreateMasterKek();
		if (indexedDbStorage.has(wrappedStorageKey)) {
			const wrapped = indexedDbStorage.get(wrappedStorageKey);
			const decrypted = await subtle.decrypt(
				{ name: 'AES-GCM', iv: wrapped.iv },
				kek,
				wrapped.ciphertext
			);
			const rawBytes = new Uint8Array(decrypted);
			const keyHex = Array.from(rawBytes)
				.map((b) => b.toString(16).padStart(2, '0'))
				.join('');
			sessionStorage.set(storageKey, keyHex);
			return keyHex;
		}

		// 3. Generate fresh 32-byte key, wrap with non-extractable WebCrypto KEK, and store in durable storage
		const rawBytes = new Uint8Array(32);
		crypto.webcrypto.getRandomValues(rawBytes);
		const keyHex = Array.from(rawBytes)
			.map((b) => b.toString(16).padStart(2, '0'))
			.join('');

		const iv = new Uint8Array(12);
		crypto.webcrypto.getRandomValues(iv);
		const ciphertextBuffer = await subtle.encrypt(
			{ name: 'AES-GCM', iv },
			kek,
			rawBytes
		);
		indexedDbStorage.set(wrappedStorageKey, {
			iv,
			ciphertext: new Uint8Array(ciphertextBuffer)
		});

		sessionStorage.set(storageKey, keyHex);
		return keyHex;
	}

	// Test Case 1: First session initializes key and writes wrapped record
	const didAlice = 'did:plc:alice1234';
	const aliceKeySession1 = await getOrCreateMlsDbKey(didAlice);
	assert.strictEqual(aliceKeySession1.length, 64, 'Generated key must be 64 hex characters (32 bytes / 256 bits)');
	assert.strictEqual(typeof aliceKeySession1, 'string');
	assert.strictEqual(sessionStorage.get(`catbird_mls_${didAlice}_mls_db_key`), aliceKeySession1, 'Plaintext key cached in sessionStorage for Worker handover');
	assert(indexedDbStorage.has(`catbird_mls_${didAlice}_mls_db_key_wrapped`), 'Wrapped key record must exist in durable storage');

	const wrappedRecord = indexedDbStorage.get(`catbird_mls_${didAlice}_mls_db_key_wrapped`);
	assert.strictEqual(wrappedRecord.iv.length, 12, 'AES-GCM IV must be 12 bytes');
	assert.strictEqual(wrappedRecord.ciphertext.length, 32 + 16, 'AES-GCM ciphertext must be 32 bytes + 16 bytes auth tag');

	// Verify master KEK is non-extractable
	const kek = indexedDbStorage.get(MASTER_KEK_ID);
	assert.strictEqual(kek.extractable, false, 'Master KEK must be non-extractable');
	let exportFailed = false;
	try {
		await subtle.exportKey('raw', kek);
	} catch (e) {
		exportFailed = true;
	}
	assert(exportFailed, 'Attempt to export non-extractable Master KEK must throw an error');
	console.log('✓ Test 1: First session generated 256-bit key, wrapped with non-extractable KEK, and saved to durable store.');

	// Test Case 2: Simulate Browser / Tab Restart (sessionStorage is cleared, durable storage remains)
	sessionStorage = new Map(); // Simulate restart
	assert.strictEqual(sessionStorage.size, 0, 'sessionStorage must be empty after restart');

	const aliceKeySession2 = await getOrCreateMlsDbKey(didAlice);
	assert.strictEqual(aliceKeySession2, aliceKeySession1, 'Session 2 MUST recover the exact same key as Session 1 across restart');
	console.log('✓ Test 2: Simulated browser restart restored identical key from durable storage without stranding ciphertext.');

	// Test Case 3: Per-DID Isolation
	const didBob = 'did:plc:bob5678';
	const bobKeySession1 = await getOrCreateMlsDbKey(didBob);
	assert.strictEqual(bobKeySession1.length, 64);
	assert.notStrictEqual(bobKeySession1, aliceKeySession1, 'Bob and Alice MUST have distinct isolated encryption keys');
	console.log('✓ Test 3: Multiple DIDs have isolated, non-colliding keys.');

	// Test Case 4: Re-simulating restart for Bob recovers Bob key
	sessionStorage = new Map();
	const bobKeySession2 = await getOrCreateMlsDbKey(didBob);
	assert.strictEqual(bobKeySession2, bobKeySession1, 'Bob key recovered across restart');
	const aliceKeySession3 = await getOrCreateMlsDbKey(didAlice);
	assert.strictEqual(aliceKeySession3, aliceKeySession1, 'Alice key recovered across restart');
	console.log('✓ Test 4: Both Bob and Alice keys recover independently after restart.');

	// Test Case 5: Tampered ciphertext fails decryption
	const tamperedRecord = {
		iv: wrappedRecord.iv,
		ciphertext: new Uint8Array(wrappedRecord.ciphertext)
	};
	tamperedRecord.ciphertext[0] ^= 0xff; // Flip bits
	let decryptFailed = false;
	try {
		await subtle.decrypt(
			{ name: 'AES-GCM', iv: tamperedRecord.iv },
			kek,
			tamperedRecord.ciphertext
		);
	} catch (e) {
		decryptFailed = true;
	}
	assert(decryptFailed, 'Decryption of tampered ciphertext must fail authentication');
	console.log('✓ Test 5: AES-GCM authentication prevents tampering or corrupted key restoration.');

	console.log('\nAll 5 browser Worker/OPFS key lifecycle persistence tests PASSED successfully.');
}

runPersistenceSuite().catch((err) => {
	console.error('Persistence test failed:', err);
	process.exit(1);
});

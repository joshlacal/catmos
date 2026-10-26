import assert from 'node:assert';
import crypto from 'node:crypto';

if (!globalThis.crypto) {
	globalThis.crypto = crypto.webcrypto;
}

// ---------------------------------------------------------------------------
// Spec-accurate IndexedDB + WebStorage + Web Locks test harness for Node.js
// Exercises the ACTUAL production functions imported from ../src/lib/wasm.ts
// and ../src/lib/stores/tab-lock.ts (not reimplemented copies).
// ---------------------------------------------------------------------------

class MemoryStorage {
	#map = new Map();
	getItem(k) {
		return this.#map.has(k) ? this.#map.get(k) : null;
	}
	setItem(k, v) {
		this.#map.set(String(k), String(v));
	}
	removeItem(k) {
		this.#map.delete(String(k));
	}
	clear() {
		this.#map.clear();
	}
	get size() {
		return this.#map.size;
	}
}

function createIndexedDbHarness() {
	/** @type {Map<string, Map<string, Map<string, any>>>} */
	const databases = new Map();
	/** @type {Promise<void>} */
	let writeQueue = Promise.resolve();
	let abortNextWriteAfterReqSuccess = false;
	let failOpen = false;

	function makeRequest() {
		return {
			result: undefined,
			error: null,
			onsuccess: null,
			onerror: null
		};
	}

	const indexedDB = {
		open(dbName, _version) {
			const req = {
				result: undefined,
				error: null,
				onupgradeneeded: null,
				onsuccess: null,
				onerror: null,
				onblocked: null
			};

			queueMicrotask(() => {
				if (failOpen) {
					req.error = new Error('Simulated IndexedDB open failure');
					req.onerror?.();
					return;
				}

				let isNew = false;
				if (!databases.has(dbName)) {
					databases.set(dbName, new Map());
					isNew = true;
				}
				const stores = databases.get(dbName);

				const db = {
					objectStoreNames: {
						contains(name) {
							return stores.has(name);
						}
					},
					createObjectStore(name) {
						if (!stores.has(name)) {
							stores.set(name, new Map());
						}
						return {};
					},
					close() {},
					transaction(storeName, mode = 'readonly') {
						if (!stores.has(storeName)) {
							throw new Error(`Object store ${storeName} not found`);
						}
						const backingStore = stores.get(storeName);
						const tx = {
							mode,
							error: null,
							oncomplete: null,
							onabort: null,
							onerror: null,
							objectStore(_name) {
								return storeApi;
							}
						};

						/** @type {Array<() => void>} */
						const ops = [];
						let scheduled = false;

						function scheduleTx() {
							if (scheduled) return;
							scheduled = true;

							const runTx = async () => {
								// Allow synchronous request setup inside the caller before running ops
								await new Promise((r) => queueMicrotask(r));
								const stagedWrites = new Map();
								let aborted = false;
								let shouldAbortAfterSuccess =
									mode === 'readwrite' && abortNextWriteAfterReqSuccess;
								if (shouldAbortAfterSuccess) {
									abortNextWriteAfterReqSuccess = false;
								}

								for (let i = 0; i < ops.length; i++) {
									ops[i]({
										backingStore,
										stagedWrites,
										abort(err) {
											aborted = true;
											tx.error = err;
										}
									});
									await new Promise((r) => queueMicrotask(r));
									if (aborted) break;
								}

								if (aborted) {
									tx.onabort?.();
									return;
								}

								if (shouldAbortAfterSuccess) {
									tx.error = new Error('Simulated QuotaExceededError on transaction commit');
									tx.onabort?.();
									return;
								}

								for (const [k, v] of stagedWrites.entries()) {
									backingStore.set(k, v);
								}
								tx.oncomplete?.();
							};

							if (mode === 'readwrite') {
								writeQueue = writeQueue.then(runTx, runTx);
							} else {
								void runTx();
							}
						}

						const storeApi = {
							get(key) {
								const r = makeRequest();
								ops.push(({ backingStore: bs, stagedWrites }) => {
									r.result = stagedWrites.has(key) ? stagedWrites.get(key) : bs.get(key);
									r.onsuccess?.();
								});
								scheduleTx();
								return r;
							},
							put(value, key) {
								const r = makeRequest();
								ops.push(({ stagedWrites }) => {
									stagedWrites.set(key, value);
									r.result = key;
									r.onsuccess?.();
								});
								scheduleTx();
								return r;
							},
							add(value, key) {
								const r = makeRequest();
								ops.push(({ backingStore: bs, stagedWrites, abort }) => {
									const exists = stagedWrites.has(key) || bs.has(key);
									if (exists) {
										const err = new Error(`ConstraintError: Key already exists: ${key}`);
										r.error = err;
										r.onerror?.();
										abort(err);
										return;
									}
									stagedWrites.set(key, value);
									r.result = key;
									r.onsuccess?.();
								});
								scheduleTx();
								return r;
							}
						};

						return tx;
					}
				};

				req.result = db;
				if (isNew) {
					req.onupgradeneeded?.();
				}
				req.onsuccess?.();
			});

			return req;
		}
	};

	return {
		indexedDB,
		databases,
		getRawStore(dbName, storeName) {
			return databases.get(dbName)?.get(storeName);
		},
		setAbortNextWriteAfterReqSuccess(v) {
			abortNextWriteAfterReqSuccess = v;
		},
		setFailOpen(v) {
			failOpen = v;
		}
	};
}

function createWebLocksHarness() {
	/** @type {Map<string, Promise<void>>} */
	const heldLocks = new Map();

	return {
		async request(name, optionsOrCallback, maybeCallback) {
			const options = typeof optionsOrCallback === 'function' ? {} : optionsOrCallback;
			const callback =
				typeof optionsOrCallback === 'function' ? optionsOrCallback : maybeCallback;

			if (options.ifAvailable) {
				if (heldLocks.has(name)) {
					return callback(null);
				}
				let release;
				const held = new Promise((r) => {
					release = r;
				});
				heldLocks.set(name, held);
				try {
					return await callback({ name, mode: 'exclusive' });
				} finally {
					heldLocks.delete(name);
					release();
				}
			}

			while (heldLocks.has(name) && !options.steal) {
				await heldLocks.get(name);
			}
			let release;
			const held = new Promise((r) => {
				release = r;
			});
			heldLocks.set(name, held);
			try {
				return await callback({ name, mode: 'exclusive' });
			} finally {
				if (heldLocks.get(name) === held) {
					heldLocks.delete(name);
				}
				release();
			}
		}
	};
}

async function runSuite() {
	console.log('--- Running Production Browser Worker/OPFS Key & Lifecycle Verification ---');

	const idbHarness = createIndexedDbHarness();
	globalThis.indexedDB = idbHarness.indexedDB;
	globalThis.sessionStorage = new MemoryStorage();
	globalThis.localStorage = new MemoryStorage();

	const wasm = await import('../src/lib/wasm.ts');
	const { acquireTabLock } = await import('../src/lib/stores/tab-lock.ts');

	const didAlice = 'did:plc:alice1234';
	const didBob = 'did:plc:bob5678';

	// -----------------------------------------------------------------------
	// Test 1: F9 — idbPut & idbPutIfAbsent wait for tx.oncomplete and reject on tx.onabort
	// -----------------------------------------------------------------------
	{
		const db = await wasm.openKeyringDb();
		let putResolvedBeforeComplete = true;
		idbHarness.setAbortNextWriteAfterReqSuccess(true);
		await assert.rejects(
			async () => {
				await wasm.idbPut(db, 'test_abort_key', { hello: 'world' });
				putResolvedBeforeComplete = false;
			},
			/Simulated QuotaExceededError|aborted/,
			'idbPut must reject when transaction aborts after req.onsuccess'
		);
		assert.strictEqual(putResolvedBeforeComplete, true);
		assert.strictEqual(
			await wasm.idbGet(db, 'test_abort_key'),
			undefined,
			'Aborted transaction must not commit key'
		);

		idbHarness.setAbortNextWriteAfterReqSuccess(true);
		await assert.rejects(
			async () => {
				await wasm.idbPutIfAbsent(db, 'test_abort_atomic_key', { hello: 'atomic' });
			},
			/Simulated QuotaExceededError|aborted/,
			'idbPutIfAbsent must reject when transaction aborts after req.onsuccess'
		);
		db.close();
		console.log('✓ Test 1 (F9): idbPut and idbPutIfAbsent resolve only on tx.oncomplete and reject on tx.onabort.');
	}

	// -----------------------------------------------------------------------
	// Test 2: F6 — Concurrent two-tab initialization does not overwrite MASTER_KEK_ID or per-DID key
	// -----------------------------------------------------------------------
	{
		// First test direct IndexedDB transaction concurrency WITHOUT navigator.locks
		// so both callers race directly into idbPutIfAbsent.
		delete globalThis.navigator;
		const [tab1Key, tab2Key] = await Promise.all([
			wasm.getOrCreateMlsDbKey(didAlice),
			wasm.getOrCreateMlsDbKey(didAlice)
		]);
		assert.strictEqual(tab1Key.length, 64, 'Generated key must be 64 hex chars');
		assert.strictEqual(
			tab1Key,
			tab2Key,
			'Concurrent tabs racing on empty keyring must converge on the exact same MLS DB key'
		);

		const store = idbHarness.getRawStore(wasm.KEYRING_DB_NAME, wasm.KEYRING_STORE_NAME);
		const kekAfterRace = store.get(wasm.MASTER_KEK_ID);
		const wrappedAfterRace = store.get(wasm.mlsKeyIdForDid(didAlice));
		assert(kekAfterRace, 'Master KEK must be durably stored');
		assert.strictEqual(kekAfterRace.extractable, false, 'Master KEK must be non-extractable');
		assert(wrappedAfterRace, 'Wrapped per-DID key must be durably stored under mls_db_key_<sanitized_did>');

		// Now enable Web Locks and verify concurrent calls with navigator.locks also preserve the exact key
		globalThis.navigator = { locks: createWebLocksHarness() };
		globalThis.sessionStorage.clear();
		const [lockedTab1Key, lockedTab2Key] = await Promise.all([
			wasm.getOrCreateMlsDbKey(didAlice),
			wasm.getOrCreateMlsDbKey(didAlice)
		]);
		assert.strictEqual(lockedTab1Key, tab1Key, 'Reopened tabs must unwrap the original durable key');
		assert.strictEqual(lockedTab2Key, tab1Key, 'Second locked tab must unwrap the original durable key');
		assert.strictEqual(
			store.get(wasm.MASTER_KEK_ID),
			kekAfterRace,
			'Master KEK must never be overwritten by subsequent tabs'
		);
		console.log('✓ Test 2 (F6): Concurrent two-tab initialization atomically preserves MASTER_KEK_ID and per-DID wrapped key.');
	}

	// -----------------------------------------------------------------------
	// Test 3: F8 — Tampered ciphertext, corrupt record, or IDB failure fails closed (no temporary key fallback)
	// -----------------------------------------------------------------------
	{
		const store = idbHarness.getRawStore(wasm.KEYRING_DB_NAME, wasm.KEYRING_STORE_NAME);
		const keyId = wasm.mlsKeyIdForDid(didAlice);
		const originalRecord = store.get(keyId);

		// Tamper with ciphertext even while sessionStorage still has the valid cached key
		const tamperedCiphertext = new Uint8Array(originalRecord.ciphertext);
		tamperedCiphertext[0] ^= 0xff;
		store.set(keyId, {
			iv: new Uint8Array(originalRecord.iv),
			ciphertext: tamperedCiphertext
		});

		await assert.rejects(
			() => wasm.getOrCreateMlsDbKey(didAlice),
			/AES-GCM authentication failed/,
			'Tampered ciphertext must reject and never return a cached or temporary session key'
		);

		// Corrupt record shape
		store.set(keyId, { iv: new Uint8Array(4), ciphertext: new Uint8Array(10) });
		await assert.rejects(
			() => wasm.getOrCreateMlsDbKey(didAlice),
			/Corrupt wrapped key record/,
			'Corrupt wrapped key record shape must reject'
		);

		// Restore valid record and test IndexedDB open failure
		store.set(keyId, originalRecord);
		idbHarness.setFailOpen(true);
		await assert.rejects(
			() => wasm.getOrCreateMlsDbKey(didAlice),
			/Simulated IndexedDB open failure/,
			'IndexedDB failure must reject and never generate an unretained random session key'
		);
		idbHarness.setFailOpen(false);
		console.log('✓ Test 3 (F8): Tampered ciphertext, corrupt records, and IDB errors fail closed without generating temporary keys.');
	}

	// -----------------------------------------------------------------------
	// Test 4: F5 — Tab lock gating & OPFS sahpool init failure fail-closed behavior
	// -----------------------------------------------------------------------
	{
		globalThis.navigator = { locks: createWebLocksHarness() };
		const statusesTab1 = [];
		const statusesTab2 = [];

		const lock1 = acquireTabLock((s) => statusesTab1.push(s));
		const status1 = await lock1.ready;
		assert.strictEqual(status1, 'granted', 'First tab must acquire the exclusive tab lock');

		const lock2 = acquireTabLock((s) => statusesTab2.push(s));
		const status2 = await lock2.ready;
		assert.strictEqual(status2, 'blocked', 'Second concurrent tab must be blocked before WASM init');

		// Unauthenticated initWasm() without DID must fail closed
		globalThis.sessionStorage.clear();
		await assert.rejects(
			() => wasm.initWasm(),
			/requires a non-empty authenticated DID/,
			'Unauthenticated initWasm() must reject instead of opening generic catbird-mls-app.db'
		);

		// Simulate OPFS sahpool failure inside Worker.init
		wasm.__setWorkerFactoryForTests(() => ({
			worker: /** @type {any} */ ({
				async init() {
					throw new Error(
						'OPFS sahpool initialization failed (persistent storage unavailable or locked by another tab)'
					);
				}
			}),
			rawWorker: { terminate() {} }
		}));

		await assert.rejects(
			() => wasm.initWasm(didAlice),
			/OPFS sahpool initialization failed/,
			'OPFS sahpool failure must reject initWasm and never fall back to volatile memvfs'
		);
		assert.strictEqual(
			wasm.__getWorkerStateForTests().hasWorker,
			false,
			'Failed initWasm must terminate Worker and reset readiness state'
		);
		console.log('✓ Test 4 (F5): Tab lock blocks second tab, unauthenticated initWasm rejects, and OPFS sahpool failure fails closed.');
	}

	// -----------------------------------------------------------------------
	// Test 5: F7 — Login -> Reload -> Logout -> Re-login -> Account Switch
	// Verifies identical DB filename (catbird_mls_<sanitized_did>-app.db),
	// identical key ID (mls_db_key_<sanitized_did>), and persistent OPFS data survival.
	// -----------------------------------------------------------------------
	{
		globalThis.sessionStorage.clear();
		globalThis.localStorage.clear();

		/** Simulated OPFS persistent encrypted SQLite store keyed by dbFileName */
		const opfsDatabases = new Map();
		/** @type {Array<{ dbFileName: string; mlsDbKey: string; did: string | null }>} */
		const workerInitLog = [];
		let activeSessionDid = didAlice;
		let workerTerminatedCount = 0;

		globalThis.fetch = async (url, init) => {
			const urlStr = String(url);
			if (urlStr.endsWith('/auth/session')) {
				const authHeader = new Headers(init?.headers).get('Authorization');
				if (!authHeader || !authHeader.startsWith('Bearer ')) {
					return new Response('Unauthorized', { status: 401 });
				}
				return new Response(
					JSON.stringify({
						did: activeSessionDid,
						handle: activeSessionDid === didAlice ? 'alice.bsky.social' : 'bob.bsky.social'
					}),
					{ status: 200, headers: { 'Content-Type': 'application/json' } }
				);
			}
			return new Response('{}', { status: 200 });
		};

		wasm.__setWorkerFactoryForTests(() => {
			let currentDbFile = null;
			let currentDbKey = null;
			let currentDid = null;

			return {
				worker: /** @type {any} */ ({
					async init(cfg) {
						currentDbFile = `${cfg.dbPrefix}-app.db`;
						currentDbKey = cfg.mlsDbKey;
						if (!opfsDatabases.has(currentDbFile)) {
							opfsDatabases.set(currentDbFile, {
								key: currentDbKey,
								credentials: null,
								groups: []
							});
						} else {
							const existingDb = opfsDatabases.get(currentDbFile);
							assert.strictEqual(
								existingDb.key,
								currentDbKey,
								`Reopened OPFS DB ${currentDbFile} must receive the exact same encryption key`
							);
						}
						workerInitLog.push({
							dbFileName: currentDbFile,
							mlsDbKey: currentDbKey,
							did: currentDid
						});
					},
					async setAuth(did, _token) {
						currentDid = did;
						const expectedDbFile = wasm.mlsDbFileNameForDid(did);
						assert.strictEqual(
							currentDbFile,
							expectedDbFile,
							`setAuth(${did}) must run against ${expectedDbFile}, got ${currentDbFile}`
						);
					},
					async setContentRootKey(_key) {},
					async clearContentRootKey() {},
					async clearAuth() {
						currentDid = null;
					},
					async setup() {
						const db = opfsDatabases.get(currentDbFile);
						assert(db, 'OPFS DB must be initialized before setup()');
						if (!db.credentials) {
							db.credentials = `cred:${currentDid}`;
							db.groups.push(`group:welcome:${currentDid}`);
						}
					},
					async replenishKeyPackages() {}
				}),
				rawWorker: {
					terminate() {
						workerTerminatedCount += 1;
					}
				}
			};
		});

		const expectedAliceDb = 'catbird_mls_did_plc_alice1234-app.db';
		const expectedAliceKeyId = 'mls_db_key_did_plc_alice1234';
		assert.strictEqual(wasm.mlsDbFileNameForDid(didAlice), expectedAliceDb);
		assert.strictEqual(wasm.mlsKeyIdForDid(didAlice), expectedAliceKeyId);

		// Step A: First login on fresh browser tab (no prior sessionStorage)
		const loginUser = await wasm.completeLogin('session-alice-1');
		assert.strictEqual(loginUser.did, didAlice);
		assert.strictEqual(workerInitLog.length, 1);
		assert.strictEqual(workerInitLog[0].dbFileName, expectedAliceDb);
		const aliceKey1 = workerInitLog[0].mlsDbKey;
		assert.strictEqual(globalThis.sessionStorage.getItem(expectedAliceKeyId), aliceKey1);
		assert.deepStrictEqual(opfsDatabases.get(expectedAliceDb).groups, [`group:welcome:${didAlice}`]);

		// Step B: Simulate page reload (Worker is recreated, sessionStorage retains active auth)
		await wasm.logout(); // terminate worker to simulate page unload, then restore sessionStorage
		wasm.persistBrowserAuth(didAlice, 'session-alice-1');
		// Simulate +layout.svelte on reload: savedAuth.did is present -> initWasm(savedAuth.did) -> tryRestoreSession()
		await wasm.initWasm(didAlice);
		const restoredUser = await wasm.tryRestoreSession();
		assert.strictEqual(restoredUser?.did, didAlice);
		assert.strictEqual(workerInitLog.length, 2, 'initWasm + tryRestoreSession on reload must initialize Worker once for Alice');
		assert.strictEqual(workerInitLog[1].dbFileName, expectedAliceDb);
		assert.strictEqual(workerInitLog[1].mlsDbKey, aliceKey1);
		assert.strictEqual(
			opfsDatabases.get(expectedAliceDb).credentials,
			`cred:${didAlice}`,
			'Credentials written on first login must survive reload in the same DB'
		);

		// Step C: Logout -> Worker terminated and sessionStorage cleared
		const termBeforeLogout = workerTerminatedCount;
		await wasm.logout();
		assert.strictEqual(workerTerminatedCount, termBeforeLogout + 1, 'logout() must terminate active Worker');
		assert.strictEqual(wasm.readBrowserAuth(), null, 'logout() must clear browser auth');
		assert.strictEqual(wasm.__getWorkerStateForTests().hasWorker, false);

		// Step D: Re-login as Alice -> opens identical DB and key
		const reloginUser = await wasm.completeLogin('session-alice-2');
		assert.strictEqual(reloginUser.did, didAlice);
		assert.strictEqual(workerInitLog.length, 3);
		assert.strictEqual(workerInitLog[2].dbFileName, expectedAliceDb);
		assert.strictEqual(workerInitLog[2].mlsDbKey, aliceKey1);
		assert.deepStrictEqual(
			opfsDatabases.get(expectedAliceDb).groups,
			[`group:welcome:${didAlice}`],
			'Group history must survive logout and re-login'
		);

		// Step E: Login as Bob while Alice Worker was active -> terminates Alice Worker and opens Bob DB
		activeSessionDid = didBob;
		const expectedBobDb = 'catbird_mls_did_plc_bob5678-app.db';
		const bobUser = await wasm.completeLogin('session-bob-1');
		assert.strictEqual(bobUser.did, didBob);
		assert.strictEqual(workerInitLog.length, 4);
		assert.strictEqual(workerInitLog[3].dbFileName, expectedBobDb);
		assert.notStrictEqual(workerInitLog[3].mlsDbKey, aliceKey1, 'Bob must use an isolated per-DID key');
		assert(
			!opfsDatabases.has('catbird-mls-app.db'),
			'Generic un-namespaced catbird-mls-app.db must NEVER be opened'
		);

		await wasm.logout();
		wasm.__setWorkerFactoryForTests(null);
		console.log('✓ Test 5 (F7): First login, reload, logout/re-login, and account switch all use catbird_mls_<DID>-app.db and mls_db_key_<DID>.');
	}

	console.log('\nAll 5 production browser Worker/OPFS key & lifecycle verification suites PASSED.');
}

runSuite().catch((err) => {
	console.error('Verification suite failed:', err);
	process.exit(1);
});

/**
 * Browser WebCrypto + IndexedDB key custody (`Spec §6.5`, `Gate 9`, `modern-web-guidance: client-side-encryption`).
 *
 * - Generates a 256-bit non-extractable `AES-GCM` `CryptoKey` (`extractable: false`)
 *   and persists the `CryptoKey` handle in `IndexedDB` via structured cloning.
 * - Wraps the 32-byte `sqlite3mc` DB key (and 32-byte content-root key) with a
 *   fresh 12-byte random IV (`crypto.getRandomValues(new Uint8Array(12))`) and
 *   domain-separated `additionalData` (`"catbird-mls-db-key:" + didHash`).
 * - Proactively purges any legacy `mls_db_key` / `content_root_key` / `mls.content.root.`
 *   entries from `sessionStorage` and `localStorage` so zero raw keys reside in DOM storage.
 */

export const WEBCRYPTO_DB_NAME = 'catbird_mls_webcrypto_v2';
export const WEBCRYPTO_STORE_NAME = 'keystore';

export interface WrappedSecretEnvelope {
	iv: Uint8Array;
	ciphertext: Uint8Array;
}

/**
 * Ephemeral in-memory object store used ONLY in headless Node unit tests where
 * `globalThis.indexedDB` is undefined. Never touches `localStorage` or `sessionStorage`,
 * and stores the exact same non-extractable `CryptoKey` objects.
 */
const memoryKeyStoreFallback = new Map<string, unknown>();

export function resetKeyStoreMemoryFallbackForTests(): void {
	memoryKeyStoreFallback.clear();
}

function purgeLegacyWebStorageKeys(): void {
	const scrub = (storage: Storage | undefined) => {
		if (!storage) return;
		const keysToRemove: string[] = [];
		for (let i = 0; i < storage.length; i++) {
			const key = storage.key(i);
			if (
				key &&
				(/mls_db_key/i.test(key) ||
					/content_root_key/i.test(key) ||
					key.startsWith('mls.content.root.'))
			) {
				keysToRemove.push(key);
			}
		}
		for (const key of keysToRemove) {
			storage.removeItem(key);
		}
	};

	if (typeof sessionStorage !== 'undefined') scrub(sessionStorage);
	if (typeof localStorage !== 'undefined') scrub(localStorage);
}

function openKeyStoreDb(): Promise<IDBDatabase | null> {
	if (typeof indexedDB === 'undefined') {
		return Promise.resolve(null);
	}
	return new Promise((resolve, reject) => {
		const req = indexedDB.open(WEBCRYPTO_DB_NAME, 1);
		req.onupgradeneeded = () => {
			const db = req.result;
			if (!db.objectStoreNames.contains(WEBCRYPTO_STORE_NAME)) {
				db.createObjectStore(WEBCRYPTO_STORE_NAME);
			}
		};
		req.onsuccess = () => resolve(req.result);
		req.onerror = () => reject(req.error ?? new Error('Failed to open WebCrypto IndexedDB'));
		req.onblocked = () => reject(new Error('WebCrypto IndexedDB open blocked'));
	});
}

async function storeGet<T>(key: string): Promise<T | undefined> {
	const db = await openKeyStoreDb();
	if (!db) {
		return memoryKeyStoreFallback.get(key) as T | undefined;
	}
	try {
		return await new Promise<T | undefined>((resolve, reject) => {
			const tx = db.transaction(WEBCRYPTO_STORE_NAME, 'readonly');
			const req = tx.objectStore(WEBCRYPTO_STORE_NAME).get(key);
			let val: T | undefined;
			req.onsuccess = () => {
				val = req.result as T | undefined;
			};
			req.onerror = () => reject(req.error ?? new Error(`IndexedDB get failed: ${key}`));
			tx.onabort = () => reject(tx.error ?? new Error(`IndexedDB get aborted: ${key}`));
			tx.oncomplete = () => resolve(val);
		});
	} finally {
		db.close();
	}
}

async function storePutIfAbsent<T>(key: string, candidate: T): Promise<T> {
	const db = await openKeyStoreDb();
	if (!db) {
		if (!memoryKeyStoreFallback.has(key)) {
			memoryKeyStoreFallback.set(key, candidate);
		}
		return memoryKeyStoreFallback.get(key) as T;
	}
	try {
		await new Promise<void>((resolve, reject) => {
			const tx = db.transaction(WEBCRYPTO_STORE_NAME, 'readwrite');
			const store = tx.objectStore(WEBCRYPTO_STORE_NAME);
			const getReq = store.get(key);
			getReq.onsuccess = () => {
				if (getReq.result === undefined) {
					store.add(candidate, key);
				}
			};
			getReq.onerror = () => reject(getReq.error ?? new Error(`IndexedDB inspect failed: ${key}`));
			tx.onabort = () => reject(tx.error ?? new Error(`IndexedDB write aborted: ${key}`));
			tx.oncomplete = () => resolve();
		});
		const committed = await storeGet<T>(key);
		if (committed === undefined) {
			throw new Error(`IndexedDB readback returned undefined for ${key}`);
		}
		return committed;
	} finally {
		db.close();
	}
}

export async function deleteAccountKeyStoreEntries(didHash: string): Promise<void> {
	purgeLegacyWebStorageKeys();
	const normalized = didHash.trim();
	if (!normalized) return;
	const keys = [
		`kek:${normalized}`,
		`wrapped:db:${normalized}`,
		`wrapped:content:${normalized}`
	];
	const db = await openKeyStoreDb();
	if (!db) {
		for (const k of keys) memoryKeyStoreFallback.delete(k);
		return;
	}
	try {
		await new Promise<void>((resolve, reject) => {
			const tx = db.transaction(WEBCRYPTO_STORE_NAME, 'readwrite');
			const store = tx.objectStore(WEBCRYPTO_STORE_NAME);
			for (const k of keys) store.delete(k);
			tx.onabort = () => reject(tx.error ?? new Error('IndexedDB delete aborted'));
			tx.oncomplete = () => resolve();
		});
	} finally {
		db.close();
	}
}

function isNonExtractableAesGcmKey(val: unknown): val is CryptoKey {
	if (typeof val !== 'object' || val === null) return false;
	const k = val as CryptoKey;
	return (
		k.extractable === false &&
		typeof k.algorithm === 'object' &&
		k.algorithm !== null &&
		k.algorithm.name === 'AES-GCM'
	);
}

async function getOrCreateAccountWrappingKey(didHash: string): Promise<CryptoKey> {
	const kekId = `kek:${didHash}`;
	const existing = await storeGet<unknown>(kekId);
	if (existing !== undefined) {
		if (!isNonExtractableAesGcmKey(existing)) {
			throw new Error(`Corrupt or extractable CryptoKey stored at ${kekId}`);
		}
		return existing;
	}

	const freshKek = await crypto.subtle.generateKey(
		{ name: 'AES-GCM', length: 256 },
		false,
		['encrypt', 'decrypt']
	);
	const committed = await storePutIfAbsent<CryptoKey>(kekId, freshKek);
	if (!isNonExtractableAesGcmKey(committed)) {
		throw new Error(`Committed CryptoKey at ${kekId} failed non-extractable validation`);
	}
	return committed;
}

export async function inspectWrappingCryptoKey(didHash: string): Promise<CryptoKey | undefined> {
	return storeGet<CryptoKey>(`kek:${didHash.trim()}`);
}

export async function loadOrCreateWrappedSecretBytes(
	didHash: string,
	purpose: 'db' | 'content'
): Promise<Uint8Array> {
	purgeLegacyWebStorageKeys();
	const normalized = didHash.trim();
	if (!normalized) {
		throw new Error('didHash must not be empty');
	}

	const kek = await getOrCreateAccountWrappingKey(normalized);
	const recordId = `wrapped:${purpose}:${normalized}`;
	const aad = new TextEncoder().encode(`catbird-mls-${purpose}-key:${normalized}`);

	let wrapped = await storeGet<WrappedSecretEnvelope>(recordId);
	if (!wrapped) {
		const rawSecret = crypto.getRandomValues(new Uint8Array(32));
		const iv = crypto.getRandomValues(new Uint8Array(12));
		const ctBuf = await crypto.subtle.encrypt(
			{
				name: 'AES-GCM',
				iv: iv as BufferSource,
				additionalData: aad as BufferSource
			},
			kek,
			rawSecret as BufferSource
		);
		wrapped = await storePutIfAbsent<WrappedSecretEnvelope>(recordId, {
			iv,
			ciphertext: new Uint8Array(ctBuf)
		});
	}

	if (!(wrapped.iv instanceof Uint8Array) || wrapped.iv.byteLength !== 12) {
		throw new Error(`Invalid 12-byte AES-GCM IV for ${recordId}`);
	}
	if (!(wrapped.ciphertext instanceof Uint8Array) || wrapped.ciphertext.byteLength !== 48) {
		throw new Error(`Invalid AES-GCM ciphertext length for ${recordId}`);
	}

	const ptBuf = await crypto.subtle.decrypt(
		{
			name: 'AES-GCM',
			iv: wrapped.iv as BufferSource,
			additionalData: aad as BufferSource
		},
		kek,
		wrapped.ciphertext as BufferSource
	);
	const bytes = new Uint8Array(ptBuf);
	if (bytes.byteLength !== 32) {
		throw new Error(`Unwrapped key length mismatch for ${recordId}: ${bytes.byteLength}`);
	}
	return bytes;
}

/**
 * Load or create the 64-character hex `sqlite3mc` key for `catbird-mls/<didHash>.db`,
 * wrapped under a non-extractable `AES-GCM` `CryptoKey` in `IndexedDB` (`Gate 9`).
 */
export async function loadOrCreateDbKeyHex(didHash: string): Promise<string> {
	const bytes = await loadOrCreateWrappedSecretBytes(didHash, 'db');
	return Array.from(bytes)
		.map((b) => b.toString(16).padStart(2, '0'))
		.join('');
}

/** Compute canonical 64-char lowercase hex SHA-256 of normalized DID (`I8`). */
export async function accountDidHashHex(did: string): Promise<string> {
	const trimmed = did.trim().split('#')[0]?.trim() ?? '';
	if (!trimmed.startsWith('did:')) {
		throw new Error(`Invalid ATProto DID: ${did}`);
	}
	const parts = trimmed.split(':');
	if (parts.length < 3) {
		throw new Error(`Invalid ATProto DID: ${did}`);
	}
	const scheme = parts[0].toLowerCase();
	const method = parts[1].toLowerCase();
	const rest = parts.slice(2).join(':');
	const normalized = `${scheme}:${method}:${method === 'web' ? rest.toLowerCase() : rest}`;
	const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(normalized));
	return Array.from(new Uint8Array(digest))
		.map((b) => b.toString(16).padStart(2, '0'))
		.join('');
}

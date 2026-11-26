/**
 * Catmos Web enrolls a device in two steps: `enrollDevice` on the chat service, then a
 * `blue.catbird.chat.device` record on the account's PDS. When the PDS write fails the chat
 * service already holds the device, so the opt-in must survive and the write must be retried,
 * in the background and after a reload. The worker here stands in for the WASM client, whose
 * own retry and adoption rules are tested in `catbird-mls-web/tests/wasm_client_enrollment.rs`.
 */
import assert from 'node:assert/strict';
import { afterEach, beforeEach, describe, it } from 'node:test';
import type { Remote } from 'comlink';

import {
	isMlsOptedInForDid,
	REQUIRED_LABYRINTH_OAUTH_SCOPES,
	setMlsOptedInForDid
} from '../src/lib/labyrinth-ui.ts';
import type { WorkerApi } from '../src/lib/mls-worker.ts';
import {
	__setDeviceRecordRetryDelaysForTests,
	__setWorkerFactoryForTests,
	DEVICE_RECORD_PENDING_MESSAGE,
	DeviceRecordPendingError,
	enableMlsAndEnroll,
	isLabyrinthDeviceRecordPending,
	logout,
	onDeviceRecordSaved,
	persistBrowserAuth,
	tryRestoreSession
} from '../src/lib/wasm.ts';
import { accountDidHashHex, resetKeyStoreMemoryFallbackForTests } from '../src/lib/webcrypto-keystore.ts';

class MemoryStorage implements Storage {
	#map = new Map<string, string>();
	get length(): number {
		return this.#map.size;
	}
	clear(): void {
		this.#map.clear();
	}
	getItem(key: string): string | null {
		return this.#map.get(key) ?? null;
	}
	key(index: number): string | null {
		return Array.from(this.#map.keys())[index] ?? null;
	}
	removeItem(key: string): void {
		this.#map.delete(key);
	}
	setItem(key: string, value: string): void {
		this.#map.set(key, String(value));
	}
}

const DID = 'did:plc:devicerecordretry01';
const SCOPES = [...REQUIRED_LABYRINTH_OAUTH_SCOPES];
const STATUS = {
	mailbox_space_uri: `at:space://${DID}/blue.catbird.labyrinth.mailbox/self`,
	epoch_seq: 1,
	has_recovery_code: false,
	has_passkey_prf: false,
	active_device_ids: ['99999999-9999-4999-8999-999999999999']
};

/** A WASM client whose `enrollDevice` fails `failures` times with the PDS record still owed. */
function installWorker(options: { failures: number; pending: boolean; terminal?: string }) {
	const state = { ...options, enrollCalls: 0, backgroundStarts: 0 };
	__setWorkerFactoryForTests(() => {
		const api: Partial<WorkerApi> = {
			oauthRestoreSession: async () => ({
				did: DID,
				handle: 'alice.example.test',
				pds: 'https://pds.example.test',
				grantedScopes: SCOPES
			}),
			oauthLogout: async () => {},
			openUnifiedClient: async (params) => ({
				accountDid: params.accountDid,
				accountDidHash: await accountDidHashHex(params.accountDid)
			}),
			setup: (async () => {}) as unknown as WorkerApi['setup'],
			enrollUnifiedDevice: async () => {
				state.enrollCalls += 1;
				if (state.terminal) {
					state.pending = false;
					throw new Error(state.terminal);
				}
				if (state.failures > 0) {
					state.failures -= 1;
					state.pending = true;
					throw new Error(
						'Internal error: DeviceRecordPending: createRecord blue.catbird.chat.device HTTP 503: {}'
					);
				}
				state.pending = false;
				return STATUS;
			},
			isDeviceRecordPending: async () => state.pending,
			startBackgroundTasks: async () => {
				state.backgroundStarts += 1;
			},
			stopBackgroundTasks: async () => {},
			retireCurrentDevice: async () => true,
			clearContentRootKey: async () => {},
			clearAuth: async () => {},
			closeUnifiedClient: async () => {},
			labyrinthStatus: async () => STATUS
		};
		// Anything else the restore path touches (key replenishment, content keys) is a no-op.
		const worker = new Proxy(api, {
			get: (target, name) =>
				name === 'then' ? undefined : (target[name as keyof WorkerApi] ?? (async () => null))
		});
		return { worker: worker as unknown as Remote<WorkerApi> };
	});
	return state;
}

async function until(done: () => boolean, what: string): Promise<void> {
	for (let i = 0; i < 400; i += 1) {
		if (done()) return;
		await new Promise((resolve) => setTimeout(resolve, 5));
	}
	assert.fail(`timed out waiting for ${what}`);
}

describe('Device record retry after the chat service enrolled the device', () => {
	beforeEach(() => {
		for (const name of ['localStorage', 'sessionStorage']) {
			Object.defineProperty(globalThis, name, {
				value: new MemoryStorage(),
				configurable: true,
				writable: true
			});
		}
		resetKeyStoreMemoryFallbackForTests();
		__setDeviceRecordRetryDelaysForTests([5]);
		persistBrowserAuth(DID, 'petrel-oauth', {
			handle: 'alice.example.test',
			pds: 'https://pds.example.test',
			grantedScopes: SCOPES
		});
	});

	afterEach(async () => {
		await logout().catch(() => {});
		__setWorkerFactoryForTests(null);
		__setDeviceRecordRetryDelaysForTests(null);
	});

	it('keeps the opt-in, reports a plain error and retries until the record is saved', async () => {
		const worker = installWorker({ failures: 3, pending: false });
		const saved: string[] = [];
		const unsubscribe = onDeviceRecordSaved((did) => saved.push(did));

		await assert.rejects(
			() => enableMlsAndEnroll(DID, true, SCOPES),
			(err: unknown) => {
				assert.ok(err instanceof DeviceRecordPendingError);
				assert.equal(err.message, DEVICE_RECORD_PENDING_MESSAGE);
				assert.doesNotMatch(err.message, /createRecord|HTTP|Internal/);
				return true;
			}
		);
		assert.equal(isMlsOptedInForDid(DID), true, 'the opt-in survives a failed PDS write');
		assert.equal(await isLabyrinthDeviceRecordPending(DID), true);

		await until(() => saved.length === 1, 'the background retry to save the record');
		unsubscribe();
		assert.equal(worker.enrollCalls, 4, 'one failed opt-in, two failed retries, one success');
		assert.equal(worker.backgroundStarts, 1);
		assert.equal(saved[0].toLowerCase(), DID.toLowerCase());
		assert.equal(isMlsOptedInForDid(DID), true);
		assert.equal(await isLabyrinthDeviceRecordPending(DID), false);

		const settled = worker.enrollCalls;
		await new Promise((resolve) => setTimeout(resolve, 40));
		assert.equal(worker.enrollCalls, settled, 'no retry after success');
	});

	it('resumes the pending record write after a reload', async () => {
		// A previous page load opted in and left the record owed; this load only restores.
		setMlsOptedInForDid(DID, true);
		const worker = installWorker({ failures: 1, pending: true });

		const restored = await tryRestoreSession();
		assert.ok(restored, 'the session restores');

		await until(() => !worker.pending, 'the resumed retry to save the record');
		assert.equal(worker.enrollCalls, 2, 'retried at once, then again after the backoff');
		assert.equal(isMlsOptedInForDid(DID), true);
	});

	it('does not resume when nothing is owed', async () => {
		setMlsOptedInForDid(DID, true);
		const worker = installWorker({ failures: 0, pending: false });
		await tryRestoreSession();
		await new Promise((resolve) => setTimeout(resolve, 40));
		assert.equal(worker.enrollCalls, 0);
	});

	it('still drops the opt-in when enrollment fails with no record owed', async () => {
		const worker = installWorker({ failures: 0, pending: false, terminal: 'EnrollmentPdsRecordConflict' });
		await assert.rejects(() => enableMlsAndEnroll(DID, true, SCOPES), /EnrollmentPdsRecordConflict/);
		assert.equal(isMlsOptedInForDid(DID), false);
		await new Promise((resolve) => setTimeout(resolve, 40));
		assert.equal(worker.enrollCalls, 1, 'a refusal is not retried');
	});

	it('stops retrying and drops the opt-in when a retry is refused for good', async () => {
		const worker = installWorker({ failures: 1, pending: false });
		await assert.rejects(() => enableMlsAndEnroll(DID, true, SCOPES), DeviceRecordPendingError);
		worker.terminal = 'EnrollmentPdsRecordConflict';
		await until(() => !isMlsOptedInForDid(DID), 'the refused retry to drop the opt-in');
		const settled = worker.enrollCalls;
		await new Promise((resolve) => setTimeout(resolve, 40));
		assert.equal(worker.enrollCalls, settled);
	});
});

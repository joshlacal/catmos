import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { beforeEach, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { get } from 'svelte/store';
import type { Remote } from 'comlink';

import { auth } from '../src/lib/stores/auth.ts';
import { conversations } from '../src/lib/stores/conversations.ts';
import { messages } from '../src/lib/stores/messages.ts';
import {
	accountDidHashHex,
	inspectWrappingCryptoKey,
	resetKeyStoreMemoryFallbackForTests
} from '../src/lib/webcrypto-keystore.ts';
import { isMlsOptedInForDid, setMlsOptedInForDid } from '../src/lib/labyrinth-ui.ts';
import {
	__setWorkerFactoryForTests,
	advanceReadState,
	approveLabyrinthSiblingDevice,
	clearCircleAclTombstone,
	completeLabyrinthOtcPairing,
	fetchAndDecryptBlob,
	getCircleOwnerState,
	getOrCreateBrowserDeviceId,
	getOrCreateMlsDbKey,
	getReadState,
	initWasm,
	isLabyrinthDevicePendingApproval,
	listCircleOwnerStates,
	listReadStates,
	listRegisteredLabyrinthDevices,
	mergeCircleOwnerState,
	persistBrowserAuth,
	putCircleOwnerState,
	readBrowserAuth,
	readBrowserDeviceId,
	respondLiveLabyrinthOtcPairing,
	revokeRegisteredLabyrinthDeviceLive,
	startLiveLabyrinthOtcPairing,
	verifyAndReindexLabyrinthHistory
} from '../src/lib/wasm.ts';
import type { WorkerApi } from '../src/lib/mls-worker.ts';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CATMOS_ROOT = path.resolve(__dirname, '..');

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

function makeSahPoolHeaderBytes(associatedPath: string): Uint8Array {
	const buf = new Uint8Array(4096);
	const encoded = new TextEncoder().encode(associatedPath);
	buf.set(encoded.subarray(0, 511), 0);
	buf[encoded.length] = 0;
	return buf;
}

function createFakeOpfsPool(initialSlots: Record<string, string>) {
	const sahPoolSlots = new Map<string, Uint8Array>();
	for (const [slotName, headerPath] of Object.entries(initialSlots)) {
		sahPoolSlots.set(slotName, makeSahPoolHeaderBytes(headerPath));
	}
	const opaqueDir = {
		kind: 'directory',
		name: '.opaque',
		async getDirectoryHandle(): Promise<never> {
			throw new Error('NotFoundError');
		},
		async removeEntry(name: string): Promise<void> {
			if (!sahPoolSlots.delete(name)) throw new Error('NotFoundError');
		},
		async *entries() {
			for (const [slotName, data] of Array.from(sahPoolSlots.entries())) {
				yield [
					slotName,
					{
						kind: 'file',
						name: slotName,
						async getFile() {
							return {
								slice(start = 0, end = data.byteLength) {
									const view = data.slice(start, end);
									return {
										async arrayBuffer() {
											return view.buffer;
										}
									};
								}
							};
						}
					}
				] as const;
			}
		}
	};
	const poolDir = {
		kind: 'directory',
		name: '.opfs-sahpool',
		async getDirectoryHandle(name: string) {
			if (name === '.opaque') return opaqueDir;
			throw new Error('NotFoundError');
		},
		async removeEntry(): Promise<void> {
			throw new Error('NotFoundError');
		}
	};
	const rootDir = {
		kind: 'directory',
		name: '',
		async getDirectoryHandle(name: string) {
			if (name === '.opfs-sahpool') return poolDir;
			throw new Error('NotFoundError');
		},
		async removeEntry(): Promise<void> {
			throw new Error('NotFoundError');
		}
	};
	return { rootDir, sahPoolSlots };
}

describe('Wave 2 Stage 2 — D-3 fail-closed deleteAccountData, Space attachments, leave error surfacing, live OTC/backfill, readState & circleOwnerState', () => {
	let fakeLocalStorage: MemoryStorage;
	let fakeSessionStorage: MemoryStorage;

	beforeEach(() => {
		fakeLocalStorage = new MemoryStorage();
		fakeSessionStorage = new MemoryStorage();
		Object.defineProperty(globalThis, 'localStorage', {
			value: fakeLocalStorage,
			configurable: true,
			writable: true
		});
		Object.defineProperty(globalThis, 'sessionStorage', {
			value: fakeSessionStorage,
			configurable: true,
			writable: true
		});
		resetKeyStoreMemoryFallbackForTests();
		__setWorkerFactoryForTests(null);
	});

	it('enforces D-3 fail-closed deleteAccountData: remote delete error preserves auth store, keys, deviceId, and OPFS; retry purges all', async () => {
		const did = 'did:plc:d3failclosed01';
		const didHash = await accountDidHashHex(did);
		setMlsOptedInForDid(did, true, fakeLocalStorage);
		persistBrowserAuth(did, 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa');
		const deviceId = getOrCreateBrowserDeviceId(didHash);
		await getOrCreateMlsDbKey(did);
		auth.setUser({ did, handle: 'alice.catbird.blue' });

		const opfs = createFakeOpfsPool({
			slot_main: `/catbird-mls/${didHash}.db`
		});

		let remoteShouldFail = true;
		let terminateCount = 0;
		__setWorkerFactoryForTests(() => ({
			worker: {
				openUnifiedClient: async () => ({ accountDid: did, accountDidHash: didHash }),
				deleteAccountData: async () => {
					if (remoteShouldFail) {
						throw new Error('OwnerMailbox deleteSpace HTTP 503');
					}
					return true;
				},
				clearContentRootKey: async () => {},
				clearAuth: async () => {},
				closeUnifiedClient: async () => {}
			} as unknown as Remote<WorkerApi>,
			rawWorker: {
				terminate() {
					terminateCount += 1;
				}
			}
		}));

		await initWasm(did);

		await assert.rejects(
			() => auth.deleteAccountData(did),
			/OwnerMailbox deleteSpace HTTP 503/
		);

		// Local state MUST remain completely intact after remote failure (`D-3`)
		assert.equal(get(auth).user?.did, did);
		assert.equal(isMlsOptedInForDid(did, fakeLocalStorage), true);
		assert.equal(readBrowserAuth()?.did, did);
		assert.equal(readBrowserDeviceId(didHash), deviceId);
		assert.ok(await inspectWrappingCryptoKey(didHash));
		assert.equal(opfs.sahPoolSlots.has('slot_main'), true);
		assert.equal(terminateCount, 0);

		// Retry after remote recovers purges local state cleanly
		remoteShouldFail = false;
		const { deleteAccountData: rawDelete } = await import('../src/lib/wasm.ts');
		await rawDelete(did, {
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			opfsRootProvider: async () => opfs.rootDir as any,
			retireTimeoutMs: 250
		});
		auth.cancelLogin();

		assert.equal(get(auth).user, null);
		assert.equal(isMlsOptedInForDid(did, fakeLocalStorage), false);
		assert.equal(readBrowserAuth(), null);
		assert.equal(readBrowserDeviceId(didHash), null);
		assert.equal(await inspectWrappingCryptoKey(didHash), undefined);
		assert.equal(opfs.sahPoolSlots.has('slot_main'), false);
		assert.equal(terminateCount, 1);
	});

	it('deleteAccountData fails closed on remoteDelete timeout and cold-open timeout without wiping local OPFS or keys (B9 / D-3)', async () => {
		const did = 'did:plc:deltimeout09';
		const didHash = await accountDidHashHex(did);
		setMlsOptedInForDid(did, true, fakeLocalStorage);
		persistBrowserAuth(did, '99999999-9999-4999-8999-999999999999');
		const deviceId = getOrCreateBrowserDeviceId(didHash);
		await getOrCreateMlsDbKey(did);
		auth.setUser({ did, handle: 'timeout.catbird.blue' });

		const opfs = createFakeOpfsPool({
			slot_main: `/catbird-mls/${didHash}.db`
		});

		let hangOpen = true;
		let hangDelete = true;
		let terminateCount = 0;
		__setWorkerFactoryForTests(() => ({
			worker: {
				openUnifiedClient: async () => {
					if (hangOpen) {
						await new Promise(() => {});
					}
					return { accountDid: did, accountDidHash: didHash };
				},
				deleteAccountData: async () => {
					if (hangDelete) {
						await new Promise(() => {});
					}
					return true;
				},
				clearContentRootKey: async () => {},
				clearAuth: async () => {},
				closeUnifiedClient: async () => {}
			} as unknown as Remote<WorkerApi>,
			rawWorker: {
				terminate() {
					terminateCount += 1;
				}
			}
		}));

		const { deleteAccountData: rawDelete } = await import('../src/lib/wasm.ts');

		// 1. Cold-open timeout (`!_worker && isMlsOptedInForDid`) must reject, never resolve null.
		await assert.rejects(
			() =>
				rawDelete(did, {
					// eslint-disable-next-line @typescript-eslint/no-explicit-any
					opfsRootProvider: async () => opfs.rootDir as any,
					retireTimeoutMs: 30
				}),
			/deleteAccountData\(openUnifiedClient\) timed out/
		);
		assert.equal(isMlsOptedInForDid(did, fakeLocalStorage), true);
		assert.equal(readBrowserAuth()?.did, did);
		assert.equal(readBrowserDeviceId(didHash), deviceId);
		assert.ok(await inspectWrappingCryptoKey(didHash));
		assert.equal(opfs.sahPoolSlots.has('slot_main'), true);

		// 2. Active worker `w.deleteAccountData()` timeout must ALSO reject and keep local state intact.
		hangOpen = false;
		await initWasm(did);
		const preTimeoutTerminateCount = terminateCount;
		await assert.rejects(
			() =>
				rawDelete(did, {
					// eslint-disable-next-line @typescript-eslint/no-explicit-any
					opfsRootProvider: async () => opfs.rootDir as any,
					retireTimeoutMs: 30
				}),
			/deleteAccountData\(remoteDelete\) timed out/
		);
		assert.equal(isMlsOptedInForDid(did, fakeLocalStorage), true);
		assert.equal(readBrowserAuth()?.did, did);
		assert.equal(readBrowserDeviceId(didHash), deviceId);
		assert.ok(await inspectWrappingCryptoKey(didHash));
		assert.equal(opfs.sahPoolSlots.has('slot_main'), true);
		assert.equal(terminateCount, preTimeoutTerminateCount);

		// 3. Once remote delete completes within deadline, local cleanup proceeds cleanly.
		hangDelete = false;
		await rawDelete(did, {
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			opfsRootProvider: async () => opfs.rootDir as any,
			retireTimeoutMs: 250
		});
		assert.equal(isMlsOptedInForDid(did, fakeLocalStorage), false);
		assert.equal(readBrowserAuth(), null);
		assert.equal(readBrowserDeviceId(didHash), null);
		assert.equal(await inspectWrappingCryptoKey(didHash), undefined);
		assert.equal(opfs.sahPoolSlots.has('slot_main'), false);
		assert.equal(terminateCount, preTimeoutTerminateCount + 1);
	});

	it('propagates leaveConversation errors (LastAdminCannotLeave) and preserves conversation state until leave succeeds', async () => {
		const did = 'did:plc:leaveuser02';
		const didHash = await accountDidHashHex(did);
		setMlsOptedInForDid(did, true, fakeLocalStorage);
		persistBrowserAuth(did, 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb');
		getOrCreateBrowserDeviceId(didHash);
		await getOrCreateMlsDbKey(did);

		let blockLeave = true;
		__setWorkerFactoryForTests(() => ({
			worker: {
				openUnifiedClient: async () => ({ accountDid: did, accountDidHash: didHash }),
				listConversations: async () => [
					{
						id: 'convo-sole-admin',
						groupId: 'abcd',
						displayName: 'Core Team',
						members: [did, 'did:plc:peer'],
						unreadCount: 0,
						isGroup: true
					}
				],
				leaveConversation: async () => {
					if (blockLeave) {
						throw new Error('LastAdminCannotLeave: promote another admin before leaving');
					}
				}
			} as unknown as Remote<WorkerApi>,
			rawWorker: { terminate() {} }
		}));

		await initWasm(did);
		await conversations.load();
		conversations.select('convo-sole-admin');

		await assert.rejects(
			() => conversations.leaveConversation('convo-sole-admin'),
			/LastAdminCannotLeave/
		);
		assert.equal(get(conversations).items.length, 1);
		assert.equal(get(conversations).selectedId, 'convo-sole-admin');

		blockLeave = false;
		await conversations.leaveConversation('convo-sole-admin');
		assert.equal(get(conversations).items.length, 0);
		assert.equal(get(conversations).selectedId, null);
	});

	it('routes Space voice & blob decryption end-to-end and mounts VoicePlayer + VoiceRecorder in Svelte UI', async () => {
		const did = 'did:plc:voiceuser03';
		const didHash = await accountDidHashHex(did);
		setMlsOptedInForDid(did, true, fakeLocalStorage);
		persistBrowserAuth(did, 'cccccccc-cccc-4ccc-8ccc-cccccccccccc');
		getOrCreateBrowserDeviceId(didHash);
		await getOrCreateMlsDbKey(did);

		let capturedMime = '';
		let capturedWaveform: number[] = [];
		const sampleAudio = new Uint8Array([0x4f, 0x67, 0x67, 0x53, 0x01, 0x02]);
		const keyBytes = new Uint8Array(32).fill(0x11);
		const ivBytes = new Uint8Array(12).fill(0x22);

		__setWorkerFactoryForTests(() => ({
			worker: {
				openUnifiedClient: async () => ({ accountDid: did, accountDidHash: didHash }),
				sendVoice: async (
					convoId: string,
					audioData: Uint8Array,
					contentType: string,
					durationMs: number,
					waveform: number[]
				) => {
					capturedMime = contentType;
					capturedWaveform = waveform;
					const audio = {
						blobId: 'bafkreivoice001',
						key: keyBytes,
						iv: ivBytes,
						sha256: '33'.repeat(32),
						contentType,
						size: audioData.byteLength,
						durationMs,
						waveform
					};
					return {
						id: 'msg-voice-1',
						conversationId: convoId,
						senderDid: did,
						senderHandle: 'alice',
						content: '',
						timestamp: '2026-11-14T12:00:00.000Z',
						status: 'sent' as const,
						isOwn: true,
						messageType: 'voice' as const,
						audio,
						audioAttachment: audio
					};
				},
				fetchAndDecryptBlob: async (
					blobId: string,
					key: Uint8Array | number[],
					iv: Uint8Array | number[],
					sha256: string
				) => {
					assert.equal(blobId, 'bafkreivoice001');
					assert.equal(key instanceof Uint8Array ? key.byteLength : key.length, 32);
					assert.equal(iv instanceof Uint8Array ? iv.byteLength : iv.length, 12);
					assert.equal(sha256.length, 64);
					return sampleAudio;
				}
			} as unknown as Remote<WorkerApi>,
			rawWorker: { terminate() {} }
		}));

		await initWasm(did);
		await messages.sendVoice(
			'convo-voice-1',
			sampleAudio,
			2400,
			[0.2, 0.7, 0.4],
			'audio/ogg;codecs=opus'
		);
		assert.equal(capturedMime, 'audio/ogg;codecs=opus');
		assert.deepEqual(capturedWaveform, [0.2, 0.7, 0.4]);

		const stored = get(messages).byConversation.get('convo-voice-1') ?? [];
		assert.equal(stored.length, 1);
		assert.equal(stored[0]?.audio?.blobId, 'bafkreivoice001');
		assert.equal(stored[0]?.audioAttachment?.contentType, 'audio/ogg;codecs=opus');

		const decrypted = await fetchAndDecryptBlob(
			'bafkreivoice001',
			Array.from(keyBytes),
			Array.from(ivBytes),
			'33'.repeat(32)
		);
		assert.deepEqual(decrypted, sampleAudio);

		const bubbleMarkup = fs.readFileSync(
			path.join(CATMOS_ROOT, 'src/lib/components/MessageBubble.svelte'),
			'utf8'
		);
		assert.ok(bubbleMarkup.includes('<VoicePlayer'), 'MessageBubble must mount VoicePlayer');

		const composerMarkup = fs.readFileSync(
			path.join(CATMOS_ROOT, 'src/lib/components/Composer.svelte'),
			'utf8'
		);
		assert.ok(composerMarkup.includes('<VoiceRecorder'), 'Composer must mount VoiceRecorder');

		const memberListMarkup = fs.readFileSync(
			path.join(CATMOS_ROOT, 'src/lib/components/MemberList.svelte'),
			'utf8'
		);
		assert.ok(
			memberListMarkup.includes('member-action-error') && memberListMarkup.includes('role="alert"'),
			'MemberList must surface leave/member action errors via role="alert"'
		);
	});

	it('wires live Labyrinth pending_approval, sibling approval, 2-device D-4 OTC ceremony, history re-index, readState, and circleOwnerState', async () => {
		const did = 'did:plc:labyrinthstage2';
		const didHash = await accountDidHashHex(did);
		setMlsOptedInForDid(did, true, fakeLocalStorage);
		persistBrowserAuth(did, 'dddddddd-dddd-4ddd-8ddd-dddddddddddd');
		const selfDeviceId = getOrCreateBrowserDeviceId(didHash);
		const siblingDeviceId = '99999999-9999-4999-8999-999999999999';
		await getOrCreateMlsDbKey(did);

		let readSeq = 0;
		const circles = new Map<string, {
			circle_id: string;
			name: string;
			description?: string | null;
			member_dids: string[];
			acl_tombstone_dids?: string[];
			updated_at: string;
		}>();
		const callLog: string[] = [];

		__setWorkerFactoryForTests(() => ({
			worker: {
				openUnifiedClient: async () => ({ accountDid: did, accountDidHash: didHash }),
				currentDeviceId: async () => selfDeviceId,
				isDevicePendingApproval: async () => true,
				listRegisteredDevices: async () => [
					{ device_id: selfDeviceId, status: 'active', is_current: true },
					{ device_id: siblingDeviceId, status: 'pending_approval', pending_approval: true }
				],
				approveSiblingDevice: async (targetId: string) => {
					callLog.push(`approve:${targetId}`);
					return {
						backup_enabled: true,
						mailbox_space_uri: `at:space://${did}/blue.catbird.labyrinth.mailbox/self`,
						has_recovery_code: true,
						has_passkey_prf: false,
						epoch_seq: 2,
						active_device_ids: [selfDeviceId, targetId],
						current_device_id: selfDeviceId
					};
				},
				revokeRegisteredDevice: async (targetId: string) => {
					callLog.push(`revoke:${targetId}`);
					return {
						backup_enabled: true,
						mailbox_space_uri: `at:space://${did}/blue.catbird.labyrinth.mailbox/self`,
						has_recovery_code: true,
						has_passkey_prf: false,
						epoch_seq: 3,
						active_device_ids: [selfDeviceId],
						current_device_id: selfDeviceId
					};
				},
				startLiveOtcPairing: async (code: string) => {
					callLog.push(`startOtc:${code}`);
					return {
						session_id_hex: 'aa'.repeat(16),
						formatted_code: '654-321',
						six_digit_code: '654321'
					};
				},
				respondLiveOtcPairing: async (sessionIdHex: string, code?: string | null) => {
					callLog.push(`respondOtc:${sessionIdHex}:${code}`);
				},
				completeOtcPairing: async (code: string) => {
					callLog.push(`completeOtc:${code}`);
					return {
						session_id: Array.from({ length: 16 }, () => 0xaa),
						initiator_mlkem768_ek_len: 1184,
						responder_mlkem768_ct_len: 1088,
						new_epoch_seq: 4
					};
				},
				verifyAndReindexHistory: async (convoId: string) => {
					callLog.push(`reindex:${convoId}`);
					return 17;
				},
				getReadState: async (convoId: string) =>
					readSeq > 0 ? { conversation_id: convoId, last_read_seq: readSeq } : null,
				advanceReadState: async (convoId: string, seq: number) => {
					readSeq = Math.max(readSeq, seq);
					return { conversation_id: convoId, last_read_seq: readSeq };
				},
				listReadStates: async () =>
					readSeq > 0 ? [{ conversation_id: 'convo-1', last_read_seq: readSeq }] : [],
				getCircleOwnerState: async (circleId: string) => circles.get(circleId) ?? null,
				putCircleOwnerState: async (state: {
					circle_id: string;
					name: string;
					description?: string | null;
					member_dids: string[];
					acl_tombstone_dids?: string[];
					updated_at: string;
				}) => {
					circles.set(state.circle_id, { ...state });
					return 'bafyreicircle001';
				},
				mergeCircleOwnerState: async (update: {
					circle_id: string;
					name?: string | null;
					add_member_dids?: string[];
					remove_member_dids?: string[];
				}) => {
					const existing = circles.get(update.circle_id) ?? {
						circle_id: update.circle_id,
						name: update.name ?? 'Untitled',
						member_dids: [],
						acl_tombstone_dids: [],
						updated_at: '2026-11-14T12:00:00Z'
					};
					const members = new Set(existing.member_dids);
					const tombstones = new Set(existing.acl_tombstone_dids ?? []);
					for (const addDid of update.add_member_dids ?? []) {
						if (!tombstones.has(addDid)) members.add(addDid);
					}
					for (const remDid of update.remove_member_dids ?? []) {
						members.delete(remDid);
						tombstones.add(remDid);
					}
					const next = {
						...existing,
						name: update.name ?? existing.name,
						member_dids: Array.from(members),
						acl_tombstone_dids: Array.from(tombstones),
						updated_at: '2026-11-14T12:05:00Z'
					};
					circles.set(update.circle_id, next);
					return next;
				},
				clearCircleAclTombstone: async (circleId: string, memberDid: string) => {
					const cur = circles.get(circleId)!;
					const next = {
						...cur,
						acl_tombstone_dids: (cur.acl_tombstone_dids ?? []).filter((d) => d !== memberDid)
					};
					circles.set(circleId, next);
					return next;
				},
				listCircleOwnerStates: async () => Array.from(circles.values())
			} as unknown as Remote<WorkerApi>,
			rawWorker: { terminate() {} }
		}));

		await initWasm(did);

		assert.equal(await isLabyrinthDevicePendingApproval(did), true);
		const regDevices = await listRegisteredLabyrinthDevices(did);
		assert.equal(regDevices.length, 2);

		const approved = await approveLabyrinthSiblingDevice(did, siblingDeviceId);
		assert.equal(approved.epoch_seq, 2);

		const startedOtc = await startLiveLabyrinthOtcPairing(did, '654321');
		assert.equal(startedOtc.session_id_hex, 'aa'.repeat(16));
		await respondLiveLabyrinthOtcPairing(did, startedOtc.session_id_hex, '654-321');
		const completedOtc = await completeLabyrinthOtcPairing(did, '654-321');
		assert.equal(completedOtc.new_epoch_seq, 4);

		await assert.rejects(
			() => revokeRegisteredLabyrinthDeviceLive(did, selfDeviceId),
			/Cannot revoke this device from itself/
		);
		const revoked = await revokeRegisteredLabyrinthDeviceLive(did, siblingDeviceId);
		assert.equal(revoked.epoch_seq, 3);

		const reindexedCount = await verifyAndReindexLabyrinthHistory(did, 'convo-1');
		assert.equal(reindexedCount, 17);

		assert.equal(await getReadState(did, 'convo-1'), null);
		assert.equal((await advanceReadState(did, 'convo-1', 12)).last_read_seq, 12);
		assert.equal((await advanceReadState(did, 'convo-1', 5)).last_read_seq, 12);
		assert.equal((await listReadStates(did)).length, 1);

		const cid = await putCircleOwnerState(did, {
			circle_id: 'circle-friends',
			name: 'Close Friends',
			member_dids: ['did:plc:bob'],
			acl_tombstone_dids: [],
			updated_at: '2026-11-14T12:00:00Z'
		});
		assert.equal(cid, 'bafyreicircle001');
		const merged = await mergeCircleOwnerState(did, {
			circle_id: 'circle-friends',
			add_member_dids: ['did:plc:carol'],
			remove_member_dids: ['did:plc:bob']
		});
		assert.deepEqual(merged.member_dids, ['did:plc:carol']);
		assert.deepEqual(merged.acl_tombstone_dids, ['did:plc:bob']);
		const cleared = await clearCircleAclTombstone(did, 'circle-friends', 'did:plc:bob');
		assert.deepEqual(cleared.acl_tombstone_dids, []);
		assert.equal((await getCircleOwnerState(did, 'circle-friends'))?.name, 'Close Friends');
		assert.equal((await listCircleOwnerStates(did)).length, 1);
		assert.deepEqual(callLog, [
			`approve:${siblingDeviceId}`,
			'startOtc:654321',
			`respondOtc:${'aa'.repeat(16)}:654-321`,
			'completeOtc:654-321',
			`revoke:${siblingDeviceId}`,
			'reindex:convo-1'
		]);
	});
});

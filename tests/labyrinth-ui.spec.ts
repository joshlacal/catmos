import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

import {
	assertCanRevokeLabyrinthDevice,
	buildUpgradeAdditionalScopes,
	createLabyrinthPasskeyUserId,
	deriveLabyrinthPrfSalt,
	deriveSiblingBackfillSummary,
	detectPasskeyPrfCapability,
	evaluateSpacesGateForUi,
	isMlsOptedInForDid,
	LABYRINTH_PASSKEY_RP_ID,
	LABYRINTH_PRF_DOMAIN_PREFIX,
	mapWebAuthnErrorToMessage,
	normalizeLabyrinthDeviceList,
	performPasskeyPrfAssertion,
	REQUIRED_LABYRINTH_OAUTH_SCOPES,
	resolveLabyrinthPasskeyRpId,
	requireBackupEligiblePasskey,
	scopeGranted,
	setMlsOptedInForDid,
	UPGRADEABLE_LABYRINTH_OAUTH_SCOPES
} from '../src/lib/labyrinth-ui.ts';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CATMOS_ROOT = path.resolve(__dirname, '..');

describe('Labyrinth Svelte settings UI, Spaces gate (I15), ctl #2 default-off, and WebAuthn capabilities', () => {
	it('keeps MLS and Spaces off by default on fresh sign-in (ctl #2)', () => {
		const mem = new Map<string, string>();
		const store = {
			getItem: (k: string) => mem.get(k) ?? null,
			setItem: (k: string, v: string) => {
				mem.set(k, v);
			},
			removeItem: (k: string) => {
				mem.delete(k);
			}
		};
		assert.equal(isMlsOptedInForDid('did:plc:alice123', store), false);
		setMlsOptedInForDid('did:plc:alice123#dev-1', true, store);
		assert.equal(isMlsOptedInForDid('did:plc:alice123', store), true);
		setMlsOptedInForDid('did:plc:alice123', false, store);
		assert.equal(isMlsOptedInForDid('did:plc:alice123', store), false);
	});

	it('enforces I15 Spaces-required gate, nest allowlisted mailboxKeys scope, and space:/repo: query-parameter subsumption', () => {
		const did = 'did:plc:scopeuser';
		assert.equal(
			REQUIRED_LABYRINTH_OAUTH_SCOPES[2],
			'repo:blue.catbird.labyrinth.mailboxKeys',
			'mailboxKeys must be unparameterized to match nest ALLOWLISTED_UPGRADE_SCOPES and support epoch updates'
		);
		assert.equal(
			REQUIRED_LABYRINTH_OAUTH_SCOPES[3],
			'repo:blue.catbird.chat.device?action=create'
		);
		assert.equal(
			REQUIRED_LABYRINTH_OAUTH_SCOPES[4],
			'repo:blue.catbird.chat.deviceRevocation?action=create'
		);
		assert.equal(REQUIRED_LABYRINTH_OAUTH_SCOPES.length, 7);
		assert.deepEqual(
			buildUpgradeAdditionalScopes(REQUIRED_LABYRINTH_OAUTH_SCOPES),
			UPGRADEABLE_LABYRINTH_OAUTH_SCOPES
		);
		assert.ok(!UPGRADEABLE_LABYRINTH_OAUTH_SCOPES.includes('atproto' as never));

		const blockedPds = evaluateSpacesGateForUi(false, [...REQUIRED_LABYRINTH_OAUTH_SCOPES], did);
		assert.equal(blockedPds.eligible, false);
		assert.match(blockedPds.message, /Spaces/i);

		const blockedScopes = evaluateSpacesGateForUi(true, ['atproto'], did);
		assert.equal(blockedScopes.eligible, false);
		assert.ok(blockedScopes.missingScopes.includes('blob:*/*'));
		assert.ok(
			blockedScopes.missingScopes.includes('repo:blue.catbird.chat.deviceRevocation?action=create')
		);
		assert.ok(
			blockedScopes.missingScopes.includes(
				'space:blue.catbird.labyrinth.mailbox?action=create&action=delete&action=read&action=update&collection=blue.catbird.labyrinth.attachmentManifest&collection=blue.catbird.labyrinth.circleOwnerState&collection=blue.catbird.labyrinth.device&collection=blue.catbird.labyrinth.epoch&collection=blue.catbird.labyrinth.epochMember&collection=blue.catbird.labyrinth.otcSession&collection=blue.catbird.labyrinth.ownerBatch&collection=blue.catbird.labyrinth.readState&collection=blue.catbird.labyrinth.virtualDevice&manage=create&manage=delete'
			)
		);
		assert.ok(
			blockedScopes.missingScopes.includes(
				'space:blue.catbird.labyrinth.conversation?action=create&action=delete&action=read&action=update&authority=*&collection=blue.catbird.labyrinth.attachmentManifest&collection=blue.catbird.labyrinth.authorRedaction&collection=blue.catbird.labyrinth.batch&collection=blue.catbird.labyrinth.mek'
			)
		);

		const oldScopeSession = evaluateSpacesGateForUi(
			true,
			[
				...REQUIRED_LABYRINTH_OAUTH_SCOPES.slice(0, 5),
				'space:blue.catbird.labyrinth.mailbox?manage=create&manage=delete',
				'space:blue.catbird.labyrinth.conversation?authority=*'
			],
			did
		);
		assert.equal(oldScopeSession.eligible, false);
		assert.deepEqual(oldScopeSession.missingScopes, REQUIRED_LABYRINTH_OAUTH_SCOPES.slice(5));

		const eligible = evaluateSpacesGateForUi(true, [...REQUIRED_LABYRINTH_OAUTH_SCOPES], did);
		assert.equal(eligible.eligible, true);
		assert.equal(eligible.missingScopes.length, 0);

		// Subsumption parity with `catbird-mls/src/client/spaces_gate.rs`
		assert.equal(scopeGranted(['transition:generic'], 'atproto', did), true);
		assert.equal(scopeGranted(['repo:*'], 'repo:blue.catbird.labyrinth.mailboxKeys', did), true);
		assert.equal(
			scopeGranted(
				['repo:blue.catbird.labyrinth.mailboxKeys?action=create&action=update&action=delete'],
				'repo:blue.catbird.labyrinth.mailboxKeys',
				did
			),
			true
		);
		assert.equal(
			scopeGranted(
				['repo:blue.catbird.labyrinth.mailboxKeys?action=create'],
				'repo:blue.catbird.labyrinth.mailboxKeys',
				did
			),
			false,
			'create-only mailboxKeys must not satisfy full create/update/delete mailboxKeys requirement'
		);
		assert.equal(
			scopeGranted(['repo:blue.catbird.chat.device'], 'repo:blue.catbird.chat.device?action=create', did),
			true
		);
		assert.equal(
			scopeGranted(
				['repo:blue.catbird.chat.device?action=delete'],
				'repo:blue.catbird.chat.device?action=create',
				did
			),
			false
		);
		assert.equal(
			scopeGranted(
				['repo:blue.catbird.chat.deviceRevocation'],
				'repo:blue.catbird.chat.deviceRevocation?action=create',
				did
			),
			true
		);
		assert.equal(
			scopeGranted(
				['repo:blue.catbird.chat.deviceRevocation?action=delete'],
				'repo:blue.catbird.chat.deviceRevocation?action=create',
				did
			),
			false
		);

		for (const requiredSpace of REQUIRED_LABYRINTH_OAUTH_SCOPES.slice(5)) {
			const [family, query] = requiredSpace.split('?');
			const reversed = `${family}?${query!.split('&').reverse().join('&')}`;
			assert.equal(scopeGranted([reversed], requiredSpace, did), true);
			assert.equal(
				scopeGranted([`${reversed}&action=read_self&manage=update`], requiredSpace, did),
				true
			);
			const wildcardCollection = `${family}?${query!
				.split('&')
				.filter((p) => !p.startsWith('collection='))
				.concat(['collection=*'])
				.join('&')}`;
			assert.equal(scopeGranted([wildcardCollection], requiredSpace, did), true);
			assert.equal(
				scopeGranted([requiredSpace.replace('&action=read', '')], requiredSpace, did),
				false
			);
			assert.equal(
				scopeGranted(
					[`${requiredSpace}&authority=did:plc:other&authority=*`],
					requiredSpace,
					did
				),
				false
			);
		}

		// Mailbox space allows explicit self DID or authority=*, rejects foreign DID
		const mailboxReq = REQUIRED_LABYRINTH_OAUTH_SCOPES[5];
		assert.equal(scopeGranted([`${mailboxReq}&authority=${did}`], mailboxReq, did), true);
		assert.equal(scopeGranted([`${mailboxReq}&authority=*`], mailboxReq, did), true);
		assert.equal(scopeGranted([`${mailboxReq}&authority=did:plc:foreign`], mailboxReq, did), false);

		// Conversation space requires authority=*
		const convoReq = REQUIRED_LABYRINTH_OAUTH_SCOPES[6];
		assert.equal(
			scopeGranted([convoReq.replace('authority=*', 'authority=self')], convoReq, did),
			false
		);

		// Canonical @atproto/oauth-scopes token response: omits default actions
		// (read, create, update, delete) and resolves authority=self to the user's DID.
		const serverNormalizedMailbox = `space:blue.catbird.labyrinth.mailbox?authority=${did}&collection=blue.catbird.labyrinth.attachmentManifest&collection=blue.catbird.labyrinth.circleOwnerState&collection=blue.catbird.labyrinth.device&collection=blue.catbird.labyrinth.epoch&collection=blue.catbird.labyrinth.epochMember&collection=blue.catbird.labyrinth.otcSession&collection=blue.catbird.labyrinth.ownerBatch&collection=blue.catbird.labyrinth.readState&collection=blue.catbird.labyrinth.virtualDevice&manage=create&manage=delete`;
		const serverNormalizedConvo =
			'space:blue.catbird.labyrinth.conversation?authority=*&collection=blue.catbird.labyrinth.attachmentManifest&collection=blue.catbird.labyrinth.authorRedaction&collection=blue.catbird.labyrinth.batch&collection=blue.catbird.labyrinth.mek';
		const serverNormalizedGate = evaluateSpacesGateForUi(
			true,
			[...REQUIRED_LABYRINTH_OAUTH_SCOPES.slice(0, 5), serverNormalizedMailbox, serverNormalizedConvo],
			did
		);
		assert.equal(serverNormalizedGate.eligible, true);
		assert.equal(serverNormalizedGate.missingScopes.length, 0);
		assert.equal(
			scopeGranted([serverNormalizedConvo.replace('authority=*', 'authority=%2A')], convoReq, did),
			true
		);
		assert.equal(
			scopeGranted(
				[serverNormalizedMailbox.replace(`authority=${did}`, `authority=${encodeURIComponent(did)}`)],
				mailboxReq,
				did
			),
			true
		);
	});

	it('gates Passkey PRF registration on PublicKeyCredential.getClientCapabilities()', async () => {
		const unsupported = await detectPasskeyPrfCapability({
			getClientCapabilities: async () => ({
				passkeyPlatformAuthenticator: false,
				conditionalGet: true
			})
		});
		assert.equal(unsupported.canRegisterPasskeyPrf, false);

		const supported = await detectPasskeyPrfCapability({
			getClientCapabilities: async () => ({
				passkeyPlatformAuthenticator: true,
				conditionalGet: true
			})
		});
		assert.equal(supported.canRegisterPasskeyPrf, true);

		assert.match(
			mapWebAuthnErrorToMessage({ name: 'InvalidStateError' }),
			/already registered/i
		);
		assert.match(mapWebAuthnErrorToMessage({ name: 'NotAllowedError' }), /cancelled|denied/i);
		assert.match(mapWebAuthnErrorToMessage({ name: 'SecurityError' }), /origin|RP ID/i);
	});

	it('shows the reason when a step after the passkey prompt fails', () => {
		// The WASM client rejects with a plain string, not an Error.
		assert.equal(
			mapWebAuthnErrorToMessage('wasm_space_getDelegationToken: HTTP 400 InvalidRequest'),
			'wasm_space_getDelegationToken: HTTP 400 InvalidRequest'
		);
		assert.equal(mapWebAuthnErrorToMessage(new Error('no PRF output')), 'no PRF output');
		assert.equal(mapWebAuthnErrorToMessage({ message: 'worker said no' }), 'worker said no');
		for (const empty of ['', '   ', null, undefined, 42, {}, { message: 7 }]) {
			assert.equal(mapWebAuthnErrorToMessage(empty), 'Passkey operation failed.');
		}
	});

	it('binds a verified, backup-eligible passkey to the relying party and ceremony', async () => {
		const rpId = LABYRINTH_PASSKEY_RP_ID;
		const data = new Uint8Array(37);
		data.set(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(rpId))));
		for (const flags of [0, 1, 5, 8, 12]) {
			data[32] = flags;
			await assert.rejects(requireBackupEligiblePasskey(data.buffer, rpId, 'assertion'), /backup-eligible/);
		}
		data[32] = 0x0d;
		await requireBackupEligiblePasskey(data.buffer, rpId, 'assertion');
		await assert.rejects(requireBackupEligiblePasskey(data.buffer, rpId, 'registration'), /backup-eligible/);
		data[32] = 0x4d;
		await requireBackupEligiblePasskey(data.buffer, rpId, 'registration');
		await assert.rejects(requireBackupEligiblePasskey(data.buffer, 'localhost', 'registration'), /domain/);
		await assert.rejects(requireBackupEligiblePasskey(data.slice(0, 32).buffer, rpId, 'assertion'));
	});

	it('runs Passkey PRF assertion restore with cross-platform iOS/Android v1 DID salt, random 32-byte user.id, and dedicated rpId', async () => {
		assert.equal(LABYRINTH_PRF_DOMAIN_PREFIX, 'catbird.labyrinth.passkey-recovery.v1:');
		assert.equal(LABYRINTH_PASSKEY_RP_ID, 'passkey.catbird.blue');
		assert.equal(resolveLabyrinthPasskeyRpId('catmos.catbird.blue'), 'passkey.catbird.blue');
		assert.throws(() => resolveLabyrinthPasskeyRpId('catbird.blue'), /web origin/);
		assert.throws(() => resolveLabyrinthPasskeyRpId('localhost', 'tauri:'), /web origin/);
		assert.throws(() => resolveLabyrinthPasskeyRpId('catmos.catbird.blue', 'http:'), /web origin/);
		assert.equal((await detectPasskeyPrfCapability(undefined, {
			hostname: 'localhost', protocol: 'tauri:'
		})).canRegisterPasskeyPrf, false);
		assert.equal(resolveLabyrinthPasskeyRpId('localhost'), 'localhost');

		const mixedPlcDid = 'DID:PLC:AbCdEf123#dev-9';
		const expectedSaltBuf = await crypto.subtle.digest(
			'SHA-256',
			new TextEncoder().encode('catbird.labyrinth.passkey-recovery.v1:did:plc:AbCdEf123')
		);
		const saltA = await deriveLabyrinthPrfSalt('did:plc:AbCdEf123');
		const saltB = await deriveLabyrinthPrfSalt(mixedPlcDid);
		assert.equal(saltA.byteLength, 32);
		assert.deepEqual(saltA, new Uint8Array(expectedSaltBuf));
		assert.deepEqual(saltA, saltB);

		const webSalt = await deriveLabyrinthPrfSalt('DID:WEB:Alice.Example.COM#dev-2');
		const expectedWebSaltBuf = await crypto.subtle.digest(
			'SHA-256',
			new TextEncoder().encode('catbird.labyrinth.passkey-recovery.v1:did:web:alice.example.com')
		);
		assert.deepEqual(webSalt, new Uint8Array(expectedWebSaltBuf));

		const userIdBytes = createLabyrinthPasskeyUserId();
		assert.equal(userIdBytes.byteLength, 32);
		assert.notDeepEqual(userIdBytes, createLabyrinthPasskeyUserId());

		const fakeCredId = new Uint8Array([1, 2, 3, 4, 5, 6]);
		const fakePrfOut = new Uint8Array(32).fill(0x5a);
		let capturedSalt: Uint8Array | null = null;
		let capturedRpId: string | undefined;

		const res = await performPasskeyPrfAssertion({
			did: 'did:plc:AbCdEf123',
			credentialsContainer: {
				get: async (options) => {
					capturedRpId = options.publicKey?.rpId;
					const prfExt = (
						options.publicKey?.extensions as {
							prf?: { eval?: { first?: BufferSource } };
						}
					)?.prf?.eval?.first;
					if (prfExt instanceof Uint8Array) {
						capturedSalt = prfExt;
					}
					const authenticatorData = new Uint8Array(37);
					authenticatorData.set(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(capturedRpId))));
					authenticatorData[32] = 0x0d;
					return {
						id: 'AQIDBAUG',
						type: 'public-key',
						rawId: fakeCredId.buffer,
						response: { authenticatorData: authenticatorData.buffer } as AuthenticatorAssertionResponse,
						authenticatorAttachment: 'platform',
						getClientExtensionResults: () => ({
							prf: {
								results: {
									first: fakePrfOut.buffer
								}
							}
						}),
						toJSON: () => ({})
					} as unknown as PublicKeyCredential;
				}
			}
		});

		assert.equal(capturedRpId, 'passkey.catbird.blue');
		assert.deepEqual(capturedSalt, saltA);
		assert.deepEqual(res.credentialId, fakeCredId);
		assert.deepEqual(res.prfOutput32, fakePrfOut);
	});

	it('normalizes multi-device metadata, enforces This Device self-revoke guard, and summarizes sibling backfill', () => {
		const selfId = '11111111-1111-4111-8111-111111111111';
		const siblingPending = '22222222-2222-4222-8222-222222222222';
		const siblingDormant = '33333333-3333-4333-8333-333333333333';

		assert.throws(
			() => assertCanRevokeLabyrinthDevice(selfId, selfId),
			/Cannot revoke this device from itself/
		);
		assert.doesNotThrow(() => assertCanRevokeLabyrinthDevice(siblingPending, selfId));

		const list = normalizeLabyrinthDeviceList(
			{
				active_device_ids: [selfId],
				devices: [
					{
						device_id: selfId,
						device_name: 'MacBook Pro Safari',
						last_active_at: '2026-11-14T00:00:00Z'
					},
					{
						device_id: siblingPending,
						device_name: 'iPhone 17 Pro',
						pending_approval: true,
						last_active_at: '2026-11-14T00:05:00Z'
					},
					{
						device_id: siblingDormant,
						device_name: 'Old Tablet',
						last_active_at: '2026-10-01T00:00:00Z',
						dormant_at: '2026-11-01T00:00:00Z'
					}
				]
			},
			selfId
		);

		assert.equal(list.length, 3);
		assert.equal(list[0]?.deviceId, selfId);
		assert.equal(list[0]?.isCurrent, true);
		assert.equal(list[0]?.deviceName, 'MacBook Pro Safari');
		assert.equal(list[1]?.deviceId, siblingPending);
		assert.equal(list[1]?.status, 'pending_approval');
		assert.equal(list[2]?.deviceId, siblingDormant);
		assert.equal(list[2]?.status, 'dormant');
		assert.equal(list[2]?.dormantAt, '2026-11-01T00:00:00Z');

		const backfill = deriveSiblingBackfillSummary({
			backfill: {
				state: 'syncing',
				synced_batches: 14,
				total_batches: 20,
				last_synced_at: '2026-11-14T00:10:00Z'
			}
		});
		assert.equal(backfill.state, 'syncing');
		assert.match(backfill.label, /14 \/ 20 batches/);
	});

	it('uses semantic HTML (<figure><pre tabindex="0"><code> and native <dialog method="dialog">) in /settings/labyrinth/+page.svelte', () => {
		const sveltePath = path.join(
			CATMOS_ROOT,
			'src/routes/settings/labyrinth/+page.svelte'
		);
		const markup = fs.readFileSync(sveltePath, 'utf8');
		const h1Matches = markup.match(/<h1\b/g) ?? [];
		assert.equal(h1Matches.length, 1, 'must have exactly one <h1> page heading');
		assert.ok(markup.includes('<figure'), 'must wrap recovery code in <figure>');
		assert.ok(markup.includes('<figcaption'), 'must include <figcaption> for recovery code');
		assert.ok(
			markup.includes('<pre tabindex="0"><code>'),
			'must present 40-char recovery code inside <pre tabindex="0"><code>'
		);
		assert.ok(markup.includes('<dialog'), 'must use native <dialog> for device revocation');
		assert.ok(markup.includes('method="dialog"'), 'must use <form method="dialog"> inside <dialog>');
		assert.ok(markup.includes('.showModal()'), 'must open confirmation modal via .showModal()');
		assert.ok(markup.includes('Restore with Passkey PRF'), 'must render Passkey PRF restore button');
		assert.ok(markup.includes('This Device'), 'must render This Device pill');
		assert.ok(markup.includes('Pending Approval'), 'must render Pending Approval badge');
		assert.ok(
			markup.includes('Grant Spaces Permissions'),
			'must render progressive /auth/upgrade button when scopes are missing'
		);
		assert.ok(
			!markup.includes('FALLBACK_DEMO_DID') && !markup.includes('catmosdemoaccount'),
			'must contain zero fake or demo fallback DIDs (FC-01..FC-10)'
		);
		assert.ok(
			markup.includes('createLabyrinthPasskeyUserId'),
			'must generate a random WebAuthn user.id per registration'
		);
		assert.ok(
			!markup.includes('.slice(0, 64)'),
			'must not truncate raw DID UTF-8 bytes for WebAuthn user.id'
		);
	});

	it('routes browser auth through Petrel CAB and chat XRPC directly to chat.catbird.blue with #atproto_mls service auth (D1, G3)', () => {
		const wasmTsPath = path.join(CATMOS_ROOT, 'src/lib/wasm.ts');
		const wasmTs = fs.readFileSync(wasmTsPath, 'utf8');
		assert.ok(
			wasmTs.includes('https://api.catbird.blue/cab/catmos'),
			'wasm.ts must target the Petrel CAB backend at api.catbird.blue/cab/catmos'
		);
		assert.ok(
			wasmTs.includes('https://catmos.catbird.blue/oauth/client-metadata.json'),
			'wasm.ts must use the CAB client_id metadata document'
		);
		assert.ok(
			wasmTs.includes('#atproto_mls'),
			'wasm.ts must mint getServiceAuth JWTs for did:web:chat.catbird.blue#atproto_mls'
		);
		assert.ok(
			wasmTs.includes('oauthServiceToken'),
			'wasm.ts must mint service auth tokens via Petrel direct OAuth'
		);
		assert.ok(
			!wasmTs.includes('/auth/login') &&
				!wasmTs.includes('/auth/exchange') &&
				!wasmTs.includes('/auth/upgrade'),
			'wasm.ts must not call legacy nest /auth/* endpoints'
		);
		assert.ok(
			!wasmTs.includes('mlschat.catbird.blue'),
			'wasm.ts must target canonical chat.catbird.blue, never legacy mlschat.catbird.blue'
		);
		assert.ok(
			wasmTs.includes('crypto.randomUUID().toLowerCase()'),
			'wasm.ts must generate canonical lowercase UUIDv4 deviceId'
		);
	});
});

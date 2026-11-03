import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

import {
	detectPasskeyPrfCapability,
	evaluateSpacesGateForUi,
	isMlsOptedInForDid,
	mapWebAuthnErrorToMessage,
	REQUIRED_LABYRINTH_OAUTH_SCOPES,
	setMlsOptedInForDid
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
		setMlsOptedInForDid('did:plc:alice123', true, store);
		assert.equal(isMlsOptedInForDid('did:plc:alice123', store), true);
		setMlsOptedInForDid('did:plc:alice123', false, store);
		assert.equal(isMlsOptedInForDid('did:plc:alice123', store), false);
	});

	it('enforces I15 Spaces-required gate and required Spec §6.7 OAuth scopes', () => {
		const blockedPds = evaluateSpacesGateForUi(false, [...REQUIRED_LABYRINTH_OAUTH_SCOPES]);
		assert.equal(blockedPds.eligible, false);
		assert.match(blockedPds.message, /Spaces/i);

		const blockedScopes = evaluateSpacesGateForUi(true, ['atproto']);
		assert.equal(blockedScopes.eligible, false);
		assert.ok(blockedScopes.missingScopes.includes('blob:*/*'));
		assert.ok(
			blockedScopes.missingScopes.includes(
				'space:blue.catbird.labyrinth.mailbox?action=create&action=delete&action=read&action=update&collection=blue.catbird.labyrinth.attachmentManifest&collection=blue.catbird.labyrinth.device&collection=blue.catbird.labyrinth.epoch&collection=blue.catbird.labyrinth.epochMember&collection=blue.catbird.labyrinth.otcSession&collection=blue.catbird.labyrinth.ownerBatch&collection=blue.catbird.labyrinth.virtualDevice&manage=create&manage=delete'
			)
		);

		const oldScopeSession = evaluateSpacesGateForUi(true, [
			...REQUIRED_LABYRINTH_OAUTH_SCOPES.slice(0, 4),
			'space:blue.catbird.labyrinth.mailbox?manage=create&manage=delete',
			'space:blue.catbird.labyrinth.conversation?authority=*'
		]);
		assert.equal(oldScopeSession.eligible, false);
		assert.deepEqual(oldScopeSession.missingScopes, REQUIRED_LABYRINTH_OAUTH_SCOPES.slice(4));

		const eligible = evaluateSpacesGateForUi(true, [...REQUIRED_LABYRINTH_OAUTH_SCOPES]);
		assert.equal(eligible.eligible, true);
		assert.equal(eligible.missingScopes.length, 0);
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
	});

	it('routes browser chat XRPC directly to chat.catbird.blue with getServiceAuth and canonical UUIDv4 deviceId (D1, G3)', () => {
		const wasmTsPath = path.join(CATMOS_ROOT, 'src/lib/wasm.ts');
		const wasmTs = fs.readFileSync(wasmTsPath, 'utf8');
		assert.ok(
			!wasmTs.includes('#atproto_mls'),
			'wasm.ts must never send legacy #atproto_mls proxy headers through nest (D1)'
		);
		assert.ok(
			!wasmTs.includes('mlschat.catbird.blue'),
			'wasm.ts must target canonical chat.catbird.blue, never legacy mlschat.catbird.blue'
		);
		assert.ok(
			wasmTs.includes('com.atproto.server.getServiceAuth'),
			'wasm.ts must mint getServiceAuth JWTs for blue.catbird.chat.* calls'
		);
		assert.ok(
			wasmTs.includes('crypto.randomUUID().toLowerCase()'),
			'wasm.ts must generate canonical lowercase UUIDv4 deviceId'
		);
	});
});

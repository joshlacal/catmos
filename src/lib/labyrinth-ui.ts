/**
 * Labyrinth 1.1 & Spaces eligibility UI helpers (`I15`, `I16`, `ctl #2`, `modern-web-guidance: passkey-registration`).
 *
 * Enforces:
 * - `ctl #2`: Chat/Spaces off by default on fresh sign-in (zero DB opens, zero PDS/DS calls,
 *   and zero KeyPackage uploads until explicit user opt-in).
 * - `I15`: Spaces-required gate (`pdsSupportsSpaces` + `space:blob` + `repo:blue.catbird.chat.device`).
 * - WebAuthn capability probing via `PublicKeyCredential.getClientCapabilities()`.
 */

export const REQUIRED_LABYRINTH_OAUTH_SCOPES = [
	'atproto',
	'blob:*/*',
	'repo:blue.catbird.labyrinth.mailboxKeys',
	'repo:blue.catbird.chat.device',
	'space:blue.catbird.labyrinth.mailbox?manage=create&manage=delete',
	'space:blue.catbird.labyrinth.conversation?authority=*'
] as const;

export interface KeyValueStorageLike {
	getItem(key: string): string | null;
	setItem(key: string, value: string): void;
	removeItem(key: string): void;
}

export interface SpacesGateUiResult {
	eligible: boolean;
	missingScopes: string[];
	message: string;
}

export interface PasskeyPrfCapabilityResult {
	canRegisterPasskeyPrf: boolean;
	reason: string | null;
}

export interface PublicKeyCredentialStaticLike {
	getClientCapabilities?: () => Promise<Record<string, boolean | undefined>>;
	signalUnknownCredential?: (options: {
		rpId: string;
		credentialId: string;
	}) => Promise<void>;
}

function defaultPrefStorage(): KeyValueStorageLike | null {
	return typeof localStorage !== 'undefined' ? localStorage : null;
}

function optInPrefKey(did: string): string {
	return `catbird:mls_opted_in:${did.trim()}`;
}

/**
 * Returns `true` ONLY if the user has explicitly opted into encrypted Chat / Spaces
 * on this browser profile (`ctl #2`: always `false` on a fresh sign-in).
 */
export function isMlsOptedInForDid(
	did: string,
	storage: KeyValueStorageLike | null = defaultPrefStorage()
): boolean {
	const trimmed = did.trim();
	if (!trimmed || !storage) return false;
	return storage.getItem(optInPrefKey(trimmed)) === '1';
}

export function setMlsOptedInForDid(
	did: string,
	optedIn: boolean,
	storage: KeyValueStorageLike | null = defaultPrefStorage()
): void {
	const trimmed = did.trim();
	if (!trimmed || !storage) return;
	if (optedIn) {
		storage.setItem(optInPrefKey(trimmed), '1');
	} else {
		storage.removeItem(optInPrefKey(trimmed));
	}
}

/** Evaluate `I15` Spaces capability and required OAuth scopes for UI display. */
export function evaluateSpacesGateForUi(
	pdsSupportsSpaces: boolean,
	grantedScopes: readonly string[]
): SpacesGateUiResult {
	const scopeSet = new Set(grantedScopes.map((s) => s.trim()));
	const missingScopes = REQUIRED_LABYRINTH_OAUTH_SCOPES.filter((s) => !scopeSet.has(s));

	if (!pdsSupportsSpaces) {
		return {
			eligible: false,
			missingScopes,
			message:
				'Your Personal Data Server (PDS) does not advertise ATProto Spaces support yet. Encrypted Chat and Labyrinth history require a Spaces-enabled PDS.'
		};
	}

	if (missingScopes.length > 0) {
		return {
			eligible: false,
			missingScopes,
			message: `Grant required OAuth scopes (${missingScopes.join(', ')}) to enable Spaces-backed encrypted Chat.`
		};
	}

	return {
		eligible: true,
		missingScopes: [],
		message: 'Your PDS supports ATProto Spaces and all Labyrinth OAuth scopes are active.'
	};
}

/**
 * Feature-detect Passkey PRF platform support via `PublicKeyCredential.getClientCapabilities()`
 * per `modern-web-guidance: passkey-registration`.
 */
export async function detectPasskeyPrfCapability(
	pkc: PublicKeyCredentialStaticLike | undefined = typeof window !== 'undefined'
		? (
				window as unknown as {
					PublicKeyCredential?: PublicKeyCredentialStaticLike;
				}
			).PublicKeyCredential
		: undefined
): Promise<PasskeyPrfCapabilityResult> {
	if (!pkc || typeof pkc.getClientCapabilities !== 'function') {
		return {
			canRegisterPasskeyPrf: false,
			reason: 'This browser does not support WebAuthn client capability detection for Passkey PRF.'
		};
	}

	try {
		const caps = await pkc.getClientCapabilities();
		const hasPlatform = Boolean(caps.passkeyPlatformAuthenticator);
		const hasConditional = Boolean(caps.conditionalGet);
		if (!hasPlatform || !hasConditional) {
			return {
				canRegisterPasskeyPrf: false,
				reason:
					'A platform passkey authenticator with conditional mediation is unavailable on this device. Use a 40-character recovery code instead.'
			};
		}
		return {
			canRegisterPasskeyPrf: true,
			reason: null
		};
	} catch {
		return {
			canRegisterPasskeyPrf: false,
			reason: 'Unable to query platform passkey capabilities in this browser.'
		};
	}
}

/** Map WebAuthn `navigator.credentials.create` / `.get` exceptions to actionable guidance. */
export function mapWebAuthnErrorToMessage(err: unknown): string {
	const name =
		typeof err === 'object' && err !== null && 'name' in err
			? String((err as { name?: unknown }).name)
			: '';
	switch (name) {
		case 'InvalidStateError':
			return 'A Labyrinth passkey is already registered on this authenticator.';
		case 'NotAllowedError':
			return 'Passkey prompt was cancelled or denied.';
		case 'SecurityError':
			return 'Passkey registration requires a secure HTTPS origin matching the RP ID.';
		case 'AbortError':
			return 'Passkey ceremony was superseded by a newer request.';
		default:
			return err instanceof Error ? err.message : 'Passkey operation failed.';
	}
}

function bytesToBase64Url(bytes: Uint8Array): string {
	const bin = Array.from(bytes, (b) => String.fromCharCode(b)).join('');
	const b64 = typeof btoa === 'function' ? btoa(bin) : Buffer.from(bytes).toString('base64');
	return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

/** Notify platform password managers when a revoked passkey credential is no longer valid. */
export async function signalUnknownPasskeyCredential(
	rpId: string,
	credentialIdBytes: Uint8Array,
	pkc: PublicKeyCredentialStaticLike | undefined = typeof window !== 'undefined'
		? (
				window as unknown as {
					PublicKeyCredential?: PublicKeyCredentialStaticLike;
				}
			).PublicKeyCredential
		: undefined
): Promise<void> {
	if (pkc && typeof pkc.signalUnknownCredential === 'function') {
		await pkc.signalUnknownCredential({
			rpId,
			credentialId: bytesToBase64Url(credentialIdBytes)
		});
	}
}

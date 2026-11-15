/**
 * Labyrinth 1.1 & Spaces eligibility UI helpers (`I15`, `I16`, `ctl #2`, `modern-web-guidance: passkey-registration`).
 *
 * Enforces:
 * - `ctl #2`: Chat/Spaces off by default on fresh sign-in (zero DB opens, zero PDS/DS calls,
 *   and zero KeyPackage uploads until explicit user opt-in).
 * - `I15`: Spaces-required gate (`pdsSupportsSpaces` + explicit Space & create-only repo scopes).
 * - WebAuthn capability probing, Passkey PRF assertion restore, and multi-device self-revoke guards.
 */

import { normalizeAccountDid, tryNormalizeAccountDid } from './did.ts';

export const REQUIRED_LABYRINTH_OAUTH_SCOPES = [
	'atproto',
	'blob:*/*',
	'repo:blue.catbird.labyrinth.mailboxKeys',
	'repo:blue.catbird.chat.device?action=create',
	'repo:blue.catbird.chat.deviceRevocation?action=create',
	'space:blue.catbird.labyrinth.mailbox?action=create&action=delete&action=read&action=update&collection=blue.catbird.labyrinth.attachmentManifest&collection=blue.catbird.labyrinth.circleOwnerState&collection=blue.catbird.labyrinth.device&collection=blue.catbird.labyrinth.epoch&collection=blue.catbird.labyrinth.epochMember&collection=blue.catbird.labyrinth.otcSession&collection=blue.catbird.labyrinth.ownerBatch&collection=blue.catbird.labyrinth.readState&collection=blue.catbird.labyrinth.virtualDevice&manage=create&manage=delete',
	'space:blue.catbird.labyrinth.conversation?action=create&action=delete&action=read&action=update&authority=*&collection=blue.catbird.labyrinth.attachmentManifest&collection=blue.catbird.labyrinth.authorRedaction&collection=blue.catbird.labyrinth.batch&collection=blue.catbird.labyrinth.mek'
] as const;

export const UPGRADEABLE_LABYRINTH_OAUTH_SCOPES = REQUIRED_LABYRINTH_OAUTH_SCOPES.filter(
	(scope) => scope !== 'atproto'
);

export const LABYRINTH_PASSKEY_RP_ID = 'catbird.blue';
export const LABYRINTH_PRF_DOMAIN_PREFIX = 'catbird.labyrinth.passkey-recovery.v1:';

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

export type LabyrinthDeviceLifecycleState = 'active' | 'pending_approval' | 'dormant';

export interface LabyrinthDeviceEntryView {
	deviceId: string;
	deviceName: string;
	isCurrent: boolean;
	status: LabyrinthDeviceLifecycleState;
	lastActiveAt: string | null;
	dormantAt: string | null;
}

export interface SiblingBackfillSummary {
	state: 'idle' | 'syncing' | 'complete' | 'degraded';
	syncedBatchCount: number;
	totalBatchCount: number | null;
	lastSyncedAt: string | null;
	label: string;
}

export interface PasskeyPrfAssertionResult {
	credentialId: Uint8Array;
	prfOutput32: Uint8Array;
}

function defaultPrefStorage(): KeyValueStorageLike | null {
	return typeof localStorage !== 'undefined' ? localStorage : null;
}

function optInPrefKey(did: string): string {
	return `catbird:mls_opted_in:${tryNormalizeAccountDid(did)}`;
}

/**
 * Returns `true` ONLY if the user has explicitly opted into encrypted Chat / Spaces
 * on this browser profile (`ctl #2`: always `false` on a fresh sign-in).
 */
export function isMlsOptedInForDid(
	did: string,
	storage: KeyValueStorageLike | null = defaultPrefStorage()
): boolean {
	const trimmed = tryNormalizeAccountDid(did);
	if (!trimmed || !storage) return false;
	return storage.getItem(optInPrefKey(trimmed)) === '1';
}

export function setMlsOptedInForDid(
	did: string,
	optedIn: boolean,
	storage: KeyValueStorageLike | null = defaultPrefStorage()
): void {
	const trimmed = tryNormalizeAccountDid(did);
	if (!trimmed || !storage) return;
	if (optedIn) {
		storage.setItem(optInPrefKey(trimmed), '1');
	} else {
		storage.removeItem(optInPrefKey(trimmed));
	}
}

const VALID_REPO_RECORD_ACTIONS = new Set(['create', 'update', 'delete']);
const VALID_SPACE_RECORD_ACTIONS = new Set(['read', 'read_self', 'create', 'update', 'delete']);
const VALID_SPACE_MANAGE_ACTIONS = new Set(['create', 'update', 'delete']);
const VALID_NSID_COLLECTION_RE = /^[A-Za-z0-9.-]+$/;

function splitOnce(input: string, separator: string): [string, string | null] {
	const idx = input.indexOf(separator);
	if (idx < 0) return [input, null];
	return [input.slice(0, idx), input.slice(idx + separator.length)];
}

function repoScopeGranted(grantedScopes: readonly string[], required: string): boolean {
	const [reqBase, reqQuery] = splitOnce(required, '?');
	if (!reqBase.startsWith('repo:')) return false;
	const reqNsid = reqBase.slice('repo:'.length);
	if (!reqNsid) return false;

	let reqActions: string[];
	if (reqQuery !== null) {
		if (!reqQuery) return false;
		reqActions = [];
		for (const pair of reqQuery.split('&')) {
			const [key, val] = splitOnce(pair, '=');
			if (key !== 'action' || val === null || !VALID_REPO_RECORD_ACTIONS.has(val)) {
				return false;
			}
			reqActions.push(val);
		}
		if (reqActions.length === 0) return false;
	} else {
		reqActions = ['create', 'update', 'delete'];
	}

	return grantedScopes.some((rawGrant) => {
		const grant = rawGrant.trim();
		const [grantBase, grantQuery] = splitOnce(grant, '?');
		if (!grantBase.startsWith('repo:')) return false;

		const grantedCollections: string[] = [];
		const inlineCollection = grantBase.slice('repo:'.length);
		if (inlineCollection) {
			grantedCollections.push(inlineCollection);
		}

		const grantedActions: string[] = [];
		if (grantQuery !== null) {
			if (!grantQuery) return false;
			for (const pair of grantQuery.split('&')) {
				const [k, v] = splitOnce(pair, '=');
				if (!k || !v) return false;
				if (k === 'action' && VALID_REPO_RECORD_ACTIONS.has(v)) {
					grantedActions.push(v);
				} else if (
					k === 'collection' &&
					(v === '*' || VALID_NSID_COLLECTION_RE.test(v))
				) {
					grantedCollections.push(v);
				} else {
					return false;
				}
			}
		}

		if (grantedCollections.length === 0) return false;
		const collectionMatches =
			grantedCollections.includes('*') || grantedCollections.includes(reqNsid);
		if (!collectionMatches) return false;

		if (grantedActions.length === 0) {
			// Unparameterized `repo:<nsid>`, `repo:*`, or `repo:?collection=*` grants create, update, and delete.
			return true;
		}
		return reqActions.every((reqAction) => grantedActions.includes(reqAction));
	});
}

/**
 * Evaluate whether `required` OAuth scope is satisfied by `grantedScopes` using
 * query-parameter subsumption matching `catbird-mls/src/client/spaces_gate.rs`.
 */
export function scopeGranted(
	grantedScopes: readonly string[],
	required: string,
	accountDid = ''
): boolean {
	if (required.startsWith('repo:')) {
		return repoScopeGranted(grantedScopes, required);
	}

	const [family, requiredQuery] = splitOnce(required, '?');
	if (family.startsWith('space:') && requiredQuery !== null) {
		const requiredPairs: Array<[string, string]> = [];
		for (const pair of requiredQuery.split('&')) {
			const [rk, rv] = splitOnce(pair, '=');
			if (rk && rv !== null) {
				requiredPairs.push([rk, rv]);
			}
		}
		const canonicalAccountDid = tryNormalizeAccountDid(accountDid);

		return grantedScopes.some((rawGrant) => {
			const [grantedFamily, query] = splitOnce(rawGrant.trim(), '?');
			if (query === null || !query || grantedFamily !== family) return false;

			const params: Array<[string, string]> = [];
			let authority: string | null = null;
			let skey: string | null = null;

			for (const pair of query.split('&')) {
				const [key, value] = splitOnce(pair, '=');
				if (!key || !value) return false;
				if (key === 'authority') {
					if (authority !== null) return false;
					authority = value;
				} else if (key === 'skey') {
					if (skey !== null) return false;
					skey = value;
				} else if (key === 'collection') {
					if (value !== '*' && !VALID_NSID_COLLECTION_RE.test(value)) return false;
				} else if (key === 'action') {
					if (!VALID_SPACE_RECORD_ACTIONS.has(value)) return false;
				} else if (key === 'manage') {
					if (!VALID_SPACE_MANAGE_ACTIONS.has(value)) return false;
				} else {
					return false;
				}
				params.push([key, value]);
			}

			const effectiveAuthority = authority ?? 'self';
			const anyAuthority = requiredPairs.some(
				([reqKey, reqVal]) => reqKey === 'authority' && reqVal === '*'
			);
			const authorityMatches = anyAuthority
				? effectiveAuthority === '*'
				: effectiveAuthority === 'self' ||
					effectiveAuthority === '*' ||
					(canonicalAccountDid !== '' &&
						tryNormalizeAccountDid(effectiveAuthority) === canonicalAccountDid);
			if (!authorityMatches) return false;

			const personal = family === 'space:blue.catbird.labyrinth.mailbox';
			if (skey !== null && skey !== '*' && !(personal && skey === 'self')) {
				return false;
			}

			return requiredPairs.every(
				([reqKey, reqVal]) =>
					reqKey === 'authority' ||
					params.some(([pk, pv]) => pk === reqKey && pv === reqVal) ||
					(reqKey === 'collection' &&
						params.some(([pk, pv]) => pk === 'collection' && pv === '*'))
			);
		});
	}

	return grantedScopes.some((rawGrant) => {
		const grant = rawGrant.trim();
		return (
			grant === required ||
			(required === 'atproto' && grant === 'transition:generic') ||
			(required.startsWith('blob:') && grant === 'blob:*/*')
		);
	});
}

/**
 * Normalize requested scopes for `POST /auth/upgrade` (`additional_scopes`),
 * excluding `'atproto'` (which `nest` carries forward from the active session).
 */
export function buildUpgradeAdditionalScopes(
	requestedScopes: readonly string[] = REQUIRED_LABYRINTH_OAUTH_SCOPES
): string[] {
	const deduped: string[] = [];
	const seen = new Set<string>();
	for (const raw of requestedScopes) {
		const trimmed = raw.trim();
		if (!trimmed || trimmed === 'atproto' || seen.has(trimmed)) continue;
		seen.add(trimmed);
		deduped.push(trimmed);
	}
	return deduped;
}

/** Evaluate `I15` Spaces capability and required OAuth scopes for UI display. */
export function evaluateSpacesGateForUi(
	pdsSupportsSpaces: boolean,
	grantedScopes: readonly string[],
	accountDid = ''
): SpacesGateUiResult {
	const normalizedGrants = grantedScopes.map((s) => s.trim()).filter(Boolean);
	const missingScopes = REQUIRED_LABYRINTH_OAUTH_SCOPES.filter(
		(required) => !scopeGranted(normalizedGrants, required, accountDid)
	);

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
 * Resolve the WebAuthn Relying Party ID so passkeys created on `catmos.catbird.blue`
 * share `rpId = "catbird.blue"` with iOS and Android synced passkeys, while remaining
 * valid on local development hosts (`localhost` / `127.0.0.1`).
 */
export function resolveLabyrinthPasskeyRpId(hostname?: string | null): string {
	const cleaned = typeof hostname === 'string' ? hostname.trim().toLowerCase() : '';
	if (!cleaned || cleaned === LABYRINTH_PASSKEY_RP_ID || cleaned.endsWith(`.${LABYRINTH_PASSKEY_RP_ID}`)) {
		return LABYRINTH_PASSKEY_RP_ID;
	}
	return cleaned;
}

/**
 * Derive the deterministic 32-byte WebAuthn `user.id` (`SHA-256(canonicalDid)`),
 * matching Android `LabyrinthPasskeyManager.buildCreatePublicKeyCredentialRequestJson`.
 */
export async function deriveLabyrinthPasskeyUserId(did: string): Promise<Uint8Array> {
	const canonicalDid = normalizeAccountDid(did);
	const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonicalDid));
	return new Uint8Array(digest);
}

/**
 * Derive the deterministic 32-byte WebAuthn PRF evaluation salt
 * (`SHA-256("catbird.labyrinth.passkey-recovery.v1:" + canonicalDid)`),
 * matching iOS `LabyrinthSettingsAndRestoreView.swift` and Android `LabyrinthPasskeyManager.kt`.
 */
export async function deriveLabyrinthPrfSalt(did: string): Promise<Uint8Array> {
	const canonicalDid = normalizeAccountDid(did);
	const digest = await crypto.subtle.digest(
		'SHA-256',
		new TextEncoder().encode(`${LABYRINTH_PRF_DOMAIN_PREFIX}${canonicalDid}`)
	);
	return new Uint8Array(digest);
}

/**
 * Execute a WebAuthn `navigator.credentials.get` PRF assertion ceremony to
 * recover the 32-byte Labyrinth PRF secret for an existing passkey wrap.
 */
export async function performPasskeyPrfAssertion(params: {
	did: string;
	rpId?: string;
	allowCredentialIds?: readonly Uint8Array[];
	credentialsContainer?: {
		get: (options: CredentialRequestOptions) => Promise<Credential | null>;
	};
}): Promise<PasskeyPrfAssertionResult> {
	const container =
		params.credentialsContainer ??
		(typeof navigator !== 'undefined' ? navigator.credentials : undefined);
	if (!container || typeof container.get !== 'function') {
		throw new Error('WebAuthn credentials API is unavailable in this environment.');
	}

	const prfSalt = await deriveLabyrinthPrfSalt(params.did);
	const challenge = crypto.getRandomValues(new Uint8Array(32));
	const rpId =
		params.rpId ??
		resolveLabyrinthPasskeyRpId(
			typeof window !== 'undefined' ? window.location?.hostname : undefined
		);

	const allowCredentials: PublicKeyCredentialDescriptor[] | undefined =
		params.allowCredentialIds && params.allowCredentialIds.length > 0
			? params.allowCredentialIds.map((id) => ({
					type: 'public-key' as const,
					id: new Uint8Array(id) as BufferSource
				}))
			: undefined;

	const assertion = (await container.get({
		publicKey: {
			challenge: challenge as BufferSource,
			rpId,
			userVerification: 'required',
			allowCredentials,
			extensions: {
				prf: {
					eval: {
						first: prfSalt as BufferSource
					}
				}
			} as AuthenticationExtensionsClientInputs
		}
	})) as PublicKeyCredential | null;

	if (!assertion) {
		throw new Error('Passkey verification returned no credential.');
	}

	const ext = assertion.getClientExtensionResults() as {
		prf?: { results?: { first?: BufferSource } };
	};
	const firstOut = ext.prf?.results?.first;
	if (!firstOut) {
		throw new Error(
			'This authenticator did not return a 32-byte WebAuthn PRF output. Restore with your 40-character recovery code instead.'
		);
	}

	const prfOutput32 =
		firstOut instanceof ArrayBuffer
			? new Uint8Array(firstOut)
			: ArrayBuffer.isView(firstOut)
				? new Uint8Array(firstOut.buffer, firstOut.byteOffset, firstOut.byteLength)
				: new Uint8Array(0);
	if (prfOutput32.byteLength !== 32) {
		throw new Error(`Invalid Passkey PRF output length (${prfOutput32.byteLength}); expected 32 bytes.`);
	}

	return {
		credentialId: new Uint8Array(assertion.rawId),
		prfOutput32
	};
}

export function isCurrentLabyrinthDevice(
	deviceId: string | null | undefined,
	currentDeviceId: string | null | undefined
): boolean {
	const left = (deviceId ?? '').trim().toLowerCase();
	const right = (currentDeviceId ?? '').trim().toLowerCase();
	if (!left || !right) return false;
	return left === right;
}

export function assertCanRevokeLabyrinthDevice(
	targetDeviceId: string,
	currentDeviceId: string | null | undefined
): void {
	const trimmedTarget = (targetDeviceId ?? '').trim();
	if (!trimmedTarget) {
		throw new Error('Target device identifier is required for revocation.');
	}
	if (isCurrentLabyrinthDevice(trimmedTarget, currentDeviceId)) {
		throw new Error('Cannot revoke this device from itself; sign out to retire this device instead.');
	}
}

function coerceOptionalIsoTimestamp(value: unknown): string | null {
	if (typeof value === 'string' && value.trim()) {
		return value.trim();
	}
	if (typeof value === 'number' && Number.isFinite(value) && value > 0) {
		const ms = value > 1e12 ? value : value * 1000;
		return new Date(ms).toISOString();
	}
	return null;
}

export function normalizeLabyrinthDeviceList(
	rawStatus: unknown,
	currentDeviceId: string | null | undefined
): LabyrinthDeviceEntryView[] {
	if (typeof rawStatus !== 'object' || rawStatus === null) return [];
	const statusObj = rawStatus as Record<string, unknown>;
	const byId = new Map<string, LabyrinthDeviceEntryView>();

	const rawDevices = Array.isArray(statusObj.devices) ? statusObj.devices : [];
	for (const item of rawDevices) {
		if (typeof item !== 'object' || item === null) continue;
		const rec = item as Record<string, unknown>;
		const deviceId = String(rec.device_id ?? rec.deviceId ?? '').trim();
		if (!deviceId) continue;
		const rawName = String(rec.device_name ?? rec.deviceName ?? '').trim();
		const isCurrent =
			Boolean(rec.is_current ?? rec.isCurrent) ||
			isCurrentLabyrinthDevice(deviceId, currentDeviceId);
		const dormantAt = coerceOptionalIsoTimestamp(rec.dormant_at ?? rec.dormantAt);
		const lastActiveAt = coerceOptionalIsoTimestamp(rec.last_active_at ?? rec.lastActiveAt);
		const rawLifecycle = String(rec.status ?? rec.state ?? '').trim().toLowerCase();
		const isPending =
			Boolean(rec.pending_approval ?? rec.pendingApproval) ||
			rawLifecycle === 'pending_approval' ||
			rawLifecycle === 'pending';
		const lifecycle: LabyrinthDeviceLifecycleState = isPending
			? 'pending_approval'
			: dormantAt || rawLifecycle === 'dormant'
				? 'dormant'
				: 'active';

		byId.set(deviceId.toLowerCase(), {
			deviceId,
			deviceName: rawName || (isCurrent ? 'Current Browser / App' : `Device ${deviceId.slice(0, 8)}`),
			isCurrent,
			status: lifecycle,
			lastActiveAt,
			dormantAt
		});
	}

	const activeIds = Array.isArray(statusObj.active_device_ids) ? statusObj.active_device_ids : [];
	for (const rawId of activeIds) {
		const deviceId = String(rawId ?? '').trim();
		if (!deviceId) continue;
		const key = deviceId.toLowerCase();
		if (byId.has(key)) continue;
		const isCurrent = isCurrentLabyrinthDevice(deviceId, currentDeviceId);
		byId.set(key, {
			deviceId,
			deviceName: isCurrent ? 'Current Browser / App' : `Device ${deviceId.slice(0, 8)}`,
			isCurrent,
			status: 'active',
			lastActiveAt: null,
			dormantAt: null
		});
	}

	const pendingIds = Array.isArray(statusObj.pending_device_ids) ? statusObj.pending_device_ids : [];
	for (const rawId of pendingIds) {
		const deviceId = String(rawId ?? '').trim();
		if (!deviceId) continue;
		const key = deviceId.toLowerCase();
		const isCurrent = isCurrentLabyrinthDevice(deviceId, currentDeviceId);
		const existing = byId.get(key);
		byId.set(key, {
			deviceId,
			deviceName:
				existing?.deviceName ??
				(isCurrent ? 'Current Browser / App' : `Device ${deviceId.slice(0, 8)}`),
			isCurrent,
			status: 'pending_approval',
			lastActiveAt: existing?.lastActiveAt ?? null,
			dormantAt: existing?.dormantAt ?? null
		});
	}

	const entries = Array.from(byId.values());
	entries.sort((a, b) => {
		if (a.isCurrent !== b.isCurrent) return a.isCurrent ? -1 : 1;
		if (a.status !== b.status) {
			if (a.status === 'pending_approval') return -1;
			if (b.status === 'pending_approval') return 1;
		}
		return a.deviceId.localeCompare(b.deviceId);
	});
	return entries;
}

export function deriveSiblingBackfillSummary(rawStatus: unknown): SiblingBackfillSummary {
	if (typeof rawStatus !== 'object' || rawStatus === null) {
		return {
			state: 'idle',
			syncedBatchCount: 0,
			totalBatchCount: null,
			lastSyncedAt: null,
			label: 'Not started'
		};
	}
	const statusObj = rawStatus as Record<string, unknown>;
	const backfillObj =
		typeof statusObj.backfill === 'object' && statusObj.backfill !== null
			? (statusObj.backfill as Record<string, unknown>)
			: statusObj;

	const rawState = String(
		backfillObj.state ?? backfillObj.backfill_state ?? backfillObj.backfillState ?? ''
	)
		.trim()
		.toLowerCase();
	const syncedBatchCount = Math.max(
		0,
		Number(
			backfillObj.synced_batches ??
				backfillObj.syncedBatches ??
				backfillObj.backfill_synced_batches ??
				0
		) || 0
	);
	const rawTotal =
		backfillObj.total_batches ??
		backfillObj.totalBatches ??
		backfillObj.backfill_total_batches ??
		null;
	const totalBatchCount =
		rawTotal !== null && rawTotal !== undefined && Number.isFinite(Number(rawTotal))
			? Math.max(syncedBatchCount, Number(rawTotal))
			: null;
	const lastSyncedAt = coerceOptionalIsoTimestamp(
		backfillObj.last_synced_at ??
			backfillObj.lastSyncedAt ??
			statusObj.last_backfill_at ??
			statusObj.lastBackfillAt
	);

	if (rawState === 'syncing' || rawState === 'in_progress' || rawState === 'running') {
		const progress =
			totalBatchCount !== null
				? `${syncedBatchCount} / ${totalBatchCount} batches`
				: `${syncedBatchCount} batches`;
		return {
			state: 'syncing',
			syncedBatchCount,
			totalBatchCount,
			lastSyncedAt,
			label: `Backfilling sibling Space history (${progress})`
		};
	}

	if (rawState === 'degraded' || rawState === 'error' || rawState === 'failed') {
		return {
			state: 'degraded',
			syncedBatchCount,
			totalBatchCount,
			lastSyncedAt,
			label: 'Backfill paused — retry to pull remaining sibling Space batches'
		};
	}

	if (
		rawState === 'complete' ||
		rawState === 'up_to_date' ||
		Boolean(statusObj.enrolled)
	) {
		return {
			state: 'complete',
			syncedBatchCount,
			totalBatchCount,
			lastSyncedAt,
			label:
				syncedBatchCount > 0
					? `Up to date (${syncedBatchCount} history batches verified)`
					: 'Up to date with Labyrinth Space'
		};
	}

	return {
		state: 'idle',
		syncedBatchCount,
		totalBatchCount,
		lastSyncedAt,
		label: 'Waiting for Labyrinth enrollment'
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
			return 'Passkey operation requires a secure HTTPS origin matching the RP ID.';
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

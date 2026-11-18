<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { auth } from '#lib/stores/auth.ts';
	import { normalizeAccountDid, tryNormalizeAccountDid } from '#lib/did.ts';
	import {
		approveLabyrinthSiblingDevice,
		completeLabyrinthOtcPairing,
		enableMlsAndEnroll,
		getCurrentLabyrinthDeviceId,
		getLabyrinthStatus,
		initiateLabyrinthOtcPairing,
		isLabyrinthDevicePendingApproval,
		isTauri,
		listRegisteredLabyrinthDevices,
		probePdsSpacesSupport,
		registerLabyrinthPasskeyPrf,
		respondLiveLabyrinthOtcPairing,
		restoreWithLabyrinthPasskeyPrf,
		restoreWithLabyrinthRecoveryCode,
		revokeRegisteredLabyrinthDeviceLive,
		setupLabyrinthRecoveryCode,
		startLiveLabyrinthOtcPairing,
		syncLabyrinthBackfill,
		verifyAndReindexLabyrinthHistory,
		type LabyrinthBackupStatusView,
		type LiveOtcInitiationView,
		type OtcPairingOfferView
	} from '#lib/wasm.ts';
	import {
		assertCanRevokeLabyrinthDevice,
		createLabyrinthPasskeyUserId,
		deriveLabyrinthPrfSalt,
		deriveSiblingBackfillSummary,
		detectPasskeyPrfCapability,
		evaluateSpacesGateForUi,
		isMlsOptedInForDid,
		mapWebAuthnErrorToMessage,
		normalizeLabyrinthDeviceList,
		performPasskeyPrfAssertion,
		REQUIRED_LABYRINTH_OAUTH_SCOPES,
		resolveLabyrinthPasskeyRpId,
		requireBackupEligiblePasskey,
		setMlsOptedInForDid
	} from '#lib/labyrinth-ui.ts';

	const activeDid = $derived($auth.user?.did ? tryNormalizeAccountDid($auth.user.did) : null);

	let pdsSupportsSpaces = $state(false);
	let probingPds = $state(false);
	const grantedScopes = $derived($auth.user?.grantedScopes ?? []);
	const spacesGate = $derived(
		evaluateSpacesGateForUi(pdsSupportsSpaces, grantedScopes, activeDid ?? '')
	);

	let optedIn = $state(false);
	let status = $state<LabyrinthBackupStatusView | null>(null);
	let currentDeviceId = $state<string | null>(null);
	let displayedCode = $state<{ did: string; code: string } | null>(null);
	const generatedRecoveryCode = $derived(displayedCode?.did === activeDid ? displayedCode?.code : null);
	let restoreCodeInput = $state('');
	let otcOffer = $state<OtcPairingOfferView | null>(null);
	let liveOtcSession = $state<LiveOtcInitiationView | null>(null);
	let otcInput = $state('');
	let otcResponderSessionId = $state('');
	let otcResponderCode = $state('');
	let reindexConversationId = $state('');
	let devicePendingApproval = $state(false);
	let canRegisterPasskeyPrf = $state(false);
	let passkeyReason = $state<string | null>(null);
	const preferPasskey = $derived(canRegisterPasskeyPrf && (!isTauri || (status?.active_device_ids.length ?? 0) > 1));
	let statusBanner = $state<string | null>(null);
	let errorBanner = $state<string | null>(null);
	let busy = $state(false);
	let initializedForDid = $state<string | null>(null);
	let accountSession = 0;

	let pendingRevokeDeviceId = $state<string | null>(null);
	let revokeDialogEl: HTMLDialogElement | undefined = $state(undefined);
	let deleteAccountDialogEl: HTMLDialogElement | undefined = $state(undefined);

	const effectiveCurrentDeviceId = $derived(status?.current_device_id ?? currentDeviceId);
	const devices = $derived(normalizeLabyrinthDeviceList(status, effectiveCurrentDeviceId));
	const currentDeviceEntry = $derived(devices.find((d) => d.isCurrent) ?? null);
	const backfillSummary = $derived(deriveSiblingBackfillSummary(status));

	function requireAuthenticatedDid(): string {
		if (!activeDid) {
			throw new Error('Sign in with your AT Protocol account to manage Labyrinth Backup.');
		}
		return normalizeAccountDid(activeDid);
	}

	async function applyAccountStatus(did: string, session: number, next: LabyrinthBackupStatusView | null) {
		if (activeDid !== did || session !== accountSession) return false;
		const device = await getCurrentLabyrinthDeviceId(did);
		if (activeDid !== did || session !== accountSession) return false;
		status = next;
		currentDeviceId = device;
		return true;
	}

	async function refreshDeviceIdentityAndStatus(did: string) {
		const session = accountSession;
		const nextDeviceId = await getCurrentLabyrinthDeviceId(did);
		const nextStatus = await getLabyrinthStatus(did);
		let pendingApproval = false;
		try {
			pendingApproval = await isLabyrinthDevicePendingApproval(did);
		} catch {
			pendingApproval = false;
		}
		if (nextStatus) {
			try {
				const liveDevices = await listRegisteredLabyrinthDevices(did);
				if (Array.isArray(liveDevices) && liveDevices.length > 0) {
					nextStatus.devices = liveDevices;
				}
			} catch {
				// Keep local status snapshot when offline
			}
		}
		if (activeDid !== did || session !== accountSession) return;
		currentDeviceId = nextDeviceId;
		devicePendingApproval = pendingApproval;
		status = nextStatus;
	}

	async function loadAccountLabyrinthState(did: string) {
		probingPds = true;
		const session = accountSession;
		try {
			const supported = await probePdsSpacesSupport();
			if (activeDid !== did || session !== accountSession) return;
			pdsSupportsSpaces = supported;
		} catch (err) {
			if (activeDid === did && session === accountSession) errorBanner = String(err);
			return;
		} finally {
			if (activeDid === did && session === accountSession) probingPds = false;
		}
		optedIn = isMlsOptedInForDid(did);
		if (optedIn) {
			try {
				await refreshDeviceIdentityAndStatus(did);
			} catch (err) {
				errorBanner = err instanceof Error ? err.message : String(err);
			}
		} else {
			status = null;
			currentDeviceId = null;
		}
	}

	onMount(async () => {
		const prfCap = await detectPasskeyPrfCapability();
		canRegisterPasskeyPrf = prfCap.canRegisterPasskeyPrf;
		passkeyReason = prfCap.reason;

		if (!activeDid && !$auth.loading) {
			await auth.tryRestore();
		}
	});

	$effect(() => {
		const did = activeDid;
		if (initializedForDid !== did) {
			accountSession += 1;
			displayedCode = null;
			otcOffer = null;
			liveOtcSession = null;
			otcInput = '';
			otcResponderSessionId = '';
			otcResponderCode = '';
			restoreCodeInput = '';
			reindexConversationId = '';
			pendingRevokeDeviceId = null;
			currentDeviceId = null;
			devicePendingApproval = false;
			pdsSupportsSpaces = false;
			optedIn = false;
			status = null;
			errorBanner = null;
			statusBanner = null;
		}
		if (!did) {
			initializedForDid = null;
			pdsSupportsSpaces = false;
			optedIn = false;
			status = null;
			currentDeviceId = null;
			return;
		}
		if (initializedForDid !== did) {
			initializedForDid = did;
			void loadAccountLabyrinthState(did);
		}
	});

	function formatDeviceTimestamp(iso: string | null): string {
		if (!iso) return '—';
		const parsed = new Date(iso);
		if (Number.isNaN(parsed.getTime())) return iso;
		return parsed.toLocaleString();
	}

	async function handleUpgradeScopes() {
		busy = true;
		errorBanner = null;
		statusBanner = null;
		try {
			requireAuthenticatedDid();
			const targetScopes =
				spacesGate.missingScopes.length > 0
					? spacesGate.missingScopes
					: REQUIRED_LABYRINTH_OAUTH_SCOPES;
			await auth.upgradeScopes(targetScopes, '/settings/labyrinth');
		} catch (err) {
			errorBanner = err instanceof Error ? err.message : String(err);
		} finally {
			busy = false;
		}
	}

	async function handleOptInAndEnroll() {
		if (!spacesGate.eligible) {
			errorBanner = spacesGate.message;
			return;
		}
		const session = accountSession;
		busy = true;
		errorBanner = null;
		statusBanner = null;
		let did = '';
		try {
			did = requireAuthenticatedDid();
			const nextStatus = await enableMlsAndEnroll(did, pdsSupportsSpaces, grantedScopes);
			if (!await applyAccountStatus(did, session, nextStatus)) return;
			optedIn = true;
			statusBanner = 'Encrypted Chat and Labyrinth 1.1 Spaces history enabled on this device.';
		} catch (err) {
			if (session !== accountSession) return;
			if (did) {
				setMlsOptedInForDid(did, false);
			}
			optedIn = false;
			errorBanner = err instanceof Error ? err.message : String(err);
		} finally {
			busy = false;
		}
	}

	async function handleSyncBackfillNow() {
		const session = accountSession;
		busy = true;
		errorBanner = null;
		try {
			const did = requireAuthenticatedDid();
			const nextStatus = await syncLabyrinthBackfill(did);
			if (!await applyAccountStatus(did, session, nextStatus)) return;
			statusBanner = 'Synchronized sibling Space history batches.';
		} catch (err) {
			if (session !== accountSession) return;
			errorBanner = err instanceof Error ? err.message : String(err);
		} finally {
			busy = false;
		}
	}

	async function handleGenerateRecoveryCode() {
		busy = true;
		errorBanner = null;
		try {
			const did = requireAuthenticatedDid();
			const session = accountSession;
			displayedCode = null;
			const code = await setupLabyrinthRecoveryCode(did);
			if (activeDid !== did || session !== accountSession) return;
			displayedCode = { did, code };
			await refreshDeviceIdentityAndStatus(did);
			statusBanner = '40-character GF(32) recovery code bound to your Labyrinth virtual device.';
		} catch (err) {
			errorBanner = err instanceof Error ? err.message : String(err);
		} finally {
			busy = false;
		}
	}

	async function handleRestoreRecoveryCode(event: SubmitEvent) {
		event.preventDefault();
		if (!restoreCodeInput.trim()) return;
		const session = accountSession;
		busy = true;
		errorBanner = null;
		try {
			const did = requireAuthenticatedDid();
			const nextStatus = await restoreWithLabyrinthRecoveryCode(did, restoreCodeInput.trim());
			if (!await applyAccountStatus(did, session, nextStatus)) return;
			restoreCodeInput = '';
			statusBanner = `Restored Labyrinth mailbox and rotated to epoch ${nextStatus.epoch_seq}.`;
		} catch (err) {
			if (session !== accountSession) return;
			errorBanner = err instanceof Error ? err.message : String(err);
		} finally {
			busy = false;
		}
	}

	async function handleRegisterPasskeyPrf() {
		const session = accountSession;
		busy = true;
		errorBanner = null;
		try {
			const canonicalDid = requireAuthenticatedDid();
			const challenge = crypto.getRandomValues(new Uint8Array(32));
			const prfSalt = await deriveLabyrinthPrfSalt(canonicalDid);
			const userId = createLabyrinthPasskeyUserId();
			const rpId = resolveLabyrinthPasskeyRpId(
				typeof window !== 'undefined' ? window.location.hostname : undefined
			);

			const cred = (await navigator.credentials.create({
				publicKey: {
					challenge: challenge as BufferSource,
					rp: { name: 'Catbird', id: rpId },
					user: {
						id: userId as BufferSource,
						name: canonicalDid,
						displayName: $auth.user?.displayName ?? $auth.user?.handle ?? canonicalDid
					},
					pubKeyCredParams: [
						{ alg: -7, type: 'public-key' },
						{ alg: -8, type: 'public-key' },
						{ alg: -257, type: 'public-key' }
					],
					authenticatorSelection: {
						authenticatorAttachment: 'platform',
						residentKey: 'required',
						userVerification: 'required'
					},
					extensions: {
						prf: {
							eval: {
								first: prfSalt as BufferSource
							}
						}
					} as AuthenticationExtensionsClientInputs
				}
			})) as PublicKeyCredential | null;

			if (!cred) {
				throw new Error('Passkey registration returned null credential.');
			}

			await requireBackupEligiblePasskey(
				(cred.response as AuthenticatorAttestationResponse).getAuthenticatorData?.(), rpId, 'registration'
			);
			const ext = cred.getClientExtensionResults() as {
				prf?: { results?: { first?: ArrayBuffer } };
			};
			const prfBytes = ext.prf?.results?.first
				? new Uint8Array(ext.prf.results.first)
				: null;
			if (!prfBytes || prfBytes.byteLength !== 32) {
				throw new Error(
					'Platform authenticator did not return a 32-byte WebAuthn PRF evaluation.'
				);
			}

			if (activeDid !== canonicalDid || session !== accountSession) return;
			const nextStatus = await registerLabyrinthPasskeyPrf(
				canonicalDid,
				new Uint8Array(cred.rawId),
				prfBytes
			);
			if (!await applyAccountStatus(canonicalDid, session, nextStatus)) return;
			statusBanner = 'Passkey PRF bound to your Labyrinth recovery keyring.';
		} catch (err) {
			if (session !== accountSession) return;
			errorBanner = mapWebAuthnErrorToMessage(err);
		} finally {
			busy = false;
		}
	}

	async function handleRestorePasskeyPrf() {
		const session = accountSession;
		busy = true;
		errorBanner = null;
		try {
			const canonicalDid = requireAuthenticatedDid();
			const { credentialId, prfOutput32 } = await performPasskeyPrfAssertion({
				did: canonicalDid
			});
			if (activeDid !== canonicalDid || session !== accountSession) return;
			const nextStatus = await restoreWithLabyrinthPasskeyPrf(canonicalDid, credentialId, prfOutput32);
			if (!await applyAccountStatus(canonicalDid, session, nextStatus)) return;
			statusBanner = `Restored Labyrinth mailbox via Passkey PRF (epoch ${nextStatus.epoch_seq}).`;
		} catch (err) {
			if (session !== accountSession) return;
			errorBanner = mapWebAuthnErrorToMessage(err);
		} finally {
			busy = false;
		}
	}

	async function handleOfferOtc() {
		busy = true;
		errorBanner = null;
		try {
			const did = requireAuthenticatedDid();
			const session = accountSession;
			const offer = await initiateLabyrinthOtcPairing(did);
			if (activeDid !== did || session !== accountSession) return;
			otcOffer = offer;
			try {
				const started = await startLiveLabyrinthOtcPairing(did, offer.six_digit_code);
				if (activeDid !== did || session !== accountSession) return;
				liveOtcSession = started;
				otcOffer = {
					six_digit_code: started.six_digit_code,
					formatted_code: started.formatted_code
				};
				otcInput = started.six_digit_code;
			} catch {
				if (activeDid === did && session === accountSession) liveOtcSession = null;
			}
		} catch (err) {
			errorBanner = err instanceof Error ? err.message : String(err);
		} finally {
			busy = false;
		}
	}

	async function handleRespondLiveOtc(event: SubmitEvent) {
		event.preventDefault();
		if (!otcResponderSessionId.trim() || !otcResponderCode.trim()) return;
		busy = true;
		errorBanner = null;
		try {
			const did = requireAuthenticatedDid();
			await respondLiveLabyrinthOtcPairing(
				did,
				otcResponderSessionId.trim(),
				otcResponderCode.trim()
			);
			await refreshDeviceIdentityAndStatus(did);
			otcResponderSessionId = '';
			otcResponderCode = '';
			statusBanner = 'Submitted post-quantum OTC pairing response to your OwnerMailbox.';
		} catch (err) {
			errorBanner = err instanceof Error ? err.message : String(err);
		} finally {
			busy = false;
		}
	}

	async function handleVerifyAndReindexHistory(event: SubmitEvent) {
		event.preventDefault();
		if (!reindexConversationId.trim()) return;
		busy = true;
		errorBanner = null;
		try {
			const did = requireAuthenticatedDid();
			const targetConvo = reindexConversationId.trim();
			const reindexed = await verifyAndReindexLabyrinthHistory(did, targetConvo);
			await refreshDeviceIdentityAndStatus(did);
			reindexConversationId = '';
			statusBanner = `Verified and re-indexed ${reindexed} message(s) for conversation ${targetConvo}.`;
		} catch (err) {
			errorBanner = err instanceof Error ? err.message : String(err);
		} finally {
			busy = false;
		}
	}

	async function handleCompleteOtc(event: SubmitEvent) {
		event.preventDefault();
		if (!otcInput.trim()) return;
		busy = true;
		errorBanner = null;
		try {
			const did = requireAuthenticatedDid();
			const res = await completeLabyrinthOtcPairing(did, otcInput.trim());
			await refreshDeviceIdentityAndStatus(did);
			otcInput = '';
			statusBanner = `Completed hybrid PQ CPace + ML-KEM-768 pairing (epoch ${res.new_epoch_seq}).`;
		} catch (err) {
			errorBanner = err instanceof Error ? err.message : String(err);
		} finally {
			busy = false;
		}
	}

	async function handleApproveSiblingDevice(deviceId: string) {
		const session = accountSession;
		busy = true;
		errorBanner = null;
		try {
			const did = requireAuthenticatedDid();
			const nextStatus = await approveLabyrinthSiblingDevice(did, deviceId);
			if (!await applyAccountStatus(did, session, nextStatus)) return;
			statusBanner = `Approved device ${deviceId} and shared mailbox epoch ${nextStatus.epoch_seq}.`;
		} catch (err) {
			if (session !== accountSession) return;
			errorBanner = err instanceof Error ? err.message : String(err);
		} finally {
			busy = false;
		}
	}

	function promptRevokeDevice(deviceId: string) {
		try {
			assertCanRevokeLabyrinthDevice(deviceId, effectiveCurrentDeviceId);
		} catch (err) {
			errorBanner = err instanceof Error ? err.message : String(err);
			return;
		}
		pendingRevokeDeviceId = deviceId;
		revokeDialogEl?.showModal();
	}

	async function handleRevokeDialogClose() {
		if (revokeDialogEl?.returnValue !== 'confirm' || !pendingRevokeDeviceId) {
			pendingRevokeDeviceId = null;
			return;
		}
		const target = pendingRevokeDeviceId;
		pendingRevokeDeviceId = null;
		busy = true;
		errorBanner = null;
		try {
			const did = requireAuthenticatedDid();
			const session = accountSession;
			assertCanRevokeLabyrinthDevice(target, effectiveCurrentDeviceId);
			displayedCode = null;
			const report = await revokeRegisteredLabyrinthDeviceLive(did, target);
			if (activeDid !== did || session !== accountSession) return;
			if (report.rekeyed_recovery_code) displayedCode = { did, code: report.rekeyed_recovery_code };
			await refreshDeviceIdentityAndStatus(did);
			if (activeDid === did) {
				statusBanner = report.labyrinth_rotated
					? `Revoked device ${target} and rotated the backup keys.`
					: `Revoked device ${target}.`;
			}
		} catch (err) {
			errorBanner = err instanceof Error ? err.message : String(err);
		} finally {
			busy = false;
		}
	}

	function promptDeleteAccountData() {
		deleteAccountDialogEl?.showModal();
	}

	async function handleDeleteAccountDialogClose() {
		if (deleteAccountDialogEl?.returnValue !== 'confirm') {
			return;
		}
		busy = true;
		errorBanner = null;
		try {
			const did = requireAuthenticatedDid();
			await auth.deleteAccountData(did);
			optedIn = false;
			status = null;
			goto('/');
		} catch (err) {
			errorBanner = err instanceof Error ? err.message : String(err);
		} finally {
			busy = false;
		}
	}
</script>

<section class="labyrinth-settings" aria-labelledby="labyrinth-page-title">
	<header class="page-header">
		<div class="header-row">
			<h1 id="labyrinth-page-title">Encrypted Chat &amp; Labyrinth Backup</h1>
			<a class="back-link" href="/">Back to Chat</a>
		</div>
		{#if activeDid}
			<p class="subtitle">
				End-to-end encrypted conversations (`MLS_256_XWING`) and Spaces-backed Labyrinth 1.1 history
				for <code>{activeDid}</code>.
			</p>
		{:else}
			<p class="subtitle">
				End-to-end encrypted conversations (`MLS_256_XWING`) and Spaces-backed Labyrinth 1.1 history.
			</p>
		{/if}
	</header>

	{#if !activeDid}
		<section class="card" aria-labelledby="auth-required-heading">
			<h2 id="auth-required-heading">Sign In Required</h2>
			<p class="gate-copy">
				Sign in with your AT Protocol account before enabling Encrypted Chat, granting ATProto
				Spaces backup permissions, or managing authorized devices.
			</p>
			<div class="button-row">
				<a class="back-link" href="/">Return to Sign In</a>
			</div>
		</section>
	{:else}
		{#if devicePendingApproval || currentDeviceEntry?.status === 'pending_approval'}
			<p class="banner warn" role="status">
				This device is <strong>pending approval</strong> from an already-enrolled device. Approve it
				from another active device, enter a 6-digit pairing code, or restore via Passkey PRF /
				40-character recovery code to unlock prior history.
			</p>
		{/if}
		{#if statusBanner}
			<p class="banner ok" role="status">{statusBanner}</p>
		{/if}
		{#if errorBanner}
			<p class="banner err" role="alert">{errorBanner}</p>
		{/if}

		<section class="card" aria-labelledby="spaces-gate-heading">
			<h2 id="spaces-gate-heading">ATProto Spaces &amp; Opt-In Status</h2>
			{#if probingPds}
				<p class="gate-copy">Checking Personal Data Server for ATProto Spaces support…</p>
			{:else}
				<p class="gate-copy">{spacesGate.message}</p>
			{/if}

			{#if spacesGate.missingScopes.length > 0}
				<div class="button-row">
					<button
						type="button"
						class="btn-primary"
						disabled={busy}
						onclick={handleUpgradeScopes}
					>
						Grant Spaces Permissions
					</button>
				</div>
			{/if}

			{#if !optedIn}
				<p class="hint">
					Encrypted Chat is off by default on fresh sign-in — no MLS databases, KeyPackages, or Spaces
					calls run until you opt in.
				</p>
				<button
					type="button"
					class="btn-primary"
					disabled={!spacesGate.eligible || probingPds || busy}
					onclick={handleOptInAndEnroll}
				>
					Enable Encrypted Chat &amp; Labyrinth Backup
				</button>
			{:else if status}
				<dl class="status-grid">
					<div>
						<dt>Mailbox Space</dt>
						<dd><code>{status.mailbox_space_uri}</code></dd>
					</div>
					<div>
						<dt>Mailbox Epoch</dt>
						<dd>{status.epoch_seq}</dd>
					</div>
					<div>
						<dt>40-Char Recovery Code</dt>
						<dd>{status.has_recovery_code ? 'Configured' : 'Not set'}</dd>
					</div>
					<div>
						<dt>Passkey PRF</dt>
						<dd>{status.has_passkey_prf ? 'Registered' : 'Not set'}</dd>
					</div>
					<div>
						<dt>Sibling Space Backfill</dt>
						<dd>{backfillSummary.label}</dd>
					</div>
					<div>
						<dt>Last History Sync</dt>
						<dd>{formatDeviceTimestamp(backfillSummary.lastSyncedAt)}</dd>
					</div>
				</dl>
				<div class="button-row">
					<button
						type="button"
						class="btn-secondary"
						disabled={busy}
						onclick={handleSyncBackfillNow}
					>
						Sync History Now
					</button>
				</div>
			{/if}
		</section>

	<section class="card" aria-labelledby="recovery-heading">
		<h2 id="recovery-heading">Backup recovery</h2>
		<p>Set up a backup-eligible passkey or save a recovery code to restore your history on a new device.</p>

		{#snippet registerPasskey()}
			<button type="button" class={preferPasskey ? 'btn-primary' : 'btn-secondary'}
				disabled={!optedIn || !canRegisterPasskeyPrf || busy} onclick={handleRegisterPasskeyPrf}>
				Register Passkey PRF
			</button>
		{/snippet}
		<div class="button-row">
			{#if preferPasskey}{@render registerPasskey()}{/if}
			<button type="button" class={preferPasskey ? 'btn-secondary' : 'btn-primary'}
				disabled={!optedIn || busy} onclick={handleGenerateRecoveryCode}>
				Generate 40-Character Recovery Code
			</button>
			{#if !preferPasskey}{@render registerPasskey()}{/if}

			<button
				type="button"
				class="btn-secondary"
				disabled={!optedIn || !canRegisterPasskeyPrf || busy}
				onclick={handleRestorePasskeyPrf}
			>
				Restore with Passkey PRF
			</button>
		</div>

		{#if passkeyReason}
			<p class="hint">{passkeyReason}</p>
		{/if}

		{#if generatedRecoveryCode}
			<figure class="recovery-figure">
				<figcaption>
					Save this 40-character Labyrinth recovery code in your password manager. Catbird servers
					cannot recover it.
				</figcaption>
				<!-- svelte-ignore a11y_no_noninteractive_tabindex -->
				<pre tabindex="0"><code>{generatedRecoveryCode}</code></pre>
			</figure>
		{/if}

		<form class="inline-form" onsubmit={handleRestoreRecoveryCode}>
			<label for="restore-code-input">Restore from existing 40-character code</label>
			<div class="input-row">
				<input
					id="restore-code-input"
					type="text"
					autocomplete="off"
					spellcheck="false"
					placeholder="XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX"
					bind:value={restoreCodeInput}
					disabled={!optedIn || busy}
				/>
				<button type="submit" class="btn-secondary" disabled={!optedIn || busy}>
					Restore History
				</button>
			</div>
		</form>
	</section>

	<section class="card" aria-labelledby="otc-heading">
		<h2 id="otc-heading">6-Digit Post-Quantum Device Pairing (CPace + ML-KEM-768)</h2>
		<p>
			Link a second browser or mobile device directly using a short-lived 6-digit One-Time Code
			protected by hybrid post-quantum key agreement.
		</p>

		<div class="button-row">
			<button type="button" class="btn-secondary" disabled={!optedIn || busy} onclick={handleOfferOtc}>
				Display 6-Digit Pairing Code
			</button>
			{#if otcOffer}
				<span class="otc-badge" aria-live="polite">{otcOffer.formatted_code}</span>
			{/if}
		</div>
		{#if liveOtcSession}
			<p class="hint">
				Live OTC Session ID: <code>{liveOtcSession.session_id_hex}</code>
			</p>
		{/if}

		<form class="inline-form" onsubmit={handleRespondLiveOtc}>
			<label for="otc-session-id-input">Respond from already-enrolled device (Session ID + 6-digit code)</label>
			<div class="input-row">
				<input
					id="otc-session-id-input"
					type="text"
					autocomplete="off"
					spellcheck="false"
					placeholder="OTC Session ID (hex)"
					bind:value={otcResponderSessionId}
					disabled={!optedIn || busy}
				/>
				<input
					id="otc-responder-code-input"
					type="text"
					inputmode="numeric"
					maxlength="7"
					placeholder="123-456"
					bind:value={otcResponderCode}
					disabled={!optedIn || busy}
				/>
				<button type="submit" class="btn-secondary" disabled={!optedIn || busy}>
					Respond to Pairing
				</button>
			</div>
		</form>

		<form class="inline-form" onsubmit={handleCompleteOtc}>
			<label for="otc-code-input">Finalize pairing on new device (6-digit code)</label>
			<div class="input-row">
				<input
					id="otc-code-input"
					type="text"
					inputmode="numeric"
					maxlength="7"
					placeholder="123-456"
					bind:value={otcInput}
					disabled={!optedIn || busy}
				/>
				<button type="submit" class="btn-primary" disabled={!optedIn || busy}>
					Pair Device
				</button>
			</div>
		</form>
	</section>

	<section class="card" aria-labelledby="reindex-heading">
		<h2 id="reindex-heading">History Verification &amp; Re-Index</h2>
		<p>
			Verify franking tags and rebuild local search/message indexes from encrypted Space history batches
			for a conversation.
		</p>
		<form class="inline-form" onsubmit={handleVerifyAndReindexHistory}>
			<label for="reindex-convo-input">Conversation ID</label>
			<div class="input-row">
				<input
					id="reindex-convo-input"
					type="text"
					autocomplete="off"
					spellcheck="false"
					placeholder="00000000-0000-4000-8000-000000000000"
					bind:value={reindexConversationId}
					disabled={!optedIn || busy}
				/>
				<button type="submit" class="btn-secondary" disabled={!optedIn || busy}>
					Verify &amp; Re-Index History
				</button>
			</div>
		</form>
	</section>

	<section class="card" aria-labelledby="devices-heading">
		<h2 id="devices-heading">Authorized Labyrinth Devices</h2>
		{#if devices.length > 0}
			<ul class="device-list">
				{#each devices as device (device.deviceId)}
					<li class="device-row">
						<div class="device-details">
							<div class="device-title-row">
								<span class="device-name">{device.deviceName}</span>
								{#if device.isCurrent}
									<span class="device-pill current">This Device</span>
								{/if}
								{#if device.status === 'pending_approval'}
									<span class="device-pill pending">Pending Approval</span>
								{:else if device.status === 'dormant'}
									<span class="device-pill dormant">Dormant</span>
								{:else}
									<span class="device-pill active">Active</span>
								{/if}
							</div>
							<code class="device-id-code">{device.deviceId}</code>
							<div class="device-meta-row">
								<span>Last active: {formatDeviceTimestamp(device.lastActiveAt)}</span>
								{#if device.dormantAt}
									<span>Dormant since: {formatDeviceTimestamp(device.dormantAt)}</span>
								{/if}
							</div>
						</div>
						<div class="device-actions">
							{#if !device.isCurrent && device.status === 'pending_approval'}
								<button
									type="button"
									class="btn-primary"
									disabled={busy}
									onclick={() => handleApproveSiblingDevice(device.deviceId)}
								>
									Approve Device
								</button>
							{/if}
							<button
								type="button"
								class="btn-danger"
								disabled={busy || device.isCurrent}
								title={device.isCurrent
									? 'Sign out to retire this device; self-revocation is disabled'
									: 'Revoke device and rotate mailbox epoch'}
								onclick={() => promptRevokeDevice(device.deviceId)}
							>
								{device.isCurrent ? 'Current Device' : 'Revoke Device'}
							</button>
						</div>
					</li>
				{/each}
			</ul>
		{:else}
			<p class="hint">No enrolled Labyrinth devices on this account yet.</p>
		{/if}
	</section>

	<section class="card danger-card" aria-labelledby="delete-account-heading">
		<h2 id="delete-account-heading">Delete Encrypted Account Data</h2>
		<p class="hint">
			Permanently purge local encrypted chat databases, WebCrypto wrapping keys, device identity,
			and request remote encrypted chat state deletion for <code>{activeDid}</code>.
		</p>
		<div class="button-row">
			<button
				type="button"
				class="btn-danger"
				disabled={busy}
				onclick={promptDeleteAccountData}
			>
				Delete Encrypted Account Data
			</button>
		</div>
	</section>

	<dialog
		bind:this={revokeDialogEl}
		aria-labelledby="revoke-dialog-title"
		onclose={handleRevokeDialogClose}
	>
		<form method="dialog" class="revoke-dialog-form">
			<h3 id="revoke-dialog-title">Revoke Labyrinth Device?</h3>
			<p>
				Revoking <code>{pendingRevokeDeviceId ?? ''}</code> rotates your Labyrinth mailbox epoch so
				the removed device can no longer read future history backups.
			</p>
			<div class="dialog-actions">
				<button type="submit" value="cancel" class="btn-secondary">Cancel</button>
				<button type="submit" value="confirm" class="btn-danger">Revoke &amp; Rotate Epoch</button>
			</div>
		</form>
	</dialog>

	<dialog
		bind:this={deleteAccountDialogEl}
		aria-labelledby="delete-account-dialog-title"
		onclose={handleDeleteAccountDialogClose}
	>
		<form method="dialog" class="revoke-dialog-form">
			<h3 id="delete-account-dialog-title">Delete Encrypted Account Data?</h3>
			<p>
				This permanently erases local encrypted messages, WebCrypto keys, and OPFS storage on this
				device and requests encrypted chat account deletion for <code>{activeDid}</code>.
			</p>
			<div class="dialog-actions">
				<button type="submit" value="cancel" class="btn-secondary">Cancel</button>
				<button type="submit" value="confirm" class="btn-danger">Delete Account Data</button>
			</div>
		</form>
	</dialog>
	{/if}
</section>

<style>
	.labyrinth-settings {
		max-width: 760px;
		margin: 0 auto;
		padding: 32px 24px 64px;
		display: flex;
		flex-direction: column;
		gap: 20px;
		overflow-y: auto;
		height: 100%;
	}

	.header-row {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 16px;
	}

	h1 {
		font-size: 22px;
		font-weight: 600;
		color: var(--text-primary);
		margin: 0;
	}

	h2 {
		font-size: 16px;
		font-weight: 600;
		color: var(--text-primary);
		margin: 0 0 8px;
	}

	h3 {
		font-size: 16px;
		font-weight: 600;
		margin: 0 0 8px;
	}

	.subtitle,
	.gate-copy,
	.hint {
		font-size: 14px;
		color: var(--text-secondary);
		line-height: 1.5;
		margin: 6px 0;
	}

	.back-link {
		font-size: 13px;
		color: var(--accent);
		text-decoration: none;
	}

	.card {
		padding: 20px;
		background: var(--bg-card);
		border: 1px solid var(--border);
		border-radius: var(--radius-md);
		display: flex;
		flex-direction: column;
		gap: 12px;
	}

	.danger-card {
		border-color: rgba(220, 38, 38, 0.4);
	}

	.banner {
		padding: 12px 16px;
		border-radius: var(--radius-sm);
		font-size: 14px;
		margin: 0;
	}

	.banner.ok {
		background: color-mix(in srgb, var(--accent) 14%, transparent);
		border: 1px solid var(--accent);
		color: var(--text-primary);
	}

	.banner.warn {
		background: rgba(217, 119, 6, 0.14);
		border: 1px solid rgba(217, 119, 6, 0.5);
		color: var(--text-primary);
	}

	.banner.err {
		background: rgba(220, 38, 38, 0.14);
		border: 1px solid rgba(220, 38, 38, 0.5);
		color: var(--text-primary);
	}

	.status-grid {
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
		gap: 12px;
		margin: 8px 0 0;
	}

	.status-grid dt {
		font-size: 12px;
		color: var(--text-secondary);
	}

	.status-grid dd {
		margin: 4px 0 0;
		font-size: 14px;
		font-weight: 500;
		word-break: break-all;
	}

	.button-row,
	.input-row,
	.dialog-actions,
	.device-actions {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: 10px;
	}

	.inline-form {
		display: flex;
		flex-direction: column;
		gap: 6px;
		margin-top: 6px;
	}

	.inline-form label {
		font-size: 13px;
		font-weight: 500;
		color: var(--text-secondary);
	}

	.input-row input {
		flex: 1;
		min-width: 220px;
		padding: 8px 12px;
		border-radius: var(--radius-sm);
		border: 1px solid var(--border);
		background: var(--bg-elevated);
		color: var(--text-primary);
		font-family: monospace;
	}

	.recovery-figure {
		margin: 8px 0;
		padding: 12px;
		background: var(--bg-elevated);
		border: 1px solid var(--border);
		border-radius: var(--radius-sm);
	}

	.recovery-figure figcaption {
		font-size: 12px;
		color: var(--text-secondary);
		margin-bottom: 8px;
	}

	.recovery-figure pre {
		margin: 0;
		padding: 10px;
		overflow-x: auto;
		background: var(--bg-app);
		border-radius: var(--radius-sm);
	}

	.otc-badge {
		font-family: monospace;
		font-size: 18px;
		font-weight: 700;
		letter-spacing: 0.08em;
		padding: 6px 12px;
		border-radius: var(--radius-sm);
		background: var(--bg-elevated);
		border: 1px solid var(--border);
	}

	.device-list {
		list-style: none;
		padding: 0;
		margin: 0;
		display: flex;
		flex-direction: column;
		gap: 10px;
	}

	.device-row {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 12px;
		padding: 12px 14px;
		border-radius: var(--radius-sm);
		background: var(--bg-elevated);
		border: 1px solid var(--border);
	}

	.device-details {
		display: flex;
		flex-direction: column;
		gap: 4px;
		min-width: 0;
	}

	.device-title-row {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: 8px;
	}

	.device-name {
		font-size: 14px;
		font-weight: 600;
		color: var(--text-primary);
	}

	.device-id-code {
		font-size: 12px;
		color: var(--text-secondary);
		word-break: break-all;
	}

	.device-meta-row {
		display: flex;
		flex-wrap: wrap;
		gap: 12px;
		font-size: 12px;
		color: var(--text-tertiary, var(--text-secondary));
	}

	.device-pill {
		font-size: 11px;
		font-weight: 600;
		padding: 2px 8px;
		border-radius: 999px;
	}

	.device-pill.current {
		background: color-mix(in srgb, var(--accent) 18%, transparent);
		color: var(--accent);
		border: 1px solid var(--accent);
	}

	.device-pill.active {
		background: rgba(52, 199, 89, 0.15);
		color: #4ade80;
	}

	.device-pill.pending {
		background: rgba(217, 119, 6, 0.18);
		color: #fbbf24;
	}

	.device-pill.dormant {
		background: rgba(148, 163, 184, 0.16);
		color: var(--text-secondary);
	}

	.btn-primary,
	.btn-secondary,
	.btn-danger {
		padding: 9px 16px;
		border-radius: var(--radius-sm);
		font-size: 13px;
		font-weight: 500;
		cursor: pointer;
	}

	.btn-primary {
		background: var(--accent);
		color: var(--text-on-accent);
		border: none;
	}

	.btn-secondary {
		background: var(--bg-elevated);
		color: var(--text-primary);
		border: 1px solid var(--border);
	}

	.btn-danger {
		background: rgba(220, 38, 38, 0.16);
		color: #f87171;
		border: 1px solid rgba(220, 38, 38, 0.45);
	}

	button:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	dialog {
		margin: auto;
		max-width: 440px;
		padding: 24px;
		border-radius: var(--radius-md);
		border: 1px solid var(--border);
		background: var(--bg-card);
		color: var(--text-primary);
	}

	dialog::backdrop {
		background: rgba(0, 0, 0, 0.6);
	}

	.revoke-dialog-form {
		display: flex;
		flex-direction: column;
		gap: 16px;
	}
</style>

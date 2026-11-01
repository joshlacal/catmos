<script lang="ts">
	import { onMount } from 'svelte';
	import { auth } from '#lib/stores/auth.ts';
	import {
		completeLabyrinthOtcPairing,
		enableMlsAndEnroll,
		getLabyrinthStatus,
		initiateLabyrinthOtcPairing,
		registerLabyrinthPasskeyPrf,
		restoreWithLabyrinthRecoveryCode,
		revokeLabyrinthDevice,
		setupLabyrinthRecoveryCode,
		type LabyrinthBackupStatusView,
		type OtcPairingOfferView
	} from '#lib/wasm.ts';
	import {
		detectPasskeyPrfCapability,
		evaluateSpacesGateForUi,
		isMlsOptedInForDid,
		mapWebAuthnErrorToMessage,
		REQUIRED_LABYRINTH_OAUTH_SCOPES,
		setMlsOptedInForDid
	} from '#lib/labyrinth-ui.ts';

	const FALLBACK_DEMO_DID = 'did:plc:catmosdemoaccount0001';
	const activeDid = $derived($auth.user?.did ?? FALLBACK_DEMO_DID);

	let pdsSupportsSpaces = $state(true);
	let grantedScopes = $state<string[]>([...REQUIRED_LABYRINTH_OAUTH_SCOPES]);
	const spacesGate = $derived(evaluateSpacesGateForUi(pdsSupportsSpaces, grantedScopes));

	let optedIn = $state(false);
	let status = $state<LabyrinthBackupStatusView | null>(null);
	let generatedRecoveryCode = $state('');
	let restoreCodeInput = $state('');
	let otcOffer = $state<OtcPairingOfferView | null>(null);
	let otcInput = $state('');
	let canRegisterPasskeyPrf = $state(false);
	let passkeyReason = $state<string | null>(null);
	let statusBanner = $state<string | null>(null);
	let errorBanner = $state<string | null>(null);
	let busy = $state(false);

	let pendingRevokeDeviceId = $state<string | null>(null);
	let revokeDialogEl: HTMLDialogElement | undefined = $state(undefined);

	onMount(async () => {
		optedIn = isMlsOptedInForDid(activeDid);
		const prfCap = await detectPasskeyPrfCapability();
		canRegisterPasskeyPrf = prfCap.canRegisterPasskeyPrf;
		passkeyReason = prfCap.reason;

		if (optedIn) {
			try {
				status = await getLabyrinthStatus(activeDid);
			} catch (err) {
				errorBanner = err instanceof Error ? err.message : String(err);
			}
		}
	});

	async function handleOptInAndEnroll() {
		if (!spacesGate.eligible) {
			errorBanner = spacesGate.message;
			return;
		}
		busy = true;
		errorBanner = null;
		statusBanner = null;
		try {
			status = await enableMlsAndEnroll(activeDid, pdsSupportsSpaces, grantedScopes);
			optedIn = true;
			statusBanner = 'Encrypted Chat and Labyrinth 1.1 Spaces history enabled on this device.';
		} catch (err) {
			setMlsOptedInForDid(activeDid, false);
			optedIn = false;
			errorBanner = err instanceof Error ? err.message : String(err);
		} finally {
			busy = false;
		}
	}

	async function handleGenerateRecoveryCode() {
		busy = true;
		errorBanner = null;
		try {
			generatedRecoveryCode = await setupLabyrinthRecoveryCode(activeDid);
			status = await getLabyrinthStatus(activeDid);
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
		busy = true;
		errorBanner = null;
		try {
			status = await restoreWithLabyrinthRecoveryCode(activeDid, restoreCodeInput.trim());
			restoreCodeInput = '';
			statusBanner = `Restored Labyrinth mailbox and rotated to epoch ${status.epoch_seq}.`;
		} catch (err) {
			errorBanner = err instanceof Error ? err.message : String(err);
		} finally {
			busy = false;
		}
	}

	async function handleRegisterPasskeyPrf() {
		busy = true;
		errorBanner = null;
		try {
			const challenge = crypto.getRandomValues(new Uint8Array(32));
			const prfSalt = new TextEncoder().encode(`catbird-labyrinth-prf:${activeDid}`);
			const userId = new TextEncoder().encode(activeDid).slice(0, 64);
			const rpId = typeof window !== 'undefined' ? window.location.hostname : 'catbird.blue';

			const cred = (await navigator.credentials.create({
				publicKey: {
					challenge,
					rp: { name: 'Catbird Encrypted Chat', id: rpId },
					user: {
						id: userId,
						name: $auth.user?.handle ?? activeDid,
						displayName: $auth.user?.displayName ?? $auth.user?.handle ?? activeDid
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
								first: prfSalt
							}
						}
					} as AuthenticationExtensionsClientInputs
				}
			})) as PublicKeyCredential | null;

			if (!cred) {
				throw new Error('Passkey registration returned null credential.');
			}

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

			status = await registerLabyrinthPasskeyPrf(
				activeDid,
				new Uint8Array(cred.rawId),
				prfBytes
			);
			statusBanner = 'Passkey PRF bound to your Labyrinth recovery keyring.';
		} catch (err) {
			errorBanner = mapWebAuthnErrorToMessage(err);
		} finally {
			busy = false;
		}
	}

	async function handleOfferOtc() {
		busy = true;
		errorBanner = null;
		try {
			otcOffer = await initiateLabyrinthOtcPairing(activeDid);
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
			const res = await completeLabyrinthOtcPairing(activeDid, otcInput.trim());
			status = await getLabyrinthStatus(activeDid);
			otcInput = '';
			statusBanner = `Completed hybrid PQ CPace + ML-KEM-768 pairing (epoch ${res.new_epoch_seq}).`;
		} catch (err) {
			errorBanner = err instanceof Error ? err.message : String(err);
		} finally {
			busy = false;
		}
	}

	function promptRevokeDevice(deviceId: string) {
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
			status = await revokeLabyrinthDevice(activeDid, target);
			statusBanner = `Revoked device ${target} and rotated mailbox to epoch ${status.epoch_seq}.`;
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
		<p class="subtitle">
			End-to-end encrypted conversations (`MLS_256_XWING`) and Spaces-backed Labyrinth 1.1 history
			for <code>{activeDid}</code>.
		</p>
	</header>

	{#if statusBanner}
		<p class="banner ok" role="status">{statusBanner}</p>
	{/if}
	{#if errorBanner}
		<p class="banner err" role="alert">{errorBanner}</p>
	{/if}

	<section class="card" aria-labelledby="spaces-gate-heading">
		<h2 id="spaces-gate-heading">ATProto Spaces &amp; Opt-In Status</h2>
		<p class="gate-copy">{spacesGate.message}</p>

		{#if !optedIn}
			<p class="hint">
				Encrypted Chat is off by default on fresh sign-in — no MLS databases, KeyPackages, or Spaces
				calls run until you opt in.
			</p>
			<button
				type="button"
				class="btn-primary"
				disabled={!spacesGate.eligible || busy}
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
			</dl>
		{/if}
	</section>

	<section class="card" aria-labelledby="recovery-heading">
		<h2 id="recovery-heading">40-Character Recovery Code &amp; Passkey PRF</h2>
		<p>
			Generate a 40-character GF(32) recovery code (corrects up to 3 typos) or bind a hardware
			Passkey PRF virtual device so you can restore chat history if you lose all enrolled devices.
		</p>

		<div class="button-row">
			<button
				type="button"
				class="btn-primary"
				disabled={!optedIn || busy}
				onclick={handleGenerateRecoveryCode}
			>
				Generate 40-Character Recovery Code
			</button>

			<button
				type="button"
				class="btn-secondary"
				disabled={!optedIn || !canRegisterPasskeyPrf || busy}
				onclick={handleRegisterPasskeyPrf}
			>
				Register Passkey PRF
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

		<form class="inline-form" onsubmit={handleCompleteOtc}>
			<label for="otc-code-input">Enter 6-digit code from another enrolled device</label>
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

	<section class="card" aria-labelledby="devices-heading">
		<h2 id="devices-heading">Authorized Labyrinth Devices</h2>
		{#if status && status.active_device_ids.length > 0}
			<ul class="device-list">
				{#each status.active_device_ids as deviceId (deviceId)}
					<li class="device-row">
						<code>{deviceId}</code>
						<button
							type="button"
							class="btn-danger"
							disabled={busy}
							onclick={() => promptRevokeDevice(deviceId)}
						>
							Revoke Device
						</button>
					</li>
				{/each}
			</ul>
		{:else}
			<p class="hint">No enrolled Labyrinth devices on this account yet.</p>
		{/if}
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
	.dialog-actions {
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
		gap: 8px;
	}

	.device-row {
		display: flex;
		align-items: center;
		justify-content: space-between;
		padding: 10px 12px;
		border-radius: var(--radius-sm);
		background: var(--bg-elevated);
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

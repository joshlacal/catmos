<script lang="ts">
	/**
	 * Layer 3 quarantine banner. Shown above the message list when a
	 * conversation is in `Quarantined` state. Two actions:
	 *
	 * - `Reset conversation` → calls `confirmManualReset(convoId)`, which
	 *   reports the user vote to the server's A7 reset pyramid and clears
	 *   local quarantine. The follow-up server-pushed groupResetEvent is
	 *   handled by the existing `mls:group-reset` listener in `+page.svelte`.
	 * - `Learn more` → opens an inline disclosure with the suspected DIDs.
	 */
	import type { QuarantineState } from '$lib/tauri';
	import { auth } from '$lib/stores/auth';
	import { confirmManualReset } from '$lib/wasm';
	import { quarantineReasonCopy } from '$lib/stores/quarantine';

	let {
		conversationId,
		quarantineState
	}: {
		conversationId: string;
		quarantineState: QuarantineState;
	} = $props();

	let resetting = $state(false);
	let resetError = $state<string | null>(null);
	let showDetails = $state(false);

	async function handleReset() {
		const session = $auth.user;
        if (!session || resetting) return;
		resetting = true;
		resetError = null;
		try {
			await confirmManualReset(conversationId, session.did, session.authRevision);
			// Server emits a groupResetEvent on quorum; the page-level
			// `mls:group-reset` listener picks it up. The orchestrator also
			// clears local quarantine, which fires `mls://quarantine-cleared`,
			// so the banner unmounts.
		} catch (err) {
			if ($auth.user !== session) return;
            resetError = String(err);
			console.error('[quarantine] manual reset failed:', err);
		} finally {
			resetting = false;
		}
	}

	let sinceLabel = $derived.by(() => {
		try {
			return new Date(quarantineState.sinceMs).toLocaleString();
		} catch {
			return '';
		}
	});
</script>

<div class="quarantine-banner" role="alert" aria-live="polite">
	<div class="banner-row">
		<svg
			class="banner-icon"
			width="18"
			height="18"
			viewBox="0 0 24 24"
			fill="none"
			stroke="currentColor"
			stroke-width="2"
			stroke-linecap="round"
			stroke-linejoin="round"
			aria-hidden="true"
		>
			<path d="M12 9v4" />
			<path
				d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0Z"
			/>
			<path d="M12 17h.01" />
		</svg>
		<div class="banner-text">
			<strong>This conversation is paused</strong>
			<span>A participant's device may be sending invalid messages.</span>
		</div>
		<div class="banner-actions">
			<button
				type="button"
				class="btn-link"
				onclick={() => (showDetails = !showDetails)}
				aria-expanded={showDetails}
			>
				{showDetails ? 'Hide' : 'Learn more'}
			</button>
			<button
				type="button"
				class="btn-primary"
				disabled={resetting}
				onclick={handleReset}
			>
				{resetting ? 'Resetting…' : 'Reset conversation'}
			</button>
		</div>
	</div>
	{#if showDetails}
		<div class="banner-details">
			<p class="reason">{quarantineReasonCopy(quarantineState.reasonTag)}</p>
			<dl>
				<dt>Reason</dt>
				<dd><code>{quarantineState.reasonTag}</code></dd>
				{#if sinceLabel}
					<dt>Paused since</dt>
					<dd>{sinceLabel}</dd>
				{/if}
				<dt>Suspected devices</dt>
				<dd>
					{#if quarantineState.suspectedDids.length === 0}
						<em class="muted">none identified — likely a framing-failure burst</em>
					{:else}
						<ul>
							{#each quarantineState.suspectedDids as did (did)}
								<li><code>{did}</code></li>
							{/each}
						</ul>
					{/if}
				</dd>
			</dl>
		</div>
	{/if}
	{#if resetError}
		<p class="reset-error">Reset failed: {resetError}</p>
	{/if}
</div>

<style>
	.quarantine-banner {
		background: var(--bg-card, #fff8e6);
		border-left: 3px solid var(--warning, #d97706);
		padding: 10px 16px;
		font-size: 13px;
		color: var(--text-primary, #1f1f1f);
	}
	.banner-row {
		display: flex;
		align-items: center;
		gap: 12px;
	}
	.banner-icon {
		flex-shrink: 0;
		color: var(--warning, #d97706);
	}
	.banner-text {
		display: flex;
		flex-direction: column;
		flex: 1;
		min-width: 0;
	}
	.banner-text strong {
		font-weight: 600;
	}
	.banner-text span {
		color: var(--text-secondary, #555);
		font-size: 12px;
	}
	.banner-actions {
		display: flex;
		gap: 8px;
		flex-shrink: 0;
	}
	.btn-link {
		background: none;
		border: none;
		color: var(--accent, #2563eb);
		font-size: 13px;
		font-weight: 500;
		cursor: pointer;
		padding: 6px 8px;
	}
	.btn-link:hover {
		text-decoration: underline;
	}
	.btn-primary {
		background: var(--warning, #d97706);
		color: var(--text-on-accent, #fff);
		border: none;
		border-radius: var(--radius-sm, 6px);
		padding: 6px 12px;
		font-size: 13px;
		font-weight: 600;
		cursor: pointer;
	}
	.btn-primary:disabled {
		opacity: 0.6;
		cursor: not-allowed;
	}
	.banner-details {
		margin-top: 10px;
		padding: 8px 0 0;
		border-top: 1px solid var(--border, rgba(0, 0, 0, 0.08));
		font-size: 12px;
	}
	.banner-details .reason {
		margin: 0 0 8px;
		color: var(--text-secondary, #555);
	}
	.banner-details dl {
		margin: 0;
		display: grid;
		grid-template-columns: max-content 1fr;
		gap: 4px 12px;
	}
	.banner-details dt {
		font-weight: 600;
		color: var(--text-secondary, #555);
	}
	.banner-details dd {
		margin: 0;
	}
	.banner-details ul {
		list-style: none;
		padding: 0;
		margin: 0;
	}
	.banner-details code {
		font-family: ui-monospace, SFMono-Regular, monospace;
		font-size: 11px;
		background: rgba(0, 0, 0, 0.04);
		padding: 1px 4px;
		border-radius: 3px;
	}
	.muted {
		color: var(--text-tertiary, #888);
	}
	.reset-error {
		color: var(--danger, #dc2626);
		font-size: 12px;
		margin: 8px 0 0;
	}
</style>

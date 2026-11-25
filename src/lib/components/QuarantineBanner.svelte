<script lang="ts">
	/**
	 * Layer 3 MLS quarantine banner.
	 * Shown above the message stream when a conversation is paused due to
	 * unverified commits or framing failures.
	 */
	import { confirmManualReset, type QuarantineState } from '#lib/wasm.ts';
	import { quarantineReasonCopy } from '#lib/stores/quarantine.ts';
	import { profiles, resolveProfileName } from '#lib/stores/profiles.ts';
	import { formatClockTime, formatSidebarTime } from '#lib/utils/time.ts';
	import {
		closeWithReset,
		useDialogLightDismiss,
		useDialogSafeAutofocus
	} from '#lib/utils/dialog.ts';
	import { announce, showToast } from '#lib/utils/announcer.ts';
	import Icon from './Icon.svelte';

	let {
		conversationId,
		state: stateProp,
		quarantineState: quarantineStateProp,
		onResetComplete
	}: {
		conversationId: string;
		state?: QuarantineState;
		quarantineState?: QuarantineState;
		onResetComplete?: () => void;
	} = $props();

	const quarantineState = $derived(stateProp ?? quarantineStateProp ?? null);

	let resetDialog = $state<HTMLDialogElement | null>(null);
	let resetting = $state(false);
	let resetError = $state<string | null>(null);

	$effect(() => {
		if (quarantineState && quarantineState.suspectedDids.length > 0) {
			profiles.resolveProfiles(quarantineState.suspectedDids);
		}
	});

	$effect(() => {
		// Reset modal state cleanly when switching conversations.
		void conversationId;
		resetError = null;
		if (resetDialog?.open && !resetting) {
			closeWithReset(resetDialog);
		}
	});

	const pausedSinceLabel = $derived.by(() => {
		if (!quarantineState) return '';
		const sidebar = formatSidebarTime(quarantineState.sinceMs);
		const clock = formatClockTime(quarantineState.sinceMs);
		if (!sidebar && !clock) return '';
		if (!sidebar) return clock;
		if (!clock || sidebar === clock) return `Today, ${clock}`;
		return `${sidebar}, ${clock}`;
	});

	function openResetDialog() {
		resetError = null;
		if (resetDialog && !resetDialog.open) {
			resetDialog.showModal();
		}
	}

	function cancelReset() {
		if (resetting) return;
		resetError = null;
		closeWithReset(resetDialog, 'cancel');
	}

	function handleDialogClose() {
		if (resetDialog) {
			resetDialog.returnValue = '';
		}
		if (!resetting) {
			resetError = null;
		}
	}

	async function confirmReset() {
		if (resetting) return;
		const targetConvoId = conversationId;
		resetting = true;
		resetError = null;
		try {
			await confirmManualReset(targetConvoId);
			closeWithReset(resetDialog, 'confirmed');
			onResetComplete?.();
			showToast({
				message: 'Conversation encryption reset requested.',
				tone: 'success'
			});
		} catch (err) {
			const message = err instanceof Error ? err.message : String(err);
			resetError = message || 'Could not reset this conversation.';
			announce(`Reset failed: ${resetError}`, 'assertive');
		} finally {
			resetting = false;
		}
	}
</script>

{#if quarantineState}
	<section class="quarantine-banner" aria-label="Conversation paused notice">
		<div class="banner-header">
			<span class="banner-icon" aria-hidden="true">
				<Icon name="shield-alert" size={18} />
			</span>
			<div class="banner-copy">
				<p class="banner-title">Conversation paused</p>
				<p class="banner-subtitle">
					A participant's device sent messages that could not be verified.
				</p>
			</div>
			<button
				type="button"
				class="reset-trigger"
				onclick={openResetDialog}
				disabled={resetting}
			>
				Reset conversation
			</button>
		</div>

		<details class="banner-details">
			<summary class="details-summary">Technical details</summary>
			<div class="details-body">
				<p class="reason-copy">{quarantineReasonCopy(quarantineState.reasonTag)}</p>
				<dl class="details-grid">
					<dt>Reason code</dt>
					<dd><code class="mono">{quarantineState.reasonTag}</code></dd>
					{#if pausedSinceLabel}
						<dt>Paused since</dt>
						<dd class="tabular-nums">{pausedSinceLabel}</dd>
					{/if}
					<dt>Suspected devices</dt>
					<dd>
						{#if quarantineState.suspectedDids.length === 0}
							<span class="details-muted">
								None identified. Likely a framing failure burst.
							</span>
						{:else}
							<ul class="suspected-list" role="list">
								{#each quarantineState.suspectedDids as did (did)}
									<li class="suspected-item">
										<span class="suspected-name">
											{resolveProfileName($profiles.cache, did)}
										</span>
										<code class="mono">{did}</code>
									</li>
								{/each}
							</ul>
						{/if}
					</dd>
				</dl>
			</div>
		</details>
	</section>
{/if}

<dialog
	bind:this={resetDialog}
	class="catmos-dialog reset-dialog"
	closedby="any"
	use:useDialogLightDismiss
	onclose={handleDialogClose}
>
	<div class="dialog-inner">
		<h1 class="dialog-title">Reset this conversation?</h1>
		<p class="dialog-description">
			Resetting creates a new encrypted epoch for all current members so messaging can resume.
			Previous messages remain in your local history.
		</p>

		{#if resetting}
			<div class="dialog-busy">
				<progress class="catmos-progress" aria-label="Resetting conversation"></progress>
				<span>Resetting encryption session...</span>
			</div>
		{/if}

		{#if resetError}
			<div class="dialog-error" role="alert">
				<Icon name="alert-triangle" size={16} />
				<span>{resetError}</span>
			</div>
		{/if}

		<div class="dialog-actions">
			<button
				type="button"
				class="catmos-btn-secondary"
				use:useDialogSafeAutofocus
				disabled={resetting}
				onclick={cancelReset}
			>
				Cancel
			</button>
			<button
				type="button"
				class="catmos-btn-primary"
				disabled={resetting}
				onclick={confirmReset}
			>
				{resetting ? 'Resetting...' : 'Reset conversation'}
			</button>
		</div>
	</div>
</dialog>

<style>
	.quarantine-banner {
		background: var(--warning-bg);
		border-inline-start: 3px solid var(--warning-border);
		border-block-end: 1px solid var(--border);
		padding-block: var(--space-3);
		padding-inline: var(--space-4);
		color: var(--warning-text);
	}

	.banner-header {
		display: flex;
		align-items: flex-start;
		flex-wrap: wrap;
		gap: var(--space-3);
	}

	.banner-icon {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		color: var(--warning-text);
		padding-block-start: 0.125rem;
		flex-shrink: 0;
	}

	.banner-copy {
		flex: 1 1 14rem;
		min-inline-size: 0;
		display: flex;
		flex-direction: column;
		gap: var(--space-fine);
	}

	.banner-title {
		font-size: var(--text-body);
		font-weight: 650;
		line-height: 1.3;
		color: var(--warning-text);
	}

	.banner-subtitle {
		font-size: var(--text-sm);
		line-height: 1.4;
		color: var(--text-primary);
		max-inline-size: 65ch;
	}

	.reset-trigger {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		flex-shrink: 0;
		min-block-size: max(2.25rem, var(--touch-min));
		padding-inline: var(--space-3);
		padding-block: var(--space-2);
		border-radius: var(--radius-sm);
		background: var(--warning-btn-bg);
		color: var(--warning-btn-fg);
		font-size: var(--text-sm);
		font-weight: 650;
		line-height: 1.2;
		transition:
			background-color var(--dur-fast) var(--ease-out),
			opacity var(--dur-fast) var(--ease-out);
	}

	.reset-trigger:hover:not(:disabled) {
		background: var(--warning-btn-hover);
	}

	.reset-trigger:disabled {
		opacity: 0.6;
		cursor: not-allowed;
	}

	.banner-details {
		margin-block-start: var(--space-2);
		padding-inline-start: calc(18px + var(--space-3));
	}

	.details-summary {
		display: inline-flex;
		align-items: center;
		gap: var(--space-1);
		min-block-size: max(1.75rem, var(--touch-min));
		font-size: var(--text-sm);
		font-weight: 600;
		color: var(--warning-text);
		cursor: pointer;
		list-style: disclosure-closed;
	}

	.banner-details[open] > .details-summary {
		list-style: disclosure-open;
	}

	.details-summary:hover {
		text-decoration: underline;
	}

	.details-body {
		margin-block-start: var(--space-2);
		padding-block-start: var(--space-2);
		border-block-start: 1px solid var(--border);
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
		color: var(--text-primary);
		font-size: var(--text-sm);
	}

	.reason-copy {
		color: var(--text-primary);
		line-height: 1.45;
		max-inline-size: 65ch;
	}

	.details-grid {
		display: grid;
		grid-template-columns: max-content minmax(0, 1fr);
		gap: var(--space-1) var(--space-4);
	}

	.details-grid dt {
		font-weight: 600;
		color: var(--text-secondary);
	}

	.details-grid dd {
		min-inline-size: 0;
		color: var(--text-primary);
	}

	.details-muted {
		color: var(--text-secondary);
	}

	.suspected-list {
		list-style: none;
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
	}

	.suspected-item {
		display: flex;
		flex-wrap: wrap;
		align-items: baseline;
		gap: var(--space-2);
	}

	.suspected-name {
		font-weight: 600;
		color: var(--text-primary);
	}

	.mono {
		font-family: var(--font-mono);
		font-size: var(--text-sm);
		word-break: break-all;
		color: var(--text-primary);
	}

	.reset-dialog {
		inline-size: min(28rem, calc(100vw - 2rem));
	}

	.dialog-inner {
		display: flex;
		flex-direction: column;
		gap: var(--space-4);
		padding: var(--space-6);
	}

	.dialog-title {
		font-size: var(--text-heading);
		font-weight: 650;
		line-height: 1.3;
		letter-spacing: -0.015em;
		color: var(--text-primary);
	}

	.dialog-description {
		font-size: var(--text-body);
		line-height: 1.5;
		color: var(--text-secondary);
		max-inline-size: 65ch;
	}

	.dialog-busy {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}

	.dialog-error {
		display: flex;
		align-items: flex-start;
		gap: var(--space-2);
		padding: var(--space-3);
		border-radius: var(--radius-sm);
		background: var(--danger-bg);
		color: var(--danger-text);
		font-size: var(--text-sm);
		line-height: 1.4;
	}

	.dialog-actions {
		display: flex;
		justify-content: flex-end;
		flex-wrap: wrap;
		gap: var(--space-2);
		padding-block-start: var(--space-1);
	}

	@media (max-width: 600px) {
		.banner-details {
			padding-inline-start: 0;
		}

		.details-grid {
			grid-template-columns: 1fr;
		}

		.details-grid dt {
			margin-block-start: var(--space-1);
		}
	}

	@media (forced-colors: active) {
		.quarantine-banner {
			border: 1px solid CanvasText;
			border-inline-start-width: 4px;
		}

		.reset-trigger {
			border: 1px solid ButtonText;
		}
	}
</style>

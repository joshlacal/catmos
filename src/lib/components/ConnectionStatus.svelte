<script lang="ts">
	import Icon from '#lib/components/Icon.svelte';
	import { auth } from '#lib/stores/auth.ts';
	import { connection } from '#lib/stores/connection.ts';
	import { conversations } from '#lib/stores/conversations.ts';
	import { openSettings, resetUi } from '#lib/stores/ui.ts';
	import { recoveryLabel, type RecoveryCategory } from '#lib/recovery.ts';

	const visible = $derived(
		$connection.state !== 'connected' && $connection.state !== 'connecting'
	);

	const isError = $derived($connection.state === 'error');
	const isOffline = $derived($connection.state === 'offline');
	const isReconnecting = $derived($connection.state === 'reconnecting');

	const label = $derived.by(() => {
		if ($connection.category && $connection.category !== 'retry') {
			return recoveryLabel($connection.category);
		}
		if (isOffline) {
			return 'You are offline';
		}
		if (isError) {
			return 'Connection failed';
		}
		return $connection.retryCount > 0
			? `Reconnecting (attempt ${$connection.retryCount})...`
			: 'Reconnecting...';
	});

	const detail = $derived.by(() => {
		const raw = $connection.lastError?.trim();
		if (!raw) return null;
		if (raw === label) return null;
		if ($connection.category === 'retry' && isReconnecting) return null;
		return raw;
	});

	function actionLabelFor(category: RecoveryCategory | null): string | null {
		switch (category) {
			case 'reauthenticate':
				return 'Sign in again';
			case 'rebind':
				return 'Reconnect device';
			case 'rejoin':
				return 'Rejoin';
			case 'access-ended':
				return 'Refresh list';
			case 'retry':
				return 'Retry';
			default:
				return isOffline || isError || isReconnecting ? 'Retry' : null;
		}
	}

	const actionLabel = $derived(actionLabelFor($connection.category));

	async function handleAction() {
		switch ($connection.category) {
			case 'reauthenticate':
				await auth.logout();
				resetUi();
				break;
			case 'rebind':
				openSettings('account');
				break;
			case 'access-ended':
				await conversations.load();
				break;
			case 'rejoin':
			case 'retry':
			default:
				connection.retryNow();
				break;
		}
	}
</script>

{#if visible}
	<div
		class="connection-banner"
		class:connection-banner--error={isError}
		class:connection-banner--offline={isOffline}
		role={isError ? 'alert' : 'status'}
		aria-live={isError ? 'assertive' : 'polite'}
	>
		<div class="banner-body">
			<span class="banner-icon" aria-hidden="true">
				{#if isReconnecting}
					<progress class="catmos-progress banner-progress" aria-label="Reconnecting"></progress>
				{:else if isOffline}
					<Icon name="wifi-off" size={16} />
				{:else}
					<Icon name="alert-triangle" size={16} />
				{/if}
			</span>

			<div class="banner-copy">
				<span class="banner-label">{label}</span>
				{#if detail}
					<span class="banner-detail">{detail}</span>
				{/if}
			</div>
		</div>

		{#if actionLabel}
			<button
				type="button"
				class="banner-action"
				class:banner-action--error={isError}
				onclick={handleAction}
			>
				{actionLabel}
			</button>
		{/if}
	</div>
{/if}

<style>
	.connection-banner {
		display: flex;
		align-items: center;
		justify-content: space-between;
		flex-wrap: wrap;
		gap: var(--space-2) var(--space-3);
		padding: var(--space-2) var(--space-4);
		background: var(--bg-surface);
		border-block-end: 1px solid var(--border);
		color: var(--text-primary);
		font-size: var(--text-sm);
		line-height: 1.4;
		flex-shrink: 0;
	}

	.connection-banner--offline {
		background: var(--warning-bg);
		border-block-end-color: var(--warning-border);
		color: var(--warning-text);
	}

	.connection-banner--error {
		background: var(--danger-bg);
		border-block-end-color: var(--danger-text);
		color: var(--danger-text);
	}

	.banner-body {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		min-inline-size: 0;
		flex: 1;
	}

	.banner-icon {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		flex-shrink: 0;
	}

	.banner-progress {
		inline-size: 0.9375rem;
		block-size: 0.9375rem;
		border-width: 2px;
	}

	.banner-copy {
		display: flex;
		align-items: baseline;
		flex-wrap: wrap;
		gap: var(--space-1) var(--space-2);
		min-inline-size: 0;
	}

	.banner-label {
		font-weight: 600;
	}

	.banner-detail {
		font-weight: 400;
		color: inherit;
		opacity: 0.92;
		word-break: break-word;
	}

	.banner-action {
		flex-shrink: 0;
		min-block-size: max(1.875rem, var(--touch-min));
		padding: var(--space-1) var(--space-3);
		border-radius: var(--radius-xs);
		border: 1px solid var(--border-strong);
		background: var(--bg-elevated);
		color: var(--text-primary);
		font-size: var(--text-sm);
		font-weight: 600;
		transition:
			background-color var(--dur-fast) var(--ease-out),
			border-color var(--dur-fast) var(--ease-out);
	}

	.banner-action:hover {
		background: var(--bg-active);
	}

	.banner-action--error {
		background: var(--danger-fill);
		border-color: transparent;
		color: #ffffff;
	}

	.banner-action--error:hover {
		background: var(--danger-hover);
	}

	@media (forced-colors: active) {
		.connection-banner {
			border-block-end: 2px solid CanvasText;
		}
		.banner-action {
			border: 1px solid ButtonText;
		}
	}
</style>

<script lang="ts">
	import { onMount } from 'svelte';
	import Icon, { type IconName } from './Icon.svelte';
	import { dismissToast, toasts, type ToastItem, type ToastTone } from '#lib/utils/announcer.ts';

	let hostEl = $state<HTMLDivElement | null>(null);
	let hasOpenModal = $state(false);

	function checkModalOpen(): boolean {
		if (typeof document === 'undefined') return false;
		try {
			return document.querySelector('dialog:modal') !== null;
		} catch {
			// Fallback for environments (like jsdom) lacking :modal pseudo-class support
			return document.querySelector('dialog[open]') !== null;
		}
	}

	function syncModalState() {
		hasOpenModal = checkModalOpen();
	}

	function iconForTone(tone: ToastTone): IconName {
		switch (tone) {
			case 'success':
				return 'check';
			case 'warning':
				return 'alert-triangle';
			case 'error':
				return 'shield-alert';
			default:
				return 'info';
		}
	}

	function handleAction(toast: ToastItem) {
		try {
			toast.onAction?.();
		} finally {
			dismissToast(toast.id);
		}
	}

	onMount(() => {
		syncModalState();

		const observer = new MutationObserver(() => {
			syncModalState();
		});
		observer.observe(document.body, {
			subtree: true,
			childList: true,
			attributes: true,
			attributeFilter: ['open']
		});

		document.addEventListener('close', syncModalState, true);
		document.addEventListener('cancel', syncModalState, true);

		return () => {
			observer.disconnect();
			document.removeEventListener('close', syncModalState, true);
			document.removeEventListener('cancel', syncModalState, true);
		};
	});

	$effect(() => {
		const el = hostEl;
		const shouldShow = $toasts.length > 0 && !hasOpenModal;
		if (!el) return;

		try {
			if (shouldShow) {
				if (typeof el.showPopover === 'function' && !el.matches(':popover-open')) {
					el.showPopover();
				}
			} else {
				if (typeof el.hidePopover === 'function' && el.matches(':popover-open')) {
					el.hidePopover();
				}
			}
		} catch {
			// Ignore popover API unavailability in test environments
		}
	});
</script>

<div
	bind:this={hostEl}
	popover="manual"
	class="toast-host"
	class:toast-host--visible={$toasts.length > 0 && !hasOpenModal}
	role="region"
	aria-label="Notifications"
>
	{#each $toasts as toast (toast.id)}
		<div class={`toast-card toast-card--${toast.tone}`}>
			<span class="toast-icon" aria-hidden="true">
				<Icon name={iconForTone(toast.tone)} size={16} />
			</span>
			<p class="toast-message">{toast.message}</p>
			{#if toast.actionLabel && toast.onAction}
				<button
					type="button"
					class="toast-action"
					onclick={() => handleAction(toast)}
				>
					{toast.actionLabel}
				</button>
			{/if}
			<button
				type="button"
				class="toast-close"
				aria-label="Dismiss notification"
				onclick={() => dismissToast(toast.id)}
			>
				<Icon name="x" size={16} />
			</button>
		</div>
	{/each}
</div>

<style>
	.toast-host {
		position: fixed;
		inset-block-start: auto;
		inset-inline-start: auto;
		inset-block-end: max(1rem, env(safe-area-inset-bottom, 0px));
		inset-inline-end: max(1rem, env(safe-area-inset-right, 0px));
		margin: 0;
		padding: 0;
		border: none;
		background: transparent;
		overflow: visible;
		max-inline-size: min(24rem, calc(100vw - 2rem));
		inline-size: 100%;
		pointer-events: none;
		z-index: 900;
	}

	.toast-host:popover-open,
	.toast-host--visible {
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
	}

	.toast-card {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		padding: var(--space-3) var(--space-3);
		border-radius: var(--radius-md);
		border: 1px solid var(--border-strong);
		background: var(--bg-elevated);
		color: var(--text-primary);
		box-shadow: var(--shadow-lg);
		pointer-events: auto;
		font-size: var(--text-sm);
		line-height: 1.4;
	}

	@supports (backdrop-filter: blur(1px)) {
		.toast-card {
			background: var(--glass-bg-strong);
			backdrop-filter: var(--glass-filter);
			-webkit-backdrop-filter: var(--glass-filter);
		}
	}

	.toast-card--info .toast-icon {
		color: var(--text-link);
	}

	.toast-card--success {
		border-color: var(--success-text);
	}

	.toast-card--success .toast-icon {
		color: var(--success-text);
	}

	.toast-card--warning {
		border-color: var(--warning-border);
	}

	.toast-card--warning .toast-icon {
		color: var(--warning-text);
	}

	.toast-card--error {
		border-color: var(--danger-text);
	}

	.toast-card--error .toast-icon {
		color: var(--danger-text);
	}

	.toast-icon {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		flex-shrink: 0;
	}

	.toast-message {
		flex: 1;
		min-inline-size: 0;
		color: var(--text-primary);
		word-break: break-word;
	}

	.toast-action {
		flex-shrink: 0;
		min-block-size: max(1.75rem, var(--touch-min));
		padding-inline: var(--space-2);
		border-radius: var(--radius-xs);
		font-size: var(--text-sm);
		font-weight: 600;
		color: var(--text-link);
		transition: background-color var(--dur-fast) var(--ease-out);
	}

	.toast-action:hover {
		background: var(--bg-hover);
	}

	.toast-close {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		flex-shrink: 0;
		min-inline-size: max(1.75rem, var(--touch-min));
		min-block-size: max(1.75rem, var(--touch-min));
		border-radius: var(--radius-xs);
		color: var(--text-secondary);
		transition:
			background-color var(--dur-fast) var(--ease-out),
			color var(--dur-fast) var(--ease-out);
	}

	.toast-close:hover {
		background: var(--bg-hover);
		color: var(--text-primary);
	}

	@media (forced-colors: active) {
		.toast-card {
			border: 2px solid CanvasText;
		}
	}
</style>

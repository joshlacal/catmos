<script lang="ts">
	import Icon from '#lib/components/Icon.svelte';
	import { auth } from '#lib/stores/auth.ts';
	import { isMlsOptedInForDid } from '#lib/labyrinth-ui.ts';

	let {
		onOpenNewConversation,
		onOpenCommandPalette
	}: {
		onOpenNewConversation: () => void;
		onOpenCommandPalette: () => void;
	} = $props();

	const isApple =
		typeof navigator !== 'undefined' && /Mac|iPhone|iPad|iPod/i.test(navigator.userAgent);
	const shortcutLabel = isApple ? '⌘K' : 'Ctrl+K';

	const isDemoMode = $derived(
		import.meta.env.DEV &&
			typeof document !== 'undefined' &&
			document.documentElement.dataset.catmosDemo === 'true'
	);

	// ctl #2: Encrypted Chat & Labyrinth Backup are off by default on fresh sign-in
	const needsMlsOptIn = $derived(
		!isDemoMode && Boolean($auth.user?.did && !isMlsOptedInForDid($auth.user.did))
	);
</script>

<section class="empty-workspace" aria-labelledby="empty-workspace-heading">
	<div class="empty-inner">
		<span class="empty-mark squircle" aria-hidden="true">
			<Icon name="catbird" size={26} />
		</span>

		<p class="encryption-note">
			<Icon name="shield" size={16} class="shield-glyph" />
			<span>End-to-end encrypted with MLS</span>
		</p>

		{#if needsMlsOptIn}
			<h1 id="empty-workspace-heading" class="empty-heading">Welcome to Catmos</h1>
			<p class="empty-subtitle">
				Encrypted Chat and Labyrinth Backup are off by default on fresh sign-in. Enable them to
				sync conversations and restore your encrypted PDS history.
			</p>

			<div class="empty-actions">
				<a href="/settings/labyrinth" class="catmos-btn-primary primary-cta opt-in-cta">
					Set Up Encrypted Chat &amp; Restore History
				</a>
			</div>
		{:else}
			<h1 id="empty-workspace-heading" class="empty-heading">Select a conversation</h1>
			<p class="empty-subtitle">
				Pick a chat from the sidebar or start a new encrypted message.
			</p>

			<div class="empty-actions">
				<button type="button" class="catmos-btn-primary primary-cta" onclick={onOpenNewConversation}>
					<Icon name="plus" size={16} />
					<span>New conversation</span>
				</button>

				<button type="button" class="catmos-btn-ghost secondary-cta" onclick={onOpenCommandPalette}>
					<Icon name="search" size={16} />
					<span>Search messages</span>
					<span class="shortcut-hint tabular-nums" aria-hidden="true">{shortcutLabel}</span>
				</button>
			</div>
		{/if}
	</div>
</section>

<style>
	.empty-workspace {
		flex: 1;
		display: flex;
		align-items: center;
		justify-content: center;
		padding: var(--space-8) var(--space-6);
		background: var(--bg-chat);
	}

	.empty-inner {
		inline-size: 100%;
		max-inline-size: 25rem;
		display: flex;
		flex-direction: column;
		align-items: center;
		text-align: center;
		gap: var(--space-3);
	}

	.empty-mark {
		inline-size: 2.75rem;
		block-size: 2.75rem;
		display: inline-flex;
		align-items: center;
		justify-content: center;
		background: var(--brand-gradient);
		border-radius: var(--radius-sm);
		margin-block-end: var(--space-1);
	}

	.encryption-note {
		display: inline-flex;
		align-items: center;
		gap: var(--space-1);
		font-size: var(--text-sm);
		font-weight: 500;
		color: var(--text-secondary);
	}

	.encryption-note :global(.shield-glyph) {
		color: var(--shield);
	}

	.empty-heading {
		font-size: var(--text-heading);
		font-weight: 650;
		letter-spacing: -0.015em;
		line-height: 1.3;
		color: var(--text-primary);
		margin-block-start: var(--space-1);
	}

	.empty-subtitle {
		font-size: var(--text-sm);
		line-height: 1.48;
		color: var(--text-secondary);
		max-inline-size: 40ch;
	}

	.empty-actions {
		margin-block-start: var(--space-3);
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: var(--space-2);
		inline-size: 100%;
	}

	.primary-cta {
		min-inline-size: 13.5rem;
		min-block-size: 2.75rem;
	}

	.opt-in-cta {
		padding-inline: var(--space-5);
		text-align: center;
	}

	.secondary-cta {
		color: var(--text-secondary);
		font-size: var(--text-sm);
		font-weight: 500;
	}

	.secondary-cta:hover {
		color: var(--text-primary);
	}

	.shortcut-hint {
		color: var(--text-muted);
		font-size: var(--text-sm);
		margin-inline-start: var(--space-1);
	}
</style>

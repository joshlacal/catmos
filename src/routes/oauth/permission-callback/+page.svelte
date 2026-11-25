<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';

	onMount(() => {
		void goto('/settings/labyrinth', { replaceState: true });
	});
</script>

<svelte:head>
	<title>Redirecting · Catmos</title>
</svelte:head>

<main id="main-thread" class="callback-shell">
	<section class="callback-card" aria-live="polite">
		<div class="callback-state" role="status">
			<progress
				class="catmos-progress callback-progress"
				aria-label="Redirecting to Encrypted Chat settings"
			></progress>
			<h1 class="callback-heading">Redirecting</h1>
			<p class="callback-body">
				Permissions are now requested directly during Bluesky sign-in.
			</p>
			<div class="callback-actions">
				<a class="catmos-btn-primary callback-link" href="/settings/labyrinth">
					Open backup settings
				</a>
			</div>
		</div>
	</section>
</main>

<style>
	.callback-shell {
		min-block-size: 100dvh;
		inline-size: 100%;
		display: flex;
		align-items: center;
		justify-content: center;
		padding: var(--space-6) var(--space-4);
		background: var(--bg-app);
		color: var(--text-primary);
		overflow-y: auto;
	}

	.callback-card {
		inline-size: 100%;
		max-inline-size: 25rem;
		padding: var(--space-8) var(--space-6);
		background: var(--bg-surface);
		border: 1px solid var(--border);
		border-radius: var(--radius-lg);
		box-shadow: var(--shadow-md);
		text-align: center;
	}

	.callback-state {
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: var(--space-3);
	}

	.callback-progress {
		inline-size: 1.75rem;
		block-size: 1.75rem;
	}

	.callback-heading {
		font-size: var(--text-heading);
		font-weight: 650;
		letter-spacing: -0.015em;
		line-height: 1.3;
		color: var(--text-primary);
		text-wrap: balance;
	}

	.callback-body {
		font-size: var(--text-sm);
		line-height: 1.48;
		color: var(--text-secondary);
		max-inline-size: 38ch;
	}

	.callback-actions {
		margin-block-start: var(--space-2);
		inline-size: 100%;
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
	}

	.callback-link {
		inline-size: 100%;
		min-block-size: 2.75rem;
	}
</style>

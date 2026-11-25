<script lang="ts">
	import Icon from '#lib/components/Icon.svelte';
	import { TAB_WAITING_MESSAGE } from '#lib/tab-lock.ts';
</script>

<main id="main-thread" class="tab-blocked-shell" role="status" aria-live="polite">
	<section class="tab-blocked-panel" aria-labelledby="tab-blocked-heading">
		<span class="tab-blocked-icon squircle" aria-hidden="true">
			<Icon name="lock" size={26} />
		</span>

		<h1 id="tab-blocked-heading" class="tab-blocked-heading">{TAB_WAITING_MESSAGE}</h1>

		<p class="tab-blocked-body">
			Encrypted chat uses an exclusive OPFS database handle per account. Close the other active
			Catmos tab and this window will automatically resume without interrupting your encryption
			state.
		</p>

		<button
			type="button"
			class="catmos-btn-secondary close-tab-btn"
			onclick={() => window.close()}
		>
			Close this tab
		</button>
	</section>
</main>

<style>
	.tab-blocked-shell {
		min-block-size: 100dvh;
		inline-size: 100%;
		display: flex;
		align-items: center;
		justify-content: center;
		padding: var(--space-6) var(--space-4);
		background: var(--bg-app);
	}

	.tab-blocked-panel {
		inline-size: 100%;
		max-inline-size: 26rem;
		display: flex;
		flex-direction: column;
		align-items: center;
		text-align: center;
		gap: var(--space-3);
		padding: var(--space-8) var(--space-6);
		background: var(--bg-surface);
		border: 1px solid var(--border);
		border-radius: var(--radius-lg);
		box-shadow: var(--shadow-md);
	}

	.tab-blocked-icon {
		inline-size: 3.5rem;
		block-size: 3.5rem;
		display: inline-flex;
		align-items: center;
		justify-content: center;
		background: var(--bg-elevated);
		border: 1px solid var(--border);
		color: var(--text-primary);
		margin-block-end: var(--space-1);
	}

	.tab-blocked-heading {
		font-size: var(--text-heading);
		font-weight: 650;
		letter-spacing: -0.015em;
		line-height: 1.3;
		color: var(--text-primary);
		text-wrap: balance;
	}

	.tab-blocked-body {
		font-size: var(--text-sm);
		line-height: 1.5;
		color: var(--text-secondary);
		max-inline-size: 40ch;
		margin-block-end: var(--space-2);
	}

	.close-tab-btn {
		inline-size: 100%;
		min-block-size: 2.75rem;
	}
</style>

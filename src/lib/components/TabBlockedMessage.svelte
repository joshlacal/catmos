<script lang="ts">
	import { TAB_WAITING_MESSAGE } from '#lib/tab-lock.ts';
</script>

<div class="tab-blocked-overlay" role="status" aria-live="polite">
	<div class="tab-blocked-card">
		<div class="icon" aria-hidden="true">
			<svg
				width="48"
				height="48"
				viewBox="0 0 24 24"
				fill="none"
				stroke="currentColor"
				stroke-width="1.5"
				stroke-linecap="round"
				stroke-linejoin="round"
			>
				<rect x="3" y="3" width="18" height="18" rx="2" ry="2" />
				<line x1="9" y1="3" x2="9" y2="21" />
				<circle cx="15" cy="12" r="2" />
			</svg>
		</div>

		<h1>{TAB_WAITING_MESSAGE}</h1>
		<p>
			Encrypted chat uses an exclusive OPFS database handle per account. Close the other active
			Catmos tab and this window will automatically resume without interrupting encryption state.
		</p>

		<div class="actions">
			<button type="button" class="btn-secondary" onclick={() => window.close()}>
				Close this tab
			</button>
		</div>
	</div>
</div>

<style>
	.tab-blocked-overlay {
		position: fixed;
		inset: 0;
		z-index: 9999;
		display: flex;
		align-items: center;
		justify-content: center;
		background: var(--bg-app);
	}

	.tab-blocked-card {
		max-width: 420px;
		padding: 40px 32px;
		text-align: center;
		background: var(--bg-card);
		border: 1px solid var(--border);
		border-radius: var(--radius-lg);
		box-shadow: var(--shadow-lg);
	}

	.icon {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		width: 72px;
		height: 72px;
		margin-bottom: 20px;
		border-radius: var(--radius-md);
		background: var(--bg-elevated);
		color: var(--text-secondary);
	}

	h1 {
		font-size: 18px;
		font-weight: 600;
		color: var(--text-primary);
		margin-bottom: 8px;
		line-height: 1.3;
	}

	p {
		font-size: 14px;
		color: var(--text-secondary);
		line-height: 1.5;
		margin-bottom: 28px;
	}

	.actions {
		display: flex;
		flex-direction: column;
		gap: 10px;
	}

	.btn-secondary {
		padding: 10px 20px;
		border-radius: var(--radius-sm);
		background: var(--bg-elevated);
		color: var(--text-primary);
		font-weight: 500;
		font-size: 14px;
		border: 1px solid var(--border);
		transition: all var(--transition-fast);
	}

	.btn-secondary:hover {
		background: var(--bg-hover);
		border-color: var(--border-strong);
	}
</style>

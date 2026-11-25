<script lang="ts">
	import Icon from '#lib/components/Icon.svelte';
	import { auth, validateLoginIdentifier } from '#lib/stores/auth.ts';
	import { preferences, setScheme, type ThemeScheme } from '#lib/stores/preferences.ts';

	let identifier = $state('');
	let validationError = $state<string | null>(null);
	let inputEl = $state<HTMLInputElement | null>(null);

	const schemeOptions: readonly { value: ThemeScheme; label: string }[] = [
		{ value: 'system', label: 'System' },
		{ value: 'light', label: 'Light' },
		{ value: 'dim', label: 'Dim' },
		{ value: 'black', label: 'Black' }
	];

	function handleInput() {
		if (validationError) {
			validationError = null;
		}
		if ($auth.error) {
			auth.clearError();
		}
	}

	async function handleSubmit(event: SubmitEvent) {
		event.preventDefault();
		if ($auth.loading) return;

		const result = validateLoginIdentifier(identifier);
		if (!result.ok) {
			validationError = result.error;
			inputEl?.focus();
			return;
		}

		validationError = null;
		await auth.startLogin(result.identifier);
	}

	async function handleRestore() {
		if ($auth.loading) return;
		validationError = null;
		try {
			await auth.tryRestore();
		} catch {
			// Error surfaced via $auth.error
		}
	}

	function handleCancelWaiting() {
		validationError = null;
		void auth.cancelLogin();
	}
</script>

<main id="main-thread" class="auth-workspace">
	<div class="auth-stack">
		<section class="auth-panel" aria-labelledby="auth-heading">
			<div class="brand-lockup">
				<span class="brand-mark squircle" aria-hidden="true">
					<Icon name="catbird" size={26} />
				</span>
				<span class="brand-wordmark">catmos</span>
			</div>

			<div class="auth-intro">
				<h1 id="auth-heading" class="auth-heading">Private messaging for Bluesky</h1>
				<p class="auth-subtitle">
					Sign in with your Bluesky handle. Messages stay end-to-end encrypted on your devices with
					MLS.
				</p>
			</div>

			{#if $auth.waitingForOAuth}
				<div class="oauth-waiting" role="status" aria-live="polite">
					<progress class="catmos-progress waiting-progress" aria-label="Signing in"></progress>
					<p class="waiting-text">Finish signing in using the browser window that opened.</p>
					<button
						type="button"
						class="catmos-btn-secondary full-width"
						onclick={handleCancelWaiting}
					>
						Cancel
					</button>
				</div>
			{:else}
				<form class="auth-form" onsubmit={handleSubmit} novalidate>
					<div class="field-group">
						<label class="field-label" for="login-handle">Bluesky handle or DID</label>
						<p id="login-handle-hint" class="field-hint">
							For example, alice.bsky.social or did:plc:...
						</p>
						<input
							bind:this={inputEl}
							id="login-handle"
							name="username"
							type="text"
							class="handle-input"
							autocomplete="username"
							autocorrect="off"
							autocapitalize="none"
							spellcheck="false"
							enterkeyhint="go"
							required
							placeholder="alice.bsky.social"
							bind:value={identifier}
							oninput={handleInput}
							aria-invalid={validationError ? 'true' : 'false'}
							aria-describedby={validationError
								? 'login-handle-hint login-handle-error'
								: 'login-handle-hint'}
						/>
						{#if validationError}
							<p id="login-handle-error" class="field-error" role="alert">
								<Icon name="alert-triangle" size={16} />
								<span>{validationError}</span>
							</p>
						{/if}
					</div>

					{#if $auth.error}
						<div class="auth-error-block" role="alert">
							<div class="auth-error-row">
								<Icon name="shield-alert" size={18} />
								<p class="auth-error-text">{$auth.error}</p>
							</div>
							<button
								type="button"
								class="catmos-btn-secondary full-width"
								disabled={$auth.loading}
								onclick={handleRestore}
							>
								Try restoring previous session
							</button>
						</div>
					{/if}

					<button
						type="submit"
						class="catmos-btn-primary submit-btn full-width"
						disabled={$auth.loading}
					>
						{#if $auth.loading}
							<progress class="catmos-progress btn-progress" aria-hidden="true"></progress>
							<span>Signing in...</span>
						{:else}
							<span>Sign in with Bluesky</span>
						{/if}
					</button>
				</form>
			{/if}
		</section>

		<footer class="auth-footer">
			<fieldset class="catmos-segmented theme-switcher">
				<legend class="visually-hidden">Appearance</legend>
				{#each schemeOptions as option (option.value)}
					<label>
						<input
							type="radio"
							name="auth-theme-scheme"
							value={option.value}
							checked={$preferences.scheme === option.value}
							onchange={() => setScheme(option.value)}
						/>
						<span>{option.label}</span>
					</label>
				{/each}
			</fieldset>
		</footer>
	</div>
</main>

<style>
	.auth-workspace {
		flex: 1;
		min-block-size: 100dvh;
		inline-size: 100%;
		display: flex;
		align-items: center;
		justify-content: center;
		padding: max(var(--space-6), env(safe-area-inset-top, 0px)) var(--space-4)
			max(var(--space-6), env(safe-area-inset-bottom, 0px));
		background: var(--bg-app);
		overflow-y: auto;
	}

	.auth-stack {
		inline-size: 100%;
		max-inline-size: 25rem;
		display: flex;
		flex-direction: column;
		gap: var(--space-5);
	}

	.auth-panel {
		display: flex;
		flex-direction: column;
		gap: var(--space-5);
		padding: var(--space-6);
		background: var(--bg-surface);
		border: 1px solid var(--border);
		border-radius: var(--radius-lg);
		box-shadow: var(--shadow-md);
	}

	.brand-lockup {
		display: flex;
		align-items: center;
		gap: var(--space-3);
	}

	.brand-mark {
		inline-size: 2.75rem;
		block-size: 2.75rem;
		display: inline-flex;
		align-items: center;
		justify-content: center;
		background: var(--brand-gradient);
		border-radius: var(--radius-sm);
		flex-shrink: 0;
	}

	.brand-wordmark {
		font-family: var(--font-display);
		font-size: 1.75rem;
		font-weight: 900;
		font-variation-settings:
			'wdth' 125,
			'wght' 900;
		letter-spacing: -0.025em;
		line-height: 1;
		color: var(--text-primary);
	}

	.auth-intro {
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
	}

	.auth-heading {
		font-size: 1.25rem;
		font-weight: 650;
		letter-spacing: -0.02em;
		line-height: 1.3;
		color: var(--text-primary);
		text-wrap: balance;
	}

	.auth-subtitle {
		font-size: var(--text-sm);
		line-height: 1.48;
		color: var(--text-secondary);
		max-inline-size: 65ch;
	}

	.auth-form {
		display: flex;
		flex-direction: column;
		gap: var(--space-4);
	}

	.field-group {
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
	}

	.field-label {
		font-size: var(--text-sm);
		font-weight: 600;
		color: var(--text-primary);
	}

	.field-hint {
		font-size: var(--text-sm);
		color: var(--text-muted);
		line-height: 1.38;
		margin-block-end: var(--space-1);
	}

	.handle-input {
		inline-size: 100%;
		min-block-size: 2.75rem;
		padding: var(--space-2) var(--space-3);
		background: var(--bg-input);
		border: 1.5px solid var(--border-input);
		border-radius: var(--radius-sm);
		color: var(--text-primary);
		font-size: var(--text-body);
		line-height: 1.4;
		transition:
			border-color var(--dur-fast) var(--ease-out),
			background-color var(--dur-fast) var(--ease-out);
	}

	.handle-input::placeholder {
		color: var(--text-muted);
	}

	.handle-input:focus-visible {
		border-color: var(--accent-fill);
		outline: 2px solid var(--focus-ring);
		outline-offset: 2px;
	}

	.handle-input[aria-invalid='true'] {
		border-color: var(--danger-text);
	}

	.field-error {
		display: flex;
		align-items: flex-start;
		gap: var(--space-2);
		margin-block-start: var(--space-1);
		font-size: var(--text-sm);
		line-height: 1.4;
		color: var(--danger-text);
	}

	.auth-error-block {
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
		padding: var(--space-3);
		border-radius: var(--radius-sm);
		background: var(--danger-bg);
		border: 1px solid var(--danger-text);
	}

	.auth-error-row {
		display: flex;
		align-items: flex-start;
		gap: var(--space-2);
		color: var(--danger-text);
	}

	.auth-error-text {
		font-size: var(--text-sm);
		line-height: 1.42;
		color: var(--danger-text);
		word-break: break-word;
	}

	.submit-btn {
		min-block-size: 2.75rem;
	}

	.full-width {
		inline-size: 100%;
	}

	.btn-progress {
		inline-size: 1rem;
		block-size: 1rem;
		border-color: rgba(255, 255, 255, 0.35);
		border-top-color: #ffffff;
	}

	.oauth-waiting {
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: var(--space-4);
		padding-block: var(--space-3);
		text-align: center;
	}

	.waiting-progress {
		inline-size: 1.75rem;
		block-size: 1.75rem;
	}

	.waiting-text {
		font-size: var(--text-body);
		color: var(--text-primary);
		line-height: 1.45;
		max-inline-size: 32ch;
	}

	.auth-footer {
		display: flex;
		justify-content: center;
	}

	.theme-switcher {
		inline-size: 100%;
	}

	@media (max-width: 480px) {
		.auth-panel {
			padding: var(--space-5);
		}
	}
</style>

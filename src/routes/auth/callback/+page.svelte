<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import Icon from '#lib/components/Icon.svelte';
	import { validateWebOAuthCallbackUrl } from '#lib/oauth-callback.ts';
	import {
		consumePendingUpgradeReturnPath,
		exchangeOAuthCode,
		hasPendingOAuthUpgrade
	} from '#lib/wasm.ts';
	import { auth } from '#lib/stores/auth.ts';

	let phase = $state<'loading' | 'error'>('loading');
	let errorMessage = $state('');

	onMount(async () => {
		const rawHref = page.url.toString();
		const expectedOrigin = typeof window !== 'undefined' ? window.location.origin : undefined;

		// Scrub OAuth query parameters from browser history immediately so one-time
		// codes or session tokens do not linger in the address bar or Referer header.
		if (typeof window !== 'undefined' && window.history?.replaceState) {
			window.history.replaceState({}, '', '/auth/callback');
		}

		try {
			const validated = validateWebOAuthCallbackUrl(rawHref, expectedOrigin);
			if (validated.kind === 'error') {
				const detail = validated.errorDescription
					? `${validated.error}: ${validated.errorDescription}`
					: validated.error;
				phase = 'error';
				errorMessage = `Sign-in failed: ${detail}`;
				return;
			}

			if (validated.kind === 'code' && hasPendingOAuthUpgrade()) {
				await auth.completeOAuthUpgradeCallback(validated.code);
				await goto(consumePendingUpgradeReturnPath(), { replaceState: true });
				return;
			}

			const sessionId =
				validated.kind === 'code'
					? await exchangeOAuthCode(validated.code)
					: validated.sessionId;

			await auth.completeOAuthCallback(sessionId);
			await goto('/', { replaceState: true });
		} catch (e) {
			phase = 'error';
			errorMessage = `Sign-in failed: ${e instanceof Error ? e.message : String(e)}`;
		}
	});
</script>

<svelte:head>
	<title>Completing sign in · Catmos</title>
</svelte:head>

<main id="main-thread" class="callback-shell">
	<section class="callback-card" aria-live="polite">
		{#if phase === 'loading'}
			<div class="callback-state" role="status">
				<progress class="catmos-progress callback-progress" aria-label="Completing sign in"></progress>
				<h1 class="callback-heading">Completing sign in</h1>
				<p class="callback-body">Verifying your Bluesky session on this device.</p>
			</div>
		{:else}
			<div class="callback-state" role="alert">
				<span class="callback-icon squircle" aria-hidden="true">
					<Icon name="shield-alert" size={24} />
				</span>
				<h1 class="callback-heading">Could not sign in</h1>
				<p class="callback-error">{errorMessage}</p>
				<div class="callback-actions">
					<a class="catmos-btn-primary callback-link" href="/">Back to sign in</a>
				</div>
			</div>
		{/if}
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

	.callback-icon {
		inline-size: 3.25rem;
		block-size: 3.25rem;
		display: inline-flex;
		align-items: center;
		justify-content: center;
		background: var(--danger-bg);
		color: var(--danger-text);
		margin-block-end: var(--space-1);
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

	.callback-error {
		font-size: var(--text-sm);
		line-height: 1.48;
		color: var(--danger-text);
		word-break: break-word;
		max-inline-size: 40ch;
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

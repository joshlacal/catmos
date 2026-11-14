<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { validateWebOAuthCallbackUrl } from '#lib/oauth-callback.ts';
	import {
		consumePendingUpgradeReturnPath,
		exchangeOAuthCode,
		hasPendingOAuthUpgrade
	} from '#lib/wasm.ts';
	import { auth } from '#lib/stores/auth.ts';

	let status = $state('Completing sign in…');

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
				status = `Sign-in failed: ${detail}`;
				return;
			}

			if (validated.kind === 'code' && hasPendingOAuthUpgrade()) {
				await auth.completeOAuthUpgradeCallback(validated.code);
				goto(consumePendingUpgradeReturnPath());
				return;
			}

			const sessionId =
				validated.kind === 'code'
					? await exchangeOAuthCode(validated.code)
					: validated.sessionId;

			await auth.completeOAuthCallback(sessionId);
			goto('/');
		} catch (e) {
			status = `Sign-in failed: ${e instanceof Error ? e.message : String(e)}`;
		}
	});
</script>

<div class="callback-container">
	<p>{status}</p>
</div>

<style>
	.callback-container {
		display: flex;
		align-items: center;
		justify-content: center;
		height: 100vh;
		color: var(--text-normal, #dcddde);
		font-family: system-ui, sans-serif;
	}
</style>

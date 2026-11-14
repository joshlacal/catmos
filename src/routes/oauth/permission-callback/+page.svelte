<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { validateWebPermissionCallbackUrl } from '#lib/oauth-callback.ts';
	import { clearPendingOAuthUpgrade, consumePendingUpgradeReturnPath } from '#lib/wasm.ts';
	import { auth } from '#lib/stores/auth.ts';

	let status = $state('Completing permission upgrade…');

	onMount(async () => {
		const rawHref = page.url.toString();
		const expectedOrigin = typeof window !== 'undefined' ? window.location.origin : undefined;

		if (typeof window !== 'undefined' && window.history?.replaceState) {
			window.history.replaceState({}, '', '/oauth/permission-callback');
		}

		try {
			const validated = validateWebPermissionCallbackUrl(rawHref, expectedOrigin);
			if (validated.kind === 'error') {
				clearPendingOAuthUpgrade();
				const detail = validated.errorDescription
					? `${validated.error}: ${validated.errorDescription}`
					: validated.error;
				status = `Permission upgrade cancelled or denied: ${detail}`;
				return;
			}
			if (validated.kind !== 'code') {
				clearPendingOAuthUpgrade();
				status = 'Permission upgrade failed: expected authorization code callback.';
				return;
			}

			await auth.completeOAuthUpgradeCallback(validated.code);
			goto(consumePendingUpgradeReturnPath());
		} catch (e) {
			clearPendingOAuthUpgrade();
			status = `Permission upgrade failed: ${e instanceof Error ? e.message : String(e)}`;
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

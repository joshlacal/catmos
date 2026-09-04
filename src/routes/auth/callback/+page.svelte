<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { page } from '$app/stores';
	import { auth } from '$lib/stores/auth';
	import { exchangeOAuthCode, clearPendingOAuthLogin } from '$lib/wasm';

	let status = $state('Completing sign in…');

	onMount(async () => {
		// Security: NEVER accept session_id directly in callback URL
		if ($page.url.searchParams.has('session_id')) {
			clearPendingOAuthLogin();
			status = 'Error: direct session_id in callback URL is forbidden.';
			return;
		}

		const error = $page.url.searchParams.get('error');
		if (error) {
			clearPendingOAuthLogin();
			const errorDescription = $page.url.searchParams.get('error_description');
			status = `Sign-in failed: ${error}${errorDescription ? ` (${errorDescription})` : ''}`;
			return;
		}

		const code = $page.url.searchParams.get('code');
		if (!code) {
			clearPendingOAuthLogin();
			status = 'Error: missing one-time code in callback URL.';
			return;
		}

		try {
			const sessionId = await exchangeOAuthCode(code);
			await auth.completeOAuthCallback(sessionId);
			goto('/');
		} catch (e) {
			clearPendingOAuthLogin();
			status = `Sign-in failed: ${e}`;
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

<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { page } from '$app/stores';
	import { auth } from '$lib/stores/auth';
	import { parseOAuthCallback } from '$lib/oauth-exchange';

	let status = $state('Completing sign in…');

	onMount(async () => {
		try {
			const code = parseOAuthCallback($page.url);
			await auth.completeOAuthCallback(code);
			goto('/');
		} catch {
			status = 'Sign-in failed. Please restart the login flow.';
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

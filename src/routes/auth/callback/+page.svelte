<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { auth } from '#lib/stores/auth.ts';

	let status = $state('Completing sign in…');

	onMount(async () => {
		const sessionId = page.url.searchParams.get('session_id');
		if (!sessionId) {
			status = 'Error: missing session_id in callback URL.';
			return;
		}
		try {
			await auth.completeOAuthCallback(sessionId);
			goto('/');
		} catch (e) {
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

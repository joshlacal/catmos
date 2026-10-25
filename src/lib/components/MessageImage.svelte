<script lang="ts">
	import { onDestroy } from 'svelte';
	import type { ImageAttachment } from '#lib/tauri.ts';
	import { getImageAttachment } from '#lib/wasm.ts';

	let { image, fallbackAlt }: { image: ImageAttachment; fallbackAlt?: string } = $props();

	let src = $state('');
	let loading = $state(false);
	let error = $state<string | null>(null);
	let cancelled = false;

	$effect(() => {
		src = image.localUrl ?? '';
		error = null;
		loading = !image.localUrl && !!image.blobId;

		if (image.localUrl || !image.blobId) {
			return;
		}

		(async () => {
			try {
				const resolved = await getImageAttachment(image);
				if (!cancelled) {
					src = resolved;
					loading = false;
				}
			} catch (err) {
				if (!cancelled) {
					console.error('[catmos] getImageAttachment failed:', err);
					error = 'Failed to load image';
					loading = false;
				}
			}
		})();
	});

	onDestroy(() => {
		cancelled = true;
		if (image.localUrl?.startsWith('blob:')) {
			URL.revokeObjectURL(image.localUrl);
		}
	});
</script>

<div class="image-shell" style={`aspect-ratio: ${Math.max(image.width, 1)} / ${Math.max(image.height, 1)};`}>
	{#if src}
		<img
			class="image"
			src={src}
			alt={image.altText ?? fallbackAlt ?? 'Image attachment'}
			loading="lazy"
		/>
	{:else if loading}
		<div class="image-placeholder">
			<div class="loading-spinner"></div>
		</div>
	{:else}
		<div class="image-placeholder error">
			<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
				<rect x="3" y="3" width="18" height="18" rx="2" ry="2" />
				<circle cx="8.5" cy="8.5" r="1.5" />
				<polyline points="21 15 16 10 5 21" />
			</svg>
			<span>{error ?? 'Image unavailable'}</span>
		</div>
	{/if}
</div>

<style>
	.image-shell {
		margin-bottom: 4px;
		max-width: min(360px, 100%);
		border-radius: var(--radius-md);
		overflow: hidden;
		background: var(--bg-hover);
	}

	.image {
		display: block;
		width: 100%;
		height: 100%;
		object-fit: cover;
	}

	.image-placeholder {
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
		gap: 8px;
		padding: 24px;
		color: var(--text-tertiary);
		font-size: 12px;
	}

	.image-placeholder.error {
		color: var(--danger);
	}

	.loading-spinner {
		width: 24px;
		height: 24px;
		border: 2px solid var(--border);
		border-top: 2px solid var(--text-secondary);
		border-radius: var(--radius-full);
		animation: spin 0.8s linear infinite;
	}

	@keyframes spin {
		to { transform: rotate(360deg); }
	}
</style>

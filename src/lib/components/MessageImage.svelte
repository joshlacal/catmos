<script lang="ts">
	import { onDestroy } from 'svelte';
	import type { ImageAttachment } from '#lib/wasm.ts';
	import { getImageAttachment } from '#lib/wasm.ts';
	import { useDialogLightDismiss, closeWithReset } from '#lib/utils/dialog.ts';
	import Icon from './Icon.svelte';

	let {
		image,
		fallbackAlt
	}: {
		image: ImageAttachment;
		fallbackAlt?: string;
	} = $props();

	let src = $state('');
	let loading = $state(false);
	let error = $state<string | null>(null);
	let retryNonce = $state(0);
	let lightboxEl: HTMLDialogElement | undefined = $state();
	let lightboxOpen = $state(false);
	let ownedObjectUrl: string | null = null;

	function revokeOwnedUrl() {
		if (ownedObjectUrl) {
			URL.revokeObjectURL(ownedObjectUrl);
			ownedObjectUrl = null;
		}
	}

	let directUrl = $derived.by(() => {
		if (image.localUrl) return image.localUrl;
		if (image.blobId && (image.blobId.startsWith('data:') || image.blobId.startsWith('blob:'))) {
			return image.blobId;
		}
		return null;
	});

	let altText = $derived(image.altText?.trim() || fallbackAlt?.trim() || 'Image attachment');
	let displayCaption = $derived(image.altText?.trim() || '');
	let safeWidth = $derived(Math.max(image.width || 4, 1));
	let safeHeight = $derived(Math.max(image.height || 3, 1));

	let downloadFilename = $derived.by(() => {
		const extMap: Record<string, string> = {
			'image/jpeg': 'jpg',
			'image/png': 'png',
			'image/webp': 'webp',
			'image/gif': 'gif'
		};
		const ext = extMap[image.contentType] ?? 'png';
		const stem = (image.blobId || 'catmos-image').replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 24);
		return `${stem || 'catmos-image'}.${ext}`;
	});

	$effect(() => {
		const currentDirect = directUrl;
		const currentImage = image;
		void retryNonce;

		revokeOwnedUrl();
		error = null;

		if (currentDirect) {
			src = currentDirect;
			loading = false;
			return;
		}

		if (!currentImage.blobId) {
			src = '';
			loading = false;
			error = 'Image unavailable';
			return;
		}

		let active = true;
		src = '';
		loading = true;

		(async () => {
			try {
				const resolved = await getImageAttachment(currentImage);
				if (!active) {
					if (resolved.startsWith('blob:')) {
						URL.revokeObjectURL(resolved);
					}
					return;
				}
				if (resolved.startsWith('blob:')) {
					ownedObjectUrl = resolved;
				}
				src = resolved;
				loading = false;
			} catch (err) {
				if (!active) return;
				console.error('[catmos] getImageAttachment failed:', err);
				error = 'Image unavailable';
				loading = false;
			}
		})();

		return () => {
			active = false;
		};
	});

	function openLightbox() {
		if (!src || !lightboxEl) return;
		lightboxOpen = true;
		if (!lightboxEl.open) {
			lightboxEl.showModal();
		}
	}

	function closeLightbox() {
		closeWithReset(lightboxEl ?? null, 'close');
		lightboxOpen = false;
	}

	function handleLightboxClose() {
		if (lightboxEl) {
			lightboxEl.returnValue = '';
		}
		lightboxOpen = false;
	}

	function handleRetry() {
		retryNonce += 1;
	}

	onDestroy(() => {
		if (lightboxEl?.open) {
			closeWithReset(lightboxEl);
		}
		revokeOwnedUrl();
	});
</script>

<div class="image-shell" style={`aspect-ratio: ${safeWidth} / ${safeHeight};`}>
	{#if src}
		<button
			type="button"
			class="image-trigger"
			onclick={openLightbox}
			aria-label={`View full image: ${altText}`}
		>
			<img class="image" {src} alt={altText} loading="lazy" decoding="async" />
		</button>
	{:else if loading}
		<div class="image-placeholder">
			<progress class="catmos-progress" aria-label="Loading image"></progress>
		</div>
	{:else}
		<div class="image-placeholder error">
			<Icon name="alert-triangle" size={20} />
			<span>{error ?? 'Image unavailable'}</span>
			{#if image.blobId}
				<button type="button" class="retry-btn" onclick={handleRetry}>Retry</button>
			{/if}
		</div>
	{/if}
</div>

<dialog
	bind:this={lightboxEl}
	class="catmos-dialog image-lightbox"
	closedby="any"
	use:useDialogLightDismiss
	onclose={handleLightboxClose}
>
	<div class="lightbox-header">
		<h1 class="lightbox-title">Image preview</h1>
		<div class="lightbox-actions">
			{#if src && lightboxOpen}
				<a
					href={src}
					download={downloadFilename}
					class="lightbox-action-btn"
					aria-label="Download image"
					title="Download image"
				>
					<Icon name="download" size={18} />
					<span>Download</span>
				</a>
			{/if}
			<button
				type="button"
				class="lightbox-close-btn"
				onclick={closeLightbox}
				aria-label="Close image preview"
				title="Close"
			>
				<Icon name="x" size={18} />
			</button>
		</div>
	</div>

	{#if src && lightboxOpen}
		<figure class="lightbox-figure">
			<img class="lightbox-img" {src} alt={altText} />
			{#if displayCaption}
				<figcaption class="lightbox-caption">{displayCaption}</figcaption>
			{/if}
		</figure>
	{/if}
</dialog>

<style>
	.image-shell {
		margin-block-end: var(--space-1);
		inline-size: 100%;
		max-inline-size: 26.25rem;
		max-block-size: 24rem;
		border-radius: var(--radius-md);
		overflow: hidden;
		background: var(--bg-surface);
	}

	.image-trigger {
		display: block;
		width: 100%;
		height: 100%;
		padding: 0;
		cursor: zoom-in;
		border-radius: var(--radius-md);
		overflow: hidden;
	}

	.image-trigger:focus-visible {
		outline: 2px solid var(--focus-ring);
		outline-offset: -2px;
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
		gap: var(--space-2);
		inline-size: 100%;
		block-size: 100%;
		min-block-size: 7rem;
		padding: var(--space-4);
		color: var(--text-secondary);
		font-size: var(--text-sm);
		text-align: center;
	}

	.image-placeholder.error {
		color: var(--danger-text);
	}

	.retry-btn {
		padding-block: var(--space-1);
		padding-inline: var(--space-3);
		min-block-size: max(2rem, var(--touch-min));
		border-radius: var(--radius-sm);
		background: var(--bg-elevated);
		border: 1px solid var(--border-strong);
		color: var(--text-primary);
		font-size: var(--text-sm);
		font-weight: 600;
		transition: background-color var(--dur-fast) var(--ease-out);
	}

	.retry-btn:hover {
		background: var(--bg-hover);
	}

	.image-lightbox {
		inline-size: min(56rem, calc(100vw - 2rem));
		max-inline-size: calc(100vw - 2rem);
		max-block-size: 90svh;
		background: var(--bg-elevated);
	}

	.lightbox-header {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: var(--space-3);
		padding-block: var(--space-3);
		padding-inline: var(--space-4);
		border-block-end: 1px solid var(--border);
		flex-shrink: 0;
	}

	.lightbox-title {
		font-size: var(--text-heading);
		font-weight: 650;
		line-height: 1.3;
		color: var(--text-primary);
	}

	.lightbox-actions {
		display: flex;
		align-items: center;
		gap: var(--space-2);
	}

	.lightbox-action-btn,
	.lightbox-close-btn {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		gap: var(--space-1);
		min-inline-size: max(2.25rem, var(--touch-min));
		min-block-size: max(2.25rem, var(--touch-min));
		border-radius: var(--radius-sm);
		font-size: var(--text-sm);
		font-weight: 600;
		color: var(--text-primary);
		text-decoration: none;
		transition: background-color var(--dur-fast) var(--ease-out);
	}

	.lightbox-action-btn {
		padding-inline: var(--space-3);
		background: var(--bg-surface);
		border: 1px solid var(--border-strong);
	}

	.lightbox-action-btn:hover,
	.lightbox-close-btn:hover {
		background: var(--bg-hover);
		text-decoration: none;
	}

	.lightbox-figure {
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
		gap: var(--space-3);
		padding: var(--space-4);
		overflow: auto;
		min-block-size: 0;
		flex: 1;
	}

	.lightbox-img {
		display: block;
		max-inline-size: 100%;
		max-block-size: calc(90svh - 8.5rem);
		inline-size: auto;
		block-size: auto;
		object-fit: contain;
		border-radius: var(--radius-sm);
	}

	.lightbox-caption {
		font-size: var(--text-sm);
		line-height: 1.45;
		color: var(--text-secondary);
		max-inline-size: 62ch;
		text-align: center;
		user-select: text;
	}
</style>

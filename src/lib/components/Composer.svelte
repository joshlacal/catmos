<script lang="ts">
	import { onDestroy } from 'svelte';
	import type { PreparedImageUpload } from '#lib/tauri.ts';
	import { drafts } from '#lib/stores/drafts.ts';

	let {
		conversationId,
		onSend,
		onSendImage,
		onTypingChanged,
		disabled = false,
		disabledPlaceholder
	}: {
		conversationId: string | null;
		onSend: (content: string) => void;
		onSendImage?: (content: string, image: PreparedImageUpload) => void | Promise<void>;
		onTypingChanged?: (isTyping: boolean) => void;
		/** When true, the composer is locked (Layer 3 quarantine, etc.). */
		disabled?: boolean;
		/** Optional placeholder shown while `disabled`. */
		disabledPlaceholder?: string;
	} = $props();

	let text = $state('');
	let inputEl: HTMLTextAreaElement | undefined = $state();
	let fileInputEl: HTMLInputElement | undefined = $state();
	let isTyping = $state(false);
	let idleTimer: ReturnType<typeof setTimeout> | null = $state(null);
	let uploadError = $state<string | null>(null);
	let isDragOver = $state(false);
	let dragCounter = $state(0);
	const TYPING_IDLE_MS = 3000;
	const ACCEPTED_IMAGE_TYPES = ['image/png', 'image/jpeg', 'image/gif', 'image/webp'];

	// Track previous conversation to save draft on switch
	let prevConvoId: string | null = null;

	$effect(() => {
		const newId = conversationId;
		if (newId !== prevConvoId) {
			// Save draft for the conversation we're leaving
			if (prevConvoId && text.trim()) {
				drafts.setDraft(prevConvoId, text);
			} else if (prevConvoId) {
				drafts.clearDraft(prevConvoId);
			}
			// Load draft for the new conversation
			text = newId ? drafts.getDraft(newId) : '';
			prevConvoId = newId;
		}
	});

	function clearIdleTimer() {
		if (idleTimer) {
			clearTimeout(idleTimer);
			idleTimer = null;
		}
	}

	function emitTyping(next: boolean) {
		if (isTyping === next) return;
		isTyping = next;
		onTypingChanged?.(next);
	}

	function scheduleIdleStop() {
		clearIdleTimer();
		idleTimer = setTimeout(() => {
			idleTimer = null;
			emitTyping(false);
		}, TYPING_IDLE_MS);
	}

	function handleInput() {
		if (conversationId) {
			drafts.setDraft(conversationId, text);
		}
		if (!text.trim()) {
			clearIdleTimer();
			emitTyping(false);
			return;
		}
		emitTyping(true);
		scheduleIdleStop();
	}

	function handleKeydown(e: KeyboardEvent) {
		if (e.key === 'Enter' && !e.shiftKey) {
			e.preventDefault();
			send();
		}
	}

	function send() {
		if (disabled) return;
		const trimmed = text.trim();
		if (!trimmed) return;
		uploadError = null;
		clearIdleTimer();
		emitTyping(false);
		onSend(trimmed);
		text = '';
		if (conversationId) {
			drafts.clearDraft(conversationId);
		}
		inputEl?.focus();
	}

	const MAX_BLOB_BYTES = 10 * 1024 * 1024;

	async function prepareImageUpload(file: File): Promise<PreparedImageUpload> {
		if (!file.type.startsWith('image/')) {
			throw new Error('Please choose an image file');
		}

		const previewUrl = URL.createObjectURL(file);
		const bitmap = await createImageBitmap(file);
		const origW = bitmap.width;
		const origH = bitmap.height;
		const inputType = file.type || 'image/jpeg';
		const canvasType = ['image/jpeg', 'image/png', 'image/webp'].includes(inputType)
			? inputType
			: 'image/jpeg';
		const outType = canvasType === inputType ? inputType : canvasType;

		if (file.size <= MAX_BLOB_BYTES && outType === inputType) {
			const data = new Uint8Array(await file.arrayBuffer());
			bitmap.close();
			return { data, contentType: inputType, width: origW, height: origH, previewUrl };
		}

		const result = await fitImageToSize(bitmap, canvasType, origW, origH, MAX_BLOB_BYTES);
		bitmap.close();
		return { ...result, contentType: outType, previewUrl };
	}

	async function fitImageToSize(
		bitmap: ImageBitmap,
		type: string,
		origW: number,
		origH: number,
		maxBytes: number
	): Promise<{ data: Uint8Array; width: number; height: number }> {
		const canvas = new OffscreenCanvas(origW, origH);

		if (type !== 'image/png') {
			const ctx = canvas.getContext('2d')!;
			ctx.drawImage(bitmap, 0, 0);
			for (const q of [0.8, 0.6, 0.4]) {
				const blob = await canvas.convertToBlob({ type, quality: q });
				if (blob.size <= maxBytes) {
					return { data: new Uint8Array(await blob.arrayBuffer()), width: origW, height: origH };
				}
			}
		}

		let scale = 0.75;
		for (let i = 0; i < 8; i++) {
			const w = Math.round(origW * scale);
			const h = Math.round(origH * scale);
			canvas.width = w;
			canvas.height = h;
			const ctx = canvas.getContext('2d')!;
			ctx.drawImage(bitmap, 0, 0, w, h);

			const quality = type === 'image/png' ? undefined : 0.8;
			const blob = await canvas.convertToBlob({ type, quality });
			if (blob.size <= maxBytes) {
				return { data: new Uint8Array(await blob.arrayBuffer()), width: w, height: h };
			}
			scale *= 0.75;
		}
		throw new Error('Image too large — could not fit within 10 MB');
	}

	async function handleFileChange(event: Event) {
		const input = event.currentTarget as HTMLInputElement;
		const file = input.files?.[0];
		input.value = '';
		if (!file || !onSendImage) return;

		try {
			uploadError = null;
			const prepared = await prepareImageUpload(file);
			const caption = text.trim();
			clearIdleTimer();
			emitTyping(false);
			await onSendImage(caption, prepared);
			text = '';
			if (conversationId) {
				drafts.clearDraft(conversationId);
			}
			inputEl?.focus();
		} catch (error) {
			console.error('[catmos] image preparation failed:', error);
			uploadError = error instanceof Error ? error.message : 'Failed to prepare image';
		}
	}

	// MARK: - Drag and drop
	function hasImageFile(dt: DataTransfer | null): boolean {
		if (!dt) return false;
		for (const item of dt.items) {
			if (item.kind === 'file' && ACCEPTED_IMAGE_TYPES.includes(item.type)) return true;
		}
		return false;
	}

	function handleDragEnter(e: DragEvent) {
		e.preventDefault();
		dragCounter++;
		if (onSendImage && hasImageFile(e.dataTransfer)) {
			isDragOver = true;
		}
	}

	function handleDragLeave(e: DragEvent) {
		e.preventDefault();
		dragCounter--;
		if (dragCounter <= 0) {
			dragCounter = 0;
			isDragOver = false;
		}
	}

	function handleDragOver(e: DragEvent) {
		e.preventDefault();
		if (e.dataTransfer) {
			e.dataTransfer.dropEffect = 'copy';
		}
	}

	async function handleDrop(e: DragEvent) {
		e.preventDefault();
		dragCounter = 0;
		isDragOver = false;
		if (!onSendImage || !e.dataTransfer) return;

		const file = Array.from(e.dataTransfer.files).find((f) =>
			ACCEPTED_IMAGE_TYPES.includes(f.type)
		);
		if (!file) return;

		try {
			uploadError = null;
			const prepared = await prepareImageUpload(file);
			const caption = text.trim();
			clearIdleTimer();
			emitTyping(false);
			await onSendImage(caption, prepared);
			text = '';
			if (conversationId) {
				drafts.clearDraft(conversationId);
			}
			inputEl?.focus();
		} catch (error) {
			console.error('[catmos] image drop failed:', error);
			uploadError = error instanceof Error ? error.message : 'Failed to prepare image';
		}
	}

	onDestroy(() => {
		clearIdleTimer();
		emitTyping(false);
	});
</script>

<div
	class="composer"
	class:drag-over={isDragOver}
	ondragenter={handleDragEnter}
	ondragleave={handleDragLeave}
	ondragover={handleDragOver}
	ondrop={handleDrop}
	role="region"
>
	{#if isDragOver}
		<div class="drop-zone-overlay">
			<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
				<rect x="3" y="3" width="18" height="18" rx="2" ry="2" />
				<circle cx="8.5" cy="8.5" r="1.5" />
				<polyline points="21 15 16 10 5 21" />
			</svg>
			<span>Drop image to attach</span>
		</div>
	{/if}
	<div class="composer-inner">
		{#if onSendImage}
			<input
				bind:this={fileInputEl}
				type="file"
				accept="image/*"
				class="hidden-file-input"
				onchange={handleFileChange}
			/>
			<button
				class="composer-btn attach"
				type="button"
				onclick={() => fileInputEl?.click()}
				aria-label="Send image"
				disabled={disabled}
			>
				<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
					<rect x="3" y="3" width="18" height="18" rx="2" ry="2" />
					<circle cx="8.5" cy="8.5" r="1.5" />
					<polyline points="21 15 16 10 5 21" />
				</svg>
			</button>
		{/if}
		<textarea
			bind:this={inputEl}
			bind:value={text}
			oninput={handleInput}
			onkeydown={handleKeydown}
			placeholder={disabled ? (disabledPlaceholder ?? 'Sending is disabled.') : 'Message...'}
			rows="1"
			disabled={disabled}
			aria-disabled={disabled}
		></textarea>
		<button
			class="composer-btn send"
			class:active={text.trim().length > 0 && !disabled}
			onclick={send}
			disabled={disabled || !text.trim()}
			aria-label="Send message"
		>
			<svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
				<path d="M2.01 21L23 12 2.01 3 2 10l15 2-15 2z"/>
			</svg>
		</button>
	</div>
	{#if uploadError}
		<div class="composer-error">{uploadError}</div>
	{/if}
</div>

<style>
	.composer {
		padding: 8px 20px 16px;
		flex-shrink: 0;
	}

	.composer-inner {
		display: flex;
		align-items: flex-end;
		gap: 6px;
		background: var(--bg-input);
		border: 1px solid var(--border);
		border-radius: var(--radius-lg);
		padding: 6px 8px;
		transition: border-color var(--transition-fast);
	}

	.composer-inner:focus-within {
		border-color: var(--accent);
	}

	.hidden-file-input {
		display: none;
	}

	textarea {
		flex: 1;
		resize: none;
		min-height: 24px;
		max-height: 120px;
		line-height: 1.45;
		background: transparent;
		color: var(--text-primary);
		padding: 4px 6px;
	}

	textarea::placeholder {
		color: var(--text-tertiary);
	}

	.composer-btn {
		width: 34px;
		height: 34px;
		display: flex;
		align-items: center;
		justify-content: center;
		border-radius: var(--radius-sm);
		transition: all var(--transition-fast);
		flex-shrink: 0;
	}

	.composer-btn.attach {
		color: var(--text-secondary);
	}

	.composer-btn.attach:hover {
		color: var(--text-primary);
		background: var(--bg-hover);
	}

	.composer-btn.send {
		color: var(--text-tertiary);
	}

	.composer-btn.send.active {
		color: var(--text-link);
	}

	.composer-btn.send:disabled {
		cursor: default;
	}

	.composer-btn.send:not(:disabled):hover {
		background: var(--bg-hover);
	}

	.composer-error {
		padding: 6px 8px 0;
		color: var(--danger);
		font-size: 12px;
	}

	/* ── Drop zone ── */
	.composer.drag-over {
		position: relative;
	}

	.drop-zone-overlay {
		position: absolute;
		inset: 0;
		display: flex;
		align-items: center;
		justify-content: center;
		gap: 8px;
		background: color-mix(in srgb, var(--accent) 10%, transparent);
		border: 2px dashed var(--accent);
		border-radius: var(--radius-lg);
		z-index: 10;
		color: var(--text-link);
		font-size: 14px;
		font-weight: 600;
		pointer-events: none;
	}

	@media (max-width: 768px) {
		.composer {
			padding: 8px 12px 12px;
		}
	}
</style>

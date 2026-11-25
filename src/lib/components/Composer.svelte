<script lang="ts">
	import { onDestroy, tick } from 'svelte';
	import type { Message, PreparedImageUpload } from '#lib/wasm.ts';
	import * as api from '#lib/wasm.ts';
	import { stripDidFragment } from '#lib/did.ts';
	import { messages } from '#lib/stores/messages.ts';
	import { drafts } from '#lib/stores/drafts.ts';
	import { extractMessagePreview } from '#lib/stores/conversations.ts';
	import { announce, showToast } from '#lib/utils/announcer.ts';
	import Icon from './Icon.svelte';
	import ReplyPreview from './ReplyPreview.svelte';
	import VoiceRecorder, { type RecordedVoicePayload } from './VoiceRecorder.svelte';

	const TYPING_IDLE_MS = 3000;
	const MAX_BLOB_BYTES = 10 * 1024 * 1024;
	const ACCEPTED_IMAGE_TYPES = ['image/png', 'image/jpeg', 'image/gif', 'image/webp'];

	interface PendingImage {
		file: File;
		previewUrl: string;
		altText: string;
	}

	let {
		conversationId,
		replyTo = null,
		disabled = false,
		disabledReason = null,
		onCancelReply
	}: {
		conversationId: string;
		replyTo?: Message | null;
		disabled?: boolean;
		disabledReason?: string | null;
		onCancelReply: () => void;
	} = $props();

	let text = $state('');
	let pendingImage = $state<PendingImage | null>(null);
	let isRecordingVoice = $state(false);
	let sending = $state(false);
	let uploadError = $state<string | null>(null);
	let isDragOver = $state(false);
	let dragCounter = 0;

	let formEl: HTMLFormElement | undefined = $state();
	let inputEl: HTMLTextAreaElement | undefined = $state();
	let fileInputEl: HTMLInputElement | undefined = $state();

	let isTyping = false;
	let idleTimer: ReturnType<typeof setTimeout> | null = null;
	let prevConvoId: string | null = null;
	let prevReplyId: string | null = null;
	const ownedObjectUrls = new Set<string>();

	let canSend = $derived(!disabled && !sending && (text.trim().length > 0 || pendingImage !== null));

	function createTrackedObjectUrl(source: Blob | File): string {
		const url = URL.createObjectURL(source);
		ownedObjectUrls.add(url);
		return url;
	}

	function revokeTrackedObjectUrl(url: string | null | undefined) {
		if (!url) return;
		if (ownedObjectUrls.has(url)) {
			ownedObjectUrls.delete(url);
		}
		if (url.startsWith('blob:')) {
			URL.revokeObjectURL(url);
		}
	}

	function clearPendingImage() {
		if (pendingImage) {
			revokeTrackedObjectUrl(pendingImage.previewUrl);
			pendingImage = null;
		}
	}

	function syncTextareaHeight() {
		if (!inputEl) return;
		if (
			typeof CSS !== 'undefined' &&
			typeof CSS.supports === 'function' &&
			CSS.supports('field-sizing', 'content')
		) {
			return;
		}
		inputEl.style.height = 'auto';
		inputEl.style.height = `${Math.min(inputEl.scrollHeight, 160)}px`;
	}

	function clearIdleTimer() {
		if (idleTimer !== null) {
			clearTimeout(idleTimer);
			idleTimer = null;
		}
	}

	function emitTyping(targetConvoId: string | null, next: boolean) {
		if (!targetConvoId) return;
		if (isTyping === next) return;
		isTyping = next;
		api.sendTyping(targetConvoId, next).catch(() => {
			// Best-effort typing signal
		});
	}

	function scheduleIdleStop(targetConvoId: string) {
		clearIdleTimer();
		idleTimer = setTimeout(() => {
			idleTimer = null;
			emitTyping(targetConvoId, false);
		}, TYPING_IDLE_MS);
	}

	// Persist and restore drafts cleanly on conversation switch
	$effect(() => {
		const nextConvoId = conversationId;
		if (nextConvoId !== prevConvoId) {
			if (prevConvoId) {
				clearIdleTimer();
				emitTyping(prevConvoId, false);
				if (text.trim()) {
					drafts.setDraft(prevConvoId, text);
				} else {
					drafts.clearDraft(prevConvoId);
				}
			}
			clearPendingImage();
			isRecordingVoice = false;
			uploadError = null;
			text = nextConvoId ? drafts.getDraft(nextConvoId) : '';
			prevConvoId = nextConvoId;
			void tick().then(() => syncTextareaHeight());
		}
	});

	// Enforce lock immediately if conversation becomes disabled / quarantined
	$effect(() => {
		if (disabled) {
			isDragOver = false;
			dragCounter = 0;
			if (isRecordingVoice) {
				isRecordingVoice = false;
			}
			clearIdleTimer();
			emitTyping(conversationId, false);
		}
	});

	// Focus composer input when entering reply mode
	$effect(() => {
		const nextReplyId = replyTo?.id ?? null;
		if (nextReplyId && nextReplyId !== prevReplyId && !disabled) {
			void tick().then(() => inputEl?.focus());
		}
		prevReplyId = nextReplyId;
	});

	function handleInput() {
		syncTextareaHeight();
		if (disabled) return;
		if (conversationId) {
			drafts.setDraft(conversationId, text);
		}
		if (!text.trim()) {
			clearIdleTimer();
			emitTyping(conversationId, false);
			return;
		}
		emitTyping(conversationId, true);
		scheduleIdleStop(conversationId);
	}

	function handleKeydown(event: KeyboardEvent) {
		if (event.key === 'Enter' && !event.shiftKey) {
			event.preventDefault();
			if (event.isComposing || event.keyCode === 229) return;
			if (!disabled) {
				formEl?.requestSubmit();
			}
		}
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
			const ctx = canvas.getContext('2d');
			if (!ctx) throw new Error('Could not initialize image encoder.');
			ctx.drawImage(bitmap, 0, 0);
			for (const q of [0.8, 0.6, 0.4]) {
				const blob = await canvas.convertToBlob({ type, quality: q });
				if (blob.size <= maxBytes) {
					return {
						data: new Uint8Array(await blob.arrayBuffer()),
						width: origW,
						height: origH
					};
				}
			}
		}

		let scale = 0.75;
		for (let i = 0; i < 8; i += 1) {
			const w = Math.max(1, Math.round(origW * scale));
			const h = Math.max(1, Math.round(origH * scale));
			canvas.width = w;
			canvas.height = h;
			const ctx = canvas.getContext('2d');
			if (!ctx) throw new Error('Could not initialize image encoder.');
			ctx.drawImage(bitmap, 0, 0, w, h);

			const quality = type === 'image/png' ? undefined : 0.8;
			const blob = await canvas.convertToBlob({ type, quality });
			if (blob.size <= maxBytes) {
				return { data: new Uint8Array(await blob.arrayBuffer()), width: w, height: h };
			}
			scale *= 0.75;
		}
		throw new Error('Image is too large to fit within 10 MB.');
	}

	async function prepareImageUpload(file: File, altText?: string): Promise<PreparedImageUpload> {
		if (!file.type.startsWith('image/')) {
			throw new Error('Please choose an image file.');
		}

		const inputType = file.type || 'image/jpeg';
		const cleanAlt = altText?.trim() || undefined;

		if (typeof createImageBitmap !== 'function') {
			if (file.size > MAX_BLOB_BYTES) {
				throw new Error('Image is too large to fit within 10 MB.');
			}
			const data = new Uint8Array(await file.arrayBuffer());
			const optimisticPreviewUrl = createTrackedObjectUrl(
				new Blob([data as BlobPart], { type: inputType })
			);
			return {
				data,
				contentType: inputType,
				width: 0,
				height: 0,
				altText: cleanAlt,
				previewUrl: optimisticPreviewUrl
			};
		}

		const bitmap = await createImageBitmap(file);
		let optimisticPreviewUrl: string | undefined;
		try {
			const origW = bitmap.width;
			const origH = bitmap.height;
			const canvasType = ['image/jpeg', 'image/png', 'image/webp'].includes(inputType)
				? inputType
				: 'image/jpeg';
			const outType = canvasType === inputType ? inputType : canvasType;

			let data: Uint8Array;
			let width = origW;
			let height = origH;

			if (file.size <= MAX_BLOB_BYTES && outType === inputType) {
				data = new Uint8Array(await file.arrayBuffer());
			} else {
				const resized = await fitImageToSize(bitmap, canvasType, origW, origH, MAX_BLOB_BYTES);
				data = resized.data;
				width = resized.width;
				height = resized.height;
			}

			optimisticPreviewUrl = createTrackedObjectUrl(
				new Blob([data as BlobPart], { type: outType })
			);

			return {
				data,
				contentType: outType,
				width,
				height,
				altText: cleanAlt,
				previewUrl: optimisticPreviewUrl
			};
		} catch (err) {
			revokeTrackedObjectUrl(optimisticPreviewUrl);
			throw err;
		} finally {
			bitmap.close();
		}
	}

	function stageImageFile(file: File) {
		if (disabled) return;
		if (!file.type.startsWith('image/')) {
			uploadError = 'Please choose an image file.';
			return;
		}
		uploadError = null;
		clearPendingImage();
		const previewUrl = createTrackedObjectUrl(file);
		pendingImage = {
			file,
			previewUrl,
			altText: ''
		};
		isRecordingVoice = false;
		void tick().then(() => inputEl?.focus());
	}

	function handleFileChange(event: Event) {
		const input = event.currentTarget as HTMLInputElement;
		const file = input.files?.[0];
		input.value = '';
		if (disabled || !file) return;
		stageImageFile(file);
	}

	function handlePaste(event: ClipboardEvent) {
		if (disabled) return;
		const dt = event.clipboardData;
		if (!dt) return;

		let imageFile: File | null = null;
		for (const item of Array.from(dt.items ?? [])) {
			if (item.kind === 'file' && item.type.startsWith('image/')) {
				const candidate = item.getAsFile();
				if (candidate) {
					imageFile = candidate;
					break;
				}
			}
		}
		if (!imageFile) {
			imageFile =
				Array.from(dt.files ?? []).find((file) => file.type.startsWith('image/')) ?? null;
		}

		if (imageFile) {
			event.preventDefault();
			stageImageFile(imageFile);
		}
	}

	function hasImageTransfer(dt: DataTransfer | null): boolean {
		if (!dt) return false;
		for (const item of Array.from(dt.items ?? [])) {
			if (
				item.kind === 'file' &&
				(item.type.startsWith('image/') || ACCEPTED_IMAGE_TYPES.includes(item.type))
			) {
				return true;
			}
		}
		return false;
	}

	function handleDragEnter(event: DragEvent) {
		if (disabled) return;
		event.preventDefault();
		dragCounter += 1;
		if (hasImageTransfer(event.dataTransfer)) {
			isDragOver = true;
		}
	}

	function handleDragLeave(event: DragEvent) {
		if (disabled) return;
		event.preventDefault();
		dragCounter -= 1;
		if (dragCounter <= 0) {
			dragCounter = 0;
			isDragOver = false;
		}
	}

	function handleDragOver(event: DragEvent) {
		if (disabled) return;
		event.preventDefault();
		if (event.dataTransfer) {
			event.dataTransfer.dropEffect = 'copy';
		}
	}

	function handleDrop(event: DragEvent) {
		event.preventDefault();
		dragCounter = 0;
		isDragOver = false;
		if (disabled || !event.dataTransfer) return;

		const file = Array.from(event.dataTransfer.files).find(
			(candidate) =>
				candidate.type.startsWith('image/') || ACCEPTED_IMAGE_TYPES.includes(candidate.type)
		);
		if (!file) return;
		stageImageFile(file);
	}

	async function handleSubmit(event: SubmitEvent) {
		event.preventDefault();
		if (disabled || sending) return;

		const trimmed = text.trim();
		const staged = pendingImage;
		if (!trimmed && !staged) return;

		uploadError = null;
		clearIdleTimer();
		emitTyping(conversationId, false);
		sending = true;

		try {
			if (staged) {
				const prepared = await prepareImageUpload(staged.file, staged.altText);
				revokeTrackedObjectUrl(staged.previewUrl);
				pendingImage = null;
				text = '';
				drafts.clearDraft(conversationId);
				if (replyTo) {
					onCancelReply();
				}
				await tick();
				syncTextareaHeight();
				try {
					await messages.sendImage(conversationId, trimmed, prepared);
				} finally {
					// If sendImage replaced the optimistic bubble cleanly, reclaim its temporary preview URL
					const currentList = $messages.byConversation.get(conversationId) ?? [];
					const stillReferenced = currentList.some(
						(m) => m.image?.localUrl === prepared.previewUrl
					);
					if (!stillReferenced) {
						revokeTrackedObjectUrl(prepared.previewUrl);
					}
				}
			} else {
				let payload = trimmed;
				if (replyTo) {
					const replyPreview =
						extractMessagePreview(replyTo.content) ||
						(replyTo.image
							? 'Photo'
							: (replyTo.audio ?? replyTo.audioAttachment)
								? 'Voice message'
								: replyTo.embed?.type === 'post'
									? 'Shared post'
									: replyTo.embed?.type === 'link'
										? 'Shared link'
										: replyTo.embed?.type === 'gif'
											? 'GIF'
											: '');
					payload = JSON.stringify({
						text: trimmed,
						reply: {
							messageId: replyTo.id,
							senderDid: stripDidFragment(replyTo.senderDid) || replyTo.senderDid,
							preview: replyPreview.slice(0, 120)
						}
					});
					onCancelReply();
				}
				text = '';
				drafts.clearDraft(conversationId);
				await tick();
				syncTextareaHeight();
				await messages.send(conversationId, payload);
			}
		} catch (err) {
			console.error('[catmos] Failed to send message:', err);
			uploadError = err instanceof Error ? err.message : 'Could not send message.';
		} finally {
			sending = false;
			inputEl?.focus();
		}
	}

	function handleStartVoice() {
		if (disabled || sending) return;
		uploadError = null;
		clearPendingImage();
		isRecordingVoice = true;
	}

	async function handleVoiceRecorded(payload: RecordedVoicePayload) {
		isRecordingVoice = false;
		if (disabled) return;
		sending = true;
		uploadError = null;
		try {
			await messages.sendVoice(
				conversationId,
				payload.data,
				payload.durationMs,
				payload.waveform,
				payload.contentType
			);
			announce('Voice message sent');
		} catch (err) {
			const msg = err instanceof Error ? err.message : 'Could not send voice message.';
			uploadError = msg;
			showToast({ message: msg, tone: 'error' });
		} finally {
			sending = false;
		}
	}

	function handleVoiceError(message: string) {
		isRecordingVoice = false;
		uploadError = message;
		showToast({ message, tone: 'error' });
	}

	onDestroy(() => {
		clearIdleTimer();
		emitTyping(prevConvoId ?? conversationId, false);
		clearPendingImage();
		for (const url of Array.from(ownedObjectUrls)) {
			URL.revokeObjectURL(url);
		}
		ownedObjectUrls.clear();
	});
</script>

<div
	class="composer"
	class:drag-over={isDragOver}
	class:disabled
	ondragenter={handleDragEnter}
	ondragleave={handleDragLeave}
	ondragover={handleDragOver}
	ondrop={handleDrop}
	role="region"
	aria-label="Message composer"
>
	{#if isDragOver && !disabled}
		<div class="drop-zone-overlay" aria-hidden="true">
			<Icon name="paperclip" size={20} />
			<span>Drop image to attach</span>
		</div>
	{/if}

	{#if replyTo}
		<ReplyPreview message={replyTo} onCancel={onCancelReply} />
	{/if}

	{#if pendingImage}
		<div class="pending-attachment" role="region" aria-label="Staged image attachment">
			<img
				src={pendingImage.previewUrl}
				alt={pendingImage.altText || 'Pending image attachment'}
				class="pending-thumb"
			/>
			<div class="pending-meta">
				<label for="composer-alt-input" class="visually-hidden">Image alt text</label>
				<input
					id="composer-alt-input"
					type="text"
					class="pending-alt-input"
					bind:value={pendingImage.altText}
					placeholder="Add alt text (optional)"
					disabled={disabled || sending}
				/>
			</div>
			<button
				type="button"
				class="pending-remove-btn"
				onclick={clearPendingImage}
				aria-label="Remove image"
				title="Remove image"
				disabled={sending}
			>
				<Icon name="x" size={16} />
			</button>
		</div>
	{/if}

	{#if isRecordingVoice && !disabled}
		<VoiceRecorder
			autoStart={true}
			onRecorded={handleVoiceRecorded}
			onCancel={() => {
				isRecordingVoice = false;
			}}
			onError={handleVoiceError}
		/>
	{:else}
		<form bind:this={formEl} class="composer-form" onsubmit={handleSubmit}>
			<input
				bind:this={fileInputEl}
				type="file"
				accept="image/*"
				class="visually-hidden"
				tabindex="-1"
				aria-hidden="true"
				onchange={handleFileChange}
				disabled={disabled || sending}
			/>

			<button
				type="button"
				class="composer-btn icon-action"
				onclick={() => fileInputEl?.click()}
				aria-label="Attach image"
				title="Attach image"
				disabled={disabled || sending}
			>
				<Icon name="paperclip" size={18} />
			</button>

			<button
				type="button"
				class="composer-btn icon-action"
				onclick={handleStartVoice}
				aria-label="Record voice message"
				title="Record voice message"
				disabled={disabled || sending || Boolean(pendingImage)}
			>
				<Icon name="mic" size={18} />
			</button>

			<label for="composer-input" class="visually-hidden">Message</label>
			<textarea
				id="composer-input"
				bind:this={inputEl}
				bind:value={text}
				oninput={handleInput}
				onkeydown={handleKeydown}
				onpaste={handlePaste}
				placeholder={disabled
					? (disabledReason ?? 'Sending is disabled in this conversation.')
					: pendingImage
						? 'Add a caption (optional)...'
						: 'Message...'}
				rows="1"
				disabled={disabled}
				aria-disabled={disabled}
			></textarea>

			<button
				type="submit"
				class="composer-btn send-btn"
				disabled={!canSend}
				aria-label="Send message"
				title="Send message"
			>
				<Icon name="send" size={17} />
			</button>
		</form>
	{/if}

	{#if uploadError}
		<p class="composer-error" role="alert">{uploadError}</p>
	{/if}
</div>

<style>
	.composer {
		position: relative;
		padding-block-start: var(--space-2);
		padding-block-end: var(--space-4);
		padding-inline: var(--space-5);
		flex-shrink: 0;
		background: var(--bg-chat);
	}

	.composer-form {
		display: flex;
		align-items: flex-end;
		gap: var(--space-1);
		background: var(--bg-input);
		border: 1px solid var(--border-input);
		border-radius: var(--radius-lg);
		padding-block: var(--space-1);
		padding-inline: var(--space-2);
		transition: border-color var(--dur-fast) var(--ease-out);
	}

	.composer-form:focus-within {
		border-color: var(--focus-ring);
	}

	.composer.disabled .composer-form {
		opacity: 0.72;
		border-color: var(--border);
	}

	textarea {
		flex: 1;
		min-inline-size: 0;
		resize: none;
		field-sizing: content;
		min-block-size: 1.5rem;
		max-block-size: 10rem;
		overflow-y: auto;
		line-height: 1.48;
		font-size: var(--text-body);
		color: var(--text-primary);
		padding-block: 0.375rem;
		padding-inline: var(--space-2);
	}

	textarea::placeholder {
		color: var(--text-muted);
	}

	textarea:focus {
		outline: none;
	}

	textarea:disabled {
		cursor: not-allowed;
	}

	.composer-btn {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		min-inline-size: max(2.25rem, var(--touch-min));
		min-block-size: max(2.25rem, var(--touch-min));
		border-radius: var(--radius-full);
		flex-shrink: 0;
		transition:
			background-color var(--dur-fast) var(--ease-out),
			color var(--dur-fast) var(--ease-out),
			opacity var(--dur-fast) var(--ease-out);
	}

	.icon-action {
		color: var(--text-secondary);
	}

	.icon-action:hover:not(:disabled) {
		background: var(--bg-hover);
		color: var(--text-primary);
	}

	.icon-action:disabled {
		opacity: 0.45;
		cursor: not-allowed;
	}

	.send-btn {
		background: var(--accent-fill);
		color: var(--text-on-accent);
	}

	.send-btn:hover:not(:disabled) {
		background: var(--accent-fill-hover);
	}

	.send-btn:disabled {
		background: var(--bg-surface);
		color: var(--text-muted);
		cursor: not-allowed;
	}

	/* Pre-send staged attachment preview strip */
	.pending-attachment {
		display: flex;
		align-items: center;
		gap: var(--space-3);
		padding: var(--space-2);
		margin-block-end: var(--space-2);
		background: var(--bg-surface);
		border: 1px solid var(--border);
		border-radius: var(--radius-md);
	}

	.pending-thumb {
		inline-size: 3.5rem;
		block-size: 3.5rem;
		border-radius: var(--radius-xs);
		object-fit: cover;
		flex-shrink: 0;
		background: var(--bg-elevated);
	}

	.pending-meta {
		flex: 1;
		min-inline-size: 0;
	}

	.pending-alt-input {
		inline-size: 100%;
		min-block-size: max(2.25rem, var(--touch-min));
		padding-block: var(--space-1);
		padding-inline: var(--space-3);
		border-radius: var(--radius-sm);
		background: var(--bg-input);
		border: 1px solid var(--border-input);
		color: var(--text-primary);
		font-size: var(--text-sm);
		transition: border-color var(--dur-fast) var(--ease-out);
	}

	.pending-alt-input::placeholder {
		color: var(--text-muted);
	}

	.pending-alt-input:focus {
		border-color: var(--focus-ring);
	}

	.pending-remove-btn {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		min-inline-size: max(2rem, var(--touch-min));
		min-block-size: max(2rem, var(--touch-min));
		border-radius: var(--radius-sm);
		color: var(--text-secondary);
		flex-shrink: 0;
		transition:
			background-color var(--dur-fast) var(--ease-out),
			color var(--dur-fast) var(--ease-out);
	}

	.pending-remove-btn:hover:not(:disabled) {
		background: var(--bg-hover);
		color: var(--text-primary);
	}

	.composer-error {
		padding-block-start: var(--space-2);
		padding-inline: var(--space-2);
		color: var(--danger-text);
		font-size: var(--text-sm);
	}

	/* Drag-and-drop overlay */
	.drop-zone-overlay {
		position: absolute;
		inset-block: var(--space-1);
		inset-inline: var(--space-4);
		display: flex;
		align-items: center;
		justify-content: center;
		gap: var(--space-2);
		background: color-mix(in oklab, var(--accent) 14%, var(--bg-elevated));
		border: 2px dashed var(--accent-fill);
		border-radius: var(--radius-lg);
		z-index: 10;
		color: var(--text-link);
		font-size: var(--text-body);
		font-weight: 600;
		pointer-events: none;
	}

	@media (max-width: 767px) {
		.composer {
			padding-inline: var(--space-3);
			padding-block-end: var(--space-3);
		}

		.drop-zone-overlay {
			inset-inline: var(--space-2);
		}
	}
</style>

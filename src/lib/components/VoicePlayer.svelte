<script lang="ts">
	import { onDestroy } from 'svelte';
	import type { AudioAttachment } from '#lib/wasm.ts';
	import { fetchAndDecryptBlob } from '#lib/wasm.ts';
	import { decodeBase64Bytes } from '#lib/message-embed.ts';
	import { formatDuration } from '#lib/utils/time.ts';
	import Icon from './Icon.svelte';

	let {
		audio,
		isOwnMessage = false
	}: {
		audio: AudioAttachment;
		isOwnMessage?: boolean;
	} = $props();

	let isPlaying = $state(false);
	let isLoading = $state(false);
	let progress = $state(0);
	let currentTimeMs = $state(0);
	let measuredDurationMs = $state<number | null>(null);
	let playbackError = $state<string | null>(null);

	let audioElement: HTMLAudioElement | null = null;
	let createdObjectUrl: string | null = null;

	const DEFAULT_WAVEFORM = [
		0.24, 0.42, 0.65, 0.52, 0.85, 0.72, 0.4, 0.58, 0.9, 0.62, 0.48, 0.76, 0.54, 0.36, 0.68, 0.82,
		0.46, 0.34, 0.6, 0.74, 0.5, 0.38, 0.28, 0.22
	];

	let bars = $derived(audio.waveform && audio.waveform.length > 0 ? audio.waveform : DEFAULT_WAVEFORM);
	let totalDurationMs = $derived(measuredDurationMs ?? audio.durationMs);

	let directUrl = $derived.by(() => {
		const record = audio as unknown as Record<string, unknown>;
		if (typeof record.localUrl === 'string' && record.localUrl.length > 0) {
			return record.localUrl;
		}
		if (audio.blobId && (audio.blobId.startsWith('data:') || audio.blobId.startsWith('blob:'))) {
			return audio.blobId;
		}
		return null;
	});

	let canPlay = $derived(Boolean(directUrl || audio.blobId));

	function teardownAudio() {
		if (audioElement) {
			audioElement.pause();
			audioElement.ontimeupdate = null;
			audioElement.onloadedmetadata = null;
			audioElement.onended = null;
			audioElement.onerror = null;
			audioElement.src = '';
			audioElement = null;
		}
		if (createdObjectUrl) {
			URL.revokeObjectURL(createdObjectUrl);
			createdObjectUrl = null;
		}
		isPlaying = false;
		isLoading = false;
	}

	$effect(() => {
		void audio.blobId;
		void directUrl;
		teardownAudio();
		progress = 0;
		currentTimeMs = 0;
		measuredDurationMs = null;
		playbackError = null;

		return () => {
			teardownAudio();
		};
	});

	function resolveBytes(raw: Uint8Array | number[] | undefined, b64?: string): Uint8Array {
		if (raw instanceof Uint8Array && raw.byteLength > 0) return raw;
		if (Array.isArray(raw) && raw.length > 0) return new Uint8Array(raw);
		return b64 ? decodeBase64Bytes(b64) : new Uint8Array();
	}

	async function ensureAudioElement(): Promise<HTMLAudioElement> {
		if (audioElement) return audioElement;

		let srcUrl = directUrl;
		if (!srcUrl) {
			const keyBytes = resolveBytes(audio.key, audio.keyB64);
			const ivBytes = resolveBytes(audio.iv, audio.ivB64);
			const decrypted = await fetchAndDecryptBlob(
				audio.blobId,
				keyBytes,
				ivBytes,
				audio.sha256
			);
			const mime = audio.contentType?.trim() || 'audio/webm;codecs=opus';
			const blob = new Blob([decrypted as BlobPart], { type: mime });
			createdObjectUrl = URL.createObjectURL(blob);
			srcUrl = createdObjectUrl;
		}

		const el = new Audio(srcUrl);
		el.preload = 'metadata';

		el.onloadedmetadata = () => {
			if (Number.isFinite(el.duration) && el.duration > 0) {
				measuredDurationMs = Math.round(el.duration * 1000);
				if (progress > 0 && progress < 1) {
					el.currentTime = el.duration * progress;
				}
			}
		};

		el.ontimeupdate = () => {
			if (Number.isFinite(el.duration) && el.duration > 0) {
				progress = Math.min(1, Math.max(0, el.currentTime / el.duration));
				currentTimeMs = Math.round(el.currentTime * 1000);
			}
		};

		el.onended = () => {
			isPlaying = false;
			progress = 0;
			currentTimeMs = 0;
		};

		el.onerror = () => {
			isPlaying = false;
			playbackError = 'Could not play voice message.';
		};

		audioElement = el;
		return el;
	}

	async function togglePlayback() {
		if (!canPlay) return;
		playbackError = null;

		if (isPlaying && audioElement) {
			audioElement.pause();
			isPlaying = false;
			return;
		}

		isLoading = true;
		try {
			const el = await ensureAudioElement();
			if (progress > 0 && progress < 1 && Number.isFinite(el.duration) && el.duration > 0) {
				el.currentTime = el.duration * progress;
			}
			await el.play();
			isPlaying = true;
		} catch (err) {
			console.error('[catmos] Voice playback failed:', err);
			playbackError = 'Could not play voice message.';
			isPlaying = false;
		} finally {
			isLoading = false;
		}
	}

	function handleSeek(event: Event) {
		const input = event.currentTarget as HTMLInputElement;
		const ratio = Math.min(1, Math.max(0, Number(input.value) / 1000));
		progress = ratio;
		currentTimeMs = Math.round(totalDurationMs * ratio);
		if (audioElement && Number.isFinite(audioElement.duration) && audioElement.duration > 0) {
			audioElement.currentTime = audioElement.duration * ratio;
		}
	}

	onDestroy(() => {
		teardownAudio();
	});
</script>

<div class="voice-wrapper" class:own={isOwnMessage}>
	<div class="voice-player">
		<button
			type="button"
			class="play-btn"
			onclick={togglePlayback}
			disabled={isLoading || !canPlay}
			aria-label={isPlaying ? 'Pause voice message' : 'Play voice message'}
		>
			{#if isLoading}
				<progress class="catmos-progress voice-spinner" aria-label="Loading voice message"></progress>
			{:else if isPlaying}
				<Icon name="pause" size={16} />
			{:else}
				<Icon name="play" size={16} />
			{/if}
		</button>

		<div class="scrubber">
			<div class="waveform" aria-hidden="true">
				{#each bars as sample, i (i)}
					{@const barProgress = i / Math.max(bars.length - 1, 1)}
					{@const clamped = Math.min(1, Math.max(0.14, sample))}
					<span
						class="bar"
						class:active={barProgress <= progress}
						style={`height: ${Math.round(clamped * 100)}%;`}
					></span>
				{/each}
			</div>
			<input
				type="range"
				class="seek-input"
				min="0"
				max="1000"
				step="1"
				value={Math.round(progress * 1000)}
				oninput={handleSeek}
				disabled={!canPlay}
				aria-label="Seek voice message"
				aria-valuetext={`${formatDuration(currentTimeMs)} of ${formatDuration(totalDurationMs)}`}
			/>
		</div>

		<span class="duration tabular-nums">
			{formatDuration(isPlaying || currentTimeMs > 0 ? currentTimeMs : totalDurationMs)}
		</span>
	</div>

	{#if playbackError}
		<p class="voice-error" role="alert">{playbackError}</p>
	{/if}

	{#if audio.transcript}
		<details class="voice-transcript">
			<summary class="transcript-summary">
				<Icon name="chevron-right" size={14} class="transcript-chevron" />
				<span>Transcript</span>
			</summary>
			<p class="transcript-body">{audio.transcript}</p>
		</details>
	{/if}
</div>

<style>
	.voice-wrapper {
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
		min-inline-size: min(15rem, 100%);
	}

	.voice-player {
		display: flex;
		align-items: center;
		gap: var(--space-3);
		padding-block: var(--space-1);
	}

	.play-btn {
		min-inline-size: max(2.25rem, var(--touch-min));
		min-block-size: max(2.25rem, var(--touch-min));
		border-radius: var(--radius-full);
		display: inline-flex;
		align-items: center;
		justify-content: center;
		background: var(--accent-fill);
		color: var(--text-on-accent);
		flex-shrink: 0;
		transition:
			background-color var(--dur-fast) var(--ease-out),
			opacity var(--dur-fast) var(--ease-out);
	}

	.play-btn:hover:not(:disabled) {
		background: var(--accent-fill-hover);
	}

	.play-btn:disabled {
		opacity: 0.6;
		cursor: not-allowed;
	}

	.own .play-btn {
		background: rgba(255, 255, 255, 0.24);
		color: var(--text-on-bubble-own);
	}

	.own .play-btn:hover:not(:disabled) {
		background: rgba(255, 255, 255, 0.34);
	}

	.voice-spinner {
		inline-size: 1rem;
		block-size: 1rem;
		border-width: 2px;
		border-color: rgba(255, 255, 255, 0.35);
		border-top-color: var(--text-on-accent);
	}

	.scrubber {
		position: relative;
		flex: 1;
		min-inline-size: 6rem;
		block-size: 2rem;
		display: flex;
		align-items: center;
	}

	.waveform {
		display: flex;
		align-items: center;
		gap: 2px;
		inline-size: 100%;
		block-size: 1.625rem;
		pointer-events: none;
	}

	.bar {
		flex: 1;
		min-inline-size: 2px;
		border-radius: var(--radius-full);
		background: var(--border-strong);
		transition: background-color var(--dur-fast) var(--ease-out);
	}

	.bar.active {
		background: var(--accent-fill);
	}

	.own .bar {
		background: rgba(255, 255, 255, 0.42);
	}

	.own .bar.active {
		background: var(--text-on-bubble-own);
	}

	.seek-input {
		position: absolute;
		inset: 0;
		inline-size: 100%;
		block-size: 100%;
		opacity: 0;
		cursor: pointer;
		margin: 0;
	}

	.seek-input:disabled {
		cursor: not-allowed;
	}

	.scrubber:has(.seek-input:focus-visible) {
		outline: 2px solid var(--focus-ring);
		outline-offset: 2px;
		border-radius: var(--radius-xs);
	}

	.own .scrubber:has(.seek-input:focus-visible) {
		outline-color: var(--text-on-bubble-own);
	}

	.duration {
		font-size: var(--text-sm);
		font-weight: 500;
		color: var(--text-secondary);
		flex-shrink: 0;
	}

	.own .duration {
		color: var(--text-on-bubble-own-muted);
	}

	.voice-error {
		font-size: var(--text-sm);
		color: var(--danger-text);
	}

	.own .voice-error {
		color: var(--text-on-bubble-own);
	}

	.voice-transcript {
		margin-block-start: var(--space-1);
		padding-block-start: var(--space-1);
		border-block-start: 1px solid var(--border);
		font-size: var(--text-sm);
	}

	.own .voice-transcript {
		border-block-start-color: rgba(255, 255, 255, 0.24);
	}

	.transcript-summary {
		display: inline-flex;
		align-items: center;
		gap: var(--space-1);
		min-block-size: max(1.75rem, var(--touch-min));
		cursor: pointer;
		font-weight: 600;
		color: var(--text-secondary);
		padding-block: 2px;
		list-style: none;
	}

	.transcript-summary::-webkit-details-marker {
		display: none;
	}

	.transcript-summary :global(.transcript-chevron) {
		flex-shrink: 0;
	}

	@media (prefers-reduced-motion: no-preference) {
		.transcript-summary :global(.transcript-chevron) {
			transition: transform var(--dur-fast) var(--ease-out);
		}
	}

	.voice-transcript[open] .transcript-summary :global(.transcript-chevron) {
		transform: rotate(90deg);
	}

	.own .transcript-summary {
		color: var(--text-on-bubble-own-muted);
	}

	@media (pointer: coarse) {
		.transcript-summary {
			min-block-size: var(--touch-min);
		}
	}

	.transcript-body {
		margin-block-start: var(--space-1);
		line-height: 1.45;
		color: var(--text-primary);
		user-select: text;
	}

	.own .transcript-body {
		color: var(--text-on-bubble-own);
	}
</style>

<script lang="ts">
	import { onDestroy } from 'svelte';
	import type { AudioAttachment } from '#lib/tauri.ts';

	let {
		audio,
		isOwnMessage = false
	}: {
		audio: AudioAttachment;
		isOwnMessage?: boolean;
	} = $props();

	let isPlaying = $state(false);
	let isLoading = $state(false);
	let playbackError = $state<string | null>(null);
	let progress = $state(0);
	let showTranscript = $state(false);

	let audioElement: HTMLAudioElement | null = null;
	let objectUrl: string | null = null;

	function decodeBase64Fallback(b64?: string): Uint8Array {
		if (!b64) return new Uint8Array();
		const normalized = b64.trim().replace(/-/g, '+').replace(/_/g, '/');
		const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
		const bin = atob(padded);
		const out = new Uint8Array(bin.length);
		for (let i = 0; i < bin.length; i += 1) {
			out[i] = bin.charCodeAt(i);
		}
		return out;
	}

	function resolveBytes(raw: Uint8Array | number[] | undefined, b64?: string): Uint8Array {
		if (raw instanceof Uint8Array && raw.byteLength > 0) return raw;
		if (Array.isArray(raw) && raw.length > 0) return new Uint8Array(raw);
		return decodeBase64Fallback(b64);
	}

	function formatDuration(ms: number): string {
		const s = Math.floor(ms / 1000);
		const m = Math.floor(s / 60);
		const sec = s % 60;
		return `${m}:${sec.toString().padStart(2, '0')}`;
	}

	async function togglePlayback() {
		playbackError = null;
		if (isPlaying && audioElement) {
			audioElement.pause();
			isPlaying = false;
			return;
		}

		if (audioElement) {
			await audioElement.play();
			isPlaying = true;
			return;
		}

		if (!audio.blobId) {
			return;
		}

		isLoading = true;
		try {
			const { fetchAndDecryptBlob } = await import('#lib/wasm.ts');
			const keyBytes = resolveBytes(audio.key, audio.keyB64);
			const ivBytes = resolveBytes(audio.iv, audio.ivB64);
			const decryptedData = await fetchAndDecryptBlob(
				audio.blobId,
				keyBytes,
				ivBytes,
				audio.sha256
			);

			const mimeType = audio.contentType?.trim() || 'audio/webm;codecs=opus';
			const blob = new Blob([decryptedData as BlobPart], { type: mimeType });
			objectUrl = URL.createObjectURL(blob);

			audioElement = new Audio(objectUrl);
			audioElement.ontimeupdate = () => {
				if (audioElement && audioElement.duration > 0) {
					progress = audioElement.currentTime / audioElement.duration;
				}
			};
			audioElement.onended = () => {
				isPlaying = false;
				progress = 0;
			};

			await audioElement.play();
			isPlaying = true;
		} catch (err) {
			console.error('Voice playback failed:', err);
			playbackError = err instanceof Error ? err.message : 'Unable to play voice message';
		} finally {
			isLoading = false;
		}
	}

	onDestroy(() => {
		if (audioElement) {
			audioElement.pause();
			audioElement = null;
		}
		if (objectUrl) {
			URL.revokeObjectURL(objectUrl);
			objectUrl = null;
		}
	});

	let bars = $derived(
		audio.waveform && audio.waveform.length > 0 ? audio.waveform : [0.2, 0.5, 0.8, 0.4, 0.6, 0.3]
	);
</script>

<div class="voice-player" class:own={isOwnMessage}>
	<button
		type="button"
		class="play-btn"
		aria-label={isPlaying ? 'Pause voice message' : 'Play voice message'}
		onclick={togglePlayback}
		disabled={isLoading || !audio.blobId}
	>
		{#if isLoading}
			<span class="spinner"></span>
		{:else if isPlaying}
			⏸
		{:else}
			▶
		{/if}
	</button>

	<div class="waveform">
		{#each bars as sample, i}
			{@const barProgress = i / Math.max(bars.length - 1, 1)}
			<div
				class="bar"
				class:active={barProgress <= progress}
				style="height: {Math.max(8, sample * 100)}%"
			></div>
		{/each}
	</div>

	<span class="duration">{formatDuration(audio.durationMs)}</span>
</div>

{#if playbackError}
	<p class="playback-error" role="alert">{playbackError}</p>
{/if}

{#if audio.transcript}
	<button
		type="button"
		class="transcript-toggle"
		onclick={() => {
			showTranscript = !showTranscript;
		}}
	>
		{#if showTranscript}
			<span class="transcript-text">{audio.transcript}</span>
		{:else}
			<span class="transcript-hint">Show transcript</span>
		{/if}
	</button>
{/if}

<style>
	.voice-player {
		display: flex;
		align-items: center;
		gap: 8px;
		padding: 6px 4px;
		min-width: 200px;
	}

	.play-btn {
		width: 32px;
		height: 32px;
		border-radius: 50%;
		border: none;
		cursor: pointer;
		display: flex;
		align-items: center;
		justify-content: center;
		font-size: 1rem;
		background: var(--accent, #007aff);
		color: white;
		flex-shrink: 0;
	}

	.play-btn:disabled {
		opacity: 0.5;
		cursor: default;
	}

	.own .play-btn {
		background: rgba(255, 255, 255, 0.3);
	}

	.waveform {
		display: flex;
		align-items: center;
		gap: 2px;
		flex: 1;
		height: 28px;
	}

	.bar {
		flex: 1;
		min-width: 2px;
		border-radius: 1px;
		background: rgba(128, 128, 128, 0.3);
		transition: background 0.1s;
	}

	.bar.active {
		background: var(--accent, #007aff);
	}

	.own .bar.active {
		background: white;
	}

	.own .bar {
		background: rgba(255, 255, 255, 0.3);
	}

	.duration {
		font-variant-numeric: tabular-nums;
		font-size: 0.8rem;
		color: var(--text-secondary, #888);
		flex-shrink: 0;
	}

	.own .duration {
		color: rgba(255, 255, 255, 0.75);
	}

	.spinner {
		width: 16px;
		height: 16px;
		border: 2px solid rgba(255, 255, 255, 0.3);
		border-top-color: white;
		border-radius: 50%;
		animation: spin 0.6s linear infinite;
	}

	@keyframes spin {
		to {
			transform: rotate(360deg);
		}
	}

	.playback-error {
		margin: 4px 0 0;
		font-size: 0.75rem;
		color: var(--danger, #ff3b30);
	}

	.transcript-toggle {
		border: none;
		background: none;
		cursor: pointer;
		padding: 4px 4px 0;
		text-align: left;
		width: 100%;
	}

	.transcript-text {
		font-size: 0.8rem;
		color: var(--text-secondary, #888);
	}

	.transcript-hint {
		font-size: 0.75rem;
		color: var(--text-secondary, #888);
		opacity: 0.75;
	}
</style>

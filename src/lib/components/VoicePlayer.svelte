<script lang="ts">
	import type { AudioAttachment } from '#lib/tauri.ts';

	export let audio: AudioAttachment;
	export let isOwnMessage = false;

	let isPlaying = false;
	let isLoading = false;
	let progress = 0;
	let audioElement: HTMLAudioElement | null = null;
	let showTranscript = false;

	function formatDuration(ms: number): string {
		const s = Math.floor(ms / 1000);
		const m = Math.floor(s / 60);
		const sec = s % 60;
		return `${m}:${sec.toString().padStart(2, '0')}`;
	}

	async function togglePlayback() {
		if (isPlaying && audioElement) {
			audioElement.pause();
			isPlaying = false;
			return;
		}

		if (audioElement) {
			audioElement.play();
			isPlaying = true;
			return;
		}

		isLoading = true;
		try {
			const { fetchAndDecryptBlob } = await import('#lib/wasm.ts');
			const decryptedData = await fetchAndDecryptBlob(
				audio.blobId,
				audio.key,
				audio.iv,
				audio.sha256
			);

			// Browser/webview can play OGG Opus natively
			const blob = new Blob([decryptedData as BlobPart], { type: 'audio/ogg; codecs=opus' });
			const url = URL.createObjectURL(blob);

			audioElement = new Audio(url);
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
		} finally {
			isLoading = false;
		}
	}
</script>

<div class="voice-player" class:own={isOwnMessage}>
	<button class="play-btn" on:click={togglePlayback} disabled={isLoading}>
		{#if isLoading}
			<span class="spinner"></span>
		{:else if isPlaying}
			⏸
		{:else}
			▶
		{/if}
	</button>

	<div class="waveform">
		{#each audio.waveform as sample, i}
			{@const barProgress = i / Math.max(audio.waveform.length - 1, 1)}
			<div
				class="bar"
				class:active={barProgress <= progress}
				style="height: {Math.max(3, sample * 100)}%"
			></div>
		{/each}
	</div>

	<span class="duration">{formatDuration(audio.durationMs)}</span>
</div>

{#if audio.transcript}
	<button class="transcript-toggle" on:click={() => (showTranscript = !showTranscript)}>
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
		padding: 8px 12px;
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
		background: var(--accent-color, #007aff);
		color: white;
		flex-shrink: 0;
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
		background: var(--accent-color, #007aff);
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
		color: rgba(255, 255, 255, 0.7);
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

	.transcript-toggle {
		border: none;
		background: none;
		cursor: pointer;
		padding: 4px 12px 0;
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
		opacity: 0.7;
	}
</style>

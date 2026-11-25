<script lang="ts">
	import { onDestroy, onMount } from 'svelte';
	import { formatDuration } from '#lib/utils/time.ts';
	import Icon from './Icon.svelte';

	export interface RecordedVoicePayload {
		data: Uint8Array;
		contentType: string;
		durationMs: number;
		waveform: number[];
	}

	let {
		autoStart = true,
		onRecorded,
		onCancel,
		onError
	}: {
		autoStart?: boolean;
		onRecorded?: (payload: RecordedVoicePayload) => void | Promise<void>;
		onCancel?: () => void;
		onError?: (message: string) => void;
	} = $props();

	let isRecording = $state(false);
	let durationMs = $state(0);
	let errorMessage = $state<string | null>(null);
	let liveBars = $state<number[]>([0.2, 0.2, 0.2, 0.2, 0.2, 0.2, 0.2, 0.2]);

	let mediaRecorder: MediaRecorder | null = null;
	let activeStream: MediaStream | null = null;
	let audioContext: AudioContext | null = null;
	let analyser: AnalyserNode | null = null;
	let chunks: Blob[] = [];
	let sampledLevels: number[] = [];
	let startTime = 0;
	let timer: ReturnType<typeof setInterval> | null = null;
	let selectedMimeType = '';
	let cancelled = false;

	function pickSupportedMimeType(): string | undefined {
		if (typeof MediaRecorder === 'undefined') return undefined;
		const candidates = [
			'audio/webm;codecs=opus',
			'audio/ogg;codecs=opus',
			'audio/mp4',
			'audio/webm'
		];
		for (const candidate of candidates) {
			if (
				typeof MediaRecorder.isTypeSupported === 'function' &&
				MediaRecorder.isTypeSupported(candidate)
			) {
				return candidate;
			}
		}
		return undefined;
	}

	function releaseMediaResources() {
		isRecording = false;
		if (timer !== null) {
			clearInterval(timer);
			timer = null;
		}
		if (activeStream) {
			for (const track of activeStream.getTracks()) {
				track.stop();
			}
			activeStream = null;
		}
		analyser = null;
		if (audioContext) {
			audioContext.close().catch(() => {});
			audioContext = null;
		}
	}

	function sampleCurrentLevel(): number {
		if (!analyser) return 0.35;
		const data = new Uint8Array(analyser.fftSize);
		analyser.getByteTimeDomainData(data);
		let sumSq = 0;
		for (let i = 0; i < data.length; i += 1) {
			const centered = (data[i] - 128) / 128;
			sumSq += centered * centered;
		}
		const rms = Math.sqrt(sumSq / data.length);
		return Math.min(1, Math.max(0.14, rms * 3.2));
	}

	function buildWaveform(samples: number[], targetLength = 28): number[] {
		if (samples.length === 0) {
			return Array.from({ length: targetLength }, (_, i) =>
				Number((0.25 + ((i * 7) % 10) * 0.055).toFixed(2))
			);
		}
		const result: number[] = [];
		for (let i = 0; i < targetLength; i += 1) {
			const startIdx = Math.floor((i * samples.length) / targetLength);
			const endIdx = Math.max(startIdx + 1, Math.floor(((i + 1) * samples.length) / targetLength));
			let sum = 0;
			let count = 0;
			for (let j = startIdx; j < endIdx && j < samples.length; j += 1) {
				sum += samples[j];
				count += 1;
			}
			const avg = count > 0 ? sum / count : 0.3;
			result.push(Number(Math.min(1, Math.max(0.14, avg)).toFixed(2)));
		}
		return result;
	}

	function describeMediaError(err: unknown): string {
		if (err instanceof DOMException) {
			if (err.name === 'NotAllowedError' || err.name === 'PermissionDeniedError') {
				return 'Microphone access was denied. Allow microphone permissions to record voice messages.';
			}
			if (err.name === 'NotFoundError' || err.name === 'DevicesNotFoundError') {
				return 'No microphone was found on this device.';
			}
			if (err.name === 'NotReadableError') {
				return 'Your microphone is currently in use by another application.';
			}
		}
		return 'Could not start voice recording.';
	}

	export async function startRecording(): Promise<void> {
		if (isRecording) return;
		errorMessage = null;
		cancelled = false;

		if (
			typeof navigator === 'undefined' ||
			!navigator.mediaDevices?.getUserMedia ||
			typeof MediaRecorder === 'undefined'
		) {
			const msg = 'Voice recording is not supported in this browser.';
			errorMessage = msg;
			onError?.(msg);
			return;
		}

		try {
			const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
			if (cancelled) {
				for (const track of stream.getTracks()) {
					track.stop();
				}
				return;
			}
			activeStream = stream;

			try {
				const AudioCtx =
					globalThis.AudioContext ??
					(globalThis as unknown as { webkitAudioContext?: typeof AudioContext })
						.webkitAudioContext;
				if (AudioCtx) {
					audioContext = new AudioCtx();
					const source = audioContext.createMediaStreamSource(stream);
					analyser = audioContext.createAnalyser();
					analyser.fftSize = 256;
					source.connect(analyser);
				}
			} catch {
				// Optional level meter; continue cleanly if AudioContext is unavailable
			}

			const mimeType = pickSupportedMimeType();
			selectedMimeType = mimeType ?? 'audio/webm;codecs=opus';
			mediaRecorder = mimeType ? new MediaRecorder(stream, { mimeType }) : new MediaRecorder(stream);
			if (mediaRecorder.mimeType) {
				selectedMimeType = mediaRecorder.mimeType;
			}
			chunks = [];
			sampledLevels = [];

			mediaRecorder.ondataavailable = (event: BlobEvent) => {
				if (event.data.size > 0) {
					chunks.push(event.data);
				}
			};

			mediaRecorder.onstop = async () => {
				const finalDuration = Math.max(100, durationMs, Date.now() - startTime);
				const resolvedType = selectedMimeType || mediaRecorder?.mimeType || 'audio/webm;codecs=opus';
				const blob = new Blob(chunks, { type: resolvedType });
				const waveform = buildWaveform(sampledLevels);
				mediaRecorder = null;
				releaseMediaResources();
				if (cancelled) return;
				const data = new Uint8Array(await blob.arrayBuffer());
				if (!cancelled) {
					await onRecorded?.({
						data,
						contentType: resolvedType,
						durationMs: finalDuration,
						waveform
					});
				}
			};

			mediaRecorder.start();
			startTime = Date.now();
			durationMs = 0;
			isRecording = true;

			timer = setInterval(() => {
				durationMs = Date.now() - startTime;
				const level = sampleCurrentLevel();
				sampledLevels.push(level);
				liveBars = [...liveBars.slice(1), level];
			}, 100);
		} catch (err) {
			releaseMediaResources();
			const msg = describeMediaError(err);
			errorMessage = msg;
			onError?.(msg);
		}
	}

	export function stopRecording(): void {
		if (mediaRecorder && mediaRecorder.state === 'recording') {
			mediaRecorder.stop();
		} else {
			releaseMediaResources();
		}
	}

	export function cancelRecording(silent = false): void {
		cancelled = true;
		if (mediaRecorder) {
			mediaRecorder.ondataavailable = null;
			mediaRecorder.onstop = null;
			if (mediaRecorder.state === 'recording' || mediaRecorder.state === 'paused') {
				try {
					mediaRecorder.stop();
				} catch {
					// Recorder may already be inactive
				}
			}
			mediaRecorder = null;
		}
		chunks = [];
		sampledLevels = [];
		releaseMediaResources();
		if (!silent) {
			onCancel?.();
		}
	}

	onMount(() => {
		if (autoStart) {
			void startRecording();
		}
	});

	onDestroy(() => {
		cancelRecording(true);
	});
</script>

<div class="voice-recorder" role="region" aria-label="Voice message recorder">
	{#if errorMessage}
		<p class="recorder-error" role="alert">{errorMessage}</p>
		<button
			type="button"
			class="recorder-btn cancel-btn"
			onclick={() => cancelRecording(false)}
			aria-label="Close voice recorder"
		>
			<Icon name="x" size={16} />
		</button>
	{:else}
		<button
			type="button"
			class="recorder-btn cancel-btn"
			onclick={() => cancelRecording(false)}
			aria-label="Cancel recording"
			title="Cancel recording"
		>
			<Icon name="x" size={16} />
		</button>

		<div class="recording-status" role="status" aria-live="off">
			<span class="recording-dot" aria-hidden="true"></span>
			<span class="recording-label">Recording</span>
			<span class="duration tabular-nums">{formatDuration(durationMs)}</span>
			<div class="live-meter" aria-hidden="true">
				{#each liveBars as level, i (i)}
					<span class="meter-bar" style={`height: ${Math.round(level * 100)}%;`}></span>
				{/each}
			</div>
		</div>

		<button
			type="button"
			class="recorder-btn send-btn"
			onclick={stopRecording}
			disabled={!isRecording || durationMs < 250}
			aria-label="Send voice message"
			title="Send voice message"
		>
			<Icon name="send" size={16} />
		</button>
	{/if}
</div>

<style>
	.voice-recorder {
		display: flex;
		align-items: center;
		gap: var(--space-3);
		padding-block: var(--space-2);
		padding-inline: var(--space-3);
		background: var(--danger-bg);
		border: 1px solid var(--danger);
		border-radius: var(--radius-lg);
		min-block-size: 3rem;
	}

	.recording-status {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		flex: 1;
		min-inline-size: 0;
	}

	.recording-dot {
		inline-size: 0.625rem;
		block-size: 0.625rem;
		border-radius: var(--radius-full);
		background: var(--danger);
		flex-shrink: 0;
	}

	@media (prefers-reduced-motion: no-preference) {
		.recording-dot {
			animation: rec-pulse 0.9s ease-in-out infinite alternate;
		}
	}

	@keyframes rec-pulse {
		from {
			transform: scale(1);
			opacity: 1;
		}
		to {
			transform: scale(1.25);
			opacity: 0.65;
		}
	}

	.recording-label {
		font-size: var(--text-sm);
		font-weight: 600;
		color: var(--danger-text);
	}

	.duration {
		font-size: var(--text-body);
		font-weight: 600;
		color: var(--text-primary);
		flex-shrink: 0;
	}

	.live-meter {
		display: flex;
		align-items: center;
		gap: 3px;
		block-size: 1.25rem;
		margin-inline-start: auto;
	}

	.meter-bar {
		inline-size: 3px;
		min-block-size: 4px;
		border-radius: var(--radius-full);
		background: var(--danger-text);
		transition: height var(--dur-fast) var(--ease-out);
	}

	.recorder-error {
		flex: 1;
		font-size: var(--text-sm);
		color: var(--danger-text);
		line-height: 1.4;
	}

	.recorder-btn {
		min-inline-size: max(2.25rem, var(--touch-min));
		min-block-size: max(2.25rem, var(--touch-min));
		border-radius: var(--radius-full);
		display: inline-flex;
		align-items: center;
		justify-content: center;
		flex-shrink: 0;
		transition:
			background-color var(--dur-fast) var(--ease-out),
			color var(--dur-fast) var(--ease-out),
			opacity var(--dur-fast) var(--ease-out);
	}

	.cancel-btn {
		background: var(--bg-surface);
		border: 1px solid var(--border-strong);
		color: var(--text-primary);
	}

	.cancel-btn:hover {
		background: var(--bg-active);
	}

	.send-btn {
		background: var(--accent-fill);
		color: var(--text-on-accent);
	}

	.send-btn:hover:not(:disabled) {
		background: var(--accent-fill-hover);
	}

	.send-btn:disabled {
		opacity: 0.55;
		cursor: not-allowed;
	}
</style>

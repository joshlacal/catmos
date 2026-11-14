<script lang="ts">
	import { onDestroy, onMount } from 'svelte';

	export interface RecordedVoicePayload {
		data: Uint8Array;
		contentType: string;
		durationMs: number;
		waveform: number[];
	}

	let {
		autoStart = false,
		onRecorded,
		onCancel
	}: {
		autoStart?: boolean;
		onRecorded?: (payload: RecordedVoicePayload) => void | Promise<void>;
		onCancel?: () => void;
	} = $props();

	const WAVEFORM_BARS = 36;
	const PREFERRED_AUDIO_MIMES = [
		'audio/webm;codecs=opus',
		'audio/ogg;codecs=opus',
		'audio/mp4',
		'audio/webm'
	];

	let isRecording = $state(false);
	let durationMs = $state(0);
	let recordError = $state<string | null>(null);
	let liveBars = $state<number[]>(Array.from({ length: WAVEFORM_BARS }, () => 0.12));

	let mediaRecorder: MediaRecorder | null = null;
	let activeStream: MediaStream | null = null;
	let audioContext: AudioContext | null = null;
	let analyser: AnalyserNode | null = null;
	let chunks: Blob[] = [];
	let collectedRms: number[] = [];
	let negotiatedMime = 'audio/webm;codecs=opus';
	let startTime = 0;
	let timer: ReturnType<typeof setInterval> | null = null;

	function selectSupportedMimeType(): string {
		if (typeof MediaRecorder === 'undefined' || typeof MediaRecorder.isTypeSupported !== 'function') {
			return 'audio/webm;codecs=opus';
		}
		for (const candidate of PREFERRED_AUDIO_MIMES) {
			if (MediaRecorder.isTypeSupported(candidate)) {
				return candidate;
			}
		}
		return '';
	}

	function downsampleWaveform(samples: number[], bars = WAVEFORM_BARS): number[] {
		if (samples.length === 0) {
			return Array.from({ length: bars }, () => 0.15);
		}
		const out: number[] = [];
		for (let i = 0; i < bars; i += 1) {
			const start = Math.floor((i * samples.length) / bars);
			const end = Math.max(start + 1, Math.floor(((i + 1) * samples.length) / bars));
			let sum = 0;
			for (let j = start; j < end && j < samples.length; j += 1) {
				sum += samples[j]!;
			}
			const avg = sum / Math.max(1, end - start);
			out.push(Math.min(1, Math.max(0.05, Number(avg.toFixed(3)))));
		}
		return out;
	}

	function sampleAnalyserLevel(): number {
		if (!analyser) return 0.15;
		const buf = new Uint8Array(analyser.fftSize);
		analyser.getByteTimeDomainData(buf);
		let sumSq = 0;
		for (let i = 0; i < buf.length; i += 1) {
			const norm = (buf[i]! - 128) / 128;
			sumSq += norm * norm;
		}
		const rms = Math.sqrt(sumSq / Math.max(1, buf.length));
		return Math.min(1, Math.max(0.06, rms * 3.5));
	}

	export async function startRecording() {
		recordError = null;
		try {
			const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
			activeStream = stream;
			const chosenMime = selectSupportedMimeType();
			negotiatedMime = chosenMime || 'audio/webm;codecs=opus';
			mediaRecorder = chosenMime
				? new MediaRecorder(stream, { mimeType: chosenMime })
				: new MediaRecorder(stream);
			if (mediaRecorder.mimeType) {
				negotiatedMime = mediaRecorder.mimeType;
			}
			chunks = [];
			collectedRms = [];

			const AudioCtx =
				globalThis.AudioContext ??
				(globalThis as unknown as { webkitAudioContext?: typeof AudioContext }).webkitAudioContext;
			if (AudioCtx) {
				audioContext = new AudioCtx();
				const source = audioContext.createMediaStreamSource(stream);
				analyser = audioContext.createAnalyser();
				analyser.fftSize = 256;
				source.connect(analyser);
			}

			mediaRecorder.ondataavailable = (e) => {
				if (e.data.size > 0) chunks.push(e.data);
			};

			mediaRecorder.onstop = async () => {
				const elapsed = Math.max(100, Date.now() - startTime);
				const blob = new Blob(chunks, { type: negotiatedMime });
				const data = new Uint8Array(await blob.arrayBuffer());
				const waveform = downsampleWaveform(collectedRms, WAVEFORM_BARS);
				releaseAudioResources();
				await onRecorded?.({
					data,
					contentType: negotiatedMime,
					durationMs: elapsed,
					waveform
				});
			};

			mediaRecorder.start();
			startTime = Date.now();
			durationMs = 0;
			isRecording = true;
			timer = setInterval(() => {
				durationMs = Date.now() - startTime;
				const level = sampleAnalyserLevel();
				collectedRms.push(level);
				liveBars = [...liveBars.slice(1), level];
			}, 100);
		} catch (err) {
			releaseAudioResources();
			recordError = err instanceof Error ? err.message : 'Microphone access denied';
		}
	}

	export function stopRecording() {
		if (mediaRecorder?.state === 'recording') {
			mediaRecorder.stop();
		}
		stopTimer();
		isRecording = false;
	}

	export function cancelRecording() {
		if (mediaRecorder?.state === 'recording') {
			mediaRecorder.ondataavailable = null;
			mediaRecorder.onstop = null;
			mediaRecorder.stop();
		}
		stopTimer();
		isRecording = false;
		releaseAudioResources();
		onCancel?.();
	}

	function stopTimer() {
		if (timer) {
			clearInterval(timer);
			timer = null;
		}
	}

	function releaseAudioResources() {
		if (activeStream) {
			activeStream.getTracks().forEach((t) => t.stop());
			activeStream = null;
		}
		analyser = null;
		if (audioContext) {
			audioContext.close().catch(() => {});
			audioContext = null;
		}
	}

	function formatDuration(ms: number): string {
		const s = Math.floor(ms / 1000);
		const m = Math.floor(s / 60);
		const sec = s % 60;
		return `${m}:${sec.toString().padStart(2, '0')}`;
	}

	onMount(() => {
		if (autoStart) {
			void startRecording();
		}
	});

	onDestroy(() => {
		if (mediaRecorder?.state === 'recording') {
			mediaRecorder.ondataavailable = null;
			mediaRecorder.onstop = null;
			mediaRecorder.stop();
		}
		stopTimer();
		releaseAudioResources();
	});
</script>

{#if recordError}
	<div class="voice-recorder error" role="alert">
		<span class="error-text">{recordError}</span>
		<button type="button" class="cancel-btn" aria-label="Dismiss voice error" onclick={() => { recordError = null; onCancel?.(); }}>✕</button>
	</div>
{:else if isRecording}
	<div class="voice-recorder">
		<button type="button" class="cancel-btn" aria-label="Cancel voice recording" onclick={cancelRecording}>✕</button>

		<div class="recording-indicator">
			<span class="pulse-dot"></span>
			<span class="duration">{formatDuration(durationMs)}</span>
			<div class="live-waveform" aria-hidden="true">
				{#each liveBars as bar}
					<div class="wave-bar" style="height: {Math.max(12, Math.round(bar * 100))}%"></div>
				{/each}
			</div>
		</div>

		<button type="button" class="send-btn" aria-label="Send voice message" onclick={stopRecording}>↑</button>
	</div>
{/if}

<style>
	.voice-recorder {
		display: flex;
		align-items: center;
		gap: 12px;
		padding: 8px 14px;
		background: rgba(255, 59, 48, 0.08);
		border: 1px solid rgba(255, 59, 48, 0.3);
		border-radius: 24px;
		flex: 1;
	}

	.voice-recorder.error {
		justify-content: space-between;
	}

	.error-text {
		font-size: 0.85rem;
		color: var(--danger, #ff3b30);
	}

	.recording-indicator {
		display: flex;
		align-items: center;
		gap: 10px;
		flex: 1;
		min-width: 0;
	}

	.pulse-dot {
		width: 10px;
		height: 10px;
		border-radius: 50%;
		background: #ff3b30;
		flex-shrink: 0;
		animation: pulse 0.8s ease-in-out infinite alternate;
	}

	@keyframes pulse {
		from {
			transform: scale(1);
			opacity: 1;
		}
		to {
			transform: scale(1.3);
			opacity: 0.7;
		}
	}

	.duration {
		font-variant-numeric: tabular-nums;
		font-size: 0.9rem;
		flex-shrink: 0;
	}

	.live-waveform {
		display: flex;
		align-items: center;
		gap: 2px;
		flex: 1;
		height: 24px;
		min-width: 60px;
	}

	.wave-bar {
		flex: 1;
		min-width: 2px;
		border-radius: 1px;
		background: #ff3b30;
		opacity: 0.75;
		transition: height 0.08s ease-out;
	}

	.cancel-btn,
	.send-btn {
		width: 32px;
		height: 32px;
		border-radius: 50%;
		border: none;
		cursor: pointer;
		display: flex;
		align-items: center;
		justify-content: center;
		font-size: 1rem;
		flex-shrink: 0;
	}

	.cancel-btn {
		background: rgba(128, 128, 128, 0.2);
		color: var(--text-secondary, #888);
	}

	.send-btn {
		background: var(--accent, #007aff);
		color: white;
	}
</style>

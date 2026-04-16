<script lang="ts">
	import { createEventDispatcher, onDestroy } from 'svelte';

	const dispatch = createEventDispatcher<{
		recorded: { blob: Blob; durationMs: number };
		cancel: void;
	}>();

	let isRecording = false;
	let durationMs = 0;
	let mediaRecorder: MediaRecorder | null = null;
	let chunks: Blob[] = [];
	let startTime = 0;
	let timer: ReturnType<typeof setInterval> | null = null;

	export async function startRecording() {
		try {
			const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
			mediaRecorder = new MediaRecorder(stream, {
				mimeType: 'audio/webm;codecs=opus'
			});
			chunks = [];

			mediaRecorder.ondataavailable = (e) => {
				if (e.data.size > 0) chunks.push(e.data);
			};

			mediaRecorder.onstop = () => {
				const blob = new Blob(chunks, { type: 'audio/webm;codecs=opus' });
				stream.getTracks().forEach((t) => t.stop());
				dispatch('recorded', { blob, durationMs });
			};

			mediaRecorder.start();
			startTime = Date.now();
			isRecording = true;
			timer = setInterval(() => {
				durationMs = Date.now() - startTime;
			}, 100);
		} catch (err) {
			console.error('Failed to start recording:', err);
		}
	}

	export function stopRecording() {
		if (mediaRecorder?.state === 'recording') {
			mediaRecorder.stop();
		}
		cleanup();
	}

	export function cancelRecording() {
		if (mediaRecorder?.state === 'recording') {
			mediaRecorder.ondataavailable = null;
			mediaRecorder.onstop = null;
			mediaRecorder.stop();
		}
		cleanup();
		dispatch('cancel');
	}

	function cleanup() {
		isRecording = false;
		if (timer) {
			clearInterval(timer);
			timer = null;
		}
	}

	function formatDuration(ms: number): string {
		const s = Math.floor(ms / 1000);
		const m = Math.floor(s / 60);
		const sec = s % 60;
		return `${m}:${sec.toString().padStart(2, '0')}`;
	}

	onDestroy(() => {
		cancelRecording();
	});
</script>

{#if isRecording}
	<div class="voice-recorder">
		<button class="cancel-btn" on:click={cancelRecording}>✕</button>

		<div class="recording-indicator">
			<span class="pulse-dot"></span>
			<span class="duration">{formatDuration(durationMs)}</span>
		</div>

		<button class="send-btn" on:click={stopRecording}>↑</button>
	</div>
{/if}

<style>
	.voice-recorder {
		display: flex;
		align-items: center;
		gap: 12px;
		padding: 8px 16px;
		background: rgba(255, 59, 48, 0.08);
		border: 1px solid rgba(255, 59, 48, 0.3);
		border-radius: 24px;
	}

	.recording-indicator {
		display: flex;
		align-items: center;
		gap: 8px;
		flex: 1;
	}

	.pulse-dot {
		width: 10px;
		height: 10px;
		border-radius: 50%;
		background: #ff3b30;
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
		font-size: 0.95rem;
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
	}

	.cancel-btn {
		background: rgba(128, 128, 128, 0.2);
		color: var(--text-secondary, #888);
	}

	.send-btn {
		background: var(--accent-color, #007aff);
		color: white;
	}
</style>

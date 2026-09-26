<script lang="ts">
	import type { DirectRequestView } from '$lib/request-types';
	import type { Message } from '$lib/tauri';
	import { auth } from '$lib/stores/auth';
	import MessageBubble, { type ReplyInfo } from './MessageBubble.svelte';

	let {
		messages = [],
		request,
		typingUsers = [],
		onReply
	}: {
		messages: Message[];
		request?: DirectRequestView;
		typingUsers?: string[];
		onReply?: (info: ReplyInfo) => void;
	} = $props();
	let scrollContainer: HTMLDivElement | undefined = $state();

	$effect(() => {
		if (scrollContainer && (messages.length || typingUsers.length)) {
			scrollContainer.scrollTop = scrollContainer.scrollHeight;
		}
	});

	// Determine if we should show sender info (avatar + name) for a message
	// Show when: first message, different sender from previous, or >5 min gap
	function shouldShowSender(index: number): boolean {
		if (index === 0) return true;
		const msg = messages[index];
		const prev = messages[index - 1];
		if (msg.senderDid !== prev.senderDid) return true;
		if (msg.messageType === 'system' || prev.messageType === 'system') return true;
		const gap = new Date(msg.timestamp).getTime() - new Date(prev.timestamp).getTime();
		return gap > 5 * 60 * 1000;
	}

	function shortDid(did: string): string {
		return did.split(':').pop() ?? did;
	}

	let typingLabel = $derived.by(() => {
		if (typingUsers.length === 0) return '';
		if (typingUsers.length === 1) return `${shortDid(typingUsers[0])} is typing`;
		if (typingUsers.length === 2) {
			return `${shortDid(typingUsers[0])} and ${shortDid(typingUsers[1])} are typing`;
		}
		return `${shortDid(typingUsers[0])} and ${typingUsers.length - 1} others are typing`;
	});
</script>

<div class="message-list" bind:this={scrollContainer}>
	{#if request?.consent === 'accepted' && request.firstMessageId && request.preview?.type === 'ready' && !messages.some(m => m.id === request?.firstMessageId)}
		<article class="request-first-message" data-message-id={request.firstMessageId}><small>First message · encrypted introduction{#if request.introduction} · {new Date(request.introduction.receivedAt).toLocaleString()}{/if}</small><p>{request.preview.text}</p>{#if request.preview.invitation}<small>Includes a separate group invitation; group consent is unchanged.</small>{/if}</article>
	{/if}
	{#if request?.consent === 'accepted' && (request.preview?.type === 'unavailable' || request.capabilities?.canSend === false)}
		<div class="empty-messages unavailable-device" role="status">
			<div class="empty-icon">
				<svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1" stroke-linecap="round" stroke-linejoin="round">
					<circle cx="12" cy="12" r="10" />
					<line x1="12" y1="8" x2="12" y2="12" />
					<line x1="12" y1="16" x2="12.01" y2="16" />
				</svg>
			</div>
			<p class="empty-title">Encrypted messages unavailable on this device</p>
			<p class="empty-subtitle">This conversation was accepted on another device. Encrypted messages are not available here.</p>
		</div>
	{:else if messages.length === 0 && request?.preview?.type !== 'ready'}
		<div class="empty-messages">
			<div class="empty-icon">
				<svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1" stroke-linecap="round" stroke-linejoin="round">
					<path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" />
				</svg>
			</div>
			<p class="empty-title">No messages yet</p>
			<p class="empty-subtitle">Send a message to start the conversation</p>
		</div>
	{:else}
		<div class="messages-inner" role="log" aria-live="polite">
			{#each messages as message, i (message.id)}
				<div class="message-item" data-status={message.status ?? 'confirmed'} data-message-id={message.id}>
					<MessageBubble {message} showSender={shouldShowSender(i)} {onReply} />
				</div>
			{/each}
		</div>
	{/if}
	{#if typingUsers.length > 0}
		<div class="typing-indicator">
			<div class="typing-dots">
				<span class="dot"></span>
				<span class="dot"></span>
				<span class="dot"></span>
			</div>
			<span class="typing-text">{typingLabel}</span>
		</div>
	{/if}
</div>

<style>
	.request-first-message { margin: 20px; padding: 20px; border: 1px solid var(--border); border-radius: 14px; background: var(--bg-secondary); }
	.request-first-message p { white-space: pre-wrap; overflow-wrap: anywhere; line-height: 1.6; }
	.request-first-message small { color: var(--text-tertiary); font-size: 11px; }
	.message-list {
		flex: 1;
		overflow-y: auto;
		padding: 16px 20px;
		display: flex;
		flex-direction: column;
	}

	.empty-messages {
		flex: 1;
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
		gap: 8px;
	}

	.empty-icon {
		color: var(--text-tertiary);
		margin-bottom: 8px;
		opacity: 0.5;
	}

	.empty-title {
		color: var(--text-secondary);
		font-size: 16px;
		font-weight: 600;
	}

	.empty-subtitle {
		color: var(--text-tertiary);
		font-size: 13px;
	}

	.messages-inner {
		display: flex;
		flex-direction: column;
		gap: 2px;
		margin-top: auto;
	}

	.typing-indicator {
		display: flex;
		align-items: center;
		gap: 8px;
		padding: 8px 12px 4px;
	}

	.typing-dots {
		display: flex;
		gap: 3px;
		align-items: center;
	}

	.dot {
		width: 5px;
		height: 5px;
		border-radius: var(--radius-full);
		background: var(--text-tertiary);
		animation: typing-bounce 1.4s ease-in-out infinite;
	}

	.dot:nth-child(2) {
		animation-delay: 0.2s;
	}

	.dot:nth-child(3) {
		animation-delay: 0.4s;
	}

	@keyframes typing-bounce {
		0%, 60%, 100% { transform: translateY(0); opacity: 0.4; }
		30% { transform: translateY(-4px); opacity: 1; }
	}

	.typing-text {
		color: var(--text-tertiary);
		font-size: 12px;
	}
</style>

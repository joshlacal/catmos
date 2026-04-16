<script lang="ts">
	import type { Message } from '$lib/tauri';
	import { auth } from '$lib/stores/auth';
	import MessageBubble, { type ReplyInfo } from './MessageBubble.svelte';

	let {
		messages = [],
		typingUsers = [],
		onReply
	}: {
		messages: Message[];
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
	{#if messages.length === 0}
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
		<div class="messages-inner">
			{#each messages as message, i (message.id)}
				<MessageBubble {message} showSender={shouldShowSender(i)} {onReply} />
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

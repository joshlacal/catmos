<script lang="ts">
	import type { Message } from '$lib/tauri';
	import { profiles } from '$lib/stores/profiles';
	import { auth } from '$lib/stores/auth';
	import { conversations } from '$lib/stores/conversations';
	import Reactions from './Reactions.svelte';
	import MessageImage from './MessageImage.svelte';
	import BlueskyEmbed from './BlueskyEmbed.svelte';

	export interface ReplyInfo {
		messageId: string;
		senderDid: string;
		senderName: string;
		preview: string;
	}

	let {
		message,
		showSender = true,
		onReply
	}: {
		message: Message;
		showSender?: boolean;
		onReply?: (info: ReplyInfo) => void;
	} = $props();

	$effect(() => {
		if (message.messageType !== 'system' && message.senderDid) {
			profiles.resolveProfiles([message.senderDid]);
		}
	});

	let profile = $derived(message.senderDid ? $profiles.cache.get(message.senderDid) : undefined);
	let displayName = $derived(
		profile?.displayName || profile?.handle || message.senderHandle || message.senderDid || 'Unknown'
	);
	let avatarUrl = $derived(profile?.avatar);
	let initial = $derived(displayName.charAt(0).toUpperCase());
	let isSystem = $derived(message.messageType === 'system');
	let isOwn = $derived(message.senderDid === $auth.user?.did);

	// Parse structured content (may contain reply reference)
	let parsed = $derived.by(() => {
		if (!message.content) return null;
		try {
			const obj = JSON.parse(message.content);
			if (typeof obj === 'object' && obj !== null && typeof obj.text === 'string') {
				return obj as { text: string; reply?: { messageId: string; senderDid: string; preview: string } };
			}
		} catch {
			// Not JSON — plain text message
		}
		return null;
	});

	// The actual text to display (unwrap from JSON if structured)
	let rawContent = $derived(parsed ? parsed.text : message.content);

	// Reply reference from parsed content
	let replyRef = $derived(parsed?.reply ?? null);

	// Resolve reply sender profile
	$effect(() => {
		if (replyRef?.senderDid) {
			profiles.resolveProfiles([replyRef.senderDid]);
		}
	});

	let replySenderName = $derived.by(() => {
		if (!replyRef) return '';
		const p = $profiles.cache.get(replyRef.senderDid);
		return p?.displayName || p?.handle || replyRef.senderDid;
	});

	// Detect Bluesky post URLs in message content
	let blueskyUrl = $derived.by(() => {
		if (!rawContent || message.groupInvitation) return null;
		const bskyMatch = rawContent.match(
			/https:\/\/bsky\.app\/profile\/[^\s/]+\/post\/[a-zA-Z0-9]+/
		);
		if (bskyMatch) return bskyMatch[0];
		const atMatch = rawContent.match(
			/at:\/\/did:[^/]+\/app\.bsky\.feed\.post\/[a-zA-Z0-9]+/
		);
		if (atMatch) return atMatch[0];
		return null;
	});

	// Message content with the Bluesky URL removed (if it's the only content)
	let textContent = $derived.by(() => {
		if (!rawContent || !blueskyUrl) return rawContent;
		const stripped = rawContent.replace(blueskyUrl, '').trim();
		return stripped || null;
	});

	function formatTime(iso: string): string {
		return new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
	}

	function handleReply() {
		onReply?.({
			messageId: message.id,
			senderDid: message.senderDid,
			senderName: displayName,
			preview: (rawContent ?? '').slice(0, 100)
		});
	}

	function scrollToMessage(messageId: string) {
		const el = document.querySelector(`[data-message-id="${messageId}"]`);
		if (el) {
			el.scrollIntoView({ behavior: 'smooth', block: 'center' });
			el.classList.add('highlight-flash');
			setTimeout(() => el.classList.remove('highlight-flash'), 1500);
		}
	}
</script>

{#if isSystem}
	<div class="system-message">
		<div class="system-line"></div>
		<span class="system-content">
			<svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor" class="system-lock">
				<path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zM12 17c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1s3.1 1.39 3.1 3.1v2z"/>
			</svg>
			{message.content}
		</span>
		<div class="system-line"></div>
	</div>
{:else}
	<div class="message-row" class:own={isOwn} class:failed={message.status === 'failed'} data-message-id={message.id}>
		{#if !isOwn && showSender}
			<div class="avatar-slot">
				<div class="message-avatar">
					{#if avatarUrl}
						<img src={avatarUrl} alt={displayName} class="avatar-img" />
					{:else}
						{initial}
					{/if}
				</div>
			</div>
		{:else if !isOwn}
			<div class="avatar-slot"></div>
		{/if}

		<div class="bubble-wrapper">
			{#if !isOwn && showSender}
				<span class="sender-name">{displayName}</span>
			{/if}
			<div class="bubble" class:own={isOwn}>
				{#if replyRef}
					<button class="reply-quote" onclick={() => scrollToMessage(replyRef!.messageId)}>
						<span class="reply-quote-sender">{replySenderName}</span>
						<span class="reply-quote-text">{replyRef.preview}</span>
					</button>
				{/if}
				{#if message.image}
					<MessageImage conversationId={message.conversationId} image={message.image} fallbackAlt={rawContent || undefined} />
				{/if}
				{#if textContent}
					<div class="bubble-text">{textContent}</div>
				{/if}
                {#if message.groupInvitation}
                    <button class="reply-quote" onclick={() => conversations.select(message.groupInvitation!.conversationId)}><span class="reply-quote-sender">View group invitation</span><span class="reply-quote-text">Review separately · opening does not accept</span></button>
                {/if}
				{#if blueskyUrl}
					<BlueskyEmbed url={blueskyUrl} />
				{/if}
				<div class="bubble-meta">
					<span class="bubble-time">{formatTime(message.timestamp)}</span>
					{#if isOwn}
						{#if message.status === 'sending'}
							<span class="status-dot sending" role="status" aria-label="Sending"></span>
						{:else if message.status === 'failed'}
							<span class="status-icon failed" role="img" aria-label="Not sent">!</span>
						{:else if message.status === 'read'}
							<svg class="status-check read" width="16" height="10" viewBox="0 0 16 10">
								<path d="M1 5l3 3 7-7" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
								<path d="M5 5l3 3 7-7" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
							</svg>
						{:else if message.status === 'delivered'}
							<svg class="status-check delivered" width="16" height="10" viewBox="0 0 16 10">
								<path d="M1 5l3 3 7-7" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
								<path d="M5 5l3 3 7-7" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
							</svg>
						{:else if message.status === 'sent'}
							<svg class="status-check sent" width="12" height="10" viewBox="0 0 12 10">
								<path d="M1 5l3 3 7-7" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
							</svg>
						{/if}
					{/if}
				</div>
			</div>
			{#if isOwn && message.status === 'failed'}
				<p class="send-error" role="alert">Not sent: {message.error ?? 'Send failed'}</p>
			{/if}
			{#if onReply}
				<button class="reply-btn" onclick={handleReply} aria-label="Reply">
					<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
						<polyline points="9 17 4 12 9 7" />
						<path d="M20 18v-2a4 4 0 0 0-4-4H4" />
					</svg>
				</button>
			{/if}
			<Reactions
				reactions={message.reactions ?? {}}
				conversationId={message.conversationId}
				messageId={message.id}
			/>
		</div>
	</div>
{/if}

<style>
	/* ── System message ── */
	.system-message {
		display: flex;
		align-items: center;
		gap: 12px;
		padding: 12px 0;
	}

	.system-line {
		flex: 1;
		height: 1px;
		background: var(--border);
	}

	.system-content {
		display: flex;
		align-items: center;
		gap: 6px;
		color: var(--text-secondary);
		font-size: 12px;
		font-weight: 500;
		white-space: nowrap;
	}

	.system-lock {
		opacity: 0.5;
	}

	/* ── Message row ── */
	.message-row {
		display: flex;
		gap: 8px;
		padding: 2px 0;
		align-items: flex-end;
	}

	.message-row.own {
		flex-direction: row-reverse;
	}

	.avatar-slot {
		width: 32px;
		flex-shrink: 0;
	}

	.message-avatar {
		width: 32px;
		height: 32px;
		border-radius: var(--radius-full);
		background: var(--accent);
		color: var(--text-on-accent);
		display: flex;
		align-items: center;
		justify-content: center;
		font-weight: 600;
		font-size: 13px;
		overflow: hidden;
	}

	.avatar-img {
		width: 100%;
		height: 100%;
		object-fit: cover;
	}

	/* ── Bubble wrapper ── */
	.bubble-wrapper {
		max-width: 70%;
		min-width: 0;
		position: relative;
	}

	.sender-name {
		display: block;
		font-size: 12px;
		font-weight: 600;
		color: var(--text-secondary);
		margin-bottom: 2px;
		margin-left: 12px;
	}

	/* ── Bubble ── */
	.bubble {
		padding: 10px 14px;
		border-radius: 18px;
		background: var(--bg-bubble-other);
		color: var(--text-primary);
		word-break: break-word;
		position: relative;
	}

	.bubble.own {
		background: var(--bg-bubble-own);
		color: var(--text-on-accent);
		border-bottom-right-radius: 4px;
	}

	.bubble:not(.own) {
		border-bottom-left-radius: 4px;
	}

	.bubble-text {
		line-height: 1.45;
		font-size: 14px;
		white-space: pre-wrap;
	}

	/* ── Meta (time + status) ── */
	.bubble-meta {
		display: flex;
		align-items: center;
		justify-content: flex-end;
		gap: 4px;
		margin-top: 4px;
	}

	.bubble-time {
		font-size: 11px;
		opacity: 0.6;
	}

	.status-dot {
		width: 6px;
		height: 6px;
		border-radius: var(--radius-full);
	}

	.status-dot.sending {
		background: currentColor;
		opacity: 0.4;
		animation: pulse 1.2s ease-in-out infinite;
	}

	@keyframes pulse {
		0%, 100% { opacity: 0.3; }
		50% { opacity: 0.7; }
	}

	.status-icon.failed {
		width: 14px;
		height: 14px;
		border-radius: var(--radius-full);
		background: var(--danger);
		color: white;
		font-size: 10px;
		font-weight: 700;
		display: inline-flex;
		align-items: center;
		justify-content: center;
	}

	.status-check {
		flex-shrink: 0;
	}

	.status-check.sent {
		opacity: 0.5;
	}

	.status-check.delivered {
		opacity: 0.6;
	}

	.status-check.read {
		color: #34c759;
		opacity: 1;
	}

	.own .status-check.read {
		color: #ffffff;
	}

	/* ── Reply quote (inline in bubble) ── */
	.reply-quote {
		display: flex;
		flex-direction: column;
		gap: 2px;
		padding: 6px 10px;
		margin-bottom: 6px;
		background: rgba(0, 0, 0, 0.08);
		border-left: 3px solid var(--accent);
		border-radius: 0 var(--radius-sm) var(--radius-sm) 0;
		cursor: pointer;
		text-align: left;
		transition: background var(--transition-fast);
	}

	.reply-quote:hover {
		background: rgba(0, 0, 0, 0.12);
	}

	.own .reply-quote {
		background: rgba(255, 255, 255, 0.15);
		border-left-color: rgba(255, 255, 255, 0.6);
	}

	.own .reply-quote:hover {
		background: rgba(255, 255, 255, 0.2);
	}

	.reply-quote-sender {
		font-size: 11px;
		font-weight: 600;
		color: var(--text-link);
	}

	.own .reply-quote-sender {
		color: rgba(255, 255, 255, 0.85);
	}

	.reply-quote-text {
		font-size: 12px;
		color: var(--text-secondary);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
		max-width: 280px;
	}

	.own .reply-quote-text {
		color: rgba(255, 255, 255, 0.7);
	}

	/* ── Reply button (hover action) ── */
	.reply-btn {
		opacity: 0;
		position: absolute;
		top: -4px;
		right: -4px;
		width: 28px;
		height: 28px;
		display: flex;
		align-items: center;
		justify-content: center;
		border-radius: var(--radius-full);
		background: var(--bg-card);
		border: 1px solid var(--border);
		color: var(--text-secondary);
		box-shadow: var(--shadow-sm, 0 1px 2px rgba(0,0,0,0.1));
		cursor: pointer;
		transition: all var(--transition-fast);
		z-index: 1;
	}

	.message-row.own .reply-btn {
		right: auto;
		left: -4px;
	}

	.message-row:hover .reply-btn {
		opacity: 1;
	}

	.reply-btn:hover {
		color: var(--text-link);
		background: var(--bg-hover);
	}

	/* ── Highlight flash for scroll-to-message ── */
	:global(.highlight-flash) {
		animation: highlight-flash 1.5s ease-out;
	}

	@keyframes highlight-flash {
		0% { background: var(--accent); opacity: 0.3; }
		100% { background: transparent; opacity: 1; }
	}

	/* ── Failed state ── */
	.message-row.failed .bubble {
		opacity: 0.6;
		outline: 1px solid var(--danger);
	}

	.send-error {
		margin: 4px 12px 0;
		font-size: 11px;
		color: var(--danger);
		text-align: right;
		overflow-wrap: anywhere;
	}
</style>

<script module lang="ts">
	export type ClusterPosition = 'single' | 'first' | 'middle' | 'last';

	export interface ReplyReference {
		messageId: string;
		senderDid: string;
		preview: string;
	}

	let nextBubbleUid = 0;
</script>

<script lang="ts">
	import type { Message } from '#lib/wasm.ts';
	import * as api from '#lib/wasm.ts';
	import {
		foldReactionsByAccount,
		hasAccountReacted,
		isSameAccountDid,
		stripDidFragment
	} from '#lib/did.ts';
	import { auth } from '#lib/stores/auth.ts';
	import { messages } from '#lib/stores/messages.ts';
	import { profiles, resolveProfileName } from '#lib/stores/profiles.ts';
	import { extractMessagePreview } from '#lib/stores/conversations.ts';
	import { formatClockTime } from '#lib/utils/time.ts';
	import {
		positionPopoverAtPoint,
		positionPopoverFallback,
		useRovingMenu,
		type PopoverPlacement
	} from '#lib/utils/popover.ts';
	import { announce, showToast } from '#lib/utils/announcer.ts';
	import Avatar from './Avatar.svelte';
	import Icon from './Icon.svelte';
	import Reactions, { QUICK_REACTION_EMOJIS } from './Reactions.svelte';
	import MessageImage from './MessageImage.svelte';
	import VoicePlayer from './VoicePlayer.svelte';
	import BlueskyEmbed from './BlueskyEmbed.svelte';

	type TextSegment =
		| { kind: 'text'; value: string }
		| { kind: 'link'; href: string; label: string };

	let {
		message,
		clusterPosition = 'single',
		isGroup = false,
		highlighted = false,
		onReply,
		onJumpToMessage
	}: {
		message: Message;
		clusterPosition?: ClusterPosition;
		isGroup?: boolean;
		highlighted?: boolean;
		onReply?: (message: Message) => void;
		onJumpToMessage?: (messageId: string) => void;
	} = $props();

	const bubbleUid = ++nextBubbleUid;
	const reactPopoverId = `catmos-msg-react-${bubbleUid}`;
	const reactAnchorName = `--catmos-msg-react-anchor-${bubbleUid}`;
	const morePopoverId = `catmos-msg-more-${bubbleUid}`;
	const moreAnchorName = `--catmos-msg-more-anchor-${bubbleUid}`;

	let reactTriggerEl: HTMLButtonElement | undefined = $state();
	let reactPopoverEl: HTMLDivElement | undefined = $state();
	let moreTriggerEl: HTMLButtonElement | undefined = $state();
	let morePopoverEl: HTMLDivElement | undefined = $state();
	let anyPopoverOpen = $state(false);
	let moreOpenedAtPoint = false;
	let contextPoint = { x: 0, y: 0 };

	let prefersReducedMotion = $state(
		typeof window !== 'undefined' && typeof window.matchMedia === 'function'
			? window.matchMedia('(prefers-reduced-motion: reduce)').matches
			: false
	);

	$effect(() => {
		if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return;
		const mq = window.matchMedia('(prefers-reduced-motion: reduce)');
		prefersReducedMotion = mq.matches;
		const onChange = (event: MediaQueryListEvent) => {
			prefersReducedMotion = event.matches;
		};
		if (typeof mq.addEventListener === 'function') {
			mq.addEventListener('change', onChange);
			return () => mq.removeEventListener('change', onChange);
		}
		return;
	});

	let senderAccountDid = $derived(stripDidFragment(message.senderDid));
	let isSystem = $derived(message.messageType === 'system' || message.messageType === 'event');
	let isOwn = $derived(
		Boolean(message.isOwn) || isSameAccountDid(message.senderDid, $auth.user?.did)
	);
	let voiceAudio = $derived(message.audio ?? message.audioAttachment ?? null);
	let showSenderName = $derived(
		!isOwn && isGroup && (clusterPosition === 'single' || clusterPosition === 'first')
	);
	let showAvatar = $derived(
		!isOwn && (clusterPosition === 'single' || clusterPosition === 'last')
	);

	let reactPlacement = $derived<PopoverPlacement>(isOwn ? 'top-end' : 'bottom-start');
	let morePlacement = $derived<PopoverPlacement>(isOwn ? 'bottom-end' : 'bottom-start');

	$effect(() => {
		if (!isSystem && senderAccountDid) {
			profiles.resolveProfiles([senderAccountDid]);
		}
	});

	let profile = $derived(senderAccountDid ? $profiles.cache.get(senderAccountDid) : undefined);

	let displayName = $derived.by(() => {
		if (!senderAccountDid) return stripDidFragment(message.senderHandle) || 'Unknown';
		if (profile) return resolveProfileName($profiles.cache, senderAccountDid);
		const cleanHandle = stripDidFragment(message.senderHandle);
		if (cleanHandle && !cleanHandle.startsWith('did:')) {
			return cleanHandle.startsWith('@') ? cleanHandle : `@${cleanHandle}`;
		}
		return resolveProfileName($profiles.cache, senderAccountDid);
	});

	let parsedEnvelope = $derived.by(() => {
		if (!message.content) return null;
		const trimmed = message.content.trim();
		if (!trimmed.startsWith('{')) return null;
		try {
			const obj = JSON.parse(trimmed) as {
				text?: unknown;
				reply?: { messageId?: unknown; senderDid?: unknown; preview?: unknown };
			};
			if (obj && typeof obj === 'object' && typeof obj.text === 'string') {
				const reply: ReplyReference | undefined =
					obj.reply &&
					typeof obj.reply.messageId === 'string' &&
					typeof obj.reply.senderDid === 'string'
						? {
								messageId: obj.reply.messageId,
								senderDid: obj.reply.senderDid,
								preview: typeof obj.reply.preview === 'string' ? obj.reply.preview : ''
							}
						: undefined;
				return { text: obj.text, reply };
			}
		} catch {
			// Plain text starting with '{'
		}
		return null;
	});

	let rawContent = $derived(parsedEnvelope ? parsedEnvelope.text : message.content);
	let replyRef = $derived<ReplyReference | null>(parsedEnvelope?.reply ?? null);
	let replyAccountDid = $derived(replyRef ? stripDidFragment(replyRef.senderDid) : '');

	$effect(() => {
		if (replyAccountDid) {
			profiles.resolveProfiles([replyAccountDid]);
		}
	});

	let replySenderName = $derived.by(() => {
		if (!replyRef) return '';
		if (isSameAccountDid(replyRef.senderDid, $auth.user?.did)) return 'You';
		return resolveProfileName($profiles.cache, replyAccountDid || replyRef.senderDid);
	});

	let replyPreviewText = $derived(replyRef ? extractMessagePreview(replyRef.preview) : '');

	// Structured post, link, and GIF embeds hydrated from MLS payload
	let embed = $derived(message.embed ?? null);
	let embedPostUri = $derived(
		embed?.type === 'post' && typeof embed.data.uri === 'string' ? embed.data.uri : null
	);

	let linkEmbed = $derived.by(() => {
		if (embed?.type !== 'link' || typeof embed.data.url !== 'string') return null;
		if (!/^https?:\/\//i.test(embed.data.url)) return null;
		const d = embed.data;
		let domain = typeof d.domain === 'string' ? d.domain.trim() : '';
		if (!domain) {
			try {
				domain = new URL(d.url as string).hostname;
			} catch {
				domain = '';
			}
		}
		return {
			url: d.url as string,
			title: typeof d.title === 'string' && d.title.trim() ? d.title.trim() : null,
			description:
				typeof d.description === 'string' && d.description.trim()
					? d.description.trim()
					: null,
			domain
		};
	});

	let gifEmbed = $derived.by(() => {
		if (embed?.type !== 'gif') return null;
		const d = embed.data;
		const mp4 = d.mp4_url ?? d.mp4URL;
		if (typeof mp4 !== 'string' || !/^https:\/\//i.test(mp4)) return null;
		const widthNum = Number(d.width ?? 0);
		const heightNum = Number(d.height ?? 0);
		return {
			mp4,
			title: typeof d.title === 'string' && d.title.trim() ? d.title.trim() : 'GIF',
			width: Number.isFinite(widthNum) && widthNum > 0 ? widthNum : 1,
			height: Number.isFinite(heightNum) && heightNum > 0 ? heightNum : 1
		};
	});

	let blueskyUrl = $derived.by(() => {
		if (embedPostUri) return embedPostUri;
		if (!rawContent) return null;
		const bskyMatch = rawContent.match(
			/https:\/\/bsky\.app\/profile\/[^\s/?#]+\/post\/[a-zA-Z0-9]+/
		);
		if (bskyMatch) return bskyMatch[0];
		const atMatch = rawContent.match(
			/at:\/\/did:[^\s/?#]+\/app\.bsky\.feed\.post\/[a-zA-Z0-9]+/
		);
		if (atMatch) return atMatch[0];
		return null;
	});

	let textContent = $derived.by(() => {
		if (!rawContent) return '';
		if (!blueskyUrl) return rawContent;
		if (rawContent.trim() === blueskyUrl) return '';
		return rawContent;
	});

	function tokenizeUrls(text: string): TextSegment[] {
		if (!text) return [];
		const segments: TextSegment[] = [];
		const urlRegex = /https?:\/\/[^\s<>"'`]+/g;
		let lastIndex = 0;
		let match: RegExpExecArray | null;

		while ((match = urlRegex.exec(text)) !== null) {
			const start = match.index;
			if (start > lastIndex) {
				segments.push({ kind: 'text', value: text.slice(lastIndex, start) });
			}

			let rawUrl = match[0];
			let trailing = '';
			while (rawUrl.length > 0 && /[.,;:!?)]$/.test(rawUrl)) {
				const lastChar = rawUrl.slice(-1);
				if (lastChar === ')' && rawUrl.includes('(')) break;
				trailing = lastChar + trailing;
				rawUrl = rawUrl.slice(0, -1);
			}

			let validHref: string | null = null;
			try {
				const parsed = new URL(rawUrl);
				if (parsed.protocol === 'https:' || parsed.protocol === 'http:') {
					validHref = parsed.toString();
				}
			} catch {
				validHref = null;
			}

			if (validHref) {
				segments.push({ kind: 'link', href: validHref, label: rawUrl });
			} else {
				segments.push({ kind: 'text', value: rawUrl });
			}

			if (trailing) {
				segments.push({ kind: 'text', value: trailing });
			}
			lastIndex = start + match[0].length;
		}

		if (lastIndex < text.length) {
			segments.push({ kind: 'text', value: text.slice(lastIndex) });
		}

		return segments;
	}

	let textSegments = $derived(tokenizeUrls(textContent));

	let foldedReactions = $derived(foldReactionsByAccount(message.reactions));

	let hasReactions = $derived(Object.keys(foldedReactions).length > 0);

	let copyableText = $derived(
		(rawContent || voiceAudio?.transcript || linkEmbed?.url || '').trim()
	);

	function hasReacted(emoji: string): boolean {
		return hasAccountReacted(foldedReactions, emoji, $auth.user?.did);
	}

	function hidePopoverSafe(el: HTMLElement | undefined) {
		try {
			if (el && typeof el.hidePopover === 'function' && el.matches(':popover-open')) {
				el.hidePopover();
			}
		} catch {
			// Ignore if Popover API is unavailable in test DOM
		}
	}

	function clearManualPopoverPosition(el: HTMLElement | undefined) {
		if (!el) return;
		el.style.removeProperty('position');
		el.style.removeProperty('inset');
		el.style.removeProperty('margin');
		el.style.removeProperty('left');
		el.style.removeProperty('top');
	}

	function syncPopoverOpenState() {
		const reactOpen = Boolean(reactPopoverEl?.matches?.(':popover-open'));
		const moreOpen = Boolean(morePopoverEl?.matches?.(':popover-open'));
		anyPopoverOpen = reactOpen || moreOpen;
	}

	function handleReactToggle(event: Event) {
		const toggleEvent = event as ToggleEvent;
		syncPopoverOpenState();
		if (toggleEvent.newState === 'open' && reactPopoverEl && reactTriggerEl) {
			positionPopoverFallback(reactPopoverEl, reactTriggerEl, reactPlacement, 6);
			requestAnimationFrame(() => {
				reactPopoverEl?.querySelector<HTMLButtonElement>('button')?.focus();
			});
		}
	}

	function handleMoreToggle(event: Event) {
		const toggleEvent = event as ToggleEvent;
		syncPopoverOpenState();
		if (toggleEvent.newState === 'open' && morePopoverEl) {
			if (moreOpenedAtPoint) {
				positionPopoverAtPoint(morePopoverEl, contextPoint.x, contextPoint.y);
			} else if (moreTriggerEl) {
				clearManualPopoverPosition(morePopoverEl);
				positionPopoverFallback(morePopoverEl, moreTriggerEl, morePlacement, 6);
			}
			requestAnimationFrame(() => {
				morePopoverEl?.querySelector<HTMLButtonElement>('button')?.focus();
			});
		} else if (toggleEvent.newState === 'closed') {
			moreOpenedAtPoint = false;
			clearManualPopoverPosition(morePopoverEl);
		}
	}

	function handleMoreButtonClick() {
		moreOpenedAtPoint = false;
		clearManualPopoverPosition(morePopoverEl);
	}

	function handleBubbleContextMenu(event: MouseEvent) {
		if (typeof window !== 'undefined') {
			const selectedText = window.getSelection()?.toString().trim();
			if (selectedText) return;
		}
		if (!morePopoverEl || typeof morePopoverEl.showPopover !== 'function') return;
		event.preventDefault();
		moreOpenedAtPoint = true;
		contextPoint = { x: event.clientX, y: event.clientY };
		try {
			if (morePopoverEl.matches(':popover-open')) {
				positionPopoverAtPoint(morePopoverEl, contextPoint.x, contextPoint.y);
			} else {
				morePopoverEl.showPopover();
			}
		} catch {
			moreOpenedAtPoint = false;
		}
	}

	function attachContextMenu(node: HTMLElement): { destroy: () => void } {
		node.addEventListener('contextmenu', handleBubbleContextMenu);
		return {
			destroy() {
				node.removeEventListener('contextmenu', handleBubbleContextMenu);
			}
		};
	}

	async function toggleQuickReaction(emoji: string) {
		const myDid = stripDidFragment($auth.user?.did);
		if (!myDid) return;
		const action: 'add' | 'remove' = hasReacted(emoji) ? 'remove' : 'add';

		messages.applyReaction({
			conversationId: message.conversationId,
			messageId: message.id,
			senderDid: myDid,
			emoji,
			action
		});
		hidePopoverSafe(reactPopoverEl);
		hidePopoverSafe(morePopoverEl);
		announce(action === 'add' ? `Added ${emoji} reaction` : `Removed ${emoji} reaction`);

		try {
			await api.sendReaction(message.conversationId, message.id, emoji, action);
		} catch (err) {
			console.error('[catmos] Failed to send reaction:', err);
			messages.applyReaction({
				conversationId: message.conversationId,
				messageId: message.id,
				senderDid: myDid,
				emoji,
				action: action === 'add' ? 'remove' : 'add'
			});
			showToast({ message: 'Could not update reaction.', tone: 'error' });
		}
	}

	function handleReplyClick() {
		hidePopoverSafe(morePopoverEl);
		onReply?.(message);
	}

	async function handleCopyText() {
		hidePopoverSafe(morePopoverEl);
		if (!copyableText) return;
		try {
			await navigator.clipboard.writeText(copyableText);
			showToast({ message: 'Copied message text', tone: 'success' });
		} catch {
			showToast({ message: 'Could not copy to clipboard.', tone: 'error' });
		}
	}

	function jumpToMessage(targetId: string) {
		hidePopoverSafe(morePopoverEl);
		if (onJumpToMessage) {
			onJumpToMessage(targetId);
			return;
		}
		if (typeof document === 'undefined') return;
		const escaped =
			typeof CSS !== 'undefined' && typeof CSS.escape === 'function'
				? CSS.escape(targetId)
				: targetId.replace(/"/g, '\\"');
		const el = document.querySelector(`[data-message-id="${escaped}"]`);
		if (el) {
			const reduced =
				typeof window !== 'undefined' &&
				window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
			el.scrollIntoView({ behavior: reduced ? 'auto' : 'smooth', block: 'center' });
		}
	}

	async function handleRetry() {
		hidePopoverSafe(morePopoverEl);
		await messages.retryMessage(message.conversationId, message.id);
	}

	function handleRemoveFailed() {
		hidePopoverSafe(morePopoverEl);
		messages.deleteFailedMessage(message.conversationId, message.id);
		announce('Removed unsent message');
	}
</script>

{#if isSystem}
	<div class="system-message" data-message-id={message.id}>
		<div class="system-line" aria-hidden="true"></div>
		<span class="system-content">
			<Icon name="lock" size={13} />
			<span>{message.content}</span>
		</span>
		<div class="system-line" aria-hidden="true"></div>
	</div>
{:else}
	<article
		class="message-row"
		class:own={isOwn}
		class:failed={message.status === 'failed'}
		class:highlighted={highlighted}
		class:popover-open={anyPopoverOpen}
		data-message-id={message.id}
		data-cluster={clusterPosition}
		aria-label={`${isOwn ? 'You' : displayName} at ${formatClockTime(message.timestamp)}`}
	>
		{#if !isOwn}
			<div class="avatar-slot">
				{#if showAvatar}
					<Avatar
						src={profile?.avatar ?? null}
						name={displayName}
						id={senderAccountDid || message.senderDid}
						size={32}
						shape="circle"
					/>
				{/if}
			</div>
		{/if}

		<div class="bubble-column">
			{#if showSenderName}
				<span class="sender-name">{displayName}</span>
			{/if}

			<div class="bubble-line">
				<div
					class="bubble"
					class:own={isOwn}
					class:has-image={Boolean(message.image)}
					class:failed={message.status === 'failed'}
					data-cluster={clusterPosition}
					use:attachContextMenu
				>
					{#if replyRef}
						<button
							type="button"
							class="reply-quote"
							onclick={() => jumpToMessage(replyRef.messageId)}
							aria-label={`Jump to quoted message from ${replySenderName}`}
						>
							<span class="reply-quote-sender">{replySenderName}</span>
							<span class="reply-quote-text">{replyPreviewText || 'Quoted message'}</span>
						</button>
					{/if}

					{#if message.image}
						<MessageImage image={message.image} fallbackAlt={rawContent || undefined} />
					{/if}

					{#if voiceAudio}
						<VoicePlayer audio={voiceAudio} isOwnMessage={isOwn} />
					{/if}

					{#if textSegments.length > 0}
						<div class="bubble-text">
							{#each textSegments as seg, idx (idx)}
								{#if seg.kind === 'link'}
									<a
										href={seg.href}
										target="_blank"
										rel="noopener noreferrer"
										class="bubble-link"
									>
										{seg.label}
									</a>
								{:else}
									{seg.value}
								{/if}
							{/each}
						</div>
					{/if}

					{#if blueskyUrl}
						<BlueskyEmbed url={blueskyUrl} inOwnBubble={isOwn} />
					{/if}

					{#if linkEmbed}
						<a
							class="link-card"
							href={linkEmbed.url}
							target="_blank"
							rel="noopener noreferrer"
						>
							{#if linkEmbed.title}
								<span class="link-card-title">{linkEmbed.title}</span>
							{/if}
							{#if linkEmbed.description}
								<span class="link-card-desc">{linkEmbed.description}</span>
							{/if}
							<span class="link-card-footer">
								<span class="link-card-domain">{linkEmbed.domain || linkEmbed.url}</span>
								<Icon name="external-link" size={14} />
							</span>
						</a>
					{/if}

					{#if gifEmbed}
						<video
							class="gif-embed"
							src={gifEmbed.mp4}
							title={gifEmbed.title}
							aria-label={gifEmbed.title}
							style={`aspect-ratio: ${gifEmbed.width} / ${gifEmbed.height};`}
							autoplay={!prefersReducedMotion}
							controls={prefersReducedMotion}
							loop
							muted
							playsinline
						></video>
					{/if}

					<div class="bubble-meta">
						<time class="bubble-time tabular-nums" datetime={message.timestamp}>
							{formatClockTime(message.timestamp)}
						</time>

						{#if isOwn}
							{#if message.status === 'sending'}
								<span class="delivery-sending">
									<span class="sending-dot" aria-hidden="true"></span>
									<span>Sending</span>
								</span>
							{:else if message.status === 'sent'}
								<span class="delivery-icon">
									<Icon name="check" size={14} label="Sent" />
								</span>
							{:else if message.status === 'delivered'}
								<span class="delivery-icon">
									<Icon name="check-double" size={14} label="Delivered" />
								</span>
							{:else if message.status === 'read'}
								<span class="delivery-icon read">
									<Icon name="check-double" size={14} label="Read" />
								</span>
							{/if}
						{/if}
					</div>
				</div>

				<div class="message-actions" role="group" aria-label="Message actions">
					{#if onReply}
						<button
							type="button"
							class="action-btn action-btn--secondary"
							onclick={handleReplyClick}
							aria-label="Reply to message"
							title="Reply"
						>
							<Icon name="reply" size={15} />
						</button>
					{/if}

					<button
						bind:this={reactTriggerEl}
						type="button"
						class="action-btn action-btn--secondary"
						popovertarget={reactPopoverId}
						style={`anchor-name: ${reactAnchorName};`}
						aria-label="Add reaction"
						title="Add reaction"
					>
						<Icon name="smile" size={15} />
					</button>
					<div
						bind:this={reactPopoverEl}
						id={reactPopoverId}
						popover="auto"
						class="catmos-popover quick-react-popover"
						data-anchored="true"
						data-placement={reactPlacement}
						style={`position-anchor: ${reactAnchorName};`}
						ontoggle={handleReactToggle}
						use:useRovingMenu={{ orientation: 'horizontal' }}
					>
						{#each QUICK_REACTION_EMOJIS as emoji (emoji)}
							{@const reacted = hasReacted(emoji)}
							<button
								type="button"
								class="quick-emoji-btn"
								aria-pressed={reacted}
								onclick={() => toggleQuickReaction(emoji)}
								aria-label={reacted ? `Remove ${emoji} reaction` : `React with ${emoji}`}
							>
								{emoji}
							</button>
						{/each}
					</div>

					<button
						bind:this={moreTriggerEl}
						type="button"
						class="action-btn action-btn--more"
						popovertarget={morePopoverId}
						onclick={handleMoreButtonClick}
						style={`anchor-name: ${moreAnchorName};`}
						aria-label="More message actions"
						title="More actions"
					>
						<Icon name="more-horizontal" size={15} />
					</button>
					<div
						bind:this={morePopoverEl}
						id={morePopoverId}
						popover="auto"
						class="catmos-popover more-menu-popover"
						data-anchored="true"
						data-placement={morePlacement}
						style={`position-anchor: ${moreAnchorName};`}
						ontoggle={handleMoreToggle}
						use:useRovingMenu={{ orientation: 'vertical' }}
					>
						<div class="more-quick-react" role="group" aria-label="Quick reactions">
							{#each QUICK_REACTION_EMOJIS as emoji (emoji)}
								{@const reacted = hasReacted(emoji)}
								<button
									type="button"
									class="more-emoji-btn"
									aria-pressed={reacted}
									onclick={() => toggleQuickReaction(emoji)}
									aria-label={reacted ? `Remove ${emoji} reaction` : `React with ${emoji}`}
								>
									{emoji}
								</button>
							{/each}
						</div>

						{#if onReply}
							<button type="button" class="popover-menu-btn" onclick={handleReplyClick}>
								<Icon name="reply" size={15} />
								<span>Reply</span>
							</button>
						{/if}

						{#if copyableText}
							<button type="button" class="popover-menu-btn" onclick={handleCopyText}>
								<Icon name="copy" size={15} />
								<span>Copy text</span>
							</button>
						{/if}

						{#if replyRef}
							<button
								type="button"
								class="popover-menu-btn"
								onclick={() => jumpToMessage(replyRef.messageId)}
							>
								<Icon name="arrow-down" size={15} />
								<span>Jump to quoted message</span>
							</button>
						{/if}

						{#if message.status === 'failed'}
							<button type="button" class="popover-menu-btn" onclick={handleRetry}>
								<Icon name="refresh" size={15} />
								<span>Retry send</span>
							</button>
							<button
								type="button"
								class="popover-menu-btn danger"
								onclick={handleRemoveFailed}
							>
								<Icon name="trash" size={15} />
								<span>Remove message</span>
							</button>
						{/if}
					</div>
				</div>
			</div>

			{#if message.status === 'failed'}
				<div class="failed-bar" role="alert">
					<span class="failed-label" title="Message could not be sent">
						<Icon name="alert-triangle" size={14} />
						<span>Not sent</span>
					</span>
					<button type="button" class="failed-action retry" onclick={handleRetry}>Retry</button>
					<button type="button" class="failed-action remove" onclick={handleRemoveFailed}>
						Remove
					</button>
				</div>
			{/if}

			{#if hasReactions}
				<Reactions
					reactions={foldedReactions}
					conversationId={message.conversationId}
					messageId={message.id}
					{isOwn}
					showAddTrigger={true}
				/>
			{/if}
		</div>
	</article>
{/if}

<style>
	/* System messages */
	.system-message {
		display: flex;
		align-items: center;
		gap: var(--space-3);
		padding-block: var(--space-3);
	}

	.system-line {
		flex: 1;
		block-size: 1px;
		background: var(--border);
	}

	.system-content {
		display: inline-flex;
		align-items: center;
		gap: var(--space-1);
		color: var(--text-muted);
		font-size: var(--text-sm);
		font-weight: 500;
		user-select: text;
	}

	/* Message row layout */
	.message-row {
		display: flex;
		align-items: flex-end;
		gap: var(--space-2);
		border-radius: var(--radius-md);
		padding-block: 1px;
		padding-inline: var(--space-1);
		transition: background-color var(--dur-normal) var(--ease-out);
	}

	.message-row.own {
		flex-direction: row-reverse;
	}

	.message-row.highlighted {
		background: var(--bg-selected);
	}

	.avatar-slot {
		inline-size: 2rem;
		flex-shrink: 0;
		display: flex;
		align-items: flex-end;
		justify-content: center;
	}

	.bubble-column {
		display: flex;
		flex-direction: column;
		align-items: flex-start;
		min-inline-size: 0;
		max-inline-size: min(62ch, 82%);
	}

	.message-row.own .bubble-column {
		align-items: flex-end;
	}

	.sender-name {
		font-size: var(--text-sm);
		font-weight: 600;
		line-height: 1.35;
		color: var(--text-secondary);
		margin-block-end: 2px;
		margin-inline-start: var(--space-3);
	}

	.bubble-line {
		display: flex;
		align-items: flex-end;
		gap: var(--space-1);
		max-inline-size: 100%;
		min-inline-size: 0;
	}

	.message-row.own .bubble-line {
		flex-direction: row-reverse;
	}

	/* Signature Catbird bubble geometry */
	.bubble {
		padding-block: var(--density-bubble-py);
		padding-inline: var(--density-bubble-px);
		background: var(--bg-bubble-other);
		color: var(--text-primary);
		border-radius: var(--radius-lg);
		word-break: break-word;
		min-inline-size: 0;
		max-inline-size: 100%;
	}

	.bubble:not(.own)[data-cluster='single'] {
		border-radius: var(--radius-lg) var(--radius-lg) var(--radius-lg) var(--radius-xs);
	}

	.bubble:not(.own)[data-cluster='first'] {
		border-radius: var(--radius-lg) var(--radius-lg) var(--radius-lg) var(--radius-sm);
	}

	.bubble:not(.own)[data-cluster='middle'] {
		border-radius: var(--radius-sm) var(--radius-lg) var(--radius-lg) var(--radius-sm);
	}

	.bubble:not(.own)[data-cluster='last'] {
		border-radius: var(--radius-sm) var(--radius-lg) var(--radius-lg) var(--radius-xs);
	}

	.bubble.own {
		background: var(--bubble-own-bg);
		color: var(--text-on-bubble-own);
	}

	.bubble.own[data-cluster='single'] {
		border-radius: var(--radius-lg) var(--radius-lg) var(--radius-xs) var(--radius-lg);
	}

	.bubble.own[data-cluster='first'] {
		border-radius: var(--radius-lg) var(--radius-lg) var(--radius-sm) var(--radius-lg);
	}

	.bubble.own[data-cluster='middle'] {
		border-radius: var(--radius-lg) var(--radius-sm) var(--radius-sm) var(--radius-lg);
	}

	.bubble.own[data-cluster='last'] {
		border-radius: var(--radius-lg) var(--radius-sm) var(--radius-xs) var(--radius-lg);
	}

	.bubble.has-image {
		inline-size: min(calc(26.25rem + 2 * var(--density-bubble-px)), 100%);
		max-inline-size: min(calc(26.25rem + 2 * var(--density-bubble-px)), 100%);
	}

	.bubble.failed {
		outline: 1.5px solid var(--danger);
		outline-offset: 1px;
	}

	.bubble-text {
		font-size: var(--text-body);
		line-height: 1.48;
		white-space: pre-wrap;
		text-wrap: pretty;
		user-select: text;
	}

	.bubble-link {
		color: var(--text-link);
		text-decoration: underline;
		text-underline-offset: 2px;
		word-break: break-all;
	}

	.bubble.own .bubble-link {
		color: var(--text-on-bubble-own);
	}

	/* Hydrated external link card embed */
	.link-card {
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
		margin-block-start: var(--space-2);
		padding-block: var(--space-2);
		padding-inline: var(--space-3);
		background: color-mix(in oklab, var(--bg-app) 55%, transparent);
		border: 1px solid var(--border);
		border-radius: var(--radius-md);
		color: var(--text-primary);
		text-decoration: none;
		max-inline-size: min(22rem, 100%);
		transition:
			background-color var(--dur-fast) var(--ease-out),
			border-color var(--dur-fast) var(--ease-out);
	}

	.link-card:hover {
		background: color-mix(in oklab, var(--bg-app) 78%, transparent);
		border-color: var(--border-strong);
		text-decoration: none;
	}

	.bubble.own .link-card {
		background: rgba(255, 255, 255, 0.14);
		border-color: rgba(255, 255, 255, 0.24);
		color: var(--text-on-bubble-own);
	}

	.bubble.own .link-card:hover {
		background: rgba(255, 255, 255, 0.22);
		border-color: rgba(255, 255, 255, 0.36);
	}

	.link-card-title {
		font-size: var(--text-body);
		font-weight: 600;
		line-height: 1.35;
		color: var(--text-primary);
		display: -webkit-box;
		-webkit-line-clamp: 2;
		line-clamp: 2;
		-webkit-box-orient: vertical;
		overflow: hidden;
	}

	.link-card-desc {
		font-size: var(--text-sm);
		line-height: 1.42;
		color: var(--text-secondary);
		display: -webkit-box;
		-webkit-line-clamp: 2;
		line-clamp: 2;
		-webkit-box-orient: vertical;
		overflow: hidden;
	}

	.link-card-footer {
		display: inline-flex;
		align-items: center;
		gap: var(--space-1);
		margin-block-start: 2px;
		font-size: var(--text-sm);
		font-weight: 500;
		color: var(--text-link);
		min-inline-size: 0;
	}

	.link-card-domain {
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.bubble.own .link-card-title,
	.bubble.own .link-card-footer {
		color: var(--text-on-bubble-own);
	}

	.bubble.own .link-card-desc {
		color: var(--text-on-bubble-own-muted);
	}

	/* Hydrated GIF video embed */
	.gif-embed {
		display: block;
		inline-size: 100%;
		max-inline-size: min(20rem, 100%);
		max-block-size: 20rem;
		border-radius: var(--radius-md);
		margin-block-start: var(--space-2);
		object-fit: cover;
		background: var(--bg-surface);
	}

	/* Quoted reply inside bubble */
	.reply-quote {
		display: flex;
		flex-direction: column;
		gap: 2px;
		inline-size: 100%;
		padding-block: var(--space-1);
		padding-inline: var(--space-2);
		margin-block-end: var(--space-2);
		background: color-mix(in oklab, var(--bg-app) 45%, transparent);
		border-inline-start: 3px solid var(--accent-fill);
		border-radius: 0 var(--radius-xs) var(--radius-xs) 0;
		text-align: start;
		transition: background-color var(--dur-fast) var(--ease-out);
	}

	.reply-quote:hover {
		background: color-mix(in oklab, var(--bg-app) 68%, transparent);
	}

	.bubble.own .reply-quote {
		background: rgba(255, 255, 255, 0.16);
		border-inline-start-color: var(--text-on-bubble-own);
	}

	.bubble.own .reply-quote:hover {
		background: rgba(255, 255, 255, 0.24);
	}

	.reply-quote-sender {
		font-size: var(--text-sm);
		font-weight: 600;
		line-height: 1.3;
		color: var(--text-link);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.bubble.own .reply-quote-sender {
		color: var(--text-on-bubble-own);
	}

	.reply-quote-text {
		font-size: var(--text-sm);
		line-height: 1.35;
		color: var(--text-secondary);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
		max-inline-size: 28rem;
		user-select: text;
	}

	.bubble.own .reply-quote-text {
		color: var(--text-on-bubble-own-muted);
	}

	/* Timestamp and delivery receipts (AA contrast, never opacity: 0.6) */
	.bubble-meta {
		display: flex;
		align-items: center;
		justify-content: flex-end;
		gap: var(--space-1);
		margin-block-start: var(--space-1);
	}

	.bubble-time {
		font-size: var(--text-sm);
		line-height: 1.25;
		color: var(--text-muted);
	}

	.bubble.own .bubble-time {
		color: var(--text-on-bubble-own-muted);
	}

	.delivery-sending {
		display: inline-flex;
		align-items: center;
		gap: 0.25rem;
		font-size: var(--text-sm);
		color: var(--text-on-bubble-own-muted);
	}

	.sending-dot {
		inline-size: 0.375rem;
		block-size: 0.375rem;
		border-radius: var(--radius-full);
		background: var(--text-on-bubble-own);
	}

	@media (prefers-reduced-motion: no-preference) {
		.sending-dot {
			animation: sending-pulse 1.2s ease-in-out infinite;
		}
	}

	@keyframes sending-pulse {
		0%,
		100% {
			opacity: 0.45;
		}
		50% {
			opacity: 1;
		}
	}

	.delivery-icon {
		display: inline-flex;
		align-items: center;
		color: var(--text-on-bubble-own-muted);
	}

	.delivery-icon.read {
		color: var(--text-on-bubble-own);
	}

	/* Discoverable accessible message action bar */
	.message-actions {
		display: inline-flex;
		align-items: center;
		gap: 2px;
		flex-shrink: 0;
	}

	.action-btn {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		min-inline-size: max(1.875rem, var(--touch-min));
		min-block-size: max(1.875rem, var(--touch-min));
		border-radius: var(--radius-full);
		color: var(--text-secondary);
		transition:
			background-color var(--dur-fast) var(--ease-out),
			color var(--dur-fast) var(--ease-out),
			opacity var(--dur-fast) var(--ease-out);
	}

	.action-btn--secondary {
		opacity: 0.35;
	}

	.action-btn--more {
		opacity: 0.65;
	}

	.message-row:hover .action-btn--secondary,
	.message-row:focus-within .action-btn--secondary,
	.message-row.popover-open .action-btn--secondary,
	.message-row:hover .action-btn--more,
	.message-row:focus-within .action-btn--more,
	.message-row.popover-open .action-btn--more {
		opacity: 1;
	}

	@media (pointer: coarse), (hover: none) {
		.action-btn--secondary,
		.action-btn--more {
			opacity: 1;
		}
	}

	.action-btn:hover {
		background: var(--bg-hover);
		color: var(--text-primary);
	}

	.action-btn:active {
		background: var(--bg-active);
	}

	/* Quick emoji popover */
	.quick-react-popover {
		min-inline-size: auto;
		padding: var(--space-1);
		border-radius: var(--radius-full);
	}

	.quick-react-popover:popover-open {
		display: flex;
		align-items: center;
		gap: 2px;
	}

	.quick-emoji-btn {
		min-inline-size: max(2.25rem, var(--touch-min));
		min-block-size: max(2.25rem, var(--touch-min));
		border-radius: var(--radius-full);
		font-size: 1.125rem;
		line-height: 1;
		display: inline-flex;
		align-items: center;
		justify-content: center;
		transition: background-color var(--dur-fast) var(--ease-out);
	}

	@media (prefers-reduced-motion: no-preference) {
		.quick-emoji-btn {
			transition:
				background-color var(--dur-fast) var(--ease-out),
				transform var(--dur-fast) var(--ease-out);
		}

		.quick-emoji-btn:hover {
			transform: scale(1.12);
		}
	}

	.quick-emoji-btn:hover {
		background: var(--bg-hover);
	}

	.quick-emoji-btn[aria-pressed='true'] {
		background: var(--bg-selected);
	}

	/* More actions popover */
	.more-menu-popover:popover-open {
		display: flex;
		flex-direction: column;
		gap: 2px;
	}

	.more-quick-react {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 2px;
		padding-block-end: var(--space-1);
		margin-block-end: var(--space-1);
		border-block-end: 1px solid var(--border);
	}

	.more-emoji-btn {
		min-inline-size: max(2rem, var(--touch-min));
		min-block-size: max(2rem, var(--touch-min));
		border-radius: var(--radius-full);
		font-size: 1.0625rem;
		line-height: 1;
		display: inline-flex;
		align-items: center;
		justify-content: center;
		transition: background-color var(--dur-fast) var(--ease-out);
	}

	.more-emoji-btn:hover {
		background: var(--bg-hover);
	}

	.more-emoji-btn[aria-pressed='true'] {
		background: var(--bg-selected);
	}

	.popover-menu-btn {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		inline-size: 100%;
		min-block-size: max(2.25rem, var(--touch-min));
		padding-block: var(--space-1);
		padding-inline: var(--space-3);
		border-radius: var(--radius-xs);
		font-size: var(--text-sm);
		font-weight: 500;
		color: var(--text-primary);
		text-align: start;
		transition: background-color var(--dur-fast) var(--ease-out);
	}

	.popover-menu-btn:hover {
		background: var(--bg-hover);
	}

	.popover-menu-btn.danger {
		color: var(--danger-text);
	}

	/* Failed message inline recovery bar */
	.failed-bar {
		display: inline-flex;
		align-items: center;
		flex-wrap: wrap;
		gap: var(--space-2);
		margin-block-start: var(--space-1);
		font-size: var(--text-sm);
	}

	.failed-label {
		display: inline-flex;
		align-items: center;
		gap: 0.25rem;
		font-weight: 600;
		color: var(--danger-text);
	}

	.failed-action {
		font-size: var(--text-sm);
		font-weight: 600;
		min-block-size: max(1.75rem, var(--touch-min));
		padding-inline: var(--space-2);
		border-radius: var(--radius-xs);
		transition: background-color var(--dur-fast) var(--ease-out);
	}

	.failed-action.retry {
		color: var(--text-link);
	}

	.failed-action.retry:hover {
		background: var(--bg-hover);
		text-decoration: underline;
	}

	.failed-action.remove {
		color: var(--danger-text);
	}

	.failed-action.remove:hover {
		background: var(--danger-bg);
	}

	@media (max-width: 767px) {
		.bubble-column {
			max-inline-size: 88%;
		}
	}

	@media (max-width: 520px) {
		.bubble-column {
			max-inline-size: 92%;
		}

		.action-btn--secondary {
			display: none;
		}
	}
</style>

<script lang="ts">
	import { onDestroy, tick } from 'svelte';
	import type { Conversation, Message } from '#lib/wasm.ts';
	import { dedupeAccountDids, isSameAccountDid, stripDidFragment } from '#lib/did.ts';
	import { auth } from '#lib/stores/auth.ts';
	import { messages } from '#lib/stores/messages.ts';
	import { profiles, resolveProfileName } from '#lib/stores/profiles.ts';
	import { formatDayDivider, isSameCalendarDay } from '#lib/utils/time.ts';
	import Avatar from './Avatar.svelte';
	import Icon from './Icon.svelte';
	import MessageBubble, { type ClusterPosition } from './MessageBubble.svelte';

	const CLUSTER_GAP_MS = 5 * 60 * 1000;
	const MAX_CLUSTER_SIZE = 5;
	const NEAR_BOTTOM_THRESHOLD_PX = 96;
	const ABOVE_THE_FOLD_COUNT = 25;

	let {
		conversation,
		highlightMessageId = null,
		onReply
	}: {
		conversation: Conversation;
		highlightMessageId?: string | null;
		onReply: (message: Message) => void;
	} = $props();

	interface RenderedRow {
		message: Message;
		clusterPosition: ClusterPosition;
		startsNewGroup: boolean;
		showDayDivider: boolean;
		dayLabel: string;
		showUnreadDivider: boolean;
		deferRendering: boolean;
	}

	let scrollContainer: HTMLDivElement | undefined = $state();
	let bottomSentinelEl: HTMLDivElement | undefined = $state();
	let jumpBtnEl: HTMLButtonElement | undefined = $state();

	let isNearBottom = $state(true);
	let pendingNewCount = $state(0);
	let unreadDividerMessageId = $state<string | null>(null);
	let activeHighlightId = $state<string | null>(null);

	let prevConvoId: string | null = null;
	let prevTailId: string | null = null;
	let prevCount = 0;
	let didInitialScroll = false;
	let pendingUnreadSnapshot = 0;
	let isPrepending = false;
	let wasJumpFocused = false;
	let highlightTimer: ReturnType<typeof setTimeout> | null = null;

	let list = $derived($messages.byConversation.get(conversation.id) ?? []);
	let typingUsers = $derived(
		dedupeAccountDids(
			($messages.typingByConversation.get(conversation.id) ?? []).filter(
				(did) => !isSameAccountDid(did, $auth.user?.did)
			)
		)
	);
	let hasMore = $derived($messages.hasMoreByConversation.get(conversation.id) ?? false);
	let loadingOlder = $derived($messages.loadingOlderByConversation.get(conversation.id) ?? false);
	let errorMsg = $derived($messages.errorByConversation.get(conversation.id) ?? null);
	let isInitialLoading = $derived($messages.loading && list.length === 0);

	let showJumpButton = $derived(list.length > 0 && (!isNearBottom || pendingNewCount > 0));

	let jumpLabel = $derived.by(() => {
		if (pendingNewCount === 1) return '1 new message';
		if (pendingNewCount > 1) return `${pendingNewCount} new messages`;
		return 'Jump to latest';
	});

	// Empty state identity (DM vs Group)
	let otherDid = $derived.by(() => {
		if (conversation.isGroup) return null;
		const myDid = $auth.user?.did;
		const raw =
			conversation.members.find((did) => !isSameAccountDid(did, myDid)) ??
			conversation.members[0] ??
			null;
		const bare = stripDidFragment(raw);
		return bare || null;
	});

	$effect(() => {
		if (otherDid) {
			profiles.resolveProfiles([otherDid]);
		}
	});

	let otherProfile = $derived(otherDid ? $profiles.cache.get(otherDid) : undefined);

	let conversationTitle = $derived.by(() => {
		if (conversation.isGroup) {
			return conversation.displayName.trim() || 'Group conversation';
		}
		if (otherDid) {
			if (otherProfile) return resolveProfileName($profiles.cache, otherDid);
			if (conversation.displayName && !conversation.displayName.startsWith('did:')) {
				return conversation.displayName;
			}
			return resolveProfileName($profiles.cache, otherDid);
		}
		return conversation.displayName || 'Conversation';
	});

	let conversationAvatar = $derived.by(() => {
		if (conversation.isGroup) return conversation.avatarDataUrl ?? null;
		return otherProfile?.avatar ?? conversation.avatarDataUrl ?? null;
	});

	// Resolve profiles for typing users
	$effect(() => {
		if (typingUsers.length > 0) {
			profiles.resolveProfiles(typingUsers);
		}
	});

	let typingLabel = $derived.by(() => {
		if (typingUsers.length === 0) return '';
		const names = typingUsers.map((did) => resolveProfileName($profiles.cache, did));
		if (names.length === 1) return `${names[0]} is typing`;
		if (names.length === 2) return `${names[0]} and ${names[1]} are typing`;
		return `${names[0]} and ${names.length - 1} others are typing`;
	});

	function isSystemMessage(msg: Message): boolean {
		return msg.messageType === 'system' || msg.messageType === 'event';
	}

	function canClusterTogether(a: Message, b: Message): boolean {
		if (isSystemMessage(a) || isSystemMessage(b)) return false;
		if (!a.senderDid || !b.senderDid || !isSameAccountDid(a.senderDid, b.senderDid)) return false;
		if (!isSameCalendarDay(a.timestamp, b.timestamp)) return false;
		if (b.id === unreadDividerMessageId) return false;
		const timeA = Date.parse(a.timestamp);
		const timeB = Date.parse(b.timestamp);
		if (!Number.isFinite(timeA) || !Number.isFinite(timeB)) return false;
		return Math.abs(timeB - timeA) <= CLUSTER_GAP_MS;
	}

	let renderedRows = $derived.by<RenderedRow[]>(() => {
		const total = list.length;
		if (total === 0) return [];

		// Partition into clusters of at most MAX_CLUSTER_SIZE consecutive messages
		const clusterIndices: number[][] = [];
		for (let i = 0; i < total; i += 1) {
			const msg = list[i];
			const currentCluster = clusterIndices[clusterIndices.length - 1];
			if (
				currentCluster &&
				currentCluster.length < MAX_CLUSTER_SIZE &&
				canClusterTogether(list[currentCluster[currentCluster.length - 1]], msg)
			) {
				currentCluster.push(i);
			} else {
				clusterIndices.push([i]);
			}
		}

		const positionByIndex = new Array<ClusterPosition>(total).fill('single');
		const groupStartByIndex = new Array<boolean>(total).fill(false);

		for (const cluster of clusterIndices) {
			groupStartByIndex[cluster[0]] = true;
			if (cluster.length === 1) {
				positionByIndex[cluster[0]] = 'single';
			} else {
				positionByIndex[cluster[0]] = 'first';
				for (let k = 1; k < cluster.length - 1; k += 1) {
					positionByIndex[cluster[k]] = 'middle';
				}
				positionByIndex[cluster[cluster.length - 1]] = 'last';
			}
		}

		const deferCutoff = total - ABOVE_THE_FOLD_COUNT;

		return list.map((msg, i) => {
			const prev = i > 0 ? list[i - 1] : null;
			const showDayDivider = i === 0 || !isSameCalendarDay(prev?.timestamp, msg.timestamp);
			const showUnreadDivider = unreadDividerMessageId === msg.id;

			return {
				message: msg,
				clusterPosition: positionByIndex[i],
				startsNewGroup: i > 0 && groupStartByIndex[i],
				showDayDivider,
				dayLabel: showDayDivider ? formatDayDivider(msg.timestamp) : '',
				showUnreadDivider,
				deferRendering: i < deferCutoff
			};
		});
	});

	function prefersReducedMotion(): boolean {
		return (
			typeof window !== 'undefined' &&
			typeof window.matchMedia === 'function' &&
			window.matchMedia('(prefers-reduced-motion: reduce)').matches
		);
	}

	function measureNearBottom(): boolean {
		if (!scrollContainer) return true;
		const distance =
			scrollContainer.scrollHeight - scrollContainer.scrollTop - scrollContainer.clientHeight;
		return distance < NEAR_BOTTOM_THRESHOLD_PX;
	}

	function handleScroll() {
		const near = measureNearBottom();
		isNearBottom = near;
		if (near && pendingNewCount > 0) {
			pendingNewCount = 0;
		}
	}

	async function scrollToBottom(instant = false) {
		await tick();
		if (!scrollContainer) return;
		const behavior: ScrollBehavior = instant || prefersReducedMotion() ? 'auto' : 'smooth';
		if (typeof scrollContainer.scrollTo === 'function') {
			scrollContainer.scrollTo({ top: scrollContainer.scrollHeight, behavior });
		} else {
			scrollContainer.scrollTop = scrollContainer.scrollHeight;
		}
		isNearBottom = true;
		pendingNewCount = 0;
	}

	async function scrollToMessageById(targetId: string) {
		if (!targetId) return;
		await tick();
		if (!scrollContainer) return;
		const escaped =
			typeof CSS !== 'undefined' && typeof CSS.escape === 'function'
				? CSS.escape(targetId)
				: targetId.replace(/"/g, '\\"');
		const el = scrollContainer.querySelector<HTMLElement>(`[data-message-id="${escaped}"]`);
		if (!el) return;
		el.scrollIntoView({
			behavior: prefersReducedMotion() ? 'auto' : 'smooth',
			block: 'center'
		});
		activeHighlightId = targetId;
		if (highlightTimer !== null) {
			clearTimeout(highlightTimer);
		}
		highlightTimer = setTimeout(() => {
			if (activeHighlightId === targetId) {
				activeHighlightId = null;
			}
			highlightTimer = null;
		}, 2000);
	}

	// Bottom sentinel IntersectionObserver keeps near-bottom accurate alongside onscroll
	$effect(() => {
		const container = scrollContainer;
		const sentinel = bottomSentinelEl;
		if (!container || !sentinel || typeof IntersectionObserver === 'undefined') return;

		const observer = new IntersectionObserver(
			(entries) => {
				const entry = entries[0];
				if (!entry) return;
				const near = entry.isIntersecting || measureNearBottom();
				isNearBottom = near;
				if (near && pendingNewCount > 0) {
					pendingNewCount = 0;
				}
			},
			{
				root: container,
				rootMargin: `0px 0px ${NEAR_BOTTOM_THRESHOLD_PX}px 0px`,
				threshold: 0
			}
		);
		observer.observe(sentinel);
		return () => observer.disconnect();
	});

	// Reset scroll & unread snapshot on conversation switch
	$effect(() => {
		const convoId = conversation.id;
		const initialUnread = conversation.unreadCount;
		if (convoId !== prevConvoId) {
			prevConvoId = convoId;
			prevTailId = null;
			prevCount = 0;
			didInitialScroll = false;
			pendingNewCount = 0;
			isNearBottom = true;
			unreadDividerMessageId = null;
			pendingUnreadSnapshot = initialUnread > 0 ? initialUnread : 0;
		}
	});

	// Smart auto-scroll when messages arrive (never hijack when reading older messages)
	$effect(() => {
		const currentList = list;
		const myDid = $auth.user?.did;
		const currentHighlight = highlightMessageId;

		if (currentList.length === 0) {
			prevCount = 0;
			prevTailId = null;
			return;
		}

		if (pendingUnreadSnapshot > 0 && !unreadDividerMessageId) {
			const firstUnreadIndex = Math.max(0, currentList.length - pendingUnreadSnapshot);
			unreadDividerMessageId = currentList[firstUnreadIndex]?.id ?? null;
			pendingUnreadSnapshot = 0;
		}

		const tail = currentList[currentList.length - 1];

		if (!didInitialScroll) {
			didInitialScroll = true;
			prevCount = currentList.length;
			prevTailId = tail.id;
			if (currentHighlight && currentList.some((m) => m.id === currentHighlight)) {
				void scrollToMessageById(currentHighlight);
			} else {
				void scrollToBottom(true);
			}
			return;
		}

		if (isPrepending) {
			prevCount = currentList.length;
			prevTailId = tail.id;
			return;
		}

		if (tail.id !== prevTailId) {
			const prevTailIdx = prevTailId ? currentList.findIndex((m) => m.id === prevTailId) : -1;
			const appendedCount =
				prevTailIdx >= 0
					? currentList.length - 1 - prevTailIdx
					: Math.max(1, currentList.length - prevCount);
			const isOwnTail = Boolean(tail.isOwn) || isSameAccountDid(tail.senderDid, myDid);

			prevCount = currentList.length;
			prevTailId = tail.id;

			if (isNearBottom || isOwnTail) {
				pendingNewCount = 0;
				void scrollToBottom(false);
			} else if (appendedCount > 0) {
				pendingNewCount += appendedCount;
			}
		} else {
			prevCount = currentList.length;
		}
	});

	// Scroll to highlighted message when requested (e.g. from CommandPalette search)
	$effect(() => {
		const target = highlightMessageId;
		if (!target) return;
		if (list.some((m) => m.id === target)) {
			void scrollToMessageById(target);
		}
	});

	// Focus guard: when the jump-to-latest button disappears while focused, return focus to the log
	$effect(() => {
		const visible = showJumpButton;
		if (!visible && wasJumpFocused) {
			wasJumpFocused = false;
			scrollContainer?.focus({ preventScroll: true });
		}
	});

	function handleJumpClick() {
		wasJumpFocused = false;
		void scrollToBottom(false);
		scrollContainer?.focus({ preventScroll: true });
	}

	function handleJumpFocusIn() {
		wasJumpFocused = true;
	}

	function handleJumpFocusOut(event: FocusEvent) {
		const nextTarget = event.relatedTarget as Node | null;
		if (!nextTarget && !showJumpButton) {
			scrollContainer?.focus({ preventScroll: true });
		}
		wasJumpFocused = false;
	}

	async function handleLoadOlder() {
		if (!scrollContainer || loadingOlder) return;
		const prevScrollHeight = scrollContainer.scrollHeight;
		const prevScrollTop = scrollContainer.scrollTop;
		isPrepending = true;
		try {
			const added = await messages.loadOlder(conversation.id);
			if (added > 0) {
				await tick();
				if (scrollContainer) {
					const heightDelta = scrollContainer.scrollHeight - prevScrollHeight;
					scrollContainer.scrollTop = prevScrollTop + heightDelta;
				}
			}
		} finally {
			isPrepending = false;
		}
	}

	function handleRetryLoad() {
		void messages.load(conversation.id);
	}

	onDestroy(() => {
		if (highlightTimer !== null) {
			clearTimeout(highlightTimer);
			highlightTimer = null;
		}
	});
</script>

<div class="message-list-shell">
	<div
		bind:this={scrollContainer}
		class="message-list"
		role="log"
		aria-label="Messages"
		aria-relevant="additions text"
		tabindex="-1"
		onscroll={handleScroll}
	>
		{#if errorMsg}
			<div class="list-error" role="alert">
				<Icon name="alert-triangle" size={16} />
				<span class="list-error-text">{errorMsg}</span>
				<button type="button" class="catmos-btn-secondary retry-load-btn" onclick={handleRetryLoad}>
					Retry
				</button>
			</div>
		{/if}

		{#if isInitialLoading}
			<div class="loading-thread">
				<progress class="catmos-progress" aria-label="Loading messages"></progress>
				<span class="loading-label">Loading messages</span>
			</div>
		{:else if list.length === 0 && !errorMsg}
			<div class="empty-thread">
				<Avatar
					src={conversationAvatar}
					name={conversationTitle}
					id={otherDid ?? conversation.id}
					size={56}
					shape={conversation.isGroup ? 'squircle' : 'circle'}
				/>
				<h2 class="empty-title">{conversationTitle}</h2>
				<p class="empty-encryption">
					<Icon name="shield" size={16} class="empty-shield" />
					<span>
						Messages in this chat are end-to-end encrypted with MLS. Only members here can read
						them.
					</span>
				</p>
			</div>
		{:else if list.length > 0}
			<div class="messages-inner">
				{#if hasMore}
					<div class="load-older-row">
						<button
							type="button"
							class="load-older-btn"
							onclick={handleLoadOlder}
							disabled={loadingOlder}
						>
							{#if loadingOlder}
								<progress class="catmos-progress older-progress" aria-label="Loading earlier messages"></progress>
								<span>Loading earlier messages</span>
							{:else}
								<span>Load earlier messages</span>
							{/if}
						</button>
					</div>
				{/if}

				{#each renderedRows as row (row.message.id)}
					{#if row.showDayDivider && row.dayLabel}
						<div class="day-divider" role="separator" aria-label={row.dayLabel}>
							<span class="divider-line" aria-hidden="true"></span>
							<span class="divider-label tabular-nums">{row.dayLabel}</span>
							<span class="divider-line" aria-hidden="true"></span>
						</div>
					{/if}

					{#if row.showUnreadDivider}
						<div class="unread-divider" role="separator" aria-label="New messages">
							<span class="unread-line" aria-hidden="true"></span>
							<span class="unread-label">New messages</span>
							<span class="unread-line" aria-hidden="true"></span>
						</div>
					{/if}

					<div
						class="message-slot"
						class:group-gap={row.startsNewGroup && !row.showDayDivider && !row.showUnreadDivider}
						class:older-row={row.deferRendering}
					>
						<MessageBubble
							message={row.message}
							clusterPosition={row.clusterPosition}
							isGroup={conversation.isGroup}
							highlighted={activeHighlightId === row.message.id}
							{onReply}
							onJumpToMessage={(id) => void scrollToMessageById(id)}
						/>
					</div>
				{/each}
			</div>
		{/if}

		{#if typingUsers.length > 0}
			<div class="typing-indicator" role="status" aria-live="polite">
				<div class="typing-dots" aria-hidden="true">
					<span class="dot"></span>
					<span class="dot"></span>
					<span class="dot"></span>
				</div>
				<span class="typing-text">{typingLabel}</span>
			</div>
		{/if}

		<div bind:this={bottomSentinelEl} class="bottom-sentinel" aria-hidden="true"></div>
	</div>

	{#if showJumpButton}
		<button
			bind:this={jumpBtnEl}
			type="button"
			class="jump-latest-btn"
			class:has-unread={pendingNewCount > 0}
			onclick={handleJumpClick}
			onfocusin={handleJumpFocusIn}
			onfocusout={handleJumpFocusOut}
			aria-label={jumpLabel}
		>
			<Icon name="arrow-down" size={16} />
			<span class="tabular-nums">{jumpLabel}</span>
		</button>
	{/if}
</div>

<style>
	.message-list-shell {
		position: relative;
		flex: 1;
		min-block-size: 0;
		min-inline-size: 0;
		display: flex;
		flex-direction: column;
	}

	.message-list {
		flex: 1;
		overflow-y: auto;
		overflow-x: hidden;
		padding-block-start: var(--space-4);
		padding-block-end: var(--space-3);
		padding-inline: var(--space-5);
		scroll-padding-bottom: 4.5rem;
		display: flex;
		flex-direction: column;
		outline: none;
	}

	.message-list:focus-visible {
		outline: 2px solid var(--focus-ring);
		outline-offset: -2px;
	}

	.list-error {
		display: flex;
		align-items: center;
		gap: var(--space-3);
		padding-block: var(--space-3);
		padding-inline: var(--space-4);
		margin-block-end: var(--space-3);
		border-radius: var(--radius-md);
		background: var(--danger-bg);
		border: 1px solid var(--danger);
		color: var(--danger-text);
		font-size: var(--text-sm);
	}

	.list-error-text {
		flex: 1;
		min-inline-size: 0;
		user-select: text;
	}

	.retry-load-btn {
		flex-shrink: 0;
		min-block-size: max(2rem, var(--touch-min));
		padding-inline: var(--space-3);
		font-size: var(--text-sm);
	}

	.loading-thread {
		flex: 1;
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
		gap: var(--space-3);
		padding: var(--space-8);
		color: var(--text-secondary);
	}

	.loading-label {
		font-size: var(--text-sm);
	}

	/* Calm empty thread state */
	.empty-thread {
		flex: 1;
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
		gap: var(--space-3);
		padding: var(--space-8);
		text-align: center;
		max-inline-size: 26rem;
		margin-inline: auto;
	}

	.empty-title {
		font-size: var(--text-heading);
		font-weight: 650;
		letter-spacing: -0.015em;
		color: var(--text-primary);
		text-wrap: balance;
	}

	.empty-encryption {
		display: inline-flex;
		align-items: flex-start;
		justify-content: center;
		gap: var(--space-2);
		font-size: var(--text-sm);
		line-height: 1.48;
		color: var(--text-secondary);
		max-inline-size: 42ch;
		text-wrap: pretty;
	}

	.empty-encryption :global(.empty-shield) {
		color: var(--shield);
		margin-block-start: 2px;
	}

	/* Message stream */
	.messages-inner {
		display: flex;
		flex-direction: column;
		gap: var(--density-cluster-gap);
		margin-block-start: auto;
		padding-block-end: 3.5rem;
	}

	.load-older-row {
		display: flex;
		justify-content: center;
		padding-block: var(--space-2);
		margin-block-end: var(--space-2);
	}

	.load-older-btn {
		display: inline-flex;
		align-items: center;
		gap: var(--space-2);
		min-block-size: max(2.125rem, var(--touch-min));
		padding-block: var(--space-1);
		padding-inline: var(--space-4);
		border-radius: var(--radius-full);
		background: var(--bg-surface);
		border: 1px solid var(--border);
		color: var(--text-secondary);
		font-size: var(--text-sm);
		font-weight: 600;
		transition:
			background-color var(--dur-fast) var(--ease-out),
			border-color var(--dur-fast) var(--ease-out),
			color var(--dur-fast) var(--ease-out);
	}

	.load-older-btn:hover:not(:disabled) {
		background: var(--bg-hover);
		border-color: var(--border-strong);
		color: var(--text-primary);
	}

	.load-older-btn:disabled {
		opacity: 0.7;
		cursor: default;
	}

	.older-progress {
		inline-size: 0.9375rem;
		block-size: 0.9375rem;
		border-width: 2px;
	}

	/* Day and unread dividers */
	.day-divider,
	.unread-divider {
		display: flex;
		align-items: center;
		gap: var(--space-3);
		padding-block: var(--space-3);
	}

	.divider-line {
		flex: 1;
		block-size: 1px;
		background: var(--border);
	}

	.divider-label {
		font-size: var(--text-sm);
		font-weight: 500;
		color: var(--text-muted);
		flex-shrink: 0;
	}

	.unread-line {
		flex: 1;
		block-size: 1px;
		background: var(--accent-fill);
	}

	.unread-label {
		font-size: var(--text-sm);
		font-weight: 600;
		color: var(--text-link);
		flex-shrink: 0;
	}

	.message-slot.group-gap {
		margin-block-start: calc(var(--density-group-gap) - var(--density-cluster-gap));
	}

	/* Off-screen rendering deferral ONLY on older messages (index < list.length - 25) */
	.message-slot.older-row {
		content-visibility: auto;
		contain-intrinsic-size: auto none auto 72px;
	}

	/* Typing indicator */
	.typing-indicator {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		padding-block: var(--space-2);
		padding-inline: var(--space-3);
	}

	.typing-dots {
		display: inline-flex;
		align-items: center;
		gap: 3px;
	}

	.dot {
		inline-size: 5px;
		block-size: 5px;
		border-radius: var(--radius-full);
		background: var(--text-muted);
	}

	@media (prefers-reduced-motion: no-preference) {
		.dot {
			animation: typing-bounce 1.4s ease-in-out infinite;
		}

		.dot:nth-child(2) {
			animation-delay: 0.2s;
		}

		.dot:nth-child(3) {
			animation-delay: 0.4s;
		}
	}

	@keyframes typing-bounce {
		0%,
		60%,
		100% {
			transform: translateY(0);
			opacity: 0.45;
		}
		30% {
			transform: translateY(-4px);
			opacity: 1;
		}
	}

	.typing-text {
		font-size: var(--text-sm);
		color: var(--text-muted);
	}

	.bottom-sentinel {
		block-size: 1px;
		inline-size: 100%;
		flex-shrink: 0;
	}

	/* Floating scroll-to-latest pill */
	.jump-latest-btn {
		position: absolute;
		inset-block-end: var(--space-4);
		inset-inline-end: var(--space-5);
		z-index: 4;
		display: inline-flex;
		align-items: center;
		gap: var(--space-2);
		min-block-size: max(2.25rem, var(--touch-min));
		padding-block: var(--space-1);
		padding-inline: var(--space-4);
		border-radius: var(--radius-full);
		background: var(--bg-elevated);
		border: 1px solid var(--border-strong);
		color: var(--text-primary);
		font-size: var(--text-sm);
		font-weight: 600;
		box-shadow: var(--shadow-md);
		transition:
			background-color var(--dur-fast) var(--ease-out),
			border-color var(--dur-fast) var(--ease-out),
			color var(--dur-fast) var(--ease-out);
	}

	.jump-latest-btn:hover {
		background: var(--bg-hover);
	}

	.jump-latest-btn.has-unread {
		background: var(--accent-fill);
		border-color: transparent;
		color: var(--text-on-accent);
	}

	.jump-latest-btn.has-unread:hover {
		background: var(--accent-fill-hover);
	}

	@media (pointer: coarse) {
		.messages-inner {
			padding-block-end: 4.5rem;
		}
	}

	@media (max-width: 767px) {
		.message-list {
			padding-inline: var(--space-3);
		}

		.jump-latest-btn {
			inset-inline-end: var(--space-3);
		}
	}
</style>

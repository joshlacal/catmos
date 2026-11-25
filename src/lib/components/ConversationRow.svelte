<script lang="ts">
	import type { Conversation, ProfileView } from '#lib/wasm.ts';
	import { stripDidFragment } from '#lib/did.ts';
	import { extractMessagePreview } from '#lib/stores/conversations.ts';
	import { formatSidebarTime } from '#lib/utils/time.ts';
	import {
		positionPopoverFallback,
		positionPopoverAtPoint,
		useRovingMenu
	} from '#lib/utils/popover.ts';
	import Avatar from './Avatar.svelte';
	import Icon from './Icon.svelte';

	let {
		conversation,
		selected = false,
		pinned = false,
		muted = false,
		quarantined = false,
		typingNames = [],
		draftText = '',
		otherProfile = null,
		displayName,
		onSelect,
		onMarkRead,
		onTogglePin,
		onToggleMute,
		onOpenDetails,
		onRequestLeave
	}: {
		conversation: Conversation;
		selected?: boolean;
		pinned?: boolean;
		muted?: boolean;
		quarantined?: boolean;
		typingNames?: string[];
		draftText?: string;
		otherProfile?: ProfileView | null;
		displayName: string;
		onSelect: (convoId: string) => void;
		onMarkRead: (convoId: string) => void;
		onTogglePin: (convoId: string) => void;
		onToggleMute: (convoId: string) => void;
		onOpenDetails: (convoId: string) => void;
		onRequestLeave: (convo: Conversation) => void;
	} = $props();

	let triggerEl: HTMLButtonElement | null = $state(null);
	let popoverEl: HTMLDivElement | null = $state(null);
	let anchored = $state(true);
	let openedAtPoint = false;

	const safeId = $derived(conversation.id.replace(/[^a-zA-Z0-9_-]/g, '_'));
	const menuId = $derived(`convo-menu-${safeId}`);
	const anchorName = $derived(`--convo-anchor-${safeId}`);

	const avatarSrc = $derived(
		conversation.isGroup
			? (conversation.avatarDataUrl ?? null)
			: (otherProfile?.avatar ?? conversation.avatarDataUrl ?? null)
	);
	const avatarId = $derived(
		conversation.isGroup
			? conversation.id
			: stripDidFragment(otherProfile?.did) || conversation.id
	);

	const timeLabel = $derived(formatSidebarTime(conversation.lastMessageAt));
	const trimmedDraft = $derived(draftText.trim());
	const messagePreview = $derived(extractMessagePreview(conversation.lastMessage ?? ''));
	const isTyping = $derived(typingNames.length > 0);
	const hasUnread = $derived(conversation.unreadCount > 0);

	function resetInlinePosition(el: HTMLElement) {
		el.style.position = '';
		el.style.inset = '';
		el.style.margin = '';
		el.style.left = '';
		el.style.top = '';
	}

	function handleContextMenu(event: MouseEvent) {
		if (!popoverEl) return;
		event.preventDefault();
		openedAtPoint = true;
		anchored = false;
		if (!popoverEl.matches(':popover-open')) {
			popoverEl.showPopover();
		}
		positionPopoverAtPoint(popoverEl, event.clientX, event.clientY);
	}

	function handleMenuToggle(event: Event) {
		if (!popoverEl) return;
		const toggleEvent = event as ToggleEvent;
		if (toggleEvent.newState === 'open') {
			if (!openedAtPoint) {
				anchored = true;
				resetInlinePosition(popoverEl);
				if (triggerEl) {
					positionPopoverFallback(popoverEl, triggerEl, 'bottom-end', 6);
				}
			}
			const firstBtn = popoverEl.querySelector<HTMLButtonElement>('button:not([disabled])');
			firstBtn?.focus({ preventScroll: true });
		} else {
			openedAtPoint = false;
			anchored = true;
			resetInlinePosition(popoverEl);
		}
	}

	function runMenuAction(action: () => void) {
		if (popoverEl?.matches(':popover-open')) {
			popoverEl.hidePopover();
		}
		action();
	}
</script>

<li class="convo-row" class:selected class:muted oncontextmenu={handleContextMenu}>
	<button
		type="button"
		class="convo-main-btn"
		aria-current={selected ? 'true' : undefined}
		onclick={() => onSelect(conversation.id)}
	>
		<Avatar
			src={avatarSrc}
			name={displayName}
			id={avatarId}
			size={40}
			shape={conversation.isGroup ? 'squircle' : 'circle'}
		/>
		<span class="convo-body">
			<span class="convo-top-row">
				<span class="convo-name-group">
					<span class="convo-name" class:unread-name={hasUnread}>{displayName}</span>
					{#if quarantined}
						<span class="status-icon status-icon--warning" title="Conversation paused">
							<Icon name="alert-triangle" size={13} label="Conversation paused" />
						</span>
					{/if}
					{#if pinned}
						<span class="status-icon" title="Pinned">
							<Icon name="pin" size={13} label="Pinned" />
						</span>
					{/if}
					{#if muted}
						<span class="status-icon" title="Muted">
							<Icon name="bell-off" size={13} label="Muted" />
						</span>
					{/if}
				</span>
				{#if timeLabel}
					<time class="convo-time tabular-nums" datetime={conversation.lastMessageAt}>
						{timeLabel}
					</time>
				{/if}
			</span>

			<span class="convo-bottom-row">
				{#if isTyping}
					<span class="convo-preview preview-typing">Typing...</span>
				{:else if trimmedDraft}
					<span class="convo-preview">
						<span class="preview-draft-prefix">Draft:</span>
						{trimmedDraft}
					</span>
				{:else if messagePreview}
					<span class="convo-preview" class:unread-preview={hasUnread}>{messagePreview}</span>
				{:else}
					<span class="convo-preview preview-empty">No messages yet</span>
				{/if}

				{#if hasUnread}
					<span
						class="unread-badge tabular-nums"
						class:unread-badge--muted={muted}
						aria-label={`${conversation.unreadCount} unread`}
					>
						{conversation.unreadCount > 99 ? '99+' : conversation.unreadCount}
					</span>
				{/if}
			</span>
		</span>
	</button>

	<button
		bind:this={triggerEl}
		type="button"
		class="convo-more-btn"
		popovertarget={menuId}
		aria-label={`More actions for ${displayName}`}
		title="Conversation actions"
		style={`anchor-name: ${anchorName};`}
	>
		<Icon name="more-horizontal" size={16} />
	</button>

	<div
		bind:this={popoverEl}
		id={menuId}
		class="catmos-popover convo-menu"
		popover="auto"
		data-anchored={anchored ? 'true' : undefined}
		data-placement="bottom-end"
		style={anchored ? `position-anchor: ${anchorName};` : undefined}
		ontoggle={handleMenuToggle}
		use:useRovingMenu={{ orientation: 'vertical', loop: true }}
	>
		{#if hasUnread}
			<button
				type="button"
				class="convo-menu-item"
				onclick={() => runMenuAction(() => onMarkRead(conversation.id))}
			>
				<Icon name="check" size={15} />
				<span>Mark as read</span>
			</button>
		{/if}
		<button
			type="button"
			class="convo-menu-item"
			onclick={() => runMenuAction(() => onTogglePin(conversation.id))}
		>
			<Icon name="pin" size={15} />
			<span>{pinned ? 'Unpin' : 'Pin'}</span>
		</button>
		<button
			type="button"
			class="convo-menu-item"
			onclick={() => runMenuAction(() => onToggleMute(conversation.id))}
		>
			<Icon name={muted ? 'bell' : 'bell-off'} size={15} />
			<span>{muted ? 'Unmute' : 'Mute'}</span>
		</button>
		<button
			type="button"
			class="convo-menu-item"
			onclick={() => runMenuAction(() => onOpenDetails(conversation.id))}
		>
			<Icon name="info" size={15} />
			<span>Conversation details</span>
		</button>
		<hr class="convo-menu-sep" />
		<button
			type="button"
			class="convo-menu-item convo-menu-item--danger"
			onclick={() => runMenuAction(() => onRequestLeave(conversation))}
		>
			<Icon name="log-out" size={15} />
			<span>Leave conversation</span>
		</button>
	</div>
</li>

<style>
	.convo-row {
		position: relative;
		display: flex;
		align-items: center;
		gap: 2px;
		border-radius: var(--radius-md);
		transition: background-color var(--dur-fast) var(--ease-out);
	}

	.convo-row:hover {
		background: var(--bg-hover);
	}

	.convo-row.selected {
		background: var(--bg-selected);
	}

	.convo-main-btn {
		flex: 1;
		min-inline-size: 0;
		display: flex;
		align-items: center;
		gap: 0.625rem;
		padding-block: var(--density-row-py);
		padding-inline-start: 0.625rem;
		padding-inline-end: 2px;
		border-radius: var(--radius-md);
		text-align: start;
	}

	.convo-body {
		flex: 1;
		min-inline-size: 0;
		display: flex;
		flex-direction: column;
		gap: 2px;
	}

	.convo-top-row {
		display: flex;
		align-items: baseline;
		justify-content: space-between;
		gap: 6px;
	}

	.convo-name-group {
		display: flex;
		align-items: center;
		gap: 4px;
		min-inline-size: 0;
		flex: 1;
	}

	.convo-name {
		font-size: var(--text-body);
		font-weight: 600;
		color: var(--text-primary);
		white-space: nowrap;
		overflow: hidden;
		text-overflow: ellipsis;
		line-height: 1.3;
	}

	.convo-name.unread-name {
		font-weight: 700;
	}

	.status-icon {
		display: inline-flex;
		align-items: center;
		color: var(--text-muted);
		flex-shrink: 0;
	}

	.status-icon--warning {
		color: var(--warning-text);
	}

	.convo-time {
		font-size: var(--text-sm);
		color: var(--text-muted);
		flex-shrink: 0;
		line-height: 1.3;
	}

	.convo-bottom-row {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: var(--space-2);
		min-inline-size: 0;
	}

	.convo-preview {
		flex: 1;
		min-inline-size: 0;
		font-size: var(--text-sm);
		color: var(--text-secondary);
		white-space: nowrap;
		overflow: hidden;
		text-overflow: ellipsis;
		line-height: 1.38;
	}

	.convo-preview.unread-preview {
		color: var(--text-primary);
		font-weight: 500;
	}

	.convo-preview.preview-typing {
		color: var(--text-link);
		font-weight: 500;
	}

	.preview-draft-prefix {
		color: var(--text-link);
		font-weight: 600;
		margin-inline-end: 4px;
	}

	.convo-preview.preview-empty {
		color: var(--text-muted);
	}

	.unread-badge {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		min-inline-size: 1.375rem;
		min-block-size: 1.375rem;
		padding-inline: 0.375rem;
		border-radius: var(--radius-full);
		background: var(--accent-fill);
		color: var(--text-on-accent);
		font-size: var(--text-sm);
		font-weight: 700;
		line-height: 1;
		flex-shrink: 0;
	}

	.unread-badge--muted {
		background: var(--bg-surface);
		color: var(--text-secondary);
		border: 1px solid var(--border-strong);
	}

	.convo-more-btn {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		min-inline-size: max(1.625rem, var(--touch-min));
		min-block-size: max(1.625rem, var(--touch-min));
		margin-inline-end: 2px;
		border-radius: var(--radius-sm);
		color: var(--text-secondary);
		opacity: 0.72;
		flex-shrink: 0;
		transition:
			background-color var(--dur-fast) var(--ease-out),
			color var(--dur-fast) var(--ease-out),
			opacity var(--dur-fast) var(--ease-out);
	}

	.convo-row:hover .convo-more-btn,
	.convo-row:focus-within .convo-more-btn,
	.convo-row.selected .convo-more-btn,
	.convo-more-btn:hover {
		opacity: 1;
	}

	.convo-more-btn:hover {
		background: var(--bg-active);
		color: var(--text-primary);
	}

	@media (pointer: coarse) {
		.convo-more-btn {
			opacity: 1;
		}
	}

	.convo-menu:popover-open {
		display: flex;
		flex-direction: column;
		gap: 2px;
	}

	.convo-menu-item {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		width: 100%;
		min-block-size: max(2.25rem, var(--touch-min));
		padding-inline: var(--space-3);
		padding-block: var(--space-1);
		border-radius: var(--radius-xs);
		font-size: var(--text-sm);
		font-weight: 500;
		color: var(--text-primary);
		text-align: start;
		transition:
			background-color var(--dur-fast) var(--ease-out),
			color var(--dur-fast) var(--ease-out);
	}

	.convo-menu-item:hover,
	.convo-menu-item:focus-visible {
		background: var(--bg-hover);
	}

	.convo-menu-item--danger {
		color: var(--danger-text);
	}

	.convo-menu-item--danger:hover,
	.convo-menu-item--danger:focus-visible {
		background: var(--danger-bg);
	}

	.convo-menu-sep {
		border: none;
		border-block-start: 1px solid var(--border);
		margin-block: var(--space-1);
	}
</style>

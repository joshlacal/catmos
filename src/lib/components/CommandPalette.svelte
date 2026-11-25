<script lang="ts">
	import { onDestroy } from 'svelte';
	import * as api from '#lib/wasm.ts';
	import type { Conversation, ProfileView, SearchHit } from '#lib/wasm.ts';
	import { dedupeAccountDids, isSameAccountDid, stripDidFragment } from '#lib/did.ts';
	import { auth } from '#lib/stores/auth.ts';
	import { conversations, extractMessagePreview } from '#lib/stores/conversations.ts';
	import { profiles, resolveProfileName, shortDid } from '#lib/stores/profiles.ts';
	import { preferences } from '#lib/stores/preferences.ts';
	import { useDialogLightDismiss, closeWithReset } from '#lib/utils/dialog.ts';
	import { formatSidebarTime } from '#lib/utils/time.ts';
	import Avatar from './Avatar.svelte';
	import Icon, { type IconName } from './Icon.svelte';

	let {
		open = false,
		onClose,
		onSelectConversation,
		onJumpToMessage,
		onOpenNewConversation,
		onOpenSettings,
		onToggleInspector
	}: {
		open: boolean;
		onClose: () => void;
		onSelectConversation: (convoId: string) => void;
		onJumpToMessage?: (convoId: string, messageId: string) => void;
		onOpenNewConversation: () => void;
		onOpenSettings: () => void;
		onToggleInspector: () => void;
	} = $props();

	type HighlightSegment = {
		text: string;
		match: boolean;
	};

	type PaletteItem =
		| {
				id: string;
				kind: 'conversation';
				conversation: Conversation;
				title: string;
				subtitle: string;
				avatarSrc: string | null;
				avatarId: string;
				timeLabel: string;
		  }
		| {
				id: string;
				kind: 'message';
				hit: SearchHit;
				conversationTitle: string;
				senderName: string;
				previewText: string;
				timeLabel: string;
		  }
		| {
				id: string;
				kind: 'action';
				label: string;
				shortcut: string;
				icon: IconName;
				run: () => void;
		  };

	let dialogEl: HTMLDialogElement | null = $state(null);
	let inputEl: HTMLInputElement | null = $state(null);
	let resultsEl: HTMLDivElement | null = $state(null);

	let query = $state('');
	let messageHits = $state<SearchHit[]>([]);
	let loadingMessages = $state(false);
	let searchedMessages = $state(false);
	let searchError = $state('');
	let activeIndex = $state(0);

	let debounceTimer: ReturnType<typeof setTimeout> | null = null;
	let searchSeq = 0;

	const isMac =
		typeof navigator !== 'undefined' && /Mac|iPhone|iPad|iPod/i.test(navigator.platform ?? '');
	const shortcutMod = isMac ? '⌘' : 'Ctrl+';

	function resetPaletteState() {
		if (debounceTimer) {
			clearTimeout(debounceTimer);
			debounceTimer = null;
		}
		searchSeq += 1;
		query = '';
		messageHits = [];
		loadingMessages = false;
		searchedMessages = false;
		searchError = '';
		activeIndex = 0;
	}

	$effect(() => {
		if (!dialogEl) return;
		if (open) {
			const allDids = $conversations.items.flatMap((c) => c.members);
			if (allDids.length > 0) {
				profiles.resolveProfiles(allDids);
			}
			if (!dialogEl.open) {
				resetPaletteState();
				dialogEl.showModal();
				requestAnimationFrame(() => {
					inputEl?.focus();
				});
			}
		} else if (dialogEl.open) {
			closeWithReset(dialogEl);
		}
	});

	function getOtherDid(convo: Conversation): string | undefined {
		if (convo.isGroup) return undefined;
		const otherRaw =
			convo.members.find((did) => !isSameAccountDid(did, $auth.user?.did)) ?? convo.members[0];
		const bare = stripDidFragment(otherRaw);
		return bare || otherRaw;
	}

	function getOtherProfile(convo: Conversation): ProfileView | null {
		const otherDid = getOtherDid(convo);
		return otherDid ? ($profiles.cache.get(stripDidFragment(otherDid)) ?? null) : null;
	}

	function resolveConvoTitle(convo: Conversation): string {
		if (convo.isGroup) return convo.displayName || 'Untitled group';
		const otherDid = getOtherDid(convo);
		if (otherDid) {
			const bareDid = stripDidFragment(otherDid);
			if (bareDid && $profiles.cache.has(bareDid)) {
				return resolveProfileName($profiles.cache, bareDid);
			}
			if (convo.displayName && !convo.displayName.startsWith('did:')) {
				return convo.displayName;
			}
			return shortDid(otherDid);
		}
		return convo.displayName || 'Direct message';
	}

	function parseTimeMs(iso?: string): number {
		if (!iso) return 0;
		const ms = Date.parse(iso);
		return Number.isFinite(ms) ? ms : 0;
	}

	const quickActions: Array<{
		id: string;
		label: string;
		keywords: string;
		shortcut: string;
		icon: IconName;
		run: () => void;
	}> = [
		{
			id: 'action-new-convo',
			label: 'New conversation',
			keywords: 'new chat message group create start',
			shortcut: `${shortcutMod}N`,
			icon: 'plus',
			run: () => onOpenNewConversation()
		},
		{
			id: 'action-settings',
			label: 'Open settings',
			keywords: 'settings preferences theme appearance notifications account',
			shortcut: `${shortcutMod},`,
			icon: 'settings',
			run: () => onOpenSettings()
		},
		{
			id: 'action-inspector',
			label: 'Toggle conversation details',
			keywords: 'inspector info details members security encryption',
			shortcut: `${shortcutMod}I`,
			icon: 'info',
			run: () => onToggleInspector()
		}
	];

	const trimmedQuery = $derived(query.trim());
	const lowerQuery = $derived(trimmedQuery.toLowerCase());

	const conversationItems = $derived.by<Extract<PaletteItem, { kind: 'conversation' }>[]>(() => {
		const pinned = new Set($preferences.pinnedIds);
		const sorted = [...$conversations.items].sort((a, b) => {
			const aPinned = pinned.has(a.id);
			const bPinned = pinned.has(b.id);
			if (aPinned !== bPinned) return aPinned ? -1 : 1;
			return parseTimeMs(b.lastMessageAt) - parseTimeMs(a.lastMessageAt);
		});

		const matching = lowerQuery
			? sorted.filter((convo) => {
					const title = resolveConvoTitle(convo).toLowerCase();
					const profile = getOtherProfile(convo);
					const handle = profile?.handle?.toLowerCase() ?? '';
					const desc = convo.description?.toLowerCase() ?? '';
					return (
						title.includes(lowerQuery) ||
						handle.includes(lowerQuery) ||
						desc.includes(lowerQuery)
					);
				})
			: sorted.slice(0, 6);

		return matching.slice(0, 8).map((convo) => {
			const otherProfile = getOtherProfile(convo);
			const title = resolveConvoTitle(convo);
			const memberCount = dedupeAccountDids(convo.members).length || convo.members.length;
			const subtitle = convo.isGroup
				? `${memberCount} members`
				: otherProfile?.handle && !otherProfile.handle.startsWith('did:')
					? `@${otherProfile.handle}`
					: extractMessagePreview(convo.lastMessage ?? '') || 'Direct message';

			return {
				id: `palette-convo-${convo.id}`,
				kind: 'conversation',
				conversation: convo,
				title,
				subtitle,
				avatarSrc: convo.isGroup
					? (convo.avatarDataUrl ?? null)
					: (otherProfile?.avatar ?? convo.avatarDataUrl ?? null),
				avatarId: convo.isGroup ? convo.id : stripDidFragment(otherProfile?.did) || convo.id,
				timeLabel: formatSidebarTime(convo.lastMessageAt)
			};
		});
	});

	const actionItems = $derived.by<Extract<PaletteItem, { kind: 'action' }>[]>(() => {
		const filtered = lowerQuery
			? quickActions.filter(
					(a) =>
						a.label.toLowerCase().includes(lowerQuery) ||
						a.keywords.includes(lowerQuery)
				)
			: quickActions;
		return filtered.map((a) => ({
			id: `palette-${a.id}`,
			kind: 'action',
			label: a.label,
			shortcut: a.shortcut,
			icon: a.icon,
			run: a.run
		}));
	});

	const messageItems = $derived.by<Extract<PaletteItem, { kind: 'message' }>[]>(() => {
		if (!trimmedQuery) return [];
		const convoMap = new Map($conversations.items.map((c) => [c.id, c]));
		return messageHits.map((hit) => {
			const convo = convoMap.get(hit.conversationId);
			const conversationTitle = convo ? resolveConvoTitle(convo) : hit.conversationName;
			return {
				id: `palette-msg-${hit.messageId}`,
				kind: 'message',
				hit,
				conversationTitle,
				senderName: resolveProfileName($profiles.cache, hit.senderDid),
				previewText: extractMessagePreview(hit.content) || hit.content,
				timeLabel: formatSidebarTime(hit.timestamp)
			};
		});
	});

	const allItems = $derived<PaletteItem[]>([
		...conversationItems,
		...messageItems,
		...actionItems
	]);

	// Keep activeIndex in bounds as results update
	$effect(() => {
		if (allItems.length === 0) {
			activeIndex = 0;
		} else if (activeIndex >= allItems.length) {
			activeIndex = 0;
		}
	});

	const activeItemId = $derived(allItems[activeIndex]?.id ?? undefined);

	function escapeRegex(str: string): string {
		return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
	}

	function highlightSegments(text: string, termRaw: string): HighlightSegment[] {
		const term = termRaw.trim();
		if (!term) return [{ text, match: false }];

		const regex = new RegExp(escapeRegex(term), 'gi');
		const segments: HighlightSegment[] = [];
		let lastIndex = 0;
		let match: RegExpExecArray | null;

		while ((match = regex.exec(text)) !== null) {
			if (match[0].length === 0) break;
			if (match.index > lastIndex) {
				segments.push({ text: text.slice(lastIndex, match.index), match: false });
			}
			segments.push({ text: match[0], match: true });
			lastIndex = regex.lastIndex;
		}

		if (lastIndex < text.length) {
			segments.push({ text: text.slice(lastIndex), match: false });
		}

		return segments.length > 0 ? segments : [{ text, match: false }];
	}

	async function runMessageSearch(targetQuery: string) {
		const q = targetQuery.trim();
		const seq = ++searchSeq;
		if (!q) {
			messageHits = [];
			loadingMessages = false;
			searchedMessages = false;
			searchError = '';
			return;
		}

		loadingMessages = true;
		searchError = '';
		try {
			const hits = await api.searchMessages(q);
			if (seq !== searchSeq) return;
			messageHits = hits;
			searchedMessages = true;
			const senderDids = hits.map((h) => stripDidFragment(h.senderDid)).filter(Boolean);
			if (senderDids.length > 0) {
				profiles.resolveProfiles(senderDids);
			}
		} catch {
			if (seq !== searchSeq) return;
			messageHits = [];
			searchedMessages = true;
			searchError = 'Could not search message history right now.';
		} finally {
			if (seq === searchSeq) {
				loadingMessages = false;
			}
		}
	}

	function handleInput() {
		activeIndex = 0;
		if (debounceTimer) {
			clearTimeout(debounceTimer);
			debounceTimer = null;
		}
		if (!query.trim()) {
			searchSeq += 1;
			messageHits = [];
			loadingMessages = false;
			searchedMessages = false;
			searchError = '';
			return;
		}
		loadingMessages = true;
		const q = query;
		debounceTimer = setTimeout(() => {
			debounceTimer = null;
			runMessageSearch(q);
		}, 220);
	}

	function activateItem(item: PaletteItem) {
		closeWithReset(dialogEl, 'selected');
		if (item.kind === 'conversation') {
			onSelectConversation(item.conversation.id);
		} else if (item.kind === 'message') {
			if (onJumpToMessage) {
				onJumpToMessage(item.hit.conversationId, item.hit.messageId);
			} else {
				onSelectConversation(item.hit.conversationId);
			}
		} else {
			item.run();
		}
	}

	function scrollActiveIntoView(index: number) {
		const target = allItems[index];
		if (!target || !resultsEl) return;
		const el = resultsEl.querySelector<HTMLElement>(`#${CSS.escape(target.id)}`);
		el?.scrollIntoView({ block: 'nearest' });
	}

	function handleInputKeydown(event: KeyboardEvent) {
		if (event.key === 'ArrowDown') {
			if (allItems.length === 0) return;
			event.preventDefault();
			activeIndex = (activeIndex + 1) % allItems.length;
			scrollActiveIntoView(activeIndex);
			return;
		}
		if (event.key === 'ArrowUp') {
			if (allItems.length === 0) return;
			event.preventDefault();
			activeIndex = (activeIndex - 1 + allItems.length) % allItems.length;
			scrollActiveIntoView(activeIndex);
			return;
		}
		if (event.key === 'Home' && allItems.length > 0 && !query) {
			event.preventDefault();
			activeIndex = 0;
			scrollActiveIntoView(0);
			return;
		}
		if (event.key === 'End' && allItems.length > 0 && !query) {
			event.preventDefault();
			activeIndex = allItems.length - 1;
			scrollActiveIntoView(activeIndex);
			return;
		}
		if (event.key === 'Enter') {
			if (event.isComposing || event.keyCode === 229) return;
			const current = allItems[activeIndex];
			if (current) {
				event.preventDefault();
				activateItem(current);
			}
		}
	}

	function handleDialogClose() {
		if (dialogEl) {
			dialogEl.returnValue = '';
		}
		resetPaletteState();
		if (open) {
			onClose();
		}
	}

	function itemIndexById(id: string): number {
		return allItems.findIndex((item) => item.id === id);
	}

	onDestroy(() => {
		if (debounceTimer) {
			clearTimeout(debounceTimer);
			debounceTimer = null;
		}
		searchSeq += 1;
	});
</script>

<dialog
	bind:this={dialogEl}
	class="catmos-dialog command-palette"
	closedby="any"
	use:useDialogLightDismiss
	onclose={handleDialogClose}
>
	<h1 class="visually-hidden">Quick switcher and message search</h1>

	<search class="palette-search">
		<span class="palette-search-icon" aria-hidden="true">
			<Icon name="search" size={18} />
		</span>
		<input
			bind:this={inputEl}
			type="search"
			class="palette-input"
			bind:value={query}
			oninput={handleInput}
			onkeydown={handleInputKeydown}
			placeholder="Search conversations, messages, or commands..."
			aria-label="Search conversations and messages"
			aria-controls="palette-results-list"
			aria-activedescendant={activeItemId}
			autocorrect="off"
			autocapitalize="none"
			spellcheck="false"
			autocomplete="off"
		/>
		{#if query.length > 0}
			<button
				type="button"
				class="palette-icon-btn"
				onclick={() => {
					query = '';
					handleInput();
					inputEl?.focus();
				}}
				aria-label="Clear search"
			>
				<Icon name="x" size={16} />
			</button>
		{/if}
		<button
			type="button"
			class="palette-icon-btn"
			onclick={() => closeWithReset(dialogEl, 'cancel')}
			aria-label="Close quick switcher"
		>
			<Icon name="x" size={18} />
		</button>
	</search>

	<div bind:this={resultsEl} id="palette-results-list" class="palette-results">
		{#if conversationItems.length > 0}
			<section class="palette-section" aria-label={trimmedQuery ? 'Conversations' : 'Recent conversations'}>
				<h2 class="section-heading">{trimmedQuery ? 'Conversations' : 'Recent conversations'}</h2>
				<ul role="list" class="palette-list">
					{#each conversationItems as item (item.id)}
						{@const idx = itemIndexById(item.id)}
						<li>
							<button
								id={item.id}
								type="button"
								class="palette-item"
								class:is-active={idx === activeIndex}
								aria-current={idx === activeIndex ? 'true' : undefined}
								onmouseenter={() => {
									if (idx >= 0) activeIndex = idx;
								}}
								onclick={() => activateItem(item)}
							>
								<Avatar
									src={item.avatarSrc}
									name={item.title}
									id={item.avatarId}
									size={32}
									shape={item.conversation.isGroup ? 'squircle' : 'circle'}
								/>
								<span class="item-main">
									<span class="item-title">
										{#each highlightSegments(item.title, trimmedQuery) as seg}
											{#if seg.match}
												<mark>{seg.text}</mark>
											{:else}
												{seg.text}
											{/if}
										{/each}
									</span>
									<span class="item-sub">{item.subtitle}</span>
								</span>
								{#if item.timeLabel}
									<span class="item-time tabular-nums">{item.timeLabel}</span>
								{/if}
							</button>
						</li>
					{/each}
				</ul>
			</section>
		{/if}

		{#if trimmedQuery}
			<section class="palette-section" aria-label="Messages">
				<h2 class="section-heading">Messages</h2>
				{#if loadingMessages}
					<div class="palette-inline-state">
						<progress class="catmos-progress palette-progress" aria-label="Searching messages"></progress>
						<span>Searching encrypted messages...</span>
					</div>
				{:else if searchError}
					<p class="palette-error" role="alert">{searchError}</p>
				{:else if messageItems.length > 0}
					<ul role="list" class="palette-list">
						{#each messageItems as item (item.id)}
							{@const idx = itemIndexById(item.id)}
							<li>
								<button
									id={item.id}
									type="button"
									class="palette-item palette-item--message"
									class:is-active={idx === activeIndex}
									aria-current={idx === activeIndex ? 'true' : undefined}
									onmouseenter={() => {
										if (idx >= 0) activeIndex = idx;
									}}
									onclick={() => activateItem(item)}
								>
									<span class="msg-header">
										<span class="msg-meta">
											<span class="msg-convo">{item.conversationTitle}</span>
											<span class="meta-dot" aria-hidden="true">·</span>
											<span class="msg-sender">{item.senderName}</span>
										</span>
										{#if item.timeLabel}
											<time class="item-time tabular-nums" datetime={item.hit.timestamp}>
												{item.timeLabel}
											</time>
										{/if}
									</span>
									<span class="msg-snippet">
										{#each highlightSegments(item.previewText, trimmedQuery) as seg}
											{#if seg.match}
												<mark>{seg.text}</mark>
											{:else}
												{seg.text}
											{/if}
										{/each}
									</span>
								</button>
							</li>
						{/each}
					</ul>
				{:else if searchedMessages}
					<p class="palette-muted-note">No messages match "{trimmedQuery}".</p>
				{/if}
			</section>
		{/if}

		{#if actionItems.length > 0}
			<section class="palette-section" aria-label="Quick actions">
				<h2 class="section-heading">Quick actions</h2>
				<ul role="list" class="palette-list">
					{#each actionItems as item (item.id)}
						{@const idx = itemIndexById(item.id)}
						<li>
							<button
								id={item.id}
								type="button"
								class="palette-item"
								class:is-active={idx === activeIndex}
								aria-current={idx === activeIndex ? 'true' : undefined}
								onmouseenter={() => {
									if (idx >= 0) activeIndex = idx;
								}}
								onclick={() => activateItem(item)}
							>
								<span class="action-icon" aria-hidden="true">
									<Icon name={item.icon} size={16} />
								</span>
								<span class="item-main">
									<span class="item-title">{item.label}</span>
								</span>
								<kbd class="shortcut-kbd">{item.shortcut}</kbd>
							</button>
						</li>
					{/each}
				</ul>
			</section>
		{/if}

		{#if trimmedQuery && !loadingMessages && allItems.length === 0 && searchedMessages && !searchError}
			<div class="palette-empty">
				<p>No conversations, messages, or actions match "{trimmedQuery}".</p>
			</div>
		{/if}
	</div>

	<footer class="palette-footer" aria-hidden="true">
		<span><kbd>↑</kbd> <kbd>↓</kbd> Navigate</span>
		<span><kbd>Enter</kbd> Select</span>
		<span><kbd>Esc</kbd> Close</span>
	</footer>
</dialog>

<style>
	.command-palette {
		inline-size: min(37rem, calc(100vw - 2rem));
		max-block-size: min(74svh, 38rem);
		margin-block-start: min(12vh, 96px);
		margin-block-end: auto;
	}

	.palette-search {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		padding: var(--space-3) var(--space-4);
		border-block-end: 1px solid var(--border);
		flex-shrink: 0;
	}

	.palette-search-icon {
		display: inline-flex;
		align-items: center;
		color: var(--text-muted);
		flex-shrink: 0;
	}

	.palette-input {
		flex: 1;
		min-inline-size: 0;
		min-block-size: max(2.25rem, var(--touch-min));
		font-size: var(--text-body);
		color: var(--text-primary);
		outline: none;
	}

	.palette-input::placeholder {
		color: var(--text-muted);
	}

	.palette-input::-webkit-search-cancel-button {
		-webkit-appearance: none;
	}

	.palette-icon-btn {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		min-inline-size: max(2rem, var(--touch-min));
		min-block-size: max(2rem, var(--touch-min));
		border-radius: var(--radius-sm);
		color: var(--text-secondary);
		flex-shrink: 0;
		transition:
			background-color var(--dur-fast) var(--ease-out),
			color var(--dur-fast) var(--ease-out);
	}

	.palette-icon-btn:hover {
		background: var(--bg-hover);
		color: var(--text-primary);
	}

	.palette-results {
		flex: 1;
		min-block-size: 0;
		overflow-y: auto;
		padding: var(--space-2);
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
	}

	.palette-section {
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
	}

	.section-heading {
		font-size: var(--text-sm);
		font-weight: 600;
		color: var(--text-secondary);
		padding-inline: var(--space-3);
		padding-block: var(--space-1);
	}

	.palette-list {
		list-style: none;
		display: flex;
		flex-direction: column;
		gap: 2px;
	}

	.palette-item {
		display: flex;
		align-items: center;
		gap: var(--space-3);
		width: 100%;
		min-block-size: max(2.75rem, var(--touch-min));
		padding-inline: var(--space-3);
		padding-block: var(--space-2);
		border-radius: var(--radius-sm);
		text-align: start;
		color: var(--text-primary);
		transition: background-color var(--dur-fast) var(--ease-out);
	}

	.palette-item:hover,
	.palette-item.is-active {
		background: var(--bg-selected);
	}

	.palette-item--message {
		flex-direction: column;
		align-items: stretch;
		gap: 4px;
	}

	.item-main {
		flex: 1;
		min-inline-size: 0;
		display: flex;
		flex-direction: column;
		gap: 2px;
	}

	.item-title {
		font-size: var(--text-body);
		font-weight: 600;
		color: var(--text-primary);
		white-space: nowrap;
		overflow: hidden;
		text-overflow: ellipsis;
		line-height: 1.3;
	}

	.item-sub {
		font-size: var(--text-sm);
		color: var(--text-secondary);
		white-space: nowrap;
		overflow: hidden;
		text-overflow: ellipsis;
		line-height: 1.35;
	}

	.item-time {
		font-size: var(--text-sm);
		color: var(--text-muted);
		flex-shrink: 0;
	}

	.action-icon {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		inline-size: 2rem;
		block-size: 2rem;
		border-radius: var(--radius-xs);
		background: var(--bg-surface);
		color: var(--text-secondary);
		flex-shrink: 0;
	}

	.msg-header {
		display: flex;
		align-items: baseline;
		justify-content: space-between;
		gap: var(--space-2);
	}

	.msg-meta {
		display: flex;
		align-items: baseline;
		gap: var(--space-1);
		min-inline-size: 0;
		flex: 1;
		font-size: var(--text-sm);
	}

	.msg-convo {
		font-weight: 600;
		color: var(--text-link);
		white-space: nowrap;
		overflow: hidden;
		text-overflow: ellipsis;
	}

	.meta-dot {
		color: var(--text-muted);
	}

	.msg-sender {
		color: var(--text-secondary);
		white-space: nowrap;
		overflow: hidden;
		text-overflow: ellipsis;
	}

	.msg-snippet {
		font-size: var(--text-body);
		color: var(--text-primary);
		white-space: nowrap;
		overflow: hidden;
		text-overflow: ellipsis;
		line-height: 1.4;
	}

	.palette-item mark {
		background: var(--accent-fill);
		color: var(--text-on-accent);
		border-radius: 3px;
		padding-inline: 2px;
	}

	.shortcut-kbd {
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		font-weight: 500;
		color: var(--text-secondary);
		background: var(--bg-surface);
		border: 1px solid var(--border);
		border-radius: var(--radius-xs);
		padding: 2px 7px;
		flex-shrink: 0;
	}

	.palette-inline-state {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		padding: var(--space-2) var(--space-3);
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}

	.palette-progress {
		inline-size: 1rem;
		block-size: 1rem;
		border-width: 2px;
	}

	.palette-error {
		padding: var(--space-2) var(--space-3);
		font-size: var(--text-sm);
		color: var(--danger-text);
	}

	.palette-muted-note {
		padding: var(--space-2) var(--space-3);
		font-size: var(--text-sm);
		color: var(--text-muted);
	}

	.palette-empty {
		padding: var(--space-6) var(--space-4);
		text-align: center;
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}

	.palette-footer {
		display: flex;
		align-items: center;
		gap: var(--space-4);
		padding: var(--space-2) var(--space-4);
		border-block-start: 1px solid var(--border);
		font-size: var(--text-sm);
		color: var(--text-muted);
		flex-shrink: 0;
	}

	.palette-footer kbd {
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		color: var(--text-secondary);
		background: var(--bg-surface);
		border: 1px solid var(--border);
		border-radius: 4px;
		padding: 1px 5px;
		margin-inline-end: 3px;
	}

	@media (max-width: 640px) {
		.command-palette {
			margin-block-start: var(--space-4);
		}

		.palette-footer {
			display: none;
		}
	}
</style>

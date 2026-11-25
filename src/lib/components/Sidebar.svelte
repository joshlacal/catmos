<script lang="ts">
	import { page } from '$app/state';
	import * as api from '#lib/wasm.ts';
	import type { Conversation, ProfileView } from '#lib/wasm.ts';
	import { isSameAccountDid, stripDidFragment } from '#lib/did.ts';
	import { isMlsOptedInForDid } from '#lib/labyrinth-ui.ts';
	import { auth } from '#lib/stores/auth.ts';
	import { conversations, extractMessagePreview } from '#lib/stores/conversations.ts';
	import { messages } from '#lib/stores/messages.ts';
	import { profiles, resolveProfileName, shortDid } from '#lib/stores/profiles.ts';
	import { drafts } from '#lib/stores/drafts.ts';
	import { quarantine } from '#lib/stores/quarantine.ts';
	import { preferences, togglePin, toggleMute } from '#lib/stores/preferences.ts';
	import {
		useDialogLightDismiss,
		closeWithReset,
		useDialogSafeAutofocus
	} from '#lib/utils/dialog.ts';
	import { announce, showToast } from '#lib/utils/announcer.ts';
	import Avatar from './Avatar.svelte';
	import Icon from './Icon.svelte';
	import ConversationRow from './ConversationRow.svelte';

	type SettingsTab = 'appearance' | 'notifications' | 'account' | 'shortcuts';
	type ConvoFilter = 'all' | 'unread' | 'direct' | 'groups';

	let {
		onSelectConversation,
		onOpenNewConversation,
		onOpenCommandPalette,
		onOpenSettings,
		onOpenInspector,
		onToggleCollapse,
		onRequestSignOut
	}: {
		onSelectConversation?: (convoId: string) => void;
		onOpenNewConversation: () => void;
		onOpenCommandPalette: () => void;
		onOpenSettings: (tab?: SettingsTab) => void;
		onOpenInspector?: (convoId: string) => void;
		onToggleCollapse: () => void;
		onRequestSignOut: () => void;
	} = $props();

	let filterQuery = $state('');
	let activeFilter = $state<ConvoFilter>('all');

	let leavingConvo = $state<Conversation | null>(null);
	let leaving = $state(false);
	let leaveError = $state('');
	let leaveDialogEl: HTMLDialogElement | null = $state(null);

	const isMac =
		typeof navigator !== 'undefined' && /Mac|iPhone|iPad|iPod/i.test(navigator.platform ?? '');
	const shortcutMod = isMac ? '⌘' : 'Ctrl+';

	const isOptedIn = $derived.by(() => {
		void page.url.pathname;
		void $conversations.items.length;
		return Boolean($auth.user?.did && isMlsOptedInForDid($auth.user.did));
	});

	// Resolve profiles for all conversation members so 1:1 chats show real names and avatars
	$effect(() => {
		const allDids = $conversations.items.flatMap((c) => c.members);
		if (allDids.length > 0) {
			profiles.resolveProfiles(allDids);
		}
	});

	// Sync native leave confirmation dialog
	$effect(() => {
		if (!leaveDialogEl) return;
		if (leavingConvo && !leaveDialogEl.open) {
			leaveDialogEl.showModal();
		} else if (!leavingConvo && leaveDialogEl.open) {
			closeWithReset(leaveDialogEl);
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
		if (!otherDid) return null;
		return $profiles.cache.get(stripDidFragment(otherDid)) ?? null;
	}

	function resolveConvoTitle(convo: Conversation): string {
		if (convo.isGroup) {
			return convo.displayName || 'Untitled group';
		}
		const otherDid = getOtherDid(convo);
		if (otherDid) {
			const bareDid = stripDidFragment(otherDid);
			const cached = bareDid ? $profiles.cache.get(bareDid) : undefined;
			if (cached) {
				return resolveProfileName($profiles.cache, bareDid);
			}
			if (convo.displayName && !convo.displayName.startsWith('did:')) {
				return convo.displayName;
			}
			return shortDid(otherDid);
		}
		return convo.displayName || 'Direct message';
	}

	function isConvoMuted(convo: Conversation, mutedIds: string[]): boolean {
		if (mutedIds.includes(convo.id)) return true;
		if (convo.mutedUntil) {
			const until = Date.parse(convo.mutedUntil);
			if (Number.isFinite(until) && until > Date.now()) return true;
		}
		return false;
	}

	function parseTimeMs(iso?: string): number {
		if (!iso) return 0;
		const ms = Date.parse(iso);
		return Number.isFinite(ms) ? ms : 0;
	}

	const pinnedSet = $derived(new Set($preferences.pinnedIds));

	const sortedConversations = $derived.by(() => {
		const pinned = pinnedSet;
		return [...$conversations.items].sort((a, b) => {
			const aPinned = pinned.has(a.id);
			const bPinned = pinned.has(b.id);
			if (aPinned !== bPinned) return aPinned ? -1 : 1;
			return parseTimeMs(b.lastMessageAt) - parseTimeMs(a.lastMessageAt);
		});
	});

	const filteredConversations = $derived.by(() => {
		const q = filterQuery.trim().toLowerCase();
		return sortedConversations.filter((convo) => {
			if (activeFilter === 'unread' && convo.unreadCount <= 0) return false;
			if (activeFilter === 'direct' && convo.isGroup) return false;
			if (activeFilter === 'groups' && !convo.isGroup) return false;
			if (!q) return true;

			const title = resolveConvoTitle(convo).toLowerCase();
			if (title.includes(q)) return true;

			const otherProfile = getOtherProfile(convo);
			if (otherProfile?.handle?.toLowerCase().includes(q)) return true;
			if (convo.description?.toLowerCase().includes(q)) return true;

			const preview = extractMessagePreview(convo.lastMessage ?? '').toLowerCase();
			if (preview.includes(q)) return true;

			return false;
		});
	});

	const hasActiveFilters = $derived(filterQuery.trim().length > 0 || activeFilter !== 'all');

	const leavingConvoTitle = $derived(leavingConvo ? resolveConvoTitle(leavingConvo) : '');

	function getTypingNames(convoId: string): string[] {
		const dids = ($messages.typingByConversation.get(convoId) ?? []).filter(
			(did) => !isSameAccountDid(did, $auth.user?.did)
		);
		return dids.map((did) => resolveProfileName($profiles.cache, did));
	}

	function clearFilters() {
		filterQuery = '';
		activeFilter = 'all';
		announce('Conversation filters cleared');
	}

	function handleSelect(convoId: string) {
		if (onSelectConversation) {
			onSelectConversation(convoId);
		} else {
			conversations.select(convoId);
		}
	}

	function handleMarkRead(convoId: string) {
		conversations.markConversationRead(convoId);
		const list = $messages.byConversation.get(convoId);
		const latestId = list && list.length > 0 ? list[list.length - 1].id : '';
		api.updateCursor(convoId, latestId).catch(() => {});
		announce('Conversation marked as read');
	}

	function handleTogglePin(convoId: string) {
		const pinnedNow = togglePin(convoId);
		showToast({
			message: pinnedNow ? 'Conversation pinned' : 'Conversation unpinned',
			tone: 'info'
		});
	}

	function handleToggleMute(convoId: string) {
		const mutedNow = toggleMute(convoId);
		showToast({
			message: mutedNow ? 'Notifications muted for this chat' : 'Notifications unmuted',
			tone: 'info'
		});
	}

	function handleOpenDetails(convoId: string) {
		handleSelect(convoId);
		onOpenInspector?.(convoId);
	}

	function handleRequestLeave(convo: Conversation) {
		leaveError = '';
		leaving = false;
		leavingConvo = convo;
	}

	function handleLeaveDialogClose() {
		if (leaveDialogEl) {
			leaveDialogEl.returnValue = '';
		}
		if (!leaving) {
			leavingConvo = null;
			leaveError = '';
		}
	}

	async function confirmLeaveConversation() {
		if (!leavingConvo || leaving) return;
		const target = leavingConvo;
		const title = resolveConvoTitle(target);
		leaving = true;
		leaveError = '';
		try {
			await conversations.leaveConversation(target.id);
			leaving = false;
			leavingConvo = null;
			closeWithReset(leaveDialogEl, 'left');
			showToast({ message: `Left ${title}`, tone: 'info' });
		} catch (err) {
			leaving = false;
			leaveError = err instanceof Error ? err.message : 'Could not leave conversation.';
		}
	}

	const userDisplayName = $derived(
		$auth.user?.displayName?.trim() || $auth.user?.handle || shortDid($auth.user?.did ?? '')
	);
	const userHandle = $derived(
		$auth.user?.handle && !$auth.user.handle.startsWith('did:')
			? `@${$auth.user.handle}`
			: shortDid($auth.user?.did ?? '')
	);
</script>

<aside id="sidebar" class="sidebar" aria-label="Conversations">
	<header class="sidebar-header">
		<div class="sidebar-header-left">
			<button
				type="button"
				class="icon-btn sidebar-collapse-btn"
				onclick={onToggleCollapse}
				aria-label="Hide sidebar"
				aria-controls="sidebar"
				aria-expanded="true"
				title={`Hide sidebar (${shortcutMod}B)`}
			>
				<Icon name="sidebar" size={18} />
			</button>
			<span class="brand-lockup">
				<span class="brand-mark" aria-hidden="true">
					<Icon name="catbird" size={16} />
				</span>
				<span class="brand-wordmark">catmos</span>
			</span>
		</div>

		<div class="sidebar-header-actions">
			<button
				type="button"
				class="icon-btn"
				onclick={onOpenCommandPalette}
				aria-label="Search conversations and messages"
				title={`Search (${shortcutMod}K)`}
			>
				<Icon name="search" size={18} />
			</button>
			<button
				type="button"
				class="icon-btn icon-btn--new"
				onclick={onOpenNewConversation}
				aria-label="New conversation"
				title={`New conversation (${shortcutMod}N)`}
			>
				<Icon name="plus" size={18} />
			</button>
		</div>
	</header>

	<search class="sidebar-search" aria-label="Filter conversations">
		<div class="filter-input-wrap">
			<span class="filter-search-icon" aria-hidden="true">
				<Icon name="search" size={15} />
			</span>
			<input
				type="search"
				class="filter-input"
				bind:value={filterQuery}
				placeholder="Filter chats..."
				aria-label="Filter conversations"
				autocorrect="off"
				autocapitalize="none"
				spellcheck="false"
				autocomplete="off"
			/>
			{#if filterQuery.length > 0}
				<button
					type="button"
					class="filter-clear-btn"
					onclick={() => {
						filterQuery = '';
					}}
					aria-label="Clear filter text"
				>
					<Icon name="x" size={14} />
				</button>
			{/if}
		</div>

		<fieldset class="catmos-segmented filter-segmented">
			<legend class="visually-hidden">Filter conversations</legend>
			<label>
				<input
					type="radio"
					name="sidebar-filter"
					value="all"
					checked={activeFilter === 'all'}
					onchange={() => {
						activeFilter = 'all';
					}}
				/>
				<span>All</span>
			</label>
			<label>
				<input
					type="radio"
					name="sidebar-filter"
					value="unread"
					checked={activeFilter === 'unread'}
					onchange={() => {
						activeFilter = 'unread';
					}}
				/>
				<span>Unread</span>
			</label>
			<label>
				<input
					type="radio"
					name="sidebar-filter"
					value="direct"
					checked={activeFilter === 'direct'}
					onchange={() => {
						activeFilter = 'direct';
					}}
				/>
				<span>Direct</span>
			</label>
			<label>
				<input
					type="radio"
					name="sidebar-filter"
					value="groups"
					checked={activeFilter === 'groups'}
					onchange={() => {
						activeFilter = 'groups';
					}}
				/>
				<span>Groups</span>
			</label>
		</fieldset>
	</search>

	{#if $conversations.error}
		<div class="sidebar-error" role="alert">
			<div class="sidebar-error-body">
				<Icon name="alert-triangle" size={16} />
				<span>{$conversations.error}</span>
			</div>
			<button
				type="button"
				class="catmos-btn-secondary retry-btn"
				onclick={() => conversations.load()}
			>
				Retry
			</button>
		</div>
	{/if}

	<nav class="conversations-nav" aria-label="Conversation list">
		{#if $conversations.loading && $conversations.items.length === 0}
			<div class="sidebar-state">
				<progress class="catmos-progress" aria-label="Loading conversations"></progress>
				<p class="state-desc">Loading conversations...</p>
			</div>
		{:else if filteredConversations.length > 0}
			<ul role="list" class="conversations-list">
				{#each filteredConversations as convo (convo.id)}
					<ConversationRow
						conversation={convo}
						selected={$conversations.selectedId === convo.id}
						pinned={pinnedSet.has(convo.id)}
						muted={isConvoMuted(convo, $preferences.mutedIds)}
						quarantined={Boolean($quarantine[convo.id])}
						typingNames={getTypingNames(convo.id)}
						draftText={$drafts.get(convo.id) ?? ''}
						otherProfile={getOtherProfile(convo)}
						displayName={resolveConvoTitle(convo)}
						onSelect={handleSelect}
						onMarkRead={handleMarkRead}
						onTogglePin={handleTogglePin}
						onToggleMute={handleToggleMute}
						onOpenDetails={handleOpenDetails}
						onRequestLeave={handleRequestLeave}
					/>
				{/each}
			</ul>
		{:else if $conversations.items.length === 0 && !$conversations.error}
			<div class="sidebar-state">
				<span class="empty-shield" aria-hidden="true">
					<Icon name="shield" size={24} />
				</span>
				{#if $auth.user?.did && !isOptedIn}
					<p class="state-title">Encrypted Chat is off</p>
					<p class="state-desc">
						Enable Encrypted Chat and Labyrinth Backup to sync conversations and restore history
						from your PDS.
					</p>
					<a href="/settings/labyrinth" class="catmos-btn-primary state-cta">
						Set Up &amp; Restore History
					</a>
				{:else}
					<p class="state-title">Start an encrypted chat</p>
					<p class="state-desc">
						Private messages stay end-to-end encrypted on your devices with MLS.
					</p>
					<button
						type="button"
						class="catmos-btn-primary state-cta"
						onclick={onOpenNewConversation}
					>
						New conversation
					</button>
					<a href="/settings/labyrinth" class="state-secondary-link">
						Labyrinth Backup &amp; Restore
					</a>
				{/if}
			</div>
		{:else if hasActiveFilters}
			<div class="sidebar-state">
				<p class="state-title">
					{#if filterQuery.trim()}
						No conversations match "{filterQuery.trim()}"
					{:else if activeFilter === 'unread'}
						No unread conversations
					{:else if activeFilter === 'direct'}
						No direct messages
					{:else}
						No group conversations
					{/if}
				</p>
				<button type="button" class="catmos-btn-secondary state-cta" onclick={clearFilters}>
					Clear filter
				</button>
			</div>
		{/if}
	</nav>

	<footer class="sidebar-footer">
		<button
			type="button"
			class="account-btn"
			onclick={() => onOpenSettings('account')}
			aria-label="Account and security settings"
		>
			<Avatar
				src={$auth.user?.avatar ?? null}
				name={userDisplayName}
				id={$auth.user?.did}
				size={34}
				shape="circle"
			/>
			<span class="account-details">
				<span class="account-name">{userDisplayName}</span>
				<span class="account-handle">{userHandle}</span>
			</span>
		</button>

		<div class="footer-actions">
			<a
				href="/settings/labyrinth"
				class="icon-btn"
				title="Labyrinth Backup and Security"
				aria-label="Labyrinth Backup and Security"
			>
				<Icon name="shield" size={18} />
			</a>
			<button
				type="button"
				class="icon-btn"
				onclick={() => onOpenSettings('appearance')}
				aria-label="Settings"
				title={`Settings (${shortcutMod},)`}
			>
				<Icon name="settings" size={18} />
			</button>
			<button
				type="button"
				class="icon-btn logout-btn"
				onclick={onRequestSignOut}
				aria-label="Sign out"
				title="Sign out"
			>
				<Icon name="log-out" size={18} />
			</button>
		</div>
	</footer>
</aside>

<dialog
	bind:this={leaveDialogEl}
	class="catmos-dialog leave-confirm-dialog"
	closedby="any"
	use:useDialogLightDismiss
	onclose={handleLeaveDialogClose}
>
	{#if leavingConvo}
		<div class="confirm-body">
			<h1>Leave {leavingConvoTitle}?</h1>
			<p class="confirm-copy">
				{#if leavingConvo.isGroup}
					You will stop receiving messages from this group. An admin will need to invite you
					again to rejoin.
				{:else}
					You will leave this encrypted conversation and remove it from your inbox on this
					device.
				{/if}
			</p>
			{#if leaveError}
				<p class="confirm-error" role="alert">{leaveError}</p>
			{/if}
			<div class="confirm-actions">
				<button
					type="button"
					class="catmos-btn-secondary"
					use:useDialogSafeAutofocus
					disabled={leaving}
					onclick={() => {
						leavingConvo = null;
						closeWithReset(leaveDialogEl, 'cancel');
					}}
				>
					Cancel
				</button>
				<button
					type="button"
					class="catmos-btn-danger"
					disabled={leaving}
					onclick={confirmLeaveConversation}
				>
					{#if leaving}
						<progress class="catmos-progress btn-progress" aria-label="Leaving conversation"></progress>
						<span>Leaving...</span>
					{:else}
						<span>Leave conversation</span>
					{/if}
				</button>
			</div>
		</div>
	{/if}
</dialog>

<style>
	.sidebar {
		inline-size: var(--sidebar-width);
		max-inline-size: 100%;
		block-size: 100%;
		background: var(--bg-sidebar);
		display: flex;
		flex-direction: column;
		border-inline-end: 1px solid var(--border);
		flex-shrink: 0;
		overflow: hidden;
	}

	.sidebar-header {
		min-block-size: var(--header-height);
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: var(--space-2);
		padding-inline: var(--space-3);
		padding-block: var(--space-2);
		flex-shrink: 0;
	}

	.sidebar-header-left {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		min-inline-size: 0;
	}

	.brand-lockup {
		display: inline-flex;
		align-items: center;
		gap: var(--space-2);
		user-select: none;
	}

	.brand-mark {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		inline-size: 1.75rem;
		block-size: 1.75rem;
		border-radius: 8px;
		background: var(--brand-gradient);
		flex-shrink: 0;
	}

	.brand-wordmark {
		font-family: var(--font-display);
		font-size: 1.125rem;
		font-weight: 800;
		font-variation-settings:
			'wdth' 125,
			'wght' 900;
		letter-spacing: -0.025em;
		color: var(--text-primary);
		line-height: 1;
	}

	.sidebar-header-actions {
		display: flex;
		align-items: center;
		gap: var(--space-1);
		flex-shrink: 0;
	}

	.icon-btn {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		min-inline-size: max(2.125rem, var(--touch-min));
		min-block-size: max(2.125rem, var(--touch-min));
		border-radius: var(--radius-sm);
		color: var(--text-secondary);
		text-decoration: none;
		flex-shrink: 0;
		transition:
			background-color var(--dur-fast) var(--ease-out),
			color var(--dur-fast) var(--ease-out);
	}

	.icon-btn:hover {
		background: var(--bg-hover);
		color: var(--text-primary);
		text-decoration: none;
	}

	.icon-btn--new {
		background: var(--accent-fill);
		color: var(--text-on-accent);
	}

	.icon-btn--new:hover {
		background: var(--accent-fill-hover);
		color: var(--text-on-accent);
	}

	.sidebar-search {
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
		padding-inline: var(--space-3);
		padding-block-end: var(--space-3);
		border-block-end: 1px solid var(--border);
		flex-shrink: 0;
	}

	.filter-input-wrap {
		display: flex;
		align-items: center;
		background: var(--bg-input);
		border: 1px solid var(--border);
		border-radius: var(--radius-sm);
		transition: border-color var(--dur-fast) var(--ease-out);
	}

	.filter-input-wrap:focus-within {
		border-color: var(--focus-ring);
	}

	.filter-search-icon {
		display: inline-flex;
		align-items: center;
		padding-inline-start: var(--space-3);
		color: var(--text-muted);
		pointer-events: none;
	}

	.filter-input {
		flex: 1;
		min-inline-size: 0;
		min-block-size: max(2.25rem, var(--touch-min));
		padding-inline: var(--space-2) var(--space-3);
		padding-block: var(--space-1);
		font-size: var(--text-body);
		color: var(--text-primary);
		outline: none;
	}

	.filter-input::placeholder {
		color: var(--text-muted);
	}

	.filter-input::-webkit-search-cancel-button {
		-webkit-appearance: none;
	}

	.filter-clear-btn {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		min-inline-size: max(1.75rem, var(--touch-min));
		min-block-size: max(1.75rem, var(--touch-min));
		margin-inline-end: 2px;
		border-radius: var(--radius-xs);
		color: var(--text-secondary);
		transition:
			background-color var(--dur-fast) var(--ease-out),
			color var(--dur-fast) var(--ease-out);
	}

	.filter-clear-btn:hover {
		background: var(--bg-hover);
		color: var(--text-primary);
	}

	.filter-segmented {
		width: 100%;
	}

	.filter-segmented label {
		padding-inline: var(--space-2);
	}

	.sidebar-error {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: var(--space-2);
		margin: var(--space-2) var(--space-3) 0;
		padding: var(--space-2) var(--space-3);
		border-radius: var(--radius-sm);
		background: var(--danger-bg);
		border: 1px solid var(--danger-text);
		color: var(--danger-text);
		font-size: var(--text-sm);
		flex-shrink: 0;
	}

	.sidebar-error-body {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		min-inline-size: 0;
	}

	.retry-btn {
		min-block-size: max(1.875rem, var(--touch-min));
		padding-inline: var(--space-3);
		padding-block: var(--space-1);
		font-size: var(--text-sm);
		flex-shrink: 0;
	}

	.conversations-nav {
		flex: 1;
		min-block-size: 0;
		overflow-y: auto;
		padding-block: var(--space-2);
		padding-inline: 0.375rem;
	}

	.conversations-list {
		list-style: none;
		display: flex;
		flex-direction: column;
		gap: 2px;
	}

	.sidebar-state {
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
		text-align: center;
		gap: var(--space-2);
		padding: var(--space-8) var(--space-4);
	}

	.empty-shield {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		color: var(--shield);
	}

	.state-title {
		font-size: var(--text-body);
		font-weight: 600;
		color: var(--text-primary);
	}

	.state-desc {
		font-size: var(--text-sm);
		color: var(--text-secondary);
		max-inline-size: 26ch;
	}

	.state-cta {
		margin-block-start: var(--space-2);
	}

	.state-secondary-link {
		margin-block-start: var(--space-1);
		font-size: var(--text-sm);
		font-weight: 500;
		color: var(--text-link);
	}

	.sidebar-footer {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: var(--space-2);
		padding: var(--space-2) var(--space-3);
		border-block-start: 1px solid var(--border);
		flex-shrink: 0;
	}

	.account-btn {
		flex: 1;
		min-inline-size: 0;
		display: flex;
		align-items: center;
		gap: var(--space-2);
		min-block-size: max(2.625rem, var(--touch-min));
		padding: var(--space-1) var(--space-2);
		margin-inline-start: calc(-1 * var(--space-2));
		border-radius: var(--radius-sm);
		text-align: start;
		transition: background-color var(--dur-fast) var(--ease-out);
	}

	.account-btn:hover {
		background: var(--bg-hover);
	}

	.account-details {
		display: flex;
		flex-direction: column;
		min-inline-size: 0;
	}

	.account-name {
		font-size: var(--text-sm);
		font-weight: 600;
		color: var(--text-primary);
		white-space: nowrap;
		overflow: hidden;
		text-overflow: ellipsis;
		line-height: 1.3;
	}

	.account-handle {
		font-size: var(--text-sm);
		color: var(--text-secondary);
		white-space: nowrap;
		overflow: hidden;
		text-overflow: ellipsis;
		line-height: 1.3;
	}

	.footer-actions {
		display: flex;
		align-items: center;
		gap: var(--space-1);
		flex-shrink: 0;
	}

	.logout-btn:hover {
		color: var(--danger-text);
		background: var(--danger-bg);
	}

	.leave-confirm-dialog {
		inline-size: min(26rem, calc(100vw - 2rem));
	}

	.confirm-body {
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
		padding: var(--space-6);
	}

	.confirm-body h1 {
		font-size: var(--text-heading);
		font-weight: 650;
		letter-spacing: -0.015em;
		line-height: 1.3;
		color: var(--text-primary);
	}

	.confirm-copy {
		font-size: var(--text-body);
		color: var(--text-secondary);
		max-inline-size: 52ch;
	}

	.confirm-error {
		font-size: var(--text-sm);
		color: var(--danger-text);
	}

	.confirm-actions {
		display: flex;
		justify-content: flex-end;
		flex-wrap: wrap;
		gap: var(--space-2);
		margin-block-start: var(--space-2);
	}

	.btn-progress {
		inline-size: 1rem;
		block-size: 1rem;
		border-width: 2px;
		border-color: rgba(255, 255, 255, 0.35);
		border-top-color: #ffffff;
	}

	@media (max-width: 767px) {
		.sidebar {
			inline-size: 100%;
			border-inline-end: none;
		}

		.sidebar-collapse-btn {
			display: none;
		}

		.sidebar-footer {
			padding-block-end: calc(var(--space-2) + env(safe-area-inset-bottom));
		}
	}
</style>

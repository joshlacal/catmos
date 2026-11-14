<script lang="ts">
	import { conversations } from '#lib/stores/conversations.ts';
	import { isSameAccountDid, stripDidFragment } from '#lib/did.ts';
	import { auth } from '#lib/stores/auth.ts';
	import { drafts } from '#lib/stores/drafts.ts';
	import { profiles } from '#lib/stores/profiles.ts';
	import UserSearch from './UserSearch.svelte';
	import type { SearchResult } from '#lib/wasm.ts';
	import type { Conversation } from '#lib/tauri.ts';

	let {
		collapsed = false,
		theme = 'dark',
		requestNewConversation = false,
		onToggleCollapse,
		onToggleTheme,
		onNewConversationHandled
	}: {
		collapsed: boolean;
		theme: 'light' | 'dark';
		requestNewConversation?: boolean;
		onToggleCollapse: () => void;
		onToggleTheme: () => void;
		onNewConversationHandled?: () => void;
	} = $props();

	let showCreateDialog = $state(false);

	// Open create dialog when requested externally
	$effect(() => {
		if (requestNewConversation) {
			openCreateDialog();
			onNewConversationHandled?.();
		}
	});
	let newGroupName = $state('');
	let newGroupDescription = $state('');
	let selectedMembers = $state<SearchResult[]>([]);
	let creating = $state(false);
	let createError = $state('');

	// Resolve profiles for all conversation members so 1:1 chats show real names
	$effect(() => {
		const allDids = $conversations.items.flatMap((c) => c.members);
		if (allDids.length > 0) {
			profiles.resolveProfiles(allDids);
		}
	});

	/** For 1:1 conversations, resolve the other participant's display name from profiles. */
	function convoDisplayName(convo: Conversation): string {
		if (convo.isGroup) return convo.displayName;
		// For 1:1: find the other member's profile (ignoring #<deviceId> suffixes)
		const otherRaw =
			convo.members.find((did) => !isSameAccountDid(did, $auth.user?.did)) ?? convo.members[0];
		const otherDid = stripDidFragment(otherRaw);
		if (otherDid) {
			const profile = $profiles.cache.get(otherDid);
			if (profile) {
				return profile.displayName ?? profile.handle;
			}
		}
		// If displayName is just DIDs joined, show a shortened version while loading
		if (convo.displayName.startsWith('did:') && otherDid) {
			return otherDid.slice(0, 20) + '…';
		}
		return convo.displayName;
	}

	function selectConversation(id: string) {
		conversations.select(id);
	}

	function openCreateDialog() {
		showCreateDialog = true;
		newGroupName = '';
		newGroupDescription = '';
		selectedMembers = [];
		createError = '';
	}

	async function handleCreateGroup(e: SubmitEvent) {
		e.preventDefault();
		creating = true;
		createError = '';
		try {
			const memberDids = selectedMembers.map((m) => m.did);

			if (selectedMembers.length === 1) {
				const existingId = conversations.findDirectConversation(memberDids[0]);
				if (existingId) {
					conversations.select(existingId);
					showCreateDialog = false;
					return;
				}
				const displayName = selectedMembers[0].displayName || selectedMembers[0].handle;
				await conversations.createGroup(displayName, memberDids);
			} else {
				if (!newGroupName.trim()) return;
				const desc = newGroupDescription.trim() || undefined;
				await conversations.createGroup(newGroupName.trim(), memberDids, desc);
			}
			showCreateDialog = false;
		} catch (err) {
			createError = err instanceof Error ? err.message : String(err);
		} finally {
			creating = false;
		}
	}

	function formatTime(iso: string | undefined): string {
		if (!iso) return '';
		const d = new Date(iso);
		const now = new Date();
		if (d.toDateString() === now.toDateString()) {
			return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
		}
		const diff = now.getTime() - d.getTime();
		if (diff < 7 * 24 * 60 * 60 * 1000) {
			return d.toLocaleDateString([], { weekday: 'short' });
		}
		return d.toLocaleDateString([], { month: 'short', day: 'numeric' });
	}
</script>

<aside class="sidebar" class:collapsed>
	<div class="sidebar-header">
		<div class="sidebar-header-left">
			<button
				class="icon-btn sidebar-toggle"
				onclick={onToggleCollapse}
				title={collapsed ? 'Show sidebar' : 'Hide sidebar'}
				aria-label={collapsed ? 'Show sidebar' : 'Hide sidebar'}
			>
				<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
					<rect x="3" y="3" width="18" height="18" rx="2" ry="2" />
					<line x1="9" y1="3" x2="9" y2="21" />
				</svg>
			</button>
			<h1 class="app-title">Catmos</h1>
		</div>
		<button class="icon-btn" title="New conversation" onclick={openCreateDialog}>
			<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
				<path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" />
				<line x1="12" y1="8" x2="12" y2="14" />
				<line x1="9" y1="11" x2="15" y2="11" />
			</svg>
		</button>
	</div>

	<div class="conversations-list">
		{#each $conversations.items as convo (convo.id)}
			<button
				class="conversation-item"
				class:selected={$conversations.selectedId === convo.id}
				onclick={() => selectConversation(convo.id)}
			>
				<div class="convo-avatar" class:group={convo.isGroup}>
					{#if convo.avatarDataUrl}
						<img class="convo-avatar-img" src={convo.avatarDataUrl} alt="" />
					{:else if convo.isGroup}
						<svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor" opacity="0.7">
							<path d="M16 11c1.66 0 2.99-1.34 2.99-3S17.66 5 16 5c-1.66 0-3 1.34-3 3s1.34 3 3 3zm-8 0c1.66 0 2.99-1.34 2.99-3S9.66 5 8 5C6.34 5 5 6.34 5 8s1.34 3 3 3zm0 2c-2.33 0-7 1.17-7 3.5V19h14v-2.5c0-2.33-4.67-3.5-7-3.5zm8 0c-.29 0-.62.02-.97.05 1.16.84 1.97 1.97 1.97 3.45V19h6v-2.5c0-2.33-4.67-3.5-7-3.5z"/>
						</svg>
					{:else}
						{convoDisplayName(convo).charAt(0).toUpperCase()}
					{/if}
				</div>
				<div class="convo-body">
					<div class="convo-top-row">
						<span class="convo-name">{convoDisplayName(convo)}</span>
						<span class="convo-time">{formatTime(convo.lastMessageAt)}</span>
					</div>
					{#if $drafts.has(convo.id) && ($drafts.get(convo.id)?.trim().length ?? 0) > 0}
						<p class="convo-preview draft-preview">Draft</p>
					{:else if convo.lastMessage}
						<p class="convo-preview">{convo.lastMessage}</p>
					{:else if convo.description}
						<p class="convo-preview">{convo.description}</p>
					{:else}
						<p class="convo-preview empty">No messages yet</p>
					{/if}
				</div>
				{#if convo.unreadCount > 0}
					<span class="unread-badge">{convo.unreadCount}</span>
				{/if}
			</button>
		{/each}

		{#if $conversations.items.length === 0 && !$conversations.loading}
			<div class="empty-conversations">
				<p class="empty-text">No conversations yet</p>
				<p class="empty-hint">Start a new chat to get going</p>
			</div>
		{/if}
	</div>

	<div class="sidebar-footer">
		<div class="user-info">
			<div class="user-avatar">
				{#if $auth.user?.avatar}
					<img src={$auth.user.avatar} alt="" class="avatar-img" />
				{:else}
					{($auth.user?.displayName ?? $auth.user?.handle ?? '?').charAt(0).toUpperCase()}
				{/if}
			</div>
			<div class="user-details">
				{#if $auth.user?.displayName}
					<span class="user-name">{$auth.user.displayName}</span>
				{/if}
				<span class="user-handle">@{$auth.user?.handle ?? ''}</span>
			</div>
		</div>
		<div class="footer-actions">
			<a
				href="/settings/labyrinth"
				class="icon-btn"
				title="Labyrinth Backup & Security"
				aria-label="Labyrinth Backup and Security"
			>
				<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
					<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
				</svg>
			</a>
			<button class="icon-btn" onclick={onToggleTheme} title="Toggle theme">
				{#if theme === 'dark'}
					<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
						<circle cx="12" cy="12" r="5" />
						<line x1="12" y1="1" x2="12" y2="3" />
						<line x1="12" y1="21" x2="12" y2="23" />
						<line x1="4.22" y1="4.22" x2="5.64" y2="5.64" />
						<line x1="18.36" y1="18.36" x2="19.78" y2="19.78" />
						<line x1="1" y1="12" x2="3" y2="12" />
						<line x1="21" y1="12" x2="23" y2="12" />
						<line x1="4.22" y1="19.78" x2="5.64" y2="18.36" />
						<line x1="18.36" y1="5.64" x2="19.78" y2="4.22" />
					</svg>
				{:else}
					<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
						<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
					</svg>
				{/if}
			</button>
			<button class="icon-btn logout-btn" onclick={() => auth.logout()} title="Sign out">
				<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
					<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
					<polyline points="16 17 21 12 16 7" />
					<line x1="21" y1="12" x2="9" y2="12" />
				</svg>
			</button>
		</div>
	</div>
</aside>

{#if showCreateDialog}
	<div class="dialog-overlay" onclick={(e) => { if (e.target === e.currentTarget) showCreateDialog = false; }} role="presentation">
		<div class="dialog" role="dialog">
			<h3>{selectedMembers.length === 1 ? 'New Message' : 'New Group'}</h3>
			<form onsubmit={handleCreateGroup}>
				{#if selectedMembers.length !== 1}
					<input
						type="text"
						placeholder="Group name"
						bind:value={newGroupName}
						class="dialog-input"
					/>
					<textarea
						placeholder="Description (optional)"
						bind:value={newGroupDescription}
						class="dialog-input dialog-textarea"
						rows="2"
					></textarea>
				{/if}
				<div class="dialog-label">Add Members</div>
				<UserSearch bind:selected={selectedMembers} />
				{#if createError}
					<p class="dialog-error">{createError}</p>
				{/if}
				<div class="dialog-actions">
					<button type="button" class="btn btn-secondary" onclick={() => (showCreateDialog = false)}>
						Cancel
					</button>
					<button
						type="submit"
						class="btn btn-primary"
						disabled={creating || (selectedMembers.length !== 1 && !newGroupName.trim()) || selectedMembers.length === 0}
					>
						{creating ? 'Creating...' : selectedMembers.length === 1 ? 'Start Chat' : 'Create'}
					</button>
				</div>
			</form>
		</div>
	</div>
{/if}

<style>
	.sidebar {
		width: var(--sidebar-width);
		background: var(--bg-sidebar);
		display: flex;
		flex-direction: column;
		border-right: 1px solid var(--border);
		flex-shrink: 0;
		transition: width var(--transition-slow), opacity var(--transition-normal);
		overflow: hidden;
	}

	.sidebar.collapsed {
		width: 0;
		border-right: none;
	}

	.sidebar-header {
		height: var(--header-height);
		display: flex;
		align-items: center;
		justify-content: space-between;
		padding: 0 12px 0 8px;
		flex-shrink: 0;
	}

	.sidebar-header-left {
		display: flex;
		align-items: center;
		gap: 4px;
	}

	.app-title {
		font-size: 17px;
		font-weight: 700;
		color: var(--text-primary);
		letter-spacing: -0.02em;
	}

	.icon-btn {
		width: 34px;
		height: 34px;
		display: inline-flex;
		align-items: center;
		justify-content: center;
		border-radius: var(--radius-sm);
		color: var(--text-secondary);
		transition: all var(--transition-fast);
		flex-shrink: 0;
	}

	.icon-btn:hover {
		color: var(--text-primary);
		background: var(--bg-hover);
	}

	.conversations-list {
		flex: 1;
		overflow-y: auto;
		padding: 4px 8px;
	}

	.conversation-item {
		width: 100%;
		display: flex;
		align-items: center;
		gap: 12px;
		padding: 10px 12px;
		border-radius: var(--radius-md);
		text-align: left;
		transition: background var(--transition-fast);
		position: relative;
	}

	.conversation-item:hover {
		background: var(--bg-hover);
	}

	.conversation-item.selected {
		background: var(--bg-selected);
	}

	.convo-avatar {
		width: 40px;
		height: 40px;
		border-radius: var(--radius-full);
		background: var(--accent);
		color: var(--text-on-accent);
		display: flex;
		align-items: center;
		justify-content: center;
		font-weight: 600;
		font-size: 16px;
		flex-shrink: 0;
	}

	.convo-avatar.group {
		background: var(--bg-elevated);
		color: var(--text-secondary);
		border: 1px solid var(--border);
	}

	.convo-avatar-img {
		width: 100%;
		height: 100%;
		border-radius: inherit;
		object-fit: cover;
	}

	.convo-body {
		flex: 1;
		min-width: 0;
	}

	.convo-top-row {
		display: flex;
		justify-content: space-between;
		align-items: baseline;
		gap: 8px;
	}

	.convo-name {
		font-weight: 600;
		font-size: 14px;
		color: var(--text-primary);
		white-space: nowrap;
		overflow: hidden;
		text-overflow: ellipsis;
	}

	.convo-time {
		font-size: 12px;
		color: var(--text-tertiary);
		flex-shrink: 0;
	}

	.convo-preview {
		font-size: 13px;
		color: var(--text-secondary);
		white-space: nowrap;
		overflow: hidden;
		text-overflow: ellipsis;
		margin-top: 2px;
	}

	.convo-preview.empty {
		color: var(--text-tertiary);
		font-style: italic;
	}

	.convo-preview.draft-preview {
		color: var(--text-link);
		font-style: italic;
		opacity: 0.8;
	}

	.unread-badge {
		background: var(--accent);
		color: var(--text-on-accent);
		font-size: 11px;
		font-weight: 700;
		min-width: 20px;
		height: 20px;
		border-radius: var(--radius-full);
		display: flex;
		align-items: center;
		justify-content: center;
		padding: 0 6px;
		flex-shrink: 0;
	}

	.empty-conversations {
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
		padding: 48px 16px;
		text-align: center;
	}

	.empty-text {
		color: var(--text-secondary);
		font-size: 15px;
		font-weight: 500;
	}

	.empty-hint {
		color: var(--text-tertiary);
		font-size: 13px;
		margin-top: 4px;
	}

	.sidebar-footer {
		padding: 8px 12px;
		border-top: 1px solid var(--border);
		display: flex;
		align-items: center;
		justify-content: space-between;
		flex-shrink: 0;
	}

	.user-info {
		display: flex;
		align-items: center;
		gap: 10px;
		min-width: 0;
		flex: 1;
	}

	.user-avatar {
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
		flex-shrink: 0;
		overflow: hidden;
	}

	.user-details {
		display: flex;
		flex-direction: column;
		min-width: 0;
	}

	:global(.avatar-img) {
		width: 100%;
		height: 100%;
		object-fit: cover;
	}

	.user-name {
		font-size: 13px;
		font-weight: 600;
		color: var(--text-primary);
		white-space: nowrap;
		overflow: hidden;
		text-overflow: ellipsis;
	}

	.user-handle {
		font-size: 12px;
		color: var(--text-secondary);
		white-space: nowrap;
		overflow: hidden;
		text-overflow: ellipsis;
	}

	.footer-actions {
		display: flex;
		gap: 2px;
	}

	.logout-btn:hover {
		color: var(--danger);
	}

	/* ── Dialog ── */
	.dialog-overlay {
		position: fixed;
		inset: 0;
		background: var(--bg-overlay);
		display: flex;
		align-items: center;
		justify-content: center;
		z-index: 100;
		backdrop-filter: blur(4px);
		-webkit-backdrop-filter: blur(4px);
	}

	.dialog {
		background: var(--bg-card);
		border-radius: var(--radius-lg);
		border: 1px solid var(--border);
		padding: 24px;
		width: 400px;
		box-shadow: var(--shadow-lg);
	}

	.dialog h3 {
		color: var(--text-primary);
		font-size: 18px;
		font-weight: 700;
		margin-bottom: 20px;
		letter-spacing: -0.01em;
	}

	.dialog-input {
		display: block;
		width: 100%;
		padding: 10px 14px;
		background: var(--bg-input);
		border: 1px solid var(--border);
		border-radius: var(--radius-sm);
		color: var(--text-primary);
		margin-bottom: 12px;
		font-family: inherit;
		font-size: 14px;
		resize: vertical;
		transition: border-color var(--transition-fast);
	}

	.dialog-input:focus {
		border-color: var(--accent);
		outline: none;
	}

	.dialog-input::placeholder {
		color: var(--text-tertiary);
	}

	.dialog-textarea {
		min-height: 48px;
		max-height: 120px;
	}

	.dialog-label {
		font-size: 12px;
		font-weight: 600;
		text-transform: uppercase;
		color: var(--text-secondary);
		margin-bottom: 8px;
		letter-spacing: 0.04em;
	}

	.dialog-error {
		color: var(--danger);
		font-size: 13px;
		margin-bottom: 12px;
	}

	.dialog-actions {
		display: flex;
		justify-content: flex-end;
		gap: 8px;
		margin-top: 20px;
	}

	.btn {
		padding: 8px 18px;
		border-radius: var(--radius-sm);
		font-weight: 600;
		font-size: 14px;
		transition: all var(--transition-fast);
	}

	.btn-secondary {
		color: var(--text-primary);
		background: var(--bg-hover);
	}

	.btn-secondary:hover {
		background: var(--bg-active);
	}

	.btn-primary {
		background: var(--accent);
		color: var(--text-on-accent);
	}

	.btn-primary:hover:not(:disabled) {
		background: var(--accent-hover);
	}

	.btn-primary:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	@media (max-width: 768px) {
		.sidebar {
			width: 100%;
			height: 100dvh;
			border-right: none;
		}

		.sidebar.collapsed {
			display: none;
		}

		.sidebar-toggle {
			display: none;
		}

		.sidebar-footer {
			padding-bottom: calc(8px + env(safe-area-inset-bottom));
		}

		.dialog {
			width: min(100vw - 24px, 420px);
			padding: 20px;
		}
	}
</style>

<script lang="ts">
	import type { Conversation } from '#lib/wasm.ts';
	import { dedupeAccountDids, isSameAccountDid, stripDidFragment } from '#lib/did.ts';
	import { auth } from '#lib/stores/auth.ts';
	import { profiles, resolveProfileName } from '#lib/stores/profiles.ts';
	import { useRovingMenu } from '#lib/utils/popover.ts';
	import Avatar from './Avatar.svelte';
	import Icon from './Icon.svelte';

	let {
		conversation,
		sidebarCollapsed = false,
		showInspector = false,
		onBack,
		onExpandSidebar,
		onOpenSearch,
		onToggleInspector
	}: {
		conversation: Conversation;
		sidebarCollapsed?: boolean;
		showInspector?: boolean;
		onBack: () => void;
		onExpandSidebar: () => void;
		onOpenSearch: () => void;
		onToggleInspector: () => void;
	} = $props();

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

	let title = $derived.by(() => {
		if (conversation.isGroup) {
			return conversation.displayName.trim() || 'Group conversation';
		}
		if (otherDid) {
			if (otherProfile) {
				return resolveProfileName($profiles.cache, otherDid);
			}
			if (conversation.displayName && !conversation.displayName.startsWith('did:')) {
				return conversation.displayName;
			}
			return resolveProfileName($profiles.cache, otherDid);
		}
		return conversation.displayName || 'Conversation';
	});

	let avatarSrc = $derived.by(() => {
		if (conversation.isGroup) {
			return conversation.avatarDataUrl ?? null;
		}
		return otherProfile?.avatar ?? conversation.avatarDataUrl ?? null;
	});

	let dmHandle = $derived.by(() => {
		if (conversation.isGroup) return null;
		const raw = otherProfile?.handle?.trim();
		if (!raw || raw.startsWith('did:')) return null;
		const clean = raw.startsWith('@') ? raw : `@${raw}`;
		return clean === title ? null : clean;
	});

	let memberCountText = $derived.by(() => {
		const count = dedupeAccountDids(conversation.members).length || conversation.members.length;
		return count === 1 ? '1 member' : `${count} members`;
	});
</script>

<header class="chat-header">
	<div class="chat-header-left">
		<button
			type="button"
			class="header-nav-btn mobile-back-btn"
			onclick={onBack}
			aria-label="Back to conversations"
			title="Back to conversations"
		>
			<Icon name="chevron-left" size={20} />
		</button>

		{#if sidebarCollapsed}
			<button
				type="button"
				class="header-nav-btn desktop-expand-btn"
				onclick={onExpandSidebar}
				aria-label="Show conversations sidebar"
				title="Show sidebar (Cmd+B)"
			>
				<Icon name="sidebar" size={18} />
			</button>
		{/if}

		<Avatar
			src={avatarSrc}
			name={title}
			id={otherDid ?? conversation.id}
			size={34}
			shape={conversation.isGroup ? 'squircle' : 'circle'}
		/>

		<div class="chat-header-info">
			<h1 class="chat-title">{title}</h1>
			<p class="chat-meta">
				<span class="encryption-status">
					<Icon name="shield" size={13} class="encryption-shield" />
					<span>Encrypted</span>
				</span>

				{#if conversation.isGroup}
					<span class="meta-dot" aria-hidden="true">&middot;</span>
					<span class="meta-detail tabular-nums">{memberCountText}</span>
					{#if conversation.description}
						<span class="meta-dot meta-description-sep" aria-hidden="true">&middot;</span>
						<span class="meta-description">{conversation.description}</span>
					{/if}
				{:else if dmHandle}
					<span class="meta-dot" aria-hidden="true">&middot;</span>
					<span class="meta-detail">{dmHandle}</span>
				{/if}
			</p>
		</div>
	</div>

	<div
		class="chat-header-actions"
		role="toolbar"
		aria-label="Conversation actions"
		use:useRovingMenu={{ orientation: 'horizontal' }}
	>
		<button
			type="button"
			class="toolbar-btn"
			onclick={onOpenSearch}
			aria-label="Search messages"
			title="Search messages (Cmd+K)"
		>
			<Icon name="search" size={18} />
		</button>

		<button
			type="button"
			class="toolbar-btn"
			aria-pressed={showInspector}
			onclick={onToggleInspector}
			aria-label="Conversation details"
			title="Conversation details (Cmd+I)"
		>
			<Icon name="info" size={18} />
		</button>
	</div>
</header>

<style>
	.chat-header {
		min-block-size: var(--header-height);
		padding-inline: var(--space-4);
		padding-block: var(--space-2);
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: var(--space-3);
		border-block-end: 1px solid var(--border);
		background: var(--bg-sidebar);
		flex-shrink: 0;
		position: sticky;
		inset-block-start: 0;
		z-index: 5;
	}

	@supports (backdrop-filter: blur(1px)) {
		.chat-header {
			background: var(--glass-bg);
			backdrop-filter: var(--glass-filter);
			-webkit-backdrop-filter: var(--glass-filter);
		}
	}

	.chat-header-left {
		display: flex;
		align-items: center;
		gap: var(--space-3);
		min-inline-size: 0;
		flex: 1;
	}

	.header-nav-btn,
	.toolbar-btn {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		min-inline-size: max(2.25rem, var(--touch-min));
		min-block-size: max(2.25rem, var(--touch-min));
		border-radius: var(--radius-sm);
		color: var(--text-secondary);
		flex-shrink: 0;
		transition:
			background-color var(--dur-fast) var(--ease-out),
			color var(--dur-fast) var(--ease-out);
	}

	.header-nav-btn:hover,
	.toolbar-btn:hover {
		background: var(--bg-hover);
		color: var(--text-primary);
	}

	.header-nav-btn:active,
	.toolbar-btn:active {
		background: var(--bg-active);
	}

	.toolbar-btn[aria-pressed='true'] {
		background: var(--bg-selected);
		color: var(--text-link);
	}

	.mobile-back-btn {
		display: none;
		min-inline-size: 44px;
		min-block-size: 44px;
		margin-inline-start: calc(var(--space-2) * -1);
		color: var(--text-link);
	}

	.desktop-expand-btn {
		display: inline-flex;
	}

	.chat-header-info {
		min-inline-size: 0;
		flex: 1;
		display: flex;
		flex-direction: column;
		gap: 1px;
	}

	.chat-title {
		font-size: var(--text-heading);
		font-weight: 650;
		letter-spacing: -0.015em;
		line-height: 1.3;
		color: var(--text-primary);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.chat-meta {
		display: flex;
		align-items: center;
		gap: var(--space-1);
		font-size: var(--text-sm);
		line-height: 1.38;
		color: var(--text-secondary);
		min-inline-size: 0;
	}

	.encryption-status {
		display: inline-flex;
		align-items: center;
		gap: 0.25rem;
		flex-shrink: 0;
		color: var(--text-secondary);
	}

	.encryption-status :global(.encryption-shield) {
		color: var(--shield);
	}

	.meta-dot {
		color: var(--text-muted);
		flex-shrink: 0;
	}

	.meta-detail {
		color: var(--text-secondary);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.meta-description {
		color: var(--text-muted);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
		min-inline-size: 0;
	}

	.chat-header-actions {
		display: flex;
		align-items: center;
		gap: var(--space-1);
		flex-shrink: 0;
	}

	@media (max-width: 767px) {
		.chat-header {
			padding-inline: var(--space-3);
		}

		.chat-header-left {
			gap: var(--space-2);
		}

		.mobile-back-btn {
			display: inline-flex;
		}

		.desktop-expand-btn {
			display: none;
		}

		.meta-description,
		.meta-description-sep {
			display: none;
		}
	}
</style>

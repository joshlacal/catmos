<script lang="ts">
	import * as api from '$lib/wasm';
	import { auth } from '$lib/stores/auth';
	import { messages } from '$lib/stores/messages';

	let {
		reactions = {},
		conversationId,
		messageId
	}: {
		reactions: Record<string, string[]>;
		conversationId: string;
		messageId: string;
	} = $props();

	let showPicker = $state(false);

	const quickEmojis = ['👍', '❤️', '😂', '😮', '😢', '🔥'];

	function hasReacted(emoji: string): boolean {
		const userDid = $auth.user?.did;
		if (!userDid) return false;
		return reactions[emoji]?.includes(userDid) ?? false;
	}

	async function toggleReaction(emoji: string) {
		const session = $auth.user;
        const userDid = session?.did;
		if (!userDid) return;
		const action = hasReacted(emoji) ? 'remove' : 'add';

		messages.applyReaction({
			conversationId,
			messageId,
			senderDid: userDid,
			emoji,
			action
		});
		showPicker = false;

		try {
			await api.sendReaction(conversationId, messageId, emoji, action, userDid, session.authRevision);
		} catch (e) {
			console.error('Failed to send reaction:', e);
            if ($auth.user !== session) return;
			messages.applyReaction({
				conversationId,
				messageId,
				senderDid: userDid,
				emoji,
				action: action === 'add' ? 'remove' : 'add'
			});
		}
	}

	function handlePickerKeydown(e: KeyboardEvent) {
		if (e.key === 'Escape') showPicker = false;
	}
</script>

<div class="reactions-container" class:has-reactions={Object.keys(reactions).length > 0}>
	{#each Object.entries(reactions) as [emoji, users]}
		<button
			class="reaction-pill"
			class:reacted={hasReacted(emoji)}
			onclick={() => toggleReaction(emoji)}
			title={users.join(', ')}
		>
			<span class="reaction-emoji">{emoji}</span>
			<span class="reaction-count">{users.length}</span>
		</button>
	{/each}

	<div class="reaction-add-wrapper">
		<button
			class="reaction-add-btn"
			onclick={() => (showPicker = !showPicker)}
			title="Add reaction"
		>
			<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
				<circle cx="12" cy="12" r="10" />
				<path d="M8 14s1.5 2 4 2 4-2 4-2" />
				<line x1="9" y1="9" x2="9.01" y2="9" />
				<line x1="15" y1="9" x2="15.01" y2="9" />
			</svg>
		</button>

		{#if showPicker}
			<!-- svelte-ignore a11y_no_static_element_interactions -->
			<div class="reaction-picker" onkeydown={handlePickerKeydown}>
				{#each quickEmojis as emoji}
					<button
						class="picker-emoji"
						class:reacted={hasReacted(emoji)}
						onclick={() => toggleReaction(emoji)}
					>
						{emoji}
					</button>
				{/each}
			</div>
		{/if}
	</div>
</div>

<style>
	.reactions-container {
		display: flex;
		flex-wrap: wrap;
		gap: 4px;
		margin-top: 4px;
		min-height: 0;
	}

	.reactions-container:not(.has-reactions) .reaction-add-wrapper {
		opacity: 0;
		transition: opacity var(--transition-fast);
	}

	:global(.message-row:hover) .reactions-container .reaction-add-wrapper {
		opacity: 1;
	}

	.reaction-pill {
		display: inline-flex;
		align-items: center;
		gap: 4px;
		padding: 3px 10px;
		border-radius: var(--radius-full);
		background: var(--bg-hover);
		font-size: 13px;
		transition: all var(--transition-fast);
		cursor: pointer;
	}

	.reaction-pill:hover {
		background: var(--bg-active);
	}

	.reaction-pill.reacted {
		background: var(--bg-selected);
		outline: 1.5px solid var(--accent);
	}

	.reaction-emoji {
		font-size: 14px;
	}

	.reaction-count {
		font-size: 12px;
		color: var(--text-secondary);
		font-weight: 500;
	}

	.reaction-pill.reacted .reaction-count {
		color: var(--text-link);
	}

	.reaction-add-wrapper {
		position: relative;
	}

	.reaction-add-btn {
		width: 28px;
		height: 26px;
		border-radius: var(--radius-full);
		background: var(--bg-hover);
		color: var(--text-tertiary);
		display: flex;
		align-items: center;
		justify-content: center;
		transition: all var(--transition-fast);
	}

	.reaction-add-btn:hover {
		background: var(--bg-active);
		color: var(--text-secondary);
	}

	.reaction-picker {
		position: absolute;
		bottom: calc(100% + 6px);
		left: 0;
		display: flex;
		gap: 2px;
		padding: 6px;
		background: var(--bg-card);
		border: 1px solid var(--border);
		border-radius: var(--radius-md);
		box-shadow: var(--shadow-md);
		z-index: 10;
	}

	.picker-emoji {
		width: 34px;
		height: 34px;
		border-radius: var(--radius-sm);
		font-size: 18px;
		display: flex;
		align-items: center;
		justify-content: center;
		transition: all var(--transition-fast);
	}

	.picker-emoji:hover {
		background: var(--bg-hover);
		transform: scale(1.15);
	}

	.picker-emoji.reacted {
		background: var(--bg-selected);
	}
</style>

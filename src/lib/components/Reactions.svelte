<script module lang="ts">
	export const QUICK_REACTION_EMOJIS = ['👍', '❤️', '😂', '😮', '😢', '🔥'] as const;

	let nextPickerUid = 0;
</script>

<script lang="ts">
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
	import {
		positionPopoverFallback,
		useRovingMenu,
		type PopoverPlacement
	} from '#lib/utils/popover.ts';
	import { announce, showToast } from '#lib/utils/announcer.ts';
	import Icon from './Icon.svelte';

	let {
		reactions = {},
		conversationId,
		messageId,
		isOwn = false,
		showAddTrigger = true
	}: {
		reactions: Record<string, string[]>;
		conversationId: string;
		messageId: string;
		isOwn?: boolean;
		showAddTrigger?: boolean;
	} = $props();

	const pickerUid = ++nextPickerUid;
	const pickerId = `catmos-react-picker-${pickerUid}`;
	const anchorName = `--catmos-react-anchor-${pickerUid}`;

	let triggerEl: HTMLButtonElement | undefined = $state();
	let pickerEl: HTMLDivElement | undefined = $state();

	let placement = $derived<PopoverPlacement>(isOwn ? 'top-end' : 'bottom-start');

	let foldedReactions = $derived(foldReactionsByAccount(reactions));

	let reactionEntries = $derived(
		Object.entries(foldedReactions).filter(([, users]) => users.length > 0)
	);

	let allVoterDids = $derived.by(() => {
		const dids = new Set<string>();
		for (const [, users] of reactionEntries) {
			for (const did of users) {
				const bare = stripDidFragment(did);
				if (bare) dids.add(bare);
			}
		}
		return Array.from(dids);
	});

	$effect(() => {
		if (allVoterDids.length > 0) {
			profiles.resolveProfiles(allVoterDids);
		}
	});

	function hasReacted(emoji: string): boolean {
		return hasAccountReacted(foldedReactions, emoji, $auth.user?.did);
	}

	function resolveVoterList(dids: string[]): string {
		const myDid = $auth.user?.did;
		const names = dids.map((did) =>
			isSameAccountDid(did, myDid) ? 'You' : resolveProfileName($profiles.cache, did)
		);
		return names.join(', ');
	}

	function closePicker() {
		try {
			if (pickerEl && typeof pickerEl.hidePopover === 'function' && pickerEl.matches(':popover-open')) {
				pickerEl.hidePopover();
			}
		} catch {
			// Ignore if popover API is unavailable in test DOM
		}
	}

	function handlePickerToggle(event: Event) {
		const toggleEvent = event as ToggleEvent;
		if (toggleEvent.newState === 'open' && pickerEl && triggerEl) {
			positionPopoverFallback(pickerEl, triggerEl, placement, 6);
			requestAnimationFrame(() => {
				const firstBtn = pickerEl?.querySelector<HTMLButtonElement>('button');
				firstBtn?.focus();
			});
		}
	}

	async function toggleReaction(emoji: string) {
		const userDid = stripDidFragment($auth.user?.did);
		if (!userDid) return;
		const action: 'add' | 'remove' = hasReacted(emoji) ? 'remove' : 'add';

		messages.applyReaction({
			conversationId,
			messageId,
			senderDid: userDid,
			emoji,
			action
		});
		closePicker();
		announce(action === 'add' ? `Added ${emoji} reaction` : `Removed ${emoji} reaction`);

		try {
			await api.sendReaction(conversationId, messageId, emoji, action);
		} catch (err) {
			console.error('[catmos] Failed to send reaction:', err);
			messages.applyReaction({
				conversationId,
				messageId,
				senderDid: userDid,
				emoji,
				action: action === 'add' ? 'remove' : 'add'
			});
			showToast({
				message: 'Could not update reaction.',
				tone: 'error'
			});
		}
	}
</script>

{#if reactionEntries.length > 0 || showAddTrigger}
	<div class="reactions-row" class:own={isOwn}>
		{#each reactionEntries as [emoji, users] (emoji)}
			{@const reacted = hasReacted(emoji)}
			{@const voterNames = resolveVoterList(users)}
			<button
				type="button"
				class="reaction-pill"
				aria-pressed={reacted}
				onclick={() => toggleReaction(emoji)}
				title={voterNames}
				aria-label={`${emoji} ${users.length}, reacted by ${voterNames}. ${
					reacted ? 'Remove your reaction' : 'Add your reaction'
				}`}
			>
				<span class="reaction-emoji" aria-hidden="true">{emoji}</span>
				<span class="reaction-count tabular-nums">{users.length}</span>
			</button>
		{/each}

		{#if showAddTrigger}
			<button
				bind:this={triggerEl}
				type="button"
				class="reaction-add-btn"
				popovertarget={pickerId}
				style={`anchor-name: ${anchorName};`}
				aria-label="Add reaction"
				title="Add reaction"
			>
				<Icon name="smile" size={15} />
			</button>
			<div
				bind:this={pickerEl}
				id={pickerId}
				popover="auto"
				class="catmos-popover reaction-picker"
				data-anchored="true"
				data-placement={placement}
				style={`position-anchor: ${anchorName};`}
				ontoggle={handlePickerToggle}
				use:useRovingMenu={{ orientation: 'horizontal' }}
			>
				{#each QUICK_REACTION_EMOJIS as emoji (emoji)}
					{@const active = hasReacted(emoji)}
					<button
						type="button"
						class="picker-emoji"
						aria-pressed={active}
						onclick={() => toggleReaction(emoji)}
						aria-label={active ? `Remove ${emoji} reaction` : `React with ${emoji}`}
					>
						{emoji}
					</button>
				{/each}
			</div>
		{/if}
	</div>
{/if}

<style>
	.reactions-row {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: var(--space-1);
		margin-block-start: var(--space-1);
	}

	.reactions-row.own {
		justify-content: flex-end;
	}

	.reaction-pill {
		display: inline-flex;
		align-items: center;
		gap: var(--space-1);
		min-block-size: max(1.75rem, var(--touch-min));
		padding-block: 0.1875rem;
		padding-inline: 0.625rem;
		border-radius: var(--radius-full);
		background: var(--bg-surface);
		border: 1px solid var(--border);
		color: var(--text-primary);
		font-size: var(--text-sm);
		line-height: 1.2;
		transition:
			background-color var(--dur-fast) var(--ease-out),
			border-color var(--dur-fast) var(--ease-out),
			color var(--dur-fast) var(--ease-out);
	}

	.reaction-pill:hover {
		background: var(--bg-hover);
		border-color: var(--border-strong);
	}

	.reaction-pill[aria-pressed='true'] {
		background: var(--bg-selected);
		border-color: var(--accent-fill);
		color: var(--text-link);
	}

	.reaction-emoji {
		font-size: var(--text-body);
		line-height: 1;
	}

	.reaction-count {
		font-size: var(--text-sm);
		font-weight: 600;
		color: var(--text-secondary);
	}

	.reaction-pill[aria-pressed='true'] .reaction-count {
		color: var(--text-link);
	}

	.reaction-add-btn {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		min-inline-size: max(1.75rem, var(--touch-min));
		min-block-size: max(1.75rem, var(--touch-min));
		border-radius: var(--radius-full);
		background: var(--bg-surface);
		border: 1px solid var(--border);
		color: var(--text-secondary);
		transition:
			background-color var(--dur-fast) var(--ease-out),
			border-color var(--dur-fast) var(--ease-out),
			color var(--dur-fast) var(--ease-out);
	}

	.reaction-add-btn:hover {
		background: var(--bg-hover);
		border-color: var(--border-strong);
		color: var(--text-primary);
	}

	.reaction-picker {
		min-inline-size: auto;
		padding: var(--space-1);
		border-radius: var(--radius-full);
	}

	.reaction-picker:popover-open {
		display: flex;
		align-items: center;
		gap: 2px;
	}

	.picker-emoji {
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
		.picker-emoji {
			transition:
				background-color var(--dur-fast) var(--ease-out),
				transform var(--dur-fast) var(--ease-out);
		}

		.picker-emoji:hover {
			transform: scale(1.12);
		}
	}

	.picker-emoji:hover {
		background: var(--bg-hover);
	}

	.picker-emoji[aria-pressed='true'] {
		background: var(--bg-selected);
	}
</style>

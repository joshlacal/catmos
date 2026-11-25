<script lang="ts">
	/**
	 * Svelte 5 compatibility wrapper around `ConversationInspector.svelte`.
	 * Resolves the conversation by ID from `$conversations.items` and forwards
	 * optional Layer 3 quarantine state.
	 */
	import type { QuarantineState } from '#lib/wasm.ts';
	import { conversations } from '#lib/stores/conversations.ts';
	import ConversationInspector from './ConversationInspector.svelte';

	let {
		conversationId,
		quarantine = null,
		onClose,
		onLeftConversation
	}: {
		conversationId: string;
		/** Layer 3 quarantine state for this conversation, if any. */
		quarantine?: QuarantineState | null;
		onClose?: () => void;
		onLeftConversation?: (convoId: string) => void;
	} = $props();

	const resolvedConversation = $derived(
		$conversations.items.find((item) => item.id === conversationId) ?? null
	);

	const fallbackError = $derived(
		!resolvedConversation && conversationId
			? 'Conversation details are currently unavailable.'
			: null
	);
</script>

{#if resolvedConversation}
	<ConversationInspector
		conversation={resolvedConversation}
		open={true}
		quarantineState={quarantine}
		onClose={() => onClose?.()}
		{onLeftConversation}
	/>
{:else if fallbackError}
	<aside class="member-list-fallback" aria-label="Conversation details">
		<p class="member-action-error" role="alert">{fallbackError}</p>
	</aside>
{/if}

<style>
	.member-list-fallback {
		inline-size: var(--inspector-width);
		flex-shrink: 0;
		background: var(--bg-sidebar);
		border-inline-start: 1px solid var(--border);
		padding: var(--space-4);
	}

	.member-action-error {
		padding: var(--space-3);
		border-radius: var(--radius-sm);
		background: var(--danger-bg);
		color: var(--danger-text);
		font-size: var(--text-sm);
		line-height: 1.4;
	}
</style>

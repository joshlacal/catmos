<script lang="ts">
	import type { Message } from '#lib/wasm.ts';
	import { stripDidFragment } from '#lib/did.ts';
	import { profiles, resolveProfileName } from '#lib/stores/profiles.ts';
	import { extractMessagePreview } from '#lib/stores/conversations.ts';
	import Icon from './Icon.svelte';

	let {
		message,
		onCancel
	}: {
		message: Message;
		onCancel: () => void;
	} = $props();

	let senderAccountDid = $derived(stripDidFragment(message.senderDid));

	$effect(() => {
		if (senderAccountDid) {
			profiles.resolveProfiles([senderAccountDid]);
		}
	});

	let senderName = $derived.by(() => {
		if (!senderAccountDid) return stripDidFragment(message.senderHandle) || 'Unknown';
		const cached = $profiles.cache.get(senderAccountDid);
		if (cached) {
			return resolveProfileName($profiles.cache, senderAccountDid);
		}
		const cleanHandle = stripDidFragment(message.senderHandle);
		if (cleanHandle && !cleanHandle.startsWith('did:')) {
			return cleanHandle.startsWith('@') ? cleanHandle : `@${cleanHandle}`;
		}
		return resolveProfileName($profiles.cache, senderAccountDid);
	});

	let previewText = $derived.by(() => {
		const plain = extractMessagePreview(message.content);
		if (plain) {
			return plain.length > 140 ? `${plain.slice(0, 140)}...` : plain;
		}
		if (message.image) return message.image.altText || 'Photo';
		if (message.audio ?? message.audioAttachment) return 'Voice message';
		if (message.embed?.type === 'post') return 'Shared post';
		if (message.embed?.type === 'link') {
			const title = message.embed.data.title;
			return typeof title === 'string' && title.trim() ? title.trim() : 'Shared link';
		}
		if (message.embed?.type === 'gif') return 'GIF';
		return 'Message';
	});
</script>

<div class="reply-preview" role="region" aria-label="Replying to message">
	<div class="reply-content">
		<span class="reply-sender">Replying to {senderName}</span>
		<span class="reply-text">{previewText}</span>
	</div>
	<button
		type="button"
		class="reply-cancel"
		onclick={onCancel}
		aria-label="Cancel reply"
		title="Cancel reply"
	>
		<Icon name="x" size={16} />
	</button>
</div>

<style>
	.reply-preview {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		padding-block: var(--space-2);
		padding-inline: var(--space-3);
		margin-block-end: var(--space-2);
		background: var(--bg-surface);
		border-inline-start: 3px solid var(--accent-fill);
		border-radius: 0 var(--radius-sm) var(--radius-sm) 0;
	}

	.reply-content {
		flex: 1;
		min-inline-size: 0;
		display: flex;
		flex-direction: column;
		gap: 2px;
	}

	.reply-sender {
		font-size: var(--text-sm);
		font-weight: 600;
		line-height: 1.35;
		color: var(--text-link);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.reply-text {
		font-size: var(--text-sm);
		line-height: 1.38;
		color: var(--text-secondary);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.reply-cancel {
		flex-shrink: 0;
		min-inline-size: max(1.75rem, var(--touch-min));
		min-block-size: max(1.75rem, var(--touch-min));
		display: inline-flex;
		align-items: center;
		justify-content: center;
		border-radius: var(--radius-sm);
		color: var(--text-secondary);
		transition:
			background-color var(--dur-fast) var(--ease-out),
			color var(--dur-fast) var(--ease-out);
	}

	.reply-cancel:hover {
		color: var(--text-primary);
		background: var(--bg-hover);
	}
</style>

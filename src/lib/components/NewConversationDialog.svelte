<script lang="ts">
	import { describeCreateConversationError } from '#lib/chat-errors.ts';
	import type { SearchResult } from '#lib/wasm.ts';
	import { stripDidFragment } from '#lib/did.ts';
	import { auth } from '#lib/stores/auth.ts';
	import { conversations } from '#lib/stores/conversations.ts';
	import { useDialogLightDismiss, closeWithReset } from '#lib/utils/dialog.ts';
	import { announce, showToast } from '#lib/utils/announcer.ts';
	import Icon from './Icon.svelte';
	import UserSearch from './UserSearch.svelte';

	type CreationMode = 'direct' | 'group';

	let {
		open = false,
		onClose,
		onCreated
	}: {
		open: boolean;
		onClose: () => void;
		onCreated?: (convoId: string) => void;
	} = $props();

	let dialogEl: HTMLDialogElement | null = $state(null);
	let groupNameInputEl: HTMLInputElement | null = $state(null);

	let mode = $state<CreationMode>('direct');
	let groupName = $state('');
	let groupDescription = $state('');
	let selectedMembers = $state<SearchResult[]>([]);
	let creating = $state(false);
	let nameError = $state('');
	let membersError = $state('');
	let submitError = $state('');

	function resetForm() {
		mode = 'direct';
		groupName = '';
		groupDescription = '';
		selectedMembers = [];
		creating = false;
		nameError = '';
		membersError = '';
		submitError = '';
	}

	$effect(() => {
		if (!dialogEl) return;
		if (open) {
			if (!dialogEl.open) {
				resetForm();
				dialogEl.showModal();
			}
		} else if (dialogEl.open) {
			closeWithReset(dialogEl);
		}
	});

	function handleModeChange(nextMode: CreationMode) {
		mode = nextMode;
		nameError = '';
		membersError = '';
		submitError = '';
		if (nextMode === 'direct' && selectedMembers.length > 1) {
			selectedMembers = selectedMembers.slice(0, 1);
		}
	}

	function handleDialogClose() {
		if (dialogEl) {
			dialogEl.returnValue = '';
		}
		if (open) {
			onClose();
		}
	}

	function requestClose() {
		if (creating) return;
		closeWithReset(dialogEl, 'cancel');
	}

	async function handleSubmit(event: SubmitEvent) {
		event.preventDefault();
		if (creating) return;

		nameError = '';
		membersError = '';
		submitError = '';

		if (mode === 'group' && !groupName.trim()) {
			nameError = 'Enter a group name.';
			groupNameInputEl?.focus();
			return;
		}

		if (selectedMembers.length === 0) {
			membersError =
				mode === 'direct'
					? 'Select a Bluesky account to start a direct message.'
					: 'Select at least one member for this group.';
			const searchInput = dialogEl?.querySelector<HTMLInputElement>('#new-convo-user-search');
			searchInput?.focus();
			return;
		}

		creating = true;
		try {
			const memberDids = selectedMembers.map((m) => stripDidFragment(m.did) || m.did);

			if (mode === 'direct') {
				const recipient = selectedMembers[0];
				const recipientDid = stripDidFragment(recipient.did) || recipient.did;
				const recipientName = recipient.displayName || `@${recipient.handle}`;
				const existingId = conversations.findDirectConversation(recipientDid);
				if (existingId) {
					conversations.select(existingId);
					creating = false;
					closeWithReset(dialogEl, 'created');
					announce(`Opened existing conversation with ${recipientName}`);
					onCreated?.(existingId);
					return;
				}
				const created = await conversations.createGroup(
					recipient.displayName || recipient.handle,
					[recipientDid]
				);
				creating = false;
				closeWithReset(dialogEl, 'created');
				showToast({ message: `Started chat with ${recipientName}`, tone: 'success' });
				onCreated?.(created.id);
				return;
			}

			const trimmedName = groupName.trim();
			const trimmedDesc = groupDescription.trim() || undefined;
			const created = await conversations.createGroup(trimmedName, memberDids, trimmedDesc);
			creating = false;
			closeWithReset(dialogEl, 'created');
			showToast({ message: `Created group "${trimmedName}"`, tone: 'success' });
			onCreated?.(created.id);
		} catch (err) {
			creating = false;
			console.error('[catmos] create conversation failed', err);
			submitError = describeCreateConversationError(err, mode).message;
		}
	}

	const excludedDids = $derived(
		$auth.user?.did ? [stripDidFragment($auth.user.did)].filter(Boolean) : []
	);
</script>

<dialog
	bind:this={dialogEl}
	class="catmos-dialog new-convo-dialog"
	closedby="any"
	use:useDialogLightDismiss
	onclose={handleDialogClose}
>
	<header class="dialog-header">
		<h1>New conversation</h1>
		<button
			type="button"
			class="dialog-close-btn"
			onclick={requestClose}
			disabled={creating}
			aria-label="Close dialog"
		>
			<Icon name="x" size={18} />
		</button>
	</header>

	<form class="dialog-form" onsubmit={handleSubmit} novalidate>
		<div class="dialog-scroll">
			<fieldset class="catmos-segmented mode-switch">
				<legend class="visually-hidden">Conversation type</legend>
				<label>
					<input
						type="radio"
						name="new-convo-mode"
						value="direct"
						checked={mode === 'direct'}
						onchange={() => handleModeChange('direct')}
					/>
					<span>Direct message</span>
				</label>
				<label>
					<input
						type="radio"
						name="new-convo-mode"
						value="group"
						checked={mode === 'group'}
						onchange={() => handleModeChange('group')}
					/>
					<span>Group chat</span>
				</label>
			</fieldset>

			{#if mode === 'group'}
				<div class="field-group">
					<label for="new-group-name" class="field-label">Group name</label>
					<p id="new-group-name-hint" class="field-hint">
						Visible to everyone in this encrypted group.
					</p>
					<input
						bind:this={groupNameInputEl}
						id="new-group-name"
						type="text"
						class="field-input"
						bind:value={groupName}
						oninput={() => {
							if (nameError && groupName.trim()) nameError = '';
						}}
						required
						maxlength={100}
						placeholder="Design review"
						aria-invalid={nameError ? 'true' : 'false'}
						aria-describedby={nameError
							? 'new-group-name-hint new-group-name-error'
							: 'new-group-name-hint'}
					/>
					{#if nameError}
						<p id="new-group-name-error" class="field-error" role="alert">{nameError}</p>
					{/if}
				</div>

				<div class="field-group">
					<label for="new-group-desc" class="field-label">Description (optional)</label>
					<input
						id="new-group-desc"
						type="text"
						class="field-input"
						bind:value={groupDescription}
						maxlength={240}
						placeholder="Topic or purpose for this group"
					/>
				</div>
			{/if}

			<div class="field-group">
				<label for="new-convo-user-search" class="field-label">
					{mode === 'direct' ? 'Recipient' : 'Members'}
				</label>
				<p class="field-hint">
					{#if mode === 'direct'}
						Search for a Bluesky handle to start a private MLS chat.
					{:else}
						Search and select Bluesky accounts to invite.
					{/if}
				</p>
				<UserSearch
					bind:selected={selectedMembers}
					mode={mode === 'direct' ? 'single' : 'multiple'}
					inputId="new-convo-user-search"
					placeholder="Search by Bluesky name or handle..."
					excludeDids={excludedDids}
				/>
				{#if membersError}
					<p class="field-error" role="alert">{membersError}</p>
				{/if}
			</div>

			{#if submitError}
				<div class="submit-error" role="alert">
					<Icon name="alert-triangle" size={16} />
					<span>{submitError}</span>
				</div>
			{/if}
		</div>

		<footer class="dialog-footer">
			<button
				type="button"
				class="catmos-btn-secondary"
				onclick={requestClose}
				disabled={creating}
			>
				Cancel
			</button>
			<button type="submit" class="catmos-btn-primary" disabled={creating}>
				{#if creating}
					<progress class="catmos-progress btn-progress" aria-label="Creating conversation"></progress>
					<span>Creating...</span>
				{:else}
					<span>{mode === 'direct' ? 'Start chat' : 'Create group'}</span>
				{/if}
			</button>
		</footer>
	</form>
</dialog>

<style>
	.new-convo-dialog {
		inline-size: min(31rem, calc(100vw - 2rem));
	}

	.dialog-header {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: var(--space-3);
		padding: var(--space-4) var(--space-5);
		border-block-end: 1px solid var(--border);
		flex-shrink: 0;
	}

	.dialog-header h1 {
		font-size: var(--text-heading);
		font-weight: 650;
		letter-spacing: -0.015em;
		line-height: 1.3;
		color: var(--text-primary);
	}

	.dialog-close-btn {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		min-inline-size: max(2rem, var(--touch-min));
		min-block-size: max(2rem, var(--touch-min));
		border-radius: var(--radius-sm);
		color: var(--text-secondary);
		transition:
			background-color var(--dur-fast) var(--ease-out),
			color var(--dur-fast) var(--ease-out);
	}

	.dialog-close-btn:hover:not(:disabled) {
		background: var(--bg-hover);
		color: var(--text-primary);
	}

	.dialog-form {
		display: flex;
		flex-direction: column;
		min-block-size: 0;
		flex: 1;
	}

	.dialog-scroll {
		display: flex;
		flex-direction: column;
		gap: var(--space-4);
		padding: var(--space-5);
		overflow-y: auto;
		min-block-size: 0;
		flex: 1;
	}

	.mode-switch {
		width: 100%;
	}

	.field-group {
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
	}

	.field-label {
		font-size: var(--text-sm);
		font-weight: 600;
		color: var(--text-primary);
	}

	.field-hint {
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}

	.field-input {
		display: block;
		width: 100%;
		min-block-size: max(2.5rem, var(--touch-min));
		padding-inline: var(--space-3);
		padding-block: var(--space-2);
		background: var(--bg-input);
		border: 1px solid var(--border-input);
		border-radius: var(--radius-sm);
		color: var(--text-primary);
		font-size: var(--text-body);
		transition: border-color var(--dur-fast) var(--ease-out);
	}

	.field-input:focus {
		border-color: var(--focus-ring);
		outline: none;
	}

	.field-input[aria-invalid='true'] {
		border-color: var(--danger-text);
	}

	.field-input::placeholder {
		color: var(--text-muted);
	}

	.field-error {
		font-size: var(--text-sm);
		color: var(--danger-text);
	}

	.submit-error {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		padding: var(--space-2) var(--space-3);
		border-radius: var(--radius-sm);
		background: var(--danger-bg);
		border: 1px solid var(--danger-text);
		color: var(--danger-text);
		font-size: var(--text-sm);
	}

	.dialog-footer {
		display: flex;
		justify-content: flex-end;
		flex-wrap: wrap;
		gap: var(--space-2);
		padding: var(--space-4) var(--space-5);
		border-block-start: 1px solid var(--border);
		flex-shrink: 0;
	}

	.btn-progress {
		inline-size: 1rem;
		block-size: 1rem;
		border-width: 2px;
		border-color: rgba(255, 255, 255, 0.35);
		border-top-color: #ffffff;
	}
</style>

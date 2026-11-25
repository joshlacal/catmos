<script lang="ts">
	/**
	 * Unified DM and Group conversation inspector.
	 *
	 * Responsive dual-mode rendering:
	 * - Desktop (>= 1024px): inline `<aside class="inspector">` when `open` is true.
	 * - Tablet & mobile (< 1024px): native `<dialog class="catmos-dialog catmos-dialog--drawer">`
	 *   opened with `showModal()` so the message list is never squeezed.
	 */
	import { onMount } from 'svelte';
	import {
		addGroupMembers,
		confirmManualReset,
		demoteMember,
		getGroupMembers,
		promoteMember,
		removeGroupMember,
		reportSpam,
		resetGroup,
		updateGroupMetadata,
		type Conversation,
		type GroupMember,
		type QuarantineState,
		type SearchResult
	} from '#lib/wasm.ts';
	import {
		dedupeAccountDids,
		foldGroupMembersByAccount,
		isSameAccountDid,
		stripDidFragment
	} from '#lib/did.ts';
	import { auth } from '#lib/stores/auth.ts';
	import { profiles, resolveProfileName, shortDid } from '#lib/stores/profiles.ts';
	import {
		affectedConversationsFor,
		blockAndLeave,
		conversations
	} from '#lib/stores/conversations.ts';
	import { quarantine, quarantineReasonCopy } from '#lib/stores/quarantine.ts';
	import { preferences, toggleMute, togglePin } from '#lib/stores/preferences.ts';
	import {
		closeWithReset,
		useDialogLightDismiss,
		useDialogSafeAutofocus
	} from '#lib/utils/dialog.ts';
	import { positionPopoverFallback, useRovingMenu } from '#lib/utils/popover.ts';
	import { formatClockTime, formatSidebarTime } from '#lib/utils/time.ts';
	import { announce, showToast } from '#lib/utils/announcer.ts';
	import Avatar from './Avatar.svelte';
	import Icon from './Icon.svelte';
	import UserSearch from './UserSearch.svelte';

	let {
		conversation,
		open = false,
		quarantineState = null,
		onClose,
		onLeftConversation
	}: {
		conversation: Conversation;
		open?: boolean;
		quarantineState?: QuarantineState | null;
		onClose: () => void;
		onLeftConversation?: (convoId: string) => void;
	} = $props();

	type ConfirmKind =
		| 'promote'
		| 'demote'
		| 'remove'
		| 'block'
		| 'leave'
		| 'reset-encryption';

	interface PendingConfirm {
		kind: ConfirmKind;
		did?: string;
		name: string;
		affectedCount?: number;
	}

	const DESKTOP_MQ = '(min-width: 1024px)';

	let isDesktop = $state(
		typeof window !== 'undefined' && typeof window.matchMedia === 'function'
			? window.matchMedia(DESKTOP_MQ).matches
			: true
	);

	let drawerDialog = $state<HTMLDialogElement | null>(null);
	let confirmDialog = $state<HTMLDialogElement | null>(null);
	let reportDialog = $state<HTMLDialogElement | null>(null);
	let addMembersDialog = $state<HTMLDialogElement | null>(null);

	let members = $state<GroupMember[]>([]);
	let membersLoading = $state(false);
	let membersError = $state<string | null>(null);
	let actionError = $state<string | null>(null);
	let processingDid = $state<string | null>(null);

	// Group metadata inline editing state
	let editingMetadata = $state(false);
	let editName = $state('');
	let editDescription = $state('');
	let savingMetadata = $state(false);
	let metadataError = $state<string | null>(null);
	let editNameInput = $state<HTMLInputElement | null>(null);

	// Confirmation dialog state
	let pendingConfirm = $state<PendingConfirm | null>(null);
	let confirmBusy = $state(false);
	let confirmError = $state<string | null>(null);

	// Report spam dialog state
	let reportTarget = $state<{ did: string; name: string } | null>(null);
	let reportReason = $state('');
	let reportBusy = $state(false);
	let reportError = $state<string | null>(null);

	// Add members dialog state
	let addMemberSelection = $state<SearchResult[]>([]);
	let addingMembers = $state(false);
	let addMembersError = $state<string | null>(null);

	let loadMembersSeq = 0;
	let closingDrawerInternally = false;

	function applySwitchAttr(node: HTMLInputElement) {
		node.setAttribute('switch', '');
		return {
			destroy() {}
		};
	}

	function isAdminRole(role: string | undefined): boolean {
		return Boolean(role && role.toLowerCase().includes('admin'));
	}

	function formatQuarantineSince(sinceMs: number): string {
		const sidebar = formatSidebarTime(sinceMs);
		const clock = formatClockTime(sinceMs);
		if (!sidebar && !clock) return '';
		if (!sidebar) return clock;
		if (!clock || sidebar === clock) return `Today, ${clock}`;
		return `${sidebar}, ${clock}`;
	}

	onMount(() => {
		if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return;
		const mq = window.matchMedia(DESKTOP_MQ);
		isDesktop = mq.matches;

		const handleChange = (event: MediaQueryListEvent) => {
			isDesktop = event.matches;
		};

		if (typeof mq.addEventListener === 'function') {
			mq.addEventListener('change', handleChange);
			return () => mq.removeEventListener('change', handleChange);
		}
		mq.addListener(handleChange);
		return () => mq.removeListener(handleChange);
	});

	// Sync mobile/tablet native modal drawer with `open` and breakpoint.
	$effect(() => {
		const dialog = drawerDialog;
		if (!dialog) return;

		if (!isDesktop && open) {
			if (!dialog.open) {
				dialog.showModal();
			}
		} else if (dialog.open) {
			closingDrawerInternally = true;
			closeWithReset(dialog);
			closingDrawerInternally = false;
		}
	});

	function handleDrawerClose() {
		if (drawerDialog) {
			drawerDialog.returnValue = '';
		}
		if (closingDrawerInternally) return;
		if (!isDesktop && open) {
			onClose();
		}
	}

	// Reactive derived values from stores
	const myDid = $derived(stripDidFragment($auth.user?.did));

	const otherDmDid = $derived.by(() => {
		if (conversation.isGroup) return null;
		const otherRaw =
			conversation.members.find((did) => !isSameAccountDid(did, myDid)) ??
			conversation.members[0] ??
			null;
		const bare = stripDidFragment(otherRaw);
		return bare || otherRaw;
	});

	const otherDmProfile = $derived(
		otherDmDid ? $profiles.cache.get(stripDidFragment(otherDmDid)) : undefined
	);

	const resolvedTitle = $derived.by(() => {
		if (conversation.isGroup) {
			return conversation.displayName.trim() || 'Untitled group';
		}
		if (otherDmDid) {
			return resolveProfileName($profiles.cache, otherDmDid);
		}
		return conversation.displayName.trim() || 'Direct message';
	});

	const resolvedAvatar = $derived.by(() => {
		if (conversation.isGroup) {
			return conversation.avatarDataUrl ?? null;
		}
		return otherDmProfile?.avatar ?? conversation.avatarDataUrl ?? null;
	});

	const dmHandle = $derived.by(() => {
		if (conversation.isGroup || !otherDmDid) return null;
		const handle = otherDmProfile?.handle?.trim();
		if (handle && !handle.startsWith('did:')) {
			return handle.startsWith('@') ? handle : `@${handle}`;
		}
		return shortDid(otherDmDid);
	});

	const isCurrentUserAdmin = $derived.by(() => {
		if (!conversation.isGroup || !myDid) return false;
		return members.some((m) => isSameAccountDid(m.did, myDid) && isAdminRole(m.role));
	});

	const activeQuarantine = $derived(quarantineState ?? $quarantine[conversation.id] ?? null);
	const isConvoPinned = $derived($preferences.pinnedIds.includes(conversation.id));
	const isConvoMuted = $derived(
		$preferences.mutedIds.includes(conversation.id) || Boolean(conversation.mutedUntil)
	);
	const existingMemberDids = $derived(
		dedupeAccountDids(members.length > 0 ? members.map((m) => m.did) : conversation.members)
	);
	const effectiveMemberCount = $derived(
		conversation.isGroup && members.length > 0
			? members.length
			: dedupeAccountDids(conversation.members).length || conversation.members.length
	);
	const securityGroupId = $derived(conversation.groupId || conversation.id);

	// Resolve member profiles whenever conversation membership changes.
	$effect(() => {
		if (conversation.members.length > 0) {
			profiles.resolveProfiles(conversation.members);
		}
	});

	// Load group members with stale-conversation sequence guard.
	async function loadMembers(targetConvoId: string) {
		const seq = ++loadMembersSeq;
		membersLoading = true;
		membersError = null;
		try {
			const fetched = await getGroupMembers(targetConvoId);
			if (seq !== loadMembersSeq || conversation.id !== targetConvoId) return;
			const folded = foldGroupMembersByAccount(fetched);
			members = folded;
			const dids = folded.map((m) => m.did).filter(Boolean);
			if (dids.length > 0) {
				profiles.resolveProfiles(dids);
			}
		} catch (err) {
			if (seq !== loadMembersSeq || conversation.id !== targetConvoId) return;
			members = [];
			membersError = err instanceof Error ? err.message : 'Could not load group members.';
		} finally {
			if (seq === loadMembersSeq) {
				membersLoading = false;
			}
		}
	}

	$effect(() => {
		const convoId = conversation.id;
		const isGroup = conversation.isGroup;

		editingMetadata = false;
		metadataError = null;
		actionError = null;
		addMemberSelection = [];
		addMembersError = null;

		if (confirmDialog?.open && !confirmBusy) {
			closeWithReset(confirmDialog);
		}
		if (reportDialog?.open && !reportBusy) {
			closeWithReset(reportDialog);
		}
		if (addMembersDialog?.open && !addingMembers) {
			closeWithReset(addMembersDialog);
		}

		if (isGroup && convoId) {
			void loadMembers(convoId);
		} else {
			loadMembersSeq += 1;
			members = [];
			membersLoading = false;
			membersError = null;
		}
	});

	// Resolve suspected DIDs if quarantine is active.
	$effect(() => {
		if (activeQuarantine && activeQuarantine.suspectedDids.length > 0) {
			profiles.resolveProfiles(activeQuarantine.suspectedDids);
		}
	});

	function memberSubtitle(member: GroupMember): string {
		const accountDid = stripDidFragment(member.did);
		const profile = accountDid ? $profiles.cache.get(accountDid) : undefined;
		const profileHandle = profile?.handle?.trim();
		const memberHandle = stripDidFragment(member.handle);
		let identityLabel = shortDid(accountDid || member.did);
		if (profileHandle && !profileHandle.startsWith('did:')) {
			identityLabel = profileHandle.startsWith('@') ? profileHandle : `@${profileHandle}`;
		} else if (memberHandle && !memberHandle.startsWith('did:')) {
			identityLabel = memberHandle.startsWith('@') ? memberHandle : `@${memberHandle}`;
		}

		const parts = [identityLabel];
		if (isAdminRole(member.role)) {
			parts.push('Admin');
		}
		if (isSameAccountDid(member.did, myDid)) {
			parts.push('You');
		}
		return parts.join(' · ');
	}

	// Group metadata edit handlers
	function startEditMetadata() {
		editName = conversation.displayName;
		editDescription = conversation.description ?? '';
		metadataError = null;
		editingMetadata = true;
	}

	function cancelEditMetadata() {
		if (savingMetadata) return;
		editingMetadata = false;
		metadataError = null;
	}

	async function handleSaveMetadata(event: SubmitEvent) {
		event.preventDefault();
		if (savingMetadata) return;

		const nextName = editName.trim();
		const nextDescription = editDescription.trim();
		if (!nextName) {
			metadataError = 'Enter a group name.';
			editNameInput?.focus();
			return;
		}

		const targetConvoId = conversation.id;
		savingMetadata = true;
		metadataError = null;
		try {
			await updateGroupMetadata(targetConvoId, nextName, nextDescription);
			conversations.updateConversation({
				...conversation,
				displayName: nextName,
				description: nextDescription || undefined
			});
			editingMetadata = false;
			showToast({ message: 'Group details updated.', tone: 'success' });
		} catch (err) {
			const message = err instanceof Error ? err.message : String(err);
			metadataError = message || 'Could not update group details.';
			announce(metadataError, 'assertive');
		} finally {
			savingMetadata = false;
		}
	}

	// Preference switches
	function handleTogglePin() {
		const pinnedNow = togglePin(conversation.id);
		showToast({
			message: pinnedNow ? 'Conversation pinned.' : 'Conversation unpinned.',
			tone: 'info'
		});
	}

	function handleToggleMute() {
		const mutedNow = toggleMute(conversation.id);
		showToast({
			message: mutedNow ? 'Notifications muted.' : 'Notifications unmuted.',
			tone: 'info'
		});
	}

	async function handleCopyGroupId() {
		const value = securityGroupId;
		if (!value) return;
		try {
			if (typeof navigator !== 'undefined' && navigator.clipboard?.writeText) {
				await navigator.clipboard.writeText(value);
				showToast({ message: 'Group ID copied.', tone: 'success' });
				return;
			}
			throw new Error('Clipboard unavailable');
		} catch {
			showToast({ message: 'Could not copy group ID.', tone: 'error' });
		}
	}

	// Popover positioning fallback for member overflow menu
	function handleMemberMenuToggle(event: Event, popoverId: string) {
		const toggleEvent = event as ToggleEvent;
		if (toggleEvent.newState !== 'open') return;
		const popoverEl = event.currentTarget as HTMLElement | null;
		const triggerEl =
			(popoverEl?.previousElementSibling as HTMLElement | null) ??
			document.querySelector<HTMLElement>(`[popovertarget="${popoverId}"]`);
		if (popoverEl && triggerEl) {
			positionPopoverFallback(popoverEl, triggerEl, 'bottom-end');
		}
	}

	function hidePopoverById(popoverId: string) {
		const el = document.getElementById(popoverId) as HTMLElement | null;
		if (!el) return;
		try {
			if (typeof el.hidePopover === 'function' && el.matches(':popover-open')) {
				el.hidePopover();
			}
		} catch {
			// Ignore if already closed
		}
	}

	// Confirmation dialog orchestration
	function openConfirm(confirm: PendingConfirm, popoverId?: string) {
		if (popoverId) {
			hidePopoverById(popoverId);
		}
		if (confirm.kind === 'block' && confirm.did) {
			confirm = {
				...confirm,
				affectedCount: affectedConversationsFor(confirm.did).length
			};
		}
		pendingConfirm = confirm;
		confirmError = null;
		if (confirmDialog && !confirmDialog.open) {
			confirmDialog.showModal();
		}
	}

	function cancelConfirm() {
		if (confirmBusy) return;
		confirmError = null;
		closeWithReset(confirmDialog, 'cancel');
	}

	function handleConfirmDialogClose() {
		if (confirmDialog) {
			confirmDialog.returnValue = '';
		}
		if (!confirmBusy) {
			pendingConfirm = null;
			confirmError = null;
		}
	}

	const confirmCopy = $derived.by(() => {
		const item = pendingConfirm;
		if (!item) {
			return {
				title: '',
				description: '',
				actionLabel: 'Confirm',
				danger: false
			};
		}
		switch (item.kind) {
			case 'promote':
				return {
					title: `Promote ${item.name} to admin?`,
					description: `${item.name} will be able to edit group details, add or remove members, and manage admin roles.`,
					actionLabel: 'Promote to admin',
					danger: false
				};
			case 'demote':
				return {
					title: `Demote ${item.name} to member?`,
					description: `${item.name} will stay in this group as a member and will no longer have admin permissions.`,
					actionLabel: 'Demote to member',
					danger: false
				};
			case 'remove':
				return {
					title: `Remove ${item.name}?`,
					description: `${item.name} will be removed from this group and will stop receiving new messages.`,
					actionLabel: 'Remove from group',
					danger: true
				};
			case 'block': {
				const count = item.affectedCount ?? 0;
				const description =
					count > 0
						? `You will leave ${count} shared conversation${count === 1 ? '' : 's'}. This cannot be undone, and unblocking later will not rejoin you.`
						: `You will no longer see each other's posts or receive messages from ${item.name}.`;
				return {
					title: `Block ${item.name}?`,
					description,
					actionLabel: 'Block user',
					danger: true
				};
			}
			case 'leave':
				return {
					title: conversation.isGroup ? 'Leave this group?' : 'Leave this conversation?',
					description: conversation.isGroup
						? 'You will stop receiving messages in this group. An admin will need to add you again to rejoin.'
						: 'You will leave this conversation and stop receiving new messages from it.',
					actionLabel: conversation.isGroup ? 'Leave group' : 'Leave conversation',
					danger: true
				};
			case 'reset-encryption':
				return {
					title: 'Reset encryption session?',
					description:
						'Resetting creates a new encrypted epoch for current members so messaging can recover. Previous messages remain in your local history.',
					actionLabel: 'Reset session',
					danger: false
				};
		}
	});

	async function executeConfirm() {
		if (!pendingConfirm || confirmBusy) return;
		const { kind, did, name } = pendingConfirm;
		const targetConvoId = conversation.id;

		confirmBusy = true;
		confirmError = null;
		actionError = null;
		if (did) {
			processingDid = stripDidFragment(did) || did;
		}

		try {
			const targetDid = did ? stripDidFragment(did) || did : undefined;
			if (kind === 'promote' && targetDid) {
				await promoteMember(targetConvoId, targetDid);
				closeWithReset(confirmDialog, 'confirmed');
				await loadMembers(targetConvoId);
				showToast({ message: `${name} is now an admin.`, tone: 'success' });
			} else if (kind === 'demote' && targetDid) {
				await demoteMember(targetConvoId, targetDid);
				closeWithReset(confirmDialog, 'confirmed');
				await loadMembers(targetConvoId);
				showToast({ message: `${name} is now a member.`, tone: 'success' });
			} else if (kind === 'remove' && targetDid) {
				await removeGroupMember(targetConvoId, targetDid);
				closeWithReset(confirmDialog, 'confirmed');
				await loadMembers(targetConvoId);
				showToast({ message: `${name} was removed from the group.`, tone: 'info' });
			} else if (kind === 'block' && targetDid) {
				const leftIds = await blockAndLeave(targetDid);
				closeWithReset(confirmDialog, 'confirmed');
				showToast({ message: `Blocked ${name}.`, tone: 'info' });
				if (leftIds.includes(targetConvoId)) {
					onLeftConversation?.(targetConvoId);
					onClose();
				} else if (conversation.isGroup) {
					await loadMembers(targetConvoId);
				}
			} else if (kind === 'leave') {
				await conversations.leaveConversation(targetConvoId);
				closeWithReset(confirmDialog, 'confirmed');
				showToast({
					message: conversation.isGroup ? 'Left group.' : 'Left conversation.',
					tone: 'info'
				});
				onLeftConversation?.(targetConvoId);
				onClose();
			} else if (kind === 'reset-encryption') {
				if (activeQuarantine) {
					await confirmManualReset(targetConvoId);
				} else {
					await resetGroup(targetConvoId, 'Manual encryption session reset');
				}
				closeWithReset(confirmDialog, 'confirmed');
				await quarantine.refresh(targetConvoId);
				showToast({
					message: 'Encryption session reset requested.',
					tone: 'success'
				});
			}
		} catch (err) {
			const message = err instanceof Error ? err.message : String(err);
			const resolvedMessage = message || 'Action could not be completed.';
			confirmError = resolvedMessage;
			actionError = resolvedMessage;
			announce(resolvedMessage, 'assertive');
		} finally {
			confirmBusy = false;
			processingDid = null;
		}
	}

	// Report spam dialog
	function openReportSpam(did: string, name: string, popoverId?: string) {
		if (popoverId) {
			hidePopoverById(popoverId);
		}
		reportTarget = { did, name };
		reportReason = '';
		reportError = null;
		if (reportDialog && !reportDialog.open) {
			reportDialog.showModal();
		}
	}

	function cancelReportSpam() {
		if (reportBusy) return;
		reportError = null;
		closeWithReset(reportDialog, 'cancel');
	}

	function handleReportDialogClose() {
		if (reportDialog) {
			reportDialog.returnValue = '';
		}
		if (!reportBusy) {
			reportTarget = null;
			reportReason = '';
			reportError = null;
		}
	}

	async function submitReportSpam(event: SubmitEvent) {
		event.preventDefault();
		if (!reportTarget || reportBusy) return;

		const target = reportTarget;
		const targetConvoId = conversation.id;
		reportBusy = true;
		reportError = null;
		try {
			await reportSpam(targetConvoId, target.did, reportReason.trim() || undefined);
			closeWithReset(reportDialog, 'confirmed');
			showToast({ message: `Reported ${target.name} as spam.`, tone: 'success' });
		} catch (err) {
			const message = err instanceof Error ? err.message : String(err);
			reportError = message || 'Could not submit spam report.';
			announce(reportError, 'assertive');
		} finally {
			reportBusy = false;
		}
	}

	// Add members dialog
	function openAddMembersDialog() {
		addMemberSelection = [];
		addMembersError = null;
		if (addMembersDialog && !addMembersDialog.open) {
			addMembersDialog.showModal();
		}
	}

	function cancelAddMembers() {
		if (addingMembers) return;
		addMembersError = null;
		closeWithReset(addMembersDialog, 'cancel');
	}

	function handleAddMembersClose() {
		if (addMembersDialog) {
			addMembersDialog.returnValue = '';
		}
		if (!addingMembers) {
			addMemberSelection = [];
			addMembersError = null;
		}
	}

	async function handleAddMembersSubmit(event: SubmitEvent) {
		event.preventDefault();
		if (addingMembers) return;

		const existingDids = new Set(existingMemberDids);
		const newDids = dedupeAccountDids(addMemberSelection.map((u) => u.did)).filter(
			(did) => !existingDids.has(did)
		);

		if (addMemberSelection.length === 0) {
			addMembersError = 'Select at least one person to add.';
			return;
		}
		if (newDids.length === 0) {
			addMembersError = 'Selected people are already in this group.';
			return;
		}

		const targetConvoId = conversation.id;
		addingMembers = true;
		addMembersError = null;
		actionError = null;
		try {
			await addGroupMembers(targetConvoId, newDids);
			closeWithReset(addMembersDialog, 'confirmed');
			await loadMembers(targetConvoId);
			showToast({
				message: `Added ${newDids.length} member${newDids.length === 1 ? '' : 's'}.`,
				tone: 'success'
			});
		} catch (err) {
			const message = err instanceof Error ? err.message : String(err);
			const resolvedMessage = message || 'Could not add members.';
			addMembersError = resolvedMessage;
			actionError = resolvedMessage;
			announce(resolvedMessage, 'assertive');
		} finally {
			addingMembers = false;
		}
	}
</script>

{#snippet inspectorContent(isModal: boolean)}
	<div class="inspector-topbar">
		<span class="inspector-topbar-label">Conversation details</span>
		<button
			type="button"
			class="close-btn"
			aria-label="Close conversation details"
			onclick={onClose}
		>
			<Icon name="x" size={18} />
		</button>
	</div>

	<div class="inspector-scroll">
		<!-- Identity section -->
		<section class="inspector-section identity-section" aria-label="Identity">
			<div class="identity-header">
				<Avatar
					src={resolvedAvatar}
					name={resolvedTitle}
					id={conversation.isGroup ? conversation.id : (otherDmDid ?? conversation.id)}
					size={56}
					shape={conversation.isGroup ? 'squircle' : 'circle'}
				/>

				{#if !editingMetadata}
					<div class="identity-text">
						{#if isModal}
							<h1 class="identity-title">{resolvedTitle}</h1>
						{:else}
							<h2 class="identity-title">{resolvedTitle}</h2>
						{/if}

						{#if !conversation.isGroup && dmHandle && dmHandle !== resolvedTitle}
							<p class="identity-subtitle">{dmHandle}</p>
						{:else if conversation.isGroup && conversation.description}
							<p class="identity-subtitle">{conversation.description}</p>
						{/if}
					</div>

					{#if conversation.isGroup && isCurrentUserAdmin}
						<button
							type="button"
							class="edit-toggle-btn"
							onclick={startEditMetadata}
						>
							<Icon name="edit" size={15} />
							<span>Edit</span>
						</button>
					{/if}
				{/if}
			</div>

			{#if editingMetadata && conversation.isGroup}
				<form class="metadata-form" onsubmit={handleSaveMetadata} novalidate>
					<div class="field-group">
						<label class="field-label" for="inspector-group-name">Group name</label>
						<input
							bind:this={editNameInput}
							id="inspector-group-name"
							class="field-input"
							type="text"
							maxlength="100"
							required
							aria-invalid={metadataError ? 'true' : 'false'}
							bind:value={editName}
							disabled={savingMetadata}
						/>
					</div>

					<div class="field-group">
						<label class="field-label" for="inspector-group-desc">
							Description (optional)
						</label>
						<textarea
							id="inspector-group-desc"
							class="field-textarea"
							rows="3"
							maxlength="300"
							placeholder="What is this group about?"
							bind:value={editDescription}
							disabled={savingMetadata}
						></textarea>
					</div>

					{#if metadataError}
						<p class="inline-error" role="alert">{metadataError}</p>
					{/if}

					<div class="metadata-actions">
						<button
							type="button"
							class="catmos-btn-secondary btn-compact"
							onclick={cancelEditMetadata}
							disabled={savingMetadata}
						>
							Cancel
						</button>
						<button
							type="submit"
							class="catmos-btn-primary btn-compact"
							disabled={savingMetadata}
						>
							{savingMetadata ? 'Saving...' : 'Save'}
						</button>
					</div>
				</form>
			{/if}
		</section>

		<!-- Preferences section -->
		<section class="inspector-section" aria-label="Conversation preferences">
			{#if isModal}
				<h2 class="section-heading">Preferences</h2>
			{:else}
				<h3 class="section-heading">Preferences</h3>
			{/if}

			<div class="pref-list">
				<label class="pref-row" for="inspector-pin-switch">
					<span class="pref-label">
						<Icon name="pin" size={16} />
						<span>Pin conversation</span>
					</span>
					<input
						id="inspector-pin-switch"
						type="checkbox"
						role="switch"
						class="catmos-switch"
						use:applySwitchAttr
						checked={isConvoPinned}
						onchange={handleTogglePin}
					/>
				</label>

				<label class="pref-row" for="inspector-mute-switch">
					<span class="pref-label">
						<Icon name={isConvoMuted ? 'bell-off' : 'bell'} size={16} />
						<span>Mute notifications</span>
					</span>
					<input
						id="inspector-mute-switch"
						type="checkbox"
						role="switch"
						class="catmos-switch"
						use:applySwitchAttr
						checked={isConvoMuted}
						onchange={handleToggleMute}
					/>
				</label>
			</div>
		</section>

		<!-- Encryption and security section -->
		<section class="inspector-section" aria-label="Encryption and security">
			{#if isModal}
				<h2 class="section-heading">Encryption and security</h2>
			{:else}
				<h3 class="section-heading">Encryption and security</h3>
			{/if}

			<div class="encryption-status">
				<span class="shield-icon" aria-hidden="true">
					<Icon name="shield" size={16} />
				</span>
				<span>End-to-end encrypted with MLS</span>
			</div>

			{#if activeQuarantine}
				<div class="quarantine-note">
					<span class="quarantine-note-icon" aria-hidden="true">
						<Icon name="shield-alert" size={16} />
					</span>
					<div class="quarantine-note-copy">
						<p class="quarantine-note-title">Conversation paused</p>
						<p class="quarantine-note-text">
							{quarantineReasonCopy(activeQuarantine.reasonTag)}
						</p>
					</div>
				</div>
			{/if}

			<details class="security-details">
				<summary class="security-summary">Security details</summary>
				<div class="security-details-body">
					<dl class="security-dl">
						<dt>Group ID</dt>
						<dd class="group-id-cell">
							<code class="mono">{securityGroupId}</code>
							<button
								type="button"
								class="copy-btn"
								onclick={handleCopyGroupId}
								aria-label="Copy group ID"
							>
								<Icon name="copy" size={14} />
								<span>Copy</span>
							</button>
						</dd>

						<dt>Members</dt>
						<dd class="tabular-nums">{effectiveMemberCount}</dd>

						{#if activeQuarantine}
							<dt>Quarantine status</dt>
							<dd>Paused</dd>

							<dt>Reason code</dt>
							<dd><code class="mono">{activeQuarantine.reasonTag}</code></dd>

							<dt>Paused since</dt>
							<dd class="tabular-nums">
								{formatQuarantineSince(activeQuarantine.sinceMs)}
							</dd>

							<dt>Suspected devices</dt>
							<dd>
								{#if activeQuarantine.suspectedDids.length === 0}
									<span class="muted-note">
										None identified. Likely a framing failure burst.
									</span>
								{:else}
									<ul class="suspected-dids" role="list">
										{#each activeQuarantine.suspectedDids as did (did)}
											<li><code class="mono">{did}</code></li>
										{/each}
									</ul>
								{/if}
							</dd>
						{/if}
					</dl>

					<button
						type="button"
						class="catmos-btn-secondary btn-compact reset-session-btn"
						onclick={() =>
							openConfirm({
								kind: 'reset-encryption',
								name: resolvedTitle
							})}
					>
						<Icon name="refresh" size={15} />
						<span>Reset encryption session</span>
					</button>
				</div>
			</details>
		</section>

		<!-- Members section (Groups only) -->
		{#if conversation.isGroup}
			<section class="inspector-section" aria-label="Group members">
				<div class="section-header-row">
					{#if isModal}
						<h2 class="section-heading tabular-nums">
							Members ({effectiveMemberCount})
						</h2>
					{:else}
						<h3 class="section-heading tabular-nums">
							Members ({effectiveMemberCount})
						</h3>
					{/if}

					{#if isCurrentUserAdmin}
						<button
							type="button"
							class="add-members-btn"
							onclick={openAddMembersDialog}
						>
							<Icon name="user-plus" size={15} />
							<span>Add members</span>
						</button>
					{/if}
				</div>

				{#if membersLoading && members.length === 0}
					<div class="members-status">
						<progress class="catmos-progress" aria-label="Loading members"></progress>
						<span>Loading members...</span>
					</div>
				{:else if membersError}
					<div class="members-error" role="alert">
						<p>{membersError}</p>
						<button
							type="button"
							class="catmos-btn-secondary btn-compact"
							onclick={() => loadMembers(conversation.id)}
						>
							Try again
						</button>
					</div>
				{:else}
					<ul class="member-list" role="list">
						{#each members as member, idx (member.did)}
							{@const accountDid = stripDidFragment(member.did)}
							{@const profile = accountDid ? $profiles.cache.get(accountDid) : undefined}
							{@const displayName = resolveProfileName($profiles.cache, member.did)}
							{@const subtitle = memberSubtitle(member)}
							{@const memberIsAdmin = isAdminRole(member.role)}
							{@const isSelf = isSameAccountDid(member.did, myDid)}
							{@const popoverId = `inspector-member-menu-${isModal ? 'modal' : 'aside'}-${idx}`}
							{@const anchorName = `--inspector-member-${isModal ? 'modal' : 'aside'}-${idx}`}
							<li class="member-row">
								<Avatar
									src={profile?.avatar ?? null}
									name={displayName}
									id={accountDid || member.did}
									size={36}
									shape="circle"
								/>
								<div class="member-info">
									<span class="member-name">{displayName}</span>
									<span class="member-subtitle">{subtitle}</span>
								</div>

								{#if isSameAccountDid(processingDid, member.did)}
									<progress
										class="catmos-progress member-spinner"
										aria-label={`Updating ${displayName}`}
									></progress>
								{:else if !isSelf}
									<button
										type="button"
										class="member-more-btn"
										popovertarget={popoverId}
										aria-label={`Actions for ${displayName}`}
										style={`anchor-name: ${anchorName};`}
									>
										<Icon name="more-horizontal" size={18} />
									</button>
									<div
										id={popoverId}
										popover="auto"
										class="catmos-popover member-popover"
										data-anchored="true"
										data-placement="bottom-end"
										style={`position-anchor: ${anchorName};`}
										use:useRovingMenu
										ontoggle={(e) => handleMemberMenuToggle(e, popoverId)}
									>
										{#if isCurrentUserAdmin}
											{#if memberIsAdmin}
												<button
													type="button"
													class="menu-item"
													onclick={() =>
														openConfirm(
															{
																kind: 'demote',
																did: member.did,
																name: displayName
															},
															popoverId
														)}
												>
													<Icon name="user" size={16} />
													<span>Demote to member</span>
												</button>
											{:else}
												<button
													type="button"
													class="menu-item"
													onclick={() =>
														openConfirm(
															{
																kind: 'promote',
																did: member.did,
																name: displayName
															},
															popoverId
														)}
												>
													<Icon name="shield" size={16} />
													<span>Promote to admin</span>
												</button>
											{/if}
											<button
												type="button"
												class="menu-item menu-item--danger"
												onclick={() =>
													openConfirm(
														{
															kind: 'remove',
															did: member.did,
															name: displayName
														},
														popoverId
													)}
											>
												<Icon name="x" size={16} />
												<span>Remove from group</span>
											</button>
										{/if}
										<button
											type="button"
											class="menu-item menu-item--danger"
											onclick={() =>
												openConfirm(
													{
														kind: 'block',
														did: member.did,
														name: displayName
													},
													popoverId
												)}
										>
											<Icon name="ban" size={16} />
											<span>Block user</span>
										</button>
										<button
											type="button"
											class="menu-item menu-item--danger"
											onclick={() =>
												openReportSpam(member.did, displayName, popoverId)}
										>
											<Icon name="flag" size={16} />
											<span>Report spam</span>
										</button>
									</div>
								{/if}
							</li>
						{/each}
					</ul>
				{/if}
			</section>
		{/if}

		<!-- Safety and danger actions (works for both DMs and Groups) -->
		<section class="inspector-section danger-section" aria-label="Safety and danger actions">
			{#if isModal}
				<h2 class="section-heading">Safety</h2>
			{:else}
				<h3 class="section-heading">Safety</h3>
			{/if}

			{#if actionError}
				<div class="action-error-banner">
					<p class="member-action-error" role="alert">{actionError}</p>
					<button
						type="button"
						class="dismiss-error-btn"
						aria-label="Dismiss error"
						onclick={() => {
							actionError = null;
						}}
					>
						<Icon name="x" size={14} />
					</button>
				</div>
			{/if}

			<div class="danger-actions">
				{#if !conversation.isGroup && otherDmDid}
					<button
						type="button"
						class="danger-row-btn"
						onclick={() =>
							openConfirm({
								kind: 'block',
								did: otherDmDid,
								name: resolvedTitle
							})}
					>
						<Icon name="ban" size={16} />
						<span class="danger-row-label">Block {resolvedTitle}</span>
					</button>

					<button
						type="button"
						class="danger-row-btn"
						onclick={() => openReportSpam(otherDmDid, resolvedTitle)}
					>
						<Icon name="flag" size={16} />
						<span class="danger-row-label">Report spam</span>
					</button>
				{/if}

				<button
					type="button"
					class="danger-row-btn"
					onclick={() =>
						openConfirm({
							kind: 'leave',
							name: resolvedTitle
						})}
				>
					<Icon name="log-out" size={16} />
					<span class="danger-row-label">
						{conversation.isGroup ? 'Leave group' : 'Leave conversation'}
					</span>
				</button>
			</div>
		</section>
	</div>
{/snippet}

{#if isDesktop}
	{#if open}
		<aside class="inspector" aria-label="Conversation details">
			{@render inspectorContent(false)}
		</aside>
	{/if}
{:else}
	<dialog
		bind:this={drawerDialog}
		class="catmos-dialog catmos-dialog--drawer inspector-drawer"
		closedby="any"
		use:useDialogLightDismiss
		onclose={handleDrawerClose}
	>
		{@render inspectorContent(true)}
	</dialog>
{/if}

<!-- Shared confirmation dialog for destructive and security actions -->
<dialog
	bind:this={confirmDialog}
	class="catmos-dialog modal-dialog"
	closedby="any"
	use:useDialogLightDismiss
	onclose={handleConfirmDialogClose}
>
	<div class="modal-inner">
		<h1 class="modal-title">{confirmCopy.title}</h1>
		<p class="modal-description">{confirmCopy.description}</p>

		{#if confirmBusy}
			<div class="modal-busy">
				<progress class="catmos-progress" aria-label="Working"></progress>
				<span>Working...</span>
			</div>
		{/if}

		{#if confirmError}
			<div class="modal-error" role="alert">
				<Icon name="alert-triangle" size={16} />
				<span>{confirmError}</span>
			</div>
		{/if}

		<div class="modal-actions">
			<button
				type="button"
				class="catmos-btn-secondary"
				use:useDialogSafeAutofocus
				disabled={confirmBusy}
				onclick={cancelConfirm}
			>
				Cancel
			</button>
			<button
				type="button"
				class={confirmCopy.danger ? 'catmos-btn-danger' : 'catmos-btn-primary'}
				disabled={confirmBusy}
				onclick={executeConfirm}
			>
				{confirmBusy ? 'Working...' : confirmCopy.actionLabel}
			</button>
		</div>
	</div>
</dialog>

<!-- Report spam dialog -->
<dialog
	bind:this={reportDialog}
	class="catmos-dialog modal-dialog"
	closedby="any"
	use:useDialogLightDismiss
	onclose={handleReportDialogClose}
>
	<form class="modal-inner" onsubmit={submitReportSpam}>
		<h1 class="modal-title">Report spam</h1>
		<p class="modal-description">
			Report <strong>{reportTarget?.name ?? 'this account'}</strong> for spam in this
			conversation.
		</p>

		<div class="field-group">
			<label class="field-label" for="inspector-report-reason">Reason (optional)</label>
			<textarea
				id="inspector-report-reason"
				class="field-textarea"
				rows="3"
				maxlength="1000"
				placeholder="Describe why you are reporting this account..."
				bind:value={reportReason}
				disabled={reportBusy}
			></textarea>
		</div>

		{#if reportError}
			<div class="modal-error" role="alert">
				<Icon name="alert-triangle" size={16} />
				<span>{reportError}</span>
			</div>
		{/if}

		<div class="modal-actions">
			<button
				type="button"
				class="catmos-btn-secondary"
				use:useDialogSafeAutofocus
				disabled={reportBusy}
				onclick={cancelReportSpam}
			>
				Cancel
			</button>
			<button type="submit" class="catmos-btn-danger" disabled={reportBusy}>
				{reportBusy ? 'Submitting...' : 'Submit report'}
			</button>
		</div>
	</form>
</dialog>

<!-- Add members dialog (Group admins) -->
<dialog
	bind:this={addMembersDialog}
	class="catmos-dialog modal-dialog add-members-dialog"
	closedby="any"
	use:useDialogLightDismiss
	onclose={handleAddMembersClose}
>
	<form class="modal-inner" onsubmit={handleAddMembersSubmit}>
		<div class="modal-header">
			<h1 class="modal-title">Add members</h1>
			<button
				type="button"
				class="close-btn"
				aria-label="Close add members"
				disabled={addingMembers}
				onclick={cancelAddMembers}
			>
				<Icon name="x" size={18} />
			</button>
		</div>

		<p class="modal-description">
			Search Bluesky accounts to add to this encrypted group.
		</p>

		<UserSearch
			bind:selected={addMemberSelection}
			inputId="inspector-add-members-search"
			excludeDids={existingMemberDids}
		/>

		{#if addMembersError}
			<div class="modal-error" role="alert">
				<Icon name="alert-triangle" size={16} />
				<span>{addMembersError}</span>
			</div>
		{/if}

		<div class="modal-actions">
			<button
				type="button"
				class="catmos-btn-secondary"
				use:useDialogSafeAutofocus
				disabled={addingMembers}
				onclick={cancelAddMembers}
			>
				Cancel
			</button>
			<button type="submit" class="catmos-btn-primary" disabled={addingMembers}>
				{addingMembers ? 'Adding...' : 'Add members'}
			</button>
		</div>
	</form>
</dialog>

<style>
	.inspector {
		inline-size: var(--inspector-width);
		flex-shrink: 0;
		background: var(--bg-sidebar);
		border-inline-start: 1px solid var(--border);
		display: flex;
		flex-direction: column;
		min-block-size: 0;
		overflow: hidden;
	}

	.inspector-drawer {
		background: var(--bg-sidebar);
	}

	.inspector-topbar {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: var(--space-2);
		min-block-size: var(--header-height);
		padding-inline: var(--space-4);
		border-block-end: 1px solid var(--border);
		flex-shrink: 0;
	}

	.inspector-topbar-label {
		font-size: var(--text-body);
		font-weight: 600;
		color: var(--text-primary);
	}

	.close-btn {
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

	.close-btn:hover:not(:disabled) {
		background: var(--bg-hover);
		color: var(--text-primary);
	}

	.inspector-scroll {
		flex: 1;
		min-block-size: 0;
		overflow-y: auto;
		overscroll-behavior: contain;
		padding-block-end: max(var(--space-6), env(safe-area-inset-bottom, 0px));
	}

	.inspector-section {
		padding-block: var(--space-4);
		padding-inline: var(--space-4);
		border-block-end: 1px solid var(--border);
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
	}

	.inspector-section:last-child {
		border-block-end: none;
	}

	.section-heading {
		font-size: var(--text-sm);
		font-weight: 650;
		color: var(--text-secondary);
		line-height: 1.35;
	}

	.section-header-row {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: var(--space-2);
	}

	/* Identity */
	.identity-header {
		display: flex;
		flex-direction: column;
		align-items: center;
		text-align: center;
		gap: var(--space-2);
	}

	.identity-text {
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: var(--space-fine);
		max-inline-size: 100%;
	}

	.identity-title {
		font-size: var(--text-heading);
		font-weight: 650;
		line-height: 1.3;
		letter-spacing: -0.015em;
		color: var(--text-primary);
		word-break: break-word;
		text-wrap: balance;
	}

	.identity-subtitle {
		font-size: var(--text-sm);
		color: var(--text-secondary);
		line-height: 1.4;
		max-inline-size: 36ch;
		word-break: break-word;
	}

	.edit-toggle-btn {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		gap: var(--space-1);
		min-block-size: max(2rem, var(--touch-min));
		padding-inline: var(--space-3);
		padding-block: var(--space-1);
		border-radius: var(--radius-sm);
		border: 1px solid var(--border-strong);
		background: var(--bg-surface);
		color: var(--text-primary);
		font-size: var(--text-sm);
		font-weight: 600;
		transition:
			background-color var(--dur-fast) var(--ease-out),
			border-color var(--dur-fast) var(--ease-out);
	}

	.edit-toggle-btn:hover {
		background: var(--bg-active);
	}

	.metadata-form {
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
	}

	.field-group {
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
	}

	.field-label {
		font-size: var(--text-sm);
		font-weight: 600;
		color: var(--text-secondary);
	}

	.field-input,
	.field-textarea {
		inline-size: 100%;
		padding-block: var(--space-2);
		padding-inline: var(--space-3);
		border-radius: var(--radius-sm);
		border: 1px solid var(--border-input);
		background: var(--bg-input);
		color: var(--text-primary);
		font-size: var(--text-body);
		line-height: 1.45;
		transition: border-color var(--dur-fast) var(--ease-out);
	}

	.field-input {
		min-block-size: max(2.5rem, var(--touch-min));
	}

	.field-textarea {
		resize: vertical;
		min-block-size: 4.75rem;
	}

	.field-input:focus-visible,
	.field-textarea:focus-visible {
		border-color: var(--focus-ring);
	}

	.field-input:disabled,
	.field-textarea:disabled {
		opacity: 0.6;
	}

	.inline-error {
		font-size: var(--text-sm);
		color: var(--danger-text);
	}

	.metadata-actions {
		display: flex;
		justify-content: flex-end;
		gap: var(--space-2);
	}

	.btn-compact {
		min-block-size: max(2.125rem, var(--touch-min));
		padding-inline: var(--space-3);
		padding-block: var(--space-1);
		font-size: var(--text-sm);
	}

	/* Preferences */
	.pref-list {
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
	}

	.pref-row {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: var(--space-3);
		min-block-size: max(2.5rem, var(--touch-min));
		padding-inline: var(--space-2);
		padding-block: var(--space-1);
		border-radius: var(--radius-sm);
		cursor: pointer;
		transition: background-color var(--dur-fast) var(--ease-out);
	}

	.pref-row:hover {
		background: var(--bg-hover);
	}

	.pref-label {
		display: inline-flex;
		align-items: center;
		gap: var(--space-2);
		font-size: var(--text-body);
		color: var(--text-primary);
		min-inline-size: 0;
	}

	/* Encryption & security */
	.encryption-status {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		font-size: var(--text-sm);
		font-weight: 500;
		color: var(--text-primary);
	}

	.shield-icon {
		display: inline-flex;
		align-items: center;
		color: var(--shield);
		flex-shrink: 0;
	}

	.quarantine-note {
		display: flex;
		align-items: flex-start;
		gap: var(--space-2);
		padding: var(--space-3);
		border-radius: var(--radius-sm);
		background: var(--warning-bg);
		border-inline-start: 3px solid var(--warning-border);
	}

	.quarantine-note-icon {
		color: var(--warning-text);
		padding-block-start: 0.125rem;
		flex-shrink: 0;
	}

	.quarantine-note-copy {
		display: flex;
		flex-direction: column;
		gap: var(--space-fine);
		min-inline-size: 0;
	}

	.quarantine-note-title {
		font-size: var(--text-sm);
		font-weight: 650;
		color: var(--warning-text);
	}

	.quarantine-note-text {
		font-size: var(--text-sm);
		color: var(--text-primary);
		line-height: 1.4;
	}

	.security-details {
		display: flex;
		flex-direction: column;
	}

	.security-summary {
		display: inline-flex;
		align-items: center;
		gap: var(--space-1);
		min-block-size: max(2rem, var(--touch-min));
		font-size: var(--text-sm);
		font-weight: 600;
		color: var(--text-link);
		cursor: pointer;
		list-style: disclosure-closed;
	}

	.security-details[open] > .security-summary {
		list-style: disclosure-open;
	}

	.security-summary:hover {
		text-decoration: underline;
	}

	.security-details-body {
		margin-block-start: var(--space-2);
		padding-block-start: var(--space-3);
		border-block-start: 1px solid var(--border);
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
	}

	.security-dl {
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
		font-size: var(--text-sm);
	}

	.security-dl dt {
		font-weight: 600;
		color: var(--text-secondary);
	}

	.security-dl dd {
		color: var(--text-primary);
		margin-block-end: var(--space-1);
	}

	.group-id-cell {
		display: flex;
		align-items: flex-start;
		justify-content: space-between;
		gap: var(--space-2);
	}

	.mono {
		font-family: var(--font-mono);
		font-size: var(--text-sm);
		word-break: break-all;
		color: var(--text-primary);
	}

	.copy-btn {
		display: inline-flex;
		align-items: center;
		gap: var(--space-1);
		flex-shrink: 0;
		min-block-size: max(1.875rem, var(--touch-min));
		padding-inline: var(--space-2);
		border-radius: var(--radius-xs);
		border: 1px solid var(--border-strong);
		background: var(--bg-surface);
		color: var(--text-primary);
		font-size: var(--text-sm);
		font-weight: 600;
		transition: background-color var(--dur-fast) var(--ease-out);
	}

	.copy-btn:hover {
		background: var(--bg-active);
	}

	.muted-note {
		color: var(--text-secondary);
	}

	.suspected-dids {
		list-style: none;
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
	}

	.reset-session-btn {
		inline-size: 100%;
	}

	/* Members */
	.add-members-btn {
		display: inline-flex;
		align-items: center;
		gap: var(--space-1);
		min-block-size: max(2rem, var(--touch-min));
		padding-inline: var(--space-2);
		border-radius: var(--radius-xs);
		color: var(--text-link);
		font-size: var(--text-sm);
		font-weight: 600;
		transition: background-color var(--dur-fast) var(--ease-out);
	}

	.add-members-btn:hover {
		background: var(--bg-hover);
	}

	.members-status {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}

	.members-error {
		display: flex;
		flex-direction: column;
		align-items: flex-start;
		gap: var(--space-2);
		font-size: var(--text-sm);
		color: var(--danger-text);
	}

	.member-list {
		list-style: none;
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
	}

	.member-row {
		display: flex;
		align-items: center;
		gap: var(--space-3);
		padding-block: var(--space-2);
		padding-inline: var(--space-2);
		margin-inline: calc(var(--space-2) * -1);
		border-radius: var(--radius-sm);
		transition: background-color var(--dur-fast) var(--ease-out);
	}

	.member-row:hover {
		background: var(--bg-hover);
	}

	.member-info {
		flex: 1;
		min-inline-size: 0;
		display: flex;
		flex-direction: column;
		gap: 1px;
	}

	.member-name {
		font-size: var(--text-body);
		font-weight: 550;
		color: var(--text-primary);
		white-space: nowrap;
		overflow: hidden;
		text-overflow: ellipsis;
		line-height: 1.3;
	}

	.member-subtitle {
		font-size: var(--text-sm);
		color: var(--text-secondary);
		white-space: nowrap;
		overflow: hidden;
		text-overflow: ellipsis;
		line-height: 1.3;
	}

	.member-more-btn {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		flex-shrink: 0;
		min-inline-size: max(2rem, var(--touch-min));
		min-block-size: max(2rem, var(--touch-min));
		border-radius: var(--radius-sm);
		color: var(--text-secondary);
		transition:
			background-color var(--dur-fast) var(--ease-out),
			color var(--dur-fast) var(--ease-out);
	}

	.member-more-btn:hover {
		background: var(--bg-active);
		color: var(--text-primary);
	}

	.member-spinner {
		flex-shrink: 0;
	}

	.member-popover:popover-open {
		display: flex;
		flex-direction: column;
		gap: 2px;
	}

	.menu-item {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		inline-size: 100%;
		min-block-size: max(2.25rem, var(--touch-min));
		padding-inline: var(--space-3);
		padding-block: var(--space-2);
		border-radius: var(--radius-xs);
		font-size: var(--text-sm);
		font-weight: 500;
		color: var(--text-primary);
		text-align: start;
		transition: background-color var(--dur-fast) var(--ease-out);
	}

	.menu-item:hover {
		background: var(--bg-hover);
	}

	.menu-item--danger {
		color: var(--danger-text);
	}

	.menu-item--danger:hover {
		background: var(--danger-bg);
	}

	/* Safety and danger actions */
	.action-error-banner {
		display: flex;
		align-items: flex-start;
		justify-content: space-between;
		gap: var(--space-2);
		padding: var(--space-2) var(--space-3);
		border-radius: var(--radius-sm);
		background: var(--danger-bg);
		border: 1px solid var(--danger-text);
	}

	.member-action-error {
		flex: 1;
		min-inline-size: 0;
		font-size: var(--text-sm);
		line-height: 1.4;
		color: var(--danger-text);
		word-break: break-word;
	}

	.dismiss-error-btn {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		flex-shrink: 0;
		min-inline-size: max(1.75rem, var(--touch-min));
		min-block-size: max(1.75rem, var(--touch-min));
		border-radius: var(--radius-xs);
		color: var(--danger-text);
		transition: background-color var(--dur-fast) var(--ease-out);
	}

	.dismiss-error-btn:hover {
		background: var(--bg-hover);
	}

	.danger-actions {
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
	}

	.danger-row-btn {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		inline-size: 100%;
		min-block-size: max(2.5rem, var(--touch-min));
		padding-inline: var(--space-3);
		padding-block: var(--space-2);
		border-radius: var(--radius-sm);
		font-size: var(--text-body);
		font-weight: 550;
		color: var(--danger-text);
		text-align: start;
		transition: background-color var(--dur-fast) var(--ease-out);
	}

	.danger-row-btn:hover {
		background: var(--danger-bg);
	}

	.danger-row-label {
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	/* Modal dialogs */
	.modal-dialog {
		inline-size: min(28rem, calc(100vw - 2rem));
	}

	.add-members-dialog {
		inline-size: min(30rem, calc(100vw - 2rem));
	}

	.modal-inner {
		display: flex;
		flex-direction: column;
		gap: var(--space-4);
		padding: var(--space-6);
		overflow-y: auto;
	}

	.modal-header {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: var(--space-2);
	}

	.modal-title {
		font-size: var(--text-heading);
		font-weight: 650;
		line-height: 1.3;
		letter-spacing: -0.015em;
		color: var(--text-primary);
	}

	.modal-description {
		font-size: var(--text-body);
		line-height: 1.5;
		color: var(--text-secondary);
		max-inline-size: 65ch;
	}

	.modal-busy {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}

	.modal-error {
		display: flex;
		align-items: flex-start;
		gap: var(--space-2);
		padding: var(--space-3);
		border-radius: var(--radius-sm);
		background: var(--danger-bg);
		color: var(--danger-text);
		font-size: var(--text-sm);
		line-height: 1.4;
	}

	.modal-actions {
		display: flex;
		justify-content: flex-end;
		flex-wrap: wrap;
		gap: var(--space-2);
		padding-block-start: var(--space-1);
	}

	@media (pointer: coarse) {
		.close-btn,
		.edit-toggle-btn,
		.copy-btn,
		.add-members-btn,
		.member-more-btn,
		.menu-item,
		.danger-row-btn,
		.pref-row,
		.security-summary {
			min-block-size: 44px;
		}

		.close-btn,
		.member-more-btn {
			min-inline-size: 44px;
		}
	}

	@media (forced-colors: active) {
		.inspector {
			border-inline-start: 1px solid CanvasText;
		}

		.quarantine-note {
			border: 1px solid CanvasText;
			border-inline-start-width: 4px;
		}

		.edit-toggle-btn,
		.copy-btn {
			border: 1px solid ButtonText;
		}
	}
</style>

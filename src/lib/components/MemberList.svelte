<script lang="ts">
	import {
		getGroupMembers,
		promoteMember,
		demoteMember,
		removeGroupMember,
		addGroupMembers,
		reportSpam,
		type GroupMember,
		type SearchResult,
		type QuarantineState
	} from '#lib/wasm.ts';
	import { auth } from '#lib/stores/auth.ts';
	import {
		foldGroupMembersByAccount,
		isSameAccountDid,
		stripDidFragment
	} from '#lib/did.ts';
	import { profiles } from '#lib/stores/profiles.ts';
	import {
		conversations,
		affectedConversationsFor,
		blockAndLeave
	} from '#lib/stores/conversations.ts';
	import { quarantineReasonCopy } from '#lib/stores/quarantine.ts';
	import UserSearch from './UserSearch.svelte';

	let {
		conversationId,
		quarantine = null
	}: {
		conversationId: string;
		/** Layer 3 quarantine state for this conversation, if any. */
		quarantine?: QuarantineState | null;
	} = $props();
	let members = $state<GroupMember[]>([]);
	let processing = $state<string | null>(null);
	let confirmAction = $state<
		{ type: string; did: string; name: string; affectedCount?: number } | null
	>(null);
	let showAddMember = $state(false);
	let addMemberSelection = $state<SearchResult[]>([]);
	let addingMembers = $state(false);
	let showReportSpam = $state<{ did: string; name: string } | null>(null);
	let reportReason = $state('');
	let reportSubmitting = $state(false);
	let reportResult = $state<{ success: boolean; message: string } | null>(null);

	$effect(() => {
		if (conversationId) {
			loadMembers();
		}
	});

	async function loadMembers() {
		try {
			const rawMembers = await getGroupMembers(conversationId);
			members = foldGroupMembersByAccount(rawMembers);
			const dids = members.map((m) => m.did);
			profiles.resolveProfiles(dids);
		} catch {
			members = [];
		}
	}

	function currentUserDid(): string {
		let authState: { user?: { did?: string } | null } | undefined;
		auth.subscribe((s) => (authState = s))();
		return stripDidFragment(authState?.user?.did);
	}

	function isCurrentUserAdmin(): boolean {
		const myDid = currentUserDid();
		return members.some(
			(m) => isSameAccountDid(m.did, myDid) && m.role.toLowerCase().includes('admin')
		);
	}

	function memberDisplayName(member: GroupMember): string {
		const accountDid = stripDidFragment(member.did);
		let profile: { displayName?: string; handle?: string } | undefined;
		profiles.subscribe((s) => (profile = s.cache.get(accountDid)))();
		return (
			profile?.displayName ??
			profile?.handle ??
			(stripDidFragment(member.handle) || accountDid.slice(0, 20))
		);
	}

	function memberAvatar(member: GroupMember): string | undefined {
		const accountDid = stripDidFragment(member.did);
		let profile: { avatar?: string } | undefined;
		profiles.subscribe((s) => (profile = s.cache.get(accountDid)))();
		return profile?.avatar;
	}

	function isAdmin(role: string): boolean {
		return role.toLowerCase().includes('admin');
	}

	async function handleAddMembers() {
		if (addMemberSelection.length === 0) return;
		addingMembers = true;
		try {
			await addGroupMembers(conversationId, addMemberSelection.map((m) => m.did));
			showAddMember = false;
			addMemberSelection = [];
			await loadMembers();
		} catch (err) {
			console.error('Add members failed:', err);
		} finally {
			addingMembers = false;
		}
	}

	function requestAction(type: string, did: string, name: string) {
		if (type === 'block') {
			confirmAction = {
				type,
				did,
				name,
				affectedCount: affectedConversationsFor(did).length
			};
			return;
		}
		confirmAction = { type, did, name };
	}

	function cancelAction() {
		confirmAction = null;
	}

	async function executeAction() {
		if (!confirmAction) return;
		const { type, did } = confirmAction;
		processing = did;
		confirmAction = null;
		try {
			if (type === 'promote') {
				await promoteMember(conversationId, did);
			} else if (type === 'demote') {
				await demoteMember(conversationId, did);
			} else if (type === 'remove') {
				await removeGroupMember(conversationId, did);
			} else if (type === 'leave') {
				await conversations.leaveConversation(conversationId);
				return;
			} else if (type === 'block') {
				await blockAndLeave(did);
				// blockAndLeave may have left the current conversation already.
				// Refreshing members is fine either way.
			}
			await loadMembers();
		} catch (err) {
			console.error(`${type} failed:`, err);
		} finally {
			processing = null;
		}
	}

	function openReportSpam(did: string, name: string) {
		showReportSpam = { did, name };
		reportReason = '';
		reportResult = null;
	}

	function closeReportSpam() {
		showReportSpam = null;
		reportReason = '';
		reportSubmitting = false;
		reportResult = null;
	}

	async function submitReport() {
		if (!showReportSpam) return;
		reportSubmitting = true;
		reportResult = null;
		try {
			await reportSpam(
				conversationId,
				showReportSpam.did,
				reportReason.trim() || undefined
			);
			reportResult = { success: true, message: 'Report submitted successfully.' };
		} catch (err) {
			const message = err instanceof Error ? err.message : 'Failed to submit report.';
			reportResult = { success: false, message };
		} finally {
			reportSubmitting = false;
		}
	}
</script>

<aside class="member-list">
	<div class="member-list-header">
		<span class="member-list-title">Members</span>
		<span class="member-list-count">{members.length}</span>
		{#if isCurrentUserAdmin()}
			<button
				class="add-member-btn"
				title="Add Member"
				onclick={() => { showAddMember = true; addMemberSelection = []; }}
			>
				<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
					<line x1="12" y1="5" x2="12" y2="19" />
					<line x1="5" y1="12" x2="19" y2="12" />
				</svg>
			</button>
		{/if}
	</div>
	{#if quarantine}
		<div class="quarantine-card" role="status">
			<div class="qc-title">Conversation paused</div>
			<div class="qc-reason">{quarantineReasonCopy(quarantine.reasonTag)}</div>
			<dl class="qc-meta">
				<dt>Reason</dt>
				<dd><code>{quarantine.reasonTag}</code></dd>
				<dt>Paused since</dt>
				<dd>{new Date(quarantine.sinceMs).toLocaleString()}</dd>
				<dt>Suspected</dt>
				<dd>
					{#if quarantine.suspectedDids.length === 0}
						<em>none identified</em>
					{:else}
						<ul>
							{#each quarantine.suspectedDids as did (did)}
								<li><code>{did}</code></li>
							{/each}
						</ul>
					{/if}
				</dd>
			</dl>
		</div>
	{/if}
	<div class="member-items">
		{#each members as member (member.did)}
			{@const name = memberDisplayName(member)}
			{@const avatar = memberAvatar(member)}
			{@const admin = isAdmin(member.role)}
			{@const isSelf = isSameAccountDid(member.did, currentUserDid())}
			<div class="member-item">
				<div class="member-avatar" class:admin>
					{#if avatar}
						<img src={avatar} alt="" class="avatar-img" />
					{:else}
						{name.charAt(0).toUpperCase()}
					{/if}
				</div>
				<div class="member-info">
					<span class="member-name">{name}</span>
					{#if admin}
						<span class="role-badge admin">Admin</span>
					{/if}
				</div>
				{#if !isSelf && processing !== member.did}
					<div class="member-actions">
						{#if isCurrentUserAdmin()}
							{#if admin}
								<button
									class="action-btn"
									title="Demote to Member"
									onclick={() => requestAction('demote', member.did, name)}
								>
									<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
										<polyline points="6 9 12 15 18 9" />
									</svg>
								</button>
							{:else}
								<button
									class="action-btn"
									title="Promote to Admin"
									onclick={() => requestAction('promote', member.did, name)}
								>
									<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
										<polyline points="18 15 12 9 6 15" />
									</svg>
								</button>
							{/if}
							<button
								class="action-btn danger"
								title="Remove from Group"
								onclick={() => requestAction('remove', member.did, name)}
							>
								<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
									<line x1="18" y1="6" x2="6" y2="18" />
									<line x1="6" y1="6" x2="18" y2="18" />
								</svg>
							</button>
						{/if}
						<button
							class="action-btn danger"
							title="Block User"
							onclick={() => requestAction('block', member.did, name)}
						>
							<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
								<circle cx="12" cy="12" r="10" />
								<line x1="4.93" y1="4.93" x2="19.07" y2="19.07" />
							</svg>
						</button>
						<button
							class="action-btn danger"
							title="Report as Spam"
							onclick={() => openReportSpam(member.did, name)}
						>
							<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
								<path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z" />
								<line x1="4" y1="22" x2="4" y2="15" />
							</svg>
						</button>
					</div>
				{/if}
				{#if processing === member.did}
					<div class="processing-spinner"></div>
				{/if}
			</div>
		{/each}
	</div>
	<div class="leave-section">
		<button
			class="leave-btn"
			onclick={() => requestAction('leave', currentUserDid(), 'you')}
		>Leave Conversation</button>
	</div>
</aside>

{#if confirmAction}
	<div class="confirm-overlay" onclick={cancelAction} role="presentation">
		<div class="confirm-dialog" onclick={(e) => e.stopPropagation()} role="dialog">
			<p class="confirm-text">
				{#if confirmAction.type === 'promote'}
					Promote <strong>{confirmAction.name}</strong> to Admin?
				{:else if confirmAction.type === 'demote'}
					Demote <strong>{confirmAction.name}</strong> to Member?
				{:else if confirmAction.type === 'leave'}
					Are you sure you want to leave this conversation?
				{:else if confirmAction.type === 'block'}
					Block <strong>{confirmAction.name}</strong>?
					{#if (confirmAction.affectedCount ?? 0) > 0}
						<br /><br />
						You'll leave {confirmAction.affectedCount} shared conversation{confirmAction.affectedCount === 1 ? '' : 's'}.
						This can't be undone — unblocking will not rejoin you.
					{:else}
						<br /><br />
						You won't see each other's posts.
					{/if}
				{:else}
					Remove <strong>{confirmAction.name}</strong> from the group?
				{/if}
			</p>
			<div class="confirm-actions">
				<button class="btn btn-secondary" onclick={cancelAction}>Cancel</button>
				<button
					class="btn"
					class:btn-danger={confirmAction.type === 'remove' || confirmAction.type === 'leave' || confirmAction.type === 'block'}
					class:btn-primary={confirmAction.type !== 'remove' && confirmAction.type !== 'leave' && confirmAction.type !== 'block'}
					onclick={executeAction}
				>
					{confirmAction.type === 'remove'
						? 'Remove'
						: confirmAction.type === 'leave'
							? 'Leave'
							: confirmAction.type === 'block'
								? 'Block'
								: 'Confirm'}
				</button>
			</div>
		</div>
	</div>
{/if}

{#if showReportSpam}
	<div class="confirm-overlay" onclick={closeReportSpam} role="presentation">
		<div class="confirm-dialog report-dialog" onclick={(e) => e.stopPropagation()} role="dialog">
			<h3 class="report-title">Report as Spam</h3>
			<p class="confirm-text">
				Report <strong>{showReportSpam.name}</strong> as spam in this conversation?
			</p>
			{#if reportResult}
				<div class="report-result" class:success={reportResult.success} class:error={!reportResult.success}>
					{reportResult.message}
				</div>
				<div class="confirm-actions">
					<button class="btn btn-secondary" onclick={closeReportSpam}>Close</button>
				</div>
			{:else}
				<label class="report-label" for="report-reason">Reason (optional)</label>
				<textarea
					id="report-reason"
					class="report-textarea"
					placeholder="Describe why you're reporting this user..."
					maxlength="1000"
					rows="3"
					bind:value={reportReason}
					disabled={reportSubmitting}
				></textarea>
				<div class="confirm-actions">
					<button class="btn btn-secondary" onclick={closeReportSpam} disabled={reportSubmitting}>Cancel</button>
					<button
						class="btn btn-danger"
						onclick={submitReport}
						disabled={reportSubmitting}
					>
						{reportSubmitting ? 'Submitting...' : 'Report'}
					</button>
				</div>
			{/if}
		</div>
	</div>
{/if}

{#if showAddMember}
	<div class="confirm-overlay" onclick={() => { showAddMember = false; }} role="presentation">
		<div class="add-member-dialog" onclick={(e) => e.stopPropagation()} role="dialog">
			<h3 class="add-member-title">Add Members</h3>
			<UserSearch bind:selected={addMemberSelection} />
			<div class="confirm-actions">
				<button class="btn btn-secondary" onclick={() => { showAddMember = false; }}>Cancel</button>
				<button
					class="btn btn-primary"
					disabled={addMemberSelection.length === 0 || addingMembers}
					onclick={handleAddMembers}
				>
					{addingMembers ? 'Adding...' : 'Add'}
				</button>
			</div>
		</div>
	</div>
{/if}

<style>
	.member-list {
		width: var(--member-list-width);
		background: var(--bg-sidebar);
		border-left: 1px solid var(--border);
		display: flex;
		flex-direction: column;
		flex-shrink: 0;
	}

	.member-list-header {
		padding: 16px 16px 12px;
		display: flex;
		align-items: center;
		gap: 6px;
	}

	.member-list-title {
		font-size: 12px;
		font-weight: 700;
		text-transform: uppercase;
		color: var(--text-secondary);
		letter-spacing: 0.04em;
	}

	.member-list-count {
		font-size: 11px;
		color: var(--text-tertiary);
		background: var(--bg-hover);
		padding: 1px 6px;
		border-radius: var(--radius-full);
		font-weight: 600;
	}

	.add-member-btn {
		width: 24px;
		height: 24px;
		display: flex;
		align-items: center;
		justify-content: center;
		border-radius: var(--radius-sm);
		color: var(--text-secondary);
		margin-left: auto;
		transition: all var(--transition-fast);
	}

	.add-member-btn:hover {
		background: var(--bg-hover);
		color: var(--text-primary);
	}

	.member-items {
		flex: 1;
		overflow-y: auto;
		padding: 0 8px;
	}

	.member-item {
		display: flex;
		align-items: center;
		gap: 10px;
		padding: 8px;
		border-radius: var(--radius-sm);
		transition: background var(--transition-fast);
	}

	.member-item:hover {
		background: var(--bg-hover);
	}

	.member-avatar {
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

	.member-avatar.admin {
		background: var(--success);
	}

	.avatar-img {
		width: 100%;
		height: 100%;
		object-fit: cover;
	}

	.member-info {
		display: flex;
		align-items: center;
		gap: 6px;
		min-width: 0;
		flex: 1;
	}

	.member-name {
		color: var(--text-primary);
		font-size: 13px;
		font-weight: 500;
		white-space: nowrap;
		overflow: hidden;
		text-overflow: ellipsis;
	}

	.role-badge {
		font-size: 10px;
		padding: 1px 6px;
		border-radius: var(--radius-full);
		font-weight: 600;
		flex-shrink: 0;
	}

	.role-badge.admin {
		background: rgba(52, 199, 89, 0.15);
		color: var(--success);
	}

	.member-actions {
		display: flex;
		gap: 2px;
		flex-shrink: 0;
		opacity: 0;
		transition: opacity var(--transition-fast);
	}

	.member-item:hover .member-actions {
		opacity: 1;
	}

	.action-btn {
		width: 26px;
		height: 26px;
		display: flex;
		align-items: center;
		justify-content: center;
		border-radius: var(--radius-sm);
		color: var(--text-secondary);
		transition: all var(--transition-fast);
	}

	.action-btn:hover {
		background: var(--bg-active);
		color: var(--text-primary);
	}

	.action-btn.danger:hover {
		color: var(--danger);
	}

	.processing-spinner {
		width: 16px;
		height: 16px;
		border: 2px solid var(--border);
		border-top: 2px solid var(--accent);
		border-radius: var(--radius-full);
		animation: spin 0.8s linear infinite;
		flex-shrink: 0;
	}

	@keyframes spin {
		to { transform: rotate(360deg); }
	}

	.leave-section {
		padding: 12px;
		border-top: 1px solid var(--border);
	}

	.leave-btn {
		width: 100%;
		padding: 8px 16px;
		border-radius: var(--radius-sm);
		font-weight: 500;
		font-size: 13px;
		color: var(--danger);
		transition: background var(--transition-fast);
	}

	.leave-btn:hover {
		background: rgba(255, 59, 48, 0.08);
	}

	/* ── Dialogs ── */
	.confirm-overlay {
		position: fixed;
		inset: 0;
		background: var(--bg-overlay);
		display: flex;
		align-items: center;
		justify-content: center;
		z-index: 200;
		backdrop-filter: blur(4px);
		-webkit-backdrop-filter: blur(4px);
	}

	.confirm-dialog {
		background: var(--bg-card);
		border: 1px solid var(--border);
		border-radius: var(--radius-lg);
		padding: 24px;
		width: 340px;
		box-shadow: var(--shadow-lg);
	}

	.confirm-text {
		color: var(--text-primary);
		font-size: 14px;
		margin-bottom: 20px;
		line-height: 1.5;
	}

	.confirm-actions {
		display: flex;
		justify-content: flex-end;
		gap: 8px;
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

	.btn-danger {
		background: var(--danger);
		color: white;
	}

	.btn-danger:hover {
		filter: brightness(1.1);
	}

	.add-member-dialog {
		background: var(--bg-card);
		border: 1px solid var(--border);
		border-radius: var(--radius-lg);
		padding: 24px;
		width: 400px;
		max-height: 80vh;
		box-shadow: var(--shadow-lg);
		display: flex;
		flex-direction: column;
		gap: 16px;
	}

	.add-member-title {
		color: var(--text-primary);
		font-size: 17px;
		font-weight: 700;
		margin: 0;
		letter-spacing: -0.01em;
	}

	/* ── Report Spam Dialog ── */
	.report-dialog {
		display: flex;
		flex-direction: column;
		gap: 12px;
	}

	.report-title {
		color: var(--text-primary);
		font-size: 17px;
		font-weight: 700;
		margin: 0;
		letter-spacing: -0.01em;
	}

	.report-label {
		font-size: 12px;
		font-weight: 600;
		color: var(--text-secondary);
		text-transform: uppercase;
		letter-spacing: 0.04em;
	}

	.report-textarea {
		width: 100%;
		padding: 10px 12px;
		border-radius: var(--radius-sm);
		border: 1px solid var(--border);
		background: var(--bg-input, var(--bg-hover));
		color: var(--text-primary);
		font-size: 13px;
		font-family: inherit;
		resize: vertical;
		min-height: 60px;
		transition: border-color var(--transition-fast);
	}

	.report-textarea:focus {
		outline: none;
		border-color: var(--accent);
	}

	.report-textarea:disabled {
		opacity: 0.5;
	}

	.report-result {
		padding: 10px 12px;
		border-radius: var(--radius-sm);
		font-size: 13px;
		font-weight: 500;
	}

	.report-result.success {
		background: rgba(52, 199, 89, 0.12);
		color: var(--success);
	}

	.report-result.error {
		background: rgba(255, 59, 48, 0.12);
		color: var(--danger);
	}

	/* Layer 3 quarantine info card */
	.quarantine-card {
		margin: 8px 12px 4px;
		padding: 10px 12px;
		background: var(--bg-card, rgba(217, 119, 6, 0.08));
		border-left: 3px solid var(--warning, #d97706);
		border-radius: var(--radius-sm, 6px);
		font-size: 12px;
		color: var(--text-primary);
	}
	.quarantine-card .qc-title {
		font-weight: 600;
		margin-bottom: 4px;
	}
	.quarantine-card .qc-reason {
		color: var(--text-secondary);
		margin-bottom: 8px;
	}
	.quarantine-card .qc-meta {
		display: grid;
		grid-template-columns: max-content 1fr;
		gap: 4px 10px;
		margin: 0;
	}
	.quarantine-card dt {
		font-weight: 600;
		color: var(--text-secondary);
	}
	.quarantine-card dd {
		margin: 0;
	}
	.quarantine-card ul {
		list-style: none;
		padding: 0;
		margin: 0;
	}
	.quarantine-card code {
		font-family: ui-monospace, SFMono-Regular, monospace;
		font-size: 11px;
		background: rgba(0, 0, 0, 0.04);
		padding: 1px 4px;
		border-radius: 3px;
	}
</style>

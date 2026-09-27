<script lang="ts">
	import { requests } from '$lib/stores/requests';
	import RequestInbox from '$lib/components/RequestInbox.svelte';
	import RequestComposer from '$lib/components/RequestComposer.svelte';
	import RequestDetail from '$lib/components/RequestDetail.svelte';
	import { onDestroy, onMount, untrack } from 'svelte';
	import { auth } from '$lib/stores/auth';
	import {
		conversations,
		selectedConversation,
		reconcileBlockedConversations
	} from '$lib/stores/conversations';
	import { messages } from '$lib/stores/messages';
	import { saveCursor, getCursor } from '$lib/stores/cursors';
	import * as api from '$lib/wasm';
	import { listenForEvent, isTauri } from '$lib/wasm';
	import type {
		Message,
		PreparedImageUpload,
		ReactionEvent,
		TypingEvent,
		GroupResetEvent,
		QuarantineEnteredEvent,
		QuarantineClearedEvent
	} from '$lib/tauri';
	import MessageList from '$lib/components/MessageList.svelte';
	import Composer from '$lib/components/Composer.svelte';
	import MemberList from '$lib/components/MemberList.svelte';
	import ReplyPreview from '$lib/components/ReplyPreview.svelte';
	import ConnectionStatus from '$lib/components/ConnectionStatus.svelte';
	import SearchPanel from '$lib/components/SearchPanel.svelte';
	import QuarantineBanner from '$lib/components/QuarantineBanner.svelte';
	import type { ReplyInfo } from '$lib/components/MessageBubble.svelte';
	import { connection } from '$lib/stores/connection';
	import { notifyIncomingMessage } from '$lib/notifications';
	import { profiles } from '$lib/stores/profiles';
	import { quarantine } from '$lib/stores/quarantine';
	import type { Conversation } from '$lib/tauri';

	let loginIdentifier = $state('');
	let replyingTo = $state<ReplyInfo | null>(null);
	let showMembers = $state(false);
	let showSearch = $state(false);
	let unlistenMessage: (() => void) | null = null;
	let unlistenReaction: (() => void) | null = null;
	let unlistenTyping: (() => void) | null = null;
	let unlistenGroupReset: (() => void) | null = null;
	let unlistenQuarantined: (() => void) | null = null;
	let unlistenQuarantineCleared: (() => void) | null = null;
	let unlistenRecovery: (() => void) | null = null;
	let unlistenConnected: (() => void) | null = null;
	let subscribedConvoId: string | null = null;
	let blockReconcileRan = false;

	function handleGlobalKeydown(e: KeyboardEvent) {
		if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
			e.preventDefault();
			showSearch = !showSearch;
			return;
		}
		// Escape — close any open panel/dialog
		if (e.key === 'Escape') {
			if (showSearch) {
				showSearch = false;
				return;
			}
			if (showMembers) {
				showMembers = false;
				return;
			}
		}
	}

	onMount(() => {
		window.addEventListener('keydown', handleGlobalKeydown);

		listenForEvent<Message>('mls-incoming-message', (payload) => {
			if (!ordinaryAllowed(payload.conversationId)) { requests.load(); return; }
			messages.addIncoming(payload);
			saveCursor(payload.conversationId, payload.id);
			notifyIncomingMessage(payload.senderHandle, payload.content, payload.conversationId);
		}).then((unlisten) => {
			unlistenMessage = unlisten;
		});

		listenForEvent<ReactionEvent>('mls-reaction-event', (payload) => {
			if (!ordinaryAllowed(payload.conversationId)) return;
			messages.applyReaction(payload);
		}).then((unlisten) => {
			unlistenReaction = unlisten;
		});

		listenForEvent<TypingEvent>('mls-typing-event', (payload) => {
			if (!ordinaryAllowed(payload.conversationId)) return;
			messages.applyTyping(payload);
		}).then((unlisten) => {
			unlistenTyping = unlisten;
		});

		listenForEvent<GroupResetEvent>('mls:group-reset', (payload) => {
			console.log('[catmos] Group reset event:', payload);
			// Refresh the conversation list to pick up new group state
			conversations.load();
			// If we're viewing the reset conversation, refresh its messages
			if ($selectedConversation?.id === payload.convoId) {
				messages.fetchFromServer(payload.convoId);
			}
		}).then((unlisten) => {
			unlistenGroupReset = unlisten;
		});

		// Layer 3 quarantine: live entry/exit events + a refresh on app load
		// for the active conversation so a restart with a pre-existing
		// quarantined row paints the banner on first frame.
		listenForEvent<QuarantineEnteredEvent>('mls://quarantined', (payload) => {
			console.warn('[catmos] Conversation quarantined:', payload);
			quarantine.applyEnteredEvent(payload);
		}).then((unlisten) => {
			unlistenQuarantined = unlisten;
		});

		listenForEvent<QuarantineClearedEvent>('mls://quarantine-cleared', (payload) => {
			console.log('[catmos] Quarantine cleared:', payload);
			quarantine.applyClearedEvent(payload);
		}).then((unlisten) => {
			unlistenQuarantineCleared = unlisten;
		});

		// Backend reconnect loops stop on explicit auth/device/MLS failures;
		// surface the stable category so the banner can offer the correct next
		// action without clearing persisted credentials.
		listenForEvent<string>('mls-ws-recovery', (payload) => {
			connection.setDisconnected(payload);
		}).then((unlisten) => {
			unlistenRecovery = unlisten;
		});
		listenForEvent('mls-ws-connected', () => {
			connection.setConnected();
		}).then((unlisten) => {
			unlistenConnected = unlisten;
		});
	});

	async function subscribeToConversation(convoId: string, force = false) {
        const session = $auth.user;
        const owner = session?.did;
        if (!owner) return;
		if (!ordinaryAllowed(convoId)) return;
		if (!force && subscribedConvoId === convoId) return;
		// On Tauri, the global WS started on login already covers this convo;
		// spawning an extra per-convo WS here would just open a duplicate
		// connection. Still tear down any prior per-convo handle and update
		// the read cursor.
		if (subscribedConvoId) {
			await api.unsubscribeConversation(subscribedConvoId).catch(() => {});
		}
		if ($auth.user !== session) return;
		subscribedConvoId = convoId;

		if (!isTauri) {
			// Browser/WASM path: no global WS yet, keep using per-convo
			// subscribeConversation with its callback-driven delivery.
			const savedCursor = getCursor(convoId);
			await api
				.subscribeConversation(
					convoId,
					(msg) => {
						const m = msg as Message;
						messages.addIncoming(m);
						saveCursor(convoId, m.id);
						notifyIncomingMessage(m.senderHandle, m.content, convoId);
					},
					(event) => {
						const e = event as { type: string; data: unknown };
						if (e?.type === 'reaction') {
							messages.applyReaction(e.data as ReactionEvent);
						} else if (e?.type === 'typing') {
							messages.applyTyping(e.data as TypingEvent);
						} else if (e?.type === 'fetchNeeded') {
							const reason = (e as { reason?: string }).reason ?? 'unknown';
							console.warn(`[catmos] WS decrypt failed (${reason}), fetching via HTTP`);
							messages.fetchFromServer(convoId);
						}
					},
					(status) => {
						const s = status as { type?: string };
						if (s?.type === 'connected' || s?.type === 'open') {
							connection.setConnected();
						} else if (s?.type === 'closed' || s?.type === 'error') {
							connection.setDisconnected(s.type);
						}
					},
					savedCursor ?? undefined,
                    owner, session.authRevision
				)
				.catch((e: unknown) => {
					console.error('WebSocket subscribe failed:', e);
					connection.setDisconnected(String(e));
				});
		}
		if ($auth.user !== session) return;
		connection.setConnected();
		api.updateCursor(convoId, '', owner, session.authRevision).catch(() => {});
		conversations.markConversationRead(convoId);
	}

	// Wire reconnect: re-subscribe the active conversation on reconnect
	connection.onReconnect(async () => {
		if (subscribedConvoId) {
			await messages.fetchFromServer(subscribedConvoId);
			await subscribeToConversation(subscribedConvoId, true);
		}
	});

	async function handleLogin(e: SubmitEvent) {
		e.preventDefault();
		await auth.startLogin(loginIdentifier);
	}

	$effect(() => {
		const owner = $auth.user?.did ?? null;
		const revision = $auth.user?.authRevision;
		untrack(() => {
			requests.bindAccount(owner, revision);
			conversations.bindAccount(owner, revision);
			messages.bindAccount(owner, revision);
			if (owner) {
				api.subscribeAllEvents().catch((e) =>
					console.warn('[catmos] subscribeAllEvents failed', e)
				);
				requests.load().then(() => conversations.load()).then(() => {
					// Startup reconciliation: leave any group containing a DID the
					// user has blocked (from another client or a previous interrupted
					// blockAndLeave). Run once per session.
					if (!blockReconcileRan) {
						blockReconcileRan = true;
						reconcileBlockedConversations().catch((e) =>
							console.warn('[catmos] block reconciliation failed', e)
						);
					}
				});
			}
		});
	});
	function ordinaryAllowed(id: string): boolean {
		const conversation = $conversations.items.find(c => c.id === id);
		const hasView = $requests.views.some(v => v.conversationId === id);
		return !!$auth.user && !($requests.loading) && (hasView ? requests.canUseOrdinaryActivity(id) : conversation?.pendingConsent !== true);
	}
	let activeRequest = $derived($requests.views.find(v => v.conversationId === ($requests.pane === 'request' ? $requests.selectedId : $selectedConversation?.id)));
	let activeDraft = $derived($requests.drafts.find(d => d.input.draftId === $requests.selectedId));
	async function openRequestConversation(id: string, requiresAcceptance = false) {
		if (requiresAcceptance || !ordinaryAllowed(id)) { requests.selectRequest(id); await requests.refresh(id); return; }
		await conversations.load(); requests.hide(); conversations.select(id);
	}
	function viewGroupInvitation(id: string) {
		// Navigation only: the exact reference came from the verified Rust preview.
		requests.hide(); conversations.select(id);
	}

	let currentConversation = $derived($selectedConversation);

	/** Resolve display name for 1:1 conversations using profile data. */
	function resolvedDisplayName(convo: Conversation): string {
		if (convo.isGroup) return convo.displayName;
		const otherDid = convo.members.find((did) => did !== $auth.user?.did) ?? convo.members[0];
		if (otherDid) {
			const profile = $profiles.cache.get(otherDid);
			if (profile) return profile.displayName ?? profile.handle;
		}
		if (convo.displayName.startsWith('did:') && otherDid) {
			return otherDid.slice(0, 20) + '…';
		}
		return convo.displayName;
	}

	let currentDisplayName = $derived(
		currentConversation ? resolvedDisplayName(currentConversation) : ''
	);

	// MARK: - Window title
	$effect(() => {
		document.title = currentConversation
			? `${currentDisplayName} — Catmos`
			: 'Catmos';
	});

	$effect(() => {
		if (currentConversation && $requests.pane === 'none' && ordinaryAllowed(currentConversation.id)) {
			replyingTo = null;
			const convoId = currentConversation.id;
			(async () => {
				await messages.load(convoId);
				await messages.fetchFromServer(convoId);
				await subscribeToConversation(convoId);
				// Pull-based seed for Layer 3 quarantine state. Covers the
				// restart-with-pre-existing-quarantine case where no
				// `mls://quarantined` event ever fires.
				await quarantine.refresh(convoId);
			})();
		}
	});

	let activeQuarantine = $derived(
		currentConversation ? ($quarantine[currentConversation.id] ?? null) : null
	);

	onDestroy(() => {
		window.removeEventListener('keydown', handleGlobalKeydown);
		unlistenMessage?.();
		unlistenReaction?.();
		unlistenTyping?.();
		unlistenGroupReset?.();
		unlistenQuarantined?.();
		unlistenQuarantineCleared?.();
		unlistenRecovery?.();
		unlistenConnected?.();
		if (subscribedConvoId) {
			api.unsubscribeConversation(subscribedConvoId).catch(() => {});
		}
	});

	let currentMessages = $derived(
		currentConversation
			? ($messages.byConversation.get(currentConversation.id) ?? [])
			: []
	);
	let currentTypingUsers = $derived(
		currentConversation
			? ($messages.typingByConversation.get(currentConversation.id) ?? []).filter(
					(did) => did !== $auth.user?.did
				)
			: []
	);

	async function handleSend(content: string) {
		if (!currentConversation || !ordinaryAllowed(currentConversation.id)) return;
		let finalContent = content;
		if (replyingTo) {
			finalContent = JSON.stringify({
				text: content,
				reply: {
					messageId: replyingTo.messageId,
					senderDid: replyingTo.senderDid,
					preview: replyingTo.preview
				}
			});
			replyingTo = null;
		}
		await messages.send(currentConversation.id, finalContent);
	}

	async function handleSendImage(content: string, image: PreparedImageUpload) {
		if (currentConversation && ordinaryAllowed(currentConversation.id)) {
			await messages.sendImage(currentConversation.id, content, image);
		}
	}

	async function handleTypingChanged(isTyping: boolean) {
		if (!currentConversation || !ordinaryAllowed(currentConversation.id)) return;
		try {
			await api.sendTyping(currentConversation.id, isTyping);
		} catch (e) {
			console.error('Failed to send typing indicator:', e);
		}
	}

	function handleSearchNavigate(conversationId: string, messageId: string) {
		conversations.select(conversationId);
		// After conversation loads, scroll to the target message
		requestAnimationFrame(() => {
			setTimeout(() => {
				const el = document.querySelector(`[data-message-id="${messageId}"]`);
				if (el) {
					el.scrollIntoView({ behavior: 'smooth', block: 'center' });
					el.classList.add('search-highlight');
					setTimeout(() => el.classList.remove('search-highlight'), 2000);
				}
			}, 300);
		});
	}
</script>

{#if !$auth.user}
	<div class="login-card">
		<div class="login-logo">
			<svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
				<path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" />
			</svg>
		</div>
		<h1 class="login-title">Catmos</h1>
		<p class="login-subtitle">End-to-end encrypted messaging on AT Protocol</p>
		{#if $auth.waitingForOAuth}
			<div class="oauth-waiting">
				<div class="oauth-spinner"></div>
				<p class="oauth-message">Waiting for authentication...</p>
				<p class="oauth-hint">Complete sign in in your browser</p>
				<button class="btn btn-secondary" onclick={() => auth.cancelLogin()}>
					Cancel
				</button>
			</div>
		{:else}
			<form onsubmit={handleLogin}>
				<input
					type="text"
					placeholder="Handle or email"
					bind:value={loginIdentifier}
					class="login-input"
				/>
				{#if $auth.error}
					<p class="login-error" role="alert">{$auth.error}</p>
					<button type="button" class="btn btn-secondary restore-btn" onclick={() => auth.tryRestore()}>
						Try restoring session
					</button>
				{/if}
				<button type="submit" class="btn btn-primary login-btn" disabled={$auth.loading || !loginIdentifier}>
					Sign in with Bluesky
				</button>
			</form>
		{/if}
	</div>
{:else if $requests.pane === 'inbox'}
	<RequestInbox />
{:else if $requests.pane === 'draft' && activeDraft}
	<RequestComposer draft={activeDraft} onOpenConversation={openRequestConversation} />
{:else if activeRequest && ($requests.pane === 'request' || activeRequest.consent !== 'accepted')}
	<RequestDetail view={activeRequest} title={currentDisplayName || 'Message request'} onOpenConversation={openRequestConversation} onViewInvitation={viewGroupInvitation} />
{:else if $requests.pane === 'request' || (currentConversation && !ordinaryAllowed(currentConversation.id))}
	<section class="empty-state"><div class="empty-state-content"><h2>Conversation is awaiting consent</h2><p>Ordinary activity is paused while request authority is unavailable.</p><button onclick={() => requests.showInbox()}>Open message requests</button></div></section>
{:else if currentConversation}
	<div class="chat-area">
		<header class="chat-header">
			<div class="chat-header-left">
				<button
					class="mobile-back"
					onclick={() => {
						showMembers = false;
						conversations.select(null);
					}}
					title="Back to conversations"
					aria-label="Back to conversations"
				>
					<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
						<polyline points="15 18 9 12 15 6" />
					</svg>
				</button>
				{#if currentConversation.avatarDataUrl}
					<img
						class="chat-header-avatar"
						src={currentConversation.avatarDataUrl}
						alt=""
					/>
				{/if}
				<div class="chat-header-info">
					<h2 class="chat-title">{currentDisplayName}</h2>
					<div class="chat-subtitle">
						{#if currentConversation.isGroup}
							<span class="e2ee-badge">
								<svg width="10" height="10" viewBox="0 0 24 24" fill="currentColor">
									<path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zM12 17c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1s3.1 1.39 3.1 3.1v2z"/>
								</svg>
								E2EE
							</span>
							<span class="header-divider">&middot;</span>
							<span class="member-count">{currentConversation.members.length} members</span>
						{:else}
							<span class="e2ee-badge">
								<svg width="10" height="10" viewBox="0 0 24 24" fill="currentColor">
									<path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zM12 17c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1s3.1 1.39 3.1 3.1v2z"/>
								</svg>
								E2EE
							</span>
						{/if}
						{#if currentConversation.description}
							<span class="header-divider">&middot;</span>
							<span class="group-description">{currentConversation.description}</span>
						{/if}
					</div>
				</div>
			</div>
			<div class="chat-header-actions">
				<button
					class="icon-btn"
					onclick={() => (showSearch = true)}
					title="Search messages (Cmd+K)"
				>
					<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
						<circle cx="11" cy="11" r="8" />
						<line x1="21" y1="21" x2="16.65" y2="16.65" />
					</svg>
				</button>
				{#if currentConversation.isGroup}
					<button
						class="icon-btn"
						class:active={showMembers}
						onclick={() => (showMembers = !showMembers)}
						title="Toggle member list"
					>
						<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
							<path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" />
							<circle cx="9" cy="7" r="4" />
							<path d="M23 21v-2a4 4 0 0 0-3-3.87" />
							<path d="M16 3.13a4 4 0 0 1 0 7.75" />
						</svg>
					</button>
				{/if}
			</div>
		</header>
		<ConnectionStatus />
		{#if activeQuarantine}
			<QuarantineBanner
				conversationId={currentConversation.id}
				quarantineState={activeQuarantine}
			/>
		{/if}
		<div class="chat-body">
			<MessageList request={activeRequest} messages={currentMessages} typingUsers={currentTypingUsers} onReply={(info) => { replyingTo = info; }} />
			{#if showMembers && currentConversation.isGroup}
				<MemberList conversationId={currentConversation.id} quarantine={activeQuarantine} />
			{/if}
		</div>
		{#if replyingTo}
			<ReplyPreview
				senderName={replyingTo.senderName}
				preview={replyingTo.preview}
				onCancel={() => { replyingTo = null; }}
			/>
		{/if}
		{#if !activeRequest || activeRequest.consent !== 'accepted' || activeRequest.capabilities?.canSend !== false}
			<Composer
				conversationId={currentConversation.id}
				onSend={handleSend}
				onSendImage={handleSendImage}
				onTypingChanged={handleTypingChanged}
				disabled={activeQuarantine !== null}
				disabledPlaceholder={activeQuarantine ? 'Conversation paused. Reset to continue.' : undefined}
			/>
		{/if}
	</div>
	<SearchPanel
		open={showSearch}
		onClose={() => { showSearch = false; }}
		onNavigate={handleSearchNavigate}
	/>
{:else}
	<div class="empty-state">
		<div class="empty-state-content">
			<svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="var(--text-tertiary)" stroke-width="0.75" stroke-linecap="round" stroke-linejoin="round" style="opacity: 0.4; margin-bottom: 16px;">
				<path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" />
			</svg>
			<h2>Welcome to Catmos</h2>
			<p>Select a conversation or start a new one</p>
		</div>
	</div>
{/if}

<style>
	/* ── Login ── */
	.login-card {
		background: var(--bg-card);
		border: 1px solid var(--border);
		border-radius: var(--radius-xl);
		padding: 40px;
		width: 380px;
		text-align: center;
		box-shadow: var(--shadow-lg);
	}

	.login-logo {
		margin-bottom: 16px;
	}

	.login-title {
		color: var(--text-primary);
		font-size: 24px;
		font-weight: 700;
		letter-spacing: -0.03em;
		margin-bottom: 6px;
	}

	.login-subtitle {
		color: var(--text-secondary);
		font-size: 14px;
		margin-bottom: 28px;
	}

	.login-input {
		display: block;
		width: 100%;
		padding: 12px 16px;
		background: var(--bg-input);
		border: 1px solid var(--border);
		border-radius: var(--radius-sm);
		margin-bottom: 12px;
		color: var(--text-primary);
		font-size: 15px;
		transition: border-color var(--transition-fast);
	}

	.login-input:focus {
		border-color: var(--accent);
		outline: none;
	}

	.login-input::placeholder {
		color: var(--text-tertiary);
	}

	.login-error {
		color: var(--danger);
		font-size: 13px;
		margin-bottom: 12px;
	}

	.btn {
		padding: 10px 20px;
		border-radius: var(--radius-sm);
		font-weight: 600;
		font-size: 14px;
		transition: all var(--transition-fast);
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

	.btn-secondary {
		background: var(--bg-hover);
		color: var(--text-primary);
	}

	.btn-secondary:hover {
		background: var(--bg-active);
	}

	.login-btn {
		width: 100%;
	}

	.restore-btn {
		width: 100%;
		margin-bottom: 12px;
	}

	.oauth-waiting {
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: 8px;
	}

	.oauth-spinner {
		width: 32px;
		height: 32px;
		border: 3px solid var(--border);
		border-top: 3px solid var(--accent);
		border-radius: var(--radius-full);
		animation: spin 0.8s linear infinite;
		margin-bottom: 8px;
	}

	@keyframes spin {
		to { transform: rotate(360deg); }
	}

	.oauth-message {
		color: var(--text-primary);
		font-weight: 600;
	}

	.oauth-hint {
		color: var(--text-secondary);
		font-size: 13px;
		margin-bottom: 8px;
	}

	/* ── Chat area ── */
	.chat-area {
		flex: 1;
		display: flex;
		flex-direction: column;
		background: var(--bg-chat);
		min-width: 0;
	}

	.chat-header {
		height: var(--header-height);
		padding: 0 20px;
		display: flex;
		align-items: center;
		justify-content: space-between;
		border-bottom: 1px solid var(--border);
		flex-shrink: 0;
		background: var(--bg-sidebar);
	}

	.chat-header-left {
		display: flex;
		align-items: center;
		gap: 8px;
		min-width: 0;
		flex: 1;
	}

	.mobile-back {
		display: none;
		width: 34px;
		height: 34px;
		align-items: center;
		justify-content: center;
		border-radius: var(--radius-sm);
		color: var(--accent);
		flex-shrink: 0;
	}

	.mobile-back:hover {
		background: var(--bg-hover);
	}

	.chat-header-info {
		min-width: 0;
	}

	.chat-header-avatar {
		width: 32px;
		height: 32px;
		border-radius: 50%;
		object-fit: cover;
		flex-shrink: 0;
	}

	.chat-title {
		font-size: 15px;
		font-weight: 700;
		color: var(--text-primary);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
		letter-spacing: -0.01em;
	}

	.chat-subtitle {
		display: flex;
		align-items: center;
		gap: 6px;
		margin-top: 1px;
	}

	.e2ee-badge {
		display: inline-flex;
		align-items: center;
		gap: 3px;
		font-size: 11px;
		font-weight: 600;
		color: var(--success);
	}

	.header-divider {
		color: var(--text-tertiary);
		font-size: 11px;
	}

	.member-count {
		font-size: 12px;
		color: var(--text-secondary);
	}

	.group-description {
		font-size: 12px;
		color: var(--text-secondary);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
		max-width: 240px;
	}

	.chat-header-actions {
		display: flex;
		align-items: center;
		gap: 4px;
		flex-shrink: 0;
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

	.icon-btn.active {
		color: var(--accent);
		background: var(--bg-selected);
	}

	.chat-body {
		flex: 1;
		display: flex;
		overflow: hidden;
		min-height: 0;
	}

	/* ── Empty state ── */
	.empty-state {
		flex: 1;
		display: flex;
		align-items: center;
		justify-content: center;
		background: var(--bg-chat);
	}

	.empty-state-content {
		text-align: center;
	}

	.empty-state-content h2 {
		color: var(--text-primary);
		font-size: 20px;
		font-weight: 700;
		margin-bottom: 6px;
		letter-spacing: -0.02em;
	}

	.empty-state-content p {
		color: var(--text-secondary);
		font-size: 14px;
	}

	:global(.search-highlight) {
		animation: highlight-flash 2s ease-out;
	}

	@keyframes highlight-flash {
		0%, 20% { background-color: var(--accent-hover); }
		100% { background-color: transparent; }
	}

	@media (max-width: 768px) {
		.login-card {
			width: min(100%, 420px);
			padding: 28px;
		}

		.chat-header {
			padding: 0 12px;
		}

		.mobile-back {
			display: inline-flex;
		}

		.chat-area {
			padding-bottom: env(safe-area-inset-bottom);
		}
	}
</style>

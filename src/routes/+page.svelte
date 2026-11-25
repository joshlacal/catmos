<script lang="ts">
	import { onDestroy, onMount } from 'svelte';
	import { get } from 'svelte/store';
	import AuthScreen from '#lib/components/AuthScreen.svelte';
	import ChatHeader from '#lib/components/ChatHeader.svelte';
	import CommandPalette from '#lib/components/CommandPalette.svelte';
	import Composer from '#lib/components/Composer.svelte';
	import ConnectionStatus from '#lib/components/ConnectionStatus.svelte';
	import ConversationInspector from '#lib/components/ConversationInspector.svelte';
	import EmptyWorkspace from '#lib/components/EmptyWorkspace.svelte';
	import Icon from '#lib/components/Icon.svelte';
	import MessageList from '#lib/components/MessageList.svelte';
	import NewConversationDialog from '#lib/components/NewConversationDialog.svelte';
	import QuarantineBanner from '#lib/components/QuarantineBanner.svelte';
	import SettingsDialog from '#lib/components/SettingsDialog.svelte';
	import Sidebar from '#lib/components/Sidebar.svelte';
	import { isSameAccountDid, stripDidFragment } from '#lib/did.ts';
	import { isMlsOptedInForDid } from '#lib/labyrinth-ui.ts';
	import { notifyIncomingMessage, setNotificationSelectHandler } from '#lib/notifications.ts';
	import { auth } from '#lib/stores/auth.ts';
	import { connection } from '#lib/stores/connection.ts';
	import {
		conversations,
		reconcileBlockedConversations,
		selectedConversation
	} from '#lib/stores/conversations.ts';
	import { getCursor, saveCursor } from '#lib/stores/cursors.ts';
	import { messages } from '#lib/stores/messages.ts';
	import { profiles, resolveProfileName } from '#lib/stores/profiles.ts';
	import { quarantine } from '#lib/stores/quarantine.ts';
	import {
		closeCommandPalette,
		closeNewConversation,
		closeSettings,
		openCommandPalette,
		openNewConversation,
		openSettings,
		resetUi,
		setHighlightMessageId,
		setShowInspector,
		toggleInspector,
		toggleSidebar,
		ui
	} from '#lib/stores/ui.ts';
	import type {
		Conversation,
		GroupResetEvent,
		Message,
		QuarantineClearedEvent,
		QuarantineEnteredEvent,
		ReactionEvent,
		TypingEvent
	} from '#lib/tauri.ts';
	import { announce, showToast } from '#lib/utils/announcer.ts';
	import {
		closeWithReset,
		useDialogLightDismiss,
		useDialogSafeAutofocus
	} from '#lib/utils/dialog.ts';
	import * as api from '#lib/wasm.ts';
	import { isTauri, listenForEvent } from '#lib/wasm.ts';

	let replyingTo = $state<Message | null>(null);
	let signOutDialog = $state<HTMLDialogElement | null>(null);
	let signingOut = $state(false);

	let unlistenMessage: (() => void) | null = null;
	let unlistenMessagesChanged: (() => void) | null = null;
	let unlistenReaction: (() => void) | null = null;
	let unlistenTyping: (() => void) | null = null;
	let unlistenGroupReset: (() => void) | null = null;
	let unlistenQuarantined: (() => void) | null = null;
	let unlistenQuarantineCleared: (() => void) | null = null;
	let unlistenRecovery: (() => void) | null = null;

	let mounted = true;
	let subscribedConvoId: string | null = null;
	let subscription = Symbol();
	let activeSwitchToken = 0;
	let blockReconcileRan = false;
	let lastInitializedDid: string | null = null;
	let highlightClearTimer: ReturnType<typeof setTimeout> | null = null;
	const bootstrappedGroupIds = new Set<string>();

	const currentConversation = $derived($selectedConversation);
	const currentQuarantine = $derived(
		currentConversation ? ($quarantine[currentConversation.id] ?? null) : null
	);
	const currentMessages = $derived(
		currentConversation
			? ($messages.byConversation.get(currentConversation.id) ?? [])
			: []
	);

	function isDemoActive(): boolean {
		return (
			import.meta.env.DEV &&
			typeof document !== 'undefined' &&
			document.documentElement.dataset.catmosDemo === 'true'
		);
	}

	function normalizeWsStatus(rawStatus: unknown): { type: string; reason?: string } {
		const type =
			typeof rawStatus === 'string'
				? rawStatus
				: ((rawStatus as { type?: string } | null | undefined)?.type ?? 'unknown');
		if (rawStatus && typeof rawStatus === 'object') {
			const record = rawStatus as { reason?: unknown; error?: unknown };
			const reason =
				typeof record.reason === 'string'
					? record.reason
					: typeof record.error === 'string'
						? record.error
						: undefined;
			return { type, reason };
		}
		return { type };
	}

	function resolvedDisplayName(convo: Conversation): string {
		if (convo.isGroup) return convo.displayName;
		const otherRaw =
			convo.members.find((did) => !isSameAccountDid(did, $auth.user?.did)) ?? convo.members[0];
		const otherDid = stripDidFragment(otherRaw);
		if (otherDid) {
			return resolveProfileName($profiles.cache, otherDid);
		}
		return convo.displayName;
	}

	const currentDisplayName = $derived(
		currentConversation ? resolvedDisplayName(currentConversation) : ''
	);

	function runMobileNavigationTransition(direction: 'forward' | 'backward', update: () => void) {
		if (
			typeof document === 'undefined' ||
			typeof window === 'undefined' ||
			!('startViewTransition' in document)
		) {
			update();
			return;
		}
		const isMobile = window.matchMedia('(max-width: 767px)').matches;
		const prefersReduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
		if (!isMobile || prefersReduced) {
			update();
			return;
		}
		const docWithTransition = document as Document & {
			startViewTransition: (cb: () => void) => { finished: Promise<void> };
		};
		document.documentElement.dataset.navDirection = direction;
		try {
			const transition = docWithTransition.startViewTransition(update);
			transition.finished
				.catch(() => {})
				.finally(() => {
					delete document.documentElement.dataset.navDirection;
				});
		} catch {
			delete document.documentElement.dataset.navDirection;
			update();
		}
	}

	function handleSelectConvo(convoId: string) {
		if ($conversations.selectedId === convoId) return;
		runMobileNavigationTransition('forward', () => {
			conversations.select(convoId);
		});
	}

	function handleMobileBack() {
		runMobileNavigationTransition('backward', () => {
			setShowInspector(false);
			conversations.select(null);
		});
	}

	function findLatestConfirmedMessageId(convoId: string): string | null {
		const list = get(messages).byConversation.get(convoId) ?? [];
		for (let i = list.length - 1; i >= 0; i--) {
			const msg = list[i];
			if (msg && msg.id && !msg.id.startsWith('temp-')) {
				return msg.id;
			}
		}
		return null;
	}

	async function subscribeToConversation(
		convoId: string,
		options: { force?: boolean; switchToken?: number; throwOnError?: boolean } = {}
	) {
		const { force = false, switchToken, throwOnError = false } = options;
		if (!force && subscribedConvoId === convoId) return;

		const request = Symbol();
		subscription = request;
		const account = get(auth).user?.did;
		const isCurrent = () =>
			mounted &&
			subscription === request &&
			(switchToken === undefined || switchToken === activeSwitchToken) &&
			get(auth).user?.did === account &&
			get(conversations).selectedId === convoId;

		// On Tauri, the global WS started on login already covers this convo;
		// still tear down any prior per-convo handle and advance the read cursor.
		if (subscribedConvoId) {
			const previousId = subscribedConvoId;
			subscribedConvoId = null;
			await api.unsubscribeConversation(previousId).catch(() => {});
		}
		if (!isCurrent()) return;
		subscribedConvoId = convoId;

		if (!isTauri) {
			const savedCursor = getCursor(convoId);
			try {
				await api.subscribeConversation(
					convoId,
					(msg) => {
						if (!isCurrent()) return;
						const incoming = msg as Message;
						void messages.refreshLocal(convoId);
						saveCursor(convoId, incoming.id);
						const currentUserDid = get(auth).user?.did;
						conversations.applyMessageActivity(convoId, {
							text: incoming.content,
							timestamp: incoming.timestamp,
							isOwn: isSameAccountDid(incoming.senderDid, currentUserDid),
							isSelected: true
						});
						const senderLabel = resolveProfileName(
							get(profiles).cache,
							incoming.senderDid,
							incoming.senderHandle
						);
						notifyIncomingMessage(senderLabel, incoming.content, convoId, {
							senderDid: incoming.senderDid,
							currentUserDid,
							onSelectConversation: handleSelectConvo
						});
					},
					(event) => {
						if (!isCurrent()) return;
						const e = event as { type: string; data: unknown; reason?: string };
						if (e?.type === 'reaction') {
							messages.applyReaction(e.data as ReactionEvent);
						} else if (e?.type === 'typing') {
							messages.applyTyping(e.data as TypingEvent);
						} else if (e?.type === 'messagesChanged') {
							void messages.refreshCached(convoId);
						} else if (e?.type === 'fetchNeeded') {
							const reason = e.reason ?? 'unknown';
							console.warn(`[catmos] WS decrypt failed (${reason}), fetching via HTTP`);
							messages.fetchFromServer(convoId);
						}
					},
					(rawStatus) => {
						if (!isCurrent()) return;
						const normalized = normalizeWsStatus(rawStatus);
						if (normalized.type === 'connected' || normalized.type === 'open') {
							if (
								isDemoActive() &&
								get(connection).state !== 'connecting' &&
								get(connection).state !== 'connected'
							) {
								return;
							}
							connection.setConnected();
						} else if (
							normalized.type === 'closed' ||
							normalized.type === 'error' ||
							normalized.type === 'disconnected'
						) {
							connection.setDisconnected(normalized.reason ?? normalized.type);
						}
					},
					savedCursor ?? undefined
				);
			} catch (err) {
				console.error('[catmos] WebSocket subscribe failed:', err);
				if (subscribedConvoId === convoId) {
					subscribedConvoId = null;
				}
				connection.setDisconnected(err instanceof Error ? err.message : String(err));
				if (throwOnError) {
					throw err;
				}
				return;
			}
		} else if (get(connection).state === 'connecting') {
			connection.setConnected();
		}

		if (!isCurrent()) return;

		const latestConfirmedId = findLatestConfirmedMessageId(convoId);
		if (latestConfirmedId) {
			saveCursor(convoId, latestConfirmedId);
			api.updateCursor(convoId, latestConfirmedId).catch(() => {});
		}
		conversations.markConversationRead(convoId);
	}

	async function bootstrapMetadataIfNeeded(convoId: string, switchToken: number) {
		if (isDemoActive()) return;
		const convo = get(conversations).items.find((c) => c.id === convoId);
		if (!convo || !convo.isGroup || !convo.groupId) return;
		if (bootstrappedGroupIds.has(convo.groupId)) return;
		if (convo.avatarDataUrl && convo.description) {
			bootstrappedGroupIds.add(convo.groupId);
			return;
		}

		bootstrappedGroupIds.add(convo.groupId);
		try {
			const meta = await api.bootstrapGroupMetadata(convo.groupId);
			if (switchToken !== activeSwitchToken || !meta) return;
			const latest = get(conversations).items.find((c) => c.id === convoId);
			if (!latest) return;
			const avatarDataUrl =
				meta.avatarBytesBase64 && meta.avatarContentType
					? `data:${meta.avatarContentType};base64,${meta.avatarBytesBase64}`
					: latest.avatarDataUrl;
			conversations.updateConversation({
				...latest,
				displayName: meta.title || latest.displayName,
				description: meta.description || latest.description,
				avatarDataUrl
			});
		} catch {
			bootstrappedGroupIds.delete(convo.groupId);
		}
	}

	async function handleQuarantineReset(convoId: string) {
		await quarantine.refresh(convoId);
		await conversations.load();
		await messages.fetchFromServer(convoId);
	}

	function handleLeftConversation() {
		setShowInspector(false);
		replyingTo = null;
		if (subscribedConvoId) {
			const prev = subscribedConvoId;
			subscribedConvoId = null;
			api.unsubscribeConversation(prev).catch(() => {});
		}
	}

	async function handleResetLocalStorage() {
		await auth.logout();
		resetUi();
		window.location.reload();
	}

	function handleSignOutDialogClose() {
		if (signOutDialog) {
			signOutDialog.returnValue = '';
		}
	}

	async function confirmSignOut() {
		if (signingOut) return;
		signingOut = true;
		try {
			closeWithReset(signOutDialog, 'confirm');
			activeSwitchToken += 1;
			subscription = Symbol();
			if (subscribedConvoId) {
				const prev = subscribedConvoId;
				subscribedConvoId = null;
				await api.unsubscribeConversation(prev).catch(() => {});
			}
			replyingTo = null;
			blockReconcileRan = false;
			lastInitializedDid = null;
			bootstrappedGroupIds.clear();
			await auth.logout();
			resetUi();
			announce('Signed out of Catmos');
		} catch (err) {
			showToast({
				message: err instanceof Error ? err.message : 'Could not sign out cleanly.',
				tone: 'error'
			});
		} finally {
			signingOut = false;
		}
	}

	onMount(() => {
		mounted = true;
		setNotificationSelectHandler(handleSelectConvo);

		if (!isDemoActive()) {
			connection.onReconnect(async () => {
				if (!mounted || !subscribedConvoId) return;
				const targetId = subscribedConvoId;
				await messages.fetchFromServer(targetId);
				await subscribeToConversation(targetId, { force: true, throwOnError: true });
			});
		}

		listenForEvent<Message>('mls-incoming-message', (payload) => {
			void messages.refreshLocal(payload.conversationId);
			saveCursor(payload.conversationId, payload.id);
			const currentUserDid = get(auth).user?.did;
			conversations.applyMessageActivity(payload.conversationId, {
				text: payload.content,
				timestamp: payload.timestamp,
				isOwn: isSameAccountDid(payload.senderDid, currentUserDid),
				isSelected: get(conversations).selectedId === payload.conversationId
			});
			const senderLabel = resolveProfileName(
				get(profiles).cache,
				payload.senderDid,
				payload.senderHandle
			);
			notifyIncomingMessage(senderLabel, payload.content, payload.conversationId, {
				senderDid: payload.senderDid,
				currentUserDid,
				onSelectConversation: handleSelectConvo
			});
		}).then((unlisten) => {
			if (!mounted) {
				unlisten();
				return;
			}
			unlistenMessage = unlisten;
		});

		listenForEvent<'ConversationsUpdated' | { MessagesUpdated?: { conversation_id: string } }>(
			'mls://platform-change',
			(event) => {
				if (event === 'ConversationsUpdated') {
					void messages.refreshCached(get(selectedConversation)?.id);
				} else if (typeof event === 'object' && event.MessagesUpdated) {
					void messages.refreshLocal(event.MessagesUpdated.conversation_id);
				}
			}
		).then((unlisten) => {
			if (!mounted) {
				unlisten();
				return;
			}
			unlistenMessagesChanged = unlisten;
		});

		listenForEvent<ReactionEvent>('mls-reaction-event', (payload) => {
			messages.applyReaction(payload);
		}).then((unlisten) => {
			if (!mounted) {
				unlisten();
				return;
			}
			unlistenReaction = unlisten;
		});

		listenForEvent<TypingEvent>('mls-typing-event', (payload) => {
			messages.applyTyping(payload);
		}).then((unlisten) => {
			if (!mounted) {
				unlisten();
				return;
			}
			unlistenTyping = unlisten;
		});

		listenForEvent<GroupResetEvent>('mls:group-reset', (payload) => {
			console.log('[catmos] Group reset event:', payload);
			conversations.load();
			if (get(conversations).selectedId === payload.convoId) {
				messages.fetchFromServer(payload.convoId);
			}
		}).then((unlisten) => {
			if (!mounted) {
				unlisten();
				return;
			}
			unlistenGroupReset = unlisten;
		});

		// Layer 3 quarantine live transitions
		listenForEvent<QuarantineEnteredEvent>('mls://quarantined', (payload) => {
			console.warn('[catmos] Conversation quarantined:', payload);
			quarantine.applyEnteredEvent(payload);
		}).then((unlisten) => {
			if (!mounted) {
				unlisten();
				return;
			}
			unlistenQuarantined = unlisten;
		});

		listenForEvent<QuarantineClearedEvent>('mls://quarantine-cleared', (payload) => {
			console.log('[catmos] Quarantine cleared:', payload);
			quarantine.applyClearedEvent(payload);
		}).then((unlisten) => {
			if (!mounted) {
				unlisten();
				return;
			}
			unlistenQuarantineCleared = unlisten;
		});

		// Backend reconnect loops stop on explicit auth/device/MLS failures;
		// surface the stable category so the banner offers the right recovery action.
		listenForEvent<string>('mls-ws-recovery', (payload) => {
			connection.setDisconnected(payload);
		}).then((unlisten) => {
			if (!mounted) {
				unlisten();
				return;
			}
			unlistenRecovery = unlisten;
		});
	});

	// Scope message cache per DID and initialize subscriptions & conversation list on login
	$effect(() => {
		const activeDid = $auth.user?.did;
		if (isDemoActive()) {
			return;
		}
		messages.setAccount(activeDid);
		if (!activeDid) {
			lastInitializedDid = null;
			blockReconcileRan = false;
			return;
		}
		// ctl #2: never spawn browser MLS worker or call DS until user opts in
		if (!isTauri && !isMlsOptedInForDid(activeDid)) {
			return;
		}
		if (lastInitializedDid === activeDid) return;
		lastInitializedDid = activeDid;

		api.subscribeAllEvents().catch((err) => {
			console.warn('[catmos] subscribeAllEvents failed:', err);
		});

		conversations.load().then(() => {
			if (!blockReconcileRan) {
				blockReconcileRan = true;
				reconcileBlockedConversations().catch((err) => {
					console.warn('[catmos] block reconciliation failed:', err);
				});
			}
		});
	});

	// Window title (zero em-dashes)
	$effect(() => {
		if (typeof document === 'undefined') return;
		document.title = currentConversation ? `${currentDisplayName} · Catmos` : 'Catmos';
	});

	// Drop stale reply context if the target message leaves the visible window
	$effect(() => {
		if (replyingTo && !currentMessages.some((message) => message.id === replyingTo?.id)) {
			replyingTo = null;
		}
	});

	// Track ONLY selectedId + account DID with stale-switch cancellation & cleanup
	$effect(() => {
		const selectedId = $conversations.selectedId;
		const activeDid = $auth.user?.did;
		replyingTo = null;

		if (!activeDid || !selectedId) {
			activeSwitchToken += 1;
			return;
		}

		const switchToken = ++activeSwitchToken;
		const demo = isDemoActive();
		let active = true;

		(async () => {
			const existingLoaded = get(messages).byConversation.get(selectedId);
			if (!demo || !existingLoaded || existingLoaded.length === 0) {
				await messages.load(selectedId);
			}
			if (!active || switchToken !== activeSwitchToken) return;

			if (!demo) {
				await messages.fetchFromServer(selectedId);
				if (!active || switchToken !== activeSwitchToken) return;
			}

			await subscribeToConversation(selectedId, { switchToken });
			if (!active || switchToken !== activeSwitchToken) return;

			if (!demo) {
				await quarantine.refresh(selectedId);
				if (!active || switchToken !== activeSwitchToken) return;
				await bootstrapMetadataIfNeeded(selectedId, switchToken);
			}
		})();

		return () => {
			active = false;
			subscription = Symbol();
			if (subscribedConvoId) {
				const prev = subscribedConvoId;
				subscribedConvoId = null;
				void api.unsubscribeConversation(prev).catch(() => {});
			}
		};
	});

	// Auto-clear search highlight after animation window so repeated jumps work cleanly
	$effect(() => {
		const id = $ui.highlightMessageId;
		if (highlightClearTimer !== null) {
			clearTimeout(highlightClearTimer);
			highlightClearTimer = null;
		}
		if (id) {
			highlightClearTimer = setTimeout(() => {
				setHighlightMessageId(null);
			}, 2600);
		}
	});

	onDestroy(() => {
		mounted = false;
		setNotificationSelectHandler(null);
		if (highlightClearTimer !== null) {
			clearTimeout(highlightClearTimer);
		}
		unlistenMessage?.();
		unlistenMessagesChanged?.();
		unlistenReaction?.();
		unlistenTyping?.();
		unlistenGroupReset?.();
		unlistenQuarantined?.();
		unlistenQuarantineCleared?.();
		unlistenRecovery?.();
		if (subscribedConvoId) {
			api.unsubscribeConversation(subscribedConvoId).catch(() => {});
			subscribedConvoId = null;
		}
	});
</script>

{#if !$auth.user}
	<AuthScreen />
{:else}
	<div
		class="app-shell"
		class:sidebar-collapsed={$ui.sidebarCollapsed}
		class:mobile-chat-view={Boolean(currentConversation)}
	>
		<div class="sidebar-pane">
			<Sidebar
				onSelectConversation={handleSelectConvo}
				onOpenNewConversation={openNewConversation}
				onOpenCommandPalette={openCommandPalette}
				onOpenSettings={openSettings}
				onOpenInspector={(id: string) => {
					handleSelectConvo(id);
					setShowInspector(true);
				}}
				onToggleCollapse={toggleSidebar}
				onRequestSignOut={() => signOutDialog?.showModal()}
			/>
		</div>

		<main id="main-thread" class="main-content">
			<ConnectionStatus />

			{#if currentConversation}
				<div class="thread-workspace">
					<div class="thread-column">
						<ChatHeader
							conversation={currentConversation}
							sidebarCollapsed={$ui.sidebarCollapsed}
							showInspector={$ui.showInspector}
							onBack={handleMobileBack}
							onExpandSidebar={toggleSidebar}
							onOpenSearch={openCommandPalette}
							onToggleInspector={toggleInspector}
						/>

						{#if currentQuarantine}
							<QuarantineBanner
								conversationId={currentConversation.id}
								state={currentQuarantine}
								onResetComplete={() => handleQuarantineReset(currentConversation.id)}
							/>
						{/if}

						<MessageList
							conversation={currentConversation}
							highlightMessageId={$ui.highlightMessageId}
							onReply={(msg) => {
								replyingTo = msg;
							}}
						/>

						<Composer
							conversationId={currentConversation.id}
							replyTo={replyingTo}
							disabled={Boolean(currentQuarantine)}
							disabledReason={currentQuarantine
								? 'This conversation is paused until its encryption session is reset.'
								: null}
							onCancelReply={() => {
								replyingTo = null;
							}}
						/>
					</div>

					<ConversationInspector
						conversation={currentConversation}
						open={$ui.showInspector}
						onClose={() => setShowInspector(false)}
						onLeftConversation={handleLeftConversation}
					/>
				</div>
			{:else}
				<div class="empty-column">
					{#if $ui.sidebarCollapsed}
						<div class="empty-toolbar">
							<button
								type="button"
								class="catmos-btn-ghost expand-sidebar-btn"
								onclick={toggleSidebar}
								aria-label="Show sidebar"
								title="Show sidebar"
							>
								<Icon name="sidebar" size={18} />
								<span>Conversations</span>
							</button>
						</div>
					{/if}
					<EmptyWorkspace
						onOpenNewConversation={openNewConversation}
						onOpenCommandPalette={openCommandPalette}
					/>
				</div>
			{/if}
		</main>
	</div>

	<NewConversationDialog
		open={$ui.showNewConversation}
		onClose={closeNewConversation}
		onCreated={(id: string) => {
			handleSelectConvo(id);
			closeNewConversation();
		}}
	/>

	<CommandPalette
		open={$ui.showCommandPalette}
		onClose={closeCommandPalette}
		onSelectConversation={(id: string) => {
			handleSelectConvo(id);
			closeCommandPalette();
		}}
		onJumpToMessage={(convoId: string, msgId: string) => {
			handleSelectConvo(convoId);
			setHighlightMessageId(msgId);
			closeCommandPalette();
		}}
		onOpenNewConversation={() => {
			closeCommandPalette();
			openNewConversation();
		}}
		onOpenSettings={() => {
			closeCommandPalette();
			openSettings();
		}}
		onToggleInspector={() => {
			closeCommandPalette();
			toggleInspector();
		}}
	/>

	<SettingsDialog
		open={$ui.showSettings}
		initialTab={$ui.settingsTab}
		onClose={closeSettings}
		onRequestSignOut={() => {
			closeSettings();
			signOutDialog?.showModal();
		}}
		onResetLocalStorage={handleResetLocalStorage}
	/>

	<dialog
		bind:this={signOutDialog}
		class="catmos-dialog sign-out-dialog"
		closedby="any"
		use:useDialogLightDismiss
		onclose={handleSignOutDialogClose}
	>
		<div class="dialog-inner">
			<h1 class="dialog-title">Sign out of Catmos?</h1>
			<p class="dialog-copy">
				You will need to sign in with Bluesky again to read or send encrypted messages on this
				device.
			</p>
			<div class="dialog-actions">
				<button
					type="button"
					class="catmos-btn-secondary"
					use:useDialogSafeAutofocus
					onclick={() => closeWithReset(signOutDialog, 'cancel')}
				>
					Cancel
				</button>
				<button
					type="button"
					class="catmos-btn-danger"
					disabled={signingOut}
					onclick={confirmSignOut}
				>
					{signingOut ? 'Signing out...' : 'Sign out'}
				</button>
			</div>
		</div>
	</dialog>
{/if}

<style>
	.app-shell {
		display: flex;
		block-size: 100dvh;
		inline-size: 100vw;
		overflow: hidden;
		background: var(--bg-app);
	}

	.sidebar-pane {
		display: flex;
		flex-shrink: 0;
		inline-size: var(--sidebar-width);
		block-size: 100%;
		min-inline-size: 0;
	}

	.app-shell.sidebar-collapsed .sidebar-pane {
		display: none;
	}

	.main-content {
		flex: 1;
		display: flex;
		flex-direction: column;
		min-inline-size: 0;
		min-block-size: 0;
		block-size: 100%;
		background: var(--bg-chat);
		position: relative;
	}

	.thread-workspace {
		flex: 1;
		display: flex;
		min-inline-size: 0;
		min-block-size: 0;
		overflow: hidden;
	}

	.thread-column {
		flex: 1;
		display: flex;
		flex-direction: column;
		min-inline-size: 0;
		min-block-size: 0;
		overflow: hidden;
	}

	.empty-column {
		flex: 1;
		display: flex;
		flex-direction: column;
		min-inline-size: 0;
		min-block-size: 0;
	}

	.empty-toolbar {
		display: flex;
		align-items: center;
		padding: var(--space-3) var(--space-4) 0;
	}

	.expand-sidebar-btn {
		font-size: var(--text-sm);
		font-weight: 500;
		color: var(--text-secondary);
	}

	.expand-sidebar-btn:hover {
		color: var(--text-primary);
	}

	/* Sign-out confirmation modal */
	.sign-out-dialog {
		inline-size: min(25rem, calc(100vw - 2rem));
	}

	.dialog-inner {
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
		padding: var(--space-6);
	}

	.dialog-title {
		font-size: var(--text-heading);
		font-weight: 650;
		letter-spacing: -0.015em;
		line-height: 1.3;
		color: var(--text-primary);
	}

	.dialog-copy {
		font-size: var(--text-sm);
		line-height: 1.5;
		color: var(--text-secondary);
		max-inline-size: 48ch;
	}

	.dialog-actions {
		display: flex;
		align-items: center;
		justify-content: flex-end;
		gap: var(--space-2);
		margin-block-start: var(--space-2);
	}

	/* Mobile drill-down (< 768px) */
	@media (max-width: 767px) {
		.sidebar-pane {
			inline-size: 100%;
		}

		.app-shell.sidebar-collapsed .sidebar-pane {
			display: flex;
		}

		.app-shell.mobile-chat-view .sidebar-pane {
			display: none;
		}

		.app-shell:not(.mobile-chat-view) .main-content {
			display: none;
		}

		.empty-toolbar {
			display: none;
		}
	}

	/* Progressive directional view transitions on mobile navigation */
	@media (prefers-reduced-motion: no-preference) {
		:global(html[data-nav-direction='forward'])::view-transition-old(root) {
			animation: catmos-slide-out-start 180ms var(--ease-out) both;
		}
		:global(html[data-nav-direction='forward'])::view-transition-new(root) {
			animation: catmos-slide-in-end 200ms var(--ease-out) both;
		}
		:global(html[data-nav-direction='backward'])::view-transition-old(root) {
			animation: catmos-slide-out-end 180ms var(--ease-out) both;
		}
		:global(html[data-nav-direction='backward'])::view-transition-new(root) {
			animation: catmos-slide-in-start 200ms var(--ease-out) both;
		}
	}

	@keyframes catmos-slide-out-start {
		to {
			transform: translateX(-8%);
			opacity: 0.7;
		}
	}

	@keyframes catmos-slide-in-end {
		from {
			transform: translateX(12%);
			opacity: 0.7;
		}
	}

	@keyframes catmos-slide-out-end {
		to {
			transform: translateX(12%);
			opacity: 0.7;
		}
	}

	@keyframes catmos-slide-in-start {
		from {
			transform: translateX(-8%);
			opacity: 0.7;
		}
	}
</style>

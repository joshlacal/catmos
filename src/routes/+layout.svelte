<script lang="ts">
	import '../app.css';
	import { onDestroy, onMount } from 'svelte';
	import { get } from 'svelte/store';
	import { page } from '$app/state';
	import Icon from '#lib/components/Icon.svelte';
	import LiveAnnouncer from '#lib/components/LiveAnnouncer.svelte';
	import TabBlockedMessage from '#lib/components/TabBlockedMessage.svelte';
	import ToastHost from '#lib/components/ToastHost.svelte';
	import { isMlsOptedInForDid } from '#lib/labyrinth-ui.ts';
	import { auth } from '#lib/stores/auth.ts';
	import { connection } from '#lib/stores/connection.ts';
	import { conversations } from '#lib/stores/conversations.ts';
	import { applyPreferencesToDom, preferences } from '#lib/stores/preferences.ts';
	import { acquireTabLock, type TabLockStatus } from '#lib/stores/tab-lock.ts';
	import {
		closeCommandPalette,
		openCommandPalette,
		openNewConversation,
		openSettings,
		setSidebarCollapsed,
		toggleInspector,
		toggleSidebar,
		ui
	} from '#lib/stores/ui.ts';
	import * as api from '#lib/wasm.ts';
	import { initWasm, isTauri, readBrowserAuth } from '#lib/wasm.ts';

	let { children } = $props();

	let tabLockStatus = $state<TabLockStatus>('acquiring');
	let initError = $state<string | null>(null);
	let resettingStorage = $state(false);
	let resetError = $state<string | null>(null);

	let releaseTabLock: (() => void) | undefined = undefined;
	let tabSessionBootstrapped = false;
	let demoActive = false;

	const isSettingsRoute = $derived(page.url.pathname.startsWith('/settings/'));

	const isApple =
		typeof navigator !== 'undefined' && /Mac|iPhone|iPad|iPod/i.test(navigator.userAgent);

	function cycleConversation(direction: -1 | 1) {
		const convState = get(conversations);
		if (convState.items.length === 0) return;

		const pinnedSet = new Set(get(preferences).pinnedIds);
		const ordered = [
			...convState.items.filter((c) => pinnedSet.has(c.id)),
			...convState.items.filter((c) => !pinnedSet.has(c.id))
		];
		if (ordered.length === 0) return;

		const currentIdx = ordered.findIndex((c) => c.id === convState.selectedId);
		let nextIdx: number;
		if (currentIdx === -1) {
			nextIdx = direction > 0 ? 0 : ordered.length - 1;
		} else {
			nextIdx = (currentIdx + direction + ordered.length) % ordered.length;
		}
		conversations.select(ordered[nextIdx].id);
	}

	function handleGlobalKeydown(e: KeyboardEvent) {
		// Never hijack Escape; native <dialog> and [popover] handle Escape directly.
		if (e.key === 'Escape') return;
		if (!get(auth).user) return;
		if (page.url.pathname !== '/') return;

		const hasOpenDialog =
			typeof document !== 'undefined' && document.querySelector('dialog[open]') !== null;

		if (e.altKey && !e.metaKey && !e.ctrlKey && !e.shiftKey) {
			if (hasOpenDialog) return;
			if (e.key === 'ArrowUp') {
				e.preventDefault();
				cycleConversation(-1);
				return;
			}
			if (e.key === 'ArrowDown') {
				e.preventDefault();
				cycleConversation(1);
				return;
			}
		}

		const mod = isApple ? e.metaKey && !e.ctrlKey : e.ctrlKey && !e.metaKey;
		if (!mod || e.altKey) return;

		const key = e.key.toLowerCase();
		switch (key) {
			case 'k':
				e.preventDefault();
				if (get(ui).showCommandPalette) {
					closeCommandPalette();
				} else {
					openCommandPalette();
				}
				break;
			case 'n':
				e.preventDefault();
				if (get(ui).sidebarCollapsed) {
					setSidebarCollapsed(false);
				}
				openNewConversation();
				break;
			case 'b':
				e.preventDefault();
				toggleSidebar();
				break;
			case ',':
				e.preventDefault();
				openSettings();
				break;
			case 'i':
				if (get(conversations).selectedId) {
					e.preventDefault();
					toggleInspector();
				}
				break;
		}
	}

	function handleVisibilityChange() {
		if (typeof document === 'undefined' || document.visibilityState !== 'visible') return;
		if (isTauri) return;
		const user = get(auth).user;
		if (!user) return;
		if (!demoActive && !isMlsOptedInForDid(user.did)) return;
		const connState = get(connection).state;
		if (connState === 'offline') return;
		if (demoActive && connState !== 'connected') return;

		api.runDeferredRecovery().catch((err) => {
			console.warn('[catmos] deferred recovery failed:', err);
		});
	}

	async function handleResetStorage() {
		if (resettingStorage) return;
		resettingStorage = true;
		resetError = null;
		try {
			await auth.logout();
			window.location.reload();
		} catch (err) {
			resetError = err instanceof Error ? err.message : String(err);
			resettingStorage = false;
		}
	}

	async function bootstrapTabSession() {
		if (tabSessionBootstrapped) return;
		tabSessionBootstrapped = true;

		try {
			if (!isTauri) {
				const savedAuth = readBrowserAuth();
				// ctl #2: never open OPFS SQLite or trigger MLS/Spaces calls unless explicitly opted in
				if (savedAuth?.did && isMlsOptedInForDid(savedAuth.did)) {
					await initWasm(savedAuth.did);
				}
			}

			await auth.tryRestore();
		} catch (err) {
			console.error('[catmos] session bootstrap failed:', err);
			initError = err instanceof Error ? err.message : String(err);
		}
	}

	onMount(async () => {
		applyPreferencesToDom();
		window.addEventListener('keydown', handleGlobalKeydown);
		document.addEventListener('visibilitychange', handleVisibilityChange);

		if (import.meta.env.DEV) {
			try {
				const { maybeBootDemoHarness } = await import('#lib/dev/demo-harness.ts');
				const demo = await maybeBootDemoHarness();
				if (demo.active) {
					demoActive = true;
					document.documentElement.dataset.catmosDemo = 'true';
					if (demo.overrideInitError) {
						initError = demo.overrideInitError;
						tabLockStatus = 'granted';
						return;
					}
					if (demo.overrideTabLock === 'blocked') {
						tabLockStatus = 'blocked';
						return;
					}
					tabLockStatus = 'granted';
					return;
				}
			} catch (err) {
				console.warn('[catmos] demo harness boot skipped:', err);
			}
		}

		// Capture pathname at mount before any callback route redirect occurs.
		const pathname = window.location.pathname;
		const mountedOnOAuthCallback =
			pathname === '/auth/callback' ||
			pathname === '/auth/callback/' ||
			pathname === '/oauth/permission-callback' ||
			pathname === '/oauth/permission-callback/';

		// Gate 9: await exclusive navigator.locks mutex without lock stealing.
		if (!isTauri) {
			const { release, ready } = acquireTabLock((status) => {
				tabLockStatus = status;
				if (status === 'granted' && !mountedOnOAuthCallback) {
					void bootstrapTabSession();
				}
			});
			releaseTabLock = release;

			const initialStatus = await ready;
			if (initialStatus === 'granted' && !mountedOnOAuthCallback) {
				await bootstrapTabSession();
			}
		} else {
			tabLockStatus = 'granted';
			if (!mountedOnOAuthCallback) {
				await bootstrapTabSession();
			}
		}
	});

	onDestroy(() => {
		if (typeof window !== 'undefined') {
			window.removeEventListener('keydown', handleGlobalKeydown);
		}
		if (typeof document !== 'undefined') {
			document.removeEventListener('visibilitychange', handleVisibilityChange);
		}
		releaseTabLock?.();
		releaseTabLock = undefined;
	});
</script>

<a href="#main-thread" class="skip-link">Skip to content</a>
<LiveAnnouncer />
<ToastHost />

{#if initError}
	<main id="main-thread" class="status-shell">
		<section class="status-card" aria-labelledby="init-error-heading">
			<span class="status-icon squircle" aria-hidden="true">
				<Icon name="shield-alert" size={26} />
			</span>
			<h1 id="init-error-heading" class="status-heading">Storage initialization failed</h1>
			<p class="status-message">{initError}</p>

			{#if resetError}
				<p class="reset-error" role="alert">{resetError}</p>
			{/if}

			<button
				type="button"
				class="catmos-btn-danger reset-btn"
				disabled={resettingStorage}
				onclick={handleResetStorage}
			>
				{#if resettingStorage}
					<progress class="catmos-progress btn-progress" aria-label="Resetting local storage"></progress>
					<span>Resetting local storage...</span>
				{:else}
					<span>Reset local storage and reload</span>
				{/if}
			</button>
		</section>
	</main>
{:else if tabLockStatus === 'blocked'}
	<TabBlockedMessage />
{:else if tabLockStatus === 'acquiring'}
	<main id="main-thread" class="status-shell" role="status" aria-live="polite">
		<div class="acquiring-state">
			<progress class="catmos-progress acquiring-progress" aria-label="Preparing secure storage"></progress>
			<p class="acquiring-label">Preparing secure storage...</p>
		</div>
	</main>
{:else if isSettingsRoute}
	<main id="main-thread" class="subroute-shell">
		{@render children()}
	</main>
{:else}
	{@render children()}
{/if}

<style>
	.subroute-shell {
		block-size: 100dvh;
		inline-size: 100%;
		overflow-y: auto;
		background: var(--bg-app);
	}

	.status-shell {
		min-block-size: 100dvh;
		inline-size: 100%;
		display: flex;
		align-items: center;
		justify-content: center;
		padding: var(--space-6) var(--space-4);
		background: var(--bg-app);
	}

	.status-card {
		inline-size: 100%;
		max-inline-size: 27rem;
		display: flex;
		flex-direction: column;
		align-items: center;
		text-align: center;
		gap: var(--space-3);
		padding: var(--space-8) var(--space-6);
		background: var(--bg-surface);
		border: 1px solid var(--border);
		border-radius: var(--radius-lg);
		box-shadow: var(--shadow-md);
	}

	.status-icon {
		inline-size: 3.5rem;
		block-size: 3.5rem;
		display: inline-flex;
		align-items: center;
		justify-content: center;
		background: var(--danger-bg);
		color: var(--danger-text);
		margin-block-end: var(--space-1);
	}

	.status-heading {
		font-size: var(--text-heading);
		font-weight: 650;
		letter-spacing: -0.015em;
		line-height: 1.3;
		color: var(--text-primary);
		text-wrap: balance;
	}

	.status-message {
		font-size: var(--text-sm);
		line-height: 1.5;
		color: var(--text-secondary);
		word-break: break-word;
		max-inline-size: 42ch;
	}

	.reset-error {
		font-size: var(--text-sm);
		color: var(--danger-text);
		line-height: 1.45;
		word-break: break-word;
	}

	.reset-btn {
		margin-block-start: var(--space-2);
		inline-size: 100%;
		min-block-size: 2.75rem;
	}

	.btn-progress {
		inline-size: 1rem;
		block-size: 1rem;
		border-color: rgba(255, 255, 255, 0.35);
		border-top-color: #ffffff;
	}

	.acquiring-state {
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: var(--space-3);
	}

	.acquiring-progress {
		inline-size: 1.75rem;
		block-size: 1.75rem;
	}

	.acquiring-label {
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}
</style>

<script lang="ts">
	import '../app.css';
	import { onMount, onDestroy } from 'svelte';
	import Sidebar from '#lib/components/Sidebar.svelte';
	import TabBlockedMessage from '#lib/components/TabBlockedMessage.svelte';
	import { auth } from '#lib/stores/auth.ts';
	import { selectedConversation } from '#lib/stores/conversations.ts';
	import { isTauri, initWasm, readBrowserAuth } from '#lib/wasm.ts';
	import { isMlsOptedInForDid } from '#lib/labyrinth-ui.ts';
	import { acquireTabLock, type TabLockStatus } from '#lib/stores/tab-lock.ts';

	let { children } = $props();
	let sidebarCollapsed = $state(false);
	let theme = $state<'light' | 'dark'>('dark');
	let tabLockStatus = $state<TabLockStatus>('acquiring');
	let releaseTabLock: (() => void) | undefined = $state(undefined);
	let requestNewConversation = $state(false);

	function toggleTheme() {
		theme = theme === 'dark' ? 'light' : 'dark';
		document.documentElement.setAttribute('data-theme', theme);
		localStorage.setItem('catmos-theme', theme);
	}

	function toggleSidebar() {
		sidebarCollapsed = !sidebarCollapsed;
	}

	// MARK: - Keyboard shortcuts
	const isMac = typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.userAgent);
	let cleanupKeydown: (() => void) | null = null;

	function handleGlobalKeydown(e: KeyboardEvent) {
		const mod = isMac ? e.metaKey : e.ctrlKey;

		// Escape — close any open panel/dialog
		if (e.key === 'Escape') {
			return;
		}

		if (!mod) return;

		switch (e.key) {
			case 'n':
				// Cmd/Ctrl+N — new conversation
				e.preventDefault();
				requestNewConversation = true;
				if (sidebarCollapsed) sidebarCollapsed = false;
				break;
			case ',':
				// Cmd/Ctrl+, — toggle sidebar
				e.preventDefault();
				toggleSidebar();
				break;
		}
	}

	let tabSessionBootstrapped = false;

	async function bootstrapTabSession() {
		if (tabSessionBootstrapped) return;
		tabSessionBootstrapped = true;

		if (!isTauri) {
			const savedAuth = readBrowserAuth();
			// ctl #2: never open OPFS SQLite or trigger MLS/Spaces calls unless explicitly opted in
			if (savedAuth?.did && isMlsOptedInForDid(savedAuth.did)) {
				await initWasm(savedAuth.did);
			}
		}

		await auth.tryRestore();
	}

	onMount(async () => {
		const saved = localStorage.getItem('catmos-theme') as 'light' | 'dark' | null;
		if (saved) {
			theme = saved;
			document.documentElement.setAttribute('data-theme', saved);
		} else {
			const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
			theme = prefersDark ? 'dark' : 'light';
			document.documentElement.setAttribute('data-theme', theme);
		}

		window.addEventListener('keydown', handleGlobalKeydown);
		cleanupKeydown = () => window.removeEventListener('keydown', handleGlobalKeydown);

		// Gate 9: await exclusive navigator.locks mutex without lock stealing.
		if (!isTauri) {
			const { release, ready } = acquireTabLock((status) => {
				tabLockStatus = status;
				if (status === 'granted') {
					void bootstrapTabSession();
				}
			});
			releaseTabLock = release;

			const initialStatus = await ready;
			if (initialStatus === 'granted') {
				await bootstrapTabSession();
			}
		} else {
			tabLockStatus = 'granted';
			await bootstrapTabSession();
		}
	});

	onDestroy(() => {
		cleanupKeydown?.();
		releaseTabLock?.();
	});
</script>

{#if tabLockStatus === 'blocked'}
	<TabBlockedMessage />
{:else}
<div
	class="app-shell"
	class:sidebar-collapsed={sidebarCollapsed}
	class:mobile-chat-view={$auth.user && $selectedConversation !== null}
>
	{#if $auth.user}
		<Sidebar
			collapsed={sidebarCollapsed}
			{theme}
			{requestNewConversation}
			onToggleCollapse={toggleSidebar}
			onToggleTheme={toggleTheme}
			onNewConversationHandled={() => (requestNewConversation = false)}
		/>
		<main class="main-content">
			{#if !sidebarCollapsed && $selectedConversation}
				<button
					class="sidebar-expand-btn"
					onclick={toggleSidebar}
					title="Show sidebar"
					aria-label="Show sidebar"
				>
					<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
						<rect x="3" y="3" width="18" height="18" rx="2" ry="2" />
						<line x1="9" y1="3" x2="9" y2="21" />
					</svg>
				</button>
			{/if}
			{@render children()}
		</main>
	{:else}
		<div class="login-container">
			{@render children()}
		</div>
	{/if}
</div>
{/if}

<style>
	.app-shell {
		display: flex;
		height: 100dvh;
		width: 100vw;
		overflow: hidden;
		background: var(--bg-app);
	}

	.main-content {
		flex: 1;
		display: flex;
		min-width: 0;
		position: relative;
	}

	.sidebar-expand-btn {
		display: none;
		position: absolute;
		top: 14px;
		left: 16px;
		z-index: 10;
		width: 32px;
		height: 32px;
		align-items: center;
		justify-content: center;
		border-radius: var(--radius-sm);
		color: var(--text-secondary);
		transition: all var(--transition-fast);
	}

	.sidebar-collapsed .sidebar-expand-btn {
		display: inline-flex;
	}

	.sidebar-expand-btn:hover {
		color: var(--text-primary);
		background: var(--bg-hover);
	}

	.login-container {
		flex: 1;
		display: flex;
		align-items: center;
		justify-content: center;
		background: var(--bg-app);
	}

	@media (max-width: 768px) {
		.app-shell.mobile-chat-view :global(.sidebar) {
			display: none;
		}

		.app-shell:not(.mobile-chat-view) .main-content {
			display: none;
		}

		.main-content {
			width: 100%;
		}

		.login-container {
			padding: 16px;
		}

		.sidebar-expand-btn {
			display: none !important;
		}
	}
</style>

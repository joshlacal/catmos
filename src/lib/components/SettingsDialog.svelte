<script lang="ts">
	import { onDestroy } from 'svelte';
	import { isTauri } from '#lib/wasm.ts';
	import { stripDidFragment } from '#lib/did.ts';
	import { auth } from '#lib/stores/auth.ts';
	import { shortDid } from '#lib/stores/profiles.ts';
	import {
		preferences,
		systemPrefersDark,
		ACCENT_PALETTES,
		setScheme,
		setAccent,
		setContrast,
		setDensity,
		setNotificationsEnabled,
		setNotificationPreviews,
		getSystemSchemeLabel,
		resolveEffectiveScheme,
		type ThemeScheme,
		type DensityMode
	} from '#lib/stores/preferences.ts';
	import { requestNotificationPermission } from '#lib/notifications.ts';
	import {
		useDialogLightDismiss,
		closeWithReset,
		useDialogSafeAutofocus
	} from '#lib/utils/dialog.ts';
	import { showToast } from '#lib/utils/announcer.ts';
	import Avatar from './Avatar.svelte';
	import Icon, { type IconName } from './Icon.svelte';

	type SettingsTab = 'appearance' | 'notifications' | 'account' | 'shortcuts';

	let {
		open = false,
		initialTab = 'appearance',
		onClose,
		onRequestSignOut,
		onResetLocalStorage
	}: {
		open: boolean;
		initialTab?: SettingsTab;
		onClose: () => void;
		onRequestSignOut: () => void;
		onResetLocalStorage?: () => Promise<void>;
	} = $props();

	let dialogEl: HTMLDialogElement | null = $state(null);
	let resetConfirmDialogEl: HTMLDialogElement | null = $state(null);

	let activeTab = $state<SettingsTab>('appearance');
	let notificationPermission = $state<NotificationPermission | 'unsupported'>('default');
	let requestingPermission = $state(false);
	let copiedDid = $state(false);
	let copiedTimer: ReturnType<typeof setTimeout> | null = null;

	let showResetConfirm = $state(false);
	let resetting = $state(false);
	let resetError = $state('');

	const isMac =
		typeof navigator !== 'undefined' && /Mac|iPhone|iPad|iPod/i.test(navigator.platform ?? '');
	const shortcutMod = isMac ? '⌘' : 'Ctrl+';

	const tabs: ReadonlyArray<{ id: SettingsTab; label: string; icon: IconName }> = [
		{ id: 'appearance', label: 'Appearance', icon: 'contrast' },
		{ id: 'notifications', label: 'Notifications', icon: 'bell' },
		{ id: 'account', label: 'Account & security', icon: 'shield' },
		{ id: 'shortcuts', label: 'Shortcuts', icon: 'keyboard' }
	];

	function readNotificationPermission(): NotificationPermission | 'unsupported' {
		if (isTauri || typeof window === 'undefined' || !('Notification' in window)) {
			return 'unsupported';
		}
		return Notification.permission;
	}

	$effect(() => {
		if (!dialogEl) return;
		if (open) {
			activeTab = initialTab;
			notificationPermission = readNotificationPermission();
			if (!dialogEl.open) {
				resetError = '';
				showResetConfirm = false;
				dialogEl.showModal();
			}
		} else {
			showResetConfirm = false;
			if (resetConfirmDialogEl?.open) {
				closeWithReset(resetConfirmDialogEl);
			}
			if (dialogEl.open) {
				closeWithReset(dialogEl);
			}
		}
	});

	$effect(() => {
		if (!resetConfirmDialogEl) return;
		if (showResetConfirm && !resetConfirmDialogEl.open) {
			resetConfirmDialogEl.showModal();
		} else if (!showResetConfirm && resetConfirmDialogEl.open) {
			closeWithReset(resetConfirmDialogEl);
		}
	});

	const systemLabel = $derived.by(() => {
		void $systemPrefersDark;
		return getSystemSchemeLabel();
	});

	const effectiveScheme = $derived.by(() => {
		void $systemPrefersDark;
		return resolveEffectiveScheme($preferences.scheme);
	});

	const isLightEffective = $derived(effectiveScheme === 'light');

	function swatchCheckColor(hex: string): string {
		const clean = hex.replace('#', '');
		const r = parseInt(clean.slice(0, 2), 16) / 255;
		const g = parseInt(clean.slice(2, 4), 16) / 255;
		const b = parseInt(clean.slice(4, 6), 16) / 255;
		const toLinear = (c: number) => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4);
		const luminance = 0.2126 * toLinear(r) + 0.7152 * toLinear(g) + 0.0722 * toLinear(b);
		// Contrast against white vs #111318
		return luminance > 0.34 ? '#111318' : '#ffffff';
	}

	onDestroy(() => {
		if (copiedTimer) {
			clearTimeout(copiedTimer);
			copiedTimer = null;
		}
	});

	const schemeOptions: ReadonlyArray<{ value: ThemeScheme; label: string }> = [
		{ value: 'system', label: 'System' },
		{ value: 'light', label: 'Light' },
		{ value: 'dim', label: 'Dim' },
		{ value: 'black', label: 'True black' }
	];

	const densityOptions: ReadonlyArray<{ value: DensityMode; label: string }> = [
		{ value: 'comfortable', label: 'Comfortable' },
		{ value: 'compact', label: 'Compact' }
	];

	const shortcutsList = $derived([
		{ keys: `${shortcutMod}K`, label: 'Open quick switcher and search' },
		{ keys: `${shortcutMod}N`, label: 'Start a new conversation' },
		{ keys: `${shortcutMod}B`, label: 'Show or hide the sidebar' },
		{ keys: `${shortcutMod},`, label: 'Open settings' },
		{ keys: `${shortcutMod}I`, label: 'Toggle conversation details' },
		{
			keys: isMac ? '⌥↑ / ⌥↓' : 'Alt+Up / Alt+Down',
			label: 'Move to previous or next conversation'
		},
		{ keys: 'Esc', label: 'Close the current dialog or menu' }
	]);

	const accountDid = $derived(stripDidFragment($auth.user?.did));
	const userDisplayName = $derived(
		$auth.user?.displayName?.trim() || $auth.user?.handle || shortDid(accountDid)
	);
	const userHandle = $derived(
		$auth.user?.handle && !$auth.user.handle.startsWith('did:')
			? `@${$auth.user.handle}`
			: shortDid(accountDid)
	);

	function handleDialogClose() {
		if (dialogEl) {
			dialogEl.returnValue = '';
		}
		showResetConfirm = false;
		if (open) {
			onClose();
		}
	}

	function handleResetConfirmClose() {
		if (resetConfirmDialogEl) {
			resetConfirmDialogEl.returnValue = '';
		}
		if (!resetting) {
			showResetConfirm = false;
			resetError = '';
		}
	}

	function handleTablistKeydown(event: KeyboardEvent) {
		const idx = tabs.findIndex((t) => t.id === activeTab);
		if (idx < 0) return;

		let nextIdx = -1;
		if (event.key === 'ArrowDown' || event.key === 'ArrowRight') {
			nextIdx = (idx + 1) % tabs.length;
		} else if (event.key === 'ArrowUp' || event.key === 'ArrowLeft') {
			nextIdx = (idx - 1 + tabs.length) % tabs.length;
		} else if (event.key === 'Home') {
			nextIdx = 0;
		} else if (event.key === 'End') {
			nextIdx = tabs.length - 1;
		}

		if (nextIdx >= 0) {
			event.preventDefault();
			const targetTab = tabs[nextIdx];
			activeTab = targetTab.id;
			const tabEl = dialogEl?.querySelector<HTMLButtonElement>(`#settings-tab-${targetTab.id}`);
			tabEl?.focus();
		}
	}

	async function handleEnableNotifications() {
		if (requestingPermission) return;
		requestingPermission = true;
		try {
			const status = await requestNotificationPermission();
			notificationPermission = status;
			if (status === 'granted') {
				setNotificationsEnabled(true);
				showToast({ message: 'Browser notifications enabled', tone: 'success' });
			} else if (status === 'denied') {
				showToast({
					message: 'Notifications are blocked in your browser site settings',
					tone: 'warning'
				});
			}
		} finally {
			requestingPermission = false;
		}
	}

	async function handleCopyDid() {
		const did = accountDid;
		if (!did) return;
		try {
			await navigator.clipboard.writeText(did);
			copiedDid = true;
			if (copiedTimer) clearTimeout(copiedTimer);
			copiedTimer = setTimeout(() => {
				copiedDid = false;
			}, 2000);
			showToast({ message: 'Copied DID to clipboard', tone: 'info' });
		} catch {
			showToast({ message: 'Could not copy DID to clipboard', tone: 'error' });
		}
	}

	async function handleConfirmResetStorage() {
		if (resetting) return;
		resetting = true;
		resetError = '';
		try {
			if (onResetLocalStorage) {
				await onResetLocalStorage();
			} else {
				await auth.deleteAccountData(accountDid || undefined);
			}
			resetting = false;
			showResetConfirm = false;
			closeWithReset(resetConfirmDialogEl, 'deleted');
			closeWithReset(dialogEl, 'deleted');
			showToast({ message: 'Encrypted account data deleted', tone: 'info' });
		} catch (err) {
			resetting = false;
			resetError =
				err instanceof Error ? err.message : 'Could not delete encrypted account data.';
		}
	}
</script>

<dialog
	bind:this={dialogEl}
	class="catmos-dialog settings-dialog"
	closedby="any"
	use:useDialogLightDismiss
	onclose={handleDialogClose}
>
	<header class="dialog-header">
		<h1>Settings</h1>
		<button
			type="button"
			class="dialog-close-btn"
			onclick={() => closeWithReset(dialogEl, 'cancel')}
			aria-label="Close settings"
		>
			<Icon name="x" size={18} />
		</button>
	</header>

	<div class="settings-layout">
		<div class="settings-tabs" role="tablist" aria-label="Settings sections">
			{#each tabs as tab (tab.id)}
				{@const isSelected = activeTab === tab.id}
				<button
					id={`settings-tab-${tab.id}`}
					type="button"
					role="tab"
					class="settings-tab"
					aria-selected={isSelected}
					aria-controls={`settings-panel-${tab.id}`}
					tabindex={isSelected ? 0 : -1}
					onkeydown={handleTablistKeydown}
					onclick={() => {
						activeTab = tab.id;
					}}
				>
					<Icon name={tab.icon} size={16} />
					<span>{tab.label}</span>
				</button>
			{/each}
		</div>

		<div
			id={`settings-panel-${activeTab}`}
			class="settings-panel"
			role="tabpanel"
			aria-labelledby={`settings-tab-${activeTab}`}
		>
			{#if activeTab === 'appearance'}
				<div class="panel-stack">
					<fieldset class="setting-fieldset">
						<legend class="setting-legend">Theme</legend>
						<div class="catmos-segmented theme-segmented">
							{#each schemeOptions as option (option.value)}
								<label>
									<input
										type="radio"
										name="settings-theme"
										value={option.value}
										checked={$preferences.scheme === option.value}
										onchange={() => setScheme(option.value)}
									/>
									<span>{option.label}</span>
								</label>
							{/each}
						</div>
						<p class="setting-caption">{systemLabel}</p>
					</fieldset>

					<fieldset class="setting-fieldset">
						<legend class="setting-legend">Accent color</legend>
						<div class="accent-grid">
							{#each ACCENT_PALETTES as palette (palette.id)}
								{@const selected = $preferences.accent === palette.id}
								{@const swatchHex = isLightEffective ? palette.swatchLight : palette.swatchDark}
								<label class="accent-option" class:is-selected={selected}>
									<input
										type="radio"
										name="settings-accent"
										value={palette.id}
										checked={selected}
										onchange={() => setAccent(palette.id)}
									/>
									<span
										class="accent-swatch"
										style={`background-color: ${swatchHex}; color: ${swatchCheckColor(swatchHex)};`}
										aria-hidden="true"
									>
										{#if selected}
											<Icon name="check" size={14} class="swatch-check" />
										{/if}
									</span>
									<span class="accent-label">{palette.label}</span>
								</label>
							{/each}
						</div>
					</fieldset>

					<div class="setting-row">
						<label for="settings-contrast-switch" class="setting-row-text">
							<span class="setting-title">Increase contrast</span>
							<span class="setting-desc">
								Use stronger borders and opaque panels instead of translucent blur.
							</span>
						</label>
						<input
							id="settings-contrast-switch"
							type="checkbox"
							role="switch"
							class="catmos-switch"
							checked={$preferences.contrast === 'more'}
							onchange={(e) => setContrast(e.currentTarget.checked ? 'more' : 'system')}
						/>
					</div>

					<fieldset class="setting-fieldset">
						<legend class="setting-legend">Message density</legend>
						<div class="catmos-segmented density-segmented">
							{#each densityOptions as option (option.value)}
								<label>
									<input
										type="radio"
										name="settings-density"
										value={option.value}
										checked={$preferences.density === option.value}
										onchange={() => setDensity(option.value)}
									/>
									<span>{option.label}</span>
								</label>
							{/each}
						</div>
					</fieldset>
				</div>
			{:else if activeTab === 'notifications'}
				<div class="panel-stack">
					<div class="status-surface">
						<div class="status-surface-text">
							<span class="setting-title">Notification permission</span>
							<span class="setting-desc">
								{#if isTauri}
									Desktop notifications are managed by your operating system settings.
								{:else if notificationPermission === 'granted'}
									Browser notifications are allowed for Catmos.
								{:else if notificationPermission === 'denied'}
									Browser notifications are blocked in your browser site settings.
								{:else if notificationPermission === 'unsupported'}
									This browser does not support desktop notifications.
								{:else}
									Enable browser notifications to get alerts when Catmos is in the background.
								{/if}
							</span>
						</div>
						{#if !isTauri && notificationPermission === 'default'}
							<button
								type="button"
								class="catmos-btn-secondary"
								disabled={requestingPermission}
								onclick={handleEnableNotifications}
							>
								Enable browser notifications
							</button>
						{/if}
					</div>

					<div class="setting-row">
						<label for="settings-notif-enabled" class="setting-row-text">
							<span class="setting-title">Enable notifications</span>
							<span class="setting-desc">
								Alert you when new messages arrive in unmuted conversations.
							</span>
						</label>
						<input
							id="settings-notif-enabled"
							type="checkbox"
							role="switch"
							class="catmos-switch"
							checked={$preferences.notificationsEnabled}
							onchange={(e) => setNotificationsEnabled(e.currentTarget.checked)}
						/>
					</div>

					<div class="setting-row">
						<label for="settings-notif-previews" class="setting-row-text">
							<span class="setting-title">Show message preview text</span>
							<span class="setting-desc">
								Display decrypted message text inside notification alerts. Turn off for private lock
								screens.
							</span>
						</label>
						<input
							id="settings-notif-previews"
							type="checkbox"
							role="switch"
							class="catmos-switch"
							checked={$preferences.notificationPreviews}
							disabled={!$preferences.notificationsEnabled}
							onchange={(e) => setNotificationPreviews(e.currentTarget.checked)}
						/>
					</div>
				</div>
			{:else if activeTab === 'account'}
				<div class="panel-stack">
					<div class="account-summary">
						<Avatar
							src={$auth.user?.avatar ?? null}
							name={userDisplayName}
							id={$auth.user?.did}
							size={48}
							shape="circle"
						/>
						<div class="account-summary-info">
							<span class="account-summary-name">{userDisplayName}</span>
							<span class="account-summary-handle">{userHandle}</span>
						</div>
					</div>

					<dl class="account-meta-list">
						<div class="meta-row">
							<dt>Decentralized identifier (DID)</dt>
							<dd class="did-row">
								<code class="mono did-value">{accountDid || 'Not signed in'}</code>
								{#if accountDid}
									<button
										type="button"
										class="catmos-btn-ghost copy-btn"
										onclick={handleCopyDid}
									>
										<Icon name={copiedDid ? 'check' : 'copy'} size={15} />
										<span>{copiedDid ? 'Copied' : 'Copy'}</span>
									</button>
								{/if}
							</dd>
						</div>

						<div class="meta-row">
							<dt>Runtime mode</dt>
							<dd>{isTauri ? 'Desktop (Tauri)' : 'Web (WASM + OPFS)'}</dd>
						</div>

						<div class="meta-row">
							<dt>Encryption</dt>
							<dd class="encryption-row">
								<span class="shield-wrap" aria-hidden="true">
									<Icon name="shield" size={15} />
								</span>
								<span>End-to-end encrypted with MLS</span>
							</dd>
						</div>
					</dl>

					<div class="labyrinth-section">
						<div class="danger-text-block">
							<span class="setting-title">Labyrinth backup and recovery</span>
							<span class="setting-desc">
								Manage encrypted history backup, linked devices, passkey recovery, and recovery
								codes.
							</span>
						</div>
						<div class="account-actions">
							<a
								href="/settings/labyrinth"
								class="catmos-btn-secondary"
								onclick={() => onClose()}
							>
								<Icon name="shield" size={16} />
								<span>Labyrinth Backup, Devices &amp; Recovery</span>
							</a>
						</div>
					</div>

					<div class="danger-section">
						<div class="danger-text-block">
							<span class="setting-title">Encrypted account data</span>
							<span class="setting-desc">
								Permanently delete your encrypted chat history, Labyrinth backup, and local MLS keys
								on this device, then sign out.
							</span>
						</div>
						<div class="account-actions">
							<button
								type="button"
								class="catmos-btn-danger"
								onclick={() => {
									resetError = '';
									showResetConfirm = true;
								}}
							>
								Delete all encrypted account data
							</button>
							<button
								type="button"
								class="catmos-btn-secondary"
								onclick={onRequestSignOut}
							>
								<Icon name="log-out" size={16} />
								<span>Sign out</span>
							</button>
						</div>
					</div>
				</div>
			{:else if activeTab === 'shortcuts'}
				<div class="panel-stack">
					<dl class="shortcuts-list">
						{#each shortcutsList as item (item.keys)}
							<div class="shortcut-row">
								<dt class="shortcut-desc">{item.label}</dt>
								<dd>
									<kbd class="shortcut-kbd">{item.keys}</kbd>
								</dd>
							</div>
						{/each}
					</dl>
				</div>
			{/if}
		</div>
	</div>
</dialog>

<dialog
	bind:this={resetConfirmDialogEl}
	class="catmos-dialog reset-confirm-dialog"
	closedby="any"
	use:useDialogLightDismiss
	onclose={handleResetConfirmClose}
>
	<div class="confirm-body">
		<h1>Delete all encrypted account data?</h1>
		<p class="confirm-copy">
			This permanently removes your encrypted Labyrinth backup, server mailbox keys, and local MLS
			database on this device, and signs you out. Your Bluesky account stays intact.
		</p>
		{#if resetError}
			<p class="confirm-error" role="alert">{resetError}</p>
		{/if}
		<div class="confirm-actions">
			<button
				type="button"
				class="catmos-btn-secondary"
				use:useDialogSafeAutofocus
				disabled={resetting}
				onclick={() => {
					showResetConfirm = false;
					closeWithReset(resetConfirmDialogEl, 'cancel');
				}}
			>
				Cancel
			</button>
			<button
				type="button"
				class="catmos-btn-danger"
				disabled={resetting}
				onclick={handleConfirmResetStorage}
			>
				{#if resetting}
					<progress class="catmos-progress btn-progress" aria-label="Deleting account data"></progress>
					<span>Deleting...</span>
				{:else}
					<span>Delete all encrypted account data</span>
				{/if}
			</button>
		</div>
	</div>
</dialog>

<style>
	.settings-dialog {
		inline-size: min(44rem, calc(100vw - 2rem));
		max-block-size: min(84svh, 42rem);
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

	.dialog-close-btn:hover {
		background: var(--bg-hover);
		color: var(--text-primary);
	}

	.settings-layout {
		display: grid;
		grid-template-columns: 12.75rem minmax(0, 1fr);
		min-block-size: 0;
		flex: 1;
		overflow: hidden;
	}

	.settings-tabs {
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
		padding: var(--space-3);
		border-inline-end: 1px solid var(--border);
		overflow-y: auto;
	}

	.settings-tab {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		width: 100%;
		min-block-size: max(2.375rem, var(--touch-min));
		padding-inline: var(--space-3);
		padding-block: var(--space-2);
		border-radius: var(--radius-sm);
		font-size: var(--text-sm);
		font-weight: 500;
		color: var(--text-secondary);
		text-align: start;
		transition:
			background-color var(--dur-fast) var(--ease-out),
			color var(--dur-fast) var(--ease-out);
	}

	.settings-tab:hover {
		background: var(--bg-hover);
		color: var(--text-primary);
	}

	.settings-tab[aria-selected='true'] {
		background: var(--bg-selected);
		color: var(--text-primary);
		font-weight: 600;
	}

	.settings-panel {
		padding: var(--space-5);
		overflow-y: auto;
		min-block-size: 0;
	}

	.panel-stack {
		display: flex;
		flex-direction: column;
		gap: var(--space-5);
	}

	.setting-fieldset {
		border: none;
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
	}

	.setting-legend {
		font-size: var(--text-sm);
		font-weight: 600;
		color: var(--text-primary);
		margin-block-end: var(--space-1);
	}

	.theme-segmented {
		width: 100%;
		grid-auto-flow: column;
		grid-auto-columns: 1fr;
	}

	.theme-segmented label {
		white-space: nowrap;
		padding-inline: var(--space-2);
	}

	.setting-caption {
		font-size: var(--text-sm);
		color: var(--text-muted);
		line-height: 1.35;
	}

	.density-segmented {
		width: 100%;
		max-inline-size: 20rem;
	}

	.accent-grid {
		display: grid;
		grid-template-columns: repeat(auto-fill, minmax(7.25rem, 1fr));
		gap: var(--space-2);
	}

	.accent-option {
		position: relative;
		display: flex;
		align-items: center;
		gap: var(--space-2);
		min-block-size: max(2.625rem, var(--touch-min));
		padding: var(--space-2) var(--space-3);
		border-radius: var(--radius-sm);
		border: 1px solid var(--border);
		background: var(--bg-surface);
		cursor: pointer;
		transition:
			background-color var(--dur-fast) var(--ease-out),
			border-color var(--dur-fast) var(--ease-out);
	}

	.accent-option:hover {
		background: var(--bg-hover);
	}

	.accent-option.is-selected {
		border-color: var(--focus-ring);
		background: var(--bg-selected);
	}

	.accent-option input[type='radio'] {
		position: absolute;
		opacity: 0;
		inset: 0;
		cursor: pointer;
		margin: 0;
	}

	.accent-option:has(input[type='radio']:focus-visible) {
		outline: 2px solid var(--focus-ring);
		outline-offset: 2px;
	}

	.accent-swatch {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		inline-size: 1.375rem;
		block-size: 1.375rem;
		border-radius: var(--radius-full);
		flex-shrink: 0;
		border: 1px solid rgba(0, 0, 0, 0.16);
		color: #ffffff;
	}

	.accent-label {
		font-size: var(--text-sm);
		font-weight: 500;
		color: var(--text-primary);
	}

	.accent-option.is-selected .accent-label {
		font-weight: 600;
	}

	.setting-row {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: var(--space-4);
		padding-block: var(--space-2);
		border-block-start: 1px solid var(--border);
	}

	.setting-row-text {
		display: flex;
		flex-direction: column;
		gap: 2px;
		cursor: pointer;
		max-inline-size: 48ch;
	}

	.setting-title {
		font-size: var(--text-body);
		font-weight: 600;
		color: var(--text-primary);
	}

	.setting-desc {
		font-size: var(--text-sm);
		color: var(--text-secondary);
		line-height: 1.4;
	}

	.status-surface {
		display: flex;
		flex-direction: column;
		align-items: flex-start;
		gap: var(--space-3);
		padding: var(--space-4);
		border-radius: var(--radius-md);
		background: var(--bg-surface);
		border: 1px solid var(--border);
	}

	.status-surface-text {
		display: flex;
		flex-direction: column;
		gap: 4px;
	}

	.account-summary {
		display: flex;
		align-items: center;
		gap: var(--space-3);
		padding: var(--space-4);
		border-radius: var(--radius-md);
		background: var(--bg-surface);
		border: 1px solid var(--border);
	}

	.account-summary-info {
		display: flex;
		flex-direction: column;
		min-inline-size: 0;
	}

	.account-summary-name {
		font-size: var(--text-body);
		font-weight: 600;
		color: var(--text-primary);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.account-summary-handle {
		font-size: var(--text-sm);
		color: var(--text-secondary);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.account-meta-list {
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
	}

	.meta-row {
		display: flex;
		flex-direction: column;
		gap: 4px;
		padding-block-end: var(--space-3);
		border-block-end: 1px solid var(--border);
	}

	.meta-row dt {
		font-size: var(--text-sm);
		font-weight: 600;
		color: var(--text-secondary);
	}

	.meta-row dd {
		font-size: var(--text-body);
		color: var(--text-primary);
	}

	.did-row {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: var(--space-2);
		flex-wrap: wrap;
	}

	.mono {
		font-family: var(--font-mono);
		font-size: var(--text-sm);
	}

	.did-value {
		word-break: break-all;
		color: var(--text-primary);
		user-select: all;
	}

	.copy-btn {
		min-block-size: max(2rem, var(--touch-min));
		padding-inline: var(--space-2);
		font-size: var(--text-sm);
	}

	.encryption-row {
		display: inline-flex;
		align-items: center;
		gap: var(--space-2);
	}

	.shield-wrap {
		display: inline-flex;
		color: var(--shield);
	}

	.labyrinth-section {
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
		padding-block-end: var(--space-4);
		border-block-end: 1px solid var(--border);
	}

	.danger-section {
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
	}

	.danger-text-block {
		display: flex;
		flex-direction: column;
		gap: 4px;
	}

	.account-actions {
		display: flex;
		flex-wrap: wrap;
		gap: var(--space-2);
	}

	.shortcuts-list {
		display: flex;
		flex-direction: column;
	}

	.shortcut-row {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: var(--space-4);
		padding-block: var(--space-3);
		border-block-end: 1px solid var(--border);
	}

	.shortcut-row:last-child {
		border-block-end: none;
	}

	.shortcut-desc {
		font-size: var(--text-body);
		color: var(--text-primary);
	}

	.shortcut-kbd {
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		font-weight: 600;
		color: var(--text-primary);
		background: var(--bg-surface);
		border: 1px solid var(--border-strong);
		border-radius: var(--radius-xs);
		padding: 3px 9px;
		white-space: nowrap;
	}

	.reset-confirm-dialog {
		inline-size: min(27rem, calc(100vw - 2rem));
	}

	.confirm-body {
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
		padding: var(--space-6);
	}

	.confirm-body h1 {
		font-size: var(--text-heading);
		font-weight: 650;
		letter-spacing: -0.015em;
		line-height: 1.3;
		color: var(--text-primary);
	}

	.confirm-copy {
		font-size: var(--text-body);
		color: var(--text-secondary);
		max-inline-size: 52ch;
	}

	.confirm-error {
		font-size: var(--text-sm);
		color: var(--danger-text);
	}

	.confirm-actions {
		display: flex;
		justify-content: flex-end;
		flex-wrap: wrap;
		gap: var(--space-2);
		margin-block-start: var(--space-2);
	}

	.btn-progress {
		inline-size: 1rem;
		block-size: 1rem;
		border-width: 2px;
		border-color: rgba(255, 255, 255, 0.35);
		border-top-color: #ffffff;
	}

	@media (max-width: 679px) {
		.settings-layout {
			grid-template-columns: 1fr;
			grid-template-rows: auto minmax(0, 1fr);
		}

		.settings-tabs {
			flex-direction: row;
			overflow-x: auto;
			overflow-y: hidden;
			border-inline-end: none;
			border-block-end: 1px solid var(--border);
			padding: var(--space-2) var(--space-3);
		}

		.settings-tab {
			width: auto;
			white-space: nowrap;
			flex-shrink: 0;
		}

		.settings-panel {
			padding: var(--space-4);
		}
	}
</style>

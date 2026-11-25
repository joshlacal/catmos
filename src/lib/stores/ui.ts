import { writable, type Writable } from 'svelte/store';

export type SettingsTab = 'appearance' | 'notifications' | 'account' | 'shortcuts';

export interface UiState {
	sidebarCollapsed: boolean;
	showInspector: boolean;
	showNewConversation: boolean;
	showCommandPalette: boolean;
	showSettings: boolean;
	settingsTab: SettingsTab;
	highlightMessageId: string | null;
}

function createInitialUiState(): UiState {
	return {
		sidebarCollapsed: false,
		showInspector: false,
		showNewConversation: false,
		showCommandPalette: false,
		showSettings: false,
		settingsTab: 'appearance',
		highlightMessageId: null
	};
}

const _ui = writable<UiState>(createInitialUiState());

export function toggleSidebar(): void {
	_ui.update((s) => ({ ...s, sidebarCollapsed: !s.sidebarCollapsed }));
}

export function setSidebarCollapsed(v: boolean): void {
	_ui.update((s) => ({ ...s, sidebarCollapsed: Boolean(v) }));
}

export function toggleInspector(): void {
	_ui.update((s) => ({ ...s, showInspector: !s.showInspector }));
}

export function setShowInspector(v: boolean): void {
	_ui.update((s) => ({ ...s, showInspector: Boolean(v) }));
}

export function openNewConversation(): void {
	_ui.update((s) => ({
		...s,
		showNewConversation: true,
		showCommandPalette: false,
		showSettings: false
	}));
}

export function closeNewConversation(): void {
	_ui.update((s) => ({ ...s, showNewConversation: false }));
}

export function openCommandPalette(): void {
	_ui.update((s) => ({
		...s,
		showCommandPalette: true,
		showNewConversation: false,
		showSettings: false
	}));
}

export function closeCommandPalette(): void {
	_ui.update((s) => ({ ...s, showCommandPalette: false }));
}

export function openSettings(tab?: SettingsTab): void {
	_ui.update((s) => ({
		...s,
		showSettings: true,
		showNewConversation: false,
		showCommandPalette: false,
		settingsTab: tab ?? s.settingsTab
	}));
}

export function closeSettings(): void {
	_ui.update((s) => ({ ...s, showSettings: false }));
}

export function setHighlightMessageId(id: string | null): void {
	_ui.update((s) => ({ ...s, highlightMessageId: id }));
}

export function resetUi(): void {
	_ui.set(createInitialUiState());
}

export interface UiStore extends Writable<UiState> {
	toggleSidebar: typeof toggleSidebar;
	setSidebarCollapsed: typeof setSidebarCollapsed;
	toggleInspector: typeof toggleInspector;
	setShowInspector: typeof setShowInspector;
	openNewConversation: typeof openNewConversation;
	closeNewConversation: typeof closeNewConversation;
	openCommandPalette: typeof openCommandPalette;
	closeCommandPalette: typeof closeCommandPalette;
	openSettings: typeof openSettings;
	closeSettings: typeof closeSettings;
	setHighlightMessageId: typeof setHighlightMessageId;
	resetUi: typeof resetUi;
}

export const ui: UiStore = {
	subscribe: _ui.subscribe,
	set: _ui.set,
	update: _ui.update,
	toggleSidebar,
	setSidebarCollapsed,
	toggleInspector,
	setShowInspector,
	openNewConversation,
	closeNewConversation,
	openCommandPalette,
	closeCommandPalette,
	openSettings,
	closeSettings,
	setHighlightMessageId,
	resetUi
};

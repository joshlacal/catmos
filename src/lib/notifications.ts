/**
 * Browser notification support for Catmos.
 * Only active in browser mode (not Tauri).
 */
import { isSameAccountDid } from '#lib/did.ts';
import { extractMessagePreview } from '#lib/stores/conversations.ts';
import { getNotificationPrefs, isMuted } from '#lib/stores/preferences.ts';

function isTauri(): boolean {
	return typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;
}

let permissionRequested = false;
let selectConversationHandler: ((convoId: string) => void) | null = null;

export function setNotificationSelectHandler(fn: ((convoId: string) => void) | null): void {
	selectConversationHandler = fn;
}

export async function requestNotificationPermission(): Promise<NotificationPermission | 'unsupported'> {
	if (isTauri() || typeof window === 'undefined' || !('Notification' in window)) {
		return 'unsupported';
	}
	if (Notification.permission === 'granted' || Notification.permission === 'denied') {
		return Notification.permission;
	}
	permissionRequested = true;
	return Notification.requestPermission();
}

async function ensurePermission(): Promise<boolean> {
	if (isTauri() || typeof window === 'undefined' || !('Notification' in window)) return false;
	if (Notification.permission === 'granted') return true;
	if (Notification.permission === 'denied') return false;
	if (!permissionRequested) {
		permissionRequested = true;
		const result = await Notification.requestPermission();
		return result === 'granted';
	}
	return false;
}

export interface NotifyOptions {
	senderDid?: string;
	currentUserDid?: string;
	onSelectConversation?: (convoId: string) => void;
}

export async function notifyIncomingMessage(
	sender: string,
	preview: string,
	convoId: string,
	options?: NotifyOptions
): Promise<void> {
	if (isTauri() || typeof document === 'undefined') return;
	if (!document.hidden) return;
	if (options?.senderDid && options?.currentUserDid && isSameAccountDid(options.senderDid, options.currentUserDid)) {
		return;
	}
	if (isMuted(convoId)) return;

	const prefs = getNotificationPrefs();
	if (!prefs.enabled) return;

	const allowed = await ensurePermission();
	if (!allowed) return;

	const cleanPreview = extractMessagePreview(preview);
	const body = prefs.showPreview
		? cleanPreview.length > 100
			? `${cleanPreview.slice(0, 97)}...`
			: cleanPreview || 'New encrypted message'
		: 'New encrypted message';

	const notification = new Notification(sender || 'Catmos', {
		body,
		tag: `catmos-${convoId}`,
		icon: '/favicon.png'
	});

	notification.onclick = () => {
		window.focus();
		(options?.onSelectConversation ?? selectConversationHandler)?.(convoId);
		notification.close();
	};
}

import { writable } from 'svelte/store';

export type AnnouncePriority = 'polite' | 'assertive';
export type ToastTone = 'info' | 'success' | 'warning' | 'error';

export interface LiveMessagesState {
	polite: string;
	assertive: string;
	politeSeq: number;
	assertiveSeq: number;
}

export interface ToastOptions {
	message: string;
	tone?: ToastTone;
	actionLabel?: string;
	onAction?: () => void;
	durationMs?: number;
}

export interface ToastItem {
	id: string;
	message: string;
	tone: ToastTone;
	actionLabel?: string;
	onAction?: () => void;
	durationMs: number;
	createdAt: number;
}

interface AriaNotifyDocument extends Document {
	ariaNotify?: (message: string, options?: { priority?: 'normal' | 'high' }) => void;
}

const MAX_TOASTS = 4;
const timers = new Map<string, ReturnType<typeof setTimeout>>();
let toastCounter = 0;

export const liveMessages = writable<LiveMessagesState>({
	polite: '',
	assertive: '',
	politeSeq: 0,
	assertiveSeq: 0
});

export const toasts = writable<ToastItem[]>([]);

function createToastId(): string {
	if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
		return crypto.randomUUID();
	}
	toastCounter += 1;
	return `toast-${Date.now()}-${toastCounter}`;
}

/**
 * Announce a non-visual status update to assistive technology.
 * Uses `document.ariaNotify()` when supported, falling back to the single
 * pre-mounted polite/assertive live regions rendered by `LiveAnnouncer.svelte`.
 */
export function announce(text: string, priority: AnnouncePriority = 'polite'): void {
	const clean = text.trim();
	if (!clean) return;

	if (typeof document !== 'undefined') {
		const doc = document as AriaNotifyDocument;
		if (typeof doc.ariaNotify === 'function') {
			try {
				doc.ariaNotify(clean, { priority: priority === 'assertive' ? 'high' : 'normal' });
				return;
			} catch {
				// Fall through to live region store
			}
		}
	}

	liveMessages.update((current) => {
		if (priority === 'assertive') {
			return {
				...current,
				assertive: clean,
				assertiveSeq: current.assertiveSeq + 1
			};
		}
		return {
			...current,
			polite: clean,
			politeSeq: current.politeSeq + 1
		};
	});
}

export function dismissToast(id: string): void {
	const timer = timers.get(id);
	if (timer !== undefined) {
		clearTimeout(timer);
		timers.delete(id);
	}
	toasts.update((items) => items.filter((item) => item.id !== id));
}

export function clearToasts(): void {
	for (const timer of timers.values()) {
		clearTimeout(timer);
	}
	timers.clear();
	toasts.set([]);
}

export function showToast(options: ToastOptions): string {
	const message = options.message.trim();
	if (!message) return '';

	const id = createToastId();
	const tone: ToastTone = options.tone ?? 'info';
	const durationMs =
		options.durationMs !== undefined ? options.durationMs : options.actionLabel ? 7000 : 4500;

	const item: ToastItem = {
		id,
		message,
		tone,
		actionLabel: options.actionLabel,
		onAction: options.onAction,
		durationMs,
		createdAt: Date.now()
	};

	toasts.update((current) => {
		const next = [...current, item];
		if (next.length > MAX_TOASTS) {
			const dropped = next.splice(0, next.length - MAX_TOASTS);
			for (const old of dropped) {
				const oldTimer = timers.get(old.id);
				if (oldTimer !== undefined) {
					clearTimeout(oldTimer);
					timers.delete(old.id);
				}
			}
		}
		return next;
	});

	if (durationMs > 0) {
		const timer = setTimeout(() => {
			dismissToast(id);
		}, durationMs);
		timers.set(id, timer);
	}

	announce(message, tone === 'error' ? 'assertive' : 'polite');
	return id;
}

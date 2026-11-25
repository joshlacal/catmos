/**
 * Native Popover positioning fallbacks & roving keyboard navigation helpers.
 */

export type PopoverPlacement = 'top-end' | 'bottom-end' | 'bottom-start';

export interface RovingMenuOptions {
	orientation?: 'vertical' | 'horizontal';
	loop?: boolean;
}

export function supportsAnchorPositioning(): boolean {
	return (
		typeof CSS !== 'undefined' &&
		typeof CSS.supports === 'function' &&
		CSS.supports('position-area', 'block-end')
	);
}

/**
 * Manual viewport-clamped popover positioning for browsers without CSS Anchor Positioning.
 * Strictly gated behind `!CSS.supports('position-area', 'block-end')`.
 */
export function positionPopoverFallback(
	popover: HTMLElement,
	anchor: HTMLElement,
	placement: PopoverPlacement = 'bottom-end',
	gap = 6
): void {
	if (supportsAnchorPositioning()) return;
	if (typeof window === 'undefined') return;

	const margin = 8;
	const anchorRect = anchor.getBoundingClientRect();
	const popRect = popover.getBoundingClientRect();
	const width = popRect.width || popover.offsetWidth || 200;
	const height = popRect.height || popover.offsetHeight || 160;
	const vw = window.innerWidth;
	const vh = window.innerHeight;

	let top: number;
	let left: number;

	if (placement === 'top-end') {
		top = anchorRect.top - height - gap;
		if (top < margin) {
			top = anchorRect.bottom + gap;
		}
		left = anchorRect.right - width;
	} else if (placement === 'bottom-start') {
		top = anchorRect.bottom + gap;
		if (top + height > vh - margin) {
			top = anchorRect.top - height - gap;
		}
		left = anchorRect.left;
	} else {
		// bottom-end
		top = anchorRect.bottom + gap;
		if (top + height > vh - margin) {
			top = anchorRect.top - height - gap;
		}
		left = anchorRect.right - width;
	}

	left = Math.max(margin, Math.min(left, vw - width - margin));
	top = Math.max(margin, Math.min(top, vh - height - margin));

	popover.style.position = 'fixed';
	popover.style.inset = 'auto';
	popover.style.margin = '0';
	popover.style.left = `${Math.round(left)}px`;
	popover.style.top = `${Math.round(top)}px`;
}

/**
 * Position a popover (such as a right-click context menu) at viewport coordinates
 * with automatic edge clamping so it never clips outside the viewport.
 */
export function positionPopoverAtPoint(
	popover: HTMLElement,
	x: number,
	y: number,
	margin = 8
): void {
	if (typeof window === 'undefined') return;

	const popRect = popover.getBoundingClientRect();
	const width = popRect.width || popover.offsetWidth || 200;
	const height = popRect.height || popover.offsetHeight || 160;
	const vw = window.innerWidth;
	const vh = window.innerHeight;

	let left = x;
	let top = y;

	if (left + width > vw - margin) {
		left = Math.max(margin, x - width);
	}
	if (top + height > vh - margin) {
		top = Math.max(margin, y - height);
	}

	left = Math.max(margin, Math.min(left, vw - width - margin));
	top = Math.max(margin, Math.min(top, vh - height - margin));

	popover.style.position = 'fixed';
	popover.style.inset = 'auto';
	popover.style.margin = '0';
	popover.style.left = `${Math.round(left)}px`;
	popover.style.top = `${Math.round(top)}px`;
}

const ITEM_SELECTOR =
	'button:not([disabled]):not([aria-hidden="true"]), a[href]:not([aria-hidden="true"]), [role="menuitem"]:not([aria-disabled="true"]), [role="option"]:not([aria-disabled="true"])';

/**
 * Svelte action providing Arrow / Home / End roving tabindex keyboard navigation
 * inside popover button groups and menus.
 */
export function useRovingMenu(
	node: HTMLElement,
	options: RovingMenuOptions = {}
): { update: (next?: RovingMenuOptions) => void; destroy: () => void } {
	let orientation = options.orientation ?? 'vertical';
	let loop = options.loop ?? true;

	function getItems(): HTMLElement[] {
		return Array.from(node.querySelectorAll<HTMLElement>(ITEM_SELECTOR)).filter(
			(el) => el.getAttribute('aria-disabled') !== 'true' && !el.hidden
		);
	}

	function syncTabIndex(activeEl?: HTMLElement): void {
		const items = getItems();
		if (items.length === 0) return;
		const target = activeEl && items.includes(activeEl) ? activeEl : items[0];
		for (const item of items) {
			item.tabIndex = item === target ? 0 : -1;
		}
	}

	function onKeyDown(event: KeyboardEvent) {
		const items = getItems();
		if (items.length === 0) return;

		const nextKey = orientation === 'horizontal' ? 'ArrowRight' : 'ArrowDown';
		const prevKey = orientation === 'horizontal' ? 'ArrowLeft' : 'ArrowUp';

		const currentIndex = items.indexOf(document.activeElement as HTMLElement);
		let nextIndex = -1;

		if (event.key === nextKey) {
			event.preventDefault();
			if (currentIndex === -1) {
				nextIndex = 0;
			} else if (currentIndex + 1 < items.length) {
				nextIndex = currentIndex + 1;
			} else if (loop) {
				nextIndex = 0;
			} else {
				nextIndex = currentIndex;
			}
		} else if (event.key === prevKey) {
			event.preventDefault();
			if (currentIndex === -1) {
				nextIndex = items.length - 1;
			} else if (currentIndex - 1 >= 0) {
				nextIndex = currentIndex - 1;
			} else if (loop) {
				nextIndex = items.length - 1;
			} else {
				nextIndex = currentIndex;
			}
		} else if (event.key === 'Home') {
			event.preventDefault();
			nextIndex = 0;
		} else if (event.key === 'End') {
			event.preventDefault();
			nextIndex = items.length - 1;
		}

		if (nextIndex >= 0 && items[nextIndex]) {
			syncTabIndex(items[nextIndex]);
			items[nextIndex].focus();
		}
	}

	function onFocusIn(event: FocusEvent) {
		const target = event.target as HTMLElement | null;
		if (target) {
			syncTabIndex(target);
		}
	}

	syncTabIndex();
	node.addEventListener('keydown', onKeyDown);
	node.addEventListener('focusin', onFocusIn);

	return {
		update(next: RovingMenuOptions = {}) {
			orientation = next.orientation ?? 'vertical';
			loop = next.loop ?? true;
			syncTabIndex();
		},
		destroy() {
			node.removeEventListener('keydown', onKeyDown);
			node.removeEventListener('focusin', onFocusIn);
		}
	};
}

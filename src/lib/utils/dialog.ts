/**
 * Native <dialog> helpers following modern-web-guidance:
 * - Light-dismiss fallback for browsers lacking HTMLDialogElement.closedBy (Safari)
 * - Safe close + returnValue reset
 */

export function supportsClosedBy(): boolean {
	return typeof HTMLDialogElement !== 'undefined' && 'closedBy' in HTMLDialogElement.prototype;
}

function isOutsideRect(clientX: number, clientY: number, rect: DOMRect): boolean {
	return (
		clientX < rect.left ||
		clientX > rect.right ||
		clientY < rect.top ||
		clientY > rect.bottom
	);
}

/**
 * Svelte action adding Safari light-dismiss fallback to a `<dialog closedby="any">`.
 * No-op in browsers with native `closedBy` support.
 * Requires both pointerdown and pointerup outside the dialog bounding rect so
 * drag-selections that end on the backdrop never dismiss the modal.
 */
export function useDialogLightDismiss(node: HTMLDialogElement): { destroy: () => void } {
	if (supportsClosedBy()) {
		return { destroy: () => {} };
	}

	let pointerDownOutside = false;

	function onPointerDown(event: PointerEvent) {
		if (!node.open || event.target !== node) {
			pointerDownOutside = false;
			return;
		}
		const rect = node.getBoundingClientRect();
		pointerDownOutside = isOutsideRect(event.clientX, event.clientY, rect);
	}

	function onPointerUp(event: PointerEvent) {
		if (!pointerDownOutside || !node.open || event.target !== node) {
			pointerDownOutside = false;
			return;
		}
		const rect = node.getBoundingClientRect();
		const releasedOutside = isOutsideRect(event.clientX, event.clientY, rect);
		pointerDownOutside = false;
		if (releasedOutside) {
			node.close('dismiss');
		}
	}

	function resetPointerState() {
		pointerDownOutside = false;
	}

	node.addEventListener('pointerdown', onPointerDown);
	node.addEventListener('pointerup', onPointerUp);
	node.addEventListener('pointercancel', resetPointerState);
	node.addEventListener('close', resetPointerState);

	return {
		destroy() {
			node.removeEventListener('pointerdown', onPointerDown);
			node.removeEventListener('pointerup', onPointerUp);
			node.removeEventListener('pointercancel', resetPointerState);
			node.removeEventListener('close', resetPointerState);
		}
	};
}

/**
 * Close a `<dialog>` if open and reset `returnValue` after close listeners run.
 */
export function closeWithReset(dialog: HTMLDialogElement | null, returnValue?: string): void {
	if (!dialog) return;
	if (dialog.open) {
		if (returnValue !== undefined) {
			dialog.close(returnValue);
		} else {
			dialog.close();
		}
	}
	dialog.returnValue = '';
}

/**
 * Svelte action to set native `autofocus` on the safe Cancel/Keep button inside
 * a destructive confirmation `<dialog>` without triggering Svelte's template
 * `a11y_autofocus` lint warning.
 */
export function useDialogSafeAutofocus(node: HTMLElement): void {
	node.autofocus = true;
}

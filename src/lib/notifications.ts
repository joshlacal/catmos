/**
 * Browser notification support for Catmos.
 * Only active in browser mode (not Tauri).
 */

function isTauri(): boolean {
  return typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;
}

let permissionRequested = false;

async function ensurePermission(): Promise<boolean> {
  if (isTauri()) return false;
  if (!('Notification' in window)) return false;

  if (Notification.permission === 'granted') return true;
  if (Notification.permission === 'denied') return false;

  if (!permissionRequested) {
    permissionRequested = true;
    const result = await Notification.requestPermission();
    return result === 'granted';
  }

  return false;
}

/**
 * Show a browser notification for an incoming message when the tab is hidden.
 * No-op in Tauri or when the tab is visible.
 */
export async function notifyIncomingMessage(
  sender: string,
  preview: string,
  convoId: string
): Promise<void> {
  if (isTauri()) return;
  if (!document.hidden) return;

  const allowed = await ensurePermission();
  if (!allowed) return;

  const truncated = preview.length > 100 ? preview.slice(0, 97) + '...' : preview;

  const notification = new Notification(sender, {
    body: truncated,
    tag: `catmos-${convoId}`,
    icon: '/icon-192.png'
  });

  notification.onclick = () => {
    window.focus();
    notification.close();
  };
}

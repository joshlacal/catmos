import type { Config } from '@sveltejs/kit/vite';

type SvelteKitCspDirectives = NonNullable<NonNullable<Config['csp']>['directives']>;

/**
 * Canonical Content Security Policy directives shared across the SvelteKit
 * static bundle (`vite.config.ts`) and verified against Tauri (`tauri.conf.json`)
 * and static edge response headers (`static/_headers`).
 *
 * Security invariants:
 * - Zero `'unsafe-inline'` or `'unsafe-eval'` in `script-src`; only `'self'`
 *   and `'wasm-unsafe-eval'` (required for WebAssembly instantiation of OpenMLS),
 *   plus SvelteKit's compile-time SHA-256 bootstrap hash (`mode: 'hash'`).
 * - `connect-src` allows direct HTTPS calls to users' Personal Data Servers,
 *   ATProto Authorization Servers, the Petrel CAB (`https://api.catbird.blue`),
 *   DNS-over-HTTPS (`https://cloudflare-dns.com`), and our delivery service
 *   (`https://chat.catbird.blue` / `wss://chat.catbird.blue`).
 * - `object-src 'none'`, `base-uri 'self'`, `form-action 'self'`, and
 *   `frame-ancestors 'none'` block plugin execution, base-tag hijacking,
 *   credential-exfiltrating form posts, and clickjacking frames.
 */
export const CATMOS_WEB_CONNECT_ORIGINS = [
	'self',
	'https:',
	'https://api.catbird.blue',
	'https://chat.catbird.blue',
	'wss://chat.catbird.blue',
	'https://public.api.bsky.app',
	'https://cloudflare-dns.com'
] as const;

export const CATMOS_TAURI_CONNECT_ORIGINS = [
	'self',
	'ipc:',
	'http://ipc.localhost',
	'https://api.catbird.blue',
	'wss://api.catbird.blue',
	'https://chat.catbird.blue',
	'wss://chat.catbird.blue',
	'https://public.api.bsky.app'
] as const;

export const CATMOS_SVELTEKIT_CSP_DIRECTIVES = {
	'default-src': ['self'],
	'script-src': ['self', 'wasm-unsafe-eval'],
	'style-src': ['self', 'unsafe-inline'],
	'img-src': ['self', 'data:', 'blob:', 'https:'],
	'media-src': ['self', 'blob:', 'data:'],
	'font-src': ['self'],
	'manifest-src': ['self'],
	'worker-src': ['self'],
	'connect-src': [...CATMOS_WEB_CONNECT_ORIGINS],
	'object-src': ['none'],
	'base-uri': ['self'],
	'form-action': ['self'],
	'frame-ancestors': ['none']
} satisfies SvelteKitCspDirectives;

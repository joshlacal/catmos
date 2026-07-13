const OAUTH_NONCE_KEY = 'catmos_oauth_browser_nonce';
const EXCHANGE_CODE_PATTERN = /^[A-Za-z0-9_-]{43}$/;

export interface OAuthStorage {
	getItem(key: string): string | null;
	setItem(key: string, value: string): void;
	removeItem(key: string): void;
}

type RandomBytes = () => Uint8Array;
type Fetcher = (input: string, init: RequestInit) => Promise<Response>;

function randomNonce(randomBytes?: RandomBytes): string {
	const bytes = randomBytes ? randomBytes() : crypto.getRandomValues(new Uint8Array(32));
	if (bytes.length !== 32) throw new Error('OAuth nonce generation failed');
	let binary = '';
	for (const byte of bytes) binary += String.fromCharCode(byte);
	return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

export function beginOAuthExchange(
	nestUrl: string,
	identifier: string,
	redirectTo: string,
	storage: OAuthStorage,
	randomBytes?: RandomBytes
): URL {
	const nonce = randomNonce(randomBytes);
	storage.setItem(OAUTH_NONCE_KEY, nonce);
	const loginUrl = new URL('/auth/login', nestUrl);
	loginUrl.searchParams.set('identifier', identifier);
	loginUrl.searchParams.set('client', 'catmos');
	loginUrl.searchParams.set('redirect_to', redirectTo);
	loginUrl.searchParams.set('browser_nonce', nonce);
	return loginUrl;
}

/** Removes the nonce before any network operation so callbacks cannot be replayed locally. */
export function consumeOAuthNonce(storage: OAuthStorage): string | null {
	const nonce = storage.getItem(OAUTH_NONCE_KEY);
	storage.removeItem(OAUTH_NONCE_KEY);
	return nonce;
}

export function parseOAuthCallback(url: URL): string {
	const code = url.searchParams.get('code');
	if (
		url.pathname !== '/auth/callback' ||
		!code ||
		url.searchParams.getAll('code').length !== 1 ||
		!EXCHANGE_CODE_PATTERN.test(code) ||
		url.searchParams.has('session_id') ||
		Array.from(url.searchParams.keys()).some((key) => key !== 'code')
	) {
		throw new Error('Invalid OAuth callback');
	}
	return code;
}

export function cancelOAuthExchange(storage: OAuthStorage): void {
	storage.removeItem(OAUTH_NONCE_KEY);
}

export async function redeemOAuthCode(
	nestUrl: string,
	code: string,
	browserNonce: string,
	fetcher: Fetcher = fetch
): Promise<string> {
	const response = await fetcher(new URL('/auth/exchange', nestUrl).toString(), {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ code, browser_nonce: browserNonce })
	});
	if (!response.ok) throw new Error(`OAuth exchange failed (${response.status})`);
	const body: unknown = await response.json();
	const sessionId =
		typeof body === 'object' && body !== null && 'session_id' in body
			? (body as { session_id?: unknown }).session_id
			: undefined;
	if (typeof sessionId !== 'string' || sessionId.length === 0) {
		throw new Error('OAuth exchange returned an invalid response');
	}
	return sessionId;
}

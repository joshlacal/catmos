const OAUTH_NONCE_KEY = 'catmos_oauth_browser_nonce';
const EXCHANGE_CODE_PATTERN = /^[A-Za-z0-9_-]{43}$/;

export interface OAuthStorage {
	getItem(key: string): string | null;
	setItem(key: string, value: string): void;
	removeItem(key: string): void;
}

type RandomBytes = () => Uint8Array;
type Fetcher = (input: string, init: RequestInit) => Promise<Response>;

export class OAuthFlowGeneration {
	private generation = 0;
	private claimedGeneration: number | null = null;

	begin(): number {
		this.generation += 1;
		this.claimedGeneration = null;
		return this.generation;
	}

	cancel(): void {
		this.generation += 1;
		this.claimedGeneration = null;
	}

	isActive(generation: number): boolean {
		return generation === this.generation;
	}

	claim(generation: number): boolean {
		if (!this.isActive(generation) || this.claimedGeneration === generation) return false;
		this.claimedGeneration = generation;
		return true;
	}
}

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
	fetcher: Fetcher = fetch,
	options: { timeoutMs?: number; maxResponseBytes?: number } = {}
): Promise<string> {
	const timeoutMs = options.timeoutMs ?? 10_000;
	const maxResponseBytes = options.maxResponseBytes ?? 4096;
	const controller = new AbortController();
	const timeout = setTimeout(() => controller.abort(), timeoutMs);
	let response: Response;
	try {
		response = await fetcher(new URL('/auth/exchange', nestUrl).toString(), {
			method: 'POST',
			redirect: 'error',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ code, browser_nonce: browserNonce }),
			signal: controller.signal
		});
		if (!response.ok) throw new Error(`OAuth exchange failed (${response.status})`);
		const contentType = response.headers.get('content-type')?.split(';', 1)[0].trim().toLowerCase();
		if (contentType !== 'application/json') throw new Error('OAuth exchange returned an invalid content type');
		const contentLength = response.headers.get('content-length');
		if (contentLength && (!/^\d+$/.test(contentLength) || Number(contentLength) > maxResponseBytes)) {
			throw new Error('OAuth exchange response is too large');
		}
		if (!response.body) throw new Error('OAuth exchange returned an invalid response');
		const reader = response.body.getReader();
		const chunks: Uint8Array[] = [];
		let total = 0;
		while (true) {
			const { done, value } = await reader.read();
			if (done) break;
			total += value.byteLength;
			if (total > maxResponseBytes) {
				await reader.cancel();
				throw new Error('OAuth exchange response is too large');
			}
			chunks.push(value);
		}
		const bytes = new Uint8Array(total);
		let offset = 0;
		for (const chunk of chunks) {
			bytes.set(chunk, offset);
			offset += chunk.byteLength;
		}
		const body: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
		const sessionId =
			typeof body === 'object' && body !== null && 'session_id' in body
				? (body as { session_id?: unknown }).session_id
				: undefined;
		if (typeof sessionId !== 'string' || sessionId.length === 0) {
			throw new Error('OAuth exchange returned an invalid response');
		}
		return sessionId;
	} catch (error) {
		if (controller.signal.aborted) throw new Error('OAuth exchange timed out');
		throw error;
	} finally {
		clearTimeout(timeout);
	}
}

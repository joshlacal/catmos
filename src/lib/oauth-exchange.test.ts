import { describe, expect, it, vi } from 'vitest';
import { beginOAuthExchange, consumeOAuthNonce, OAuthFlowGeneration, parseOAuthCallback, redeemOAuthCode, type OAuthStorage } from './oauth-exchange';

function memoryStorage(): OAuthStorage {
	const values = new Map<string, string>();
	return { getItem: (key) => values.get(key) ?? null, setItem: (key, value) => values.set(key, value), removeItem: (key) => values.delete(key) };
}

describe('OAuth callback exchange', () => {
	it('generation-binds overlapping starts, cancellation, stale events, and duplicate newest events', () => {
		const flows = new OAuthFlowGeneration();
		const first = flows.begin();
		const second = flows.begin();
		expect(flows.claim(first)).toBe(false);
		expect(flows.claim(second)).toBe(true);
		expect(flows.claim(second)).toBe(false);
		const canceled = flows.begin();
		flows.cancel();
		expect(flows.isActive(canceled)).toBe(false);
		expect(flows.claim(canceled)).toBe(false);
	});
	it('binds login to a random browser nonce and exact redirect URL', () => {
		const storage = memoryStorage();
		const login = beginOAuthExchange('https://api.catbird.blue', 'alice.example', 'https://catmos.example/auth/callback', storage, () => new Uint8Array(32).fill(0xab));
		expect(login.searchParams.get('redirect_to')).toBe('https://catmos.example/auth/callback');
		expect(login.searchParams.get('browser_nonce')).toMatch(/^[A-Za-z0-9_-]{43}$/);
		expect(consumeOAuthNonce(storage)).toBe(login.searchParams.get('browser_nonce'));
	});

	it('consumes the local nonce exactly once', () => {
		const storage = memoryStorage();
		beginOAuthExchange('https://api.catbird.blue', 'alice', 'https://catmos.example/auth/callback', storage);
		expect(consumeOAuthNonce(storage)).not.toBeNull();
		expect(consumeOAuthNonce(storage)).toBeNull();
	});

	it('accepts only a structural code callback and rejects session credentials', () => {
		expect(parseOAuthCallback(new URL('https://catmos.example/auth/callback?code=' + 'A'.repeat(43)))).toBe('A'.repeat(43));
		expect(() => parseOAuthCallback(new URL('https://catmos.example/auth/callback?session_id=secret'))).toThrow('Invalid OAuth callback');
		expect(() => parseOAuthCallback(new URL('https://catmos.example/auth/callback?code=bad!'))).toThrow('Invalid OAuth callback');
		expect(() => parseOAuthCallback(new URL('https://catmos.example/other?code=' + 'A'.repeat(43)))).toThrow('Invalid OAuth callback');
		expect(() => parseOAuthCallback(new URL('https://catmos.example/auth/callback?code=' + 'A'.repeat(43) + '&code=' + 'B'.repeat(43)))).toThrow('Invalid OAuth callback');
	});

	it('posts the code and nonce to the exchange endpoint without fallback', async () => {
		const fetcher = vi.fn().mockResolvedValue(new Response(JSON.stringify({ session_id: 'credential' }), { status: 200, headers: { 'Content-Type': 'application/json' } }));
		await expect(redeemOAuthCode('https://api.catbird.blue', 'A'.repeat(43), 'nonce-value-123456', fetcher)).resolves.toBe('credential');
		expect(fetcher).toHaveBeenCalledWith('https://api.catbird.blue/auth/exchange', expect.objectContaining({ method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ code: 'A'.repeat(43), browser_nonce: 'nonce-value-123456' }), signal: expect.any(AbortSignal) }));
		fetcher.mockResolvedValueOnce(new Response('', { status: 401 }));
		await expect(redeemOAuthCode('https://api.catbird.blue', 'A'.repeat(43), 'nonce-value-123456', fetcher)).rejects.toThrow('OAuth exchange failed');
		expect(fetcher).toHaveBeenCalledTimes(2);
	});

	it('refuses redirects so code and nonce cannot be forwarded to another origin', async () => {
		const fetcher = vi.fn().mockImplementation((_input: string, init: RequestInit) => {
			expect(init.redirect).toBe('error');
			return Promise.resolve(new Response(JSON.stringify({ session_id: 'credential' }), { status: 200, headers: { 'Content-Type': 'application/json' } }));
		});
		await expect(redeemOAuthCode('https://api.catbird.blue', 'A'.repeat(43), 'nonce-value-123456', fetcher)).resolves.toBe('credential');
		expect(fetcher).toHaveBeenCalledOnce();
	});

	it('times out a delayed exchange response', async () => {
		const fetcher = vi.fn((_input: string, init: RequestInit) => new Promise<Response>((_resolve, reject) => {
			init.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')));
		}));
		await expect(redeemOAuthCode('https://api.catbird.blue', 'A'.repeat(43), 'nonce-value-123456', fetcher, { timeoutMs: 5 })).rejects.toThrow('timed out');
	});

	it('rejects oversized content-length and chunked exchange bodies', async () => {
		const oversizedLength = vi.fn().mockResolvedValue(new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json', 'Content-Length': '4097' } }));
		await expect(redeemOAuthCode('https://api.catbird.blue', 'A'.repeat(43), 'nonce-value-123456', oversizedLength)).rejects.toThrow('too large');

		const stream = new ReadableStream<Uint8Array>({
			start(controller) {
				controller.enqueue(new Uint8Array(3000));
				controller.enqueue(new Uint8Array(2000));
				controller.close();
			}
		});
		const oversizedChunked = vi.fn().mockResolvedValue(new Response(stream, { status: 200, headers: { 'Content-Type': 'application/json' } }));
		await expect(redeemOAuthCode('https://api.catbird.blue', 'A'.repeat(43), 'nonce-value-123456', oversizedChunked)).rejects.toThrow('too large');
	});

	it('rejects a non-json exchange response', async () => {
		const fetcher = vi.fn().mockResolvedValue(new Response('{"session_id":"credential"}', { status: 200, headers: { 'Content-Type': 'text/plain' } }));
		await expect(redeemOAuthCode('https://api.catbird.blue', 'A'.repeat(43), 'nonce-value-123456', fetcher)).rejects.toThrow('content type');
	});
});

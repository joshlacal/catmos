import { describe, expect, it, vi } from 'vitest';
import { beginOAuthExchange, consumeOAuthNonce, parseOAuthCallback, redeemOAuthCode, type OAuthStorage } from './oauth-exchange';

function memoryStorage(): OAuthStorage {
	const values = new Map<string, string>();
	return { getItem: (key) => values.get(key) ?? null, setItem: (key, value) => values.set(key, value), removeItem: (key) => values.delete(key) };
}

describe('OAuth callback exchange', () => {
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
		expect(fetcher).toHaveBeenCalledWith('https://api.catbird.blue/auth/exchange', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ code: 'A'.repeat(43), browser_nonce: 'nonce-value-123456' }) });
		fetcher.mockResolvedValueOnce(new Response('', { status: 401 }));
		await expect(redeemOAuthCode('https://api.catbird.blue', 'A'.repeat(43), 'nonce-value-123456', fetcher)).rejects.toThrow('OAuth exchange failed');
		expect(fetcher).toHaveBeenCalledTimes(2);
	});
});

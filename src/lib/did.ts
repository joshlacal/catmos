/**
 * Multi-device DID normalization helpers.
 *
 * MLS leaf credentials carry device-scoped identifiers (`did:plc:abc#device-uuid`),
 * whereas AT Protocol profiles, account auth state, reactions, and conversation
 * ownership are keyed by bare account DID (`did:plc:abc`).
 */

export function stripDidFragment(did: string | null | undefined): string {
	if (typeof did !== 'string') return '';
	const trimmed = did.trim();
	if (!trimmed) return '';
	const hashIdx = trimmed.indexOf('#');
	return (hashIdx >= 0 ? trimmed.slice(0, hashIdx) : trimmed).trim();
}

/**
 * Canonicalize an ATProto account DID matching `catbird_mls::normalize_account_did`:
 * - Strips any `#<deviceId>` fragment and surrounding whitespace.
 * - Lowercases scheme (`did`) and method (`plc`, `web`, `key`, ...).
 * - Lowercases the method-specific identifier ONLY when `method === 'web'`,
 *   preserving exact case on `did:plc:` / `did:key:` identifiers.
 */
export function normalizeAccountDid(did: string): string {
	const bare = stripDidFragment(did);
	const firstColon = bare.indexOf(':');
	const secondColon = firstColon >= 0 ? bare.indexOf(':', firstColon + 1) : -1;
	if (firstColon <= 0 || secondColon <= firstColon + 1) {
		throw new Error(`invalid ATProto account DID \`${did}\``);
	}
	const scheme = bare.slice(0, firstColon).toLowerCase();
	const method = bare.slice(firstColon + 1, secondColon).toLowerCase();
	const methodSpecific = bare.slice(secondColon + 1);
	if (scheme !== 'did' || !method || !methodSpecific) {
		throw new Error(`invalid ATProto account DID \`${did}\``);
	}
	const normalizedId = method === 'web' ? methodSpecific.toLowerCase() : methodSpecific;
	return `${scheme}:${method}:${normalizedId}`;
}

export function tryNormalizeAccountDid(did: string | null | undefined): string {
	const bare = stripDidFragment(did);
	if (!bare) return '';
	try {
		return normalizeAccountDid(bare);
	} catch {
		return bare;
	}
}

export function extractDidDeviceFragment(did: string | null | undefined): string | null {
	if (typeof did !== 'string') return null;
	const trimmed = did.trim();
	const hashIdx = trimmed.indexOf('#');
	if (hashIdx < 0) return null;
	const fragment = trimmed.slice(hashIdx + 1).trim();
	return fragment.length > 0 ? fragment : null;
}

export function isSameAccountDid(
	a: string | null | undefined,
	b: string | null | undefined
): boolean {
	const left = tryNormalizeAccountDid(a);
	const right = tryNormalizeAccountDid(b);
	if (!left || !right) return false;
	return left === right;
}

export function dedupeAccountDids(dids: Iterable<string | null | undefined>): string[] {
	const seen = new Set<string>();
	const result: string[] = [];
	for (const raw of dids) {
		const accountDid = tryNormalizeAccountDid(raw);
		if (!accountDid || seen.has(accountDid)) continue;
		seen.add(accountDid);
		result.push(accountDid);
	}
	return result;
}

/**
 * Fold per-device reaction sender lists (`did#dev-A`, `did#dev-B`) down to at
 * most one canonical account DID per emoji, preserving first-seen order.
 */
export function foldReactionsByAccount(
	reactions: Record<string, string[]> | undefined | null
): Record<string, string[]> {
	if (!reactions) return {};
	const folded: Record<string, string[]> = {};
	for (const [emoji, senders] of Object.entries(reactions)) {
		if (!emoji || !Array.isArray(senders)) continue;
		const accounts = dedupeAccountDids(senders);
		if (accounts.length > 0) {
			folded[emoji] = accounts;
		}
	}
	return folded;
}

export function hasAccountReacted(
	reactions: Record<string, string[]> | undefined | null,
	emoji: string,
	userDid: string | null | undefined
): boolean {
	if (!reactions || !emoji) return false;
	const entries = reactions[emoji];
	if (!Array.isArray(entries)) return false;
	return entries.some((entry) => isSameAccountDid(entry, userDid));
}

export function applyReactionToMap(
	reactions: Record<string, string[]> | undefined | null,
	senderDid: string,
	emoji: string,
	action: 'add' | 'remove'
): Record<string, string[]> {
	const folded = foldReactionsByAccount(reactions);
	const accountDid = tryNormalizeAccountDid(senderDid);
	if (!accountDid || !emoji) return folded;

	const current = folded[emoji] ? [...folded[emoji]] : [];
	if (action === 'add') {
		if (!current.some((existing) => isSameAccountDid(existing, accountDid))) {
			current.push(accountDid);
		}
	} else {
		for (let i = current.length - 1; i >= 0; i -= 1) {
			if (isSameAccountDid(current[i], accountDid)) {
				current.splice(i, 1);
			}
		}
	}

	if (current.length > 0) {
		folded[emoji] = current;
	} else {
		delete folded[emoji];
	}
	return folded;
}

export function foldGroupMembersByAccount<
	T extends { did: string; handle: string; displayName?: string; role: 'admin' | 'member' }
>(members: readonly T[]): T[] {
	const byAccount = new Map<string, T>();
	for (const member of members) {
		const accountDid = tryNormalizeAccountDid(member.did);
		if (!accountDid) continue;
		const existing = byAccount.get(accountDid);
		const normalizedRole: 'admin' | 'member' = member.role.toLowerCase().includes('admin')
			? 'admin'
			: 'member';
		const normalizedHandle =
			member.handle && !member.handle.includes('#')
				? member.handle
				: stripDidFragment(member.handle) || accountDid;
		if (!existing) {
			byAccount.set(accountDid, {
				...member,
				did: accountDid,
				handle: normalizedHandle,
				role: normalizedRole
			});
		} else if (normalizedRole === 'admin' && existing.role !== 'admin') {
			byAccount.set(accountDid, {
				...existing,
				role: 'admin',
				displayName: existing.displayName ?? member.displayName
			});
		}
	}
	return Array.from(byAccount.values());
}

export type RecoveryCategory =
	| 'retry'
	| 'reauthenticate'
	| 'rebind'
	| 'rejoin'
	| 'access-ended';

export interface RecoveryNotice {
	category: RecoveryCategory;
	message: string;
}

const PREFIX = 'catmos-recovery:';

/** Decode the backend's stable action marker without exposing credentials. */
export function recoveryNotice(error: unknown): RecoveryNotice {
	const raw = error instanceof Error ? error.message : String(error);
	if (raw.startsWith(PREFIX)) {
		const [, category, ...rest] = raw.split(':');
		if (
			category === 'reauthenticate' ||
			category === 'rebind' ||
			category === 'rejoin' ||
			category === 'access-ended' ||
			category === 'retry'
		) {
			return { category, message: rest.join(':') || 'Chat connection failed' };
		}
	}
	const lower = raw.toLowerCase();
	if (lower.includes('401') || lower.includes('unauthorized') || lower.includes('expired')) {
		return { category: 'reauthenticate', message: raw };
	}
	if (
		lower.includes('access ended') ||
		lower.includes('not a member') ||
		lower.includes('not_member')
	) {
		return { category: 'access-ended', message: raw };
	}
	if (lower.includes('403') || lower.includes('forbidden')) {
		return { category: 'rebind', message: raw };
	}
	if (lower.includes('binding') || lower.includes('dpop') || lower.includes('signer')) {
		return { category: 'rebind', message: raw };
	}
	if (lower.includes('rejoin') || lower.includes('not joined') || lower.includes('epoch')) {
		return { category: 'rejoin', message: raw };
	}
	return { category: 'retry', message: raw };
}

export function recoveryLabel(category: RecoveryCategory): string {
	return {
		retry: 'Retrying connection',
		reauthenticate: 'Sign in again',
		rebind: 'Reconnect chat device',
		rejoin: 'Rejoin conversation',
		'access-ended': 'Chat access ended'
	}[category];
}

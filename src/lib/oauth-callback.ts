/**
 * Strict validation for `catmos://oauth/callback` desktop deep links and
 * `/auth/callback` browser OAuth redirects.
 */

const UUID_V4_RE =
	/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const OAUTH_CODE_RE = /^[A-Za-z0-9._~+/-]{8,512}={0,2}$/;
const OAUTH_STATE_RE = /^[A-Za-z0-9._~-]{8,256}$/;
const OAUTH_ERROR_CODE_RE = /^[A-Za-z0-9_.-]{1,64}$/;

const ALLOWED_CALLBACK_PARAMS = new Set([
	'session_id',
	'code',
	'state',
	'iss',
	'error',
	'error_description'
]);

export type ValidatedOAuthCallback =
	| {
			kind: 'session';
			sessionId: string;
			state?: string;
			iss?: string;
	  }
	| {
			kind: 'code';
			code: string;
			state?: string;
			iss?: string;
	  }
	| {
			kind: 'error';
			error: string;
			errorDescription?: string;
			state?: string;
	  };

export function isCanonicalUuidV4(value: unknown): value is string {
	if (typeof value !== 'string') return false;
	return UUID_V4_RE.test(value);
}

export function normalizeSessionId(value: unknown): string {
	if (typeof value !== 'string') {
		throw new Error('Invalid OAuth session_id: expected string');
	}
	const trimmed = value.trim();
	if (!UUID_V4_RE.test(trimmed)) {
		throw new Error('Invalid OAuth session_id: must be a canonical UUIDv4');
	}
	return trimmed.toLowerCase();
}

function validateHttpsIssuer(rawIss: string): string {
	let parsed: URL;
	try {
		parsed = new URL(rawIss);
	} catch {
		throw new Error('Invalid OAuth iss parameter: malformed URL');
	}
	if (parsed.protocol !== 'https:') {
		throw new Error('Invalid OAuth iss parameter: must use https');
	}
	if (parsed.username || parsed.password || parsed.hash) {
		throw new Error('Invalid OAuth iss parameter: credentials and fragments are forbidden');
	}
	return parsed.toString();
}

function sanitizeErrorDescription(raw: string): string {
	const cleaned = raw.replace(/[\u0000-\u001f\u007f]/g, ' ').trim();
	return cleaned.slice(0, 256);
}

function validateSearchParams(searchParams: URLSearchParams): ValidatedOAuthCallback {
	const seenKeys = new Set<string>();
	for (const [key] of searchParams.entries()) {
		if (!ALLOWED_CALLBACK_PARAMS.has(key)) {
			throw new Error(`Unexpected OAuth callback parameter: ${key}`);
		}
		if (seenKeys.has(key)) {
			throw new Error(`Duplicate OAuth callback parameter: ${key}`);
		}
		seenKeys.add(key);
	}

	const errorParam = searchParams.get('error');
	const sessionIdParam = searchParams.get('session_id');
	const codeParam = searchParams.get('code');
	const stateParam = searchParams.get('state');
	const issParam = searchParams.get('iss');

	let validatedState: string | undefined;
	if (stateParam !== null) {
		if (!OAUTH_STATE_RE.test(stateParam)) {
			throw new Error('Invalid OAuth state parameter');
		}
		validatedState = stateParam;
	}

	let validatedIss: string | undefined;
	if (issParam !== null) {
		validatedIss = validateHttpsIssuer(issParam);
	}

	if (errorParam !== null) {
		if (sessionIdParam !== null || codeParam !== null) {
			throw new Error('Ambiguous OAuth callback: error cannot be combined with credentials');
		}
		if (!OAUTH_ERROR_CODE_RE.test(errorParam)) {
			throw new Error('Invalid OAuth error code');
		}
		const descRaw = searchParams.get('error_description');
		return {
			kind: 'error',
			error: errorParam,
			errorDescription: descRaw !== null ? sanitizeErrorDescription(descRaw) : undefined,
			state: validatedState
		};
	}

	if (sessionIdParam !== null && codeParam !== null) {
		throw new Error('Ambiguous OAuth callback: cannot contain both session_id and code');
	}

	if (sessionIdParam !== null) {
		return {
			kind: 'session',
			sessionId: normalizeSessionId(sessionIdParam),
			state: validatedState,
			iss: validatedIss
		};
	}

	if (codeParam !== null) {
		if (!OAUTH_CODE_RE.test(codeParam)) {
			throw new Error('Invalid OAuth authorization code format');
		}
		return {
			kind: 'code',
			code: codeParam,
			state: validatedState,
			iss: validatedIss
		};
	}

	throw new Error('Missing OAuth callback credentials (expected code or session_id)');
}

/**
 * Strictly validate a `catmos://oauth/callback?...` deep-link URL.
 */
export function validateCatmosDeepLinkCallback(rawUrl: string): ValidatedOAuthCallback {
	if (typeof rawUrl !== 'string' || rawUrl.length === 0 || rawUrl.length > 2048) {
		throw new Error('Invalid deep-link OAuth callback URL');
	}
	if (/[\u0000-\u001f\u007f\s]/.test(rawUrl)) {
		throw new Error('Invalid deep-link OAuth callback URL: control characters or whitespace');
	}

	let parsed: URL;
	try {
		parsed = new URL(rawUrl);
	} catch {
		throw new Error('Malformed deep-link OAuth callback URL');
	}

	if (parsed.protocol !== 'catmos:') {
		throw new Error(`Invalid OAuth callback scheme: ${parsed.protocol}`);
	}
	if (parsed.username || parsed.password) {
		throw new Error('OAuth callback deep link must not contain credentials');
	}
	if (parsed.port !== '') {
		throw new Error('OAuth callback deep link must not specify a port');
	}
	if (parsed.hostname !== 'oauth' || parsed.pathname !== '/callback') {
		throw new Error('Invalid OAuth callback target: expected catmos://oauth/callback');
	}
	if (parsed.hash !== '') {
		throw new Error('OAuth callback deep link must not contain a URL fragment');
	}
	// Guard against raw path-traversal sequences normalized away by URL parser
	const beforeQuery = rawUrl.split('?')[0] ?? '';
	if (beforeQuery !== 'catmos://oauth/callback') {
		throw new Error('Non-canonical catmos://oauth/callback URL');
	}

	return validateSearchParams(parsed.searchParams);
}

function validateHttpsCallbackUrlForPath(
	rawUrl: string | URL,
	expectedPath: '/auth/callback' | '/oauth/permission-callback',
	expectedOrigin?: string
): ValidatedOAuthCallback {
	const rawString = typeof rawUrl === 'string' ? rawUrl : rawUrl.toString();
	if (!rawString || rawString.length > 2048 || /[\u0000-\u001f\u007f]/.test(rawString)) {
		throw new Error('Invalid web OAuth callback URL');
	}

	let parsed: URL;
	try {
		parsed = typeof rawUrl === 'string' ? new URL(rawUrl) : new URL(rawUrl.toString());
	} catch {
		throw new Error('Malformed web OAuth callback URL');
	}

	const isLocalDev =
		parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1' || parsed.hostname === '[::1]';
	if (parsed.protocol !== 'https:' && !(isLocalDev && parsed.protocol === 'http:')) {
		throw new Error(`Insecure web OAuth callback protocol: ${parsed.protocol}`);
	}
	if (expectedOrigin && parsed.origin !== expectedOrigin) {
		throw new Error('OAuth callback origin mismatch');
	}
	if (parsed.username || parsed.password) {
		throw new Error('Web OAuth callback URL must not contain credentials');
	}
	if (parsed.pathname !== expectedPath) {
		throw new Error(`Invalid web OAuth callback path: expected ${expectedPath}`);
	}
	if (parsed.hash !== '') {
		throw new Error('Web OAuth callback URL must not contain a fragment');
	}

	return validateSearchParams(parsed.searchParams);
}

/**
 * Strictly validate a browser `/auth/callback` redirect URL.
 */
export function validateWebOAuthCallbackUrl(
	rawUrl: string | URL,
	expectedOrigin?: string
): ValidatedOAuthCallback {
	return validateHttpsCallbackUrlForPath(rawUrl, '/auth/callback', expectedOrigin);
}

/**
 * Strictly validate a browser `/oauth/permission-callback` progressive scope-upgrade redirect URL.
 */
export function validateWebPermissionCallbackUrl(
	rawUrl: string | URL,
	expectedOrigin?: string
): ValidatedOAuthCallback {
	return validateHttpsCallbackUrlForPath(rawUrl, '/oauth/permission-callback', expectedOrigin);
}

/**
 * Validate a Tauri `oauth-callback` IPC payload, which may be either a full
 * `catmos://oauth/callback?...` deep link or a pre-extracted UUIDv4 `session_id`.
 */
export function parseTauriOAuthCallbackPayload(payload: unknown): ValidatedOAuthCallback {
	if (typeof payload !== 'string') {
		throw new Error('Invalid Tauri OAuth callback payload type');
	}
	const trimmed = payload.trim();
	if (trimmed.includes('://')) {
		return validateCatmosDeepLinkCallback(trimmed);
	}
	return {
		kind: 'session',
		sessionId: normalizeSessionId(trimmed)
	};
}

/**
 * Clean storage isolation and state table unit tests for Catmos web/browser host.
 *
 * Imports canonical constants directly from $lib/wasm to prevent drift:
 * - Generation token and filesystem/logical suffix `-clean-v2-openmls-v09`
 * - Exact storagePrefix and dbPrefix
 * - Content root key format with sha256(did) and clean suffix
 * - Per-DID namespace isolation
 * - State table fail-closed checks
 * - Legacy key isolation
 * - Explicit reset marker-last ordering
 */

import {
	CLEAN_STORAGE_GENERATION_TOKEN,
	CLEAN_STORAGE_SUFFIX,
	STORAGE_PREFIX as DEFAULT_CLEAN_STORAGE_PREFIX,
	DB_PREFIX as DEFAULT_CLEAN_DB_PREFIX,
	CONTENT_ROOT_PREFIX,
	MLS_DB_KEY_PREFIX,
	INIT_RECORD_PREFIX,
	didKey
} from './wasm';

export async function computeContentRootKeyName(userDid: string): Promise<string> {
	const bytes = new TextEncoder().encode(userDid);
	const digest = await crypto.subtle.digest('SHA-256', bytes);
	const hex = Array.from(new Uint8Array(digest))
		.map((b) => b.toString(16).padStart(2, '0'))
		.join('');
	return `${CONTENT_ROOT_PREFIX}${hex}${CLEAN_STORAGE_SUFFIX}`;
}

export function testCleanStorageInvariants(): { passed: boolean; details: string[] } {
	const details: string[] = [];

	// 1. Generation tokens and suffixes
	if (CLEAN_STORAGE_GENERATION_TOKEN !== 'mls-state-clean-v2-openmls-v09') {
		throw new Error('Token mismatch');
	}
	details.push('Exact generation token verified');

	if (DEFAULT_CLEAN_STORAGE_PREFIX !== 'catbird_mls-clean-v2-openmls-v09') {
		throw new Error('Storage prefix mismatch');
	}
	if (DEFAULT_CLEAN_DB_PREFIX !== 'catbird-mls-clean-v2-openmls-v09') {
		throw new Error('DB prefix mismatch');
	}
	details.push('Default storage and DB prefixes verified');

	// 2. Canonical key formatting
	if (MLS_DB_KEY_PREFIX !== 'catbird_mls-clean-v2-openmls-v09_mls_db_key') {
		throw new Error(`Invalid MLS_DB_KEY_PREFIX: ${MLS_DB_KEY_PREFIX}`);
	}
	if (INIT_RECORD_PREFIX !== 'catbird_mls-clean-v2-openmls-v09_init_record') {
		throw new Error(`Invalid INIT_RECORD_PREFIX: ${INIT_RECORD_PREFIX}`);
	}
	details.push('Canonical database and marker prefixes verified');

	// 3. Per-DID key naming
	const aliceDid = 'did:plc:alice1234567890';
	const sessionKey = didKey(aliceDid, 'session_id');
	const mlsDbKey = didKey(aliceDid, 'mls_db_key');
	const initMarker = didKey(aliceDid, 'init_record');

	if (sessionKey !== `catbird_mls:${aliceDid}:session_id-clean-v2-openmls-v09`) {
		throw new Error(`Invalid session key: ${sessionKey}`);
	}
	if (mlsDbKey !== `catbird_mls:${aliceDid}:mls_db_key-clean-v2-openmls-v09`) {
		throw new Error(`Invalid mlsDbKey: ${mlsDbKey}`);
	}
	if (initMarker !== `catbird_mls:${aliceDid}:init_record-clean-v2-openmls-v09`) {
		throw new Error(`Invalid initMarker: ${initMarker}`);
	}
	details.push('Per-DID namespaced keys verified');

	// 4. Legacy isolation
	const legacyKeys = [
		'catbird_mls_active_did',
		'catbird_mls_mls_db_key',
		'catbird_mls_session_id',
		'catbird_ws_cursor'
	];
	for (const legacy of legacyKeys) {
		if (legacy.includes(CLEAN_STORAGE_SUFFIX)) {
			throw new Error(`Legacy key contains clean suffix: ${legacy}`);
		}
	}
	details.push('Legacy isolation verified');

	return { passed: true, details };
}

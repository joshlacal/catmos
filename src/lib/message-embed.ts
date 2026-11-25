/**
 * Projects a stored MLS message payload (`MessageRow.plaintext_json`) into the
 * fields the chat UI renders.
 *
 * The wire embed shape is Catbird's `{"type": kind, "data": {...}}` with
 * snake_case fields inside `data` (see catbird-mls `MLSEmbedData` and
 * CatbirdMLSCore `MLSMessagePayload.swift`). Older Catmos builds wrote a flat
 * camelCase embed, so every field read falls back to that shape too.
 */

export interface ImagePayload {
	blobId: string;
	keyB64: string;
	ivB64: string;
	sha256: string;
	contentType: string;
	size: number;
	width: number;
	height: number;
	altText?: string;
	blurhash?: string;
}

export interface AudioPayload {
	blobId: string;
	key: Uint8Array;
	iv: Uint8Array;
	keyB64: string;
	ivB64: string;
	sha256: string;
	contentType: string;
	size: number;
	durationMs: number;
	waveform: number[];
	transcript?: string;
}

/** Card-rendered embed kinds, kept in the wire shape. */
export interface DisplayEmbed {
	type: 'post' | 'link' | 'gif';
	data: Record<string, unknown>;
}

export interface MessageDetails {
	messageType: string;
	content: string;
	image?: ImagePayload;
	audio?: AudioPayload;
	embed?: DisplayEmbed;
}

const DISPLAY_EMBED_KINDS = new Set(['post', 'link', 'gif']);

export function decodeBase64Bytes(input: string): Uint8Array {
	const normalized = input.trim().replace(/-/g, '+').replace(/_/g, '/');
	if (!normalized) return new Uint8Array();
	const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
	const bin = atob(padded);
	const out = new Uint8Array(bin.length);
	for (let i = 0; i < bin.length; i += 1) {
		out[i] = bin.charCodeAt(i);
	}
	return out;
}

function asRecord(value: unknown): Record<string, unknown> | null {
	return typeof value === 'object' && value !== null && !Array.isArray(value)
		? (value as Record<string, unknown>)
		: null;
}

/** First defined value among `snake_case` and `camelCase` spellings. */
function field(d: Record<string, unknown>, ...names: string[]): unknown {
	for (const name of names) {
		if (d[name] !== undefined && d[name] !== null) return d[name];
	}
	return undefined;
}

function str(d: Record<string, unknown>, fallback: string, ...names: string[]): string {
	const v = field(d, ...names);
	return v === undefined ? fallback : String(v);
}

function optStr(d: Record<string, unknown>, ...names: string[]): string | undefined {
	const v = field(d, ...names);
	return typeof v === 'string' ? v : undefined;
}

function num(d: Record<string, unknown>, ...names: string[]): number {
	const n = Number(field(d, ...names) ?? 0);
	return Number.isFinite(n) ? n : 0;
}

export function extractMessageDetails(plaintextJson: string): MessageDetails {
	try {
		const parsed = JSON.parse(plaintextJson) as Record<string, unknown>;
		const messageType =
			typeof parsed.messageType === 'string'
				? parsed.messageType
				: typeof parsed.type === 'string'
					? parsed.type
					: 'text';
		const embed = asRecord(parsed.embed);
		const content =
			typeof parsed.text === 'string'
				? parsed.text
				: typeof parsed.content === 'string'
					? parsed.content
					: embed
						? ''
						: plaintextJson;

		if (!embed || typeof embed.type !== 'string') {
			return { messageType, content };
		}
		// Wire shape nests fields under `data`; legacy Catmos wrote them flat.
		const d = asRecord(embed.data) ?? embed;

		if (embed.type === 'image') {
			return {
				messageType: 'image',
				content,
				image: {
					blobId: str(d, '', 'blob_id', 'blobId'),
					keyB64: str(d, '', 'key', 'keyB64'),
					ivB64: str(d, '', 'iv', 'ivB64'),
					sha256: str(d, '', 'sha256'),
					contentType: str(d, 'image/jpeg', 'content_type', 'contentType'),
					size: num(d, 'size'),
					width: num(d, 'width'),
					height: num(d, 'height'),
					altText: optStr(d, 'alt_text', 'altText'),
					blurhash: optStr(d, 'blurhash')
				}
			};
		}
		if (embed.type === 'audio') {
			const keyB64 = str(d, '', 'key', 'keyB64');
			const ivB64 = str(d, '', 'iv', 'ivB64');
			const waveformRaw = field(d, 'waveform');
			return {
				messageType: 'voice',
				content,
				audio: {
					blobId: str(d, '', 'blob_id', 'blobId'),
					key: decodeBase64Bytes(keyB64),
					iv: decodeBase64Bytes(ivB64),
					keyB64,
					ivB64,
					sha256: str(d, '', 'sha256'),
					contentType: str(d, 'audio/webm;codecs=opus', 'content_type', 'contentType'),
					size: num(d, 'size'),
					durationMs: num(d, 'duration_ms', 'durationMs'),
					waveform: Array.isArray(waveformRaw)
						? waveformRaw.map((n) => Number(n)).filter((n) => Number.isFinite(n))
						: [],
					transcript: optStr(d, 'transcript')
				}
			};
		}
		if (DISPLAY_EMBED_KINDS.has(embed.type) && asRecord(embed.data)) {
			return {
				messageType,
				content,
				embed: { type: embed.type as DisplayEmbed['type'], data: d }
			};
		}
		return { messageType, content };
	} catch {
		return { messageType: 'text', content: plaintextJson };
	}
}

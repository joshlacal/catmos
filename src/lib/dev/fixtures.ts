/**
 * Deterministic offline-safe fixtures for Catmos DEV preview and verification.
 *
 * Uses zero external network URLs (all avatars and images are inline SVG data
 * URLs; the voice note is a synthesized PCM WAV buffer) and zero em-dashes.
 * Imported ONLY behind `if (import.meta.env.DEV)` so Rollup eliminates 100%
 * of this file from production builds.
 */

import type { Remote } from 'comlink';
import type { WorkerApi } from '#lib/mls-worker.ts';
import type {
	AuthState,
	Conversation,
	GroupMember,
	GroupMetadataView,
	LabyrinthBackupStatusView,
	Message,
	OptInStatus,
	ProfileView,
	QuarantineState,
	SearchResult
} from '#lib/wasm.ts';
import { applyReactionToMap, isSameAccountDid, stripDidFragment } from '#lib/did.ts';
import { REQUIRED_LABYRINTH_OAUTH_SCOPES } from '#lib/labyrinth-ui.ts';

// ---------------------------------------------------------------------------
// Inline SVG data URLs (zero external network fetches)
// ---------------------------------------------------------------------------

function svgDataUrl(svg: string): string {
	return `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg.trim())}`;
}

function makeAvatarSvg(initials: string, bgStart: string, bgEnd: string): string {
	return svgDataUrl(`
		<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 96 96" width="96" height="96">
			<defs>
				<linearGradient id="g" x1="0%" y1="0%" x2="100%" y2="100%">
					<stop offset="0%" stop-color="${bgStart}" />
					<stop offset="100%" stop-color="${bgEnd}" />
				</linearGradient>
			</defs>
			<rect width="96" height="96" rx="48" fill="url(#g)" />
			<text x="48" y="56" text-anchor="middle" fill="#FFFFFF" font-family="system-ui, -apple-system, sans-serif" font-size="34" font-weight="700">${initials}</text>
		</svg>
	`);
}

function makeGroupAvatarSvg(label: string, bgStart: string, bgEnd: string): string {
	return svgDataUrl(`
		<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 96 96" width="96" height="96">
			<defs>
				<linearGradient id="g" x1="0%" y1="0%" x2="100%" y2="100%">
					<stop offset="0%" stop-color="${bgStart}" />
					<stop offset="100%" stop-color="${bgEnd}" />
				</linearGradient>
			</defs>
			<rect width="96" height="96" rx="24" fill="url(#g)" />
			<text x="48" y="56" text-anchor="middle" fill="#FFFFFF" font-family="system-ui, -apple-system, sans-serif" font-size="30" font-weight="700">${label}</text>
		</svg>
	`);
}

export const DEMO_DIAGRAM_IMAGE_URL = svgDataUrl(`
	<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 640 360" width="640" height="360">
		<rect width="640" height="360" rx="18" fill="#16181F" />
		<rect x="24" y="24" width="592" height="312" rx="14" fill="#1D1F26" stroke="#313542" stroke-width="2" />
		<text x="48" y="64" fill="#E6E6EC" font-family="system-ui, sans-serif" font-size="20" font-weight="700">MLS Epoch Sync Pipeline</text>
		<text x="48" y="88" fill="#A8A8B0" font-family="system-ui, sans-serif" font-size="13">Device verification and encrypted metadata commit flow</text>
		<rect x="48" y="128" width="152" height="84" rx="12" fill="#005EFF" />
		<text x="124" y="164" text-anchor="middle" fill="#FFFFFF" font-family="system-ui, sans-serif" font-size="15" font-weight="700">Client Device</text>
		<text x="124" y="186" text-anchor="middle" fill="#DCE8FF" font-family="system-ui, sans-serif" font-size="12">OpenMLS + OPFS</text>
		<path d="M206 170 L246 170" stroke="#5192FF" stroke-width="3" stroke-linecap="round" />
		<polygon points="246,164 258,170 246,176" fill="#5192FF" />
		<rect x="262" y="128" width="152" height="84" rx="12" fill="#2A2D36" stroke="#5192FF" stroke-width="2" />
		<text x="338" y="164" text-anchor="middle" fill="#E6E6EC" font-family="system-ui, sans-serif" font-size="15" font-weight="700">Sequencer</text>
		<text x="338" y="186" text-anchor="middle" fill="#A8A8B0" font-family="system-ui, sans-serif" font-size="12">Ordered epoch log</text>
		<path d="M420 170 L460 170" stroke="#34C759" stroke-width="3" stroke-linecap="round" />
		<polygon points="460,164 472,170 460,176" fill="#34C759" />
		<rect x="476" y="128" width="116" height="84" rx="12" fill="#183A26" stroke="#34C759" stroke-width="2" />
		<text x="534" y="164" text-anchor="middle" fill="#E6E6EC" font-family="system-ui, sans-serif" font-size="15" font-weight="700">Peers</text>
		<text x="534" y="186" text-anchor="middle" fill="#8AE4A5" font-family="system-ui, sans-serif" font-size="12">Verified state</text>
		<rect x="48" y="246" width="544" height="58" rx="10" fill="#23252D" />
		<circle cx="74" cy="275" r="8" fill="#34C759" />
		<text x="94" y="280" fill="#E6E6EC" font-family="system-ui, sans-serif" font-size="13" font-weight="600">All 4 active devices converged on epoch 42 with zero framing errors</text>
	</svg>
`);

/**
 * Synthesize a real playable 16-bit PCM WAV clip (gentle two-note harmonic chime)
 * so `<VoicePlayer>` plays audio natively in Chromium without external files.
 */
export function synthesizeDemoWavBytes(durationMs = 2400, sampleRate = 8000): Uint8Array {
	const numSamples = Math.max(1, Math.floor((sampleRate * durationMs) / 1000));
	const dataSize = numSamples * 2;
	const buffer = new ArrayBuffer(44 + dataSize);
	const view = new DataView(buffer);

	const writeAscii = (offset: number, text: string) => {
		for (let i = 0; i < text.length; i += 1) {
			view.setUint8(offset + i, text.charCodeAt(i));
		}
	};

	writeAscii(0, 'RIFF');
	view.setUint32(4, 36 + dataSize, true);
	writeAscii(8, 'WAVE');
	writeAscii(12, 'fmt ');
	view.setUint32(16, 16, true);
	view.setUint16(20, 1, true);
	view.setUint16(22, 1, true);
	view.setUint32(24, sampleRate, true);
	view.setUint32(28, sampleRate * 2, true);
	view.setUint16(32, 2, true);
	view.setUint16(34, 16, true);
	writeAscii(36, 'data');
	view.setUint32(40, dataSize, true);

	for (let i = 0; i < numSamples; i += 1) {
		const t = i / sampleRate;
		const progress = i / numSamples;
		const envelope = Math.sin(Math.PI * Math.min(1, progress)) * 0.25;
		const freq = progress < 0.5 ? 440 : 554.37;
		const sample = Math.sin(2 * Math.PI * freq * t) * envelope;
		view.setInt16(44 + i * 2, Math.round(sample * 32767), true);
	}

	return new Uint8Array(buffer);
}

// ---------------------------------------------------------------------------
// Actors, Sessions & Profiles
// ---------------------------------------------------------------------------

export const DEMO_SESSION_ID = '11111111-1111-4111-8111-111111111111';
export const DEMO_DEVICE_ID = '22222222-2222-4222-8222-222222222222';
export const DEMO_SIBLING_DEVICE_ID = '33333333-3333-4333-8333-333333333333';

export const DEMO_CURRENT_USER: AuthState = {
	did: 'did:plc:alice0001',
	handle: 'alice.bsky.social',
	displayName: 'Alice Mercer',
	avatar: makeAvatarSvg('AM', '#005EFF', '#5192FF'),
	grantedScopes: [...REQUIRED_LABYRINTH_OAUTH_SCOPES]
};

export const DEMO_PROFILES: ProfileView[] = [
	{
		did: 'did:plc:alice0001',
		handle: 'alice.bsky.social',
		displayName: 'Alice Mercer',
		avatar: DEMO_CURRENT_USER.avatar
	},
	{
		did: 'did:plc:maya0002',
		handle: 'maya.catbird.blue',
		displayName: 'Maya Lin',
		avatar: makeAvatarSvg('ML', '#7B4FB5', '#C5A8E5')
	},
	{
		did: 'did:plc:marcus0003',
		handle: 'marcus.dev',
		displayName: 'Marcus Vance',
		avatar: makeAvatarSvg('MV', '#117A78', '#30B0AE')
	},
	{
		did: 'did:plc:priya0004',
		handle: 'priya.bsky.social',
		displayName: 'Priya Patel',
		avatar: makeAvatarSvg('PP', '#B03A6B', '#D66091')
	},
	{
		did: 'did:plc:devon0005',
		handle: 'devon.studio',
		displayName: 'Devon Brooks',
		avatar: makeAvatarSvg('DB', '#B84A14', '#FF955E')
	},
	{
		did: 'did:plc:soren0006',
		handle: 'soren.security',
		displayName: 'Soren Lindqvist',
		avatar: makeAvatarSvg('SL', '#3154A5', '#7490C9')
	},
	{
		did: 'did:plc:tessa0007',
		handle: 'tessa.bsky.social',
		displayName: 'Tessa Okafor',
		avatar: makeAvatarSvg('TO', '#4A48C4', '#9A98EA')
	}
];

export const DEMO_OPT_IN_MAP: Record<string, boolean> = {
	'did:plc:alice0001': true,
	'did:plc:maya0002': true,
	'did:plc:marcus0003': true,
	'did:plc:priya0004': true,
	'did:plc:devon0005': true,
	'did:plc:soren0006': true,
	'did:plc:tessa0007': false
};

export interface DemoBlueskyPostFixture {
	uri: string;
	author: {
		did: string;
		handle: string;
		displayName: string;
		avatar: string;
	};
	text: string;
	createdAt: string;
	likeCount: number;
	repostCount: number;
	replyCount: number;
}

export const DEMO_BLUESKY_POSTS: Record<string, DemoBlueskyPostFixture> = {
	'at://did:plc:maya0002/app.bsky.feed.post/3kdemo001': {
		uri: 'at://did:plc:maya0002/app.bsky.feed.post/3kdemo001',
		author: {
			did: 'did:plc:maya0002',
			handle: 'maya.catbird.blue',
			displayName: 'Maya Lin',
			avatar: makeAvatarSvg('ML', '#7B4FB5', '#C5A8E5')
		},
		text: 'Shipped end-to-end encrypted Spaces history sync across iOS, desktop, and web today. Every accent palette clears WCAG AA contrast in Light, Dim, and True Black.',
		createdAt: new Date(Date.now() - 3 * 60 * 60 * 1000).toISOString(),
		likeCount: 148,
		repostCount: 29,
		replyCount: 14
	}
};

// ---------------------------------------------------------------------------
// Timestamp helpers (anchored cleanly around today and yesterday)
// ---------------------------------------------------------------------------

function makeDayTimestamp(daysAgo: number, hours: number, minutes: number): string {
	const d = new Date();
	d.setHours(hours, minutes, 0, 0);
	d.setDate(d.getDate() - daysAgo);
	return d.toISOString();
}

export const DEMO_CONVO_IDS = {
	eng: 'convo-eng',
	design: 'convo-design',
	maya: 'convo-maya',
	marcus: 'convo-marcus',
	releases: 'convo-releases',
	priya: 'convo-priya'
} as const;

export const DEMO_SAVED_DRAFT = {
	convoId: DEMO_CONVO_IDS.marcus,
	text: 'Can we check the key package rotation threshold before Friday?'
};

export const DEMO_PINNED_IDS = [DEMO_CONVO_IDS.eng];
export const DEMO_MUTED_IDS = [DEMO_CONVO_IDS.releases];

export const DEMO_QUARANTINE_STATE: QuarantineState = {
	reasonTag: 'peer_bad_commit',
	sinceMs: Date.now() - 18 * 60 * 1000,
	suspectedDids: ['did:plc:devon0005']
};

export interface DemoFixtureDataset {
	user: AuthState;
	profiles: Map<string, ProfileView>;
	conversations: Conversation[];
	messagesByConvo: Map<string, Message[]>;
	failedMessagesByConvo: Map<string, Message[]>;
	olderMessagesByConvo: Map<string, Message[]>;
	membersByConvo: Map<string, GroupMember[]>;
	metadataByConvo: Map<string, GroupMetadataView>;
	quarantineByConvo: Map<string, QuarantineState>;
	blobs: Map<string, Uint8Array>;
	imageUrls: Map<string, string>;
}

const DEMO_ADMIN_DIDS: Record<string, string[]> = {
	[DEMO_CONVO_IDS.eng]: ['did:plc:alice0001', 'did:plc:maya0002'],
	[DEMO_CONVO_IDS.design]: ['did:plc:alice0001'],
	[DEMO_CONVO_IDS.releases]: ['did:plc:alice0001', 'did:plc:soren0006']
};

export function createDemoDataset(options?: {
	empty?: boolean;
	quarantineEng?: boolean;
}): DemoFixtureDataset {
	const profilesMap = new Map<string, ProfileView>();
	for (const p of DEMO_PROFILES) {
		profilesMap.set(p.did, { ...p });
	}

	const blobs = new Map<string, Uint8Array>();
	const voiceBytes = synthesizeDemoWavBytes(2400, 8000);
	blobs.set('demo:voice-blob-1', voiceBytes);

	const imageUrls = new Map<string, string>();
	imageUrls.set('demo-img-pipeline', DEMO_DIAGRAM_IMAGE_URL);

	if (options?.empty) {
		return {
			user: { ...DEMO_CURRENT_USER },
			profiles: profilesMap,
			conversations: [],
			messagesByConvo: new Map(),
			failedMessagesByConvo: new Map(),
			olderMessagesByConvo: new Map(),
			membersByConvo: new Map(),
			metadataByConvo: new Map(),
			quarantineByConvo: new Map(),
			blobs,
			imageUrls
		};
	}

	const y1015 = makeDayTimestamp(1, 10, 15);
	const y1016 = makeDayTimestamp(1, 10, 16);
	const y1018 = makeDayTimestamp(1, 10, 18);
	const y1430 = makeDayTimestamp(1, 14, 30);
	const t0905 = makeDayTimestamp(0, 9, 5);
	const t0906 = makeDayTimestamp(0, 9, 6);
	const t0908 = makeDayTimestamp(0, 9, 8);
	const t0912 = makeDayTimestamp(0, 9, 12);
	const t0914 = makeDayTimestamp(0, 9, 14);
	const t0916 = makeDayTimestamp(0, 9, 16);
	const t0918 = makeDayTimestamp(0, 9, 18);
	const t0919 = makeDayTimestamp(0, 9, 19);
	const t0920 = makeDayTimestamp(0, 9, 20);
	const t0840 = makeDayTimestamp(0, 8, 40);
	const t0815 = makeDayTimestamp(0, 8, 15);
	const d2 = makeDayTimestamp(2, 16, 45);
	const d4 = makeDayTimestamp(4, 11, 20);

	const conversations: Conversation[] = [
		{
			id: DEMO_CONVO_IDS.eng,
			groupId: 'a94f82c10e3b77d419f20c8b55d1a3e7',
			displayName: 'Core Engineering',
			description: 'MLS protocol sync, release readiness, and client architecture',
			members: [
				'did:plc:alice0001',
				'did:plc:maya0002',
				'did:plc:marcus0003',
				'did:plc:devon0005',
				'did:plc:soren0006'
			],
			lastMessage: 'Everything in that flow matches the mobile inspector spec. Ready to sign off.',
			lastMessageAt: t0919,
			unreadCount: 2,
			isGroup: true,
			avatarDataUrl: makeGroupAvatarSvg('CE', '#005EFF', '#3154A5')
		},
		{
			id: DEMO_CONVO_IDS.maya,
			groupId: 'b12e44d90c7a88e134f56b92aa10cd33',
			displayName: 'Maya Lin',
			members: ['did:plc:alice0001', 'did:plc:maya0002'],
			lastMessage: 'Looks super crisp on Dim and True Black.',
			lastMessageAt: t0912,
			unreadCount: 1,
			isGroup: false
		},
		{
			id: DEMO_CONVO_IDS.design,
			groupId: 'c44a9910e2b15f7c8901d234ef567890',
			displayName: 'Design Review',
			description: 'Catbird token parity across iOS, desktop, and web',
			members: ['did:plc:alice0001', 'did:plc:maya0002', 'did:plc:priya0004', 'did:plc:devon0005'],
			lastMessage: 'All seven accent palettes clear WCAG AA contrast now.',
			lastMessageAt: t0840,
			unreadCount: 0,
			isGroup: true,
			avatarDataUrl: makeGroupAvatarSvg('DR', '#7B4FB5', '#B03A6B')
		},
		{
			id: DEMO_CONVO_IDS.marcus,
			groupId: 'd88f0021c5a47e9b3102f445aa678901',
			displayName: 'Marcus Vance',
			members: ['did:plc:alice0001', 'did:plc:marcus0003'],
			lastMessage: 'I will merge the SQLCipher checkpoint patch tonight.',
			lastMessageAt: t0815,
			unreadCount: 0,
			isGroup: false
		},
		{
			id: DEMO_CONVO_IDS.releases,
			groupId: 'e19c3340a7d28b5e6601a778bc901234',
			displayName: 'Releases',
			description: 'Automated build and TestFlight release alerts',
			members: ['did:plc:alice0001', 'did:plc:soren0006', 'did:plc:marcus0003'],
			lastMessage: 'Catmos desktop 0.9.4 notarized and signed.',
			lastMessageAt: d2,
			unreadCount: 0,
			isGroup: true,
			avatarDataUrl: makeGroupAvatarSvg('RL', '#117A78', '#30B0AE')
		},
		{
			id: DEMO_CONVO_IDS.priya,
			groupId: 'f72b1189d4e30c6a9902b889cd012345',
			displayName: 'Priya Patel',
			members: ['did:plc:alice0001', 'did:plc:priya0004'],
			lastMessage: 'Thanks for walking through the accessibility checklist.',
			lastMessageAt: d4,
			unreadCount: 0,
			isGroup: false
		}
	];

	const engOlder: Message[] = [
		{
			id: 'msg-eng-001',
			conversationId: DEMO_CONVO_IDS.eng,
			senderDid: 'did:plc:soren0006',
			senderHandle: 'soren.security',
			content: 'Kicking off the epoch verification notes for this week.',
			timestamp: makeDayTimestamp(2, 11, 10),
			sequenceNumber: 1,
			status: 'read',
			isOwn: false,
			messageType: 'text'
		},
		{
			id: 'msg-eng-002',
			conversationId: DEMO_CONVO_IDS.eng,
			senderDid: 'did:plc:alice0001',
			senderHandle: 'alice.bsky.social',
			content: 'Sounds good. Let us verify browser OPFS recovery first.',
			timestamp: makeDayTimestamp(2, 11, 14),
			sequenceNumber: 2,
			status: 'read',
			isOwn: true,
			messageType: 'text'
		}
	];

	const demoVoicePayload = {
		blobId: 'demo:voice-blob-1',
		key: new Uint8Array(32).fill(0x11),
		iv: new Uint8Array(12).fill(0x22),
		keyB64: 'ERERERERERERERERERERERERERERERERERERERERERE=',
		ivB64: 'IiIiIiIiIiIiIiIi',
		sha256: '33'.repeat(32),
		contentType: 'audio/wav',
		size: voiceBytes.byteLength,
		durationMs: 2400,
		waveform: [
			0.18, 0.34, 0.58, 0.82, 0.66, 0.44, 0.72, 0.91, 0.78, 0.55,
			0.39, 0.68, 0.85, 0.73, 0.49, 0.31, 0.54, 0.62, 0.41, 0.22
		],
		transcript:
			'Quick update on the MLS group reset check. The new key schedule merged cleanly on iOS and desktop.'
	};

	const engMessages: Message[] = [
		{
			id: 'msg-eng-101',
			conversationId: DEMO_CONVO_IDS.eng,
			senderDid: 'did:plc:maya0002',
			senderHandle: 'maya.catbird.blue',
			content: 'Finished auditing the browser storage boundaries across tabs.',
			timestamp: y1015,
			sequenceNumber: 10,
			status: 'read',
			isOwn: false,
			messageType: 'text'
		},
		{
			id: 'msg-eng-102',
			conversationId: DEMO_CONVO_IDS.eng,
			senderDid: 'did:plc:maya0002',
			senderHandle: 'maya.catbird.blue',
			content: 'Tab eviction now tears down the displaced worker before a second tab opens OPFS.',
			timestamp: y1016,
			sequenceNumber: 11,
			status: 'read',
			isOwn: false,
			messageType: 'text'
		},
		{
			id: 'msg-eng-103',
			conversationId: DEMO_CONVO_IDS.eng,
			senderDid: 'did:plc:maya0002',
			senderHandle: 'maya.catbird.blue',
			content: 'That eliminates the split-brain commit risk completely.',
			timestamp: y1018,
			sequenceNumber: 12,
			status: 'read',
			isOwn: false,
			messageType: 'text',
			reactions: {
				'🎉': ['did:plc:alice0001', 'did:plc:marcus0003', 'did:plc:soren0006'],
				'🔒': ['did:plc:devon0005']
			}
		},
		{
			id: 'msg-eng-104',
			conversationId: DEMO_CONVO_IDS.eng,
			senderDid: 'did:plc:alice0001',
			senderHandle: 'alice.bsky.social',
			content: 'Huge win. I also cleaned up the service worker so OAuth callbacks bypass Cache Storage.',
			timestamp: y1430,
			sequenceNumber: 13,
			status: 'read',
			isOwn: true,
			messageType: 'text',
			reactions: {
				'👍': ['did:plc:maya0002', 'did:plc:soren0006']
			}
		},
		{
			id: 'msg-eng-201',
			conversationId: DEMO_CONVO_IDS.eng,
			senderDid: 'did:plc:alice0001',
			senderHandle: 'alice.bsky.social',
			content: 'Morning everyone. Ready for the pre-release sweep?',
			timestamp: t0905,
			sequenceNumber: 14,
			status: 'read',
			isOwn: true,
			messageType: 'text'
		},
		{
			id: 'msg-eng-202',
			conversationId: DEMO_CONVO_IDS.eng,
			senderDid: 'did:plc:alice0001',
			senderHandle: 'alice.bsky.social',
			content: 'We have desktop, web, and mobile builds lined up on the same epoch.',
			timestamp: t0906,
			sequenceNumber: 15,
			status: 'delivered',
			isOwn: true,
			messageType: 'text'
		},
		{
			id: 'msg-eng-203',
			conversationId: DEMO_CONVO_IDS.eng,
			senderDid: 'did:plc:marcus0003',
			senderHandle: 'marcus.dev',
			content: JSON.stringify({
				text: 'Confirmed on desktop too. Zero key package drift across three restarts.',
				reply: {
					messageId: 'msg-eng-104',
					senderDid: 'did:plc:alice0001',
					preview: 'Huge win. I also cleaned up the service worker so OAuth callbacks bypass Cache Storage.'
				}
			}),
			timestamp: t0908,
			sequenceNumber: 16,
			status: 'delivered',
			isOwn: false,
			messageType: 'text',
			reactions: {
				'🚀': ['did:plc:alice0001', 'did:plc:maya0002']
			}
		},
		{
			id: 'msg-eng-204',
			conversationId: DEMO_CONVO_IDS.eng,
			senderDid: 'did:plc:soren0006',
			senderHandle: 'soren.security',
			content: '',
			timestamp: t0914,
			sequenceNumber: 17,
			status: 'delivered',
			isOwn: false,
			messageType: 'voice',
			audio: demoVoicePayload,
			audioAttachment: demoVoicePayload
		},
		{
			id: 'msg-eng-205',
			conversationId: DEMO_CONVO_IDS.eng,
			senderDid: 'did:plc:maya0002',
			senderHandle: 'maya.catbird.blue',
			content: 'Updated the epoch diagram for the web worker handoff.',
			timestamp: t0916,
			sequenceNumber: 18,
			status: 'delivered',
			isOwn: false,
			messageType: 'image',
			image: {
				blobId: 'demo-img-pipeline',
				keyB64: 'ZGVtbw==',
				ivB64: 'ZGVtbw==',
				sha256: 'demo-img-sha256',
				contentType: 'image/svg+xml',
				size: DEMO_DIAGRAM_IMAGE_URL.length,
				width: 640,
				height: 360,
				altText:
					'Diagram showing Client Device using OpenMLS and OPFS syncing through Sequencer to verified Peers on epoch 42.',
				localUrl: DEMO_DIAGRAM_IMAGE_URL
			}
		},
		{
			id: 'msg-eng-205b',
			conversationId: DEMO_CONVO_IDS.eng,
			senderDid: 'did:plc:marcus0003',
			senderHandle: 'marcus.dev',
			content: 'Published the updated protocol checklist for all three clients.',
			timestamp: t0918,
			sequenceNumber: 19,
			status: 'delivered',
			isOwn: false,
			messageType: 'text',
			embed: {
				type: 'link',
				data: {
					url: 'https://catbird.blue/docs/mls-protocol',
					title: 'Catbird MLS Client Protocol Specification',
					description:
						'End-to-end encrypted group messaging with OpenMLS, Labyrinth history sync, and ATProto Spaces.',
					domain: 'catbird.blue'
				}
			}
		},
		{
			id: 'msg-eng-206',
			conversationId: DEMO_CONVO_IDS.eng,
			senderDid: 'did:plc:devon0005',
			senderHandle: 'devon.studio',
			content: 'Everything in that flow matches the mobile inspector spec. Ready to sign off.',
			timestamp: t0919,
			sequenceNumber: 20,
			status: 'delivered',
			isOwn: false,
			messageType: 'text'
		}
	];

	// Optimistic failed message kept separate from worker storage so reconcileMessages never duplicates it
	const failedMessagesByConvo = new Map<string, Message[]>([
		[
			DEMO_CONVO_IDS.eng,
			[
				{
					id: 'temp-failed-demo-1',
					conversationId: DEMO_CONVO_IDS.eng,
					senderDid: DEMO_CURRENT_USER.did,
					senderHandle: DEMO_CURRENT_USER.handle,
					content: 'Uploading the final smoke-test checklist now.',
					timestamp: t0920,
					status: 'failed',
					isOwn: true,
					messageType: 'text'
				}
			]
		]
	]);

	const mayaMessages: Message[] = [
		{
			id: 'msg-maya-1',
			conversationId: DEMO_CONVO_IDS.maya,
			senderDid: 'did:plc:alice0001',
			senderHandle: 'alice.bsky.social',
			content: 'Have you had a chance to look at the updated Catmos theme tokens?',
			timestamp: makeDayTimestamp(0, 9, 4),
			sequenceNumber: 1,
			status: 'read',
			isOwn: true,
			messageType: 'text'
		},
		{
			id: 'msg-maya-2',
			conversationId: DEMO_CONVO_IDS.maya,
			senderDid: 'did:plc:maya0002',
			senderHandle: 'maya.catbird.blue',
			content: 'Looks super crisp on Dim and True Black.',
			timestamp: t0912,
			sequenceNumber: 2,
			status: 'delivered',
			isOwn: false,
			messageType: 'text',
			embed: {
				type: 'post',
				data: {
					uri: 'at://did:plc:maya0002/app.bsky.feed.post/3kdemo001'
				}
			},
			reactions: {
				'✨': ['did:plc:alice0001']
			}
		}
	];

	const designMessages: Message[] = [
		{
			id: 'msg-design-1',
			conversationId: DEMO_CONVO_IDS.design,
			senderDid: 'did:plc:priya0004',
			senderHandle: 'priya.bsky.social',
			content: 'All seven accent palettes clear WCAG AA contrast now.',
			timestamp: t0840,
			sequenceNumber: 1,
			status: 'read',
			isOwn: false,
			messageType: 'text'
		}
	];

	const marcusMessages: Message[] = [
		{
			id: 'msg-marcus-1',
			conversationId: DEMO_CONVO_IDS.marcus,
			senderDid: 'did:plc:marcus0003',
			senderHandle: 'marcus.dev',
			content: 'I will merge the SQLCipher checkpoint patch tonight.',
			timestamp: t0815,
			sequenceNumber: 1,
			status: 'read',
			isOwn: false,
			messageType: 'text'
		}
	];

	const releasesMessages: Message[] = [
		{
			id: 'msg-rel-1',
			conversationId: DEMO_CONVO_IDS.releases,
			senderDid: 'did:plc:soren0006',
			senderHandle: 'soren.security',
			content: 'Catmos desktop 0.9.4 notarized and signed.',
			timestamp: d2,
			sequenceNumber: 1,
			status: 'read',
			isOwn: false,
			messageType: 'text'
		}
	];

	const priyaMessages: Message[] = [
		{
			id: 'msg-priya-1',
			conversationId: DEMO_CONVO_IDS.priya,
			senderDid: 'did:plc:priya0004',
			senderHandle: 'priya.bsky.social',
			content: 'Thanks for walking through the accessibility checklist.',
			timestamp: d4,
			sequenceNumber: 1,
			status: 'read',
			isOwn: false,
			messageType: 'text'
		}
	];

	const messagesByConvo = new Map<string, Message[]>([
		[DEMO_CONVO_IDS.eng, engMessages],
		[DEMO_CONVO_IDS.maya, mayaMessages],
		[DEMO_CONVO_IDS.design, designMessages],
		[DEMO_CONVO_IDS.marcus, marcusMessages],
		[DEMO_CONVO_IDS.releases, releasesMessages],
		[DEMO_CONVO_IDS.priya, priyaMessages]
	]);

	const olderMessagesByConvo = new Map<string, Message[]>([[DEMO_CONVO_IDS.eng, engOlder]]);

	const toMembers = (convo: Conversation): GroupMember[] => {
		const admins = new Set(DEMO_ADMIN_DIDS[convo.id] ?? []);
		return convo.members.map((did) => {
			const profile = profilesMap.get(did);
			return {
				did,
				handle: profile?.handle ?? did,
				displayName: profile?.displayName,
				role: admins.has(did) ? 'admin' : 'member'
			};
		});
	};

	const membersByConvo = new Map<string, GroupMember[]>();
	const metadataByConvo = new Map<string, GroupMetadataView>();
	for (const convo of conversations) {
		membersByConvo.set(convo.id, toMembers(convo));
		if (convo.isGroup) {
			metadataByConvo.set(convo.id, {
				name: convo.displayName,
				description: convo.description
			});
		}
	}

	const quarantineByConvo = new Map<string, QuarantineState>();
	if (options?.quarantineEng) {
		quarantineByConvo.set(DEMO_CONVO_IDS.eng, {
			...DEMO_QUARANTINE_STATE,
			sinceMs: Date.now() - 18 * 60 * 1000
		});
	}

	return {
		user: { ...DEMO_CURRENT_USER },
		profiles: profilesMap,
		conversations,
		messagesByConvo,
		failedMessagesByConvo,
		olderMessagesByConvo,
		membersByConvo,
		metadataByConvo,
		quarantineByConvo,
		blobs,
		imageUrls
	};
}

// ---------------------------------------------------------------------------
// Interactive in-memory WorkerApi factory for `__setWorkerFactoryForTests`
// ---------------------------------------------------------------------------

function extractPlainText(raw: string): string {
	if (!raw) return '';
	const trimmed = raw.trim();
	if (trimmed.startsWith('{')) {
		try {
			const parsed = JSON.parse(trimmed) as { text?: unknown };
			if (typeof parsed.text === 'string') return parsed.text;
		} catch {
			// Plain text
		}
	}
	return trimmed;
}

export interface DemoWorkerOptions {
	connectionMode?: 'connected' | 'reconnecting' | 'offline' | 'reauth';
}

export function createDemoWorkerFactory(
	dataset: DemoFixtureDataset,
	options: DemoWorkerOptions = {}
): () => { worker: Remote<WorkerApi>; rawWorker: { terminate(): void } } {
	let nextSeq = 100;
	let nextId = 1;
	const olderLoaded = new Set<string>();
	const readStates = new Map<string, { conversation_id: string; last_read_seq: number }>();

	const nextMessageId = (prefix = 'demo-msg') => `${prefix}-${Date.now()}-${nextId++}`;

	const appendStoredMessage = (convoId: string, msg: Message) => {
		const list = dataset.messagesByConvo.get(convoId) ?? [];
		dataset.messagesByConvo.set(convoId, [...list, msg]);
		const convo = dataset.conversations.find((c) => c.id === convoId);
		if (convo) {
			convo.lastMessage =
				extractPlainText(msg.content) ||
				(msg.messageType === 'image'
					? 'Photo'
					: msg.messageType === 'voice'
						? 'Voice message'
						: convo.lastMessage);
			convo.lastMessageAt = msg.timestamp;
		}
	};

	const buildLabyrinthStatus = (): LabyrinthBackupStatusView => ({
		backup_enabled: true,
		mailbox_space_uri: `at:space://${dataset.user.did}/blue.catbird.labyrinth.mailbox/self`,
		has_recovery_code: true,
		has_passkey_prf: false,
		epoch_seq: 42,
		active_device_ids: [DEMO_DEVICE_ID, DEMO_SIBLING_DEVICE_ID],
		pending_device_ids: [],
		current_device_id: DEMO_DEVICE_ID,
		devices: [
			{
				device_id: DEMO_DEVICE_ID,
				device_name: 'Catmos Web (This browser)',
				status: 'active',
				is_current: true,
				last_active_at: new Date().toISOString()
			},
			{
				device_id: DEMO_SIBLING_DEVICE_ID,
				device_name: 'Catbird on iPhone',
				status: 'active',
				is_current: false,
				last_active_at: new Date(Date.now() - 12 * 60 * 1000).toISOString()
			}
		],
		backfill: {
			state: 'complete',
			synced_batches: 12,
			total_batches: 12,
			last_synced_at: new Date().toISOString()
		}
	});

	const demoWorker = {
		oauthStartLogin: async (identifier: string) =>
			`https://bsky.social/oauth/authorize?login_hint=${encodeURIComponent(identifier)}`,
		oauthCompleteLogin: async () => ({
			did: dataset.user.did,
			handle: dataset.user.handle,
			pds: 'https://bsky.social',
			grantedScopes: dataset.user.grantedScopes ?? []
		}),
		oauthRestoreSession: async () => ({
			did: dataset.user.did,
			handle: dataset.user.handle,
			pds: 'https://bsky.social',
			grantedScopes: dataset.user.grantedScopes ?? []
		}),
		oauthLogout: async () => {},
		oauthServiceToken: async () => 'demo-service-auth-jwt',
		oauthPdsExchange: async (_did: string, _method: string, path: string) => {
			let payload: unknown = {};
			if (path.includes('com.atproto.repo.listRecords')) {
				payload = { records: [] };
			} else if (path.includes('com.atproto.repo.createRecord')) {
				payload = { uri: `at://${dataset.user.did}/app.bsky.graph.block/demo` };
			}
			return {
				status: 200,
				contentType: 'application/json',
				headers: [['content-type', 'application/json']],
				body: new TextEncoder().encode(JSON.stringify(payload))
			};
		},
		runDeferredRecovery: async () => 0,
		startBackgroundTasks: async () => {},
		stopBackgroundTasks: async () => {},
		init: async () => {},
		setAuth: () => {},
		clearAuth: () => {},
		setSignerBridge: async () => {},
		hasSignerBridge: () => true,
		prepareUnsignedRequest: (operation: string) => ({
			operation,
			method: 'POST',
			path: `/xrpc/blue.catbird.chat.${operation}`,
			body: '{}'
		}),
		prepareSignedRequest: async (operation: string, requestJson: string) => ({
			operation,
			method: 'POST',
			path: `/xrpc/blue.catbird.chat.${operation}`,
			body: requestJson
		}),
		setContentRootKey: async () => {},
		clearContentRootKey: async () => {},
		setup: async () => {},
		replenishKeyPackages: async () => {},
		ping: () => 'pong',

		openUnifiedClient: async (params: { accountDid: string }) => ({
			accountDid: params.accountDid,
			accountDidHash: 'demo-did-hash'
		}),
		closeUnifiedClient: async () => {},
		currentDeviceId: async () => DEMO_DEVICE_ID,
		syncUnified: async () => 0,
		evaluateSpacesEligibility: async () => ({ eligible: true, missing_scopes: [] }),
		enrollUnifiedDevice: async () => buildLabyrinthStatus(),
		labyrinthStatus: async () => buildLabyrinthStatus(),
		enableLabyrinthLive: async () => buildLabyrinthStatus(),
		isDevicePendingApproval: async () => false,
		isDeviceRecordPending: async () => false,
		setupRecoveryCode: async () => 'DEMO-ABCD-EFGH-JKLM-NPQR-STUV-WXYZ-1234',
		restoreWithRecoveryCode: async () => buildLabyrinthStatus(),
		registerPasskeyPrf: async () => buildLabyrinthStatus(),
		restoreWithPasskeyPrf: async () => buildLabyrinthStatus(),
		approveSiblingDevice: async () => buildLabyrinthStatus(),
		listRegisteredDevices: async () => buildLabyrinthStatus().devices ?? [],
		revokeRegisteredDevice: async (targetDeviceId: string) => ({
			target_device_id: targetDeviceId,
			ds_revoked: true,
			labyrinth_rotated: true,
			new_epoch_seq: 43
		}),
		revokeLabyrinthDevice: async () => ({
			status: buildLabyrinthStatus(),
			rekeyed_recovery_code: null,
			rekeyed_passkey_ids: []
		}),
		retireCurrentDevice: async () => true,
		deleteAccountData: async () => true,
		initiateOtcPairing: async () => ({ six_digit_code: '654321', formatted_code: '654-321' }),
		startLiveOtcPairing: async (sixDigitCode: string) => ({
			session_id_hex: 'aa'.repeat(16),
			formatted_code: `${sixDigitCode.slice(0, 3)}-${sixDigitCode.slice(3, 6)}`,
			six_digit_code: sixDigitCode
		}),
		respondLiveOtcPairing: async () => {},
		completeLiveOtcPairing: async () => ({
			session_id: Array.from({ length: 16 }, () => 0xaa),
			initiator_mlkem768_ek_len: 1184,
			responder_mlkem768_ct_len: 1088,
			new_epoch_seq: 43
		}),
		completeOtcPairing: async () => ({
			session_id: Array.from({ length: 16 }, () => 0xaa),
			initiator_mlkem768_ek_len: 1184,
			responder_mlkem768_ct_len: 1088,
			new_epoch_seq: 43
		}),
		verifyAndReindexHistory: async () => 12,
		getReadState: async (convoId: string) => readStates.get(convoId) ?? null,
		advanceReadState: async (convoId: string, candidateSeq: number) => {
			const prev = readStates.get(convoId)?.last_read_seq ?? 0;
			const next = { conversation_id: convoId, last_read_seq: Math.max(prev, candidateSeq) };
			readStates.set(convoId, next);
			return next;
		},
		listReadStates: async () => Array.from(readStates.values()),
		getCircleOwnerState: async () => null,
		putCircleOwnerState: async () => 'bafyreidemocircle',
		mergeCircleOwnerState: async (update: { circle_id: string; name?: string | null }) => ({
			circle_id: update.circle_id,
			name: update.name ?? 'Circle',
			member_dids: [],
			acl_tombstone_dids: [],
			updated_at: new Date().toISOString()
		}),
		clearCircleAclTombstone: async (circleId: string) => ({
			circle_id: circleId,
			name: 'Circle',
			member_dids: [],
			acl_tombstone_dids: [],
			updated_at: new Date().toISOString()
		}),
		listCircleOwnerStates: async () => [],
		listDirectRequests: async () => [],
		acceptDirectRequest: async () => {},
		declineDirectRequest: async () => {},

		// Conversations
		listConversations: async () => dataset.conversations.map((c) => ({ ...c })),

		createConversation: async (name: string, memberDids: string[], description?: string) => {
			const uniqueMembers = Array.from(
				new Set([dataset.user.did, ...memberDids.map((d) => stripDidFragment(d)).filter(Boolean)])
			);
			const isGroup = uniqueMembers.length > 2 || Boolean(name.trim());
			const id = `convo-demo-${nextId++}`;
			const peerDid = uniqueMembers.find((d) => !isSameAccountDid(d, dataset.user.did));
			const peerProfile = peerDid ? dataset.profiles.get(peerDid) : undefined;
			const displayName =
				name.trim() || peerProfile?.displayName || peerProfile?.handle || 'New conversation';

			const created: Conversation = {
				id,
				groupId: `demo-group-${nextId}`,
				displayName,
				description: description?.trim() || undefined,
				members: uniqueMembers,
				lastMessage: undefined,
				lastMessageAt: new Date().toISOString(),
				unreadCount: 0,
				isGroup
			};

			dataset.conversations = [created, ...dataset.conversations];
			dataset.messagesByConvo.set(id, []);
			dataset.membersByConvo.set(
				id,
				uniqueMembers.map((did) => {
					const p = dataset.profiles.get(did);
					return {
						did,
						handle: p?.handle ?? did,
						displayName: p?.displayName,
						role: isSameAccountDid(did, dataset.user.did) ? 'admin' : 'member'
					};
				})
			);
			if (isGroup) {
				dataset.metadataByConvo.set(id, {
					name: created.displayName,
					description: created.description
				});
			}
			return { ...created };
		},

		joinGroup: async (convoId: string) => {
			const found = dataset.conversations.find((c) => c.id === convoId);
			if (!found) throw new Error(`Conversation ${convoId} not found`);
			return { ...found };
		},

		leaveConversation: async (conversationId: string) => {
			dataset.conversations = dataset.conversations.filter((c) => c.id !== conversationId);
			dataset.messagesByConvo.delete(conversationId);
			dataset.failedMessagesByConvo.delete(conversationId);
			dataset.membersByConvo.delete(conversationId);
			dataset.quarantineByConvo.delete(conversationId);
		},

		subscribe: async (
			_convoId: string,
			_onMessage: (data: unknown) => void,
			_onEvent: (data: unknown) => void,
			onStatus: (status: unknown) => void
		) => {
			if (options.connectionMode === 'reconnecting') {
				throw new Error('Reconnecting to encrypted sync...');
			}
			if (options.connectionMode === 'reauth') {
				throw new Error(
					'catmos-recovery:reauthenticate:Your Bluesky session expired. Sign in again to resume encrypted sync.'
				);
			}
			if (options.connectionMode === 'offline') {
				return;
			}
			onStatus?.({ type: 'connected' });
		},

		unsubscribe: () => {},

		// Messages
		getMessages: async (conversationId: string, before?: string) => {
			if (before) {
				if (olderLoaded.has(conversationId)) return [];
				olderLoaded.add(conversationId);
				return (dataset.olderMessagesByConvo.get(conversationId) ?? []).map((m) => ({ ...m }));
			}
			return (dataset.messagesByConvo.get(conversationId) ?? []).map((m) => ({ ...m }));
		},

		fetchNewMessages: async (conversationId: string) =>
			(dataset.messagesByConvo.get(conversationId) ?? []).map((m) => ({ ...m })),

		sendMessage: async (conversationId: string, content: string) => {
			const msg: Message = {
				id: nextMessageId('msg'),
				conversationId,
				senderDid: dataset.user.did,
				senderHandle: dataset.user.handle,
				content,
				timestamp: new Date().toISOString(),
				sequenceNumber: ++nextSeq,
				status: 'sent',
				isOwn: true,
				messageType: 'text'
			};
			appendStoredMessage(conversationId, msg);
			return { ...msg };
		},

		sendImage: async (
			conversationId: string,
			content: string,
			data: Uint8Array,
			contentType: string,
			width: number,
			height: number,
			altText?: string
		) => {
			const blobId = nextMessageId('img-blob');
			const blob = new Blob([data as BlobPart], { type: contentType });
			const localUrl =
				typeof URL !== 'undefined' && typeof URL.createObjectURL === 'function'
					? URL.createObjectURL(blob)
					: DEMO_DIAGRAM_IMAGE_URL;
			dataset.imageUrls.set(blobId, localUrl);

			const msg: Message = {
				id: nextMessageId('msg-img'),
				conversationId,
				senderDid: dataset.user.did,
				senderHandle: dataset.user.handle,
				content,
				timestamp: new Date().toISOString(),
				sequenceNumber: ++nextSeq,
				status: 'sent',
				isOwn: true,
				messageType: 'image',
				image: {
					blobId,
					keyB64: 'ZGVtbw==',
					ivB64: 'ZGVtbw==',
					sha256: blobId,
					contentType,
					size: data.byteLength,
					width,
					height,
					altText,
					localUrl
				}
			};
			appendStoredMessage(conversationId, msg);
			return { ...msg };
		},

		getImageAttachment: async (blobId: string) =>
			dataset.imageUrls.get(blobId) ?? DEMO_DIAGRAM_IMAGE_URL,

		sendVoice: async (
			conversationId: string,
			audioData: Uint8Array,
			contentType: string,
			durationMs: number,
			waveform: number[],
			transcript?: string
		) => {
			const blobId = `demo:${nextMessageId('voice-blob')}`;
			dataset.blobs.set(blobId, audioData);
			const audio = {
				blobId,
				key: new Uint8Array(32).fill(0x11),
				iv: new Uint8Array(12).fill(0x22),
				keyB64: 'ERERERERERERERERERERERERERERERERERERERERERE=',
				ivB64: 'IiIiIiIiIiIiIiIi',
				sha256: '33'.repeat(32),
				contentType,
				size: audioData.byteLength,
				durationMs,
				waveform,
				transcript
			};
			const msg: Message = {
				id: nextMessageId('msg-voice'),
				conversationId,
				senderDid: dataset.user.did,
				senderHandle: dataset.user.handle,
				content: '',
				timestamp: new Date().toISOString(),
				sequenceNumber: ++nextSeq,
				status: 'sent',
				isOwn: true,
				messageType: 'voice',
				audio,
				audioAttachment: audio
			};
			appendStoredMessage(conversationId, msg);
			return { ...msg };
		},

		fetchAndDecryptBlob: async (blobId: string) => {
			const bytes = dataset.blobs.get(blobId);
			if (!bytes) {
				return synthesizeDemoWavBytes(1800, 8000);
			}
			return bytes;
		},

		prepareVoice: async () => ({}),
		decodeOpus: async (opusData: Uint8Array) => opusData,

		sendReaction: async (
			conversationId: string,
			messageId: string,
			emoji: string,
			action: string
		) => {
			const list = dataset.messagesByConvo.get(conversationId) ?? [];
			const normalizedAction: 'add' | 'remove' = action === 'remove' ? 'remove' : 'add';
			for (const msg of list) {
				if (msg.id !== messageId) continue;
				msg.reactions = applyReactionToMap(msg.reactions, dataset.user.did, emoji, normalizedAction);
			}
		},

		sendTyping: async () => {},
		updateCursor: async () => {},

		// Members
		getMembers: async (conversationId: string) =>
			(dataset.membersByConvo.get(conversationId) ?? []).map((m) => ({ ...m })),

		addParticipants: async (conversationId: string, did: string) => {
			await demoWorker.addGroupMembers(conversationId, [did]);
		},

		addGroupMembers: async (conversationId: string, memberDids: string[]) => {
			const existing = dataset.membersByConvo.get(conversationId) ?? [];
			const existingDids = new Set(existing.map((m) => stripDidFragment(m.did)));
			for (const rawDid of memberDids) {
				const did = stripDidFragment(rawDid);
				if (!did || existingDids.has(did)) continue;
				existingDids.add(did);
				const p = dataset.profiles.get(did);
				existing.push({
					did,
					handle: p?.handle ?? did,
					displayName: p?.displayName,
					role: 'member'
				});
			}
			dataset.membersByConvo.set(conversationId, existing);
			const convo = dataset.conversations.find((c) => c.id === conversationId);
			if (convo) {
				convo.members = existing.map((m) => m.did);
			}
		},

		promoteMember: async (conversationId: string, targetDid: string) => {
			const list = dataset.membersByConvo.get(conversationId) ?? [];
			dataset.membersByConvo.set(
				conversationId,
				list.map((m) => (isSameAccountDid(m.did, targetDid) ? { ...m, role: 'admin' } : m))
			);
		},

		demoteMember: async (conversationId: string, targetDid: string) => {
			const list = dataset.membersByConvo.get(conversationId) ?? [];
			dataset.membersByConvo.set(
				conversationId,
				list.map((m) => (isSameAccountDid(m.did, targetDid) ? { ...m, role: 'member' } : m))
			);
		},

		removeParticipants: async (conversationId: string, targetDid: string) => {
			const list = (dataset.membersByConvo.get(conversationId) ?? []).filter(
				(m) => !isSameAccountDid(m.did, targetDid)
			);
			dataset.membersByConvo.set(conversationId, list);
			const convo = dataset.conversations.find((c) => c.id === conversationId);
			if (convo) {
				convo.members = list.map((m) => m.did);
			}
		},

		// Profiles & search
		getProfiles: async (dids: string[]) =>
			dids
				.map((did) => dataset.profiles.get(stripDidFragment(did)))
				.filter((p): p is ProfileView => Boolean(p))
				.map((p) => ({ ...p })),

		searchUsers: async (query: string): Promise<SearchResult[]> => {
			const q = query.trim().toLowerCase();
			if (!q) return [];
			return Array.from(dataset.profiles.values())
				.filter(
					(p) =>
						!isSameAccountDid(p.did, dataset.user.did) &&
						(p.handle.toLowerCase().includes(q) ||
							(p.displayName ?? '').toLowerCase().includes(q) ||
							p.did.toLowerCase().includes(q))
				)
				.map((p) => ({ ...p }));
		},

		checkOptInStatus: async (dids: string[]): Promise<OptInStatus[]> =>
			dids.map((did) => {
				const bare = stripDidFragment(did);
				return {
					did: bare || did,
					optedIn: DEMO_OPT_IN_MAP[bare] ?? true
				};
			}),

		// Group metadata
		getGroupMetadata: async (conversationId: string) => {
			const meta = dataset.metadataByConvo.get(conversationId);
			if (!meta) return null;
			return {
				title: meta.name ?? '',
				description: meta.description ?? ''
			};
		},

		updateGroupMetadata: async (
			conversationId: string,
			title: string | null,
			description: string | null
		) => {
			const existing = dataset.metadataByConvo.get(conversationId) ?? {};
			const updated: GroupMetadataView = {
				...existing,
				name: title !== null ? title : existing.name,
				description: description !== null ? description : existing.description
			};
			dataset.metadataByConvo.set(conversationId, updated);
			const convo = dataset.conversations.find((c) => c.id === conversationId);
			if (convo) {
				if (title !== null && title.trim()) convo.displayName = title.trim();
				if (description !== null) convo.description = description.trim() || undefined;
			}
			return { title: updated.name ?? '', description: updated.description ?? '' };
		},

		bootstrapGroupMetadata: async () => null,
		republishMetadataAfterReset: async () => null
	};

	return () => ({
		worker: demoWorker as unknown as Remote<WorkerApi>,
		rawWorker: { terminate() {} }
	});
}

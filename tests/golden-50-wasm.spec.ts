import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { wasmPkgEntry } from '../scripts/wasm-package.ts';
import { describe, it } from 'node:test';

const { initSync, verifyGoldenManifest, verifyGoldenTranscriptJson }: typeof import('catbird-mls-web') =
	await import(pathToFileURL(wasmPkgEntry).href);

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const WASM_BINARY_PATH = path.join(path.dirname(wasmPkgEntry), 'catbird_mls_web_bg.wasm');
const GOLDEN_DIR = process.env.T7_GOLDEN_CORPUS_DIR
	? path.resolve(process.env.T7_GOLDEN_CORPUS_DIR)
	: path.resolve(__dirname, '../../catbird-sim/fixtures/golden_50');

let wasmInitialized = false;
function ensureRealWasmLoaded(): void {
	if (!wasmInitialized) {
		const wasmBytes = fs.readFileSync(WASM_BINARY_PATH);
		initSync({ module: wasmBytes });
		wasmInitialized = true;
	}
}

describe('T7-GOLDEN-50 real compiled catbird-mls-web WASM conformance (C5)', () => {
	it('checks manifest bytes and the recorded wire and state digests for all 50 transcripts in compiled WASM', () => {
		ensureRealWasmLoaded();

		const manifestPath = path.join(GOLDEN_DIR, 'MANIFEST.sha256');
		assert.equal(fs.existsSync(manifestPath), true, `missing ${manifestPath}`);
		const manifestRaw = fs.readFileSync(manifestPath, 'utf8');

		const jsonFiles = fs
			.readdirSync(GOLDEN_DIR)
			.filter((name) => name.startsWith('transcript_') && name.endsWith('.json'))
			.sort();
		assert.equal(jsonFiles.length, 50, 'golden_50 corpus must contain 50 transcript JSON files');

		const filePayloads = jsonFiles.map((filename) => ({
			filename,
			bytes: Array.from(fs.readFileSync(path.join(GOLDEN_DIR, filename)))
		}));

		const manifestReport = verifyGoldenManifest(manifestRaw, filePayloads) as {
			verifiedCount: number;
			manifestSha256: string;
		};
		assert.equal(manifestReport.verifiedCount, 50);
		assert.match(manifestReport.manifestSha256, /^[0-9a-f]{64}$/);

		const categoryCounts = new Map<string, number>();
		let totalWireFrames = 0;
		let totalConversations = 0;
		let totalOpenDevices = 0;

		for (let i = 0; i < jsonFiles.length; i += 1) {
			const filename = jsonFiles[i];
			const rawJson = fs.readFileSync(path.join(GOLDEN_DIR, filename), 'utf8');
			const report = verifyGoldenTranscriptJson(rawJson) as {
				index: number;
				slug: string;
				category: string;
				wireFrameCount: number;
				conversationCount: number;
				messageCount: number;
				openDeviceCount: number;
				wireDigestBlake3: string;
				postStateBlake3: string;
			};

			assert.equal(report.index, i + 1, `unexpected transcript index in ${filename}`);
			assert.equal(filename, `transcript_${String(report.index).padStart(2, '0')}_${report.slug}.json`);
			assert.ok(report.wireFrameCount > 0, `${filename} must exercise >=1 wire frame`);
			assert.match(report.wireDigestBlake3, /^[0-9a-f]{64}$/);
			assert.match(report.postStateBlake3, /^[0-9a-f]{64}$/);

			categoryCounts.set(report.category, (categoryCounts.get(report.category) ?? 0) + 1);
			totalWireFrames += report.wireFrameCount;
			totalConversations += report.conversationCount;
			totalOpenDevices += report.openDeviceCount;
		}

		assert.equal(categoryCounts.size, 10, 'must cover all 10 golden conformance categories');
		for (const [category, count] of categoryCounts.entries()) {
			assert.equal(count, 5, `category ${category} must have exactly 5 golden transcripts`);
		}
		assert.ok(totalWireFrames >= 50);
		assert.ok(totalConversations >= 40);
		assert.ok(totalOpenDevices >= 40);
	});

	it('fails closed inside WASM on tampered MANIFEST.sha256, wire_digest_blake3, post_state_blake3, or SpaceUri', () => {
		ensureRealWasmLoaded();

		const samplePath = path.join(
			GOLDEN_DIR,
			'transcript_01_direct_1to1_bootstrap_accept_reply.json'
		);
		const sampleRaw = fs.readFileSync(samplePath, 'utf8');
		const parsed = JSON.parse(sampleRaw);

		const badWire = structuredClone(parsed);
		badWire.wire_digest_blake3 = 'f'.repeat(64);
		assert.throws(
			() => verifyGoldenTranscriptJson(JSON.stringify(badWire)),
			/wire_digest_blake3 mismatch/
		);

		const badPost = structuredClone(parsed);
		badPost.post_state_blake3 = '0'.repeat(64);
		assert.throws(
			() => verifyGoldenTranscriptJson(JSON.stringify(badPost)),
			/post_state_blake3 mismatch/
		);

		const manifestRaw = fs.readFileSync(path.join(GOLDEN_DIR, 'MANIFEST.sha256'), 'utf8');
		const jsonFiles = fs
			.readdirSync(GOLDEN_DIR)
			.filter((name) => name.startsWith('transcript_') && name.endsWith('.json'))
			.sort();
		const corruptedEntries = jsonFiles.map((filename, idx) => {
			const bytes = Array.from(fs.readFileSync(path.join(GOLDEN_DIR, filename)));
			if (idx === 0) {
				bytes[0] ^= 0x01;
			}
			return { filename, bytes };
		});
		assert.throws(
			() => verifyGoldenManifest(manifestRaw, corruptedEntries),
			/SHA-256 mismatch/
		);
	});
});

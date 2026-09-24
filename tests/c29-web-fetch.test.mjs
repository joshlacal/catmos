// C29 Catmos Web: the real requests store + real $lib/wasm in browser mode
// (no Tauri). Every remote path in this mode is fetch or the MLS Worker, so
// both constructors are the transport boundary and are counted.
// Run: bun test tests/c29-web-fetch.test.mjs  OR  node --test tests/c29-web-fetch.test.mjs
import assert from 'node:assert/strict';
import test from 'node:test';
import { get } from 'svelte/store';

let fetches = 0, workers = 0;
Object.assign(globalThis, {
  window: globalThis,
  location: new URL('http://127.0.0.1:1420'),
  fetch: async () => { fetches++; throw new Error('draft-only entrypoints must not fetch'); },
  Worker: class { constructor() { workers++; throw new Error('draft-only entrypoints must not start the MLS Worker'); } },
});
// Dynamic imports are required: $lib/wasm evaluates `isTauri` at module load.
const api = await import('../src/lib/wasm.ts');
const { requests } = await import('../src/lib/stores/requests.ts');
const pending = {
  conversationId: 'pending', firstMessageId: 'first', consent: 'incomingPending', crypto: 'ready',
  preview: { type: 'ready', text: 'hi' }, generation: 0, stateVersion: 1,
  capabilities: { canPreview: true, canAccept: true, canClose: true, canSend: false, canEmitReceipts: false, canAdminister: false },
};

test('browser contact select, composer, draft, attachment-first and cancel make zero remote calls', async () => {
  assert.equal(api.isTauri, false);
  requests.bindAccount('did:plc:alice', 'browser:0');
  requests.begin('did:plc:bob', 'Bob');
  const id = get(requests).selectedId;
  await requests.saveText(id, 'Browser draft text');
  assert.equal(get(requests).drafts[0].input.text, 'Browser draft text');
  requests.applyView('did:plc:alice', pending);
  assert.equal(requests.canUseOrdinaryActivity('pending'), false);
  await requests.cancel(id);
  assert.equal(get(requests).drafts[0].archived, true);
  assert.equal(fetches, 0);
  assert.equal(workers, 0);
});

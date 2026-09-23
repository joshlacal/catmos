// C29 Catmos Web: the real requests store + real $lib/wasm in browser mode
// (no Tauri). Every remote path in this mode is fetch or the MLS Worker, so
// both constructors are the transport boundary and are counted.
// Run: bun test tests/c29-web-fetch.test.ts
import { expect, test } from 'bun:test';
import { get } from 'svelte/store';
import type { DirectRequestView } from '../src/lib/request-types';

let fetches = 0, workers = 0;
Object.assign(globalThis, {
  window: globalThis,
  location: new URL('http://127.0.0.1:1420'),
  fetch: async () => { fetches++; throw new Error('draft-only entrypoints must not fetch'); },
  Worker: class { constructor() { workers++; throw new Error('draft-only entrypoints must not start the MLS Worker'); } },
});
// Dynamic imports are required: $lib/wasm evaluates `isTauri` at module load.
const api = await import('../src/lib/wasm');
const { requests } = await import('../src/lib/stores/requests');
const pending: DirectRequestView = {
  conversationId: 'pending', firstMessageId: 'first', consent: 'incomingPending', crypto: 'ready',
  preview: { type: 'ready', text: 'hi' }, generation: 0, stateVersion: 1,
  capabilities: { canPreview: true, canAccept: true, canClose: true, canSend: false, canEmitReceipts: false, canAdminister: false },
};

test('browser contact select, composer, draft, attachment-first and cancel make zero remote calls', async () => {
  expect(api.isTauri).toBe(false);
  requests.bindAccount('did:plc:alice', 'browser:0');
  requests.begin('did:plc:bob', 'Bob');
  const id = get(requests).selectedId!;
  await requests.saveText(id, 'Browser draft text');
  expect(get(requests).drafts[0].input.text).toBe('Browser draft text');
  requests.applyView('did:plc:alice', pending);
  expect(requests.canUseOrdinaryActivity('pending')).toBe(false);
  await requests.cancel(id);
  expect(get(requests).drafts[0].archived).toBe(true);
  expect(fetches).toBe(0);
  expect(workers).toBe(0);
});

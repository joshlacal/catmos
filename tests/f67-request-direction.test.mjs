// F67: a request the viewer received must stay labelled incoming after it is declined (consent=closed).
// Server-renders the real RequestDetail.svelte against a stub requests store.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import vm from 'node:vm';
import { compile } from 'svelte/compiler';
import * as serverInternals from 'svelte/internal/server';
import { render } from 'svelte/server';
import { writable } from 'svelte/store';

const ME = 'did:web:bob.example.test';
const THEM = 'did:web:alice.example.test';

const source = await readFile(new URL('../src/lib/components/RequestDetail.svelte', import.meta.url), 'utf8');
const { js } = compile(source, { generate: 'server', filename: 'RequestDetail.svelte' });

async function renderDetail(ownerDid, view) {
  const requests = writable({ ownerDid, busy: false, notice: null, error: null });
  const store = new vm.SyntheticModule(['requests'], function () { this.setExport('requests', requests); });
  const internals = new vm.SyntheticModule(Object.keys(serverInternals), function () {
    for (const [k, v] of Object.entries(serverInternals)) this.setExport(k, v);
  });
  const component = new vm.SourceTextModule(js.code);
  await component.link(name => {
    if (name === '$lib/stores/requests') return store;
    if (name === 'svelte/internal/server') return internals;
    throw new Error(`unexpected import ${name}`);
  });
  await component.evaluate();
  const props = { view, onOpenConversation() {}, onViewInvitation() {} };
  const { body } = render(component.namespace.default, { props });
  const eyebrow = body.match(/<p class="eyebrow[^"]*">([^<]*)<\/p>/)[1];
  const avatar = body.match(/<span class="avatar[^"]*" aria-hidden="true">([^<]*)<\/span>/)[1];
  return { body, eyebrow, avatar };
}

const base = {
  conversationId: '00000000-0000-4000-8000-000000000001',
  firstMessageId: '00000000-0000-4000-8000-000000000002',
  crypto: 'ready',
  preview: { type: 'ready', text: 'hello' },
  capabilities: { canPreview: true, canAccept: false, canClose: false, canSend: false, canEmitReceipts: false, canAdminister: false },
  stateVersion: 3,
  generation: 1,
};
const intro = senderDid => ({ senderDid, senderDeviceId: '00000000-0000-4000-8000-000000000009', receivedAt: '2026-09-26T00:00:00Z', epoch: 1, sequenceNumber: 1 });

test('F67: a declined incoming request is still labelled as received', async () => {
  const r = await renderDetail(ME, { ...base, consent: 'closed', introduction: intro(THEM) });
  assert.equal(r.eyebrow, 'AN INTRODUCTION TO YOU');
  assert.equal(r.avatar, '↙');
  assert.match(r.body, /This request is closed\./);
  assert.doesNotMatch(r.body, />(Decline|Block sender|Accept conversation)</, 'closed requests offer no consent actions');
});

test('F67: a closed request the viewer sent is labelled as their introduction', async () => {
  const r = await renderDetail(ME, { ...base, consent: 'closed', introduction: intro(ME) });
  assert.equal(r.eyebrow, 'YOUR INTRODUCTION');
  assert.equal(r.avatar, '↗');
});

test('F67: a closed request with no sender metadata claims no direction', async () => {
  const r = await renderDetail(ME, { ...base, consent: 'closed', introduction: null, crypto: 'unavailable', preview: { type: 'unavailable', code: 'DeviceNotAddressed' } });
  assert.equal(r.eyebrow, 'MESSAGE REQUEST');
  assert.equal(r.avatar, '✉');
});

test('F67: pending requests keep their consent-derived labels and actions', async () => {
  const incoming = await renderDetail(ME, { ...base, consent: 'incomingPending', introduction: intro(THEM), capabilities: { ...base.capabilities, canAccept: true, canClose: true } });
  assert.equal(incoming.eyebrow, 'WANTS TO CHAT WITH YOU');
  assert.match(incoming.body, />Decline</);
  const outgoing = await renderDetail(ME, { ...base, consent: 'outgoingPending', introduction: intro(ME) });
  assert.equal(outgoing.eyebrow, 'YOUR INTRODUCTION');
  assert.equal(outgoing.avatar, '↗');
});

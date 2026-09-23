// C29 desktop frontend: the real requests store + real $lib/wasm + real
// @tauri-apps/api/core `invoke`, observed at window.__TAURI_INTERNALS__ (the
// Tauri IPC boundary). fetch and Worker are counted too. The Rust side of these
// commands is covered by src-tauri/src/request_ipc_tests.rs.
// Run: bun test tests/c29-desktop-ipc.test.ts
import { expect, test } from 'bun:test';
import { get } from 'svelte/store';
import type { DirectRequestInput, DirectRequestView, RequestDraft } from '../src/lib/request-types';

type IpcArgs = { ownerDid?: string; ownerRevision?: string; input?: DirectRequestInput; recipientLabel?: string; draftId?: string };
const ipc: { cmd: string; args: IpcArgs }[] = [];
let fetches = 0, workers = 0;
let lastDraft: RequestDraft | null = null;
Object.assign(globalThis, {
  window: globalThis,
  location: new URL('http://127.0.0.1:1420'),
  fetch: async () => { fetches++; throw new Error('network is not part of draft-only entrypoints'); },
  Worker: class { constructor() { workers++; throw new Error('no browser Worker in desktop mode'); } },
  __TAURI_INTERNALS__: {
    transformCallback: () => 0,
    invoke: async (cmd: string, args: IpcArgs) => {
      ipc.push({ cmd, args });
      if (cmd === 'save_request_draft' && args.input) {
        lastDraft = { input: args.input, recipientLabel: args.recipientLabel ?? '', phase: 'draft', outcome: null, archived: false };
        return lastDraft;
      }
      if (cmd === 'cancel_request_draft' && lastDraft) return { ...lastDraft, archived: true };
      throw new Error(`unexpected IPC ${cmd}`);
    },
  },
});
// Dynamic imports are required: $lib/wasm evaluates `isTauri` at module load,
// so the IPC boundary must exist before the modules are evaluated.
const api = await import('../src/lib/wasm');
const { recordNativeAuthority } = await import('../src/lib/native-authority');
const { requests } = await import('../src/lib/stores/requests');
const LOCAL: Record<string, true> = { save_request_draft: true, cancel_request_draft: true };
const settle = async () => { for (let i = 0; i < 20; i++) await Promise.resolve(); };
const pending: DirectRequestView = {
  conversationId: 'pending', firstMessageId: 'first', consent: 'incomingPending', crypto: 'ready',
  preview: { type: 'ready', text: 'hi' }, generation: 0, stateVersion: 1,
  capabilities: { canPreview: true, canAccept: true, canClose: true, canSend: false, canEmitReceipts: false, canAdminister: false },
};

test('contact select, composer, draft, attachment-first and cancel are local-only', async () => {
  expect(api.isTauri).toBe(true);
  recordNativeAuthority({ did: 'did:plc:alice', authRevision: '4' });
  requests.bindAccount('did:plc:alice', '4');

  requests.begin('did:plc:bob', 'Bob');                 // contact selection opens the composer
  await settle();
  const id = get(requests).selectedId!;
  expect(get(requests).pane).toBe('draft');
  await requests.saveText(id, 'A private introduction'); // typing in the composer
  expect(get(requests).drafts[0].input.text).toBe('A private introduction');

  // Attachment-first: a pending request blocks ordinary activity (the media composer).
  requests.applyView('did:plc:alice', pending);
  expect(requests.canUseOrdinaryActivity('pending')).toBe(false);

  await requests.cancel(id);
  expect(get(requests).drafts[0].archived).toBe(true);

  expect(ipc.every(c => LOCAL[c.cmd])).toBe(true);
  expect(ipc.some(c => c.cmd === 'save_request_draft')).toBe(true);
  expect(ipc.every(c => c.args.ownerDid === 'did:plc:alice' && c.args.ownerRevision === '4')).toBe(true);
  expect(fetches).toBe(0);
  expect(workers).toBe(0);
  console.log(JSON.stringify({ ipc: ipc.map(c => c.cmd), fetches, workers }));
});

test('after an account switch the previous draft is not exposed or resumed', async () => {
  const before = ipc.length;
  recordNativeAuthority({ did: 'did:plc:carol', authRevision: '5' });
  requests.bindAccount('did:plc:carol', '5');
  expect(get(requests).drafts).toEqual([]);
  await requests.resume(ipc[0].args.input!.draftId);
  expect(ipc.length).toBe(before + 1);
  expect(ipc[before].cmd).toBe('resume_request_draft'); // reaches IPC only as carol; Rust rejects (request_ipc_tests)
  expect(ipc[before].args.ownerDid).toBe('did:plc:carol');
  expect(get(requests).error).toMatch(/unexpected IPC resume_request_draft/);
  expect(fetches).toBe(0);
});

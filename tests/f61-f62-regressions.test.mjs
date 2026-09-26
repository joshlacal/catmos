// Regression tests for F61 (unified account binding without items wipe)
// and F62 (unavailable device on accepted request shows unavailable copy, no composer)
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import test from 'node:test';
import vm from 'node:vm';
import ts from 'typescript';
import { get, writable } from 'svelte/store';

// Transpile stores
const requestsTs = await readFile(new URL('../src/lib/stores/requests.ts', import.meta.url), 'utf8');
const requestsJs = ts.transpileModule(requestsTs, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText;

const convosTs = await readFile(new URL('../src/lib/stores/conversations.ts', import.meta.url), 'utf8');
const convosJs = ts.transpileModule(convosTs, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText;

test('F61: conversations store bindAccount preserves idempotency on same revision and reloads correctly', async () => {
  const context = vm.createContext({ console, crypto: { randomUUID } });
  let loadCalls = 0;
  const mockApi = {
    getConversations: async () => {
      loadCalls++;
      return [{ id: 'convo-1', groupId: 'g1', displayName: 'Chat 1', members: ['did:plc:alice', 'did:plc:bob'], isGroup: false, conversationKind: 'direct' }];
    },
    createBlock: async () => {},
    listOwnBlocks: async () => []
  };

  const transport = new vm.SyntheticModule(Object.keys(mockApi), function () {
    for (const [k, v] of Object.entries(mockApi)) this.setExport(k, v);
  }, { context });
  const svelte = new vm.SyntheticModule(['writable', 'derived', 'get'], function () {
    this.setExport('writable', writable);
    this.setExport('derived', (store, fn) => store);
    this.setExport('get', get);
  }, { context });
  const authModule = new vm.SyntheticModule(['auth'], function () {
    this.setExport('auth', writable({ user: null }));
  }, { context });

  const module = new vm.SourceTextModule(convosJs, { context });
  await module.link(name => {
    if (name === 'svelte/store') return svelte;
    if (name === '$lib/stores/auth') return authModule;
    return transport;
  });
  await module.evaluate();

  const convos = module.namespace.conversations;

  // Initial bind and load
  convos.bindAccount('did:plc:alice', 'rev-1');
  await convos.load();
  assert.equal(get(convos).items.length, 1, 'items must be populated after load()');

  // Idempotent bind with same owner and revision must NOT wipe items or increment epoch
  convos.bindAccount('did:plc:alice', 'rev-1');
  assert.equal(get(convos).items.length, 1, 'idempotent bindAccount must not clear items');

  // New revision for same account updates authRevision and increments epoch, but preserves items until reload
  convos.bindAccount('did:plc:alice', 'rev-2');
  assert.equal(get(convos).items.length, 1, 'same account new revision preserves items until reload');
  await convos.load();
  assert.equal(get(convos).items.length, 1, 'items repopulated after reload');

  // Switching to a different account DID clears items immediately
  convos.bindAccount('did:plc:bob', 'rev-1');
  assert.equal(get(convos).items.length, 0, 'account switch to different DID clears items');
});

test('F62: accepted request on unaddressed device (canSend=false) disallows ordinary activity', async () => {
  const context = vm.createContext({ console, crypto: { randomUUID } });
  const mockApi = {
    requestBackendAvailable: true,
    getRequestWorkspace: async owner => ({
      ownerDid: owner,
      drafts: [],
      requests: [{
        conversationId: 'convo-unaddressed',
        firstMessageId: 'msg-1',
        consent: 'accepted',
        crypto: 'unavailable',
        preview: { type: 'unavailable', code: 'DeviceNotAddressed' },
        generation: 0,
        stateVersion: 2,
        capabilities: {
          canPreview: false,
          canAccept: false,
          canClose: true,
          canSend: false,
          canEmitReceipts: false,
          canAdminister: false
        }
      }]
    })
  };

  const transport = new vm.SyntheticModule(Object.keys(mockApi), function () {
    for (const [k, v] of Object.entries(mockApi)) this.setExport(k, v);
  }, { context });
  const svelte = new vm.SyntheticModule(['writable', 'get'], function () {
    this.setExport('writable', writable);
    this.setExport('get', get);
  }, { context });

  const module = new vm.SourceTextModule(requestsJs, { context });
  await module.link(name => (name === 'svelte/store' ? svelte : transport));
  await module.evaluate();

  const requests = module.namespace.createRequestsStore();
  requests.bindAccount('did:plc:alice', 'rev-1');
  await requests.load();

  const views = get(requests).views;
  assert.equal(views.length, 1);
  assert.equal(views[0].consent, 'accepted');
  assert.equal(views[0].capabilities.canSend, false);

  // canUseOrdinaryActivity MUST return false when canSend is false, preventing empty thread state and composer
  assert.equal(requests.canUseOrdinaryActivity('convo-unaddressed'), false,
    'canUseOrdinaryActivity must return false when capabilities.canSend is false');
});

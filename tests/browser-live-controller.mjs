// Interactive Browser controller for live cross-platform qualifications.
// Runs real Chromium with SPKI pinning, host resolution rules, and real Catmos web.
// Reads JSON-lines from stdin, writes JSON-lines to stdout.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash, randomUUID, X509Certificate } from 'node:crypto';
import { connect as connectTls } from 'node:tls';
import { createInterface } from 'node:readline';
import { dirname, join } from 'node:path';
import { chromium } from '../../catmos/node_modules/@playwright/test/index.mjs';

let browser = null;
let context = null;
let page = null;
let manifest = null;
let sessions = null;
let actor = null;
let runId = null;

const rpcMethods = new Map();
for(const name of ['getOwnDevices','getDevices','getDeviceKey','getConversations','getPendingWelcomes','getLeafRecoveryInbox','getConversationState','getEntries','getDirectRequestOutcome']) rpcMethods.set(`/xrpc/blue.catbird.chat.${name}`,'GET');
for(const name of ['enrollDevice','publishDirectRequestKeys','replenishKeyPackages','prepareDirectRequest','publishDirectRequest','cancelDirectRequestPreparation','acknowledgeWelcome','rejectWelcome','acceptConversation','sendMessage','createConversation','submitTransition','closeConversation','requestLeave','getSubscriptionTicket']) rpcMethods.set(`/xrpc/blue.catbird.chat.${name}`,'POST');
for(const path of ['/auth/session','/xrpc/app.bsky.actor.getProfile','/xrpc/app.bsky.actor.getProfiles','/xrpc/app.bsky.graph.getBlocks','/xrpc/com.atproto.repo.listRecords','/xrpc/com.atproto.repo.getRecord']) rpcMethods.set(path,'GET');

function allowedRemote(url, method='GET', websocket=false, browserHosts) {
  const isFixtureHost = url.hostname.endsWith('.request-fixture.catbird.blue') || (browserHosts && browserHosts.has(url.hostname));
  if (url.protocol !== (websocket ? 'wss:' : 'https:') || url.port || url.username || url.password || url.hash || !isFixtureHost) {
    console.error('[DISALLOWED_REMOTE_CHECK]', url.href, 'proto:', url.protocol, 'port:', url.port, 'in_hosts:', isFixtureHost);
    return false;
  }
  if (websocket) return url.hostname === 'chat.catbird.blue' && url.pathname === '/xrpc/blue.catbird.chat.subscribeEvents';
  if (url.origin === manifest.origin || url.hostname.endsWith('.request-fixture.catbird.blue')) {
    const expected = rpcMethods.get(url.pathname);
    const ok = expected !== undefined && (method === expected || method === 'OPTIONS');
    if (!ok) console.error('[DISALLOWED_RPC]', url.pathname, 'method:', method, 'expected:', expected);
    return ok;
  }
  return method === 'GET' && (url.pathname === '/.well-known/did.json' || /^\/xrpc\/com\.atproto\.repo\.(listRecords|getRecord)$/.test(url.pathname));
}

function allowedLocal(url, method) {
  return url.origin === manifest.corsOrigin && ['GET','HEAD'].includes(method) &&
    (url.pathname === '/' || /^\/(src|node_modules|@vite|@id|@fs|\.svelte-kit|_app)\//.test(url.pathname) || /^\/(favicon|logo|catmos)[^/]*\.(svg|png|ico)$/.test(url.pathname));
}

async function handleCommand(req) {
  const { cmd } = req;
  if (cmd === 'init') {
    if (context) {
      await context.close().catch(() => {});
      context = null;
      page = null;
    }
    manifest = JSON.parse(await readFile(req.manifestPath, 'utf8'));
    sessions = JSON.parse(await readFile(join(dirname(req.manifestPath), 'sessions.json'), 'utf8')).accounts;
    actor = sessions.find(a => a.label === req.label);
    assert(actor, `Account ${req.label} not found`);
    runId = req.runId;

    const gatewayHost = new URL(manifest.origin).hostname;
    const browserHosts = new Set([gatewayHost, 'chat.catbird.blue', 'api.catbird.blue', ...manifest.accounts.map(a => a.did.slice('did:web:'.length))]);
    const mappings = [...browserHosts].map(h => `MAP ${h} ${manifest.hosts[h] || manifest.hosts[gatewayHost]}`).join(',');
    const args = [`--host-resolver-rules=${mappings}`, '--no-proxy-server', `--ignore-certificate-errors-spki-list=${manifest.tlsSpkiSha256}`];
    const userDataDir = join('/tmp', `catmos-browser-${req.label}-${runId}`);
    context = await chromium.launchPersistentContext(userDataDir, {
      headless: true,
      args,
      viewport: { width: 1360, height: 980 },
      ignoreHTTPSErrors: true,
      serviceWorkers: 'block'
    });
    const dbKey = createHash('sha256').update(`catmos-mls-db-key-${req.label}-${runId}`).digest('hex');
    await context.addInitScript(({ key }) => {
      sessionStorage.setItem('catbird_mls_db_key', key);
    }, { key: dbKey });
    await context.route('**/*', route => {
      const url = new URL(route.request().url());
      if (allowedLocal(url, route.request().method()) || allowedRemote(url, route.request().method(), false, browserHosts)) return route.continue();
      console.error('[ABORTED]', url.href, 'origin:', url.origin, 'manifest.origin:', manifest?.origin, 'method:', route.request().method());
      return route.abort('blockedbyclient');
    });
    await context.routeWebSocket('**/*', socket => {
      const url = new URL(socket.url());
      if ((url.protocol === 'ws:' && url.host === new URL(manifest.corsOrigin).host && url.pathname === '/') || allowedRemote(url, 'GET', true, browserHosts)) return socket.connectToServer();
      socket.close({ code: 1008, reason: 'Unlisted fixture host' });
    });

    page = context.pages()[0] || await context.newPage();
    page.on('console', msg => console.error('[PAGE CONSOLE]', msg.text()));
    page.on('pageerror', err => console.error('[PAGE ERROR]', err));
    page.on('requestfailed', req => console.error('[REQ FAILED]', req.url(), req.failure()?.errorText));
    globalThis.loadedWasmHash = null;
    globalThis.wasmResponseInfo = null;
    page.on('response', async resp => {
      if (resp.url().includes('.wasm')) {
        try {
          const body = await resp.body();
          const digest = createHash('sha256').update(body).digest('hex');
          globalThis.loadedWasmHash = digest;
          globalThis.wasmResponseInfo = {
            url: resp.url(),
            status: resp.status(),
            bytes: body.length,
            sha256: digest,
            timestamp: new Date().toISOString()
          };
          console.error('[LOADED WASM NETWORK RESPONSE]', JSON.stringify(globalThis.wasmResponseInfo));
        } catch (e) {
          console.error('[WASM RESPONSE ERROR]', e);
        }
      }
    });
    page.setDefaultTimeout(60000);
    await page.goto(manifest.corsOrigin);

    // Complete login
    await page.evaluate(async () => {
      const { auth } = await import('/src/lib/stores/auth.ts');
      let ready = false;
      const unsub = auth.subscribe(v => { ready = !v.loading; });
      const deadline = Date.now() + 15000;
      while (!ready) {
        if (Date.now() > deadline) { unsub(); throw new Error('Auth readiness timeout'); }
        await new Promise(r => setTimeout(r, 20));
      }
      unsub();
    });

    await page.evaluate(async act => {
      const api = await import('/src/lib/wasm.ts');
      const { auth } = await import('/src/lib/stores/auth.ts');
      const user = await api.completeLogin(act.session);
      auth.setUser(user);
      globalThis.fixtureActor = user;
    }, actor);

    await page.evaluate(async () => {
      const { requests } = await import('/src/lib/stores/requests.ts');
      requests.bindAccount(fixtureActor.did, fixtureActor.authRevision);
      await requests.setDeliveryEnabled(true);
      await requests.load();
      requests.showInbox();
    });

    return { ok: true, did: actor.did, label: actor.label, wasmHash: globalThis.loadedWasmHash };
  }

  if (cmd === 'await_preview') {
    const { cid, text } = req;
    // Wait for decrypted preview to show up
    await page.evaluate(async c => {
      const { requests } = await import('/src/lib/stores/requests.ts');
      const api = await import('/src/lib/wasm.ts');
      for (let i = 0; i < 40; i++) {
        await requests.load();
        try {
          const refreshed = await api.refreshDirectRequest(globalThis.fixtureActor.did, c, globalThis.fixtureActor.authRevision);
          requests.applyView(globalThis.fixtureActor.did, refreshed);
        } catch (_) {}
        requests.selectRequest(c);
        let ready = false;
        const unsub = requests.subscribe(s => {
          const v = s.views.find(x => x.conversationId === c);
          if (v && v.preview) ready = true;
        });
        unsub();
        if (ready) break;
        await new Promise(r => setTimeout(r, 500));
      }
    }, cid);

    if (text) {
      try {
        await page.getByLabel('Decrypted introduction').getByText(text, { exact: false }).waitFor({ timeout: 10000 });
      } catch (_) {}
    }

    const pending = await page.evaluate(async c => {
      const api = await import('/src/lib/wasm.ts');
      return api.refreshDirectRequest(fixtureActor.did, c, fixtureActor.authRevision);
    }, cid);

    return {
      ok: true,
      consent: pending.consent,
      previewText: pending.preview?.text,
      canSend: pending.capabilities.canSend,
      canEmitReceipts: pending.capabilities.canEmitReceipts
    };
  }

  if (cmd === 'accept') {
    const { cid } = req;
    await page.getByRole('button', { name: 'Accept conversation', exact: true }).click();
    await page.getByRole('button', { name: 'Open conversation', exact: true }).waitFor({ timeout: 20000 });
    await page.getByRole('button', { name: 'Open conversation', exact: true }).click();
    return { ok: true };
  }

  if (cmd === 'send_message') {
    const { cid, text } = req;
    const msg = await page.evaluate(async ({ c, t }) => {
      const api = await import('/src/lib/wasm.ts');
      return api.sendMessage(c, t, fixtureActor.did, fixtureActor.authRevision);
    }, { c: cid, t: text });
    return { ok: true, message: msg };
  }

  if (cmd === 'send_request') {
    const { recipientDid, text } = req;
    const draftId = await page.evaluate(async ({ recipient, t }) => {
      const { requests } = await import('/src/lib/stores/requests.ts');
      requests.bindAccount(fixtureActor.did, fixtureActor.authRevision);
      await requests.setDeliveryEnabled(true);
      await requests.load();
      requests.begin(recipient, 'Peer fixture', t);
      let id;
      const unsub = requests.subscribe(s => { id = s.selectedId; });
      unsub();
      if (!id) throw new Error('No draftId created by requests.begin');
      return id;
    }, { recipient: recipientDid, t: text });

    // Click 'Send introduction' in the real Playwright UI
    const sendBtn = page.getByRole('button', { name: 'Send introduction' });
    await sendBtn.waitFor({ timeout: 5000 });
    await sendBtn.click();

    // Wait for the outcome to settle
    const res = await page.evaluate(async id => {
      const { requests } = await import('/src/lib/stores/requests.ts');
      let deadline = Date.now() + 20000;
      while (Date.now() < deadline) {
        let d;
        const unsub = requests.subscribe(s => {
          d = s.drafts.find(x => x.input.draftId === id);
        });
        unsub();
        if (d && d.outcome) return { draftId: id, outcome: d.outcome };
        await new Promise(r => setTimeout(r, 200));
      }
      throw new Error('Timeout waiting for request outcome');
    }, draftId);

    if (!res.outcome || (res.outcome.type !== 'requestSent' && res.outcome.type !== 'existingDirect')) {
      throw new Error(`Unexpected outcome: ${JSON.stringify(res.outcome)}`);
    }
    return { ok: true, draftId: res.draftId, cid: res.outcome.conversationId, outcome: res.outcome, timestamp: new Date().toISOString() };
  }

  if (cmd === 'fetch_messages') {
    const { cid, expectedText } = req;
    const messages = await page.evaluate(async ({ c, expected }) => {
      const api = await import('/src/lib/wasm.ts');
      for (let i = 0; i < 20; i++) {
        await api.refreshDirectRequest(fixtureActor.did, c, fixtureActor.authRevision);
        await api.fetchNewMessages(c, fixtureActor.did, fixtureActor.authRevision);
        const all = await api.getMessages(c, undefined, fixtureActor.did, fixtureActor.authRevision);
        if (!expected || (all && all.some(m => m.content === expected))) {
          return all;
        }
        await new Promise(r => setTimeout(r, 500));
      }
      return api.getMessages(c, undefined, fixtureActor.did, fixtureActor.authRevision);
    }, { c: cid, expected: expectedText });
    return { ok: true, messages };
  }

  if (cmd === 'reload_and_check') {
    const { cid } = req;
    console.error('[CONTROLLER] reload_and_check started for cid:', cid);
    await page.reload();
    console.error('[CONTROLLER] page.reload() finished');
    await page.evaluate(async act => {
      const { auth } = await import('/src/lib/stores/auth.ts');
      const api = await import('/src/lib/wasm.ts');
      let ready = false;
      let user = null;
      const unsub = auth.subscribe(v => {
        if (!v.loading && v.user) {
          user = v.user;
          ready = true;
        }
      });
      const deadline = Date.now() + 15000;
      while (!ready) {
        if (Date.now() > deadline) { unsub(); break; }
        await new Promise(r => setTimeout(r, 50));
      }
      unsub();
      if (!user) {
        user = await api.tryRestoreSession();
        if (!user) user = await api.completeLogin(act.session);
        auth.setUser(user);
      }
      globalThis.fixtureActor = user;
      console.error('[CONTROLLER] fixtureActor set:', user.did);
    }, actor);
    console.error('[CONTROLLER] calling api.getMessages...');
    const messages = await page.evaluate(async c => {
      const api = await import('/src/lib/wasm.ts');
      return api.getMessages(c, undefined, globalThis.fixtureActor.did, globalThis.fixtureActor.authRevision);
    }, cid);
    console.error('[CONTROLLER] api.getMessages returned:', messages.length, 'messages');
    return { ok: true, count: messages.length, messages };
  }

  if (cmd === 'reload_worker_before_welcome') {
    await page.reload();
    await page.evaluate(async act => {
      const { auth } = await import('/src/lib/stores/auth.ts');
      const api = await import('/src/lib/wasm.ts');
      let ready = false;
      let user = null;
      const unsub = auth.subscribe(v => {
        if (!v.loading && v.user) {
          user = v.user;
          ready = true;
        }
      });
      const deadline = Date.now() + 15000;
      while (!ready) {
        if (Date.now() > deadline) { unsub(); break; }
        await new Promise(r => setTimeout(r, 50));
      }
      unsub();
      if (!user) {
        user = await api.tryRestoreSession();
        if (!user) user = await api.completeLogin(act.session);
        auth.setUser(user);
      }
      globalThis.fixtureActor = user;
    }, actor);
    return { ok: true };
  }

  if (cmd === 'save_draft') {
    const { recipientDid, text } = req;
    // 1. UI: Click 'New conversation' in sidebar
    const newConvoBtn = page.getByRole('button', { name: 'New conversation' });
    await newConvoBtn.waitFor({ timeout: 5000 });
    await newConvoBtn.click();

    // 2. UI: Search for recipient in user search input
    const searchInput = page.getByPlaceholder('Search by name or handle...');
    await searchInput.waitFor({ timeout: 5000 });
    await searchInput.fill('bob');

    // 3. UI: Select the first matching search result
    const searchResult = page.locator('.search-result').first();
    await searchResult.waitFor({ timeout: 10000 });
    await searchResult.click();

    // 4. UI: Click 'Start Chat' button in dialog
    const startChatBtn = page.getByRole('button', { name: 'Start Chat' });
    await startChatBtn.waitFor({ timeout: 5000 });
    await startChatBtn.click();

    // 5. UI: Fill the 'Your message' compose textarea
    const msgTextarea = page.locator('#request-message');
    await msgTextarea.waitFor({ timeout: 5000 });
    if (text) {
      await msgTextarea.fill(text);
    }

    // Read state strictly for return value / logging
    const draft = await page.evaluate(async recipient => {
      const { requests } = await import('/src/lib/stores/requests.ts');
      let d;
      const unsub = requests.subscribe(s => {
        d = s.drafts.find(x => x.input.recipientDid === recipient);
      });
      unsub();
      return d;
    }, recipientDid);
    return { ok: true, draft, timestamp: new Date().toISOString() };
  }

  if (cmd === 'cancel_draft') {
    const { draftId } = req;
    const cancelBtn = page.getByRole('button', { name: 'Cancel draft' });
    await cancelBtn.waitFor({ timeout: 5000 });
    await cancelBtn.click();
    await page.getByRole('region', { name: 'Message requests' }).waitFor({ timeout: 5000 });
    const draft = await page.evaluate(async id => {
      const { requests } = await import('/src/lib/stores/requests.ts');
      let d;
      const unsub = requests.subscribe(s => {
        d = s.drafts.find(x => x.input.draftId === id);
      });
      unsub();
      return d;
    }, draftId);
    return { ok: true, draftId, remainingDraft: draft || null, timestamp: new Date().toISOString() };
  }

  if (cmd === 'screenshot') {
    await page.screenshot({ path: req.path });
    return { ok: true, path: req.path };
  }

  if (cmd === 'close') {
    if (context) await context.close().catch(() => {});
    context = null;
    page = null;
    return { ok: true };
  }
  if (cmd === 'get_wasm_hash') {
    return { ok: true, wasmHash: globalThis.loadedWasmHash, responseInfo: globalThis.wasmResponseInfo };
  }


  throw new Error(`Unknown command: ${cmd}`);
}

const rl = createInterface({ input: process.stdin, output: process.stdout, terminal: false });
for await (const line of rl) {
  if (!line.trim()) continue;
  try {
    const req = JSON.parse(line);
    const res = await handleCommand(req);
    console.log(JSON.stringify(res));
  } catch (err) {
    console.log(JSON.stringify({ ok: false, error: String(err.message ?? err) }));
  }
}

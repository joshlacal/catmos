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
for(const path of ['/auth/session','/xrpc/app.bsky.actor.getProfile','/xrpc/app.bsky.actor.getProfiles','/xrpc/app.bsky.actor.searchActors','/xrpc/app.bsky.actor.searchActorsTypeahead','/xrpc/app.bsky.graph.getBlocks','/xrpc/com.atproto.repo.listRecords','/xrpc/com.atproto.repo.getRecord']) rpcMethods.set(path,'GET');
// Block sender publishes app.bsky.graph.block; the fixture gateway accepts only that record shape.
rpcMethods.set('/xrpc/com.atproto.repo.createRecord', 'POST');

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
  return method === 'GET' && (url.pathname === '/.well-known/did.json' || /^\/xrpc\/com\.atproto\.repo\.(listRecords|getRecord)$/.test(url.pathname) || /^\/xrpc\/app\.bsky\.actor\.searchActors(Typeahead)?$/.test(url.pathname));
}

function allowedLocal(url, method) {
  return url.origin === manifest.corsOrigin && ['GET','HEAD'].includes(method) &&
    (url.pathname === '/' || /^\/(src|node_modules|@vite|@id|@fs|\.svelte-kit|_app)\//.test(url.pathname) || /^\/(favicon|logo|catmos)[^/]*\.(svg|png|ico)$/.test(url.pathname));
}

function mark(label) {
  const line = `[CONTROLLER] MARK ${label} ${new Date().toISOString()}`;
  console.error(line);
  return line;
}

async function restoreLogin() {
  await page.evaluate(async act => {
    const { auth } = await import('/src/lib/stores/auth.ts');
    const api = await import('/src/lib/wasm.ts');
    let user = null;
    const unsub = auth.subscribe(v => { if (!v.loading && v.user) user = v.user; });
    const deadline = Date.now() + 15000;
    while (!user && Date.now() < deadline) await new Promise(r => setTimeout(r, 50));
    unsub();
    if (!user) {
      user = await api.tryRestoreSession();
      if (!user) user = await api.completeLogin(act.session);
      auth.setUser(user);
    }
    globalThis.fixtureActor = user;
  }, actor);
}

// Real UI: New conversation -> search exact recipient DID -> pick that result -> Start Chat -> type text.
async function composeDraftUI(recipientDid, text) {
  await page.getByRole('button', { name: 'New conversation' }).click({ timeout: 10000 });
  const search = page.getByPlaceholder('Search by name or handle...');
  await search.fill(recipientDid, { timeout: 5000 });
  const handle = recipientDid.slice('did:web:'.length);
  await page.locator('.search-result', { hasText: handle }).first().click({ timeout: 15000 });
  await page.getByRole('button', { name: 'Start Chat' }).click({ timeout: 5000 });
  const box = page.locator('#request-message');
  await box.fill(text, { timeout: 5000 });
  const draft = await page.evaluate(async ({ recipient, t }) => {
    const { requests } = await import('/src/lib/stores/requests.ts');
    let d;
    const unsub = requests.subscribe(s => { d = s.drafts.find(x => x.input.recipientDid === recipient && x.input.text === t); });
    unsub();
    return d ?? null;
  }, { recipient: recipientDid, t: text });
  return { draft, composerValue: await box.inputValue() };
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
    const browserHosts = new Set([gatewayHost, 'chat.catbird.blue', 'api.catbird.blue', 'public.api.bsky.app', ...Object.keys(manifest.hosts), ...manifest.accounts.map(a => a.did.slice('did:web:'.length))]);
    // Every other hostname fails to resolve, so nothing outside the fixture can be reached by name.
    const mappings = [...[...browserHosts].map(h => `MAP ${h} ${manifest.hosts[h] || manifest.hosts[gatewayHost]}`), 'MAP * ~NOTFOUND', 'EXCLUDE 127.0.0.1'].join(',');
    const args = [`--host-resolver-rules=${mappings}`, '--no-proxy-server', `--ignore-certificate-errors-spki-list=${manifest.tlsSpkiSha256}`, '--disable-http-cache', '--disk-cache-size=0'];
    const userDataDir = join('/tmp', `catmos-browser-${req.label}-${runId}`);
    if (req.fresh) {
      const { rm } = await import('node:fs/promises');
      await rm(userDataDir, { recursive: true, force: true }).catch(() => {});
    }
    context = await chromium.launchPersistentContext(userDataDir, {
      args,
      viewport: { width: 1360, height: 980 },
      ignoreHTTPSErrors: true,
      serviceWorkers: 'block'
    });
    const dbKey = createHash('sha256').update(`catmos-mls-db-key-${req.label}-${runId}`).digest('hex');
    // Only the app document gets the key; a parked about:blank must run nothing at all.
    await context.addInitScript(({ key, origin }) => {
      if (location.origin === origin) sessionStorage.setItem('catbird_mls_db_key', key);
    }, { key: dbKey, origin: new URL(manifest.corsOrigin).origin });
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
    await page.waitForLoadState('domcontentloaded');

    // Complete login with retry in case Vite initialization navigates
    for (let attempt = 0; attempt < 5; attempt++) {
      try {
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
            if (!user) {
              user = await api.completeLogin(act.session);
            }
            auth.setUser(user);
          }
          globalThis.fixtureActor = user;
        }, actor);
        break;
      } catch (e) {
        if (attempt === 4) throw e;
        await new Promise(r => setTimeout(r, 1000));
      }
    }
    await page.evaluate(async () => {
      const { requests } = await import('/src/lib/stores/requests.ts');
      requests.bindAccount(fixtureActor.did, fixtureActor.authRevision);
      await requests.load();
    });
    // The SvelteKit app itself must have booted, not just the modules evaluated above.
    await page.getByRole('button', { name: 'New conversation' }).waitFor({ timeout: 30000 });
    return { ok: true, did: actor.did, label: actor.label, wasmHash: globalThis.loadedWasmHash, appBooted: true };
  }

  if (cmd === 'enable_delivery_ui') {
    await page.locator('.conversations-list .conversation-item', { hasText: 'Message requests' }).click({ timeout: 15000 });
    const summary = page.locator('summary', { hasText: 'Receive encrypted requests on this device' });
    await summary.click({ timeout: 15000 });
    await page.getByRole('button', { name: 'Enable delivery', exact: true }).click({ timeout: 10000 });
    const status = page.getByRole('status').filter({ hasText: 'Encrypted request delivery enabled' });
    await status.waitFor({ timeout: 30000 });
    return { ok: true, notice: (await status.innerText()).trim(), summary: (await summary.innerText()).trim() };
  }

  if (cmd === 'await_preview') {
    const { text } = req;
    await page.locator('.conversations-list .conversation-item', { hasText: 'Message requests' }).click({ timeout: 15000 });
    const row = page.locator('.request-inbox .row', { hasText: 'Review' });
    const deadline = Date.now() + 90000;
    let refreshes = 0;
    while (Date.now() < deadline && (await row.count()) === 0) {
      const refresh = page.getByRole('button', { name: 'Refresh', exact: true });
      if (await refresh.isEnabled().catch(() => false)) { await refresh.click().catch(() => {}); refreshes++; }
      await page.waitForTimeout(2000);
    }
    await row.first().click({ timeout: 5000 });
    const intro = page.locator('.request-detail .intro p');
    await intro.waitFor({ timeout: 60000 });
    const previewText = await intro.innerText();
    const eyebrow = await page.locator('.request-detail .eyebrow').innerText().catch(() => null);
    return { ok: true, previewText, eyebrow, refreshes, textMatches: text ? previewText === text : null };
  }

  if (cmd === 'accept') {
    await page.getByRole('button', { name: 'Accept conversation', exact: true }).click({ timeout: 10000 });
    const openBtn = page.getByRole('button', { name: 'Open conversation', exact: true });
    await openBtn.waitFor({ timeout: 60000 });
    const deadline = Date.now() + 60000;
    while (!(await openBtn.isEnabled()) && Date.now() < deadline) await page.waitForTimeout(500);
    const openEnabled = await openBtn.isEnabled();
    const eyebrow = await page.locator('.request-detail .eyebrow').innerText().catch(() => null);
    if (!openEnabled) throw new Error(`Accepted request never became sendable; eyebrow=${eyebrow}`);
    await openBtn.click();
    const composer = page.locator('textarea[placeholder="Message..."]');
    await composer.waitFor({ timeout: 30000 });
    return { ok: true, eyebrow, openEnabled, composerEnabled: await composer.isEnabled() };
  }

  if (cmd === 'decline' || cmd === 'block') {
    const label = cmd === 'decline' ? 'Decline' : 'Block sender';
    // Block publishes an app.bsky.graph.block record; keep the exchange the page actually made.
    const blockResponse = cmd === 'block'
      ? page.waitForResponse(r => r.url().includes('/xrpc/com.atproto.repo.createRecord'), { timeout: 30000 })
      : null;
    await page.getByRole('button', { name: label, exact: true }).click({ timeout: 10000 });
    const deadline = Date.now() + 30000;
    let state = null;
    while (Date.now() < deadline) {
      state = await page.evaluate(() => ({
        eyebrow: document.querySelector('.request-detail .eyebrow')?.textContent?.trim() ?? null,
        header: document.querySelector('.request-detail header p:last-child')?.textContent?.trim() ?? null,
        notice: document.querySelector('.request-detail .notice:not(.error)')?.textContent?.trim() ?? null,
        error: document.querySelector('.request-detail .notice.error')?.textContent?.trim() ?? null,
        busy: !!document.querySelector('.request-detail button:disabled')
      }));
      if (state.error || (cmd === 'decline' && state.header === 'This request is closed.') || (cmd === 'block' && state.notice?.startsWith('Sender blocked'))) break;
      await page.waitForTimeout(500);
    }
    let blockRecord = null;
    if (blockResponse) {
      const resp = await blockResponse;
      const sent = JSON.parse(resp.request().postData() || '{}');
      blockRecord = { status: resp.status(), repo: sent.repo ?? null, collection: sent.collection ?? null,
        subject: sent.record?.subject ?? null, uri: resp.ok() ? (await resp.json()).uri ?? null : null };
    }
    return { ok: true, action: cmd, ui: state, blockRecord };
  }

  if (cmd === 'send_message') {
    const { text } = req;
    const composer = page.locator('textarea[placeholder="Message..."]');
    await composer.fill(text, { timeout: 10000 });
    await page.getByRole('button', { name: 'Send message' }).click({ timeout: 5000 });
    const bubble = page.locator('.bubble', { hasText: text });
    await bubble.first().waitFor({ timeout: 30000 });
    const bubbles = await page.locator('.bubble').allInnerTexts();
    return { ok: true, bubbles };
  }

  if (cmd === 'compose_request') {
    const res = await composeDraftUI(req.recipientDid, req.text);
    return { ok: true, ...res };
  }

  if (cmd === 'send_introduction') {
    const { recipientDid, text } = req;
    await page.getByRole('button', { name: 'Send introduction' }).click({ timeout: 5000 });
    const res = await page.evaluate(async ({ recipient, t }) => {
      const { requests } = await import('/src/lib/stores/requests.ts');
      const deadline = Date.now() + 45000;
      while (Date.now() < deadline) {
        let d;
        const unsub = requests.subscribe(s => { d = s.drafts.find(x => x.input.recipientDid === recipient && x.input.text === t && x.outcome); });
        unsub();
        if (d) return { draftId: d.input.draftId, outcome: d.outcome };
        await new Promise(r => setTimeout(r, 250));
      }
      return { draftId: null, outcome: null };
    }, { recipient: recipientDid, t: text });
    await page.waitForTimeout(500);
    const ui = await page.evaluate(() => ({
      resultTitle: document.querySelector('.request-compose .result h2')?.textContent?.trim() ?? null,
      resultBody: document.querySelector('.request-compose .result p')?.textContent?.trim() ?? null,
      error: document.querySelector('.request-compose .notice.error')?.textContent?.trim() ?? null,
      composerValue: document.querySelector('#request-message')?.value ?? null
    }));
    return { ok: true, ...res, cid: res.outcome?.conversationId ?? null, ui };
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
    console.error('[CONTROLLER] Waiting for conversation row in UI sidebar up to 60s...');
    let found = false;
    const deadline = Date.now() + 60000;
    while (Date.now() < deadline) {
      const info = await page.evaluate(() => {
        const items = Array.from(document.querySelectorAll('.conversations-list .conversation-item'));
        return { count: items.length, texts: items.map(b => b.innerText.trim().replace(/\n/g, ' ')) };
      });
      if (info.count > 1) {
        console.error('[CONTROLLER] Found conversation row! Items:', JSON.stringify(info));
        found = true;
        break;
      }
      console.error('[CONTROLLER] Polling sidebar... current info:', JSON.stringify(info));
      await page.evaluate(async (c) => {
        try {
          const { requests } = await import('/src/lib/stores/requests.ts');
          const { conversations } = await import('/src/lib/stores/conversations.ts');
          const api = await import('/src/lib/wasm.ts');
          if (globalThis.fixtureActor?.did) {
            try {
              const refreshed = await api.refreshDirectRequest(globalThis.fixtureActor.did, c, globalThis.fixtureActor.authRevision);
              requests.applyView(globalThis.fixtureActor.did, refreshed);
            } catch {}
          }
          await requests.load();
          await conversations.load();
        } catch {}
      }, cid);
      await new Promise(r => setTimeout(r, 1000));
    }
    assert(found, 'Conversation row never appeared in UI sidebar after reload');

    console.error('[CONTROLLER] Clicking conversation in UI sidebar...');
    const convoBtn = page.locator('.conversations-list .conversation-item').nth(1);
    for (let attempt = 0; attempt < 5; attempt++) {
      await convoBtn.click({ timeout: 10000 });
      if (await page.locator('.message-list').count()) break;
      await page.waitForTimeout(1000);
    }

    console.error('[CONTROLLER] Waiting for message bubbles or thread state in UI...');
    await page.waitForSelector('.bubble, .message-row, .message-item, .request-first-message, .unavailable-device, .empty-messages, .message-list', { timeout: 30000 });
    await new Promise(r => setTimeout(r, 1000));
    const renderedState = await page.evaluate(async (c) => {
      const bubbles = Array.from(document.querySelectorAll('.bubble, .request-first-message'));
      const unavailable = document.querySelector('.unavailable-device');
      const emptyMsg = document.querySelector('.empty-messages');
      const { messages } = await import('/src/lib/stores/messages.ts');
      const { requests } = await import('/src/lib/stores/requests.ts');
      const { conversations, selectedConversation } = await import('/src/lib/stores/conversations.ts');
      const { auth } = await import('/src/lib/stores/auth.ts');
      const api = await import('/src/lib/wasm.ts');
      const getStore = s => { let v; s.subscribe(x => { v = x; })(); return v; };
      const msgStore = getStore(messages);
      const reqStore = getStore(requests);
      const authStore = getStore(auth);
      const convoStore = getStore(conversations);
      const selected = getStore(selectedConversation);
      let wasmMsgs = [];
      try {
        wasmMsgs = await api.getMessages(c, undefined, authStore.user?.did, authStore.user?.authRevision);
      } catch (e) {
        wasmMsgs = [{ error: String(e) }];
      }

      const convo = convoStore.items.find(item => item.id === c);
      const hasView = reqStore.views.some(v => v.conversationId === c);
      const ordinaryAllowedVal = !!authStore.user && !reqStore.loading && (hasView ? requests.canUseOrdinaryActivity(c) : convo?.pendingConsent !== true);
      const activeRequestVal = reqStore.views.find(v => v.conversationId === (reqStore.pane === 'request' ? reqStore.selectedId : selected?.id));

      return {
        bubbles: bubbles.map(b => ({
          text: b.innerText.trim(),
          className: b.className
        })),
        unavailableState: unavailable ? unavailable.innerText.trim() : null,
        emptyState: emptyMsg ? emptyMsg.innerText.trim() : null,
        composerPresent: document.querySelector('.composer') !== null,
        storeMessages: msgStore.byConversation.get(c) ?? [],
        wasmMsgs,
        ordinaryAllowedVal,
        activeRequestVal,
        selectedConvoId: selected?.id
      };
    }, cid);
    console.error('[CONTROLLER] Rendered state from UI:', JSON.stringify(renderedState));

    return {
      ok: true,
      count: renderedState.bubbles.length,
      messages: renderedState.bubbles,
      diag: renderedState,
      method: 'ui'
    };
  }
  if (cmd === 'eval') {
    const res = await page.evaluate(req.code);
    return { ok: true, result: res };
  }

  if (cmd === 'mark') {
    return { ok: true, line: mark(req.label) };
  }

  // Unload the app document (and its MLS worker) while keeping the browser
  // and its OPFS profile up, so nothing can sync until the next navigation.
  if (cmd === 'park') {
    const line = mark('parked');
    await page.goto('about:blank');
    return { ok: true, line };
  }

  // Real document + worker reload. From a parked page this is the first load
  // after the peer's publication; otherwise it reloads the running app.
  if (cmd === 'reload_worker_before_welcome') {
    const line = mark('reload-before-welcome');
    if (page.url() === 'about:blank') await page.goto(manifest.corsOrigin);
    else await page.reload();
    await restoreLogin();
    return { ok: true, line };
  }

  if (cmd === 'save_draft') {
    const res = await composeDraftUI(req.recipientDid, req.text);
    return { ok: true, ...res, timestamp: new Date().toISOString() };
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

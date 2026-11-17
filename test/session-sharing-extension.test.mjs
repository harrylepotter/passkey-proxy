import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

async function fixture() {
  let listener, tab = { id: 7, url: 'https://app.example.co.uk/private?secret=query#fragment' }, permission = false, readCount = 0, capture, posted, afterRead;
  const stored = {}, event = () => ({ addListener() {} });
  const chrome = {
    runtime: { getURL: path => `chrome-extension://fixture/${path}`, onInstalled: event(), onStartup: event(), onMessage: { addListener(fn) { listener = fn; } } },
    storage: { local: { get: async () => ({ ownerToken: 'p'.repeat(43), proxyEnabled: false }) }, session: { get: async () => ({ ...stored }), set: async value => Object.assign(stored, value), remove: async key => { delete stored[key]; } } },
    tabs: { query: async () => [tab] }, permissions: { contains: async () => permission },
    cookies: { getAllCookieStores: async () => [{ id: 'other-profile', tabIds: [9] }, { id: 'selected-profile', tabIds: [7] }],
      getAll: async query => { readCount++; capture = query; afterRead?.(); return [{ name: 'session', value: 'fixture-cookie', session: true }]; } },
    action: { setBadgeText: async () => {}, setBadgeBackgroundColor: async () => {} }, windows: { onRemoved: event() },
    webAuthenticationProxy: { detach: async () => {}, attach: async () => {}, onCreateRequest: event(), onGetRequest: event(), onRequestCanceled: event(), onIsUvpaaRequest: event() },
  };
  const context = vm.createContext({ chrome, URL, AbortSignal, setTimeout, clearTimeout, fetch: async (url, options) => {
    if (options.body) posted = JSON.parse(options.body);
    return { ok: true, json: async () => options.body
      ? { id: 'a'.repeat(24), site: posted.site, url: 'https://gateway.test/session#session=fixture', status: 'ready' }
      : { sessionSharing: { version: 1 }, sessionInvites: [], agentAccess: { publicOrigin: 'https://gateway.test' } } };
  } });
  context.importScripts = file => vm.runInContext(readFileSync(new URL(`../extension/${file}`, import.meta.url), 'utf8'), context);
  vm.runInContext(readFileSync(new URL('../extension/background.js', import.meta.url), 'utf8'), context);
  await vm.runInContext('attachmentReady', context);
  return {
    send: (message, sender = 'chrome-extension://fixture/popup.html') => new Promise(resolve => listener(message, { url: sender, frameId: 0 }, resolve)),
    setURL: url => { tab = { id: 7, url }; }, allow: () => { permission = true; }, switchOnRead: () => { afterRead = () => { tab = { id: 7, url: 'https://changed.test/' }; }; },
    readCount: () => readCount, capture: () => capture, posted: () => posted, stored: () => stored,
  };
}
test('extension cookie permissions stop at public/private suffix boundaries and popup inspection reads no cookies', async () => {
  const f = await fixture();
  const first = (await f.send({ action: 'session-share-context' })).value;
  assert.deepEqual(Array.from(first.permissionOrigins), ['https://app.example.co.uk/*', 'https://example.co.uk/*']);
  assert.equal(first.cookieURL, 'https://app.example.co.uk/private');
  f.setURL('https://app.customer.github.io/');
  assert.deepEqual(Array.from((await f.send({ action: 'session-share-context' })).value.permissionOrigins), ['https://app.customer.github.io/*', 'https://customer.github.io/*']);
  f.setURL('http://127.0.0.1:9999/');
  assert.deepEqual(Array.from((await f.send({ action: 'session-share-context' })).value.permissionOrigins), ['http://127.0.0.1/*']);
  assert.equal(f.readCount(), 0); assert.equal(f.posted(), undefined);
});
test('only a popup action with granted permissions and an unchanged active tab can capture its own cookie store', async () => {
  const f = await fixture();
  const request = { action: 'create-session-invite', tabId: 7, site: 'https://app.example.co.uk' };
  assert.ok((await f.send(request, 'https://app.example.co.uk/')).error);
  assert.ok((await f.send(request, 'http://127.0.0.1:4780/')).error);
  assert.ok((await f.send(request, 'chrome-extension://fixture/approve.html')).error);
  assert.ok((await f.send(request)).error); assert.equal(f.readCount(), 0);
  f.allow();
  assert.ok((await f.send({ ...request, tabId: 99 })).error); assert.equal(f.readCount(), 0);
  assert.ok((await f.send(request)).value);
  assert.deepEqual(JSON.parse(JSON.stringify(f.capture())), { url: 'https://app.example.co.uk/private', storeId: 'selected-profile' });
  assert.equal(f.posted().site, request.site);
  assert.ok(!JSON.stringify(f.stored()).includes('fixture-cookie'));
  const changing = await fixture(); changing.allow(); changing.switchOnRead();
  assert.ok((await changing.send(request)).error); assert.equal(changing.posted(), undefined);
});

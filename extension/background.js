importScripts('tldts.min.js');
const gateway = 'http://127.0.0.1:4780';
const pending = new Map();
let attached = false, attachmentError = '';
let attachmentQueue = Promise.resolve();
async function api(path, data, timeout) {
  const { ownerToken } = await chrome.storage.local.get('ownerToken');
  if (!ownerToken) throw new Error('Connect the extension from the owner dashboard first.');
  const response = await fetch(`${gateway}${path}`, { method: data ? 'POST' : 'GET',
    ...(timeout ? { signal: AbortSignal.timeout(timeout) } : {}),
    headers: { Authorization: `Bearer ${ownerToken}`, ...(data ? { 'Content-Type': 'application/json' } : {}) },
    ...(data ? { body: JSON.stringify(data) } : {}) });
  const result = await response.json(); if (!response.ok) throw new Error(result.error); return result;
}
function syncAttachment() {
  // Serialize startup/pair/provider changes so a stale attach cannot override
  // the owner's choice to use their OS authenticator.
  attachmentQueue = attachmentQueue.catch(() => {}).then(async () => {
    const { ownerToken, proxyEnabled } = await chrome.storage.local.get(['ownerToken', 'proxyEnabled']);
    try {
      if (ownerToken && proxyEnabled !== false) { await chrome.webAuthenticationProxy.attach(); attached = true; }
      else { await chrome.webAuthenticationProxy.detach(); attached = false; }
      attachmentError = '';
      await updateBadge();
    } catch (error) { attachmentError = error.message; throw error; }
  });
  return attachmentQueue;
}
async function updateBadge() {
  await chrome.action.setBadgeText({ text: pending.size ? String(pending.size) : attached ? '' : 'OS' });
  await chrome.action.setBadgeBackgroundColor({ color: attached ? '#245843' : '#64748b' });
}
async function setProvider(enabled, keepRequestId) {
  const { ownerToken } = await chrome.storage.local.get('ownerToken');
  if (enabled && !ownerToken) throw new Error('Connect the extension from the owner dashboard first.');
  await chrome.storage.local.set({ proxyEnabled: enabled });
  for (const [id, request] of [...pending]) {
    request.keepWindow = id === String(keepRequestId);
    await complete(id, null, 'Provider changed. Retry the website’s passkey button.').catch(() => cleanup(id));
  }
  await syncAttachment();
  return { enabled: attached };
}
function cleanup(id) {
  const request = pending.get(String(id)); if (!request) return;
  pending.delete(String(id)); clearTimeout(request.timer);
  void updateBadge();
  if (request.windowId && !request.keepWindow) chrome.windows.remove(request.windowId).catch(() => {});
  return request;
}
async function complete(id, value, error) {
  const request = pending.get(String(id)); if (!request) return;
  const details = { requestId: request.requestId, ...(error ? { error: { name: 'NotAllowedError', message: error } } : { responseJson: JSON.stringify(value) }) };
  await chrome.webAuthenticationProxy[request.operation === 'create' ? 'completeCreateRequest' : 'completeGetRequest'](details);
  cleanup(id);
}
async function receive(operation, event) {
  const id = String(event.requestId);
  try {
    const options = JSON.parse(event.requestDetailsJson);
    // Chrome supplies the real calling origin after RP/permissions-policy checks.
    // Web pages never send credential requests to this background worker.
    const client = options.extensions?.remoteDesktopClientOverride;
    if (!client?.origin) throw new Error('Chrome did not provide the calling origin.');
    const origin = new URL(client.origin).origin;
    if (client.sameOriginWithAncestors === false) throw new Error('Cross-origin iframe ceremonies are not supported yet. Open the sign-in page directly.');
    delete options.extensions.remoteDesktopClientOverride;
    const request = { id, requestId: event.requestId, operation, options, origin };
    pending.set(id, request);
    request.timer = setTimeout(() => complete(id, null, 'Passkey approval expired.').catch(() => cleanup(id)), Math.min(options.timeout || 120000, 300000));
    await chrome.action.setBadgeText({ text: String(pending.size) });
    const win = await chrome.windows.create({ url: chrome.runtime.getURL(`approve.html#${id}`), type: 'popup', width: 460, height: 670, focused: true });
    if (pending.has(id)) request.windowId = win.id;
    else await chrome.windows.remove(win.id).catch(() => {});
  } catch (error) {
    if (!pending.has(id)) pending.set(id, { id, requestId: event.requestId, operation });
    await complete(id, null, error.message).catch(() => cleanup(id));
  }
}
chrome.webAuthenticationProxy.onCreateRequest.addListener(event => { void receive('create', event); });
chrome.webAuthenticationProxy.onGetRequest.addListener(event => { void receive('get', event); });
chrome.webAuthenticationProxy.onRequestCanceled.addListener(id => cleanup(id));
chrome.webAuthenticationProxy.onIsUvpaaRequest.addListener(event => {
  chrome.webAuthenticationProxy.completeIsUvpaaRequest({ requestId: event.requestId, isUvpaa: true }).catch(() => {});
});
chrome.windows.onRemoved.addListener(id => {
  for (const [key, request] of pending) if (request.windowId === id) void complete(key, null, 'Passkey request dismissed.').catch(() => cleanup(key));
});
chrome.runtime.onInstalled.addListener(() => { syncAttachment().catch(() => {}); });
chrome.runtime.onStartup.addListener(() => { syncAttachment().catch(() => {}); });
const attachmentReady = syncAttachment().catch(() => {});

async function sharingTab() {
  const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
  let url;
  try { url = new URL(tab?.url); } catch { throw new Error('Open a signed-in website, then open this popup again.'); }
  if (!['https:', 'http:'].includes(url.protocol) || url.username || url.password || url.origin === gateway) throw new Error('Open the website you want to share, not a browser or dashboard page.');
  url.search = ''; url.hash = '';
  const root = tldts.getDomain(url.hostname, { allowPrivateDomains: true, extractHostname: false }) || url.hostname;
  const permissionOrigins = [];
  for (let host = url.hostname;; host = host.slice(host.indexOf('.') + 1)) {
    permissionOrigins.push(`${url.protocol}//${host}/*`);
    if (host === root || !host.includes('.')) break;
  }
  return { tabId: tab.id, site: url.origin, cookieURL: url.href, permissionOrigins };
}
async function sessionShareContext() {
  const tab = await sharingTab(), state = await api('/api/owner/state', undefined, 1500);
  if (state.sessionSharing?.version !== 1) throw new Error('Restart the gateway to enable session invites.');
  const { cookieInvite } = await chrome.storage.session.get('cookieInvite');
  const invites = (state.sessionInvites || []).filter(i => i.site === tab.site);
  const saved = cookieInvite && invites.some(i => i.id === cookieInvite.id && i.status === 'ready') ? cookieInvite : null;
  if (cookieInvite && !state.sessionInvites.some(i => i.id === cookieInvite.id && i.status === 'ready')) await chrome.storage.session.remove('cookieInvite');
  return { ...tab, remoteReady: !!state.agentAccess?.publicOrigin, invite: saved, invites };
}
async function createSessionInvite(message) {
  const tab = await sharingTab();
  if (message.tabId !== tab.tabId || message.site !== tab.site) throw new Error('The active website changed. Reopen the popup before sharing.');
  if (!await chrome.permissions.contains({ permissions: ['cookies'], origins: tab.permissionOrigins })) throw new Error('Allow cookie access for this website before sharing.');
  const store = (await chrome.cookies.getAllCookieStores()).find(s => s.tabIds.includes(tab.tabId));
  if (!store) throw new Error('Chrome could not identify this tab’s cookie store.');
  // URL + store scope excludes other profiles, sibling hosts and third parties.
  // The API defaults to unpartitioned cookies. Do not flatten CHIPS into ordinary cookies.
  const cookies = (await chrome.cookies.getAll({ url: tab.cookieURL, storeId: store.id }))
    .filter(c => !c.partitionKey && (c.session || c.expirationDate * 1000 > Date.now()));
  if (!cookies.length) throw new Error('No shareable cookies were found for this page. Sign in first, then try again.');
  const current = await sharingTab();
  if (current.tabId !== tab.tabId || current.cookieURL !== tab.cookieURL) throw new Error('The page changed during capture. Reopen the popup and try again.');
  const invite = await api('/api/extension/session-invites', { site: tab.site, cookies }, 10_000);
  // Only the short-lived invitation is kept for popup reopening. Cookie values
  // go directly to the local gateway and are never stored by the extension.
  await chrome.storage.session.set({ cookieInvite: invite });
  return invite;
}
chrome.runtime.onMessage.addListener((message, sender, respond) => {
  (async () => {
    const origin = sender.url ? new URL(sender.url).origin : '';
    const ownPage = sender.url?.startsWith(chrome.runtime.getURL(''));
    if (message.action === 'ping' && origin === gateway && sender.frameId === 0) {
      await attachmentReady;
      const { ownerToken } = await chrome.storage.local.get('ownerToken');
      return { value: { installed: true, version: chrome.runtime.getManifest().version, paired: !!ownerToken, enabled: attached, attachmentError } };
    }
    if (message.action === 'pair' && origin === gateway && sender.frameId === 0) {
      if (!/^[A-Za-z0-9_-]{43}$/.test(message.ownerToken)) throw new Error('Invalid owner token.');
      const response = await fetch(`${gateway}/api/owner/state`, { headers: { Authorization: `Bearer ${message.ownerToken}` } });
      if (!response.ok) throw new Error('The gateway rejected this owner token.');
      // Reconnecting the dashboard must not silently replace an OS selection.
      await chrome.storage.local.set({ ownerToken: message.ownerToken }); await syncAttachment();
      return { value: { paired: true, enabled: attached } };
    }
    if (!ownPage) throw new Error('Message not allowed.');
    if (['session-share-context', 'create-session-invite', 'revoke-session-invite'].includes(message.action)) {
      if (new URL(sender.url).pathname !== '/popup.html') throw new Error('Open the extension popup to share a session.');
      if (message.action === 'session-share-context') return { value: await sessionShareContext() };
      if (message.action === 'create-session-invite') return { value: await createSessionInvite(message) };
      if (!/^[a-f0-9]{24}$/.test(message.id)) throw new Error('Invalid session invite.');
      const result = await api(`/api/owner/session-invites/${message.id}/revoke`, {});
      const { cookieInvite } = await chrome.storage.session.get('cookieInvite');
      if (cookieInvite?.id === message.id) await chrome.storage.session.remove('cookieInvite');
      return { value: result };
    }
    if (message.action === 'use-os') return { value: await setProvider(false, message.id) };
    if (message.action === 'keepalive') return { value: pending.has(String(message.id)) };
    if (message.action === 'approval-details') {
      const r = pending.get(String(message.id)); if (!r) throw new Error('This request has expired.');
      const state = await api('/api/owner/state');
      const rpId = (r.operation === 'create' ? r.options.rp?.id : r.options.rpId) || new URL(r.origin).hostname;
      const accounts = state.vault.credentials.filter(c => c.rpId === rpId && (!r.options.allowCredentials?.length || r.options.allowCredentials.some(a => a.id === c.id)));
      const uv = r.operation === 'create' ? r.options.authenticatorSelection?.userVerification : r.options.userVerification;
      return { value: { operation: r.operation, origin: r.origin, rpId, account: r.options.user?.name,
        accounts, initialized: state.vault.initialized, unlocked: state.vault.unlocked, verifyUser: uv !== 'discouraged' } };
    }
    if (message.action === 'decision') {
      const r = pending.get(String(message.id)); if (!r || r.deciding) throw new Error('This request is no longer active.');
      if (!message.approved) { await complete(r.id, null, 'Passkey request declined.'); return { value: true }; }
      r.deciding = true;
      try {
        const value = await api('/api/extension/credential', { operation: r.operation, options: r.options, origin: r.origin,
          passphrase: message.passphrase, credentialId: message.credentialId });
        if (pending.has(r.id)) await complete(r.id, value);
      } catch (error) { r.deciding = false; throw error; }
      return { value: true };
    }
    if (message.action === 'status') {
      await attachmentReady;
      const { ownerToken } = await chrome.storage.local.get('ownerToken');
      let state = {}, gatewayError = '';
      try { state = await api('/api/owner/state', undefined, 1500); } catch (error) { gatewayError = error.message; }
      return { value: { ...state, paired: !!ownerToken, enabled: attached, gatewayError, attachmentError } };
    }
    if (message.action === 'toggle') {
      return { value: await setProvider(!!message.enabled) };
    }
    if (message.action === 'disconnect') { await setProvider(false); await chrome.storage.local.remove('ownerToken'); await chrome.storage.session.remove('cookieInvite'); return { value: true }; }
    throw new Error('Message not allowed.');
  })().then(respond, error => respond({ error: error.message }));
  return true;
});

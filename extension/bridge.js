(() => {
  if (location.origin !== 'http://127.0.0.1:4780' || window !== window.top) return;
  window.addEventListener('message', async event => {
    if (event.source !== window || event.origin !== location.origin || event.data?.channel !== 'passkey-proxy-request') return;
    const { id, action, ...payload } = event.data;
    if (!['pair', 'ping'].includes(action)) return;
    try {
      const result = await chrome.runtime.sendMessage({ action, id, ...payload });
      window.postMessage({ channel: 'passkey-proxy-response', id, ...result }, location.origin);
    } catch { window.postMessage({ channel: 'passkey-proxy-response', id, error: 'Extension unavailable. Reload this tab after loading the extension.' }, location.origin); }
  });
})();

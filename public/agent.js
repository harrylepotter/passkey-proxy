const $ = s => document.querySelector(s), fragment = new URLSearchParams(location.hash.slice(1));
// Opening another access link in the same tab can be a fragment-only navigation.
// Reinitialize the page rather than leaving the previous request on screen.
addEventListener('hashchange', () => {
  const next = new URLSearchParams(location.hash.slice(1));
  if (next.has('link') || next.has('invite')) location.reload();
});
if (fragment.has('invite') || fragment.has('link')) {
  for (const key of ['invite', 'agent-link', 'request-token']) sessionStorage.removeItem(key);
  sessionStorage.setItem(fragment.has('link') ? 'agent-link' : 'invite', fragment.get('link') || fragment.get('invite'));
  history.replaceState(null, '', '/agent');
}
let invite = sessionStorage.getItem('invite'), link = sessionStorage.getItem('agent-link'), requestToken = sessionStorage.getItem('request-token'), bundle;
let polling = false, login;
function notice(text, error = false) { $('#message').hidden = false; $('#message').textContent = text; $('#message').classList.toggle('error', error); }
async function api(path, secret, data) {
  const response = await fetch(path, { method: data === undefined ? 'GET' : 'POST', headers: { Authorization: `Bearer ${secret || ''}`, ...(data === undefined ? {} : { 'Content-Type': 'application/json' }) }, ...(data === undefined ? {} : { body: JSON.stringify(data) }) });
  const result = await response.json(); if (!response.ok) throw new Error(result.error); return result;
}
const descriptions = {
  pending: ['Waiting for approval', 'The owner can approve this request in their dashboard.'],
  authenticating: ['Signing your challenge', 'The vault is signing the website challenge approved by the owner.'],
  ready: ['Passkey response ready', 'Collect it once and finish the website login from the client that started it.'],
  redeemed: ['Passkey response already collected', 'This handoff has been consumed. Use your persistent link for a new request, or ask the owner for another invitation.'],
  denied: ['Access was declined', 'The owner declined this request or cancelled the handoff.'],
  cancelled: ['Request cancelled', 'Start a fresh challenge on the website before requesting another login.'],
  expired: ['This request expired', 'Use your persistent link to request again, or ask the owner for another invitation.'],
  failed: ['Sign-in needs attention', 'The owner can check the vault and retry in their dashboard.'],
};
function showTarget(target) {
  if (!target) return;
  if (target.login) login = target.login;
  $('#account-name').textContent = target.name;
  $('#account-detail').textContent = `${target.account} · ${new URL(target.site).hostname}`;
}
async function refresh() {
  if (!requestToken || polling) return;
  polling = true;
  const currentToken = requestToken;
  let request;
  try { request = await api('/api/agent/request', currentToken); }
  catch (error) {
    if (currentToken !== requestToken) return;
    if (link && error.message === 'Invalid request token.') {
      requestToken = null; sessionStorage.removeItem('request-token');
      await prepareRequest();
      notice('The previous request is no longer available. Submit a new request using this same link.');
      return;
    }
    throw error;
  } finally { polling = false; }
  if (currentToken !== requestToken) return;
  showTarget(request.target);
  $('#request-form').hidden = true; $('#request-status').hidden = !!bundle;
  $('#status').textContent = request.status; $('#status-heading').textContent = descriptions[request.status][0];
  $('#status-description').textContent = descriptions[request.status][1]; $('#request-purpose').textContent = request.purpose;
  $('#collect').hidden = request.status !== 'ready';
  $('#cancel-request').hidden = !['pending', 'ready', 'failed'].includes(request.status);
  $('#request-again').hidden = !link || !['redeemed', 'denied', 'cancelled', 'expired'].includes(request.status);
}
async function prepareRequest() {
  const target = await api('/api/agent/config', link || invite);
  showTarget(target);
  $('#ceremony-origin').value = target.login.origin;
  $('#login-flow').textContent = target.login.options ? `In your browser or HTTP client, request ${target.login.options.method} ${target.login.options.url}. Keep its cookies and CSRF state in that client. Paste ${target.login.options.responseField ? 'the ' + target.login.options.responseField + ' field' : 'the options JSON'} above. After collection, submit credential as ${target.login.verify.credentialField} to ${target.login.verify.url}${target.login.verify.contextField ? ', together with the original ' + target.login.verify.contextField : ''}.` : 'Start the website’s passkey login from your own browser or HTTP client using your available tools. Keep its challenge cookies and CSRF state in that client. Obtain fresh request options and identify how to submit the signed response before requesting approval. Read /instructions for the gateway protocol.';
  $('#reusable-note').hidden = !target.reusable;
  $('#request-form').hidden = false; $('#request-status').hidden = true;
  $('#status').textContent = target.reusable ? 'Persistent link active' : 'Invitation valid';
}
$('#request-again').onclick = async () => {
  try {
    await prepareRequest();
    requestToken = null; sessionStorage.removeItem('request-token'); bundle = null;
    $('#handoff').hidden = true; $('#bundle').value = ''; $('#collect').disabled = false;
    $('#request-again').hidden = true; $('#message').hidden = true; $('#ceremony-options').value = ''; $('#purpose').focus();
  } catch (error) { notice(error.message, true); }
};
$('#request-form').onsubmit = async event => {
  event.preventDefault(); const button = event.target.querySelector('button'); button.disabled = true;
  try {
    const result = await api('/api/agent/requests', link || invite, { agent: $('#agent-name').value, purpose: $('#purpose').value, ceremony: { origin: $('#ceremony-origin').value, options: JSON.parse($('#ceremony-options').value) } });
    requestToken = result.accessToken; sessionStorage.setItem('request-token', requestToken); sessionStorage.removeItem('invite'); invite = null;
    bundle = null; $('#handoff').hidden = true; $('#bundle').value = ''; $('#collect').disabled = false; $('#message').hidden = true;
    await refresh();
  } catch (error) { notice(error.message, true); } finally { button.disabled = false; }
};
$('#cancel-request').onclick = async () => {
  try { await api('/api/agent/cancel', requestToken, {}); await refresh(); } catch (error) { notice(error.message, true); }
};
$('#collect').onclick = async () => {
  $('#collect').disabled = true;
  try { bundle = await api('/api/agent/redeem', requestToken, {}); $('#bundle').value = JSON.stringify(bundle, null, 2); $('#target-link').href = bundle.site; $('#handoff').hidden = false; await refresh(); }
  catch (error) { notice(error.message, true); $('#collect').disabled = false; }
};
$('#download').onclick = () => {
  const url = URL.createObjectURL(new Blob([JSON.stringify(bundle, null, 2)], { type: 'application/json' }));
  const a = document.createElement('a'); a.href = url; a.download = `${new URL(bundle.site).hostname.replace(/[^a-z0-9.-]/gi, '')}-passkey-response.json`; a.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
};
$('#copy').onclick = async () => { try { await navigator.clipboard.writeText(JSON.stringify(bundle)); notice('Passkey response copied. Submit it to the website from your original client; keep it out of chat.'); } catch { $('#bundle').closest('details').open = true; $('#bundle').select(); notice('Select and copy the session JSON.'); } };
$('#technical-instructions').textContent = `Read ${location.origin}/instructions. GET /api/agent/config using the original #link= or #invite= token as a Bearer token. Start a fresh website passkey login from your own browser or HTTP client, retaining its cookies and CSRF state. POST /api/agent/requests with the link token and JSON {"agent":"your agent name","purpose":"your task","ceremony":{"origin":"the configured login origin","options":"the actual request-options object"}}. Poll /api/agent/request with the returned accessToken while the owner approves, then POST /api/agent/redeem with that token and JSON {}. Submit the returned credential to the website from the same client and verify the expected account. For a browser task, continue in that browser context. Keep tokens and signed responses out of chat. If a required operation is unavailable, report the specific step.`;
(async () => {
  try {
    if (link) { const target = await api('/api/agent/config', link); showTarget(target); $('#reusable-note').hidden = false; }
    if (requestToken) return await refresh();
    if (!invite && !link) throw new Error('Open an access link from the owner to request a session.');
    await prepareRequest();
  } catch (error) { notice(error.message, true); $('#status').textContent = 'Access link required'; }
})();
$('#connection-note').textContent = ['localhost', '127.0.0.1', '[::1]'].includes(location.hostname) ? 'Local preview. A remote agent browser needs the owner’s public HTTPS access link.' : 'Owner approval is required for every session. Your tools must complete the website’s WebAuthn login; the gateway does not transfer sessions.';
setInterval(() => refresh().catch(error => notice(error.message, true)), 2000);

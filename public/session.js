const $ = selector => document.querySelector(selector);
const fragment = new URLSearchParams(location.hash.slice(1));
addEventListener('hashchange', () => { if (new URLSearchParams(location.hash.slice(1)).has('session')) location.reload(); });
if (fragment.has('session')) {
  sessionStorage.setItem('cookie-session-invite', fragment.get('session'));
  history.replaceState(null, '', '/session');
}
const secret = sessionStorage.getItem('cookie-session-invite');
let bundle, expiryTimer;
function notice(text, error = false) { $('#message').hidden = false; $('#message').textContent = text; $('#message').classList.toggle('error', error); }
async function api(path, data) {
  const response = await fetch(path, { method: data === undefined ? 'GET' : 'POST', headers: { Authorization: `Bearer ${secret || ''}`, ...(data === undefined ? {} : { 'Content-Type': 'application/json' }) }, ...(data === undefined ? {} : { body: JSON.stringify(data) }) });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || 'The session invite is unavailable.');
  return result;
}
async function refresh() {
  const invite = await api('/api/agent/session');
  $('#session-site').textContent = invite.site;
  $('#session-details').textContent = `${invite.cookieCount} cookies · collection expires ${new Date(invite.expiresAt).toLocaleString()}`;
  const requirements = invite.importRequirements;
  $('#import-requirements').textContent = requirements
    ? requirements.requiresHttpOnlySupport
      ? `${requirements.httpOnlyCount} HttpOnly cookie${requirements.httpOnlyCount === 1 ? '' : 's'}: your browser needs a cookie-import API that preserves HttpOnly.`
      : 'No HttpOnly cookies in this invite. A permitted page-script import may work if it preserves the other cookie attributes.'
    : 'This older invite does not describe its cookie attributes. Request a fresh invite to inspect its import requirements.';
  $('#status').textContent = { ready: 'Ready to collect', collected: 'Collected', expired: 'Expired', revoked: 'Cancelled' }[invite.status] || invite.status;
  $('#collect-form').hidden = invite.status !== 'ready';
  clearTimeout(expiryTimer);
  if (invite.status === 'ready') expiryTimer = setTimeout(() => refresh().catch(error => notice(error.message, true)), Math.max(0, invite.expiresAt - Date.now() + 100));
}
$('#collect-form').onsubmit = async event => {
  event.preventDefault(); $('#collect-session').disabled = true;
  try {
    bundle = await api('/api/agent/session/redeem', { agent: $('#agent-name').value, purpose: $('#purpose').value });
    clearTimeout(expiryTimer); $('#collect-form').hidden = true; $('#status').textContent = 'Collected';
    $('#bundle').value = JSON.stringify(bundle, null, 2); $('#target-link').href = bundle.site; $('#handoff').hidden = false;
    $('#message').hidden = true;
  } catch (error) { notice(error.message, true); $('#collect-session').disabled = false; await refresh().catch(() => {}); }
};
$('#download').onclick = () => {
  if (!bundle) return;
  const url = URL.createObjectURL(new Blob([JSON.stringify(bundle, null, 2)], { type: 'application/json' }));
  const anchor = document.createElement('a'); anchor.href = url; anchor.download = `${new URL(bundle.site).hostname.replace(/[^a-z0-9.-]/gi, '')}-session.json`; anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
};
$('#copy').onclick = async () => {
  try { await navigator.clipboard.writeText(JSON.stringify(bundle)); notice('Session JSON copied. Keep it private.'); }
  catch { $('#bundle').closest('details').open = true; $('#bundle').select(); notice('Copy the selected session JSON and keep it private.'); }
};
$('#technical-instructions').textContent = `Read ${location.origin}/session-instructions. Use the #session token as Bearer authorization. GET /api/agent/session reads metadata only. POST /api/agent/session/redeem with JSON {"agent":"your agent name","purpose":"the owner’s task"} collects the cookies once. The token is not a passkey invitation. Do not call the passkey request endpoints.`;
if (secret) refresh().catch(error => { notice(error.message, true); $('#status').textContent = 'Unavailable'; });
else { notice('Open the session invite supplied by the owner.', true); $('#status').textContent = 'Invite required'; }

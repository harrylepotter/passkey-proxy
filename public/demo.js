const $ = s => document.querySelector(s), fragment = new URLSearchParams(location.hash.slice(1));
if (fragment.has('enroll')) { sessionStorage.setItem('enroll', fragment.get('enroll')); history.replaceState(null, '', '/'); }
let enroll = sessionStorage.getItem('enroll');
const decode = s => Uint8Array.from(atob(s.replaceAll('-', '+').replaceAll('_', '/')), c => c.charCodeAt(0));
const encode = b => btoa(String.fromCharCode(...new Uint8Array(b))).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
function options(json) {
  const result = { ...json, challenge: decode(json.challenge) };
  if (json.user) result.user = { ...json.user, id: decode(json.user.id) };
  for (const key of ['allowCredentials', 'excludeCredentials']) if (json[key]) result[key] = json[key].map(c => ({ ...c, id: decode(c.id) }));
  return result;
}
function credentialJSON(c) {
  if (c.toJSON) return c.toJSON();
  const response = {};
  for (const k of ['clientDataJSON', 'attestationObject', 'authenticatorData', 'signature', 'userHandle']) if (c.response[k]) response[k] = encode(c.response[k]);
  return { id: c.id, rawId: encode(c.rawId), type: c.type, response, clientExtensionResults: c.getClientExtensionResults() };
}
function notice(text, error = false) { $('#message').hidden = false; $('#message').textContent = text; $('#message').classList.toggle('error', error); }
async function api(path, data, registration = false) {
  const response = await fetch(path, { method: data === undefined ? 'GET' : 'POST', headers: { ...(data === undefined ? {} : { 'Content-Type': 'application/json' }), ...(registration ? { Authorization: `Bearer ${enroll}` } : {}) }, ...(data === undefined ? {} : { body: JSON.stringify(data) }) });
  const result = await response.json(); if (!response.ok) throw new Error(result.error); return result;
}
async function refresh() {
  try {
    const user = await api('/api/me'); $('#login').hidden = true; $('#account').hidden = false; $('#account').dataset.authenticated = 'true';
    $('#welcome').textContent = `Welcome back, ${user.name}.`; $('#email').textContent = user.email;
    $('#trips').replaceChildren(...user.trips.map((trip, i) => {
      const article = document.createElement('article'); article.className = `trip-card trip-${i}`;
      const art = document.createElement('div'); art.className = 'trip-art'; art.setAttribute('aria-hidden', 'true'); art.textContent = i ? '42° S' : '35° N';
      const content = document.createElement('div'); content.className = 'trip-content';
      for (const [tag, text] of [['span', trip.status], ['h3', trip.destination], ['p', trip.dates], ['small', `Booking ${trip.reference}`]]) { const el = document.createElement(tag); el.textContent = text; content.append(el); }
      article.append(art, content); return article;
    }));
  } catch {
    $('#login').hidden = false; $('#account').hidden = true; delete $('#account').dataset.authenticated;
    const config = await api('/api/config'); $('#sign-in').disabled = !config.registered;
    $('#registration-hint').textContent = config.registered ? 'Your passkey is ready to use.' : 'First, register a passkey using an invitation from the gateway owner.';
    $('#enrollment').hidden = !enroll;
  }
}
for (const [selector, registration] of [['#register', true], ['#sign-in', false]]) $(selector).onclick = async () => {
  const button = $(selector); button.disabled = true;
  try {
    const path = registration ? 'register' : 'auth', request = await api(`/api/${path}/options`, {}, registration);
    notice(registration ? 'Approve the registration in the extension window.' : 'Waiting for passkey authentication…');
    const credential = await navigator.credentials[registration ? 'create' : 'get']({ publicKey: options(request.publicKey) });
    await api(`/api/${path}/verify`, { ceremonyId: request.ceremonyId, credential: credentialJSON(credential) }, registration);
    if (registration) { sessionStorage.removeItem('enroll'); enroll = null; }
    notice(registration ? 'Passkey registered. Return to the gateway to invite your agent.' : 'Signed in with your passkey.'); await refresh();
  } catch (error) { notice(error.message, true); } finally { button.disabled = false; }
};
$('#logout').onclick = async () => { await api('/api/logout', {}); $('#message').hidden = true; await refresh(); };
refresh().catch(error => notice(error.message, true));

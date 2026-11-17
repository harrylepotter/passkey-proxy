const $ = s => document.querySelector(s);
const escape = value => String(value).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const hash = new URLSearchParams(location.hash.slice(1));
// Pasting the private link over this dashboard may only change the fragment.
// Reload so the new token is consumed before any owner requests or rendering.
addEventListener('hashchange', () => {
  if (new URLSearchParams(location.hash.slice(1)).has('owner')) location.reload();
});
if (hash.has('owner')) { sessionStorage.setItem('owner', hash.get('owner')); history.replaceState(null, '', '/'); }
let ownerToken = sessionStorage.getItem('owner'), state, lastVault = '', lastRequests = '', lastAudit = '', paired = false, registeredBefore;
let preferredAccount;
function notice(text, error = false) { $('#message').hidden = false; $('#message').textContent = text; $('#message').classList.toggle('error', error); }
function targetChanged() {
  const credential = state?.vault.credentials.find(c => c.id === $('#target-account').value);
  $('#target-site-field').hidden = !credential;
  if (credential) { $('#target-site').value = `https://${credential.rpId}`; $('#target-login').value = state.loginDefaults?.[credential.rpId] || credential.origin; }
}
function requestCard(r, unlocked) {
  const target = r.target || { name: 'Demo Travel', account: 'user@example.test' };
  const pending = ['pending', 'failed'].includes(r.status);
  const status = { pending: 'Needs approval', authenticating: 'Signing challenge…', ready: 'Response ready', redeemed: 'Collected', failed: 'Needs attention', denied: 'Denied', cancelled: 'Cancelled', expired: 'Expired' }[r.status];
  return `<article class="request-card"><div class="request-top"><div class="agent-avatar">↗</div><div><h3>${escape(r.agent)}</h3><p class="muted">${escape(target.name)} · ${escape(target.account)}</p></div><span class="status ${['ready', 'redeemed'].includes(r.status) ? 'success' : ''}">${escape(status)}</span></div>${r.requestNumber ? `<p class="fine-print">${escape(r.linkLabel)} · Request #${r.requestNumber}</p>` : ''}<p class="purpose">${escape(r.purpose)}</p><p class="fine-print">Approve a passkey signature for ${escape(target.rpId || 'localhost')}. The agent completes its own website login. Agent identity is self-reported; the task does not limit the account's permissions.</p>${r.error ? `<p class="error-text">${escape(r.error)}</p>` : ''}${pending ? `<label for="verify-${r.id}">Vault passphrase for this sign-in</label><input id="verify-${r.id}" type="password" autocomplete="off" data-passphrase="${r.id}" placeholder="Verify to approve this challenge"><div class="button-row"><button data-id="${r.id}" data-action="approve" ${unlocked ? '' : 'disabled'}>Approve passkey sign-in</button><button class="secondary" data-id="${r.id}" data-action="deny">Deny</button></div>${unlocked ? '' : '<p class="fine-print">Unlock your vault to approve.</p>'}` : r.status === 'ready' ? `<p class="muted">The agent must collect the response and finish the website login before the challenge expires.</p><button class="secondary small-button" data-id="${r.id}" data-action="deny">Cancel handoff</button>` : r.status === 'redeemed' ? '<p class="muted">Passkey response collected. The agent must submit it to the website and confirm login succeeded.</p>' : ''}</article>`;
}
async function api(path, data) {
  const response = await fetch(path, { method: data === undefined ? 'GET' : 'POST', headers: { Authorization: `Bearer ${ownerToken || ''}`, ...(data === undefined ? {} : { 'Content-Type': 'application/json' }) }, ...(data === undefined ? {} : { body: JSON.stringify(data) }) });
  const result = await response.json();
  if (!response.ok) { if (response.status === 401) { $('#owner-login').hidden = false; $('#workspace').hidden = true; } throw new Error(result.error); }
  return result;
}
const extension = (action, payload = {}, timeout = 1500) => new Promise((resolve, reject) => {
  const id = crypto.randomUUID();
  const listener = event => {
    if (event.source !== window || event.origin !== location.origin || event.data?.channel !== 'passkey-proxy-response' || event.data.id !== id) return;
    clearTimeout(timer); window.removeEventListener('message', listener);
    event.data.error ? reject(new Error(event.data.error)) : resolve(event.data.value);
  };
  const timer = setTimeout(() => { window.removeEventListener('message', listener); reject(new Error('Load the extension and reload this page, then connect again.')); }, timeout);
  window.addEventListener('message', listener); window.postMessage({ channel: 'passkey-proxy-request', id, action, ...payload }, location.origin);
});
function render() {
  const { vault, demo, requests, audit } = state;
  if (registeredBefore === false && demo.registered) notice('Passkey registered. Create an invitation to let an agent request a session.');
  registeredBefore = demo.registered;
  $('#owner-login').hidden = true; $('#workspace').hidden = false;
  $('#vault-heading').textContent = vault.unlocked ? 'Your vault is ready.' : vault.initialized ? 'Your keys are safely locked.' : 'Create your private vault.';
  $('#vault-description').textContent = vault.unlocked ? 'Approve a passkey challenge so the agent can sign in. Your private key stays here.' : 'Unlock your vault to register passkeys and approve agent access.';
  $('#vault-badge').textContent = vault.unlocked ? '● Unlocked' : vault.initialized ? '● Locked' : '○ Not set up';
  $('#lock').hidden = !vault.unlocked; $('#vault-setup-link').hidden = vault.unlocked;
  $('#vault-setup-link').textContent = vault.initialized ? 'Unlock vault ↗' : 'Set up vault ↗';
  $('#account-count').textContent = vault.unlocked ? String(vault.credentials.length) : 'Locked';
  const external = vault.credentials.filter(c => c.rpId !== 'localhost');
  const externalKey = JSON.stringify(external);
  if ($('#external-passkeys').dataset.contents !== externalKey) {
    $('#external-passkeys').dataset.contents = externalKey;
    $('#external-passkeys').innerHTML = external.map(c => `<div class="request-card"><h3>${escape(c.rpName || c.rpId)}</h3><p class="muted">${escape(c.userName)}</p><p class="fine-print">${escape(c.rpId)} · stored in vault</p></div>`).join('');
  }
  $('#credential-status').textContent = demo.registered ? 'stored in vault' : 'Not registered';
  $('#register').hidden = demo.registered; $('#register').disabled = !vault.unlocked;
  const targets = [...external.map(c => ({ id: c.id, name: `${c.rpName || c.rpId} · ${c.userName}` })), ...(demo.registered ? [{ id: 'demo', name: 'Demo Travel · local demo' }] : [])];
  const targetKey = JSON.stringify(targets);
  if ($('#target-account').dataset.contents !== targetKey) {
    const selected = preferredAccount;
    $('#target-account').dataset.contents = targetKey;
    $('#target-account').replaceChildren(...targets.map(t => { const option = document.createElement('option'); option.value = t.id; option.textContent = t.name; return option; }));
    if (targets.some(t => t.id === selected)) $('#target-account').value = selected;
    targetChanged();
  }
  $('#invite').disabled = !vault.unlocked || !targets.length || !state.agentAccess;
  $('#target-account').disabled = !vault.unlocked;
  const links = state.links || [], linksKey = JSON.stringify(links);
  $('#agent-links-section').hidden = !links.length;
  if ($('#agent-links').dataset.contents !== linksKey) {
    $('#agent-links').dataset.contents = linksKey;
    $('#agent-links').innerHTML = links.map(link => `<article class="request-card"><h3>${escape(link.label)}</h3><p class="muted">${escape(link.target.name)} · ${escape(link.target.account)}</p><p class="fine-print">${link.requestCount} request${link.requestCount === 1 ? '' : 's'} · ${link.revokedAt !== null ? 'Revoked' : 'Active until revoked'}</p>${link.revokedAt === null ? `<button class="secondary small-button" data-revoke="${link.id}">Revoke link</button>` : ''}</article>`).join('');
  }
  $('#remote-status').textContent = state.agentAccess?.publicOrigin ? `Remote agent link ready: ${state.agentAccess.publicOrigin}` : 'Remote sharing is off. Your agent needs a public HTTPS invitation; Local preview stays on this machine.';
  $('#demo-link').href = demo.origin;
  const vaultKey = `${vault.initialized}/${vault.unlocked}`;
  if (lastVault !== vaultKey) {
    lastVault = vaultKey;
    $('#vault-form-container').innerHTML = vault.unlocked ? '<p class="muted">Your vault is unlocked for up to 15 minutes. It locks automatically when the server restarts.</p><span class="status success">Ready for approved requests</span>' :
      `<p class="muted">${vault.initialized ? 'Enter your passphrase to allow approved sign-ins.' : 'Choose a passphrase of at least 12 characters. Keep it for your next session.'}</p><form id="vault-form"><label class="sr-only" for="passphrase">Vault passphrase</label><input id="passphrase" name="passphrase" type="password" autocomplete="${vault.initialized ? 'current-password' : 'new-password'}" minlength="12" maxlength="1024" required placeholder="Vault passphrase"><button>${vault.initialized ? 'Unlock vault' : 'Create encrypted vault'}</button></form>`;
    $('#vault-form')?.addEventListener('submit', async event => {
      event.preventDefault(); const button = event.target.querySelector('button'); button.disabled = true;
      try { await api(`/api/owner/vault/${state.vault.initialized ? 'unlock' : 'setup'}`, { passphrase: $('#passphrase').value }); $('#passphrase').value = ''; notice('Vault unlocked. You can now connect the extension and register a passkey.'); await refresh(); }
      catch (error) { notice(error.message, true); } finally { button.disabled = false; }
    });
  }
  const requestKey = JSON.stringify(requests.map(r => ({ ...r, unlocked: vault.unlocked })));
  if (lastRequests !== requestKey) {
    lastRequests = requestKey;
    if (requests.length) $('#requests').innerHTML = requests.map(r => requestCard(r, vault.unlocked)).join('');
  }
  const auditKey = JSON.stringify(audit);
  if (lastAudit !== auditKey) { lastAudit = auditKey; if (audit.length) $('#activity').innerHTML = audit.slice(0, 12).map(a => `<div class="activity-row"><span class="activity-dot"></span><div><strong>${escape(a.event)}</strong><p>${escape(a.detail)}</p></div><time>${new Date(a.at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</time></div>`).join(''); }
}
async function refresh() {
  if (!ownerToken) { $('#owner-login').hidden = false; return; }
  const next = await api('/api/owner/state');
  // Avoid rewriting unchanged DOM every poll: browser agents wait for it to settle.
  if (JSON.stringify(next) !== JSON.stringify(state) || $('#workspace').hidden) { state = next; render(); }
}
$('#owner-form').onsubmit = async event => {
  event.preventDefault();
  let value = $('#owner-input').value.trim();
  try {
    if (!/^[A-Za-z0-9_-]{43}$/.test(value)) {
      let link;
      try { link = new URL(value); } catch {}
      if (!link || link.origin !== location.origin || link.pathname !== '/' || link.username || link.password || link.search) throw new Error('Paste the private owner link from .data/owner-url.txt, or its owner token.');
      value = new URLSearchParams(link.hash.slice(1)).get('owner') || '';
      if (!/^[A-Za-z0-9_-]{43}$/.test(value)) throw new Error('This link does not contain an owner token. Use .data/owner-url.txt.');
    }
    ownerToken = value; sessionStorage.setItem('owner', ownerToken); $('#owner-input').value = '';
    await refresh();
    $('#message').hidden = true; $('#message').textContent = ''; $('#message').classList.remove('error');
  } catch (error) { notice(error.message, true); }
};
$('#lock').onclick = async () => { try { await api('/api/owner/vault/lock', {}); await refresh(); } catch (error) { notice(error.message, true); } };
$('#pair').onclick = async () => {
  try { const result = await extension('pair', { ownerToken }, 5000); paired = true; $('#extension-badge').textContent = result.enabled ? 'Extension connected' : 'OS passkeys active'; $('#extension-badge').classList.add('success'); notice(result.enabled ? 'Extension connected across websites. Add a passkey in any site’s account settings, or try the demo below.' : 'Extension connected. OS passkeys remain active. Choose “Use vault passkeys” in the extension menu when you want to use the vault.'); }
  catch (error) { notice(error.message, true); }
};
$('#register').onclick = async () => {
  try {
    if (!paired) { await extension('pair', { ownerToken }, 5000); paired = true; $('#extension-badge').textContent = 'Extension connected'; }
    if (!(await extension('ping')).enabled) throw new Error('OS passkeys are active. Choose “Use vault passkeys” in the extension menu, then retry vault registration.');
    const { url } = await api('/api/owner/enrollment', {});
    const a = document.createElement('a'); a.href = url; a.target = '_blank'; a.rel = 'noreferrer'; a.click();
    notice('Finish registration in the Demo Travel tab and approve it in the extension window.');
  } catch (error) { notice(error.message, true); }
};
$('#invite').onclick = async () => {
  $('#invite').disabled = true;
  try {
    const { url, target, remote, reusable } = await api('/api/owner/invites', { credentialId: $('#target-account').value, site: $('#target-site').value, loginUrl: $('#target-login').value, localPreview: $('#local-preview').checked, reusable: $('#reusable-link').checked, label: $('#link-label').value });
    $('#invitation').hidden = false; $('#open-agent').href = url;
    $('#invitation-summary').textContent = reusable ? 'Save these instructions now. This link can request access again until you revoke it. Every request needs approval.' : 'This invitation allows one request and expires in one hour.';
    $('#invite-text').value = `Use my ${target.name} account (${target.account}) at ${target.site} for the task I give you.

Sign-in page: ${target.loginUrl || target.site}
Approved sign-in origin: ${target.authenticationOrigin || new URL(target.loginUrl || target.site).origin}

${remote ? '' : 'LOCAL PREVIEW — only reachable on this machine.\n\n'}${reusable ? 'Save this persistent access link privately' : 'Open this one-use invitation'}: ${url}

Read the instructions at ${new URL(url).origin}/instructions and GET /api/agent/config using the token in this link. Start a fresh passkey login on the website from your own browser or HTTP client. Keep its challenge cookies and CSRF state in that same client.

Request access as your agent name, stating the task and supplying ceremony: {origin, options} from that login. Wait for my approval, then collect the signed WebAuthn response once and submit its credential to the website from the same client. The website creates your session there; this passkey gateway provides no browser cookies. Verify the expected account is signed in before doing the task. For a browser task, keep using that same browser context.

If your tools cannot obtain and complete a WebAuthn challenge, report that limitation instead of requesting cookies, my passphrase or owner token. Keep link tokens and signed responses out of chat. ${reusable ? 'When the website logs you out, reuse this link with a fresh challenge and new approval. You may save a verified per-site recipe without transient secrets.' : 'This invitation allows one request and expires in one hour.'} A challenge request expires after two minutes, or earlier if the website expires it.`;
    notice(`${reusable ? 'Persistent link' : 'Invitation'} created for ${target.name}. Copy the instructions to your agent.`);
    await refresh();
  } catch (error) { notice(error.message, true); }
  finally { render(); }
};
$('#reusable-link').onchange = () => {
  $('#link-label-field').hidden = !$('#reusable-link').checked;
  $('#invite').textContent = $('#reusable-link').checked ? 'Create agent link ↗' : 'Create invitation ↗';
};
$('#agent-links').onclick = async event => {
  const button = event.target.closest('button[data-revoke]'); if (!button) return;
  button.disabled = true;
  try { await api(`/api/owner/links/${button.dataset.revoke}/revoke`, {}); notice('Link revoked. Future requests and uncollected handoffs are blocked.'); await refresh(); }
  catch (error) { notice(error.message, true); button.disabled = false; }
};
$('#target-account').onchange = () => { preferredAccount = $('#target-account').value; targetChanged(); };
$('#agent-origin-form').onsubmit = async event => { event.preventDefault(); try { await api('/api/owner/agent-origin', { origin: $('#agent-origin').value.trim() }); await refresh(); notice('Agent gateway URL saved. Existing links need this same public hostname to stay reachable.'); } catch (error) { notice(error.message, true); } };
$('#copy-invite').onclick = async () => { try { await navigator.clipboard.writeText($('#invite-text').value); notice('Agent instructions copied.'); } catch { $('#invite-text').select(); notice('Select and copy the instructions above.'); } };
$('#requests').onclick = async event => {
  const button = event.target.closest('button[data-action]'); if (!button) return;
  button.disabled = true;
  const input = document.querySelector(`input[data-passphrase="${button.dataset.id}"]`); const passphrase = input?.value; if (input) input.value = '';
  try { await api(`/api/owner/requests/${button.dataset.id}/${button.dataset.action}`, { passphrase: button.dataset.action === 'approve' ? passphrase : undefined }); notice(button.dataset.action === 'approve' ? 'Passkey response ready. The agent must collect it and complete its website login.' : 'Access request denied.'); await refresh(); }
  catch (error) { notice(error.message, true); button.disabled = false; }
};
refresh().catch(error => notice(error.message, true));
setInterval(() => refresh().catch(() => {}), 2000);
extension('ping').then(result => { paired = result.paired; $('#extension-badge').textContent = result.attachmentError || (result.enabled ? 'Vault passkeys active' : result.paired ? 'OS passkeys active' : 'Extension detected'); }).catch(() => { $('#extension-badge').textContent = 'Extension not loaded'; });

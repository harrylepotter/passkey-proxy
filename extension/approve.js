const id = location.hash.slice(1), $ = s => document.querySelector(s);
// Keep this user-visible ceremony alive while the owner reads or types. MV3
// workers otherwise suspend after an idle period and lose in-memory requests.
const heartbeat = setInterval(() => chrome.runtime.sendMessage({ action: 'keepalive', id }).then(result => {
  if (!result.value) { clearInterval(heartbeat); $('#error').textContent = 'This request has expired. Retry on the website.'; $('#approve').disabled = true; }
}).catch(() => clearInterval(heartbeat)), 20000);
addEventListener('pagehide', () => clearInterval(heartbeat));
let needsPassphrase = true, switchingProvider = false;
async function details() {
  const result = await chrome.runtime.sendMessage({ action: 'approval-details', id });
  if (switchingProvider) return;
  if (result.error) throw new Error(result.error);
  const { operation, origin, rpId, account, accounts, initialized, unlocked, verifyUser } = result.value;
  $('#title').textContent = operation === 'create' ? 'Save a passkey?' : 'Use your passkey?';
  $('#description').textContent = operation === 'create' ? `Create a passkey for ${rpId} in your encrypted vault.` : `Sign in to ${rpId} with a vault passkey.`;
  $('#origin').textContent = origin; $('#account').textContent = account || accounts[0]?.userName || 'Choose the matching account from your vault';
  $('#credential').replaceChildren(...accounts.map(c => { const option = document.createElement('option'); option.value = c.id; option.textContent = c.userName; return option; }));
  $('#account-select').hidden = operation === 'create' || accounts.length < 2;
  needsPassphrase = verifyUser || !unlocked;
  $('#verification').hidden = !needsPassphrase; $('#passphrase').required = needsPassphrase;
  const noMatch = operation === 'get' && unlocked && accounts.length === 0;
  $('#approve').disabled = !initialized || noMatch;
  if (!initialized) $('#error').textContent = 'Create your vault in the owner dashboard first, then retry.';
  else if (noMatch) $('#error').textContent = 'No matching passkey in this vault. Use OS passkeys for a credential stored with another provider.';
}
details().catch(error => { $('#error').textContent = error.message; });
$('#approval-form').onsubmit = async event => {
  event.preventDefault(); $('#approve').disabled = true; $('#deny').disabled = true; $('#use-os').disabled = true; $('#error').textContent = '';
  const passphrase = needsPassphrase ? $('#passphrase').value : undefined; $('#passphrase').value = '';
  const result = await chrome.runtime.sendMessage({ action: 'decision', id, approved: true, passphrase, credentialId: $('#credential').value || undefined });
  if (result.error) { await details().catch(() => {}); $('#error').textContent = result.error; $('#deny').disabled = false; $('#use-os').disabled = false; $('#passphrase').focus(); }
};
$('#deny').onclick = () => chrome.runtime.sendMessage({ action: 'decision', id, approved: false });
$('#use-os').onclick = async () => {
  switchingProvider = true; $('#use-os').disabled = true; $('#approve').disabled = true; $('#deny').disabled = true;
  $('#passphrase').value = ''; $('#error').textContent = '';
  try {
    const result = await chrome.runtime.sendMessage({ action: 'use-os', id });
    if (result.error) throw new Error(result.error);
    clearInterval(heartbeat);
    $('#title').textContent = 'OS passkeys are on';
    $('#description').textContent = 'Chrome now handles passkeys using its usual providers.';
    $('.provider-choice').hidden = true; $('#approval-form').hidden = true; $('#request-details').hidden = true; $('#os-selected').hidden = false;
    $('#done').focus();
  } catch (error) { switchingProvider = false; $('#error').textContent = error.message; $('#use-os').disabled = false; $('#deny').disabled = false; }
};
$('#done').onclick = () => window.close();

let enabled = false;
async function refresh() {
  const result = await chrome.runtime.sendMessage({ action: 'status' });
  if (result.error) { document.querySelector('#error').textContent = result.error; return; }
  enabled = result.value.enabled;
  document.querySelector('#status').textContent = enabled ? `Vault passkeys active${result.value.vault ? ` · ${result.value.vault.unlocked ? 'unlocked' : 'locked'}` : ''}` : 'OS passkeys active';
  document.querySelector('#toggle').textContent = enabled ? 'Use OS passkeys' : 'Use vault passkeys';
  document.querySelector('#toggle').disabled = !enabled && !result.value.paired;
  document.querySelector('#error').textContent = result.value.attachmentError || (enabled ? result.value.gatewayError : '') || '';
  document.querySelector('#provider-note').textContent = !result.value.paired ? 'Connect the extension from the dashboard to enable vault passkeys.' : 'After switching, retry the website’s passkey button.';
}
refresh();
document.querySelector('#toggle').onclick = async () => {
  document.querySelector('#toggle').disabled = true;
  const result = await chrome.runtime.sendMessage({ action: 'toggle', enabled: !enabled });
  await refresh();
  if (result.error) document.querySelector('#error').textContent = result.error;
};
document.querySelector('#disconnect').onclick = async () => { await chrome.runtime.sendMessage({ action: 'disconnect' }); window.close(); };

let shareContext, sharing = false;
const $ = selector => document.querySelector(selector);
const send = async message => { const result = await chrome.runtime.sendMessage(message); if (result.error) throw new Error(result.error); return result.value; };
function showSessionInvite(invite) {
  $('#session-result').hidden = !invite;
  if (!invite) { $('#session-instructions').value = ''; return; }
  $('#session-summary').textContent = `Ready · ${invite.cookieCount} cookies · collect by ${new Date(invite.expiresAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`;
  $('#session-instructions').value = `Use my signed-in session at ${invite.site} for the task I give you.

Open: ${invite.url}

Open the invite in your existing task browser and read its details and ${new URL(invite.url).origin}/session-instructions. Then use your available tools to collect the shared session, import it into that browser context, and verify which account is signed in. Keep using that same browser context for the task. If a step is unavailable or fails, identify the exact operation and result.

This is a cookie-session invite. I have already approved one collection; no passkey or additional approval is needed. It expires at ${new Date(invite.expiresAt).toISOString()}. Keep the invite and cookie values out of chat.`;
}
async function refreshSharing() {
  if (sharing) return;
  try {
    shareContext = await send({ action: 'session-share-context' });
    $('#share-site').textContent = shareContext.site;
    $('#share-session').disabled = !shareContext.remoteReady;
    $('#share-error').textContent = shareContext.remoteReady ? '' : 'Start remote sharing or configure the public agent gateway URL in the dashboard first.';
    showSessionInvite(shareContext.invite);
    $('#session-invites').replaceChildren(...shareContext.invites.filter(i => i.status === 'ready').map(invite => {
      const row = document.createElement('div'); row.className = 'session-invite-row';
      const label = document.createElement('span'); label.textContent = `${invite.cookieCount} cookies · expires ${new Date(invite.expiresAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`;
      const button = document.createElement('button'); button.className = 'secondary'; button.textContent = 'Cancel invite';
      button.onclick = async () => {
        button.disabled = true;
        try { await send({ action: 'revoke-session-invite', id: invite.id }); await refreshSharing(); }
        catch (error) { $('#share-error').textContent = error.message; button.disabled = false; }
      };
      row.append(label, button); return row;
    }));
  } catch (error) { shareContext = null; $('#share-site').textContent = 'Session sharing unavailable'; $('#share-error').textContent = error.message; $('#share-session').disabled = true; showSessionInvite(null); }
}
$('#share-session').onclick = async () => {
  if (!shareContext || sharing) return;
  sharing = true; $('#share-session').disabled = true; $('#share-error').textContent = ''; $('#copy-status').textContent = '';
  try {
    // Parent-domain cookies need parent-domain permission too. No wildcards or
    // public/private suffixes are requested. Capture remains scoped to the page.
    const granted = await chrome.permissions.request({ permissions: ['cookies'], origins: shareContext.permissionOrigins });
    if (!granted) throw new Error('Cookie access was not granted. No session invite was created.');
    const invite = await send({ action: 'create-session-invite', tabId: shareContext.tabId, site: shareContext.site });
    showSessionInvite(invite);
  } catch (error) { $('#share-error').textContent = error.message; }
  finally { sharing = false; $('#share-session').disabled = !shareContext?.remoteReady; }
  if (!$('#share-error').textContent) await refreshSharing();
};
$('#copy-session').onclick = async () => {
  try { await navigator.clipboard.writeText($('#session-instructions').value); $('#copy-status').textContent = 'Invite instructions copied.'; }
  catch { $('#session-instructions').select(); $('#copy-status').textContent = 'Press Copy to copy the selected instructions.'; }
};
refreshSharing();
setInterval(refreshSharing, 5000);

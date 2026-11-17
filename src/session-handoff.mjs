import { validateScope } from './vault.mjs';
import { validateCookieSession } from './session-invites.mjs';

export const defaultLoginUrls = Object.freeze({});
export function defaultLoginUrl(credential) { return defaultLoginUrls[credential.rpId] || credential.origin || credential.site; }

export function websiteTarget(credential, site = credential?.origin, loginUrl) {
  if (!credential) throw new Error('Select a passkey from your unlocked vault.');
  const url = new URL(site);
  if (url.protocol !== 'https:' || url.username || url.password) throw new Error('Use an HTTPS website address.');
  validateScope(url.origin, credential.rpId);
  const login = new URL(loginUrl || defaultLoginUrl(credential) || url.origin);
  if (login.protocol !== 'https:' || login.username || login.password || login.hash) throw new Error('Use an HTTPS sign-in page on the selected website.');
  validateScope(login.origin, credential.rpId);
  return { kind: 'passkey-login', credentialId: credential.id, rpId: credential.rpId,
    name: credential.rpName || credential.rpId, account: credential.userName, site: url.origin, loginUrl: login.href, authenticationOrigin: login.origin };
}

export function cookiesForSite(cookies, rpId, now = Date.now()) {
  return cookies.filter(cookie => {
    const domain = cookie.domain.replace(/^\./, '');
    return (domain === rpId || domain.endsWith(`.${rpId}`)) && (cookie.expires <= 0 || cookie.expires * 1000 > now);
  });
}

export function validateSessionBundle(bundle) {
  if (bundle?.format === 'passkey-proxy/cookie-session-v1') return validateCookieSession(bundle);
  if (bundle?.format !== 'passkey-proxy/session-v1' || !Array.isArray(bundle.storageState?.cookies)) throw new Error('Invalid session bundle.');
  const url = new URL(bundle.site);
  if (url.username || url.password || (url.protocol !== 'https:' && url.origin !== 'http://localhost:4781')) throw new Error('Unexpected destination website.');
  const rpId = bundle.rpId || url.hostname;
  validateScope(url.origin, rpId);
  if (bundle.sessionExpiresAt && (!Number.isFinite(Date.parse(bundle.sessionExpiresAt)) || Date.parse(bundle.sessionExpiresAt) <= Date.now())) throw new Error('The session has expired.');
  if (cookiesForSite(bundle.storageState.cookies, rpId).length !== bundle.storageState.cookies.length) throw new Error('The bundle includes expired cookies or cookies outside the approved site.');
  if (bundle.storageState.origins?.length) throw new Error('This importer accepts cookie-only session bundles.');
  return bundle;
}

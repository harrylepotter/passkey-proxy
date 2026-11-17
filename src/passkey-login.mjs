import { createHash } from 'node:crypto';
import { validateScope } from './vault.mjs';
import { defaultLoginUrl } from './session-handoff.mjs';

export function loginConfiguration(target) {
  const demo = target.kind === 'demo' || target.demo === true;
  const loginUrl = target.loginUrl || defaultLoginUrl(target);
  const origin = target.authenticationOrigin || new URL(loginUrl).origin;
  const login = { origin, rpId: target.rpId, loginUrl, adapter: 'webauthn-tools' };
  if (demo) Object.assign(login, { adapter: 'demo', options: { url: `${origin}/api/auth/options`, method: 'POST', responseField: 'publicKey' }, verify: { url: `${origin}/api/auth/verify`, method: 'POST', credentialField: 'credential', contextField: 'ceremonyId' } });
  return login;
}

export function validateCeremony(target, input) {
  const login = loginConfiguration(target);
  if (!input || input.origin !== login.origin) throw new Error('Provide the WebAuthn request from the configured sign-in origin.');
  validateScope(input.origin, target.rpId);
  const options = input.options;
  if (!options || typeof options !== 'object' || Array.isArray(options)) throw new Error('Provide the website’s WebAuthn request options.');
  if (typeof options.challenge !== 'string' || !/^[A-Za-z0-9_-]{22,1366}$/.test(options.challenge) || Buffer.from(options.challenge, 'base64url').toString('base64url') !== options.challenge || Buffer.from(options.challenge, 'base64url').length < 16) throw new Error('Invalid WebAuthn challenge.');
  if ((options.rpId || new URL(input.origin).hostname) !== target.rpId) throw new Error('The challenge is for a different relying party.');
  if (options.allowCredentials !== undefined && (!Array.isArray(options.allowCredentials) || options.allowCredentials.some(c => c?.type !== 'public-key' || typeof c.id !== 'string'))) throw new Error('Invalid allowed credentials.');
  if (options.allowCredentials?.length && !options.allowCredentials.some(c => c.id === target.credentialId)) throw new Error('The website did not allow the selected vault passkey.');
  if (options.userVerification !== undefined && !['required', 'preferred', 'discouraged'].includes(options.userVerification)) throw new Error('Invalid user verification requirement.');
  if (options.extensions?.remoteDesktopClientOverride || input.crossOrigin === true) throw new Error('Caller origin overrides and cross-origin ceremonies are not accepted.');
  // Copy only WebAuthn fields. Cookies, headers, passwords and arbitrary caller
  // flags never become part of the signing request or its approval metadata.
  return { origin: input.origin, options: { challenge: options.challenge, rpId: target.rpId,
    ...(options.allowCredentials ? { allowCredentials: structuredClone(options.allowCredentials) } : {}),
    userVerification: options.userVerification || 'preferred', extensions: structuredClone(options.extensions || {}) } };
}

export const ceremonyDigest = (target, ceremony) => createHash('sha256').update(JSON.stringify([target.credentialId, target.rpId, ceremony.origin, ceremony.options.challenge])).digest('hex');

export function signLogin(vault, request, passphrase) {
  const ceremony = validateCeremony(request.target, request.ceremony);
  if (typeof passphrase !== 'string' || !passphrase) throw new Error('Verify with your vault passphrase to approve this sign-in.');
  vault.verifyUser(passphrase);
  const credential = vault.authenticate(ceremony.options, ceremony.origin, { credentialId: request.target.credentialId, userVerified: true });
  return { format: 'passkey-proxy/webauthn-v1', site: request.target.site, account: request.target.account, name: request.target.name,
    rpId: request.target.rpId, origin: ceremony.origin, credential,
    instructions: 'Submit credential to the website using the same browser context or HTTP cookie jar that requested this challenge. Keep the website’s challenge cookies and CSRF state on your side. The website creates your session after it verifies the assertion. This response contains no browser cookies. Do not reuse it for another challenge or print it in chat.' };
}

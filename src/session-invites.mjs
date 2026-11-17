import { createHash, randomBytes } from 'node:crypto';
import { getDomain } from 'tldts';
const token = () => randomBytes(32).toString('base64url');
const digest = value => createHash('sha256').update(value || '').digest('hex');

export const SESSION_INVITE_TTL = 10 * 60_000;
const format = 'passkey-proxy/cookie-session-v1';
const sameSites = { strict: 'Strict', lax: 'Lax', no_restriction: 'None', unspecified: undefined };
const invalid = () => { throw new Error('Invalid or out-of-scope session cookies.'); };

export function sessionSite(value) {
  let url;
  try { url = new URL(value); } catch { throw new Error('Open a website before sharing a session.'); }
  if (!['https:', 'http:'].includes(url.protocol) || url.username || url.password || url.search || url.hash || url.pathname !== '/') {
    throw new Error('Use a website origin without credentials, a path, or private URL parameters.');
  }
  return url.origin;
}

function cookieDomain(domain, host, hostOnly) {
  if (typeof domain !== 'string' || domain.length > 253 || domain !== domain.toLowerCase()) invalid();
  const bare = domain.replace(/^\./, '');
  const ipv6 = bare === host && host.startsWith('[') && host.endsWith(']');
  if (!bare || (!ipv6 && /[\s/\\:?#@]/.test(bare)) || (hostOnly && domain.startsWith('.'))) invalid();
  if (hostOnly ? bare !== host : bare !== host && !host.endsWith(`.${bare}`)) invalid();
  if (!hostOnly && bare !== 'localhost' && !getDomain(bare, { allowPrivateDomains: true, extractHostname: false })) invalid();
  return hostOnly ? bare : `.${bare}`;
}

export function captureSession(siteValue, input, now = Date.now()) {
  const site = sessionSite(siteValue), url = new URL(site);
  if (!Array.isArray(input) || !input.length || input.length > 400 || Buffer.byteLength(JSON.stringify(input)) > 524288) invalid();
  const seen = new Set();
  const cookies = input.map(c => {
    if (!c || typeof c.name !== 'string' || typeof c.value !== 'string' || c.name.length > 1024 || c.value.length > 16384 ||
        /[\x00-\x20\x7f;=]/.test(c.name) || /[\x00-\x1f\x7f;]/.test(c.value) ||
        typeof c.path !== 'string' || !c.path.startsWith('/') || c.path.length > 4096 || /[\x00-\x1f\x7f]/.test(c.path) ||
        typeof c.hostOnly !== 'boolean' || typeof c.secure !== 'boolean' || typeof c.httpOnly !== 'boolean' || typeof c.session !== 'boolean' ||
        !Object.hasOwn(sameSites, c.sameSite) || c.partitionKey !== undefined) invalid();
    const domain = cookieDomain(c.domain, url.hostname, c.hostOnly);
    if (c.secure && url.protocol !== 'https:' && !url.hostname.endsWith('localhost') && url.hostname !== '127.0.0.1') invalid();
    if (c.name.startsWith('__Host-') && (!c.hostOnly || !c.secure || c.path !== '/')) invalid();
    if (c.name.startsWith('__Secure-') && !c.secure) invalid();
    const expires = c.session ? -1 : c.expirationDate;
    if (!Number.isFinite(expires) || (!c.session && expires * 1000 <= now)) invalid();
    const identity = JSON.stringify([c.name, domain, c.path]);
    if (seen.has(identity)) invalid(); seen.add(identity);
    return { name: c.name, value: c.value, domain, path: c.path, expires, httpOnly: c.httpOnly, secure: c.secure,
      ...(sameSites[c.sameSite] ? { sameSite: sameSites[c.sameSite] } : {}) };
  });
  return { format, kind: 'cookie-session', site, capturedAt: new Date(now).toISOString(), sessionExpiresAt: null,
    storageState: { cookies, origins: [] } };
}

export function validateCookieSession(bundle, now = Date.now()) {
  if (bundle?.format !== format || !Array.isArray(bundle.storageState?.cookies) || !Array.isArray(bundle.storageState?.origins) || bundle.storageState.origins.length) invalid();
  const map = { Strict: 'strict', Lax: 'lax', None: 'no_restriction' };
  const raw = bundle.storageState.cookies.map(c => ({ ...c, hostOnly: !c.domain?.startsWith('.'),
    session: c.expires === -1, expirationDate: c.expires,
    sameSite: c.sameSite === undefined ? 'unspecified' : map[c.sameSite] }));
  // Return only validated fields, excluding arbitrary storage or URL properties.
  return captureSession(bundle.site, raw, now);
}

export function sessionImportRequirements(cookies) {
  const httpOnlyCount = cookies.filter(c => c.httpOnly).length;
  return {
    httpOnlyCount, requiresHttpOnlySupport: httpOnlyCount > 0,
    secureCount: cookies.filter(c => c.secure).length,
    hostOnlyCount: cookies.filter(c => !c.domain.startsWith('.')).length,
    domainCookieCount: cookies.filter(c => c.domain.startsWith('.')).length,
    persistentCookieCount: cookies.filter(c => c.expires !== -1).length,
    sameSiteValues: [...new Set(cookies.map(c => c.sameSite || 'Unspecified'))].sort(),
  };
}

export class SessionInvites {
  constructor({ now = Date.now } = {}) { this.now = now; this.entries = new Map(); }
  expire(entry) {
    if (entry.status === 'ready' && entry.expiresAt <= this.now()) { entry.status = 'expired'; delete entry.bundle; }
    return entry;
  }
  public(entry) {
    this.expire(entry);
    const { bundle, tokenHash, ...metadata } = entry;
    return structuredClone(metadata);
  }
  list() { this.prune(); return [...this.entries.values()].reverse().map(e => this.public(e)); }
  create(site, cookies) {
    this.prune();
    if ([...this.entries.values()].filter(e => e.status === 'ready').length >= 20) throw new Error('Revoke an unused session invite before creating another.');
    const bundle = captureSession(site, cookies, this.now()), secret = token(), tokenHash = digest(secret);
    const entry = { id: randomBytes(12).toString('hex'), tokenHash, kind: 'cookie-session', site: bundle.site, status: 'ready',
      cookieCount: bundle.storageState.cookies.length, importRequirements: sessionImportRequirements(bundle.storageState.cookies),
      createdAt: this.now(), expiresAt: this.now() + SESSION_INVITE_TTL, bundle };
    this.entries.set(tokenHash, entry);
    return { secret, invite: this.public(entry) };
  }
  byToken(secret) {
    const entry = this.entries.get(digest(secret));
    if (!entry) throw new Error('Session invite not found. Ask the owner for a new invite.');
    return this.expire(entry);
  }
  redeem(secret, agent, purpose) {
    if (typeof agent !== 'string' || !agent.trim() || agent.length > 80 || typeof purpose !== 'string' || !purpose.trim() || purpose.length > 500) throw new Error('Provide your agent name and a short purpose.');
    const entry = this.byToken(secret);
    if (entry.status !== 'ready') throw new Error(`Session invite is ${entry.status}. Ask the owner for a new invite.`);
    const bundle = entry.bundle;
    bundle.storageState.cookies = bundle.storageState.cookies.filter(c => c.expires === -1 || c.expires * 1000 > this.now());
    if (!bundle.storageState.cookies.length) { entry.status = 'expired'; delete entry.bundle; throw new Error('The captured cookies have expired. Ask the owner for a new invite.'); }
    // Consume synchronously before returning any cookie values.
    entry.status = 'collected'; entry.collectedAt = this.now(); entry.agent = agent.trim(); entry.purpose = purpose.trim(); delete entry.bundle;
    return { invite: this.public(entry), bundle };
  }
  revoke(id) {
    const entry = [...this.entries.values()].find(e => e.id === id);
    if (!entry || this.expire(entry).status !== 'ready') throw new Error('This session invite is no longer available to revoke.');
    entry.status = 'revoked'; delete entry.bundle;
    return this.public(entry);
  }
  prune() {
    for (const [key, entry] of this.entries) {
      this.expire(entry);
      if (entry.expiresAt + 60 * 60_000 <= this.now()) this.entries.delete(key);
    }
  }
}

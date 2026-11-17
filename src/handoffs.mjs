import { createHash, createHmac, randomBytes } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { saveJSON } from './vault.mjs';
import { ceremonyDigest } from './passkey-login.mjs';
export const token = () => randomBytes(32).toString('base64url');
export const digest = value => createHash('sha256').update(value || '').digest('hex');
export class Handoffs {
  constructor({ now = Date.now, linksFile } = {}) {
    this.now = now; this.linksFile = linksFile; this.invites = new Map(); this.requests = new Map();
    const saved = linksFile && existsSync(linksFile) ? JSON.parse(readFileSync(linksFile, 'utf8')) : { version: 1, links: [] };
    if (saved.version !== 1 || !Array.isArray(saved.links)) throw new Error('Invalid agent links file.');
    this.links = new Map(saved.links.map(link => [link.tokenHash, link]));
  }
  saveLinks() { if (this.linksFile) saveJSON(this.linksFile, { version: 1, links: [...this.links.values()] }); }
  publicLink(link) { const { tokenHash, ...safe } = link; return structuredClone(safe); }
  listLinks() { return [...this.links.values()].map(link => this.publicLink(link)); }
  createLink(target, label = '') {
    if (typeof label !== 'string' || label.length > 80) throw new Error('Use a link label of at most 80 characters.');
    const secret = token(), tokenHash = digest(secret);
    const link = { id: randomBytes(12).toString('hex'), tokenHash, target: structuredClone(target), label: label.trim() || 'Agent access', createdAt: this.now(), requestCount: 0, lastRequestedAt: null, revokedAt: null };
    this.links.set(tokenHash, link);
    try { this.saveLinks(); } catch (error) { this.links.delete(tokenHash); throw error; }
    return { secret, link: this.publicLink(link) };
  }
  revokeLink(id) {
    const link = [...this.links.values()].find(link => link.id === id);
    if (!link) throw new Error('Agent link not found.');
    const previous = link.revokedAt; link.revokedAt = this.now();
    try { this.saveLinks(); } catch (error) { link.revokedAt = previous; throw error; }
    for (const r of this.requests.values()) if (r.linkId === id && ['pending', 'authenticating', 'ready', 'failed'].includes(r.status)) {
      r.status = 'denied'; delete r.bundle;
    }
    return this.publicLink(link);
  }
  access(secret) {
    const link = this.links.get(digest(secret));
    if (link) {
      if (link.revokedAt !== null) throw new Error('This agent link has been revoked. Ask the owner for a new link.');
      return { target: structuredClone(link.target), reusable: true, link };
    }
    const invite = this.validInvite(secret);
    return { target: structuredClone(invite.target), reusable: false, expiresAt: invite.expiresAt };
  }
  invite(target = null) {
    this.prune();
    const secret = token();
    this.invites.set(digest(secret), { target: structuredClone(target), expiresAt: this.now() + 60 * 60_000 });
    return secret;
  }
  validInvite(secret) {
    const invite = this.invites.get(digest(secret));
    if (!invite || invite.expiresAt <= this.now()) throw new Error('This invitation has expired or has already been used. Ask the owner for a new one.');
    return invite;
  }
  request(secret, agent, purpose, ceremony) {
    const access = this.access(secret), link = access.link;
    if (typeof agent !== 'string' || !agent.trim() || agent.length > 80 || typeof purpose !== 'string' || !purpose.trim() || purpose.length > 500) throw new Error('Provide an agent name and a short purpose.');
    // A retry of a pending link request resumes the same approval and token.
    // The link holder can derive only this link's request tokens, never another link's.
    const requestToken = id => createHmac('sha256', secret).update(`passkey-proxy/request/${id}`).digest('base64url');
    if (link) {
      const active = [...this.requests.values()].find(r => r.linkId === link.id && ['pending', 'authenticating', 'ready', 'failed'].includes(this.expire(r).status));
      if (active) {
        if (JSON.stringify(active.ceremony) !== JSON.stringify(ceremony)) throw new Error('This link already has an active request for a different challenge. Cancel it before requesting another login.');
        return { request: this.public(active), accessToken: requestToken(active.id), created: false };
      }
      if (link.lastRequestedAt !== null && this.now() - link.lastRequestedAt < 60_000) throw new Error('Wait one minute between new access requests on this link.');
    }
    const challengeHash = ceremony ? ceremonyDigest(access.target, ceremony) : undefined;
    if (challengeHash && [...this.requests.values()].some(r => r.challengeHash === challengeHash)) throw new Error('This challenge has already been requested. Start a fresh login on the website.');
    const id = randomBytes(12).toString('hex'), accessToken = link ? requestToken(id) : token();
    const r = { id, tokenHash: digest(accessToken), target: access.target, agent: agent.trim(), purpose: purpose.trim(), status: 'pending', createdAt: this.now(), expiresAt: this.now() + (ceremony ? 2 : 10) * 60_000,
      ...(ceremony ? { ceremony: structuredClone(ceremony), challengeHash } : {}),
      ...(link ? { linkId: link.id, linkLabel: link.label, requestNumber: link.requestCount + 1 } : {}) };
    if (link) {
      const before = { requestCount: link.requestCount, lastRequestedAt: link.lastRequestedAt };
      link.requestCount++; link.lastRequestedAt = this.now();
      try { this.saveLinks(); } catch (error) { Object.assign(link, before); throw error; }
    } else this.invites.delete(digest(secret));
    this.requests.set(r.id, r);
    return { request: this.public(r), accessToken, created: true };
  }
  expire(r) {
    if (['pending', 'authenticating', 'ready', 'failed'].includes(r.status) && (r.expiresAt <= this.now() || (r.handoffExpiresAt && r.handoffExpiresAt <= this.now()))) {
      r.status = 'expired'; delete r.bundle;
    }
    return r;
  }
  public(r) {
    this.expire(r);
    const { tokenHash, bundle, ceremony, challengeHash, ...safe } = r;
    return safe;
  }
  byId(id) { const r = this.requests.get(id); if (!r) throw new Error('Request not found.'); return this.expire(r); }
  byToken(secret) {
    const hashed = digest(secret);
    const r = [...this.requests.values()].find(r => r.tokenHash === hashed);
    if (!r) throw new Error('Invalid request token.');
    return this.expire(r);
  }
  begin(id) {
    const r = this.byId(id);
    if (!['pending', 'failed'].includes(r.status)) throw new Error('This request cannot be approved.');
    r.status = 'authenticating'; delete r.error;
    return r;
  }
  ready(id, bundle) {
    const r = this.byId(id);
    if (r.status !== 'authenticating') throw new Error('This request is no longer active.');
    r.status = 'ready'; r.bundle = bundle; r.handoffExpiresAt = Math.min(r.expiresAt, this.now() + 2 * 60_000);
  }
  deny(id) {
    const r = this.byId(id);
    if (!['pending', 'ready', 'failed'].includes(r.status)) throw new Error('This request cannot be denied.');
    r.status = 'denied'; delete r.bundle;
  }
  cancel(secret) {
    const r = this.byToken(secret);
    if (!['pending', 'ready', 'failed'].includes(r.status)) throw new Error('This request cannot be cancelled.');
    r.status = 'cancelled'; delete r.bundle;
    return this.public(r);
  }
  redeem(secret) {
    const r = this.byToken(secret);
    if (r.status !== 'ready') throw new Error(`Session unavailable: ${r.status}.`);
    const bundle = r.bundle;
    // No await between state transition and removal: simultaneous redemptions cannot both succeed.
    r.status = 'redeemed'; r.redeemedAt = this.now(); delete r.bundle;
    return { request: this.public(r), bundle };
  }
  prune() {
    for (const [key, invite] of this.invites) if (invite.expiresAt <= this.now()) this.invites.delete(key);
    for (const [key, r] of this.requests) if (r.createdAt + 24 * 60 * 60_000 < this.now()) this.requests.delete(key);
  }
}

'use strict';

const crypto = require('node:crypto');
const { canonicalEd25519, validateInstallationScope } = require('./setup-session-authority');
const { canonicalJson } = require('../core/canonical');

const REQUEST_ID = /^cla_[A-Za-z0-9_-]{32}$/;
const CODE_CHALLENGE = /^[A-Za-z0-9_-]{43}$/;
const STATE = /^[A-Za-z0-9_-]{32,128}$/;
const VERIFIER = /^[A-Za-z0-9._~-]{43,128}$/;
const DEPLOYMENT_ID = /^dpl_[A-Za-z0-9_-]{32}$/;

function emptyState() { return { schemaVersion: 1, authorizations: [] }; }
function copy(value) { return structuredClone(value); }
function hash(value) { return crypto.createHash('sha256').update(value, 'utf8').digest('base64url'); }
function random(randomBytes, bytes, prefix = '') { return `${prefix}${Buffer.from(randomBytes(bytes)).toString('base64url')}`; }
function deploymentFingerprint(publicKeySpkiPem) {
  const key = crypto.createPublicKey(publicKeySpkiPem);
  return `SHA256:${crypto.createHash('sha256').update(key.export({ type: 'spki', format: 'der' })).digest('base64')}`;
}
function scopeDigest(scope) { return crypto.createHash('sha256').update(canonicalJson(scope)).digest('base64url'); }

function loopbackRedirect(value) {
  let url;
  try { url = new URL(value); } catch { throw new Error('CLI login redirect is invalid'); }
  if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1' || !url.port || url.username || url.password || url.search || url.hash || url.pathname !== '/callback') throw new Error('CLI login redirect must be an exact IPv4 loopback callback');
  return url.toString();
}

function validateState(value, maximum) {
  if (!value || value.schemaVersion !== 1 || !Array.isArray(value.authorizations) || value.authorizations.length > maximum) throw new Error('Persisted CLI authorization state is invalid');
  for (const item of value.authorizations) {
    if (!REQUEST_ID.test(item?.id || '') || !CODE_CHALLENGE.test(item.codeChallenge || '') || !STATE.test(item.clientState || '') || !['pending', 'approved', 'consumed'].includes(item.status) || Number.isNaN(Date.parse(item.createdAt)) || Number.isNaN(Date.parse(item.expiresAt)) || !Number.isSafeInteger(item.verificationAttempts) || item.verificationAttempts < 0 || item.verificationAttempts > 5 || (item.status === 'pending' && typeof item.verificationCodeHash !== 'string')) throw new Error('Persisted CLI authorization is invalid');
    loopbackRedirect(item.redirectUri);
    if (item.status !== 'pending' && (typeof item.tenantId !== 'string' || typeof item.userId !== 'string')) throw new Error('Persisted CLI authorization identity is invalid');
    if (item.email !== undefined && (typeof item.email !== 'string' || item.email.length > 320)) throw new Error('Persisted CLI authorization email is invalid');
    if (item.deploymentId !== undefined && !DEPLOYMENT_ID.test(item.deploymentId)) throw new Error('Persisted CLI authorization deployment is invalid');
    item.deploymentPublicKeySpkiPem = canonicalEd25519(item.deploymentPublicKeySpkiPem).canonical;
    item.installationScope = validateInstallationScope(item.installationScope);
    if (item.installationScopeDigest !== scopeDigest(item.installationScope)) throw new Error('Persisted CLI authorization scope digest is invalid');
  }
  return copy(value);
}

class CliAuthorizationAuthority {
  constructor({ setupAuthority, store = null, clock = () => new Date(), randomBytes = crypto.randomBytes, ttlMs = 10 * 60 * 1000, maximum = 10000 } = {}) {
    if (!setupAuthority || typeof setupAuthority.create !== 'function') throw new TypeError('CLI authorization requires a setup authority');
    if (store && (typeof store.load !== 'function' || typeof store.save !== 'function')) throw new TypeError('CLI authorization store must implement load and save');
    if (!Number.isSafeInteger(ttlMs) || ttlMs < 60000 || ttlMs > 60 * 60 * 1000 || !Number.isSafeInteger(maximum) || maximum < 1 || maximum > 100000) throw new Error('CLI authorization limits are invalid');
    this.setupAuthority = setupAuthority;
    this.store = store;
    this.clock = clock;
    this.randomBytes = randomBytes;
    this.ttlMs = ttlMs;
    this.maximum = maximum;
    this.state = emptyState();
    this.loaded = false;
    this.serial = Promise.resolve();
  }

  async initialize() {
    if (this.loaded) return this;
    const persisted = this.store ? await this.store.load() : null;
    if (persisted !== null) this.state = validateState(persisted, this.maximum);
    this.loaded = true;
    return this;
  }

  #now() {
    const value = this.clock();
    const date = value instanceof Date ? value : new Date(value);
    if (Number.isNaN(date.getTime())) throw new Error('CLI authorization clock is invalid');
    return date;
  }

  async #mutate(operation) {
    await this.initialize();
    const run = this.serial.then(async () => {
      if (this.store?.shared) this.state = validateState((await this.store.load()) || emptyState(), this.maximum);
      const draft = copy(this.state);
      const result = await operation(draft);
      if (this.store) await this.store.save(draft);
      this.state = draft;
      return result;
    });
    this.serial = run.catch(() => {});
    return run;
  }

  async #read(operation) {
    await this.initialize();
    await this.serial;
    if (this.store?.shared) this.state = validateState((await this.store.load()) || emptyState(), this.maximum);
    return operation(this.state);
  }

  async create({ codeChallenge, redirectUri, state, deploymentPublicKeySpkiPem, installationScope } = {}) {
    if (!CODE_CHALLENGE.test(codeChallenge || '') || !STATE.test(state || '')) throw new Error('CLI login request is invalid');
    const redirect = loopbackRedirect(redirectUri);
    const identity = canonicalEd25519(deploymentPublicKeySpkiPem);
    const scope = validateInstallationScope(installationScope);
    return this.#mutate((draft) => {
      const now = this.#now();
      draft.authorizations = draft.authorizations.filter((item) => Date.parse(item.expiresAt) > now.getTime() && item.status !== 'consumed');
      if (draft.authorizations.length >= this.maximum) throw new Error('CLI authorization capacity reached');
      const item = {
        id: random(this.randomBytes, 24, 'cla_'), codeChallenge, redirectUri: redirect, clientState: state,
        deploymentId: random(this.randomBytes, 24, 'dpl_'),
        deploymentPublicKeySpkiPem: identity.canonical, installationScope: scope,
        installationScopeDigest: scopeDigest(scope), verificationAttempts: 0,
        status: 'pending', createdAt: now.toISOString(), expiresAt: new Date(now.getTime() + this.ttlMs).toISOString()
      };
      const verificationCode = String(crypto.randomInt(0, 100000000)).padStart(8, '0');
      item.verificationCodeHash = hash(verificationCode);
      draft.authorizations.push(item);
      return { request_id: item.id, deployment_id: item.deploymentId, expires_at: item.expiresAt, verification_code: verificationCode, installation_scope_digest: item.installationScopeDigest, deployment_key_fingerprint: deploymentFingerprint(item.deploymentPublicKeySpkiPem) };
    });
  }

  async describe({ requestId } = {}) {
    return this.#read((state) => {
      const item = state.authorizations.find((entry) => entry.id === requestId);
      if (!item || item.status !== 'pending' || Date.parse(item.expiresAt) <= this.#now().getTime()) throw new Error('CLI authorization is unavailable');
      return {
        request_id: item.id, expires_at: item.expiresAt, permission: 'create_one_deployment',
        deployment_key_fingerprint: deploymentFingerprint(item.deploymentPublicKeySpkiPem),
        installation_scope_digest: item.installationScopeDigest,
        installation_scope: copy(item.installationScope)
      };
    });
  }

  async approve({ requestId, tenantId, userId, email, verificationCode } = {}) {
    const result = await this.#mutate((draft) => {
      const item = draft.authorizations.find((entry) => entry.id === requestId);
      const now = this.#now();
      if (!item || item.status !== 'pending' || Date.parse(item.expiresAt) <= now.getTime()) throw new Error('CLI authorization is unavailable');
      item.verificationAttempts += 1;
      if (!/^\d{8}$/.test(verificationCode || '') || item.verificationAttempts > 5 || hash(verificationCode) !== item.verificationCodeHash) return { verificationRejected: true };
      const code = random(this.randomBytes, 32);
      item.status = 'approved';
      item.approvedAt = now.toISOString();
      item.tenantId = tenantId;
      item.userId = userId;
      if (email) item.email = email;
      item.authorizationCodeHash = hash(code);
      delete item.verificationCodeHash;
      const redirect = new URL(item.redirectUri);
      redirect.searchParams.set('code', code);
      redirect.searchParams.set('state', item.clientState);
      return { redirect_uri: redirect.toString() };
    });
    if (result.verificationRejected) throw new Error('CLI authorization verification failed');
    return result;
  }

  async exchange({ requestId, code, codeVerifier } = {}) {
    if (!REQUEST_ID.test(requestId || '') || typeof code !== 'string' || code.length < 32 || code.length > 256 || !VERIFIER.test(codeVerifier || '')) throw new Error('CLI authorization exchange is invalid');
    return this.#mutate(async (draft) => {
      const item = draft.authorizations.find((entry) => entry.id === requestId);
      const now = this.#now();
      const codeMatches = item?.authorizationCodeHash && crypto.timingSafeEqual(Buffer.from(item.authorizationCodeHash), Buffer.from(hash(code)));
      const verifierMatches = item?.codeChallenge === hash(codeVerifier);
      if (!item || item.status !== 'approved' || !codeMatches || !verifierMatches || Date.parse(item.expiresAt) <= now.getTime()) throw new Error('CLI authorization exchange is unavailable');
      const setup = await this.setupAuthority.create({
        tenantId: item.tenantId, userId: item.userId, email: item.email, ttlMs: this.ttlMs,
        authorizedPublicKeySpkiPem: item.deploymentPublicKeySpkiPem, authorizedInstallationScope: item.installationScope,
        authorizedDeploymentId: item.deploymentId
      });
      const result = { setup_token: setup.setup_token, expires_at: setup.expires_at, deployment_id: item.deploymentId };
      item.status = 'consumed';
      item.consumedAt = now.toISOString();
      delete item.authorizationCodeHash;
      delete item.verificationCodeHash;
      return result;
    });
  }
}

module.exports = { CliAuthorizationAuthority, loopbackRedirect };

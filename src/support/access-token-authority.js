'use strict';

const crypto = require('node:crypto');

const TOKEN_PATTERN = /^lsp_[A-Za-z0-9_-]{43}$/;
const TOKEN_ID_PATTERN = /^sat_[A-Za-z0-9_-]{32}$/;
const ACCOUNT_TOKEN_EXPIRES_AT = '9999-12-31T23:59:59.999Z';

function digestToken(token) { return crypto.createHash('sha256').update(token, 'utf8').digest('hex'); }
function tokenName(value) {
  const name = typeof value === 'string' ? value.trim() : '';
  if (!name || [...name].length > 64 || /[\p{Cc}\p{Cf}]/u.test(name)) throw Object.assign(new Error('Support token name is invalid'), { status: 400 });
  return name;
}

class SupportAccessTokenAuthority {
  constructor({ store, protector = null, clock = () => Date.now(), randomBytes = crypto.randomBytes, lifetimeMs = 90 * 24 * 60 * 60 * 1000 } = {}) {
    if (!store) throw new TypeError('Support token store is required');
    this.store = store; this.protector = protector; this.clock = clock; this.randomBytes = randomBytes; this.lifetimeMs = lifetimeMs;
  }

  async accountToken({ tenantId, userId, email }) {
    if (!tenantId || !userId || !email) throw Object.assign(new Error('Authenticated account email is required'), { status: 503 });
    if (!this.protector) throw Object.assign(new Error('Support token encryption is unavailable'), { status: 503 });
    const plaintextToken = `lsp_${this.randomBytes(32).toString('base64url')}`;
    const tokenId = `sat_${this.randomBytes(24).toString('base64url')}`;
    const context = `support-account-token:${tenantId}:${userId}:${tokenId}`;
    const createdAt = new Date(this.clock()).toISOString();
    const record = await this.store.getOrCreateAccountTokenAtomic({
      tokenId, digest: digestToken(plaintextToken), tenantId, userId, accountEmail: email,
      name: 'Account support token', createdAt, expiresAt: ACCOUNT_TOKEN_EXPIRES_AT,
      envelope: this.protector.sealString(plaintextToken, context), accountToken: true
    });
    const storedContext = `support-account-token:${record.tenantId}:${record.userId}:${record.tokenId}`;
    let token;
    try { token = this.protector.openString(record.envelope, storedContext); }
    catch { throw Object.assign(new Error('Support token could not be decrypted'), { status: 503 }); }
    if (!TOKEN_PATTERN.test(token) || digestToken(token) !== record.digest) throw Object.assign(new Error('Support token storage is invalid'), { status: 503 });
    return { token, metadata: this.publicMetadata(record) };
  }

  async create({ tenantId, userId, email, name }) {
    if (!tenantId || !userId || !email) throw Object.assign(new Error('Authenticated account email is required'), { status: 503 });
    const plaintextToken = `lsp_${this.randomBytes(32).toString('base64url')}`;
    const tokenId = `sat_${this.randomBytes(24).toString('base64url')}`;
    const createdAt = new Date(this.clock());
    const record = await this.store.createTokenAtomic({
      tokenId, digest: digestToken(plaintextToken), tenantId, userId, accountEmail: email,
      name: tokenName(name), createdAt: createdAt.toISOString(), expiresAt: new Date(createdAt.valueOf() + this.lifetimeMs).toISOString()
    });
    return { token: plaintextToken, metadata: this.publicMetadata(record) };
  }

  async list(principal) { return (await this.store.listTokens(principal)).map((record) => this.publicMetadata(record)); }
  async revoke(principal, tokenId) {
    if (!TOKEN_ID_PATTERN.test(tokenId || '')) throw Object.assign(new Error('Support token was not found'), { status: 404 });
    const record = await this.store.revokeTokenAtomic({ ...principal, tokenId, now: new Date(this.clock()).toISOString() });
    if (!record) throw Object.assign(new Error('Support token was not found'), { status: 404 });
    return this.publicMetadata(record);
  }

  async authenticate(token) {
    if (!TOKEN_PATTERN.test(token || '')) return null;
    const digest = digestToken(token);
    const record = await this.store.authenticateTokenDigest({ digest, now: new Date(this.clock()).toISOString() });
    if (!record || !TOKEN_PATTERN.test(token)) return null;
    const supplied = Buffer.from(digest, 'hex');
    const stored = Buffer.from(record.digest, 'hex');
    if (supplied.length !== stored.length || !crypto.timingSafeEqual(supplied, stored)) return null;
    const active = await this.store.touchTokenAtomic({ tokenId: record.tokenId, now: new Date(this.clock()).toISOString(), minimumIntervalMs: 60 * 60 * 1000 });
    if (!active) return null;
    return { tokenId: record.tokenId, tenantId: record.tenantId, userId: record.userId, accountEmail: record.accountEmail, expiresAt: record.expiresAt };
  }

  publicMetadata(record) {
    return { id: record.tokenId, name: record.name, created_at: record.createdAt, expires_at: record.expiresAt, last_used_at: record.lastUsedAt || null, revoked_at: record.revokedAt || null };
  }
}

module.exports = { SupportAccessTokenAuthority, TOKEN_PATTERN, TOKEN_ID_PATTERN, ACCOUNT_TOKEN_EXPIRES_AT, digestSupportToken: digestToken, validateSupportTokenName: tokenName };

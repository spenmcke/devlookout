'use strict';

const crypto = require('node:crypto');

const ROLE_PERMISSIONS = {
  console: ['read:console'],
  viewer: ['read:health', 'read:graph', 'read:behaviors', 'read:rules', 'read:events', 'read:alerts', 'read:incidents'],
  ingestor: ['ingest:events'],
  collector: ['ingest:collector'],
  analyst: ['read:health', 'read:graph', 'read:behaviors', 'read:rules', 'read:events', 'read:alerts', 'read:incidents', 'manage:alerts', 'manage:incidents'],
  rule_admin: ['read:health', 'read:graph', 'read:behaviors', 'read:rules', 'manage:rules'],
  admin: ['*']
};

function hashToken(token) {
  if (typeof token !== 'string' || token.length < 16) throw new Error('API tokens must contain at least 16 characters');
  return crypto.createHash('sha256').update(token).digest('hex');
}

function generateApiToken() {
  const token = crypto.randomBytes(32).toString('base64url');
  return { token, hash: hashToken(token) };
}

function constantEqual(left, right) {
  const a = Buffer.from(left); const b = Buffer.from(right);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

class ApiAuthenticator {
  constructor({ credentials = [], allowLocalAdmin = false } = {}) {
    this.credentials = credentials.map((credential) => {
      if (!credential.id || !/^[a-f0-9]{64}$/i.test(credential.tokenHash) || !Array.isArray(credential.roles) || !credential.roles.length) throw new Error('Credentials require id, SHA-256 tokenHash, and roles');
      for (const role of credential.roles) if (!ROLE_PERMISSIONS[role]) throw new Error(`Unknown role: ${role}`);
      return { id: credential.id, tokenHash: credential.tokenHash.toLowerCase(), roles: [...new Set(credential.roles)].sort(), disabled: Boolean(credential.disabled), expiresAt: credential.expiresAt || null };
    });
    this.allowLocalAdmin = allowLocalAdmin;
  }

  authenticate(req, now = new Date()) {
    const header = req.headers.authorization || '';
    if (!header.startsWith('Bearer ')) {
      if (this.allowLocalAdmin && ['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(req.socket?.remoteAddress)) return { id: 'local-admin', roles: ['admin'], authentication: 'loopback' };
      return null;
    }
    const candidateHash = crypto.createHash('sha256').update(header.slice(7)).digest('hex');
    const credential = this.credentials.find((item) => constantEqual(candidateHash, item.tokenHash));
    if (!credential || credential.disabled || (credential.expiresAt && Date.parse(credential.expiresAt) <= now.getTime())) return null;
    return { id: credential.id, roles: [...credential.roles], authentication: 'bearer' };
  }

  authorize(principal, permission) {
    if (!principal) return false;
    return principal.roles.some((role) => ROLE_PERMISSIONS[role]?.includes('*') || ROLE_PERMISSIONS[role]?.includes(permission));
  }

  static legacy(token, { allowLocalAdmin = false } = {}) {
    return new ApiAuthenticator({ credentials: token ? [{ id: 'legacy-api-token', tokenHash: hashToken(token), roles: ['admin'] }] : [], allowLocalAdmin });
  }
}

module.exports = { ROLE_PERMISSIONS, hashToken, generateApiToken, constantEqual, ApiAuthenticator };

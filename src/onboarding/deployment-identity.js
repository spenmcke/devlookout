'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');
const { canonicalJson } = require('../core/canonical');

function validateIdentity(document) {
  if (!document || document.schemaVersion !== 1 || typeof document.privateKeyPem !== 'string' || typeof document.publicKeyPem !== 'string' || typeof document.createdAt !== 'string' || Number.isNaN(Date.parse(document.createdAt))) throw new Error('Persisted deployment identity is invalid');
  let privateKey;
  let publicKey;
  try {
    privateKey = crypto.createPrivateKey(document.privateKeyPem);
    publicKey = crypto.createPublicKey(document.publicKeyPem);
  } catch { throw new Error('Persisted deployment identity key is invalid'); }
  if (privateKey.asymmetricKeyType !== 'ed25519' || publicKey.asymmetricKeyType !== 'ed25519') throw new Error('Deployment identity must use Ed25519');
  const derived = crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'pem' });
  const canonicalPublic = publicKey.export({ type: 'spki', format: 'pem' });
  if (derived !== canonicalPublic) throw new Error('Persisted deployment identity keys do not match');
  return Object.freeze({ ...document, publicKeyPem: canonicalPublic });
}

async function ensurePrivateDirectory(directory) {
  const target = path.resolve(directory);
  await fs.mkdir(target, { recursive: true, mode: 0o700 });
  const stat = await fs.lstat(target);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error('Deployment identity directory must be a non-symlink directory');
  if (process.platform !== 'win32' && ((stat.mode & 0o077) !== 0 || (typeof process.geteuid === 'function' && stat.uid !== process.geteuid()))) throw new Error('Deployment identity directory must be private and owned by the current user');
  return target;
}

async function loadOrCreateDeploymentIdentity(directory, { now = new Date() } = {}) {
  if (!(now instanceof Date) || Number.isNaN(now.getTime())) throw new Error('Deployment identity timestamp is invalid');
  const target = await ensurePrivateDirectory(directory);
  const filename = path.join(target, 'deployment-identity.json');
  try {
    const handle = await fs.open(filename, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
    try {
      const stat = await handle.stat();
      if (!stat.isFile() || stat.size > 64 * 1024) throw new Error('Persisted deployment identity must be a bounded regular file');
      if (process.platform !== 'win32' && ((stat.mode & 0o077) !== 0 || (typeof process.geteuid === 'function' && stat.uid !== process.geteuid()))) throw new Error('Persisted deployment identity must be private and owned by the current user');
      return validateIdentity(JSON.parse(await handle.readFile('utf8')));
    } finally { await handle.close(); }
  } catch (error) {
    if (error.code !== 'ENOENT') {
      if (error instanceof SyntaxError) throw new Error('Persisted deployment identity is not valid JSON');
      throw error;
    }
  }
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  const document = {
    schemaVersion: 1,
    createdAt: now.toISOString(),
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }),
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' })
  };
  const temporary = path.join(target, `.deployment-identity.${process.pid}.${crypto.randomUUID()}.tmp`);
  try {
    await fs.writeFile(temporary, `${canonicalJson(document)}\n`, { mode: 0o600, flag: 'wx' });
    try { await fs.link(temporary, filename); }
    catch (error) {
      if (error.code !== 'EEXIST') throw error;
      const winner = JSON.parse(await fs.readFile(filename, 'utf8'));
      return validateIdentity(winner);
    }
  } finally { await fs.rm(temporary, { force: true }); }
  return validateIdentity(document);
}

function signSetupChallenge(identity, challenge) {
  const validated = validateIdentity(identity);
  if (typeof challenge !== 'string' || !/^[A-Za-z0-9_-]{32,512}$/.test(challenge)) throw new Error('Setup proof challenge is invalid');
  return crypto.sign(null, Buffer.from(challenge, 'utf8'), validated.privateKeyPem).toString('base64url');
}

function signSetupProof(identity, message) {
  const validated = validateIdentity(identity);
  if (!(Buffer.isBuffer(message) || message instanceof Uint8Array) || message.length < 32 || message.length > 2048) throw new Error('Setup proof message is invalid');
  return crypto.sign(null, Buffer.from(message), validated.privateKeyPem);
}

module.exports = { loadOrCreateDeploymentIdentity, signSetupChallenge, signSetupProof, validateIdentity };

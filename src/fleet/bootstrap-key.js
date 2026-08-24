'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');
const { canonicalJson } = require('../core/canonical');

function sshString(value) {
  const bytes = Buffer.isBuffer(value) ? value : Buffer.from(value);
  const length = Buffer.alloc(4);
  length.writeUInt32BE(bytes.length);
  return Buffer.concat([length, bytes]);
}

function sshUint32(value) {
  const bytes = Buffer.alloc(4);
  bytes.writeUInt32BE(value);
  return bytes;
}

function openSshEd25519PrivateKey(privateKey, publicKey, comment) {
  if (privateKey.asymmetricKeyType !== 'ed25519' || publicKey.asymmetricKeyType !== 'ed25519') throw new Error('Bootstrap key must be Ed25519');
  const publicRaw = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
  const privateRaw = privateKey.export({ type: 'pkcs8', format: 'der' }).subarray(-32);
  if (publicRaw.length !== 32 || privateRaw.length !== 32) throw new Error('Unable to encode Ed25519 private key');
  const publicBlob = Buffer.concat([sshString('ssh-ed25519'), sshString(publicRaw)]);
  const check = crypto.randomBytes(4);
  const unpadded = Buffer.concat([
    check, check, sshString('ssh-ed25519'), sshString(publicRaw),
    sshString(Buffer.concat([privateRaw, publicRaw])), sshString(comment)
  ]);
  const paddingLength = 8 - (unpadded.length % 8);
  const padding = Buffer.from(Array.from({ length: paddingLength }, (_, index) => index + 1));
  const encoded = Buffer.concat([
    Buffer.from('openssh-key-v1\0'), sshString('none'), sshString('none'), sshString(Buffer.alloc(0)),
    sshUint32(1), sshString(publicBlob), sshString(Buffer.concat([unpadded, padding]))
  ]).toString('base64');
  return `-----BEGIN OPENSSH PRIVATE KEY-----\n${encoded.match(/.{1,70}/g).join('\n')}\n-----END OPENSSH PRIVATE KEY-----\n`;
}

function openSshEd25519PublicKey(publicKey, comment) {
  if (publicKey.asymmetricKeyType !== 'ed25519') throw new Error('Bootstrap key must be Ed25519');
  if (!/^[A-Za-z0-9._:-]{1,128}$/.test(comment || '')) throw new Error('Bootstrap key comment is invalid');
  const der = publicKey.export({ type: 'spki', format: 'der' });
  const raw = der.subarray(-32);
  if (raw.length !== 32) throw new Error('Unable to encode Ed25519 public key');
  const blob = Buffer.concat([sshString('ssh-ed25519'), sshString(raw)]);
  return { line: `ssh-ed25519 ${blob.toString('base64')} ${comment}`, fingerprint: `SHA256:${crypto.createHash('sha256').update(blob).digest('base64').replace(/=+$/, '')}` };
}

async function ensurePrivateDirectory(directory) {
  const target = path.resolve(directory);
  await fs.mkdir(target, { recursive: true, mode: 0o700 });
  const stat = await fs.lstat(target);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error('Bootstrap key directory must be a non-symlink directory');
  if (process.platform !== 'win32' && ((stat.mode & 0o077) !== 0 || (typeof process.geteuid === 'function' && stat.uid !== process.geteuid()))) throw new Error('Bootstrap key directory must be private and owned by the current user');
  return target;
}

async function createBootstrapKey(directory, { deploymentId = crypto.randomUUID(), now = new Date() } = {}) {
  if (!/^[A-Za-z0-9._:-]{1,128}$/.test(deploymentId)) throw new Error('Bootstrap deployment ID is invalid');
  if (!(now instanceof Date) || Number.isNaN(now.getTime())) throw new Error('Bootstrap key timestamp is invalid');
  const target = await ensurePrivateDirectory(directory);
  const privateKeyFile = path.join(target, 'lookout-bootstrap-key');
  const publicKeyFile = path.join(target, 'lookout-bootstrap-key.pub');
  const manifestFile = path.join(target, 'lookout-bootstrap-key.json');
  for (const filename of [privateKeyFile, publicKeyFile, manifestFile]) {
    try { await fs.lstat(filename); throw new Error(`Refusing to replace existing bootstrap material: ${filename}`); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
  const comment = `lookout-bootstrap:${deploymentId}`;
  let encoded;
  try {
    const pair = crypto.generateKeyPairSync('ed25519');
    encoded = openSshEd25519PublicKey(pair.publicKey, comment);
    await fs.writeFile(privateKeyFile, openSshEd25519PrivateKey(pair.privateKey, pair.publicKey, comment), { mode: 0o600, flag: 'wx' });
    await fs.writeFile(publicKeyFile, `${encoded.line}\n`, { mode: 0o600, flag: 'wx' });
    const manifest = { schemaVersion: 1, deploymentId, createdAt: now.toISOString(), comment, fingerprint: encoded.fingerprint, privateKeyFile, publicKeyFile };
    await fs.writeFile(manifestFile, `${canonicalJson(manifest)}\n`, { mode: 0o600, flag: 'wx' });
    return { ...manifest, authorizedKeysLine: `restrict ${encoded.line}` };
  } catch (error) {
    await Promise.all([privateKeyFile, publicKeyFile, manifestFile].map((filename) => fs.rm(filename, { force: true })));
    throw error;
  }
}

module.exports = { createBootstrapKey, ensurePrivateDirectory, openSshEd25519PublicKey, openSshEd25519PrivateKey, sshString };

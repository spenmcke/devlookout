'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

class DataProtector {
  constructor(masterKey) {
    if (!Buffer.isBuffer(masterKey) || masterKey.length !== 32) throw new Error('Data protection master key must be exactly 32 bytes');
    this.key = Buffer.from(crypto.hkdfSync('sha256', masterKey, Buffer.from('lookout-storage-v1'), Buffer.from('aes-256-gcm'), 32));
    this.keyId = crypto.createHash('sha256').update(this.key).digest('hex').slice(0, 16);
  }

  sealString(plaintext, context) {
    if (typeof plaintext !== 'string' || typeof context !== 'string' || !context) throw new Error('Encryption requires plaintext and context strings');
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.key, iv);
    cipher.setAAD(Buffer.from(context));
    const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    return { format: 'lookout-encrypted-v1', algorithm: 'aes-256-gcm', keyId: this.keyId, iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), ciphertext: ciphertext.toString('base64') };
  }

  openString(envelope, context) {
    if (!DataProtector.isEnvelope(envelope) || envelope.algorithm !== 'aes-256-gcm') throw new Error('Unsupported encrypted data envelope');
    if (envelope.keyId !== this.keyId) throw new Error('Encrypted data was produced by a different key');
    try {
      const decipher = crypto.createDecipheriv('aes-256-gcm', this.key, Buffer.from(envelope.iv, 'base64'));
      decipher.setAAD(Buffer.from(context));
      decipher.setAuthTag(Buffer.from(envelope.tag, 'base64'));
      return Buffer.concat([decipher.update(Buffer.from(envelope.ciphertext, 'base64')), decipher.final()]).toString('utf8');
    } catch { throw new Error('Encrypted data authentication failed'); }
  }

  static isEnvelope(value) { return value?.format === 'lookout-encrypted-v1'; }
}

function decodeMasterKey(value) {
  if (typeof value !== 'string' || !value.trim()) throw new Error('Master key is empty');
  const trimmed = value.trim();
  const key = /^[a-f0-9]{64}$/i.test(trimmed) ? Buffer.from(trimmed, 'hex') : Buffer.from(trimmed, 'base64');
  if (key.length !== 32) throw new Error('Master key must encode exactly 32 bytes');
  return key;
}

function protectorFromEnvironment(environment = process.env) {
  let value = environment.LOOKOUT_MASTER_KEY;
  if (environment.LOOKOUT_MASTER_KEY_FILE) {
    const file = path.resolve(environment.LOOKOUT_MASTER_KEY_FILE);
    const flags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0);
    let descriptor;
    try {
      descriptor = fs.openSync(file, flags);
      const stat = fs.fstatSync(descriptor);
      if (!stat.isFile()) throw new Error('Master key path must be a regular file');
      if (stat.size > 4096) throw new Error('Master key file exceeds the maximum size');
      if (process.platform !== 'win32') {
        if ((stat.mode & 0o077) !== 0) throw new Error('Master key file must not be accessible by group or other users');
        if (typeof process.geteuid === 'function' && stat.uid !== process.geteuid()) throw new Error('Master key file must be owned by the current user');
      }
      value = fs.readFileSync(descriptor, 'utf8');
    } catch (error) {
      if (['ELOOP', 'EMLINK'].includes(error.code)) throw new Error('Master key file must not be a symbolic link');
      throw error;
    } finally { if (descriptor !== undefined) fs.closeSync(descriptor); }
  }
  return value ? new DataProtector(decodeMasterKey(value)) : null;
}

module.exports = { DataProtector, decodeMasterKey, protectorFromEnvironment };

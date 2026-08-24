'use strict';

const crypto = require('node:crypto');

const ARCHITECTURES = Object.freeze(['amd64', 'arm64']);
const ACTIONS = new Set(['install', 'rollback', 'pause']);
const CHANNELS = new Set(['stable', 'cli-stable']);

function exactKeys(value, expected, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} is invalid`);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) throw new Error(`${label} has unexpected fields`);
}

function normalizeArtifact(value, label) {
  exactKeys(value, ['url', 'sha256', 'size'], label);
  let url;
  try { url = new URL(value.url); } catch { throw new Error(`${label} URL is invalid`); }
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash) throw new Error(`${label} URL is invalid`);
  if (!/^[a-f0-9]{64}$/.test(value.sha256 || '') || !Number.isSafeInteger(value.size) || value.size < 1 || value.size > 1024 * 1024 * 1024) throw new Error(`${label} metadata is invalid`);
  return { url: url.toString(), sha256: value.sha256, size: value.size };
}

function normalizePayload(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Update manifest payload is invalid');
  if (!ACTIONS.has(value.action)) throw new Error('Update manifest action is invalid');
  const fields = value.action === 'pause'
    ? ['schemaVersion', 'channel', 'sequence', 'action', 'release', 'publishedAt']
    : ['schemaVersion', 'channel', 'sequence', 'action', 'release', 'publishedAt', 'artifacts'];
  exactKeys(value, fields, 'Update manifest payload');
  if (value.schemaVersion !== 1 || !CHANNELS.has(value.channel) || !Number.isSafeInteger(value.sequence) || value.sequence < 1 || !/^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(value.release || '') || Number.isNaN(Date.parse(value.publishedAt || ''))) throw new Error('Update manifest payload metadata is invalid');
  const normalized = {
    schemaVersion: 1,
    channel: value.channel,
    sequence: value.sequence,
    action: value.action,
    release: value.release,
    publishedAt: new Date(value.publishedAt).toISOString()
  };
  if (value.action !== 'pause') {
    exactKeys(value.artifacts, ARCHITECTURES, 'Update manifest artifacts');
    normalized.artifacts = Object.fromEntries(ARCHITECTURES.map((architecture) => [architecture, normalizeArtifact(value.artifacts[architecture], `Update manifest ${architecture} artifact`)]));
  }
  return normalized;
}

function payloadBytes(payload) {
  return Buffer.from(JSON.stringify(normalizePayload(payload)));
}

function signingKey(value, type) {
  let key;
  try { key = type === 'private' ? crypto.createPrivateKey(value) : crypto.createPublicKey(value); }
  catch { throw new Error(`Update signing ${type} key is invalid`); }
  if (key.asymmetricKeyType !== 'ed25519') throw new Error(`Update signing ${type} key must be Ed25519`);
  return key;
}

function signManifest(payload, { keyId, privateKeyPem }) {
  if (!/^[A-Za-z0-9._-]{1,64}$/.test(keyId || '')) throw new Error('Update signing key ID is invalid');
  const normalized = normalizePayload(payload);
  const signature = crypto.sign(null, Buffer.from(JSON.stringify(normalized)), signingKey(privateKeyPem, 'private')).toString('base64url');
  return { schemaVersion: 1, keyId, payload: normalized, signature };
}

function verifyManifest(envelope, trustedKeys, { channel = null } = {}) {
  exactKeys(envelope, ['schemaVersion', 'keyId', 'payload', 'signature'], 'Signed update manifest');
  if (envelope.schemaVersion !== 1 || !/^[A-Za-z0-9._-]{1,64}$/.test(envelope.keyId || '') || !/^[A-Za-z0-9_-]{86}$/.test(envelope.signature || '')) throw new Error('Signed update manifest metadata is invalid');
  if (!Array.isArray(trustedKeys) || trustedKeys.length < 1 || trustedKeys.length > 8) throw new Error('Update trusted keys are invalid');
  const record = trustedKeys.find((item) => item?.keyId === envelope.keyId);
  if (!record || typeof record.publicKeySpkiPem !== 'string') throw new Error('Update manifest signing key is not trusted');
  const payload = normalizePayload(envelope.payload);
  const valid = crypto.verify(null, Buffer.from(JSON.stringify(payload)), signingKey(record.publicKeySpkiPem, 'public'), Buffer.from(envelope.signature, 'base64url'));
  if (!valid) throw new Error('Update manifest signature is invalid');
  if (channel !== null && payload.channel !== channel) throw new Error('Update manifest channel is invalid');
  return payload;
}

module.exports = { ACTIONS, ARCHITECTURES, CHANNELS, normalizePayload, payloadBytes, signManifest, verifyManifest };

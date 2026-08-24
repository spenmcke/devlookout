'use strict';

const crypto = require('node:crypto');
const { canonicalJson, stableId } = require('../core/canonical');
const { validateFact } = require('../core/validation');
const { validateEvent } = require('../events/schema');
const { validateOperationalHealthSample } = require('./operational-telemetry');

const MAXIMUM_FACTS = 5000;
const MAXIMUM_EVENTS = 5000;
const MAXIMUM_OPERATIONAL_HEALTH = 32;
const MAXIMUM_PAYLOAD_BYTES = 4 * 1024 * 1024;

function generateCollectorKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });
  const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const collectorId = stableId('collector', publicKeyPem);
  return { collectorId, publicKeyPem, privateKeyPem };
}

function validatePayload(payload) {
  const issues = [];
  const allowedFields = new Set(['schemaVersion', 'collectorId', 'sequence', 'collectedAt', 'facts', 'events', 'operationalHealth']);
  if (payload && typeof payload === 'object' && !Array.isArray(payload) && Object.keys(payload).some((key) => !allowedFields.has(key))) issues.push('payload contains unsupported fields');
  if (!payload || payload.schemaVersion !== 1) issues.push('schemaVersion must equal 1');
  if (typeof payload?.collectorId !== 'string' || !payload.collectorId) issues.push('collectorId is required');
  if (!Number.isSafeInteger(payload?.sequence) || payload.sequence < 1) issues.push('sequence must be a positive safe integer');
  if (typeof payload?.collectedAt !== 'string' || Number.isNaN(Date.parse(payload.collectedAt))) issues.push('collectedAt must be an ISO-compatible timestamp string');
  if (!Array.isArray(payload?.facts) || !Array.isArray(payload?.events)) issues.push('facts and events must be arrays');
  if (payload?.operationalHealth !== undefined && !Array.isArray(payload.operationalHealth)) issues.push('operationalHealth must be an array when present');
  if (issues.length) throw new Error(`Invalid collector payload: ${issues.join('; ')}`);
  if (payload.facts.length > MAXIMUM_FACTS || payload.events.length > MAXIMUM_EVENTS) throw new Error('Invalid collector payload: observation count exceeds the maximum');
  if ((payload.operationalHealth || []).length > MAXIMUM_OPERATIONAL_HEALTH) throw new Error('Invalid collector payload: operational health count exceeds the maximum');
  payload.facts.forEach(validateFact);
  payload.events.forEach(validateEvent);
  (payload.operationalHealth || []).forEach(validateOperationalHealthSample);
  if (Buffer.byteLength(canonicalJson(payload), 'utf8') > MAXIMUM_PAYLOAD_BYTES) throw new Error('Invalid collector payload: encoded payload exceeds the maximum size');
  return payload;
}

function signPayload(payload, privateKeyPem) {
  validatePayload(payload);
  const signature = crypto.sign(null, Buffer.from(canonicalJson(payload)), privateKeyPem).toString('base64');
  return { algorithm: 'Ed25519', payload: structuredClone(payload), signature };
}

function verifyEnvelope(envelope, publicKeyPem) {
  if (!envelope || envelope.algorithm !== 'Ed25519' || typeof envelope.signature !== 'string') throw new Error('Invalid collector signature envelope');
  validatePayload(envelope.payload);
  let signature;
  try {
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(envelope.signature) || envelope.signature.length % 4 !== 0) throw new Error();
    signature = Buffer.from(envelope.signature, 'base64');
    if (signature.length !== 64 || signature.toString('base64') !== envelope.signature) throw new Error();
  }
  catch { throw new Error('Collector signature is not valid base64'); }
  if (!crypto.verify(null, Buffer.from(canonicalJson(envelope.payload)), publicKeyPem, signature)) throw new Error('Collector signature verification failed');
  return structuredClone(envelope.payload);
}

module.exports = { MAXIMUM_FACTS, MAXIMUM_EVENTS, MAXIMUM_OPERATIONAL_HEALTH, MAXIMUM_PAYLOAD_BYTES, generateCollectorKeyPair, validatePayload, signPayload, verifyEnvelope };

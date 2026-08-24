'use strict';

const crypto = require('node:crypto');
const { SnapshotStore } = require('../storage/snapshot-store');
const { verifyEnvelope } = require('./envelope');
const { canonicalJson } = require('../core/canonical');

class CollectorRegistry {
  #queue = Promise.resolve();

  constructor({ dataDirectory, publicKeys = {}, maximumFutureSkewSeconds = 300, maximumAgeSeconds = 604800, protector = null, requireEncryption = false } = {}) {
    if (!Number.isFinite(maximumFutureSkewSeconds) || maximumFutureSkewSeconds < 0 || !Number.isFinite(maximumAgeSeconds) || maximumAgeSeconds <= 0) throw new Error('Collector time limits must be finite positive values');
    this.publicKeys = new Map();
    for (const [collectorId, publicKeyPem] of Object.entries(publicKeys)) this.register(collectorId, publicKeyPem);
    this.maximumFutureSkewSeconds = maximumFutureSkewSeconds;
    this.maximumAgeSeconds = maximumAgeSeconds;
    this.sequences = new Map();
    this.lastAccepted = new Map();
    this.store = new SnapshotStore(dataDirectory, 'collectors.snapshot.json', { protector, requireEncryption });
  }

  async initialize() {
    const snapshot = await this.store.load();
    if (snapshot) {
      if (snapshot.schemaVersion !== 1) throw new Error('Unsupported collector registry snapshot');
      const entries = Object.entries(snapshot.sequences || {});
      if (entries.some(([id, value]) => !id || !Number.isSafeInteger(value) || value < 1)) throw new Error('Collector registry snapshot contains an invalid sequence');
      this.sequences = new Map(entries);
      const accepted = Object.entries(snapshot.lastAccepted || {});
      for (const [id, record] of accepted) {
        if (!this.sequences.has(id) || record?.sequence !== this.sequences.get(id) || !/^[a-f0-9]{64}$/.test(record.envelopeDigest) || !Object.hasOwn(record, 'result')) throw new Error('Collector registry snapshot contains invalid idempotency state');
      }
      this.lastAccepted = new Map(accepted);
    }
    return this;
  }

  register(collectorId, publicKeyPem) {
    if (typeof collectorId !== 'string' || !collectorId || typeof publicKeyPem !== 'string') throw new Error('Collector registration requires an ID and public key');
    let key;
    try { key = crypto.createPublicKey(publicKeyPem); }
    catch { throw new Error('Collector public key is invalid'); }
    if (key.asymmetricKeyType !== 'ed25519') throw new Error('Collector public key must be Ed25519');
    this.publicKeys.set(collectorId, publicKeyPem);
  }

  async accept(envelope, handler, now = new Date()) {
    const operation = async () => {
      const claimedId = envelope?.payload?.collectorId;
      const publicKey = this.publicKeys.get(claimedId);
      if (!publicKey) throw new Error('Collector is not registered');
      const payload = verifyEnvelope(envelope, publicKey);
      const envelopeDigest = crypto.createHash('sha256').update(canonicalJson(envelope)).digest('hex');
      const collected = Date.parse(payload.collectedAt);
      if (collected > now.getTime() + this.maximumFutureSkewSeconds * 1000) throw new Error('Collector timestamp is too far in the future');
      if (collected < now.getTime() - this.maximumAgeSeconds * 1000) throw new Error('Collector submission is too old');
      const previous = this.sequences.get(payload.collectorId) || 0;
      if (payload.sequence === previous) {
        const accepted = this.lastAccepted.get(payload.collectorId);
        if (accepted?.envelopeDigest === envelopeDigest) return structuredClone(accepted.result);
        throw new Error('Collector submission sequence was already accepted with different content');
      }
      if (payload.sequence < previous) throw new Error('Collector submission sequence was already accepted');
      const result = await handler(payload);
      const durableResult = result === undefined ? null : JSON.parse(JSON.stringify(result));
      const priorAccepted = this.lastAccepted.get(payload.collectorId);
      this.sequences.set(payload.collectorId, payload.sequence);
      this.lastAccepted.set(payload.collectorId, { sequence: payload.sequence, envelopeDigest, result: durableResult });
      try { await this.store.save(this.snapshot()); }
      catch (error) {
        if (previous) this.sequences.set(payload.collectorId, previous);
        else this.sequences.delete(payload.collectorId);
        if (priorAccepted) this.lastAccepted.set(payload.collectorId, priorAccepted);
        else this.lastAccepted.delete(payload.collectorId);
        throw error;
      }
      return result;
    };
    const result = this.#queue.then(operation, operation);
    this.#queue = result.then(() => undefined, () => undefined);
    return result;
  }

  snapshot() {
    return {
      schemaVersion: 1,
      sequences: Object.fromEntries([...this.sequences.entries()].sort(([a], [b]) => a.localeCompare(b))),
      lastAccepted: Object.fromEntries([...this.lastAccepted.entries()].sort(([a], [b]) => a.localeCompare(b)))
    };
  }
}

module.exports = { CollectorRegistry };

'use strict';

const crypto = require('node:crypto');
const { SnapshotStore } = require('../storage/snapshot-store');
const { CollectorRunner } = require('./runner');
const { verifyEnvelope } = require('./envelope');

class CollectorScheduler {
  #queue = Promise.resolve();

  constructor({ dataDirectory, collectorId, privateKeyPem, modules, sender, intervalSeconds = 300, maximumBackoffSeconds = 3600, clock = () => new Date(), protector = null, requireEncryption = false } = {}) {
    if (typeof sender !== 'function') throw new Error('CollectorScheduler requires a sender');
    if (!Number.isSafeInteger(intervalSeconds) || intervalSeconds < 1 || !Number.isSafeInteger(maximumBackoffSeconds) || maximumBackoffSeconds < 1) throw new Error('Collector scheduling intervals must be positive integers');
    this.store = new SnapshotStore(dataDirectory, 'collector-state.json', { protector, requireEncryption });
    this.collectorId = collectorId;
    this.privateKeyPem = privateKeyPem;
    this.modules = modules;
    this.sender = sender;
    this.intervalSeconds = intervalSeconds;
    this.maximumBackoffSeconds = maximumBackoffSeconds;
    this.clock = clock;
    this.state = { schemaVersion: 1, sequence: 0, pending: null, failureCount: 0, lastSuccessAt: null, nextRunAt: null };
    this.timer = null;
  }

  async initialize() {
    const stored = await this.store.load();
    if (stored) {
      if (stored.schemaVersion !== 1) throw new Error('Unsupported collector state');
      if (!Number.isSafeInteger(stored.sequence) || stored.sequence < 0 || !Number.isSafeInteger(stored.failureCount) || stored.failureCount < 0) throw new Error('Collector state contains invalid counters');
      for (const field of ['lastSuccessAt', 'nextRunAt']) if (stored[field] !== null && (typeof stored[field] !== 'string' || Number.isNaN(Date.parse(stored[field])))) throw new Error(`Collector state contains invalid ${field}`);
      if (stored.pending) {
        let publicKey;
        try { publicKey = crypto.createPublicKey(crypto.createPrivateKey(this.privateKeyPem)); }
        catch { throw new Error('Collector private key is invalid'); }
        const payload = verifyEnvelope(stored.pending, publicKey);
        if (payload.collectorId !== this.collectorId || payload.sequence !== stored.sequence) throw new Error('Pending collector envelope does not match persisted identity and sequence');
      }
      this.state = stored;
    }
    this.runner = new CollectorRunner({ collectorId: this.collectorId, privateKeyPem: this.privateKeyPem, modules: this.modules, initialSequence: this.state.sequence, clock: this.clock });
    return this;
  }

  due(now = this.clock()) {
    return Boolean(this.state.pending) || !this.state.nextRunAt || Date.parse(this.state.nextRunAt) <= now.getTime();
  }

  async runCycle(now = this.clock()) {
    const operation = () => this.#runCycle(now);
    const result = this.#queue.then(operation, operation);
    this.#queue = result.then(() => undefined, () => undefined);
    return result;
  }

  async #runCycle(now) {
    if (!(now instanceof Date) || Number.isNaN(now.getTime())) throw new Error('Collector clock returned an invalid date');
    if (!this.due(now)) return { status: 'not-due', nextRunAt: this.state.nextRunAt };
    if (!this.state.pending) {
      this.state.pending = this.runner.collectOnce();
      this.state.sequence = this.state.pending.payload.sequence;
      await this.store.save(this.state);
    }
    try {
      const result = await this.sender(this.state.pending);
      this.state.pending = null;
      this.state.failureCount = 0;
      this.state.lastSuccessAt = now.toISOString();
      this.state.nextRunAt = new Date(now.getTime() + this.intervalSeconds * 1000).toISOString();
      await this.store.save(this.state);
      return { status: 'submitted', sequence: this.state.sequence, result, nextRunAt: this.state.nextRunAt };
    } catch (error) {
      this.state.failureCount += 1;
      const backoff = Math.min(this.maximumBackoffSeconds, Math.max(1, 2 ** Math.min(this.state.failureCount - 1, 20)) * this.intervalSeconds);
      this.state.nextRunAt = new Date(now.getTime() + backoff * 1000).toISOString();
      await this.store.save(this.state);
      throw error;
    }
  }

  async start() {
    if (this.timer) return;
    const run = async () => {
      try { await this.runCycle(); } catch { /* failure is recorded for health reporting */ }
      const delay = Math.max(1000, Date.parse(this.state.nextRunAt || new Date().toISOString()) - this.clock().getTime());
      this.timer = setTimeout(run, delay);
      this.timer.unref?.();
    };
    await run();
  }

  stop() {
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
  }

  status() {
    const { pending, ...safe } = this.state;
    return { ...safe, pending: Boolean(pending) };
  }
}

module.exports = { CollectorScheduler };

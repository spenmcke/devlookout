'use strict';

const path = require('node:path');
const { SnapshotStore } = require('../storage/snapshot-store');

function emptyState() {
  return { schemaVersion: 1, sequence: 0, acknowledgedThrough: 0, pending: null, retry: null, blocked: null };
}

function failureIsValid(value) {
  return value === null || (value && Number.isSafeInteger(value.throughSequence) && value.throughSequence > 0
    && Number.isSafeInteger(value.attempts) && value.attempts > 0
    && /^[a-zA-Z0-9_-]{1,64}$/.test(value.errorCode || ''));
}

function validateState(value) {
  if (!value) return emptyState();
  if (value.schemaVersion !== 1 || !Number.isSafeInteger(value.sequence) || value.sequence < 0
    || !Number.isSafeInteger(value.acknowledgedThrough) || value.acknowledgedThrough < 0
    || value.acknowledgedThrough > value.sequence || !failureIsValid(value.retry) || !failureIsValid(value.blocked)
    || (value.retry && value.blocked)) throw new Error('Invalid latest console snapshot state');
  if (value.pending !== null) {
    if (!value.pending || value.pending.sequence !== value.sequence || !value.pending.event || typeof value.pending.event.id !== 'string') throw new Error('Invalid pending console snapshot');
    if (value.acknowledgedThrough >= value.pending.sequence) throw new Error('Acknowledged console snapshot cannot remain pending');
  } else if (value.acknowledgedThrough !== value.sequence) throw new Error('Latest console snapshot state has a sequence gap');
  return structuredClone(value);
}

class LatestSnapshotOutbox {
  #ready = null;
  #queue = Promise.resolve();
  #state = emptyState();

  constructor(directory, { protector = null, requireEncryption = false, filename = 'console-sync.latest.json' } = {}) {
    if (!path.isAbsolute(directory)) throw new Error('Console snapshot directory must be absolute');
    this.directory = path.resolve(directory);
    this.store = new SnapshotStore(this.directory, filename, { protector, requireEncryption });
  }

  async initialize() {
    if (!this.#ready) this.#ready = this.#initialize();
    return this.#ready;
  }

  async #initialize() {
    this.#state = validateState(await this.store.load());
    return this;
  }

  async enqueue(events) {
    if (!Array.isArray(events)) throw new Error('Console snapshot input must be an array');
    if (!events.length) return { enqueued: 0, duplicates: 0, ...this.stats() };
    const event = events.at(-1);
    if (!event || typeof event !== 'object' || Array.isArray(event) || typeof event.id !== 'string' || !event.id) throw new Error('Console snapshot must have a non-empty ID');
    return this.#serialized(async () => {
      if (this.#state.pending?.event.id === event.id) return { enqueued: 0, duplicates: events.length, ...this.stats() };
      const sequence = this.#state.sequence + 1;
      this.#state = { schemaVersion: 1, sequence, acknowledgedThrough: sequence - 1, pending: { sequence, event: structuredClone(event) }, retry: null, blocked: null };
      await this.store.save(this.#state);
      return { enqueued: 1, duplicates: Math.max(0, events.length - 1), ...this.stats() };
    });
  }

  async pending({ limit = 1 } = {}) {
    await this.initialize();
    if (!Number.isSafeInteger(limit) || limit < 1) throw new Error('Console snapshot limit must be positive');
    return this.#state.pending ? [structuredClone(this.#state.pending)] : [];
  }

  async acknowledge({ throughSequence, batchId }) {
    return this.#serialized(async () => {
      if (!this.#state.pending || throughSequence !== this.#state.pending.sequence || typeof batchId !== 'string' || !batchId) throw new Error('Invalid console snapshot acknowledgement');
      this.#state = { ...this.#state, acknowledgedThrough: throughSequence, pending: null, retry: null, blocked: null };
      await this.store.save(this.#state);
      return this.stats();
    });
  }

  async recordFailure({ throughSequence, attempts, nextAttemptAt = null, errorCode, retryable = true, failedAt = new Date().toISOString() }) {
    return this.#serialized(async () => {
      if (!this.#state.pending || throughSequence !== this.#state.pending.sequence || !Number.isSafeInteger(attempts) || attempts < 1 || !/^[a-zA-Z0-9_-]{1,64}$/.test(errorCode || '')) throw new Error('Invalid console snapshot failure');
      const failure = retryable
        ? { throughSequence, attempts, nextAttemptAt, errorCode }
        : { throughSequence, attempts, blockedAt: failedAt, errorCode };
      this.#state = { ...this.#state, retry: retryable ? failure : null, blocked: retryable ? null : failure };
      await this.store.save(this.#state);
      return structuredClone(failure);
    });
  }

  async resumeBlocked({ includeRetry = false, errorCodes = null } = {}) {
    return this.#serialized(async () => {
      if (errorCodes !== null && (!Array.isArray(errorCodes) || errorCodes.some((code) => !/^[a-zA-Z0-9_-]{1,64}$/.test(code || '')))) throw new Error('Console snapshot resume error codes are invalid');
      const failure = this.#state.blocked || (includeRetry ? this.#state.retry : null);
      if (!failure || (errorCodes && !errorCodes.includes(failure.errorCode))) return false;
      this.#state = { ...this.#state, retry: null, blocked: null };
      await this.store.save(this.#state);
      return true;
    });
  }

  stats() {
    return {
      pending: this.#state.pending ? 1 : 0,
      acknowledgedThrough: this.#state.acknowledgedThrough,
      compactedThrough: this.#state.acknowledgedThrough,
      lastBatchId: null,
      retry: this.#state.retry ? structuredClone(this.#state.retry) : null,
      blocked: this.#state.blocked ? structuredClone(this.#state.blocked) : null
    };
  }

  async #serialized(work) {
    const execute = async () => { await this.initialize(); return work(); };
    const result = this.#queue.then(execute, execute);
    this.#queue = result.then(() => undefined, () => undefined);
    return result;
  }
}

module.exports = { LatestSnapshotOutbox, validateState };

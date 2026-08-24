'use strict';

const crypto = require('node:crypto');
const { canonicalJson } = require('../core/canonical');
const { selectExportEvent } = require('../events/export');

function batchIdFor(records) {
  if (!Array.isArray(records) || !records.length) throw new Error('Cannot identify an empty export batch');
  return crypto.createHash('sha256').update(canonicalJson(records.map((record) => ({ sequence: record.sequence, id: record.event.id })))).digest('hex');
}

function safeErrorCode(error) {
  const code = typeof error?.code === 'string' ? error.code : error?.name;
  return /^[a-zA-Z0-9_-]{1,64}$/.test(code || '') ? code : 'delivery_error';
}

class CloudExportService {
  #deliveryQueue = Promise.resolve();

  constructor({ outbox, exporter, policy, selector = selectExportEvent, batchSize = 100, baseRetryMs = 1000, maxRetryMs = 15 * 60 * 1000, clock = () => Date.now() } = {}) {
    if (!outbox || typeof outbox.enqueue !== 'function' || typeof outbox.pending !== 'function') throw new Error('Cloud export service requires an outbox');
    if (!exporter || typeof exporter.send !== 'function') throw new Error('Cloud export service requires an exporter');
    if (!policy || policy.enabled !== true) throw new Error('Cloud export service requires an enabled export policy');
    if (typeof selector !== 'function') throw new Error('Cloud export selector must be a function');
    if (!Number.isSafeInteger(batchSize) || batchSize < 1 || batchSize > 1000) throw new Error('Cloud export batch size must be between 1 and 1000');
    if (!Number.isSafeInteger(baseRetryMs) || baseRetryMs < 100 || !Number.isSafeInteger(maxRetryMs) || maxRetryMs < baseRetryMs) throw new Error('Invalid cloud export retry settings');
    this.outbox = outbox;
    this.exporter = exporter;
    this.policy = structuredClone(policy);
    this.selector = selector;
    this.batchSize = batchSize;
    this.baseRetryMs = baseRetryMs;
    this.maxRetryMs = maxRetryMs;
    this.clock = clock;
  }

  async enqueue(events) {
    if (!Array.isArray(events)) throw new Error('Cloud export input must be an event array');
    const selected = events.map((event) => this.selector(event, this.policy)).filter(Boolean);
    if (!selected.length) {
      await this.outbox.initialize();
      return { enqueued: 0, filtered: events.length, ...this.outbox.stats() };
    }
    const result = await this.outbox.enqueue(selected);
    return { ...result, filtered: events.length - selected.length };
  }

  async flush() {
    const result = this.#deliveryQueue.then(() => this.#flush(), () => this.#flush());
    this.#deliveryQueue = result.then(() => undefined, () => undefined);
    return result;
  }

  async #flush() {
    await this.outbox.initialize();
    const state = this.outbox.stats();
    const now = this.clock();
    if (state.blocked) return { delivered: 0, blocked: true, errorCode: state.blocked.errorCode, pending: state.pending };
    if (state.retry && Date.parse(state.retry.nextAttemptAt) > now) return { delivered: 0, deferred: true, nextAttemptAt: state.retry.nextAttemptAt, pending: state.pending };
    const records = await this.outbox.pending({ limit: this.batchSize });
    if (!records.length) return { delivered: 0, pending: 0 };
    const batchId = batchIdFor(records);
    const firstSequence = records[0].sequence;
    const lastSequence = records.at(-1).sequence;
    try {
      await this.exporter.send(records.map((record) => record.event), { batchId, firstSequence, lastSequence });
      const updated = await this.outbox.acknowledge({ throughSequence: lastSequence, batchId });
      return { delivered: records.length, batchId, pending: updated.pending };
    } catch (error) {
      const attempts = state.retry?.throughSequence === lastSequence ? state.retry.attempts + 1 : 1;
      const delay = Math.min(this.maxRetryMs, this.baseRetryMs * (2 ** Math.min(attempts - 1, 20)));
      const retryable = error.retryable !== false;
      const nextAttemptAt = retryable ? new Date(now + delay).toISOString() : null;
      await this.outbox.recordFailure({ throughSequence: lastSequence, attempts, nextAttemptAt, errorCode: safeErrorCode(error), retryable, failedAt: new Date(now).toISOString() });
      error.exportRetry = { attempts, nextAttemptAt, retryable, blocked: !retryable };
      throw error;
    }
  }

  async resume(options) { return this.outbox.resumeBlocked(options); }

  async drain({ maxBatches = 10 } = {}) {
    if (!Number.isSafeInteger(maxBatches) || maxBatches < 1 || maxBatches > 1000) throw new Error('maxBatches must be between 1 and 1000');
    let delivered = 0;
    for (let index = 0; index < maxBatches; index += 1) {
      const result = await this.flush();
      delivered += result.delivered;
      if (!result.delivered) return { delivered, pending: result.pending, deferred: result.deferred === true, blocked: result.blocked === true };
      if (result.pending === 0) return { delivered, pending: 0, deferred: false };
    }
    return { delivered, pending: this.outbox.stats().pending, deferred: false };
  }
}

module.exports = { CloudExportService, batchIdFor, safeErrorCode };

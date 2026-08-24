'use strict';

const { canonicalJson } = require('../core/canonical');
const { batchIdFor, safeErrorCode } = require('../export/service');
const { ExportDeliveryError } = require('../export/https-exporter');

function validateAlert(alert) {
  if (!alert || typeof alert !== 'object' || Array.isArray(alert)) throw new Error('Alert webhook input must be an alert object');
  if (alert.schemaVersion !== 1 || typeof alert.id !== 'string' || !alert.id) throw new Error('Alert webhook input requires a versioned alert ID');
  if (typeof alert.title !== 'string' || !alert.title || typeof alert.severity !== 'string' || Number.isNaN(Date.parse(alert.time))) throw new Error('Alert webhook input is invalid');
  if (!Array.isArray(alert.entities) || !Array.isArray(alert.evidence)) throw new Error('Alert webhook input requires entity and evidence arrays');
  return {
    schemaVersion: 1,
    id: alert.id,
    findingId: alert.findingId,
    title: alert.title,
    severity: alert.severity,
    severityScore: alert.severityScore,
    time: alert.time,
    status: alert.status,
    entities: [...alert.entities],
    evidence: [...alert.evidence],
    confidence: alert.confidence,
    analyticKind: alert.analyticKind
  };
}

class AlertWebhookExporter {
  constructor({ endpoint, credentialProvider = null, credentialReference = null, fetchImpl = globalThis.fetch, timeoutMs = 10000, maxPayloadBytes = 1024 * 1024 } = {}) {
    let url;
    try { url = new URL(endpoint); } catch { throw new Error('Alert webhook endpoint must be a valid URL'); }
    if (url.protocol !== 'https:') throw new Error('Alert webhook endpoint must use HTTPS');
    if (url.username || url.password) throw new Error('Alert webhook endpoint must not contain credentials');
    if (url.hash) throw new Error('Alert webhook endpoint must not contain a fragment');
    if (typeof fetchImpl !== 'function') throw new Error('Alert webhook requires a fetch implementation');
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 120000) throw new Error('Alert webhook timeout must be between 100 and 120000 milliseconds');
    if (!Number.isSafeInteger(maxPayloadBytes) || maxPayloadBytes < 1024) throw new Error('Alert webhook payload limit must be at least 1024 bytes');
    if (credentialReference && (!credentialProvider || typeof credentialProvider.get !== 'function')) throw new Error('Alert webhook credential reference requires a secret provider');
    this.endpoint = url.toString();
    this.credentialProvider = credentialProvider;
    this.credentialReference = credentialReference;
    this.fetch = fetchImpl;
    this.timeoutMs = timeoutMs;
    this.maxPayloadBytes = maxPayloadBytes;
  }

  async send(alerts, { batchId, firstSequence, lastSequence } = {}) {
    if (!Array.isArray(alerts) || !alerts.length) throw new Error('Alert webhook requires a non-empty alert batch');
    if (typeof batchId !== 'string' || !/^[a-f0-9]{64}$/.test(batchId)) throw new Error('Alert webhook requires a SHA-256 batch ID');
    if (!Number.isSafeInteger(firstSequence) || !Number.isSafeInteger(lastSequence) || firstSequence < 1 || lastSequence < firstSequence) throw new Error('Alert webhook requires a valid sequence range');
    const selected = alerts.map(validateAlert);
    const body = canonicalJson({ schemaVersion: 1, batchId, firstSequence, lastSequence, alerts: selected });
    if (Buffer.byteLength(body) > this.maxPayloadBytes) throw new ExportDeliveryError('Alert webhook batch exceeds the configured payload limit', { code: 'payload_too_large', retryable: false });
    const headers = { 'content-type': 'application/json', 'user-agent': 'lookout-alert-webhook/1', 'idempotency-key': batchId, 'x-lookout-batch-id': batchId };
    if (this.credentialReference) {
      const credential = await this.credentialProvider.get(this.credentialReference);
      if (typeof credential !== 'string' || !credential) throw new ExportDeliveryError('Alert webhook credential is unavailable', { code: 'credential_unavailable', retryable: false });
      headers.authorization = `Bearer ${credential}`;
    }
    let response;
    try {
      response = await this.fetch(this.endpoint, { method: 'POST', headers, body, redirect: 'error', signal: AbortSignal.timeout(this.timeoutMs) });
    } catch (error) {
      if (error instanceof ExportDeliveryError) throw error;
      throw new ExportDeliveryError(`Alert webhook request failed: ${error.name || 'network error'}`, { code: error.name === 'TimeoutError' ? 'timeout' : 'network_error' });
    }
    if (response.status < 200 || response.status >= 300) {
      const retryable = response.status === 408 || response.status === 425 || response.status === 429 || response.status >= 500;
      throw new ExportDeliveryError(`Alert webhook returned HTTP ${response.status}`, { code: `http_${response.status}`, retryable, status: response.status });
    }
    return { batchId, status: response.status, accepted: selected.length };
  }
}

class AlertWebhookService {
  #deliveryQueue = Promise.resolve();

  constructor({ outbox, exporter, batchSize = 100, baseRetryMs = 1000, maxRetryMs = 15 * 60 * 1000, clock = () => Date.now() } = {}) {
    if (!outbox || typeof outbox.enqueue !== 'function' || typeof outbox.pending !== 'function') throw new Error('Alert webhook service requires an outbox');
    if (!exporter || typeof exporter.send !== 'function') throw new Error('Alert webhook service requires an exporter');
    if (!Number.isSafeInteger(batchSize) || batchSize < 1 || batchSize > 1000) throw new Error('Alert webhook batch size must be between 1 and 1000');
    if (!Number.isSafeInteger(baseRetryMs) || baseRetryMs < 100 || !Number.isSafeInteger(maxRetryMs) || maxRetryMs < baseRetryMs) throw new Error('Invalid alert webhook retry settings');
    this.outbox = outbox;
    this.exporter = exporter;
    this.batchSize = batchSize;
    this.baseRetryMs = baseRetryMs;
    this.maxRetryMs = maxRetryMs;
    this.clock = clock;
  }

  async enqueue(alerts) {
    if (!Array.isArray(alerts)) throw new Error('Alert webhook input must be an alert array');
    return this.outbox.enqueue(alerts.map(validateAlert));
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
      error.webhookRetry = { attempts, nextAttemptAt, retryable, blocked: !retryable };
      throw error;
    }
  }

  async resume() { return this.outbox.resumeBlocked(); }
}

module.exports = { AlertWebhookExporter, AlertWebhookService, validateAlert };

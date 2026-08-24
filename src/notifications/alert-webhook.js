'use strict';

const { canonicalJson, stableId } = require('../core/canonical');
const { SnapshotStore } = require('../storage/snapshot-store');
const { DurableExportOutbox } = require('../export/outbox');
const { ExportDeliveryError } = require('../export/https-exporter');
const { batchIdFor, safeErrorCode } = require('../export/service');

function defaultState() {
  return { schemaVersion: 1, processedAlertIds: [], lastQueuedByFingerprint: {}, suppressed: 0 };
}

function validateState(value) {
  if (!value) return defaultState();
  if (value.schemaVersion !== 1 || !Array.isArray(value.processedAlertIds) || value.processedAlertIds.some((id) => typeof id !== 'string')) throw new Error('Invalid alert webhook state');
  if (!value.lastQueuedByFingerprint || typeof value.lastQueuedByFingerprint !== 'object' || Array.isArray(value.lastQueuedByFingerprint)) throw new Error('Invalid alert webhook cooldown state');
  for (const [fingerprint, at] of Object.entries(value.lastQueuedByFingerprint)) {
    if (!/^alert-webhook-cooldown_[a-f0-9]{24}$/.test(fingerprint) || Number.isNaN(Date.parse(at))) throw new Error('Invalid alert webhook cooldown entry');
  }
  if (!Number.isSafeInteger(value.suppressed) || value.suppressed < 0) throw new Error('Invalid alert webhook suppression count');
  return structuredClone(value);
}

function alertFingerprint(alert) {
  return stableId('alert-webhook-cooldown', {
    ruleId: alert.ruleId || alert.title,
    entities: [...(alert.entities || [])].sort()
  });
}

function webhookAlert(alert) {
  return {
    id: alert.id,
    title: alert.title,
    ruleId: alert.ruleId || null,
    severity: alert.severity,
    time: alert.time,
    firstSeen: alert.firstSeen || alert.time,
    status: alert.status,
    entities: [...(alert.entities || [])],
    affectedSystems: structuredClone(alert.affectedSystems || []),
    evidence: [...(alert.evidence || [])],
    confidence: alert.confidence,
    analyticKind: alert.analyticKind,
    matchReason: alert.matchReason || null
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
    if (credentialReference && (!credentialProvider || typeof credentialProvider.get !== 'function')) throw new Error('Alert webhook credential reference requires a secret provider');
    this.endpoint = url.toString();
    this.credentialProvider = credentialProvider;
    this.credentialReference = credentialReference;
    this.fetch = fetchImpl;
    this.timeoutMs = timeoutMs;
    this.maxPayloadBytes = maxPayloadBytes;
  }

  async send(alerts, { batchId, firstSequence, lastSequence } = {}) {
    const body = canonicalJson({ schemaVersion: 1, type: 'lookout.alert.batch', batchId, firstSequence, lastSequence, alerts });
    if (Buffer.byteLength(body) > this.maxPayloadBytes) throw new ExportDeliveryError('Alert webhook payload exceeds the configured limit', { code: 'payload_too_large', retryable: false });
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
    return { batchId, status: response.status, accepted: alerts.length };
  }
}

class AlertWebhookService {
  #queue = Promise.resolve();
  #deliveryQueue = Promise.resolve();

  constructor({ outbox, exporter, stateStore, cooldownSeconds = 300, batchSize = 50, baseRetryMs = 1000, maxRetryMs = 15 * 60 * 1000, clock = () => Date.now() } = {}) {
    if (!outbox || !exporter || !stateStore) throw new Error('Alert webhook service requires an outbox, exporter, and state store');
    if (!Number.isInteger(cooldownSeconds) || cooldownSeconds < 0 || cooldownSeconds > 86400) throw new Error('Alert webhook cooldown must be between 0 and 86400 seconds');
    if (!Number.isInteger(batchSize) || batchSize < 1 || batchSize > 1000) throw new Error('Alert webhook batch size must be between 1 and 1000');
    this.outbox = outbox;
    this.exporter = exporter;
    this.stateStore = stateStore;
    this.cooldownSeconds = cooldownSeconds;
    this.batchSize = batchSize;
    this.baseRetryMs = baseRetryMs;
    this.maxRetryMs = maxRetryMs;
    this.clock = clock;
    this.state = defaultState();
  }

  async initialize() {
    await this.outbox.initialize();
    this.state = validateState(await this.stateStore.load());
    return this;
  }

  async enqueue(alerts) {
    const work = async () => {
      const nextState = structuredClone(this.state);
      const processed = new Set(nextState.processedAlertIds);
      const selected = [];
      let duplicates = 0;
      let suppressed = 0;
      for (const alert of [...alerts].sort((left, right) => left.time.localeCompare(right.time) || left.id.localeCompare(right.id))) {
        if (processed.has(alert.id)) { duplicates += 1; continue; }
        const fingerprint = alertFingerprint(alert);
        const lastQueuedAt = nextState.lastQueuedByFingerprint[fingerprint];
        const withinCooldown = lastQueuedAt && Date.parse(alert.time) < Date.parse(lastQueuedAt) + this.cooldownSeconds * 1000;
        processed.add(alert.id);
        if (withinCooldown) { suppressed += 1; continue; }
        selected.push(webhookAlert(alert));
        nextState.lastQueuedByFingerprint[fingerprint] = alert.time;
      }
      const result = await this.outbox.enqueue(selected);
      nextState.processedAlertIds = [...processed].sort();
      nextState.suppressed += suppressed;
      await this.stateStore.save(nextState);
      this.state = nextState;
      return { enqueued: result.enqueued, duplicates: duplicates + result.duplicates, suppressed, pending: result.pending };
    };
    const result = this.#queue.then(work, work);
    this.#queue = result.then(() => undefined, () => undefined);
    return result;
  }

  async flush() {
    const result = this.#deliveryQueue.then(() => this.#flush(), () => this.#flush());
    this.#deliveryQueue = result.then(() => undefined, () => undefined);
    return result;
  }

  async #flush() {
    const state = this.outbox.stats();
    const now = this.clock();
    if (state.blocked) return { delivered: 0, blocked: true, errorCode: state.blocked.errorCode, pending: state.pending };
    if (state.retry && Date.parse(state.retry.nextAttemptAt) > now) return { delivered: 0, deferred: true, nextAttemptAt: state.retry.nextAttemptAt, pending: state.pending };
    const records = await this.outbox.pending({ limit: this.batchSize });
    if (!records.length) return { delivered: 0, pending: 0 };
    const batchId = batchIdFor(records);
    const lastSequence = records.at(-1).sequence;
    try {
      await this.exporter.send(records.map((record) => record.event), { batchId, firstSequence: records[0].sequence, lastSequence });
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

  stats() { return { ...this.outbox.stats(), cooldownSeconds: this.cooldownSeconds, suppressed: this.state.suppressed }; }

  async resume() { return this.outbox.resumeBlocked(); }
}

function createAlertWebhookService({ dataDirectory, endpoint, credentialProvider = null, credentialReference = null, protector = null, requireEncryption = false, maxPending = 10000, batchSize = 50, cooldownSeconds = 300, fetchImpl = globalThis.fetch } = {}) {
  const outbox = new DurableExportOutbox(dataDirectory, { protector, requireEncryption, maxPending, filename: 'alert-webhook.jsonl' });
  const stateStore = new SnapshotStore(dataDirectory, 'alert-webhook.state.json', { protector, requireEncryption });
  const exporter = new AlertWebhookExporter({ endpoint, credentialProvider, credentialReference, fetchImpl });
  return new AlertWebhookService({ outbox, exporter, stateStore, cooldownSeconds, batchSize });
}

module.exports = { defaultState, validateState, alertFingerprint, webhookAlert, AlertWebhookExporter, AlertWebhookService, createAlertWebhookService };

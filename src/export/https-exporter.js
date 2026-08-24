'use strict';

const { canonicalJson } = require('../core/canonical');

class ExportDeliveryError extends Error {
  constructor(message, { code = 'delivery_error', retryable = true, status = null } = {}) {
    super(message);
    this.name = 'ExportDeliveryError';
    this.code = code;
    this.retryable = retryable;
    this.status = status;
  }
}

class HttpsBatchExporter {
  constructor({ endpoint, credentialProvider = null, credentialReference = null, fetchImpl = globalThis.fetch, timeoutMs = 10000, maxPayloadBytes = 1024 * 1024, retryableStatuses = [] } = {}) {
    let url;
    try { url = new URL(endpoint); } catch { throw new Error('Cloud export endpoint must be a valid URL'); }
    if (url.protocol !== 'https:') throw new Error('Cloud export endpoint must use HTTPS');
    if (url.username || url.password) throw new Error('Cloud export endpoint must not contain credentials');
    if (url.hash) throw new Error('Cloud export endpoint must not contain a fragment');
    if (typeof fetchImpl !== 'function') throw new Error('HTTPS exporter requires a fetch implementation');
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 120000) throw new Error('Export timeout must be between 100 and 120000 milliseconds');
    if (!Number.isSafeInteger(maxPayloadBytes) || maxPayloadBytes < 1024) throw new Error('Export payload limit must be at least 1024 bytes');
    if (!Array.isArray(retryableStatuses) || retryableStatuses.some((status) => !Number.isSafeInteger(status) || status < 400 || status > 599)) throw new Error('Retryable export statuses are invalid');
    if (credentialReference && (!credentialProvider || typeof credentialProvider.get !== 'function')) throw new Error('Credential reference requires a secret provider');
    this.endpoint = url.toString();
    this.credentialProvider = credentialProvider;
    this.credentialReference = credentialReference;
    this.fetch = fetchImpl;
    this.timeoutMs = timeoutMs;
    this.maxPayloadBytes = maxPayloadBytes;
    this.retryableStatuses = new Set(retryableStatuses);
  }

  async send(events, { batchId, firstSequence, lastSequence, generatedAt } = {}) {
    if (!Array.isArray(events) || !events.length) throw new Error('HTTPS exporter requires a non-empty event batch');
    if (typeof batchId !== 'string' || !/^[a-f0-9]{64}$/.test(batchId)) throw new Error('HTTPS exporter requires a SHA-256 batch ID');
    if (!Number.isSafeInteger(firstSequence) || !Number.isSafeInteger(lastSequence) || firstSequence < 1 || lastSequence < firstSequence) throw new Error('HTTPS exporter requires a valid sequence range');
    if (generatedAt !== undefined && Number.isNaN(Date.parse(generatedAt))) throw new Error('Export generatedAt must be an ISO-compatible timestamp');
    // generatedAt is omitted by the service so a retry is byte-for-byte stable
    // under the same idempotency key. Callers may provide a stable timestamp.
    const body = canonicalJson({ schemaVersion: 1, batchId, generatedAt, firstSequence, lastSequence, events });
    if (Buffer.byteLength(body) > this.maxPayloadBytes) throw new ExportDeliveryError('Export batch exceeds the configured payload limit', { code: 'payload_too_large', retryable: false });
    const headers = { 'content-type': 'application/json', 'user-agent': 'lookout-cloud-export/1', 'idempotency-key': batchId, 'x-lookout-batch-id': batchId };
    if (this.credentialReference) {
      const credential = await this.credentialProvider.get(this.credentialReference);
      if (typeof credential !== 'string' || !credential) throw new ExportDeliveryError('Export credential is unavailable', { code: 'credential_unavailable', retryable: false });
      headers.authorization = `Bearer ${credential}`;
    }
    let response;
    try {
      response = await this.fetch(this.endpoint, { method: 'POST', headers, body, redirect: 'error', signal: AbortSignal.timeout(this.timeoutMs) });
    } catch (error) {
      if (error instanceof ExportDeliveryError) throw error;
      throw new ExportDeliveryError(`Cloud export request failed: ${error.name || 'network error'}`, { code: error.name === 'TimeoutError' ? 'timeout' : 'network_error' });
    }
    if (response.status < 200 || response.status >= 300) {
      const retryable = this.retryableStatuses.has(response.status) || response.status === 408 || response.status === 425 || response.status === 429 || response.status >= 500;
      throw new ExportDeliveryError(`Cloud export returned HTTP ${response.status}`, { code: `http_${response.status}`, retryable, status: response.status });
    }
    return { batchId, status: response.status, accepted: events.length };
  }
}

module.exports = { ExportDeliveryError, HttpsBatchExporter };

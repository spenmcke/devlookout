'use strict';

const { DurableExportOutbox } = require('./outbox');
const { HttpsBatchExporter, ExportDeliveryError } = require('./https-exporter');
const { CloudExportService } = require('./service');

function createHttpsExportService({
  dataDirectory, policy, endpoint, credentialProvider = null, credentialReference = null,
  protector = null, requireEncryption = false, maxPending = 50000, batchSize = 100,
  timeoutMs = 10000, maxPayloadBytes = 1024 * 1024, baseRetryMs = 1000,
  maxRetryMs = 15 * 60 * 1000, fetchImpl = globalThis.fetch, clock
} = {}) {
  const outbox = new DurableExportOutbox(dataDirectory, { protector, requireEncryption, maxPending });
  const exporter = new HttpsBatchExporter({ endpoint, credentialProvider, credentialReference, fetchImpl, timeoutMs, maxPayloadBytes });
  return new CloudExportService({ outbox, exporter, policy, batchSize, baseRetryMs, maxRetryMs, clock });
}

module.exports = { createHttpsExportService, DurableExportOutbox, HttpsBatchExporter, ExportDeliveryError, CloudExportService };

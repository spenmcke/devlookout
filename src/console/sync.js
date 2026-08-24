'use strict';

const { LatestSnapshotOutbox } = require('./latest-snapshot-outbox');
const { HttpsBatchExporter } = require('../export/https-exporter');
const { CloudExportService } = require('../export/service');
const { validateConsoleSnapshot } = require('./snapshot');

function createConsoleSyncService({
  dataDirectory, endpoint, credentialProvider = null, credentialReference = null,
  protector = null, requireEncryption = false, maxPending = 1000, batchSize = 10,
  timeoutMs = 10000, maxPayloadBytes = 1024 * 1024, fetchImpl = globalThis.fetch, clock,
  deploymentId = 'local'
} = {}) {
  const outbox = new LatestSnapshotOutbox(dataDirectory, { protector, requireEncryption });
  const exporter = new HttpsBatchExporter({ endpoint, credentialProvider, credentialReference, fetchImpl, timeoutMs, maxPayloadBytes, retryableStatuses: [401, 403] });
  const service = new CloudExportService({
    outbox, exporter, policy: { enabled: true }, batchSize, clock,
    selector: (snapshot) => structuredClone(validateConsoleSnapshot(snapshot))
  });
  service.initialize = async () => {
    await outbox.initialize();
    const resumed = await service.resume({ includeRetry: true, errorCodes: ['http_401', 'http_403', 'credential_unavailable'] });
    return { resumedAuthenticationFailure: resumed, ...outbox.stats() };
  };
  service.capture = async (runtime, options = {}) => service.enqueue([await runtime.consoleSnapshot({ deploymentId, ...options })]);
  return service;
}

module.exports = { createConsoleSyncService };

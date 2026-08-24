'use strict';

const { LatestSnapshotOutbox } = require('../console/latest-snapshot-outbox');
const { HttpsBatchExporter } = require('../export/https-exporter');
const { CloudExportService } = require('../export/service');
const { validateOperationalHealthSnapshot } = require('./snapshot');

function operationalEndpoint(consoleEndpoint) {
  const url = new URL(consoleEndpoint);
  const match = /^\/v1\/console-sync\/(dpl_[A-Za-z0-9_-]{32})$/.exec(url.pathname);
  if (!match || url.search || url.hash) throw new Error('Operational health requires a hosted console sync endpoint');
  url.pathname = `/v1/operational-health/${match[1]}`;
  return url.toString();
}

function createOperationalHealthSyncService({ dataDirectory, consoleEndpoint, credentialProvider, credentialReference, protector = null, requireEncryption = false, fetchImpl = globalThis.fetch, clock } = {}) {
  const outbox = new LatestSnapshotOutbox(dataDirectory, { protector, requireEncryption, filename: 'operational-health-sync.latest.json' });
  const exporter = new HttpsBatchExporter({ endpoint: operationalEndpoint(consoleEndpoint), credentialProvider, credentialReference, fetchImpl, maxPayloadBytes: 1024 * 1024 });
  const service = new CloudExportService({
    outbox, exporter, policy: { enabled: true }, batchSize: 1, clock,
    selector: (snapshot) => structuredClone(validateOperationalHealthSnapshot(snapshot))
  });
  service.initialize = async () => {
    await outbox.initialize();
    const resumed = await service.resume({ includeRetry: true, errorCodes: ['http_401', 'http_403', 'credential_unavailable'] });
    return { resumedAuthenticationFailure: resumed, ...outbox.stats() };
  };
  service.capture = async (registry, options) => service.enqueue([registry.snapshot(options)]);
  return service;
}

module.exports = { createOperationalHealthSyncService, operationalEndpoint };

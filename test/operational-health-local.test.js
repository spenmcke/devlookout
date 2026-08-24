'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { LocalOperationalHealthRegistry } = require('../src/operations-health/local-registry');
const { createOperationalHealthSyncService, operationalEndpoint } = require('../src/operations-health/sync');

function sample(collectorId, observedAt) {
  return {
    schemaVersion: 1, collectorId, entityKey: 'endpoint:one', observedAt,
    host: { uptimeSeconds: 1, cpu: { logicalProcessors: 1, usedPercent: 1, loadAverage: [0, 0, 0] }, memory: { totalBytes: 100, usedBytes: 10, availableBytes: 90, usedPercent: 10 }, filesystems: { status: 'available', truncated: false, volumes: [] } },
    lookout: { process: { uptimeSeconds: 1, cpu: { usedPercent: 1, cumulativeMilliseconds: 1 }, memory: { residentBytes: 10, heapUsedBytes: 5, externalBytes: 1 } }, dataStorage: { status: 'available', bytes: 1, entries: 1, truncated: false }, delivery: { status: 'available', queues: [] } }
  };
}

test('local operational registry persists only the latest separate sample per collector', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-operational-registry-'));
  try {
    const registry = await new LocalOperationalHealthRegistry({ dataDirectory: directory }).initialize();
    await registry.accept({ collectorId: 'collector-one', sequence: 1, samples: [sample('collector-one', '2026-08-23T12:00:00.000Z')] });
    await registry.accept({ collectorId: 'collector-one', sequence: 2, samples: [sample('collector-one', '2026-08-23T12:05:00.000Z')] });
    const restored = await new LocalOperationalHealthRegistry({ dataDirectory: directory }).initialize();
    const snapshot = restored.snapshot({ deploymentId: 'deployment-one' });
    assert.equal(snapshot.nodes.length, 1);
    assert.equal(snapshot.nodes[0].collectorSequence, 2);
    assert.equal(snapshot.generatedAt, '2026-08-23T12:05:00.000Z');
    assert.equal(JSON.stringify(snapshot).includes('events'), false);
  } finally { await fs.rm(directory, { recursive: true, force: true }); }
});

test('operational sync derives a separate endpoint without accepting arbitrary console URLs', () => {
  const deployment = `dpl_${'a'.repeat(32)}`;
  assert.equal(operationalEndpoint(`https://app.example/v1/console-sync/${deployment}`), `https://app.example/v1/operational-health/${deployment}`);
  assert.throws(() => operationalEndpoint('https://app.example/v1/anything'), /hosted console sync/);
});

test('operational sync initializes its durable outbox before central startup', async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-operational-sync-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const deployment = `dpl_${'b'.repeat(32)}`;
  const service = createOperationalHealthSyncService({
    dataDirectory: directory,
    consoleEndpoint: `https://app.example/v1/console-sync/${deployment}`,
    credentialProvider: { async get() { return 'credential'; } },
    credentialReference: 'console-token'
  });
  const state = await service.initialize();
  assert.equal(state.pending, 0);
});

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { buildConsoleSnapshot, validateConsoleSnapshot } = require('../src/console/snapshot');
const { createConsoleSyncService } = require('../src/console/sync');

test('SaaS console projection contains topology, coverage, cases, and health but no raw logs', () => {
  const snapshot = buildConsoleSnapshot({
    deploymentId: 'fleet-test', generatedAt: '2026-08-19T00:00:00.000Z',
    graph: {
      entities: [
        { key: 'endpoint:a', type: 'endpoint', name: 'server-a', platform: 'linux', lastSeen: '2026-08-19T00:00:00.000Z', provenance: ['fact-secret'] },
        { key: 'network:private', type: 'network', name: 'Private network', lastSeen: '2026-08-19T00:00:00.000Z', provenance: ['fact-secret'] }
      ],
      relationships: [{ fromKey: 'endpoint:a', toKey: 'network:private', relation: 'member_of', provenance: ['fact-secret'] }],
      capabilities: [
        { entityKey: 'endpoint:a', capability: 'authentication', status: 'available', provenance: ['fact-secret'] },
        { entityKey: 'endpoint:a', capability: 'sensor_health', status: 'available', provenance: ['fact-secret'] }
      ]
    },
    cases: {
      alerts: [{ id: 'alert:a', ruleId: 'auth-failure-burst', title: 'Authentication burst', severity: 'high', status: 'open', firstSeen: '2026-08-19T00:00:00.000Z', lastSeen: '2026-08-19T00:00:00.000Z', entities: ['endpoint:a'], evidence: ['event:private'], confidence: 0.9, matchReason: 'Twelve failures matched.', statusHistory: [{ status: 'open', actor: 'lookout', at: '2026-08-19T00:00:00.000Z', reason: 'Created from a detection rule match.' }] }],
      incidents: []
    },
    detectionPlan: [{ analyticId: 'auth-failure-burst', state: 'ready', deploy: true, coveredEntityKeys: ['endpoint:a'], gapEntityKeys: [], missingRequired: [] }],
    analytics: [{ id: 'auth-failure-burst', title: 'Authentication failure burst', severity: 'high' }],
    status: { status: 'ok', graph: { entities: 1, relationships: 1, capabilities: 1 }, detections: { ready: 1, partial: 0, degraded: 0, blocked: 0 }, cases: { alerts: 1, incidents: 0 }, cloudExport: { enabled: false } }
  });
  assert.equal(snapshot.graph.entities[0].name, 'server-a');
  assert.equal(snapshot.graph.entities[0].managed, true);
  assert.deepEqual(snapshot.graph.relationships[0], { fromKey: 'endpoint:a', toKey: 'network:private', relation: 'member_of' });
  assert.equal(snapshot.alerts[0].evidenceCount, 1);
  assert.equal(snapshot.alerts[0].confidence, 0.9);
  assert.equal(snapshot.alerts[0].matchReason, 'Twelve failures matched.');
  assert.equal(snapshot.alerts[0].statusHistory.length, 1);
  assert.equal(snapshot.detections[0].title, 'Authentication failure burst');
  assert.equal(snapshot.detections[0].deploy, true);
  const encoded = JSON.stringify(snapshot);
  assert.equal(encoded.includes('event:private'), false);
  assert.equal(encoded.includes('fact-secret'), false);
  assert.equal(Object.hasOwn(snapshot, 'events'), false);
  assert.equal(validateConsoleSnapshot(snapshot), snapshot);
});

test('console projection rejects secret-bearing data', () => {
  const invalid = { schemaVersion: 1, id: 'snapshot', kind: 'lookout_console_snapshot', graph: { entities: [], relationships: [], capabilities: [] }, alerts: [], incidents: [], detections: [], auth_token: 'not-allowed' };
  assert.throws(() => validateConsoleSnapshot(invalid), /Invalid console snapshot/);
});

test('console sync is outbound-only, durable, and sends no raw event records', async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-console-sync-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  let request;
  const service = createConsoleSyncService({
    dataDirectory: directory, endpoint: 'https://console.example.test/v1/snapshots',
    deploymentId: 'deployment-123',
    fetchImpl: async (url, options) => { request = { url: String(url), options }; return { status: 202 }; }
  });
  const projection = buildConsoleSnapshot({
    graph: { entities: [], relationships: [], capabilities: [] }, cases: { alerts: [], incidents: [] }, detectionPlan: [],
    status: { status: 'ok', graph: {}, detections: {}, cases: {}, cloudExport: { enabled: false } }, generatedAt: '2026-08-19T00:00:00.000Z'
  });
  let captureOptions;
  await service.capture({ consoleSnapshot: async (options) => { captureOptions = options; return projection; } });
  const latestProjection = { ...projection, id: 'latest-snapshot', generatedAt: '2026-08-19T00:01:00.000Z' };
  await service.enqueue([latestProjection]);
  assert.equal(captureOptions.deploymentId, 'deployment-123');
  assert.equal(service.outbox.stats().pending, 1);
  const delivered = await service.flush();
  assert.equal(delivered.delivered, 1);
  assert.equal(request.url, 'https://console.example.test/v1/snapshots');
  const body = JSON.parse(request.options.body);
  assert.equal(body.events[0].id, 'latest-snapshot');
  assert.equal(body.events[0].kind, 'lookout_console_snapshot');
  assert.equal(Object.hasOwn(body.events[0], 'events'), false);
});

test('console sync automatically resumes a persisted authentication block after credential repair', async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-console-auth-repair-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const projection = buildConsoleSnapshot({
    graph: { entities: [], relationships: [], capabilities: [] }, cases: { alerts: [], incidents: [] }, detectionPlan: [],
    status: { status: 'ok', graph: {}, detections: {}, cases: {}, cloudExport: { enabled: false } }, generatedAt: '2026-08-21T00:00:00.000Z'
  });
  const blocked = createConsoleSyncService({
    dataDirectory: directory, endpoint: 'https://console.example.test/v1/snapshots', deploymentId: 'deployment-123',
    fetchImpl: async () => ({ status: 202 })
  });
  await blocked.enqueue([projection]);
  await blocked.outbox.recordFailure({ throughSequence: 1, attempts: 1, errorCode: 'http_401', retryable: false });
  assert.equal(blocked.outbox.stats().blocked.errorCode, 'http_401');

  const repaired = createConsoleSyncService({
    dataDirectory: directory, endpoint: 'https://console.example.test/v1/snapshots', deploymentId: 'deployment-123',
    fetchImpl: async () => ({ status: 202 })
  });
  const initialized = await repaired.initialize();
  assert.equal(initialized.resumedAuthenticationFailure, true);
  assert.equal(initialized.blocked, null);
  assert.equal((await repaired.flush()).delivered, 1);
});

test('console authentication failures retry instead of permanently blocking reporting', async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-console-auth-retry-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const service = createConsoleSyncService({
    dataDirectory: directory, endpoint: 'https://console.example.test/v1/snapshots', deploymentId: 'deployment-123',
    fetchImpl: async () => ({ status: 401 })
  });
  const projection = buildConsoleSnapshot({
    graph: { entities: [], relationships: [], capabilities: [] }, cases: { alerts: [], incidents: [] }, detectionPlan: [],
    status: { status: 'ok', graph: {}, detections: {}, cases: {}, cloudExport: { enabled: false } }, generatedAt: '2026-08-21T00:00:00.000Z'
  });
  await service.enqueue([projection]);
  await assert.rejects(service.flush(), (error) => error.code === 'http_401' && error.exportRetry.retryable === true && error.exportRetry.blocked === false);
  assert.equal(service.outbox.stats().blocked, null);
  assert.equal(service.outbox.stats().retry.errorCode, 'http_401');
});

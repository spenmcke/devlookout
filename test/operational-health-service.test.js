'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { OperationalHealthService } = require('../src/operations-health/service');

function node({ observedAt, memory = 50, cpu = 20, disk = 40 } = {}) {
  return {
    collectorSequence: Date.parse(observedAt), schemaVersion: 1, collectorId: 'collector-one', entityKey: 'endpoint:one', observedAt,
    host: {
      uptimeSeconds: 100, cpu: { logicalProcessors: 2, usedPercent: cpu, loadAverage: [0.1, 0.2, 0.3] },
      memory: { totalBytes: 1000, usedBytes: memory * 10, availableBytes: (100 - memory) * 10, usedPercent: memory },
      filesystems: { status: 'available', truncated: false, volumes: [{ id: '0123456789abcdef', filesystemType: 'ext4', root: true, dataVolume: true, totalBytes: 100 * 1024 ** 3, usedBytes: disk * 1024 ** 3, availableBytes: (100 - disk) * 1024 ** 3, usedPercent: disk }] }
    },
    lookout: {
      process: { uptimeSeconds: 90, cpu: { usedPercent: 5, cumulativeMilliseconds: 100 }, memory: { residentBytes: 100, heapUsedBytes: 50, externalBytes: 5 } },
      dataStorage: { status: 'available', bytes: 10, entries: 1, truncated: false }, delivery: { status: 'available', queues: [] }
    }
  };
}

function snapshot(observedAt, values) {
  return { schemaVersion: 1, kind: 'lookout_operational_health', id: `snapshot-${Date.parse(observedAt)}`, deploymentId: 'deployment-one', generatedAt: observedAt, nodes: [node({ observedAt, ...values })] };
}

function memoryStore() {
  const alerts = new Map();
  const notifications = [];
  return {
    alerts, notifications, samples: [], missing: [],
    async insertSample(value) { this.samples.push(value); return value; },
    async getAlertState({ alertKey }) { return alerts.get(alertKey) || null; },
    async upsertAlertState(value) {
      const row = { alert_key: value.alertKey, status: value.status, severity: value.severity, opened_at: value.openedAt, updated_at: value.updatedAt, resolved_at: value.resolvedAt, last_notified_at: value.lastNotifiedAt, details: value.details };
      alerts.set(value.alertKey, row); return row;
    },
    async enqueueNotification(value) { notifications.push(value); return value; },
    async missingTelemetry() { return this.missing; },
    async listAlertStates() { return [...alerts.values()]; }, async recentSamples() { return this.samples; }, async recentDeploymentSamples() { return this.samples; },
    async deleteExpired() { return 0; }, async deleteTenant() { return 0; }
  };
}

test('operational thresholds persist before opening and recover without duplicate notifications', async () => {
  const store = memoryStore();
  let now = new Date('2026-08-23T12:00:00.000Z');
  const service = new OperationalHealthService({ store, now: () => now, notificationChannel: 'slack' });
  const principal = { tenantId: 'tenant-one', deploymentId: 'deployment-one' };
  await service.acceptSnapshot(principal, snapshot(now.toISOString(), { memory: 86 }));
  assert.equal(store.alerts.get('collector-one:vm_memory').status, 'pending');
  assert.equal(store.notifications.length, 0);
  now = new Date('2026-08-23T12:15:00.000Z');
  await service.acceptSnapshot(principal, snapshot(now.toISOString(), { memory: 86 }));
  assert.equal(store.alerts.get('collector-one:vm_memory').status, 'open');
  assert.equal(store.notifications.length, 1);
  now = new Date('2026-08-23T12:20:00.000Z');
  await service.acceptSnapshot(principal, snapshot(now.toISOString(), { memory: 50 }));
  assert.equal(store.alerts.get('collector-one:vm_memory').status, 'open');
  now = new Date('2026-08-23T12:25:00.000Z');
  await service.acceptSnapshot(principal, snapshot(now.toISOString(), { memory: 50 }));
  assert.equal(store.alerts.get('collector-one:vm_memory').status, 'resolved');
  assert.equal(store.notifications.length, 2);
  assert.equal(store.notifications[1].payload.transition, 'recovered');
});

test('missing VM telemetry opens a vendor-only critical alert once', async () => {
  const store = memoryStore();
  store.missing = [{ tenant_id: 'tenant-one', deployment_id: 'deployment-one', collector_id: 'collector-two' }];
  const service = new OperationalHealthService({ store, now: () => new Date('2026-08-23T12:30:00.000Z'), notificationChannel: 'slack' });
  assert.deepEqual(await service.sweepMissing(), { missing: 1 });
  assert.equal(store.alerts.get('collector-two:telemetry_missing').status, 'open');
  assert.equal(store.notifications.length, 1);
  await service.sweepMissing();
  assert.equal(store.notifications.length, 1);
});

test('one stale collector does not reject fresh deployment telemetry', async () => {
  const store = memoryStore();
  const now = new Date('2026-08-23T12:30:00.000Z');
  const service = new OperationalHealthService({ store, now: () => now });
  const fresh = node({ observedAt: now.toISOString() });
  const stale = { ...node({ observedAt: '2026-08-01T00:00:00.000Z' }), collectorId: 'collector-stale', collectorSequence: 1 };
  const input = { schemaVersion: 1, kind: 'lookout_operational_health', id: 'mixed-age', deploymentId: 'deployment-one', generatedAt: now.toISOString(), nodes: [fresh, stale] };
  assert.deepEqual(await service.acceptSnapshot({ tenantId: 'tenant-one', deploymentId: 'deployment-one' }, input), { accepted: 1 });
  assert.equal(store.samples.length, 1);
  assert.equal(store.samples[0].collectorId, 'collector-one');
});

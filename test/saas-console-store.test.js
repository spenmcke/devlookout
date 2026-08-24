'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { SaasConsoleStore } = require('../src/console/saas-store');
const { batchIdFor } = require('../src/export/service');

function memoryStore() {
  let value = null;
  return { load: async () => structuredClone(value), save: async (next) => { value = structuredClone(next); } };
}

function snapshot(deploymentId, generatedAt, suffix = 'a') {
  return {
    schemaVersion: 1, kind: 'lookout_console_snapshot', id: `snapshot-${suffix}`, deploymentId, generatedAt,
    graph: { entities: [], relationships: [], capabilities: [] }, alerts: [], incidents: [], detections: [],
    health: { status: 'ok', graph: {}, detections: {}, cases: {}, cloudExport: { enabled: false } }
  };
}

function batch(events, firstSequence = 1) {
  const records = events.map((event, index) => ({ sequence: firstSequence + index, event }));
  return { schemaVersion: 1, batchId: batchIdFor(records), firstSequence, lastSequence: firstSequence + events.length - 1, events };
}

test('central heartbeat age is detected and dashboard health is marked missing', async () => {
  let now = Date.parse('2026-08-21T00:00:00.000Z');
  const store = await new SaasConsoleStore({ snapshotStore: memoryStore(), clock: () => new Date(now) }).initialize();
  const deploymentId = `dpl_${'h'.repeat(32)}`;
  const principal = { tenantId: 'tenant-heartbeat', deploymentId };
  await store.acceptBatch(principal, batch([snapshot(deploymentId, new Date(now).toISOString())]));
  now += 299_000;
  assert.deepEqual(await store.missingCentral({ thresholdMs: 300_000 }), []);
  now += 2_000;
  assert.equal((await store.missingCentral({ thresholdMs: 300_000 }))[0].deploymentId, deploymentId);
  await store.markCentralMissing({ tenantId: principal.tenantId, deploymentId, recoverySessionId: 'set_recovery_session_1234', notifiedAt: new Date(now).toISOString() });
  assert.equal((await store.snapshot(principal)).health.status, 'central_missing');
  assert.deepEqual(await store.acceptBatch(principal, batch([snapshot(deploymentId, new Date(now).toISOString())])), { accepted: 1, idempotent: true });
  assert.equal((await store.listDeployments({ tenantId: principal.tenantId }))[0].status, 'active');
  assert.equal((await store.snapshot(principal)).health.status, 'ok');
});

test('SaaS console accepts ordered idempotent snapshots and isolates tenants', async () => {
  const store = await new SaasConsoleStore({ snapshotStore: memoryStore() }).initialize();
  const deploymentId = `dpl_${'a'.repeat(32)}`;
  const principal = { tenantId: 'tenant-a', deploymentId };
  const first = snapshot(deploymentId, '2026-08-20T00:00:00.000Z');
  assert.deepEqual(await store.acceptBatch(principal, batch([first])), { accepted: 1, idempotent: false });
  assert.deepEqual(await store.acceptBatch(principal, batch([first])), { accepted: 1, idempotent: true });
  assert.equal((await store.snapshot(principal)).id, first.id);
  await assert.rejects(() => store.snapshot({ tenantId: 'tenant-b', deploymentId }), /unavailable/);

  const second = snapshot(deploymentId, '2026-08-20T00:01:00.000Z', 'b');
  await assert.rejects(() => store.acceptBatch(principal, batch([second], 3)), /sequence conflict/);
  await store.acceptBatch(principal, batch([second], 2));
  assert.equal((await store.snapshot(principal)).id, second.id);
  const deployments = await store.listDeployments({ tenantId: 'tenant-a' });
  assert.equal(deployments.length, 1);
  assert.equal(deployments[0].deployment_id, deploymentId);
  assert.equal(deployments[0].status, 'active');
  assert.ok(Number.isFinite(Date.parse(deployments[0].updated_at)));
  assert.deepEqual(await store.listDeployments({ tenantId: 'tenant-b' }), []);
});

test('hosted alert status updates accept an omitted reason and survive later snapshots', async () => {
  const store = await new SaasConsoleStore({ snapshotStore: memoryStore(), clock: () => new Date('2026-08-20T00:02:00.000Z') }).initialize();
  const deploymentId = `dpl_${'u'.repeat(32)}`;
  const principal = { tenantId: 'tenant-a', deploymentId };
  const first = snapshot(deploymentId, '2026-08-20T00:00:00.000Z');
  first.alerts = [{ id: 'alert_one', title: 'Test alert', severity: 'high', status: 'open', time: '2026-08-20T00:00:00.000Z', entities: [], evidenceCount: 1, statusHistory: [] }];
  await store.acceptBatch(principal, batch([first]));
  const updated = await store.updateAlert(principal, 'alert_one', { status: 'to_fix', actor: 'owner@example.test' });
  assert.equal(updated.status, 'to_fix');
  assert.equal(Object.hasOwn(updated.statusHistory[0], 'reason'), false);

  const second = snapshot(deploymentId, '2026-08-20T00:01:00.000Z', 'next');
  second.alerts = [{ ...first.alerts[0] }];
  await store.acceptBatch(principal, batch([second], 2));
  assert.equal((await store.snapshot(principal)).alerts[0].status, 'to_fix');
});

test('uninstall clears tracked SaaS data and a later snapshot reactivates the deployment', async () => {
  const clockValues = [new Date('2026-08-20T00:00:00.000Z'), new Date('2026-08-20T00:01:00.000Z'), new Date('2026-08-20T00:02:00.000Z')];
  const store = await new SaasConsoleStore({ snapshotStore: memoryStore(), clock: () => clockValues.shift() }).initialize();
  const deploymentId = `dpl_${'e'.repeat(32)}`;
  const principal = { tenantId: 'tenant-a', deploymentId };
  await store.acceptBatch(principal, batch([snapshot(deploymentId, '2026-08-20T00:00:00.000Z')]));

  assert.deepEqual(await store.markUninstalled(principal), { status: 'uninstalled', idempotent: false });
  assert.deepEqual(await store.markUninstalled(principal), { status: 'uninstalled', idempotent: true });
  const uninstalled = await store.snapshot(principal);
  assert.equal(uninstalled.health.status, 'uninstalled');
  assert.deepEqual(uninstalled.graph.entities, []);
  assert.deepEqual(uninstalled.alerts, []);
  assert.equal((await store.listDeployments({ tenantId: principal.tenantId }))[0].status, 'uninstalled');

  await store.acceptBatch(principal, batch([snapshot(deploymentId, '2026-08-20T00:03:00.000Z', 'reactivated')], 2));
  assert.equal((await store.listDeployments({ tenantId: principal.tenantId }))[0].status, 'active');
  assert.equal((await store.snapshot(principal)).id, 'snapshot-reactivated');
});

test('deployment replacement tombstones old console data and is idempotent when absent', async () => {
  const store = await new SaasConsoleStore({ snapshotStore: memoryStore(), clock: () => new Date('2026-08-20T00:05:00.000Z') }).initialize();
  const deploymentId = `dpl_${'r'.repeat(32)}`;
  const principal = { tenantId: 'tenant-a', deploymentId };
  await store.acceptBatch(principal, batch([snapshot(deploymentId, '2026-08-20T00:00:00.000Z')]));
  assert.deepEqual(await store.markReplaced(principal), { status: 'uninstalled', idempotent: false });
  assert.equal((await store.snapshot(principal)).health.status, 'uninstalled');
  assert.deepEqual(await store.markReplaced(principal), { status: 'uninstalled', idempotent: true });
  assert.deepEqual(await store.markReplaced({ tenantId: 'tenant-a', deploymentId: `dpl_${'z'.repeat(32)}` }), { status: 'absent', idempotent: true });
});

test('same deployment retry resets snapshot sequencing for a fresh installation', async () => {
  const store = await new SaasConsoleStore({ snapshotStore: memoryStore() }).initialize();
  const deploymentId = `dpl_${'s'.repeat(32)}`;
  const principal = { tenantId: 'tenant-a', deploymentId };
  await store.acceptBatch(principal, batch([snapshot(deploymentId, '2026-08-20T00:00:00.000Z')]));
  await store.acceptBatch(principal, batch([snapshot(deploymentId, '2026-08-20T00:01:00.000Z', 'second')], 2));
  assert.deepEqual(await store.resetForRetry(principal), { status: 'reset', idempotent: false });
  await assert.rejects(() => store.snapshot(principal), /unavailable/);
  assert.deepEqual(await store.acceptBatch(principal, batch([snapshot(deploymentId, '2026-08-20T00:02:00.000Z', 'fresh')])), { accepted: 1, idempotent: false });
  assert.equal((await store.snapshot(principal)).id, 'snapshot-fresh');
});

test('SaaS console rejects forged batch IDs and cross-deployment snapshots', async () => {
  const store = await new SaasConsoleStore({ snapshotStore: memoryStore() }).initialize();
  const deploymentId = `dpl_${'b'.repeat(32)}`;
  const principal = { tenantId: 'tenant-a', deploymentId };
  const item = batch([snapshot(deploymentId, '2026-08-20T00:00:00.000Z')]);
  item.batchId = crypto.randomBytes(32).toString('hex');
  await assert.rejects(() => store.acceptBatch(principal, item), /identifier/);
  await assert.rejects(() => store.acceptBatch(principal, batch([snapshot(`dpl_${'c'.repeat(32)}`, '2026-08-20T00:00:00.000Z')])), /deployment/);
});

test('tenant deletion removes snapshots and permanently blocks stale deployment uploads', async () => {
  const store = await new SaasConsoleStore({ snapshotStore: memoryStore() }).initialize();
  const deploymentId = `dpl_${'d'.repeat(32)}`;
  const principal = { tenantId: 'tenant-delete', deploymentId };
  const item = batch([snapshot(deploymentId, '2026-08-20T00:00:00.000Z')]);
  await store.acceptBatch(principal, item);
  assert.deepEqual(await store.deleteTenant({ tenantId: principal.tenantId }), { removedDeployments: 1 });
  await assert.rejects(() => store.snapshot(principal), /unavailable/);
  await assert.rejects(() => store.acceptBatch(principal, item), /deleted/);
  assert.deepEqual(await store.deleteTenant({ tenantId: principal.tenantId }), { removedDeployments: 0 });
});

test('failed account deletion can clear its console marker without restoring snapshots', async () => {
  const store = await new SaasConsoleStore({ snapshotStore: memoryStore() }).initialize();
  const deploymentId = `dpl_${'e'.repeat(32)}`;
  const principal = { tenantId: 'tenant-restore', deploymentId };
  const item = batch([snapshot(deploymentId, '2026-08-20T00:00:00.000Z')]);
  await store.acceptBatch(principal, item);
  await store.deleteTenant({ tenantId: principal.tenantId });
  assert.deepEqual(await store.restoreTenantAfterFailedDeletion({ tenantId: principal.tenantId }), { restored: true });
  await assert.rejects(() => store.snapshot(principal), /unavailable/);
  assert.deepEqual(await store.acceptBatch(principal, item), { accepted: 1, idempotent: false });
});

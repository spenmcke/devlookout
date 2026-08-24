'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { SnapshotStore } = require('../src/storage/snapshot-store');
const { DurableExportOutbox } = require('../src/export/outbox');
const { ExportDeliveryError } = require('../src/export/https-exporter');
const { AlertWebhookExporter, AlertWebhookService } = require('../src/notifications/alert-webhook');
const { LookoutRuntime } = require('../src/runtime');
const { AdapterRegistry } = require('../src/adapters/contract');
const { declarationAdapter } = require('../src/adapters/declaration');
const { createEvent } = require('../src/events/schema');

function alert(id, time, entity = 'endpoint:server') {
  return { id, title: 'Test alert', ruleId: 'test-rule', severity: 'high', time, firstSeen: time, status: 'open', entities: [entity], evidence: [`event:${id}`], confidence: 0.9, analyticKind: 'threshold', matchReason: 'Test evidence matched.' };
}

async function fixture(directory, exporter, clock = () => Date.parse('2026-08-18T10:00:00.000Z')) {
  const outbox = new DurableExportOutbox(directory, { filename: 'alert-webhook.jsonl' });
  const stateStore = new SnapshotStore(directory, 'alert-webhook.state.json');
  return new AlertWebhookService({ outbox, stateStore, exporter, cooldownSeconds: 300, batchSize: 10, clock }).initialize();
}

test('alert webhook exporter sends a stable idempotent alert batch', async () => {
  const calls = [];
  const exporter = new AlertWebhookExporter({ endpoint: 'https://hooks.example.test/lookout', fetchImpl: async (url, options) => { calls.push({ url, options }); return { status: 202 }; } });
  const batchId = 'a'.repeat(64);
  const result = await exporter.send([alert('alert-1', '2026-08-18T10:00:00.000Z')], { batchId, firstSequence: 1, lastSequence: 1 });
  assert.deepEqual(result, { batchId, status: 202, accepted: 1 });
  assert.equal(calls[0].options.headers['idempotency-key'], batchId);
  assert.equal(JSON.parse(calls[0].options.body).type, 'lookout.alert.batch');
  assert.throws(() => new AlertWebhookExporter({ endpoint: 'http://hooks.example.test' }), /must use HTTPS/);
});

test('alert webhook durably deduplicates and applies cooldown by rule and systems', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-alert-webhook-'));
  const delivered = [];
  const exporter = { send: async (alerts) => delivered.push(...alerts.map((item) => item.id)) };
  try {
    const service = await fixture(directory, exporter);
    const first = alert('alert-1', '2026-08-18T10:00:00.000Z');
    const cooled = alert('alert-2', '2026-08-18T10:01:00.000Z');
    const differentSystem = alert('alert-3', '2026-08-18T10:01:00.000Z', 'endpoint:other');
    assert.deepEqual(await service.enqueue([first, cooled, differentSystem, first]), { enqueued: 2, duplicates: 1, suppressed: 1, pending: 2 });
    assert.equal((await service.flush()).delivered, 2);

    const restarted = await fixture(directory, exporter);
    assert.deepEqual(await restarted.enqueue([first, cooled, differentSystem]), { enqueued: 0, duplicates: 3, suppressed: 0, pending: 0 });
    const afterCooldown = alert('alert-4', '2026-08-18T10:06:00.000Z');
    assert.equal((await restarted.enqueue([afterCooldown])).enqueued, 1);
    assert.equal((await restarted.flush()).delivered, 1);
    assert.deepEqual(delivered.sort(), ['alert-1', 'alert-3', 'alert-4']);
  } finally { await fs.rm(directory, { recursive: true, force: true }); }
});

test('alert webhook retains retryable failures in its durable outbox', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-alert-webhook-retry-'));
  let now = Date.parse('2026-08-18T10:00:00.000Z');
  let attempts = 0;
  try {
    const service = await fixture(directory, { send: async () => { attempts += 1; if (attempts === 1) throw new ExportDeliveryError('offline', { code: 'network_error' }); } }, () => now);
    await service.enqueue([alert('alert-retry', '2026-08-18T10:00:00.000Z')]);
    await assert.rejects(() => service.flush(), (error) => error.webhookRetry.attempts === 1);
    assert.equal((await service.flush()).deferred, true);
    now += 1000;
    assert.equal((await service.flush()).delivered, 1);
  } finally { await fs.rm(directory, { recursive: true, force: true }); }
});

test('runtime queues new alerts without making detection depend on webhook delivery', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-alert-webhook-runtime-'));
  const queued = [];
  const alertWebhook = {
    initialize: async () => {},
    enqueue: async (alerts) => { queued.push(...alerts); return { enqueued: alerts.length, duplicates: 0, suppressed: 0, pending: alerts.length }; },
    flush: async () => { throw new Error('offline'); },
    stats: () => ({ pending: queued.length, retry: null, blocked: null, suppressed: 0 })
  };
  try {
    const runtime = await new LookoutRuntime({ dataDirectory: directory, alertWebhook }).initialize();
    const adapter = declarationAdapter({ entities: [{ key: 'sensor:auth', type: 'telemetry', name: 'Auth sensor' }], capabilities: [{ entityKey: 'sensor:auth', capability: 'authentication', status: 'available' }] });
    await runtime.applySurveyFacts(await new AdapterRegistry().register(adapter).survey('declaration'));
    const events = Array.from({ length: 12 }, (_, index) => {
      const time = `2026-08-18T10:00:${String(index).padStart(2, '0')}.000Z`;
      return createEvent({ time, ingestedAt: time, category: 'identity', class: 'authentication', activity: 'logon', outcome: 'failure', source: { adapter: 'fixture', instance: 'site', recordId: `auth-${index}` }, entityKeys: ['endpoint:client'], sourceEndpoint: { id: 'endpoint:client' }, attributes: {} });
    });
    const result = await runtime.ingest(events);
    assert.equal(result.alerts.length, 1);
    assert.equal(queued.some((alert) => alert.id === result.alerts[0].id), true);
    await assert.rejects(() => runtime.flushAlertWebhook(), /offline/);
    assert.equal(runtime.cases.snapshot().alerts.length, 1);
  } finally { await fs.rm(directory, { recursive: true, force: true }); }
});

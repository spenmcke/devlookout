'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { LookoutRuntime } = require('../src/runtime');
const { DurableExportOutbox } = require('../src/export/outbox');
const { AlertWebhookExporter, AlertWebhookService } = require('../src/alerts/webhook');

test('external service access becomes an event, Alert, and durable webhook delivery', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-alert-webhook-'));
  const deliveries = [];
  try {
    const outbox = new DurableExportOutbox(directory, { filename: 'alert-webhook.jsonl' });
    const exporter = new AlertWebhookExporter({
      endpoint: 'https://alerts.example.test/lookout',
      fetchImpl: async (url, options) => { deliveries.push({ url, options }); return { status: 202 }; }
    });
    const alertWebhook = new AlertWebhookService({ outbox, exporter });
    const runtime = await new LookoutRuntime({ dataDirectory: directory, alertWebhook }).initialize();
    await runtime.recordServiceAccess({ principal: 'external-principal', sourceAddress: '100.64.0.10', method: 'GET', path: '/private-service', accessDecision: 'unapproved_device' });

    const event = (await runtime.eventStore.query()).find((item) => item.source.adapter === 'lookout-service-auth');
    assert.ok(event);
    assert.equal(event.activity, 'service_access');
    assert.equal(event.actor.id, 'external-principal');
    assert.equal(event.attributes.accessDecision, 'unapproved_device');
    const alert = runtime.cases.snapshot().alerts.find((item) => item.title === 'New or unapproved device or service accessed');
    assert.ok(alert);
    assert.equal(outbox.stats().pending, 1);

    const delivery = await runtime.flushAlertWebhook();
    assert.equal(delivery.delivered, 1);
    assert.equal(delivery.pending, 0);
    assert.equal(deliveries.length, 1);
    const payload = JSON.parse(deliveries[0].options.body);
    assert.deepEqual(payload.alerts.map((item) => item.id), [alert.id]);
    assert.equal(payload.events, undefined);
    assert.equal(deliveries[0].options.headers['idempotency-key'], payload.batchId);

    assert.equal((await runtime.flushAlertWebhook()).delivered, 0);
    assert.equal(deliveries.length, 1);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('alert webhook requires HTTPS and retries with a stable idempotency key', async () => {
  assert.throws(() => new AlertWebhookExporter({ endpoint: 'http://alerts.example.test' }), /must use HTTPS/);
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-alert-webhook-retry-'));
  let now = Date.parse('2026-08-18T18:00:00.000Z');
  const attempts = [];
  try {
    const outbox = new DurableExportOutbox(directory, { filename: 'alert-webhook.jsonl' });
    const service = new AlertWebhookService({
      outbox, clock: () => now,
      exporter: { send: async (alerts, metadata) => { attempts.push({ alerts, metadata }); if (attempts.length === 1) throw Object.assign(new Error('offline'), { code: 'network_error', retryable: true }); } }
    });
    const alert = { schemaVersion: 1, id: 'alert-1', findingId: 'finding-1', title: 'Test alert', severity: 'high', severityScore: 8, time: '2026-08-18T18:00:00.000Z', status: 'open', entities: [], evidence: ['event-1'], confidence: 1, analyticKind: 'event' };
    assert.equal((await service.enqueue([alert, alert])).enqueued, 1);
    await assert.rejects(() => service.flush(), (error) => error.webhookRetry.attempts === 1);
    now += 1000;
    assert.equal((await service.flush()).delivered, 1);
    assert.equal(attempts[0].metadata.batchId, attempts[1].metadata.batchId);
  } finally { await fs.rm(directory, { recursive: true, force: true }); }
});

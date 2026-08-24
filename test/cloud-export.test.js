'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { createEvent } = require('../src/events/schema');
const { DataProtector } = require('../src/security/data-protector');
const { DurableExportOutbox } = require('../src/export/outbox');
const { HttpsBatchExporter, ExportDeliveryError } = require('../src/export/https-exporter');
const { CloudExportService } = require('../src/export/service');

function event(recordId, category = 'identity') {
  return createEvent({
    time: '2026-08-17T20:00:00.000Z', ingestedAt: '2026-08-17T20:00:01.000Z', category,
    class: 'authentication', activity: 'logon', outcome: 'failure', source: { adapter: 'fixture', instance: 'site-a', recordId },
    entityKeys: ['identity:1'], actor: { id: 'identity:1', name: 'private-name', type: 'user' },
    attributes: { method: 'ssh', sourceMessage: 'local only' }, rawReference: `local:${recordId}`
  });
}

async function temporaryDirectory() { return fs.mkdtemp(path.join(os.tmpdir(), 'lookout-cloud-export-')); }

test('durable outbox deduplicates, checkpoints, restarts, and compacts encrypted records', async () => {
  const directory = await temporaryDirectory();
  const protector = new DataProtector(Buffer.alloc(32, 7));
  try {
    const outbox = new DurableExportOutbox(directory, { protector, requireEncryption: true, maxPending: 3 });
    assert.deepEqual(await outbox.enqueue([{ id: 'one', activity: 'a' }, { id: 'two', activity: 'b' }, { id: 'one', activity: 'a' }]), { enqueued: 2, duplicates: 1, pending: 2 });
    const raw = await fs.readFile(outbox.file, 'utf8');
    assert.equal(raw.includes('"activity":"a"'), false);
    assert.deepEqual((await outbox.pending({ limit: 1 })).map((record) => record.sequence), [1]);
    await outbox.acknowledge({ throughSequence: 1, batchId: 'batch-one' });
    await outbox.recordFailure({ throughSequence: 2, attempts: 1, nextAttemptAt: '2026-08-17T20:01:00.000Z', errorCode: 'timeout' });

    const restarted = new DurableExportOutbox(directory, { protector, requireEncryption: true, maxPending: 3 });
    await restarted.initialize();
    assert.equal(restarted.stats().pending, 1);
    assert.equal(restarted.stats().retry.errorCode, 'timeout');
    assert.deepEqual(await restarted.compact(), { removed: 1, retained: 1 });

    const compacted = new DurableExportOutbox(directory, { protector, requireEncryption: true, maxPending: 3 });
    await compacted.initialize();
    assert.deepEqual((await compacted.pending()).map((record) => record.sequence), [2]);
    await compacted.enqueue([{ id: 'three' }, { id: 'four' }]);
    await assert.rejects(() => compacted.enqueue([{ id: 'five' }]), /capacity exceeded/);
  } finally { await fs.rm(directory, { recursive: true, force: true }); }
});

test('outbox detects tampering and requires encryption when configured', async () => {
  const directory = await temporaryDirectory();
  try {
    const plain = new DurableExportOutbox(directory);
    await plain.enqueue([{ id: 'one', activity: 'before' }]);
    const line = JSON.parse((await fs.readFile(plain.file, 'utf8')).trim());
    line.event.activity = 'after';
    await fs.writeFile(plain.file, `${JSON.stringify(line)}\n`);
    await assert.rejects(() => new DurableExportOutbox(directory).initialize(), /integrity check failed/);
    await assert.rejects(() => new DurableExportOutbox(directory, { protector: new DataProtector(Buffer.alloc(32, 2)), requireEncryption: true }).initialize(), /Encrypted export record required/);
  } finally { await fs.rm(directory, { recursive: true, force: true }); }
});

test('HTTPS exporter enforces transport, credentials, idempotency, and response handling', async () => {
  assert.throws(() => new HttpsBatchExporter({ endpoint: 'http://logs.example.test' }), /must use HTTPS/);
  assert.throws(() => new HttpsBatchExporter({ endpoint: 'https://user:pass@logs.example.test' }), /must not contain credentials/);
  const calls = [];
  const exporter = new HttpsBatchExporter({
    endpoint: 'https://logs.example.test/v1/events', credentialReference: 'cloud-token',
    credentialProvider: { get: async (reference) => reference === 'cloud-token' ? 'sensitive-value' : null },
    fetchImpl: async (url, options) => { calls.push({ url, options }); return { status: 202 }; }
  });
  const batchId = 'a'.repeat(64);
  assert.deepEqual(await exporter.send([{ id: 'event-1' }], { batchId, firstSequence: 1, lastSequence: 1, generatedAt: '2026-08-17T20:00:00.000Z' }), { batchId, status: 202, accepted: 1 });
  assert.equal(calls[0].url, 'https://logs.example.test/v1/events');
  assert.equal(calls[0].options.redirect, 'error');
  assert.equal(calls[0].options.headers['idempotency-key'], batchId);
  assert.equal(calls[0].options.headers.authorization, 'Bearer sensitive-value');
  assert.equal(JSON.parse(calls[0].options.body).events[0].id, 'event-1');
  await exporter.send([{ id: 'event-1' }], { batchId, firstSequence: 1, lastSequence: 1 });
  await exporter.send([{ id: 'event-1' }], { batchId, firstSequence: 1, lastSequence: 1 });
  assert.equal(calls[1].options.body, calls[2].options.body);
  assert.equal(JSON.parse(calls[1].options.body).generatedAt, undefined);

  const rejected = new HttpsBatchExporter({ endpoint: 'https://logs.example.test', fetchImpl: async () => ({ status: 429 }) });
  await assert.rejects(() => rejected.send([{ id: 'event-1' }], { batchId, firstSequence: 1, lastSequence: 1 }), (error) => error instanceof ExportDeliveryError && error.retryable && error.code === 'http_429');
  const badRequest = new HttpsBatchExporter({ endpoint: 'https://logs.example.test', fetchImpl: async () => ({ status: 400 }) });
  await assert.rejects(() => badRequest.send([{ id: 'event-1' }], { batchId, firstSequence: 1, lastSequence: 1 }), (error) => error instanceof ExportDeliveryError && !error.retryable);
});

test('cloud service filters before persistence, uses stable batch IDs, and durably backs off', async () => {
  const directory = await temporaryDirectory();
  let now = Date.parse('2026-08-17T20:00:00.000Z');
  const attempts = [];
  try {
    const outbox = new DurableExportOutbox(directory);
    const exporter = {
      send: async (events, metadata) => {
        attempts.push({ events, metadata });
        if (attempts.length === 1) throw new ExportDeliveryError('offline', { code: 'network_error' });
      }
    };
    const policy = { enabled: true, categories: ['identity'], attributeAllowlist: ['method'] };
    const service = new CloudExportService({ outbox, exporter, policy, batchSize: 1, baseRetryMs: 1000, maxRetryMs: 8000, clock: () => now });
    assert.deepEqual(await service.enqueue([event('one'), event('ignored', 'network')]), { enqueued: 1, duplicates: 0, pending: 1, filtered: 1 });
    const queued = (await outbox.pending())[0].event;
    assert.deepEqual(queued.attributes, { method: 'ssh' });
    assert.deepEqual(queued.actor, { id: 'identity:1', type: 'user' });
    assert.equal(queued.rawReference, undefined);
    await assert.rejects(() => service.flush(), (error) => error.exportRetry.attempts === 1);
    assert.deepEqual(await service.flush(), { delivered: 0, deferred: true, nextAttemptAt: '2026-08-17T20:00:01.000Z', pending: 1 });

    const restartedOutbox = new DurableExportOutbox(directory);
    const restarted = new CloudExportService({ outbox: restartedOutbox, exporter, policy, batchSize: 1, clock: () => now });
    assert.equal((await restarted.flush()).deferred, true);
    now += 1000;
    const delivered = await restarted.flush();
    assert.equal(delivered.delivered, 1);
    assert.equal(delivered.pending, 0);
    assert.equal(attempts[0].metadata.batchId, attempts[1].metadata.batchId);
  } finally { await fs.rm(directory, { recursive: true, force: true }); }
});

test('cloud service drains bounded batches and leaves local work queued after failures', async () => {
  const directory = await temporaryDirectory();
  try {
    const outbox = new DurableExportOutbox(directory);
    const delivered = [];
    const service = new CloudExportService({
      outbox, policy: { enabled: true, attributeAllowlist: [] }, batchSize: 2,
      exporter: { send: async (events) => delivered.push(...events.map((value) => value.id)) }
    });
    await service.enqueue([event('one'), event('two'), event('three')]);
    assert.deepEqual(await service.drain({ maxBatches: 2 }), { delivered: 3, pending: 0, deferred: false });
    assert.equal(new Set(delivered).size, 3);

    await service.enqueue([event('four')]);
    const concurrent = await Promise.all([service.flush(), service.flush()]);
    assert.equal(concurrent.reduce((sum, value) => sum + value.delivered, 0), 1);
  } finally { await fs.rm(directory, { recursive: true, force: true }); }
});

test('non-retryable delivery errors durably block without dropping data until explicitly resumed', async () => {
  const directory = await temporaryDirectory();
  let reject = true;
  try {
    const policy = { enabled: true, attributeAllowlist: [] };
    const outbox = new DurableExportOutbox(directory);
    const exporter = { send: async () => { if (reject) throw new ExportDeliveryError('bad request', { code: 'http_400', retryable: false }); } };
    const service = new CloudExportService({ outbox, exporter, policy });
    await service.enqueue([event('blocked')]);
    await assert.rejects(() => service.flush(), (error) => error.exportRetry.blocked === true && error.exportRetry.nextAttemptAt === null);

    const restarted = new CloudExportService({ outbox: new DurableExportOutbox(directory), exporter, policy });
    assert.deepEqual(await restarted.flush(), { delivered: 0, blocked: true, errorCode: 'http_400', pending: 1 });
    assert.equal(await restarted.resume(), true);
    reject = false;
    assert.equal((await restarted.flush()).delivered, 1);
    assert.equal(await restarted.resume(), false);
  } finally { await fs.rm(directory, { recursive: true, force: true }); }
});

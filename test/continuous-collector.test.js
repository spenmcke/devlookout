'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { ContinuousCollector } = require('../src/collector/continuous');
const { generateCollectorKeyPair, verifyEnvelope } = require('../src/collector/envelope');
const { createEvent } = require('../src/events/schema');
const { systemCollector } = require('../src/collector/system');
const { SnapshotStore } = require('../src/storage/snapshot-store');
const { signPayload } = require('../src/collector/envelope');

function event(number, time = '2026-08-18T12:00:00.000Z') {
  return createEvent({
    time, ingestedAt: time, category: 'system', class: 'process_activity', activity: 'start', outcome: 'success',
    source: { adapter: 'test-stream', instance: 'host-1', recordId: String(number) },
    entityKeys: ['endpoint:host-1'], attributes: { number }
  });
}

function operationalSample(collectorId, number) {
  return {
    schemaVersion: 1, collectorId, entityKey: 'endpoint:host-1', observedAt: new Date(Date.parse('2026-08-18T12:00:00.000Z') + number * 1000).toISOString(),
    host: { uptimeSeconds: number, cpu: { logicalProcessors: 1, usedPercent: 1, loadAverage: [0, 0, 0] }, memory: { totalBytes: 100, usedBytes: 10, availableBytes: 90, usedPercent: 10 }, filesystems: { status: 'available', truncated: false, volumes: [] } },
    lookout: { process: { uptimeSeconds: number, cpu: { usedPercent: 1, cumulativeMilliseconds: number }, memory: { residentBytes: 10, heapUsedBytes: 5, externalBytes: 1 } }, dataStorage: { status: 'available', bytes: 1, entries: 1, truncated: false }, delivery: { status: 'available', queues: [] } }
  };
}

async function temporaryDirectory(prefix, operation) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), prefix));
  try { return await operation(directory); }
  finally { await fs.rm(directory, { recursive: true, force: true }); }
}

test('continuous collector enforces a two-second batching ceiling', async () => temporaryDirectory('lookout-continuous-', async (directory) => {
  const keys = generateCollectorKeyPair();
  let now = new Date('2026-08-18T12:00:00.000Z');
  const sent = [];
  const collector = await new ContinuousCollector({
    dataDirectory: directory, ...keys, sources: [{ id: 'fake' }], sender: async (envelope) => sent.push(envelope),
    batchMaximumEvents: 10, queueCapacity: 10, batchMaximumWaitMs: 2000, clock: () => new Date(now)
  }).initialize();
  await collector.ingest('fake', event(1), { offset: 1 });
  assert.equal((await collector.flush()).status, 'waiting');
  now = new Date(now.getTime() + 1999);
  assert.equal((await collector.flush()).status, 'waiting');
  now = new Date(now.getTime() + 1);
  const result = await collector.flush();
  assert.equal(result.status, 'submitted');
  assert.equal(result.count, 1);
  assert.equal(verifyEnvelope(sent[0], keys.publicKeyPem).events[0].attributes.number, 1);
}));

test('continuous collector splits accumulated operational health without jamming delivery', async () => temporaryDirectory('lookout-continuous-operational-', async (directory) => {
  const keys = generateCollectorKeyPair();
  const sent = [];
  const collector = await new ContinuousCollector({ dataDirectory: directory, ...keys, sources: [{ id: 'fake' }], batchMaximumEvents: 100, queueCapacity: 100, sender: async (envelope) => sent.push(envelope) }).initialize();
  await collector.ingestBatch('fake', { operationalHealth: Array.from({ length: 32 }, (_, index) => operationalSample(keys.collectorId, index + 1)) });
  await collector.ingestBatch('fake', { operationalHealth: [operationalSample(keys.collectorId, 33)] });
  assert.equal((await collector.flush({ force: true })).count, 32);
  assert.equal((await collector.flush({ force: true })).count, 1);
  assert.deepEqual(sent.map((envelope) => verifyEnvelope(envelope, keys.publicKeyPem).operationalHealth.length), [32, 1]);
}));

test('continuous collector retries an identical signed batch after failure and restart without event loss', async () => temporaryDirectory('lookout-continuous-restart-', async (directory) => {
  const keys = generateCollectorKeyPair();
  const clock = () => new Date('2026-08-18T12:00:00.000Z');
  const attempted = [];
  const source = { id: 'audit' };
  const first = await new ContinuousCollector({
    dataDirectory: directory, ...keys, sources: [source], batchMaximumEvents: 2, queueCapacity: 3, clock, random: () => 0.5,
    sender: async (envelope) => { attempted.push(envelope); throw new Error('network offline'); }
  }).initialize();
  await first.ingest('audit', event(1), { offset: 1 });
  await first.ingest('audit', event(2), { offset: 2 });
  await first.ingest('audit', event(3), { offset: 3 });
  await assert.rejects(() => first.flush({ force: true }), /network offline/);
  assert.equal(first.status().queue.depth, 3);
  assert.deepEqual(first.status().cursors.audit, { offset: 3 });

  const delivered = [];
  const restarted = await new ContinuousCollector({
    dataDirectory: directory, ...keys, sources: [source], batchMaximumEvents: 2, queueCapacity: 3, clock,
    sender: async (envelope) => { attempted.push(envelope); delivered.push(...verifyEnvelope(envelope, keys.publicKeyPem).events); return { accepted: true }; }
  }).initialize();
  assert.equal((await restarted.flush({ force: true })).count, 2);
  assert.equal(attempted[0].signature, attempted[1].signature);
  assert.equal((await restarted.flush({ force: true })).count, 1);
  assert.deepEqual(delivered.map((item) => item.attributes.number), [1, 2, 3]);
  assert.equal(restarted.status().queue.depth, 0);
  assert.deepEqual(restarted.status().cursors.audit, { offset: 3 });
}));

test('continuous collector applies backpressure at capacity instead of dropping', async () => temporaryDirectory('lookout-continuous-pressure-', async (directory) => {
  const keys = generateCollectorKeyPair();
  const delivered = [];
  const collector = await new ContinuousCollector({
    dataDirectory: directory, ...keys, sources: [{ id: 'fake' }], batchMaximumEvents: 1, queueCapacity: 1,
    sender: async (envelope) => delivered.push(...verifyEnvelope(envelope, keys.publicKeyPem).events)
  }).initialize();
  await collector.ingest('fake', event(1), 1);
  let secondCommitted = false;
  const second = collector.ingest('fake', event(2), 2).then(() => { secondCommitted = true; });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(secondCommitted, false);
  await collector.flush({ force: true });
  await second;
  await collector.flush({ force: true });
  assert.deepEqual(delivered.map((item) => item.attributes.number), [1, 2]);
}));

test('continuous collector merges async and periodic observations under one sequence', async () => temporaryDirectory('lookout-continuous-source-', async (directory) => {
  const keys = generateCollectorKeyPair();
  const periodicModules = [{ collect: () => ({ events: [event(99)], facts: [] }) }];
  const source = {
    id: 'fake',
    async *events({ cursor }) {
      assert.equal(cursor, undefined);
      yield { event: event(1), cursor: { offset: 1 } };
      yield { event: event(2), cursor: { offset: 2 } };
    }
  };
  const delivered = [];
  const collector = await new ContinuousCollector({
    dataDirectory: directory, ...keys, sources: [source], periodicModules, periodicIntervalMs: 1000, batchMaximumEvents: 4, queueCapacity: 4,
    sender: async (envelope) => delivered.push(...verifyEnvelope(envelope, keys.publicKeyPem).events)
  }).initialize();
  await collector.start();
  for (let attempt = 0; attempt < 200 && collector.status().cursors.fake?.offset !== 2; attempt += 1) await new Promise((resolve) => setTimeout(resolve, 5));
  assert.deepEqual(collector.status().cursors.fake, { offset: 2 });
  await collector.stop();
  assert.deepEqual(delivered.map((item) => item.attributes.number).sort((a, b) => a - b), [1, 2, 99]);
  assert.equal(collector.status().delivery.sequence, 1);
}));

test('continuous collector restarts transient source failures with its committed cursor', async () => temporaryDirectory('lookout-continuous-source-retry-', async (directory) => {
  const keys = generateCollectorKeyPair();
  let attempts = 0;
  const cursors = [];
  const source = {
    id: 'retrying',
    async *events({ cursor, signal }) {
      attempts += 1;
      cursors.push(cursor);
      if (attempts === 1) throw new Error('temporary read failure');
      if (attempts === 2) { yield { event: event(1), cursor: 1 }; return; }
      await new Promise((resolve) => signal.addEventListener('abort', resolve, { once: true }));
    }
  };
  const delivered = [];
  const collector = await new ContinuousCollector({
    dataDirectory: directory, ...keys, sources: [source], batchMaximumEvents: 1, queueCapacity: 2,
    sourceRetryBaseMs: 1, sourceRetryMaximumMs: 1, random: () => 0.5,
    sender: async (envelope) => delivered.push(...verifyEnvelope(envelope, keys.publicKeyPem).events)
  }).initialize();
  await collector.start();
  for (let attempt = 0; attempt < 200 && collector.status().cursors.retrying !== 1; attempt += 1) await new Promise((resolve) => setTimeout(resolve, 5));
  assert.equal(collector.status().cursors.retrying, 1);
  assert.ok(attempts >= 2);
  assert.equal(cursors[0], undefined);
  assert.equal(cursors[1], undefined);
  await collector.stop();
  assert.equal(delivered.length, 1);
  assert.ok(collector.status().sources.retrying.restartCount >= 1);
}));

test('periodic collection persists unique observation sequence and uses the shared envelope sequence', async () => temporaryDirectory('lookout-continuous-periodic-', async (directory) => {
  const keys = generateCollectorKeyPair();
  const envelopes = [];
  const collector = await new ContinuousCollector({
    dataDirectory: directory, ...keys, periodicModules: [systemCollector({ collectorId: keys.collectorId })],
    batchMaximumEvents: 20, queueCapacity: 20, sender: async (envelope) => envelopes.push(envelope)
  }).initialize();
  assert.equal((await collector.collectPeriodicOnce()).sequence, 1);
  assert.equal((await collector.collectPeriodicOnce()).sequence, 2);
  await collector.flush({ force: true });
  const payload = verifyEnvelope(envelopes[0], keys.publicKeyPem);
  assert.equal(payload.sequence, 1);
  assert.deepEqual(payload.events.map((item) => item.source.recordId), ['heartbeat:1', 'heartbeat:2']);
  assert.equal(new Set(payload.facts.map((item) => item.source.recordId)).size, 6);
}));

test('periodic module baselines persist atomically across collector restart', async () => temporaryDirectory('lookout-continuous-module-state-', async (directory) => {
  const keys = generateCollectorKeyPair();
  const observed = [];
  const module = {
    manifest: { id: 'stateful-survey' },
    collect({ state }) { observed.push(state); return { facts: [], events: [], state: { schemaVersion: 1, count: (state?.count || 0) + 1 } }; }
  };
  const first = await new ContinuousCollector({ dataDirectory: directory, ...keys, periodicModules: [module], sender: async () => ({ ok: true }) }).initialize();
  await first.collectPeriodicOnce();
  const second = await new ContinuousCollector({ dataDirectory: directory, ...keys, periodicModules: [module], sender: async () => ({ ok: true }) }).initialize();
  await second.collectPeriodicOnce();
  assert.deepEqual(observed, [null, { schemaVersion: 1, count: 1 }]);
}));

test('continuous collector shrinks batches to the signed payload limit and rejects an invalid oversized observation', async () => temporaryDirectory('lookout-continuous-size-', async (directory) => {
  const keys = generateCollectorKeyPair();
  const envelopes = [];
  const collector = await new ContinuousCollector({
    dataDirectory: directory, ...keys, sources: [{ id: 'large' }], batchMaximumEvents: 5, queueCapacity: 5,
    sender: async (envelope) => envelopes.push(envelope)
  }).initialize();
  for (let number = 1; number <= 5; number += 1) {
    const large = event(number);
    large.attributes.chunks = Array.from({ length: 15 }, () => 'x'.repeat(60000));
    await collector.ingest('large', large, number);
  }
  const first = await collector.flush({ force: true });
  assert.ok(first.count < 5);
  await collector.flush({ force: true });
  assert.equal(envelopes.reduce((total, envelope) => total + verifyEnvelope(envelope, keys.publicKeyPem).events.length, 0), 5);
  const invalid = event(6);
  invalid.attributes.value = 'x'.repeat(70000);
  await assert.rejects(() => collector.ingest('large', invalid, 6), /Invalid normalized event/);
  assert.equal(collector.status().queue.depth, 0);
}));

test('continuous collector migrates the accepted legacy sequence floor before new delivery', async () => temporaryDirectory('lookout-continuous-legacy-floor-', async (directory) => {
  const keys = generateCollectorKeyPair();
  await new SnapshotStore(directory, 'collector-state.json').save({
    schemaVersion: 1, sequence: 7, pending: null, failureCount: 0,
    lastSuccessAt: '2026-08-18T12:00:00.000Z', nextRunAt: '2026-08-18T12:05:00.000Z'
  });
  const sent = [];
  const collector = await new ContinuousCollector({
    dataDirectory: directory, ...keys, sources: [{ id: 'fake' }], batchMaximumEvents: 1, queueCapacity: 1,
    sender: async (envelope) => sent.push(envelope)
  }).initialize();
  await collector.ingest('fake', event(8), 8);
  await collector.flush({ force: true });
  assert.equal(verifyEnvelope(sent[0], keys.publicKeyPem).sequence, 8);
  assert.equal(collector.status().delivery.sequence, 8);
}));

test('continuous collector migrates and retries an exact pending legacy envelope', async () => temporaryDirectory('lookout-continuous-legacy-pending-', async (directory) => {
  const keys = generateCollectorKeyPair();
  const pending = signPayload({
    schemaVersion: 1, collectorId: keys.collectorId, sequence: 4,
    collectedAt: '2026-08-18T12:00:00.000Z', facts: [], events: [event(4)]
  }, keys.privateKeyPem);
  await new SnapshotStore(directory, 'collector-state.json').save({
    schemaVersion: 1, sequence: 4, pending, failureCount: 1,
    lastSuccessAt: null, nextRunAt: '2026-08-18T12:01:00.000Z'
  });
  const sent = [];
  const collector = await new ContinuousCollector({
    dataDirectory: directory, ...keys, sender: async (envelope) => sent.push(envelope)
  }).initialize();
  assert.equal(collector.status().queue.pending, true);
  assert.equal(collector.status().queue.depth, 1);
  await collector.flush({ force: true });
  assert.equal(sent[0].signature, pending.signature);
  assert.equal(verifyEnvelope(sent[0], keys.publicKeyPem).sequence, 4);
  assert.equal(collector.status().queue.depth, 0);
}));

test('started collector keeps the daemon alive while idle until graceful stop', async () => temporaryDirectory('lookout-continuous-idle-', async (directory) => {
  const keys = generateCollectorKeyPair();
  const collector = await new ContinuousCollector({ dataDirectory: directory, ...keys, sender: async () => {} }).initialize();
  await collector.start();
  assert.equal(collector.keepaliveTimer.hasRef(), true);
  assert.equal(collector.status().running, true);
  await collector.stop({ flush: false });
  assert.equal(collector.keepaliveTimer, null);
  assert.equal(collector.status().running, false);
}));

test('continuous state is bound to its collector identity even without a pending envelope', async () => temporaryDirectory('lookout-continuous-identity-', async (directory) => {
  const original = generateCollectorKeyPair();
  const collector = await new ContinuousCollector({
    dataDirectory: directory, ...original, sources: [{ id: 'fake' }], sender: async () => {}
  }).initialize();
  await collector.ingest('fake', event(1), 1);
  const replacement = generateCollectorKeyPair();
  await assert.rejects(() => new ContinuousCollector({
    dataDirectory: directory, ...replacement, sources: [{ id: 'fake' }], sender: async () => {}
  }).initialize(), /different collector identity/);
}));

test('pre-binding continuous state receives a durable one-time identity migration', async () => temporaryDirectory('lookout-continuous-identity-migration-', async (directory) => {
  const original = generateCollectorKeyPair();
  await new SnapshotStore(directory, 'continuous-collector-state.json').save({
    schemaVersion: 1, sequence: 3, recordSequence: 0, periodicSequence: 0, entries: [], cursors: {}, pending: null,
    failureCount: 0, retryAt: null, lastSuccessAt: null, lastFailureAt: null, lastFailure: null
  });
  await new ContinuousCollector({ dataDirectory: directory, ...original, sender: async () => {} }).initialize();
  const migrated = await new SnapshotStore(directory, 'continuous-collector-state.json').load();
  assert.equal(migrated.collectorId, original.collectorId);
  const replacement = generateCollectorKeyPair();
  await assert.rejects(() => new ContinuousCollector({ dataDirectory: directory, ...replacement, sender: async () => {} }).initialize(), /different collector identity/);
}));

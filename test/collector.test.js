'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { generateCollectorKeyPair, signPayload, verifyEnvelope } = require('../src/collector/envelope');
const { CollectorRegistry } = require('../src/collector/registry');
const { systemCollector } = require('../src/collector/system');
const { CollectorRunner, submitEnvelope } = require('../src/collector/runner');
const { CollectorScheduler } = require('../src/collector/scheduler');

test('collector envelopes are signed and tampering is rejected', () => {
  const keys = generateCollectorKeyPair();
  const payload = { schemaVersion: 1, collectorId: keys.collectorId, sequence: 1, collectedAt: '2026-08-17T20:00:00.000Z', facts: [], events: [] };
  const envelope = signPayload(payload, keys.privateKeyPem);
  assert.deepEqual(verifyEnvelope(envelope, keys.publicKeyPem), payload);
  envelope.payload.sequence = 2;
  assert.throws(() => verifyEnvelope(envelope, keys.publicKeyPem), /verification failed/);
});

test('collector registry rejects replay and commits sequence only after ingestion succeeds', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-collectors-'));
  const keys = generateCollectorKeyPair();
  try {
    const registry = await new CollectorRegistry({ dataDirectory: directory, publicKeys: { [keys.collectorId]: keys.publicKeyPem } }).initialize();
    const payload = { schemaVersion: 1, collectorId: keys.collectorId, sequence: 1, collectedAt: '2026-08-17T20:00:00.000Z', facts: [], events: [] };
    const envelope = signPayload(payload, keys.privateKeyPem);
    await assert.rejects(() => registry.accept(envelope, async () => { throw new Error('ingestion failed'); }, new Date('2026-08-17T20:01:00.000Z')), /ingestion failed/);
    assert.equal(registry.snapshot().sequences[keys.collectorId], undefined);
    assert.equal(await registry.accept(envelope, async () => 'accepted', new Date('2026-08-17T20:01:00.000Z')), 'accepted');
    assert.equal(await registry.accept(envelope, async () => 'must-not-run', new Date('2026-08-17T20:01:00.000Z')), 'accepted');
    const altered = signPayload({ ...payload, facts: [], events: [], collectedAt: '2026-08-17T20:00:01.000Z' }, keys.privateKeyPem);
    await assert.rejects(() => registry.accept(altered, async () => 'duplicate', new Date('2026-08-17T20:01:00.000Z')), /different content/);
  } finally { await fs.rm(directory, { recursive: true, force: true }); }
});

test('portable system collector emits inventory, health capabilities, and heartbeat', () => {
  const keys = generateCollectorKeyPair();
  const runner = new CollectorRunner({ collectorId: keys.collectorId, privateKeyPem: keys.privateKeyPem, modules: [systemCollector({ collectorId: keys.collectorId })], clock: () => new Date('2026-08-17T20:00:00.000Z') });
  const envelope = runner.collectOnce();
  const payload = verifyEnvelope(envelope, keys.publicKeyPem);
  assert.equal(payload.sequence, 1);
  assert.ok(payload.facts.some((fact) => fact.kind === 'entity' && fact.data.entityType === 'endpoint'));
  const heartbeat = payload.events.find((event) => event.class === 'sensor_activity' && event.activity === 'heartbeat');
  assert.ok(heartbeat);
  assert.equal(heartbeat.attributes.collectorVersion, require('../package.json').version);
});

test('system heartbeat survives unavailable network-interface enumeration', () => {
  const original = os.networkInterfaces;
  os.networkInterfaces = () => { throw new Error('netlink unavailable'); };
  try {
    const output = systemCollector({ collectorId: 'collector_fixture' }).collect({ collectedAt: '2026-08-17T20:00:00.000Z', sequence: 1 });
    assert.equal(output.facts.find((fact) => fact.data.capability === 'inventory').data.status, 'degraded');
    assert.equal(output.events[0].activity, 'heartbeat');
  } finally { os.networkInterfaces = original; }
});

test('collector transport refuses cleartext non-loopback destinations', async () => {
  await assert.rejects(() => submitEnvelope('http://192.0.2.1/submit', {}, { fetchImpl: async () => { throw new Error('must not run'); } }), /require HTTPS/);
});

test('collector scheduler persists pending envelope and retries without sequence reuse', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-scheduler-'));
  const keys = generateCollectorKeyPair();
  const sent = [];
  let fail = true;
  const clock = () => new Date('2026-08-17T20:00:00.000Z');
  try {
    const makeScheduler = () => new CollectorScheduler({ dataDirectory: directory, collectorId: keys.collectorId, privateKeyPem: keys.privateKeyPem, modules: [systemCollector({ collectorId: keys.collectorId })], clock, sender: async (envelope) => { sent.push(envelope); if (fail) throw new Error('offline'); return { ok: true }; } });
    const first = await makeScheduler().initialize();
    await assert.rejects(() => first.runCycle(), /offline/);
    assert.equal(first.status().pending, true);
    fail = false;
    const restarted = await makeScheduler().initialize();
    const result = await restarted.runCycle();
    assert.equal(result.sequence, 1);
    assert.equal(sent[0].signature, sent[1].signature);
    assert.equal(restarted.status().pending, false);
  } finally { await fs.rm(directory, { recursive: true, force: true }); }
});

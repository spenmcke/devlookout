'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { EventStore } = require('../src/storage/event-store');
const { BackupManager } = require('../src/storage/backup');
const { DataProtector, protectorFromEnvironment } = require('../src/security/data-protector');
const { FileSecretProvider } = require('../src/security/secrets');
const { generateCollectorKeyPair, signPayload, validatePayload, verifyEnvelope, MAXIMUM_EVENTS } = require('../src/collector/envelope');
const { CollectorRegistry } = require('../src/collector/registry');
const { CollectorScheduler } = require('../src/collector/scheduler');
const { RobustNumericBaseline, SetBaseline } = require('../src/detection/baselines');
const { BehavioralEngine } = require('../src/detection/behavioral-engine');
const { validateRule } = require('../src/detection/engine');
const { TailscaleClient } = require('../src/adapters/tailscale-client');
const { createEvent } = require('../src/events/schema');

test('protected storage and secret readers reject symbolic links', { skip: process.platform === 'win32' }, async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-links-'));
  const outside = path.join(directory, 'outside');
  const linkedSecret = path.join(directory, 'secret-link');
  try {
    await fs.writeFile(outside, crypto.randomBytes(32).toString('base64'), { mode: 0o600 });
    await fs.symlink(outside, linkedSecret);
    await assert.rejects(() => new FileSecretProvider({ key: linkedSecret }).get('key'), /symbolic link/);
    assert.throws(() => protectorFromEnvironment({ LOOKOUT_MASTER_KEY_FILE: linkedSecret }), /symbolic link/);
    await fs.symlink(outside, path.join(directory, 'events.jsonl'));
    await assert.rejects(() => new EventStore(directory).initialize(), /symbolic link/);
  } finally { await fs.rm(directory, { recursive: true, force: true }); }
});

test('storage rejects broadly accessible directories and backups never overwrite', { skip: process.platform === 'win32' }, async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-permissions-'));
  const data = path.join(root, 'data');
  const backup = path.join(root, 'state.lkb');
  try {
    await fs.mkdir(data, { mode: 0o755 });
    await assert.rejects(() => new EventStore(data).initialize(), /permissions are too broad/);
    await fs.chmod(data, 0o700);
    await fs.writeFile(path.join(data, 'events.jsonl'), '', { mode: 0o600 });
    const manager = new BackupManager({ dataDirectory: data, protector: new DataProtector(crypto.randomBytes(32)) });
    await manager.create(backup);
    await assert.rejects(() => manager.create(backup), /already exists/);
  } finally { await fs.rm(root, { recursive: true, force: true }); }
});

test('collector validation bounds batches and requires canonical Ed25519 signatures', () => {
  const keys = generateCollectorKeyPair();
  const payload = { schemaVersion: 1, collectorId: keys.collectorId, sequence: 1, collectedAt: '2026-08-17T20:00:00.000Z', facts: [], events: [] };
  const envelope = signPayload(payload, keys.privateKeyPem);
  envelope.signature = envelope.signature.replace(/=+$/, '');
  assert.throws(() => verifyEnvelope(envelope, keys.publicKeyPem), /base64/);
  assert.throws(() => validatePayload({ ...payload, events: new Array(MAXIMUM_EVENTS + 1).fill(null) }), /count exceeds/);
  assert.throws(() => createEvent({ time: payload.collectedAt, category: 'health', class: 'test', activity: 'test', source: { adapter: 'test', instance: 'test', recordId: 'test' }, attributes: { invalid: [undefined] } }), /Invalid normalized event/);
});

test('collector replay state rolls back when its durable commit fails', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-sequence-'));
  const keys = generateCollectorKeyPair();
  try {
    const registry = await new CollectorRegistry({ dataDirectory: directory, publicKeys: { [keys.collectorId]: keys.publicKeyPem } }).initialize();
    const envelope = signPayload({ schemaVersion: 1, collectorId: keys.collectorId, sequence: 1, collectedAt: '2026-08-17T20:00:00.000Z', facts: [], events: [] }, keys.privateKeyPem);
    const save = registry.store.save.bind(registry.store);
    registry.store.save = async () => { throw new Error('disk unavailable'); };
    await assert.rejects(() => registry.accept(envelope, async () => 'handled', new Date('2026-08-17T20:01:00.000Z')), /disk unavailable/);
    assert.equal(registry.snapshot().sequences[keys.collectorId], undefined);
    registry.store.save = save;
    assert.equal(await registry.accept(envelope, async () => 'retried', new Date('2026-08-17T20:01:00.000Z')), 'retried');
  } finally { await fs.rm(directory, { recursive: true, force: true }); }
});

test('collector scheduler serializes concurrent cycles', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-scheduler-lock-'));
  const keys = generateCollectorKeyPair();
  let submissions = 0;
  try {
    const scheduler = await new CollectorScheduler({
      dataDirectory: directory, collectorId: keys.collectorId, privateKeyPem: keys.privateKeyPem,
      modules: [{ collect: () => ({ facts: [], events: [] }) }], clock: () => new Date('2026-08-17T20:00:00.000Z'),
      sender: async () => { submissions += 1; return { ok: true }; }
    }).initialize();
    const [first, second] = await Promise.all([scheduler.runCycle(), scheduler.runCycle()]);
    assert.equal(first.status, 'submitted');
    assert.equal(second.status, 'not-due');
    assert.equal(submissions, 1);
  } finally { await fs.rm(directory, { recursive: true, force: true }); }
});

test('behavioral models bound cardinality and never learn anomalous numeric samples', () => {
  const numeric = new RobustNumericBaseline({ defaults: [100, 101, 99], minimumSamples: 6, warningDeviations: 4, criticalDeviations: 8, maximumSamples: 12 });
  assert.equal(numeric.score(1000).state, 'critical');
  assert.deepEqual(numeric.snapshot().samples, [100, 101, 99]);
  const relationships = new SetBaseline({ maximumValues: 1, minimumObservations: 2, noveltySeconds: 0 });
  relationships.observe('one', '2026-08-17T20:00:00.000Z');
  relationships.observe('two', '2026-08-17T20:01:00.000Z');
  assert.deepEqual(Object.keys(relationships.snapshot().values), ['one']);
  assert.throws(() => BehavioralEngine.fromSnapshot({ schemaVersion: 1, maximumModels: 1, analytics: [], models: [{ key: 'a', state: numeric.snapshot() }, { key: 'b', state: numeric.snapshot() }] }), /model capacity/);
});

test('rules and outbound API requests reject resource abuse and origin escape', async () => {
  assert.throws(() => validateRule({ id: 'bad', version: '1', title: 'bad', kind: 'threshold', severity: 'high', selector: {}, threshold: 0, windowSeconds: -1, groupBy: [] }), /bounded positive/);
  const client = new TailscaleClient({ tokenProvider: async () => 'token', baseUrl: 'https://api.example.test', fetchImpl: async () => { throw new Error('must not fetch'); } });
  await assert.rejects(() => client.request('https://attacker.example/api/v2/devices'), /absolute API path/);
});

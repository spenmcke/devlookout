'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { canonicalJson, stableId } = require('../src/core/canonical');
const { ValidationError } = require('../src/core/validation');
const { createFact, AdapterRegistry } = require('../src/adapters/contract');
const { SecurityGraph } = require('../src/graph/security-graph');
const { SnapshotStore } = require('../src/storage/snapshot-store');

const source = { adapter: 'fixture', instance: 'site-a', recordId: 'device-1' };
const observedAt = '2026-08-17T20:00:00.000Z';

function entity(overrides = {}) {
  return createFact({ kind: 'entity', observedAt, source, data: { entityKey: 'device:1', entityType: 'endpoint', name: 'Server', attributes: { platform: 'other' }, ...overrides } });
}

test('canonical identifiers do not depend on object key order', () => {
  assert.equal(canonicalJson({ b: 2, a: 1 }), canonicalJson({ a: 1, b: 2 }));
  assert.equal(stableId('test', { b: 2, a: 1 }), stableId('test', { a: 1, b: 2 }));
});

test('facts reject embedded secret values while permitting references', () => {
  assert.throws(() => entity({ attributes: { api_key: 'do-not-store' } }), ValidationError);
  assert.doesNotThrow(() => entity({ attributes: { api_key_reference: 'secret-store:item-1' } }));
});

test('adapter registry verifies declared capabilities and attribution', async () => {
  const registry = new AdapterRegistry().register({
    manifest: { id: 'fixture', version: '1.0.0', kind: 'endpoint', capabilities: ['authentication'] },
    survey: () => [entity(), createFact({ kind: 'capability', observedAt, source: { ...source, recordId: 'cap-1' }, data: { entityKey: 'device:1', capability: 'authentication', status: 'available' } })]
  });
  const facts = await registry.survey('fixture');
  assert.equal(facts.length, 2);
  assert.deepEqual(registry.manifests().map((item) => item.id), ['fixture']);
});

test('graph merge is deterministic and keeps provenance', () => {
  const lower = entity({ name: 'old-name' });
  lower.confidence = 0.5;
  const higher = createFact({ kind: 'entity', observedAt: '2026-08-17T21:00:00.000Z', confidence: 0.9, source: { ...source, recordId: 'device-1-new' }, data: { entityKey: 'device:1', entityType: 'endpoint', name: 'preferred-name', attributes: { platform: 'unknown' } } });
  const relationship = createFact({ kind: 'relationship', observedAt, source: { ...source, recordId: 'rel-1' }, data: { from: 'device:1', to: 'service:1', relation: 'runs' } });
  const service = createFact({ kind: 'entity', observedAt, source: { ...source, recordId: 'service-1' }, data: { entityKey: 'service:1', entityType: 'service', name: 'Custom service' } });
  const first = new SecurityGraph().apply([lower, service, relationship, higher]).snapshot();
  const second = new SecurityGraph().apply([relationship, higher, service, lower]).snapshot();
  assert.deepEqual(first, second);
  assert.equal(first.entities.find((item) => item.key === 'device:1').name, 'preferred-name');
  assert.equal(first.entities.find((item) => item.key === 'device:1').provenance.length, 2);
});

test('snapshot storage writes private files and detects tampering', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-store-'));
  try {
    const store = new SnapshotStore(directory);
    const snapshot = new SecurityGraph().apply([entity()]).snapshot();
    await store.save(snapshot);
    assert.deepEqual(await store.load(), snapshot);
    const mode = (await fs.stat(store.file)).mode & 0o777;
    assert.equal(mode, 0o600);
    const document = JSON.parse(await fs.readFile(store.file, 'utf8'));
    document.entities[0].name = 'tampered';
    await fs.writeFile(store.file, JSON.stringify(document));
    await assert.rejects(() => store.load(), /integrity check failed/);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

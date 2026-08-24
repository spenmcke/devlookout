'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { createEvent } = require('../src/events/schema');
const { EventStore } = require('../src/storage/event-store');
const { selectExportEvent, ExportManager } = require('../src/events/export');

function event(recordId, time, overrides = {}) {
  return createEvent({
    time, ingestedAt: '2026-08-18T00:00:00.000Z', category: 'identity', class: 'authentication', activity: 'logon', outcome: 'failure',
    source: { adapter: 'fixture', instance: 'site-a', recordId }, entityKeys: ['endpoint:1', 'identity:1'],
    actor: { id: 'identity:1', name: 'admin', type: 'user' }, attributes: { method: 'ssh', sourceMessage: 'redacted locally' }, rawReference: `local:${recordId}`,
    ...overrides
  });
}

test('normalized events reject secret-bearing fields', () => {
  assert.throws(
    () => event('secret', '2026-08-17T20:00:00.000Z', { attributes: { password: 'bad' } }),
    (error) => error.name === 'ValidationError' && error.issues.some((issue) => issue.includes('secret material'))
  );
});

test('event store deduplicates, queries, compacts, and detects tampering', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-events-'));
  try {
    const store = new EventStore(directory);
    const older = event('one', '2026-08-16T20:00:00.000Z');
    const newer = event('two', '2026-08-17T20:00:00.000Z', { outcome: 'success' });
    assert.deepEqual(await store.append([older, newer, older]), [older.id, newer.id]);
    assert.equal((await store.query({ category: 'identity' })).length, 2);
    assert.equal((await store.query({ since: '2026-08-17T00:00:00.000Z' }))[0].id, newer.id);
    assert.equal((await store.query({ source: 'fixture', keyword: 'redacted locally' })).length, 2);
    assert.equal((await store.query({ source: 'another-source' })).length, 0);
    assert.equal((await store.query({ keyword: 'does not exist' })).length, 0);
    assert.deepEqual(await store.compact({ retainAfter: '2026-08-17T00:00:00.000Z' }), { retained: 1, removed: 1 });
    assert.equal((await store.query()).length, 1);
    const lines = (await fs.readFile(store.file, 'utf8')).trim().split('\n');
    const record = JSON.parse(lines[0]);
    const middle = Math.floor(record.data.length / 2);
    record.data = `${record.data.slice(0, middle)}${record.data[middle] === 'A' ? 'B' : 'A'}${record.data.slice(middle + 1)}`;
    await fs.writeFile(store.file, `${JSON.stringify(record)}\n`);
    await assert.rejects(() => new EventStore(directory).query());
  } finally { await fs.rm(directory, { recursive: true, force: true }); }
});

test('event storage is compressed, byte bounded, and preserves quieter VM history', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-events-bounded-'));
  try {
    const store = new EventStore(directory, { maximumBytes: 24 * 1024 });
    const events = [];
    for (let index = 0; index < 160; index += 1) events.push(event(`noisy-${index}`, `2026-08-17T20:${String(Math.floor(index / 60)).padStart(2, '0')}:${String(index % 60).padStart(2, '0')}.000Z`, { source: { adapter: 'fixture', instance: 'noisy-vm', recordId: `noisy-${index}` }, attributes: { message: crypto.randomBytes(256).toString('hex') } }));
    for (let index = 0; index < 8; index += 1) events.push(event(`quiet-${index}`, `2026-08-17T21:00:${String(index).padStart(2, '0')}.000Z`, { source: { adapter: 'fixture', instance: 'quiet-vm', recordId: `quiet-${index}` }, attributes: { message: crypto.randomBytes(256).toString('hex') } }));
    await store.append(events);
    await store.compact({ retainAfter: '2026-08-01T00:00:00.000Z', maximumBytes: 24 * 1024 });
    assert.ok((await fs.stat(store.file)).size <= 24 * 1024);
    const retained = await store.query({ limit: 10000 });
    assert.ok(retained.some((item) => item.source.instance === 'quiet-vm'));
  } finally { await fs.rm(directory, { recursive: true, force: true }); }
});

test('cloud export is disabled by default and strips non-allowlisted detail', async () => {
  const value = event('export', '2026-08-17T20:00:00.000Z');
  assert.equal(selectExportEvent(value), null);
  const selected = selectExportEvent(value, { enabled: true, categories: ['identity'], attributeAllowlist: ['method'] });
  assert.deepEqual(selected.attributes, { method: 'ssh' });
  assert.deepEqual(selected.actor, { id: 'identity:1', type: 'user' });
  assert.equal(selected.rawReference, undefined);
  const batches = [];
  const manager = new ExportManager({ policy: { enabled: true, categories: ['identity'], attributeAllowlist: [] }, exporter: { send: async (batch) => batches.push(batch) } });
  assert.deepEqual(await manager.send([value]), { exported: 1, disabled: false });
  assert.equal(batches.length, 1);
});

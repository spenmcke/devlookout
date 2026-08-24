'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { DataProtector, decodeMasterKey } = require('../src/security/data-protector');
const { SnapshotStore } = require('../src/storage/snapshot-store');
const { EventStore } = require('../src/storage/event-store');
const { MigrationRegistry } = require('../src/storage/migrations');
const { BackupManager } = require('../src/storage/backup');
const { createEvent } = require('../src/events/schema');

const key = crypto.createHash('sha256').update('test-only-key').digest();

function fixtureEvent() {
  return createEvent({ time: '2026-08-17T20:00:00.000Z', ingestedAt: '2026-08-17T20:00:00.000Z', category: 'health', class: 'sensor_activity', activity: 'heartbeat', source: { adapter: 'fixture', instance: 'site', recordId: 'one' }, entityKeys: ['sensor:1'], attributes: {} });
}

test('data protector authenticates context and ciphertext', () => {
  const protector = new DataProtector(key);
  const sealed = protector.sealString('sensitive local data', 'context:a');
  assert.equal(protector.openString(sealed, 'context:a'), 'sensitive local data');
  assert.throws(() => protector.openString(sealed, 'context:b'), /authentication failed/);
  sealed.ciphertext = `${sealed.ciphertext.slice(0, -2)}AA`;
  assert.throws(() => protector.openString(sealed, 'context:a'), /authentication failed/);
  assert.deepEqual(decodeMasterKey(key.toString('base64')), key);
});

test('snapshot and event stores encrypt all persisted content', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-encrypted-'));
  const protector = new DataProtector(key);
  try {
    const snapshots = new SnapshotStore(directory, 'test.snapshot.json', { protector, requireEncryption: true });
    await snapshots.save({ schemaVersion: 1, secretLabel: 'must-not-be-plaintext' });
    assert.ok(!(await fs.readFile(snapshots.file, 'utf8')).includes('must-not-be-plaintext'));
    assert.equal((await snapshots.load()).secretLabel, 'must-not-be-plaintext');
    const events = new EventStore(directory, { protector, requireEncryption: true });
    await events.append([fixtureEvent()]);
    assert.ok(!(await fs.readFile(events.file, 'utf8')).includes('sensor_activity'));
    assert.equal((await events.query()).length, 1);
  } finally { await fs.rm(directory, { recursive: true, force: true }); }
});

test('encryption-required stores reject plaintext state', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-plaintext-'));
  try {
    const file = path.join(directory, 'test.snapshot.json');
    await fs.writeFile(file, JSON.stringify({ schemaVersion: 1 }));
    const store = new SnapshotStore(directory, 'test.snapshot.json', { protector: new DataProtector(key), requireEncryption: true });
    await assert.rejects(() => store.load(), /Encrypted snapshot required/);
  } finally { await fs.rm(directory, { recursive: true, force: true }); }
});

test('migration registry advances deterministically and rejects missing paths', () => {
  const registry = new MigrationRegistry('fixture').register(1, 2, (document) => ({ ...document, schemaVersion: 2, added: true }));
  assert.deepEqual(registry.migrate({ schemaVersion: 1, value: 1 }, 2), { schemaVersion: 2, value: 1, added: true });
  assert.throws(() => registry.migrate({ schemaVersion: 2 }, 3), /No fixture migration/);
  assert.throws(() => registry.migrate({ schemaVersion: 3 }, 2), /newer than/);
});

test('encrypted backups verify and restore into a new directory', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-backup-'));
  const data = path.join(root, 'data');
  const restored = path.join(root, 'restored');
  const backup = path.join(root, 'backup.lkb');
  const protector = new DataProtector(key);
  try {
    await fs.mkdir(data, { mode: 0o700 });
    await fs.writeFile(path.join(data, 'events.jsonl'), 'encrypted-looking-data\n', { mode: 0o600 });
    const manager = new BackupManager({ dataDirectory: data, protector });
    assert.equal((await manager.create(backup, '2026-08-17T20:00:00.000Z')).entries, 1);
    assert.ok(!(await fs.readFile(backup, 'utf8')).includes('encrypted-looking-data'));
    await manager.restoreToNewDirectory(backup, restored);
    assert.equal(await fs.readFile(path.join(restored, 'events.jsonl'), 'utf8'), 'encrypted-looking-data\n');
  } finally { await fs.rm(root, { recursive: true, force: true }); }
});

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { DataProtector } = require('../src/security/data-protector');
const { SnapshotStore } = require('../src/storage/snapshot-store');
const { DurableExportOutbox } = require('../src/export/outbox');
const { inspectDataDirectory, checkSensitiveFile, summarize } = require('../src/operations/doctor');

test('doctor validates encrypted snapshots without modifying storage', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-doctor-'));
  const protector = new DataProtector(crypto.randomBytes(32));
  try {
    await fs.chmod(directory, 0o700);
    await new SnapshotStore(directory, 'graph.snapshot.json', { protector, requireEncryption: true }).save({ schemaVersion: 1, entities: [], relationships: [], capabilities: [] });
    const before = await fs.readdir(directory);
    const report = await inspectDataDirectory({ dataDirectory: directory, protector, requireEncryption: true, minimumFreeBytes: 0 });
    assert.equal(report.status, 'pass');
    assert.equal(report.checks.find((check) => check.id === 'integrity:graph.snapshot.json').status, 'pass');
    assert.deepEqual(await fs.readdir(directory), before);
  } finally { await fs.rm(directory, { recursive: true, force: true }); }
});

test('doctor fails closed for missing encryption keys and unsafe sensitive files', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-doctor-'));
  const sensitive = path.join(directory, 'credentials.json');
  try {
    await fs.chmod(directory, 0o700);
    await fs.writeFile(sensitive, '{}', { mode: 0o644 });
    const report = await inspectDataDirectory({ dataDirectory: directory, requireEncryption: true, minimumFreeBytes: 0 });
    assert.equal(report.status, 'fail');
    assert.match(report.checks.find((check) => check.id === 'storage.encryption').message, /no master key/);
    if (process.platform !== 'win32') assert.equal((await checkSensitiveFile(sensitive, 'credentials')).status, 'fail');
  } finally { await fs.rm(directory, { recursive: true, force: true }); }
});

test('doctor reports corrupt or future-version state and summarizes severity', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-doctor-'));
  try {
    await fs.chmod(directory, 0o700);
    await new SnapshotStore(directory, 'rules.snapshot.json').save({ schemaVersion: 2, imported: [] });
    const report = await inspectDataDirectory({ dataDirectory: directory, minimumFreeBytes: 0 });
    assert.equal(report.status, 'fail');
    assert.match(report.checks.find((check) => check.id === 'integrity:rules.snapshot.json').message, /newer than/);
    assert.deepEqual(summarize([{ status: 'pass' }, { status: 'warn' }]).totals, { pass: 1, warn: 1, fail: 0 });
  } finally { await fs.rm(directory, { recursive: true, force: true }); }
});

test('doctor validates event export and alert webhook outboxes', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-doctor-'));
  const protector = new DataProtector(crypto.randomBytes(32));
  try {
    await fs.chmod(directory, 0o700);
    const outbox = new DurableExportOutbox(directory, { protector, requireEncryption: true });
    await outbox.initialize();
    await outbox.enqueue([{ id: 'export-event-1', category: 'authentication' }]);
    const webhook = new DurableExportOutbox(directory, { protector, requireEncryption: true, filename: 'alert-webhook.jsonl' });
    await webhook.initialize();
    await webhook.enqueue([{ id: 'alert-1', title: 'test' }]);
    const before = await fs.readdir(directory);
    const report = await inspectDataDirectory({ dataDirectory: directory, protector, requireEncryption: true, minimumFreeBytes: 0 });
    assert.equal(report.checks.find((check) => check.id === 'integrity:cloud-export').status, 'pass');
    assert.equal(report.checks.find((check) => check.id === 'integrity:alert-webhook').status, 'pass');
    assert.deepEqual(await fs.readdir(directory), before);
  } finally { await fs.rm(directory, { recursive: true, force: true }); }
});

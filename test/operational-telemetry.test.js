'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const {
  createOperationalTelemetryCollector,
  inspectDirectorySize,
  inspectFilesystems,
  inspectQueues,
  operationalHealthCollector,
  parseMountInfo,
  validateOperationalHealthSample
} = require('../src/collector/operational-telemetry');

test('operational telemetry reports bounded VM and Lookout metrics without paths or filenames', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-operational-'));
  let cpuTicks = 0;
  let idleTicks = 50;
  let processCpu = 0;
  let monotonic = 1000;
  const osApi = {
    cpus: () => [{ times: { user: (cpuTicks += 50), nice: 0, sys: 10, idle: (idleTicks += 50), irq: 0 } }],
    totalmem: () => 1000,
    freemem: () => 250,
    uptime: () => 1234,
    loadavg: () => [0.5, 0.25, 0.1]
  };
  const processApi = {
    resourceUsage: () => ({ userCPUTime: (processCpu += 100000), systemCPUTime: 0 }),
    memoryUsage: () => ({ rss: 400, heapUsed: 200, external: 50 }),
    uptime: () => 99
  };
  try {
    await fs.writeFile(path.join(directory, 'state.secret'), Buffer.alloc(12));
    const collector = createOperationalTelemetryCollector({ collectorId: 'collector-1', entityKey: 'collector-endpoint:collector-1', dataDirectory: directory, osApi, processApi, procRoot: path.join(directory, 'missing-proc'), monotonicNow: () => (monotonic += 1000), now: () => '2026-08-23T12:00:00.000Z' });
    const first = await collector.collect();
    const second = await collector.collect();

    assert.equal(first.schemaVersion, 1);
    assert.equal(first.host.memory.usedBytes, 750);
    assert.equal(first.host.memory.usedPercent, 75);
    assert.deepEqual(first.host.cpu.loadAverage, [0.5, 0.25, 0.1]);
    assert.equal(first.host.cpu.usedPercent, null);
    assert.equal(second.host.cpu.usedPercent, 50);
    assert.equal(first.lookout.process.memory.residentBytes, 400);
    assert.equal(first.lookout.process.cpu.usedPercent, null);
    assert.equal(second.lookout.process.cpu.usedPercent, 10);
    assert.equal(first.lookout.dataStorage.bytes, 12);
    assert.equal(first.lookout.dataStorage.entries, 1);
    assert.equal(JSON.stringify(first).includes(directory), false);
    assert.equal(JSON.stringify(first).includes('state.secret'), false);
  } finally { await fs.rm(directory, { recursive: true, force: true }); }
});

test('collector returns operational health separately from security facts and events', async () => {
  const collector = operationalHealthCollector({ collectorId: 'collector-2', dataDirectory: null, procRoot: '/definitely-missing' });
  const result = await collector.collect({ collectedAt: '2026-08-23T12:34:56.000Z' });
  assert.deepEqual(result.facts, []);
  assert.deepEqual(result.events, []);
  assert.equal(result.operationalHealth.length, 1);
  assert.equal(result.operationalHealth[0].collectorId, 'collector-2');
  assert.equal(result.operationalHealth[0].entityKey, 'collector-endpoint:collector-2');
  assert.equal(result.operationalHealth[0].observedAt, '2026-08-23T12:34:56.000Z');
  assert.equal(validateOperationalHealthSample(result.operationalHealth[0]), result.operationalHealth[0]);
  assert.throws(() => validateOperationalHealthSample({ ...result.operationalHealth[0], filename: 'secret' }), /invalid fields/);
});

test('directory size is bounded and does not follow symbolic links', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-size-'));
  const outside = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-outside-'));
  try {
    await fs.writeFile(path.join(directory, 'one'), Buffer.alloc(5));
    await fs.writeFile(path.join(directory, 'two'), Buffer.alloc(7));
    await fs.writeFile(path.join(outside, 'private'), Buffer.alloc(100));
    await fs.symlink(outside, path.join(directory, 'link'));
    const summary = await inspectDirectorySize(directory, { maxEntries: 2 });
    assert.equal(summary.truncated, true);
    assert.ok(summary.entries <= 2);
    assert.ok(summary.bytes <= 12);
    assert.equal(Object.hasOwn(summary, 'files'), false);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
    await fs.rm(outside, { recursive: true, force: true });
  }
});

test('filesystem inspection parses Linux mount metadata, hashes identities, and caps volumes', async () => {
  const mountInfo = [
    '24 1 8:1 / / rw,relatime - ext4 /dev/root rw',
    '25 24 0:20 / /proc rw,nosuid - proc proc rw',
    '26 24 8:2 / /data\\040disk rw,relatime - xfs /dev/sdb rw'
  ].join('\n');
  assert.deepEqual(parseMountInfo(mountInfo), [
    { mountPoint: '/', filesystemType: 'ext4' },
    { mountPoint: '/data disk', filesystemType: 'xfs' }
  ]);
  const fsApi = {
    readFile: async () => mountInfo,
    statfs: async () => ({ bsize: 100, blocks: 10, bavail: 2 })
  };
  const report = await inspectFilesystems({ dataDirectory: '/data disk/lookout', fsApi, maxMounts: 1 });
  assert.equal(report.volumes.length, 1);
  assert.equal(report.truncated, true);
  assert.equal(report.volumes[0].totalBytes, 1000);
  assert.equal(report.volumes[0].usedPercent, 80);
  assert.match(report.volumes[0].id, /^[a-f0-9]{16}$/);
  assert.equal(JSON.stringify(report).includes('/data disk'), false);
});

test('queue summaries expose counts only and degrade safely for missing queues', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-queues-'));
  try {
    await fs.writeFile(path.join(directory, 'cloud-export.jsonl'), [1, 2, 3].map((sequence) => JSON.stringify({ sequence, event: { secret: 'not emitted' } })).join('\n') + '\n');
    await fs.writeFile(path.join(directory, 'cloud-export.checkpoint.json'), JSON.stringify({ acknowledgedThrough: 1 }));
    const report = await inspectQueues(directory);
    assert.equal(report.queues[0].records, 3);
    assert.equal(report.queues[0].pending, 2);
    assert.equal(report.queues[1].status, 'notConfigured');
    assert.equal(JSON.stringify(report).includes('not emitted'), false);
    assert.equal(JSON.stringify(report).includes('.jsonl'), false);
  } finally { await fs.rm(directory, { recursive: true, force: true }); }
});

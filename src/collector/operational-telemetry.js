'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');

const DEFAULT_MAX_MOUNTS = 32;
const DEFAULT_MAX_DIRECTORY_ENTRIES = 10000;
const DEFAULT_MAX_QUEUE_RECORDS = 50000;
const MAX_QUEUE_INSPECTION_BYTES = 8 * 1024 * 1024;
const MAX_SAFE_VALUE = Number.MAX_SAFE_INTEGER;
const EXCLUDED_FILESYSTEMS = new Set([
  'autofs', 'bpf', 'cgroup', 'cgroup2', 'configfs', 'debugfs', 'devpts', 'devtmpfs',
  'fusectl', 'hugetlbfs', 'mqueue', 'proc', 'pstore', 'ramfs', 'securityfs', 'sysfs', 'tmpfs', 'tracefs'
]);

function boundedNumber(value, { integer = false } = {}) {
  const number = Number(value);
  if (!Number.isFinite(number) || number < 0) return null;
  const bounded = Math.min(number, MAX_SAFE_VALUE);
  return integer ? Math.floor(bounded) : bounded;
}

function percentage(used, total) {
  if (!Number.isFinite(used) || !Number.isFinite(total) || total <= 0) return null;
  return Math.round(Math.min(100, Math.max(0, used / total * 100)) * 100) / 100;
}

function cpuTotals(cpus) {
  let idle = 0;
  let total = 0;
  for (const cpu of Array.isArray(cpus) ? cpus : []) {
    const times = cpu?.times || {};
    for (const value of Object.values(times)) total += boundedNumber(value) || 0;
    idle += boundedNumber(times.idle) || 0;
  }
  return { idle, total };
}

function cpuPercent(previous, current) {
  if (!previous || current.total <= previous.total) return null;
  const totalDelta = current.total - previous.total;
  const idleDelta = Math.max(0, current.idle - previous.idle);
  return percentage(totalDelta - idleDelta, totalDelta);
}

function decodeMountField(value) {
  return value.replace(/\\([0-7]{3})/g, (_match, octal) => String.fromCharCode(parseInt(octal, 8)));
}

function parseMountInfo(text) {
  const mounts = [];
  for (const line of String(text || '').split('\n')) {
    if (!line) continue;
    const separator = line.indexOf(' - ');
    if (separator < 0) continue;
    const left = line.slice(0, separator).split(' ');
    const right = line.slice(separator + 3).split(' ');
    if (left.length < 5 || !right[0] || EXCLUDED_FILESYSTEMS.has(right[0])) continue;
    mounts.push({ mountPoint: decodeMountField(left[4]), filesystemType: right[0] });
  }
  return mounts;
}

function volumeId(mountPoint) {
  return crypto.createHash('sha256').update(mountPoint).digest('hex').slice(0, 16);
}

function isWithin(candidate, parent) {
  const relative = path.relative(parent, candidate);
  return relative === '' || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative));
}

async function inspectFilesystems({ dataDirectory, fsApi = fs, procRoot = '/proc', maxMounts = DEFAULT_MAX_MOUNTS } = {}) {
  const result = { status: 'available', truncated: false, volumes: [] };
  let mounts;
  try { mounts = parseMountInfo(await fsApi.readFile(path.join(procRoot, 'self/mountinfo'), 'utf8')); }
  catch { mounts = [{ mountPoint: path.parse(path.resolve(dataDirectory || '/')).root, filesystemType: 'unknown' }]; result.status = 'degraded'; }

  const resolvedData = dataDirectory ? path.resolve(dataDirectory) : null;
  const unique = new Map();
  for (const mount of mounts) unique.set(mount.mountPoint, mount);
  const dataMount = resolvedData ? [...unique.values()].filter((mount) => isWithin(resolvedData, path.resolve(mount.mountPoint))).sort((a, b) => b.mountPoint.length - a.mountPoint.length)[0]?.mountPoint : null;
  const candidates = [...unique.values()]
    .sort((a, b) => Number(b.mountPoint === dataMount) - Number(a.mountPoint === dataMount) || Number(b.mountPoint === '/') - Number(a.mountPoint === '/') || a.mountPoint.localeCompare(b.mountPoint))
    .slice(0, Math.max(1, Math.min(DEFAULT_MAX_MOUNTS, maxMounts)));
  result.truncated = unique.size > candidates.length;

  for (const mount of candidates) {
    try {
      const stat = await fsApi.statfs(mount.mountPoint);
      const blockSize = boundedNumber(stat.bsize, { integer: true });
      const blocks = boundedNumber(stat.blocks, { integer: true });
      const availableBlocks = boundedNumber(stat.bavail, { integer: true });
      if (blockSize === null || blocks === null || availableBlocks === null) throw new Error('invalid statfs values');
      const totalBytes = boundedNumber(blockSize * blocks, { integer: true });
      const reportedAvailableBytes = boundedNumber(blockSize * availableBlocks, { integer: true });
      const availableBytes = totalBytes === null || reportedAvailableBytes === null ? null : Math.min(totalBytes, reportedAvailableBytes);
      const usedBytes = totalBytes === null || availableBytes === null ? null : Math.max(0, totalBytes - availableBytes);
      result.volumes.push({
        id: volumeId(mount.mountPoint),
        filesystemType: String(mount.filesystemType).slice(0, 32),
        root: mount.mountPoint === path.parse(mount.mountPoint).root,
        dataVolume: mount.mountPoint === dataMount,
        totalBytes,
        usedBytes,
        availableBytes,
        usedPercent: percentage(usedBytes, totalBytes)
      });
    } catch { result.status = 'degraded'; }
  }
  return result;
}

async function inspectDirectorySize(directory, { fsApi = fs, maxEntries = DEFAULT_MAX_DIRECTORY_ENTRIES } = {}) {
  maxEntries = Math.max(1, Math.min(DEFAULT_MAX_DIRECTORY_ENTRIES, Number.isSafeInteger(maxEntries) ? maxEntries : DEFAULT_MAX_DIRECTORY_ENTRIES));
  const summary = { status: 'available', bytes: 0, entries: 0, truncated: false };
  if (!directory) return { ...summary, status: 'unavailable' };
  const pending = [path.resolve(directory)];
  try {
    const root = await fsApi.lstat(pending[0]);
    if (!root.isDirectory() || root.isSymbolicLink()) return { ...summary, status: 'unavailable' };
  } catch { return { ...summary, status: 'unavailable' }; }

  while (pending.length && summary.entries < maxEntries) {
    const current = pending.pop();
    let entries;
    try {
      const currentStat = await fsApi.lstat(current);
      if (!currentStat.isDirectory() || currentStat.isSymbolicLink()) continue;
      entries = await fsApi.readdir(current, { withFileTypes: true });
    }
    catch { summary.status = 'degraded'; continue; }
    for (const entry of entries) {
      if (summary.entries >= maxEntries) { summary.truncated = true; break; }
      summary.entries += 1;
      const target = path.join(current, entry.name);
      try {
        if (entry.isSymbolicLink()) continue;
        if (entry.isDirectory()) pending.push(target);
        else if (entry.isFile()) summary.bytes = Math.min(MAX_SAFE_VALUE, summary.bytes + boundedNumber((await fsApi.lstat(target)).size, { integer: true }));
      } catch { summary.status = 'degraded'; }
    }
  }
  if (pending.length) summary.truncated = true;
  return summary;
}

const QUEUES = Object.freeze([
  { id: 'eventDelivery', journal: 'cloud-export.jsonl', checkpoint: 'cloud-export.checkpoint.json' },
  { id: 'alertDelivery', journal: 'alert-webhook.jsonl', checkpoint: 'alert-webhook.checkpoint.json' }
]);

async function inspectQueues(dataDirectory, { fsApi = fs, maxRecords = DEFAULT_MAX_QUEUE_RECORDS } = {}) {
  maxRecords = Math.max(1, Math.min(DEFAULT_MAX_QUEUE_RECORDS, Number.isSafeInteger(maxRecords) ? maxRecords : DEFAULT_MAX_QUEUE_RECORDS));
  if (!dataDirectory) return { status: 'unavailable', queues: [] };
  const queues = [];
  let degraded = false;
  for (const definition of QUEUES) {
    const queue = { id: definition.id, status: 'available', journalBytes: 0, records: 0, pending: null, truncated: false };
    try {
      const journalPath = path.join(dataDirectory, definition.journal);
      const stat = await fsApi.lstat(journalPath);
      if (!stat.isFile() || stat.isSymbolicLink()) throw new Error('unsafe journal');
      queue.journalBytes = boundedNumber(stat.size, { integer: true });
      if (stat.size > MAX_QUEUE_INSPECTION_BYTES) {
        queue.truncated = true;
        queue.records = null;
        queues.push(queue);
        continue;
      }
      const text = await fsApi.readFile(journalPath, 'utf8');
      const lines = text.split('\n').filter(Boolean);
      queue.records = Math.min(lines.length, maxRecords);
      queue.truncated = lines.length > maxRecords;
      let acknowledgedThrough = null;
      try {
        const checkpointText = await fsApi.readFile(path.join(dataDirectory, definition.checkpoint), 'utf8');
        if (checkpointText.length <= 65536) {
          const checkpoint = JSON.parse(checkpointText);
          if (Number.isSafeInteger(checkpoint.acknowledgedThrough) && checkpoint.acknowledgedThrough >= 0) acknowledgedThrough = checkpoint.acknowledgedThrough;
        }
      } catch { /* A missing or protected checkpoint leaves pending unknown. */ }
      if (!queue.truncated && acknowledgedThrough !== null) {
        let lastSequence = acknowledgedThrough;
        for (const line of lines) {
          try {
            const sequence = JSON.parse(line).sequence;
            if (Number.isSafeInteger(sequence) && sequence > lastSequence) lastSequence = sequence;
          } catch { /* Content is intentionally not inspected beyond sequence metadata. */ }
        }
        queue.pending = Math.max(0, lastSequence - acknowledgedThrough);
      }
    } catch (error) {
      if (error.code === 'ENOENT') queue.status = 'notConfigured';
      else { queue.status = 'degraded'; degraded = true; }
    }
    queues.push(queue);
  }
  return { status: degraded ? 'degraded' : 'available', queues };
}

class OperationalTelemetryCollector {
  #previousHostCpu = null;
  #previousProcessCpu = null;

  constructor({ collectorId = 'unknown', entityKey = `collector-endpoint:${collectorId}`, dataDirectory = null, osApi = os, fsApi = fs, processApi = process, procRoot = '/proc', maxMounts = DEFAULT_MAX_MOUNTS, maxDirectoryEntries = DEFAULT_MAX_DIRECTORY_ENTRIES, maxQueueRecords = DEFAULT_MAX_QUEUE_RECORDS, now = () => new Date().toISOString(), monotonicNow = () => Number(process.hrtime.bigint()) / 1e6 } = {}) {
    this.options = { collectorId, entityKey, dataDirectory, osApi, fsApi, processApi, procRoot, maxMounts, maxDirectoryEntries, maxQueueRecords, now, monotonicNow };
  }

  async collect() {
    const { collectorId, entityKey, dataDirectory, osApi, fsApi, processApi, procRoot, maxMounts, maxDirectoryEntries, maxQueueRecords, now, monotonicNow } = this.options;
    let cpus = [];
    let hostCpu = { idle: 0, total: 0 };
    try { cpus = osApi.cpus(); hostCpu = cpuTotals(cpus); } catch { /* Report null CPU percentage while preserving other metrics. */ }
    let totalMemoryBytes = null;
    let availableMemoryBytes = null;
    try { totalMemoryBytes = boundedNumber(osApi.totalmem(), { integer: true }); } catch { /* Preserve a partial sample. */ }
    try { availableMemoryBytes = boundedNumber(osApi.freemem(), { integer: true }); } catch { /* Preserve a partial sample. */ }
    if (totalMemoryBytes !== null && availableMemoryBytes !== null) availableMemoryBytes = Math.min(totalMemoryBytes, availableMemoryBytes);
    const usedMemoryBytes = totalMemoryBytes === null || availableMemoryBytes === null ? null : Math.max(0, totalMemoryBytes - availableMemoryBytes);
    const hostCpuPercent = cpuPercent(this.#previousHostCpu, hostCpu);
    this.#previousHostCpu = hostCpu.total > 0 ? hostCpu : null;

    let resourceUsage = null;
    try { resourceUsage = processApi.resourceUsage(); } catch { /* Runtime may not expose process resource usage. */ }
    const processCpuMs = resourceUsage ? boundedNumber((resourceUsage.userCPUTime + resourceUsage.systemCPUTime) / 1000) : null;
    const monotonicMs = safeCall(() => boundedNumber(monotonicNow()));
    let processCpuPercent = null;
    if (processCpuMs !== null && monotonicMs !== null && this.#previousProcessCpu && monotonicMs > this.#previousProcessCpu.monotonicMs) {
      processCpuPercent = percentage(processCpuMs - this.#previousProcessCpu.cpuMs, monotonicMs - this.#previousProcessCpu.monotonicMs);
    }
    if (processCpuMs !== null && monotonicMs !== null) this.#previousProcessCpu = { cpuMs: processCpuMs, monotonicMs };
    let memoryUsage = {};
    try { memoryUsage = processApi.memoryUsage(); } catch { /* Preserve the sample with null process memory values. */ }

    const [filesystems, dataStorage, delivery] = await Promise.all([
      inspectFilesystems({ dataDirectory, fsApi, procRoot, maxMounts }),
      inspectDirectorySize(dataDirectory, { fsApi, maxEntries: maxDirectoryEntries }),
      inspectQueues(dataDirectory, { fsApi, maxRecords: maxQueueRecords })
    ]);

    const sample = {
      schemaVersion: 1,
      collectorId,
      entityKey,
      observedAt: now(),
      host: {
        uptimeSeconds: safeCall(() => boundedNumber(osApi.uptime(), { integer: true })),
        cpu: { logicalProcessors: Math.min(1024, Array.isArray(cpus) ? cpus.length : 0), usedPercent: hostCpuPercent, loadAverage: safeCall(() => (osApi.loadavg?.() || []).slice(0, 3).map((value) => boundedNumber(value)), []) },
        memory: { totalBytes: totalMemoryBytes, usedBytes: usedMemoryBytes, availableBytes: availableMemoryBytes, usedPercent: percentage(usedMemoryBytes, totalMemoryBytes) },
        filesystems
      },
      lookout: {
        process: {
          uptimeSeconds: safeCall(() => boundedNumber(processApi.uptime(), { integer: true })),
          cpu: { usedPercent: processCpuPercent, cumulativeMilliseconds: processCpuMs },
          memory: { residentBytes: boundedNumber(memoryUsage.rss, { integer: true }), heapUsedBytes: boundedNumber(memoryUsage.heapUsed, { integer: true }), externalBytes: boundedNumber(memoryUsage.external, { integer: true }) }
        },
        dataStorage,
        delivery
      }
    };
    validateOperationalHealthSample(sample);
    return sample;
  }
}

function safeCall(callback, fallback = null) {
  try { return callback(); } catch { return fallback; }
}

function exactKeys(value, keys, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} must be an object`);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) throw new Error(`${label} has invalid fields`);
}

function validMetric(value) {
  return value === null || (Number.isFinite(value) && value >= 0 && value <= MAX_SAFE_VALUE);
}

function validPercent(value) {
  return value === null || (Number.isFinite(value) && value >= 0 && value <= 100);
}

function requireMetrics(values, label) {
  if (values.some((value) => !validMetric(value))) throw new Error(`${label} has invalid metric values`);
}

function validateOperationalHealthSample(sample) {
  exactKeys(sample, ['schemaVersion', 'collectorId', 'entityKey', 'observedAt', 'host', 'lookout'], 'Operational health sample');
  if (sample.schemaVersion !== 1) throw new Error('Operational health schemaVersion must be 1');
  for (const [label, value] of [['collectorId', sample.collectorId], ['entityKey', sample.entityKey]]) {
    if (typeof value !== 'string' || value.length < 1 || value.length > 256) throw new Error(`${label} is invalid`);
  }
  if (typeof sample.observedAt !== 'string' || Number.isNaN(Date.parse(sample.observedAt))) throw new Error('observedAt is invalid');
  exactKeys(sample.host, ['uptimeSeconds', 'cpu', 'memory', 'filesystems'], 'host');
  exactKeys(sample.host.cpu, ['logicalProcessors', 'usedPercent', 'loadAverage'], 'host.cpu');
  exactKeys(sample.host.memory, ['totalBytes', 'usedBytes', 'availableBytes', 'usedPercent'], 'host.memory');
  if (!Array.isArray(sample.host.cpu.loadAverage) || sample.host.cpu.loadAverage.length > 3 || !validPercent(sample.host.cpu.usedPercent) || !validPercent(sample.host.memory.usedPercent)) throw new Error('host CPU or memory values are invalid');
  requireMetrics([sample.host.uptimeSeconds, sample.host.cpu.logicalProcessors, ...sample.host.cpu.loadAverage, sample.host.memory.totalBytes, sample.host.memory.usedBytes, sample.host.memory.availableBytes], 'host');
  exactKeys(sample.host.filesystems, ['status', 'truncated', 'volumes'], 'host.filesystems');
  if (!['available', 'degraded'].includes(sample.host.filesystems.status) || typeof sample.host.filesystems.truncated !== 'boolean' || !Array.isArray(sample.host.filesystems.volumes) || sample.host.filesystems.volumes.length > DEFAULT_MAX_MOUNTS) throw new Error('host.filesystems is invalid');
  for (const volume of sample.host.filesystems.volumes) {
    exactKeys(volume, ['id', 'filesystemType', 'root', 'dataVolume', 'totalBytes', 'usedBytes', 'availableBytes', 'usedPercent'], 'host.filesystem');
    if (!/^[a-f0-9]{16}$/.test(volume.id) || typeof volume.filesystemType !== 'string' || volume.filesystemType.length > 32 || typeof volume.root !== 'boolean' || typeof volume.dataVolume !== 'boolean') throw new Error('host.filesystem identity is invalid');
    requireMetrics([volume.totalBytes, volume.usedBytes, volume.availableBytes], 'host.filesystem');
    if (!validPercent(volume.usedPercent)) throw new Error('host.filesystem percentage is invalid');
  }
  exactKeys(sample.lookout, ['process', 'dataStorage', 'delivery'], 'lookout');
  exactKeys(sample.lookout.process, ['uptimeSeconds', 'cpu', 'memory'], 'lookout.process');
  exactKeys(sample.lookout.process.cpu, ['usedPercent', 'cumulativeMilliseconds'], 'lookout.process.cpu');
  exactKeys(sample.lookout.process.memory, ['residentBytes', 'heapUsedBytes', 'externalBytes'], 'lookout.process.memory');
  requireMetrics([sample.lookout.process.uptimeSeconds, sample.lookout.process.cpu.cumulativeMilliseconds, sample.lookout.process.memory.residentBytes, sample.lookout.process.memory.heapUsedBytes, sample.lookout.process.memory.externalBytes], 'lookout.process');
  if (!validPercent(sample.lookout.process.cpu.usedPercent)) throw new Error('lookout.process CPU percentage is invalid');
  exactKeys(sample.lookout.dataStorage, ['status', 'bytes', 'entries', 'truncated'], 'lookout.dataStorage');
  if (!['available', 'degraded', 'unavailable'].includes(sample.lookout.dataStorage.status) || typeof sample.lookout.dataStorage.truncated !== 'boolean') throw new Error('lookout.dataStorage is invalid');
  requireMetrics([sample.lookout.dataStorage.bytes, sample.lookout.dataStorage.entries], 'lookout.dataStorage');
  exactKeys(sample.lookout.delivery, ['status', 'queues'], 'lookout.delivery');
  if (!['available', 'degraded', 'unavailable'].includes(sample.lookout.delivery.status) || !Array.isArray(sample.lookout.delivery.queues) || sample.lookout.delivery.queues.length > QUEUES.length) throw new Error('lookout.delivery is invalid');
  for (const queue of sample.lookout.delivery.queues) {
    exactKeys(queue, ['id', 'status', 'journalBytes', 'records', 'pending', 'truncated'], 'lookout.delivery.queue');
    if (!QUEUES.some((definition) => definition.id === queue.id) || !['available', 'degraded', 'notConfigured'].includes(queue.status) || typeof queue.truncated !== 'boolean') throw new Error('lookout.delivery.queue is invalid');
    requireMetrics([queue.journalBytes, queue.records, queue.pending], 'lookout.delivery.queue');
  }
  return sample;
}

function operationalHealthCollector({ collectorId, entityKey = null, ...options } = {}) {
  if (!collectorId) throw new Error('Operational health collector requires collectorId');
  const metrics = new OperationalTelemetryCollector({ collectorId, entityKey: entityKey || `collector-endpoint:${collectorId}`, ...options });
  return {
    manifest: { id: 'operational-health', version: '1.0.0', intervalSeconds: 300, capabilities: ['operational_health'] },
    async collect({ collectedAt, state = null } = {}) {
      const observedAt = collectedAt || new Date().toISOString();
      if (state?.lastCollectedAt && Date.parse(observedAt) - Date.parse(state.lastCollectedAt) < 300000) return { facts: [], events: [], operationalHealth: [], state };
      const sample = await metrics.collect();
      sample.observedAt = observedAt;
      validateOperationalHealthSample(sample);
      return { facts: [], events: [], operationalHealth: [sample], state: { lastCollectedAt: observedAt } };
    }
  };
}

function createOperationalTelemetryCollector(options) {
  return new OperationalTelemetryCollector(options);
}

module.exports = {
  DEFAULT_MAX_MOUNTS,
  DEFAULT_MAX_DIRECTORY_ENTRIES,
  DEFAULT_MAX_QUEUE_RECORDS,
  OperationalTelemetryCollector,
  createOperationalTelemetryCollector,
  operationalHealthCollector,
  validateOperationalHealthSample,
  inspectDirectorySize,
  inspectFilesystems,
  inspectQueues,
  parseMountInfo
};

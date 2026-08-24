'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const { SnapshotStore } = require('../storage/snapshot-store');
const { parseJournal, verifyRecords } = require('../storage/event-store');
const { DurableExportOutbox } = require('../export/outbox');

const CURRENT_SCHEMA_VERSION = 1;
const SNAPSHOT_FILES = Object.freeze([
  'graph.snapshot.json',
  'detection-state.snapshot.json',
  'cases.snapshot.json',
  'baselines.snapshot.json',
  'rules.snapshot.json',
  'collectors.snapshot.json',
  'collector-state.json'
]);
const JOURNAL_FILES = Object.freeze(['events.jsonl', 'audit.jsonl']);
const EXPORT_FILES = Object.freeze(['cloud-export.jsonl', 'cloud-export.checkpoint.json', 'alert-webhook.jsonl', 'alert-webhook.checkpoint.json']);
const DATA_FILES = Object.freeze([...SNAPSHOT_FILES, ...JOURNAL_FILES, ...EXPORT_FILES]);

function result(id, status, message, details = undefined) {
  return { id, status, message, ...(details === undefined ? {} : { details }) };
}

function summarize(checks) {
  const totals = { pass: 0, warn: 0, fail: 0 };
  for (const check of checks) totals[check.status] += 1;
  return { status: totals.fail ? 'fail' : totals.warn ? 'warn' : 'pass', totals, checks };
}

function permissionsArePrivate(mode) {
  return process.platform === 'win32' || (mode & 0o077) === 0;
}

async function checkSensitiveFile(filename, label) {
  if (!filename) return null;
  const target = path.resolve(filename);
  try {
    const stat = await fs.lstat(target);
    if (!stat.isFile() || stat.isSymbolicLink()) return result(`file:${label}`, 'fail', `${label} must be a regular, non-symlink file`, { path: target });
    if (!permissionsArePrivate(stat.mode)) return result(`file:${label}`, 'fail', `${label} is accessible by group or other users`, { path: target, mode: (stat.mode & 0o777).toString(8) });
    if (process.platform !== 'win32' && typeof process.geteuid === 'function' && stat.uid !== process.geteuid()) return result(`file:${label}`, 'fail', `${label} is not owned by the current user`, { path: target, uid: stat.uid });
    return result(`file:${label}`, 'pass', `${label} permissions are private`, { path: target });
  } catch (error) {
    return result(`file:${label}`, 'fail', `${label} cannot be inspected: ${error.message}`, { path: target });
  }
}

async function validateSnapshot(directory, filename, { protector, requireEncryption }) {
  const store = new SnapshotStore(directory, filename, { protector, requireEncryption });
  const snapshot = await store.load();
  if (!snapshot) return null;
  if (!Number.isInteger(snapshot.schemaVersion)) throw new Error('document has no integer schemaVersion');
  if (snapshot.schemaVersion > CURRENT_SCHEMA_VERSION) throw new Error(`schema version ${snapshot.schemaVersion} is newer than this runtime`);
  if (snapshot.schemaVersion < CURRENT_SCHEMA_VERSION) throw new Error(`schema version ${snapshot.schemaVersion} requires a migration that is not registered`);
  return snapshot.schemaVersion;
}

async function validateJournal(directory, filename, { protector, requireEncryption }) {
  const target = path.join(directory, filename);
  let text;
  try { text = await fs.readFile(target, 'utf8'); }
  catch (error) { if (error.code === 'ENOENT') return null; throw error; }
  const records = parseJournal(text, protector, requireEncryption, path.basename(filename, '.jsonl'));
  verifyRecords(records);
  return records.length;
}

async function inspectDataDirectory({ dataDirectory, protector = null, requireEncryption = false, minimumFreeBytes = 1024 ** 3 } = {}) {
  if (!dataDirectory || !path.isAbsolute(dataDirectory)) throw new Error('Doctor requires an absolute dataDirectory');
  const directory = path.resolve(dataDirectory);
  const checks = [requireEncryption && !protector
    ? result('storage.encryption', 'fail', 'Encrypted storage is required but no master key is available')
    : result('storage.encryption', requireEncryption ? 'pass' : 'warn', requireEncryption ? 'Encrypted storage is required and a key is available' : 'Encrypted storage is not required')];
  let entries;
  try {
    const stat = await fs.lstat(directory);
    if (!stat.isDirectory() || stat.isSymbolicLink()) {
      checks.push(result('storage.directory', 'fail', 'Data directory must be a non-symlink directory', { path: directory }));
      return summarize(checks);
    }
    checks.push(permissionsArePrivate(stat.mode)
      ? result('storage.permissions', 'pass', 'Data directory permissions are private', { path: directory })
      : result('storage.permissions', 'fail', 'Data directory is accessible by group or other users', { path: directory, mode: (stat.mode & 0o777).toString(8) }));
    entries = await fs.readdir(directory, { withFileTypes: true });
  } catch (error) {
    checks.push(result('storage.directory', error.code === 'ENOENT' ? 'warn' : 'fail', error.code === 'ENOENT' ? 'Data directory does not exist yet' : `Data directory cannot be inspected: ${error.message}`, { path: directory }));
    return summarize(checks);
  }

  const known = new Set(DATA_FILES);
  const present = new Set(entries.map((entry) => entry.name));
  const temporary = entries.filter((entry) => /\.(tmp|restore)$/.test(entry.name));
  checks.push(temporary.length
    ? result('storage.temporary-files', 'warn', 'Abandoned temporary files should be reviewed before upgrade', temporary.map((entry) => entry.name).sort())
    : result('storage.temporary-files', 'pass', 'No abandoned temporary files were found'));

  for (const entry of entries.filter((item) => known.has(item.name)).sort((a, b) => a.name.localeCompare(b.name))) {
    const target = path.join(directory, entry.name);
    const stat = await fs.lstat(target);
    if (!stat.isFile() || stat.isSymbolicLink()) checks.push(result(`storage.file:${entry.name}`, 'fail', 'State path must be a regular, non-symlink file'));
    else if (!permissionsArePrivate(stat.mode)) checks.push(result(`storage.file:${entry.name}`, 'fail', 'State file is accessible by group or other users', { mode: (stat.mode & 0o777).toString(8) }));
  }

  if (!requireEncryption || protector) {
    for (const filename of SNAPSHOT_FILES.filter((name) => present.has(name))) {
      try {
        const version = await validateSnapshot(directory, filename, { protector, requireEncryption });
        checks.push(result(`integrity:${filename}`, 'pass', `Snapshot integrity and schema version ${version} are valid`));
      } catch (error) { checks.push(result(`integrity:${filename}`, 'fail', error.message)); }
    }
    for (const filename of JOURNAL_FILES.filter((name) => present.has(name))) {
      try {
        const count = await validateJournal(directory, filename, { protector, requireEncryption });
        checks.push(result(`integrity:${filename}`, 'pass', 'Journal chain and events are valid', { records: count }));
      } catch (error) { checks.push(result(`integrity:${filename}`, 'fail', error.message)); }
    }
    for (const [id, filename] of [['cloud-export', 'cloud-export.jsonl'], ['alert-webhook', 'alert-webhook.jsonl']]) {
      const checkpoint = filename.replace(/\.jsonl$/, '.checkpoint.json');
      if (present.has(checkpoint) && !present.has(filename)) {
        checks.push(result(`integrity:${id}`, 'fail', `${id} checkpoint exists without its outbox journal`));
      } else if (present.has(filename)) {
        try {
          const outbox = new DurableExportOutbox(directory, { protector, requireEncryption, filename });
          await outbox.initialize();
          checks.push(result(`integrity:${id}`, 'pass', `${id} outbox chain and checkpoint are valid`, outbox.stats()));
        } catch (error) { checks.push(result(`integrity:${id}`, 'fail', error.message)); }
      }
    }
  }

  try {
    const stats = await fs.statfs(directory);
    const availableBytes = Number(stats.bavail) * Number(stats.bsize);
    checks.push(result('storage.capacity', availableBytes >= minimumFreeBytes ? 'pass' : 'warn', availableBytes >= minimumFreeBytes ? 'Data volume has sufficient free-space headroom' : 'Data volume has low free-space headroom', { availableBytes, minimumFreeBytes }));
  } catch (error) { checks.push(result('storage.capacity', 'warn', `Free space could not be determined: ${error.message}`)); }
  return summarize(checks);
}

async function runDoctor({ config, protector = null, sensitiveFiles = {}, minimumFreeBytes } = {}) {
  if (!config?.storage?.dataDirectory) throw new Error('Doctor requires validated Lookout configuration');
  const checks = [result('runtime.node', Number(process.versions.node.split('.')[0]) >= 20 ? 'pass' : 'fail', `Node.js ${process.versions.node} is ${Number(process.versions.node.split('.')[0]) >= 20 ? 'supported' : 'unsupported; version 20 or newer is required'}`)];
  const storage = await inspectDataDirectory({ dataDirectory: config.storage.dataDirectory, requireEncryption: config.storage.requireEncryption, protector, minimumFreeBytes });
  checks.push(...storage.checks);
  const candidates = {
    config: sensitiveFiles.config,
    'master-key': sensitiveFiles.masterKey,
    credentials: config.auth?.credentialsFile,
    'collector-keys': config.collectors?.keysFile,
    ...sensitiveFiles.extra
  };
  for (const [label, filename] of Object.entries(candidates)) {
    const check = await checkSensitiveFile(filename, label);
    if (check) checks.push(check);
  }
  return summarize(checks);
}

module.exports = { CURRENT_SCHEMA_VERSION, SNAPSHOT_FILES, JOURNAL_FILES, EXPORT_FILES, DATA_FILES, permissionsArePrivate, checkSensitiveFile, inspectDataDirectory, runDoctor, summarize };

'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');
const { canonicalJson } = require('../core/canonical');
const { assertSafePath, syncDirectory, writeFileDurably } = require('./safe-files');

const DEFAULT_FILES = ['graph.snapshot.json', 'events.jsonl', 'audit.jsonl', 'detection-state.snapshot.json', 'cases.snapshot.json', 'baselines.snapshot.json', 'rules.snapshot.json', 'collectors.snapshot.json', 'collector-state.json', 'cloud-export.jsonl', 'cloud-export.checkpoint.json', 'alert-webhook.jsonl', 'alert-webhook.checkpoint.json', 'alert-webhook.state.json'];

class BackupManager {
  constructor({ dataDirectory, protector, files = DEFAULT_FILES } = {}) {
    if (!path.isAbsolute(dataDirectory)) throw new Error('Backup dataDirectory must be absolute');
    if (!protector) throw new Error('Backups require authenticated encryption');
    this.dataDirectory = path.resolve(dataDirectory);
    this.protector = protector;
    this.files = [...new Set(files)].sort();
    if (this.files.some((name) => path.basename(name) !== name)) throw new Error('Backup filenames must not contain paths');
  }

  async create(outputFile, createdAt = new Date().toISOString()) {
    await assertSafePath(this.dataDirectory, { allowMissing: false, type: 'directory', privateDirectory: true });
    const entries = [];
    for (const name of this.files) {
      try {
        await assertSafePath(path.join(this.dataDirectory, name), { allowMissing: false });
        const content = await fs.readFile(path.join(this.dataDirectory, name));
        entries.push({ name, bytes: content.length, digest: crypto.createHash('sha256').update(content).digest('hex'), content: content.toString('base64') });
      } catch (error) { if (error.code !== 'ENOENT') throw error; }
    }
    const bundle = { schemaVersion: 1, createdAt, entries };
    const encrypted = this.protector.sealString(canonicalJson(bundle), 'backup:lookout-v1');
    const target = path.resolve(outputFile);
    await fs.mkdir(path.dirname(target), { recursive: true, mode: 0o700 });
    if (await assertSafePath(target)) throw new Error('Backup output already exists');
    const temporary = `${target}.${process.pid}.${crypto.randomUUID()}.tmp`;
    try {
      await writeFileDurably(temporary, `${canonicalJson(encrypted)}\n`, { mode: 0o600, flag: 'wx' });
      await fs.link(temporary, target);
      await fs.rm(temporary);
      await syncDirectory(path.dirname(target));
    } catch (error) { await fs.rm(temporary, { force: true }); throw error; }
    return { file: target, entries: entries.length, createdAt };
  }

  async inspect(backupFile) {
    const resolved = path.resolve(backupFile);
    const stat = await assertSafePath(resolved, { allowMissing: false });
    if (stat.size > 512 * 1024 * 1024) throw new Error('Backup exceeds the maximum supported size');
    const encrypted = JSON.parse(await fs.readFile(resolved, 'utf8'));
    const bundle = JSON.parse(this.protector.openString(encrypted, 'backup:lookout-v1'));
    if (bundle.schemaVersion !== 1 || !Array.isArray(bundle.entries)) throw new Error('Unsupported backup bundle');
    const allowed = new Set(this.files);
    const seen = new Set();
    for (const entry of bundle.entries) {
      if (!allowed.has(entry.name) || path.basename(entry.name) !== entry.name || seen.has(entry.name)) throw new Error('Backup contains an invalid or duplicate filename');
      seen.add(entry.name);
      if (!Number.isSafeInteger(entry.bytes) || entry.bytes < 0 || entry.bytes > 512 * 1024 * 1024 || typeof entry.content !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(entry.content)) throw new Error(`Backup entry encoding is invalid: ${entry.name}`);
      const content = Buffer.from(entry.content, 'base64');
      if (content.toString('base64') !== entry.content) throw new Error(`Backup entry encoding is invalid: ${entry.name}`);
      if (content.length !== entry.bytes || crypto.createHash('sha256').update(content).digest('hex') !== entry.digest) throw new Error(`Backup entry integrity check failed: ${entry.name}`);
    }
    return bundle;
  }

  async restoreToNewDirectory(backupFile, targetDirectory) {
    const target = path.resolve(targetDirectory);
    try { await fs.access(target); throw new Error('Restore target already exists'); }
    catch (error) { if (error.message === 'Restore target already exists') throw error; if (error.code !== 'ENOENT') throw error; }
    const bundle = await this.inspect(backupFile);
    const staging = `${target}.${process.pid}.${crypto.randomUUID()}.restore`;
    await fs.mkdir(staging, { recursive: false, mode: 0o700 });
    try {
      for (const entry of bundle.entries) await fs.writeFile(path.join(staging, entry.name), Buffer.from(entry.content, 'base64'), { mode: 0o600, flag: 'wx' });
      await fs.rename(staging, target);
    } catch (error) { await fs.rm(staging, { recursive: true, force: true }); throw error; }
    return { directory: target, entries: bundle.entries.length, createdAt: bundle.createdAt };
  }
}

module.exports = { DEFAULT_FILES, BackupManager };

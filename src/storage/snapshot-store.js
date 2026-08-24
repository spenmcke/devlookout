'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');
const { canonicalJson } = require('../core/canonical');
const { assertSafePath, syncDirectory, writeFileDurably } = require('./safe-files');

class SnapshotStore {
  constructor(directory, filename = 'graph.snapshot.json', { protector = null, requireEncryption = false } = {}) {
    if (!path.isAbsolute(directory)) throw new Error('Snapshot directory must be an absolute path');
    if (!/^[a-z0-9][a-z0-9._-]*\.json$/i.test(filename)) throw new Error('Snapshot filename is invalid');
    this.directory = path.resolve(directory);
    this.file = path.join(this.directory, filename);
    this.protector = protector;
    this.requireEncryption = requireEncryption;
  }

  async save(snapshot) {
    await fs.mkdir(this.directory, { recursive: true, mode: 0o700 });
    await assertSafePath(this.directory, { allowMissing: false, type: 'directory', privateDirectory: true });
    await assertSafePath(this.file);
    const temporary = path.join(this.directory, `.graph.${process.pid}.${crypto.randomUUID()}.tmp`);
    const document = { ...snapshot, integrity: { algorithm: 'sha256', digest: crypto.createHash('sha256').update(canonicalJson(snapshot)).digest('hex') } };
    const serialized = `${canonicalJson(document)}\n`;
    const output = this.protector ? `${canonicalJson(this.protector.sealString(serialized, `snapshot:${path.basename(this.file)}`))}\n` : serialized;
    try {
      await writeFileDurably(temporary, output, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
      await fs.rename(temporary, this.file);
      await syncDirectory(this.directory);
    } catch (error) {
      await fs.rm(temporary, { force: true });
      throw error;
    }
  }

  async load() {
    let document;
    try {
      await assertSafePath(this.file, { allowMissing: false });
      const outer = JSON.parse(await fs.readFile(this.file, 'utf8'));
      if (this.protector && this.protector.constructor.isEnvelope(outer)) document = JSON.parse(this.protector.openString(outer, `snapshot:${path.basename(this.file)}`));
      else {
        if (this.requireEncryption) throw new Error(`Encrypted snapshot required: ${path.basename(this.file)}`);
        document = outer;
      }
    }
    catch (error) { if (error.code === 'ENOENT') return null; throw error; }
    const { integrity, ...snapshot } = document;
    const digest = crypto.createHash('sha256').update(canonicalJson(snapshot)).digest('hex');
    if (!integrity || integrity.algorithm !== 'sha256' || integrity.digest !== digest) throw new Error('Graph snapshot integrity check failed');
    return snapshot;
  }
}

module.exports = { SnapshotStore };

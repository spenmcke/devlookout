'use strict';

const fs = require('node:fs/promises');
const fsSync = require('node:fs');
const readline = require('node:readline');
const path = require('node:path');
const crypto = require('node:crypto');
const zlib = require('node:zlib');
const { canonicalJson } = require('../core/canonical');
const { validateEvent } = require('../events/schema');
const { assertSafePath, syncDirectory, writeFileDurably } = require('./safe-files');

const GENESIS = '0'.repeat(64);
const MAXIMUM_RECENT_IDS = 50000;

function digestRecord(previousDigest, sequence, event) {
  return crypto.createHash('sha256').update(previousDigest).update('\0').update(String(sequence)).update('\0').update(canonicalJson(event)).digest('hex');
}

function parseJournalLine(line, lineNumber, protector = null, requireEncryption = false, contextPrefix = 'events') {
    try {
      const outer = JSON.parse(line);
      let encoded;
      if (protector && protector.constructor.isEnvelope(outer)) encoded = JSON.parse(protector.openString(outer, `${contextPrefix}-record:${lineNumber}`));
      else {
        if (requireEncryption) throw new Error(`Encrypted event record required at line ${lineNumber}`);
        encoded = outer;
      }
      if (encoded?.format !== 'gzip-base64-v1' || typeof encoded.data !== 'string') throw new Error(`Compressed event record required at line ${lineNumber}`);
      return JSON.parse(zlib.gunzipSync(Buffer.from(encoded.data, 'base64')).toString('utf8'));
    }
    catch (error) {
      if (!(error instanceof SyntaxError)) throw error;
      throw new Error(`Invalid event journal JSON at line ${lineNumber}`);
    }
}

function parseJournal(text, protector = null, requireEncryption = false, contextPrefix = 'events') {
  if (!text.trim()) return [];
  return text.trimEnd().split('\n').map((line, index) => parseJournalLine(line, index + 1, protector, requireEncryption, contextPrefix));
}

function encodeJournalRecord(record, sequence, protector, contextPrefix = 'events') {
  const encoded = canonicalJson({ format: 'gzip-base64-v1', data: zlib.gzipSync(Buffer.from(canonicalJson(record)), { level: zlib.constants.Z_BEST_SPEED, memLevel: 4, windowBits: 14 }).toString('base64') });
  return protector ? canonicalJson(protector.sealString(encoded, `${contextPrefix}-record:${sequence}`)) : encoded;
}

function verifyRecords(records) {
  let previousDigest = GENESIS;
  let sequence = 0;
  const ids = new Set();
  for (const record of records) {
    sequence += 1;
    if (record.sequence !== sequence) throw new Error(`Event journal sequence mismatch at ${sequence}`);
    if (record.previousDigest !== previousDigest) throw new Error(`Event journal chain mismatch at ${sequence}`);
    validateEvent(record.event);
    const expected = digestRecord(previousDigest, sequence, record.event);
    if (record.digest !== expected) throw new Error(`Event journal integrity check failed at ${sequence}`);
    if (ids.has(record.event.id)) throw new Error(`Duplicate event ID in journal: ${record.event.id}`);
    ids.add(record.event.id);
    while (ids.size > MAXIMUM_RECENT_IDS) ids.delete(ids.values().next().value);
    previousDigest = expected;
  }
  return { previousDigest, sequence, ids };
}

class EventStore {
  #ready = null;
  #tail = { previousDigest: GENESIS, sequence: 0, ids: new Set(), oldestTime: null, newestTime: null };
  #evicted = 0;
  #queue = Promise.resolve();

  constructor(directory, { protector = null, requireEncryption = false, filename = 'events.jsonl', maximumBytes = null } = {}) {
    if (!path.isAbsolute(directory)) throw new Error('Event directory must be an absolute path');
    if (!/^[a-z0-9][a-z0-9._-]*\.jsonl$/i.test(filename)) throw new Error('Event journal filename is invalid');
    this.directory = path.resolve(directory);
    this.file = path.join(this.directory, filename);
    this.contextPrefix = path.basename(filename, '.jsonl');
    this.protector = protector;
    this.requireEncryption = requireEncryption;
    this.maximumBytes = maximumBytes;
  }

  async initialize() {
    if (!this.#ready) this.#ready = this.#initialize();
    return this.#ready;
  }

  async #initialize() {
    await fs.mkdir(this.directory, { recursive: true, mode: 0o700 });
    await assertSafePath(this.directory, { allowMissing: false, type: 'directory', privateDirectory: true });
    try {
      await assertSafePath(this.file, { allowMissing: false });
      let previousDigest = GENESIS;
      let sequence = 0;
      const ids = new Set();
      let oldestTime = null;
      let newestTime = null;
      for await (const record of this.#records()) {
        sequence += 1;
        if (record.sequence !== sequence || record.previousDigest !== previousDigest) throw new Error(`Event journal chain mismatch at ${sequence}`);
        validateEvent(record.event);
        const expected = digestRecord(previousDigest, sequence, record.event);
        if (record.digest !== expected) throw new Error(`Event journal integrity check failed at ${sequence}`);
        if (ids.has(record.event.id)) throw new Error(`Duplicate recent event ID in journal: ${record.event.id}`);
        ids.add(record.event.id);
        while (ids.size > MAXIMUM_RECENT_IDS) ids.delete(ids.values().next().value);
        previousDigest = expected;
        if (!oldestTime || record.event.time < oldestTime) oldestTime = record.event.time;
        if (!newestTime || record.event.time > newestTime) newestTime = record.event.time;
      }
      this.#tail = { previousDigest, sequence, ids, oldestTime, newestTime };
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
      await writeFileDurably(this.file, '', { mode: 0o600, flag: 'wx' });
      await syncDirectory(this.directory);
    }
  }

  async *#records({ afterLine = 0 } = {}) {
    const input = fsSync.createReadStream(this.file, { encoding: 'utf8' });
    const lines = readline.createInterface({ input, crlfDelay: Infinity });
    let lineNumber = 0;
    try {
      for await (const line of lines) {
        lineNumber += 1;
        if (!line || lineNumber <= afterLine) continue;
        yield parseJournalLine(line, lineNumber, this.protector, this.requireEncryption, this.contextPrefix);
      }
    } finally { lines.close(); input.destroy(); }
  }

  async append(events) {
    const work = async () => {
      await this.initialize();
      const accepted = [];
      const lines = [];
      let { previousDigest, sequence } = this.#tail;
      const newIds = new Set();
      for (const event of events) {
        validateEvent(event);
        if (this.#tail.ids.has(event.id) || newIds.has(event.id)) continue;
        sequence += 1;
        const digest = digestRecord(previousDigest, sequence, event);
        lines.push(encodeJournalRecord({ sequence, previousDigest, digest, event }, sequence, this.protector, this.contextPrefix));
        previousDigest = digest;
        newIds.add(event.id);
        accepted.push(event.id);
      }
      if (lines.length) {
        await assertSafePath(this.file, { allowMissing: false });
        const handle = await fs.open(this.file, 'a');
        try { await handle.writeFile(`${lines.join('\n')}\n`, { encoding: 'utf8' }); await handle.sync(); }
        finally { await handle.close(); }
      }
      for (const id of newIds) this.#tail.ids.add(id);
      while (this.#tail.ids.size > MAXIMUM_RECENT_IDS) this.#tail.ids.delete(this.#tail.ids.values().next().value);
      this.#tail.previousDigest = previousDigest;
      this.#tail.sequence = sequence;
      for (const event of events) {
        if (!newIds.has(event.id)) continue;
        if (!this.#tail.oldestTime || event.time < this.#tail.oldestTime) this.#tail.oldestTime = event.time;
        if (!this.#tail.newestTime || event.time > this.#tail.newestTime) this.#tail.newestTime = event.time;
      }
      return accepted;
    };
    const result = this.#queue.then(work, work);
    this.#queue = result.then(() => undefined, () => undefined);
    return result;
  }

  async query({ since, until, category, entityKey, source, keyword, excludeClasses = [], limit = 1000 } = {}) {
      await this.initialize();
      await assertSafePath(this.file, { allowMissing: false });
    const sinceTime = since ? Date.parse(since) : -Infinity;
    const untilTime = until ? Date.parse(until) : Infinity;
    const selected = [];
    for await (const record of this.#records()) {
      const event = record.event;
      const time = Date.parse(event.time);
      if (time >= sinceTime && time <= untilTime
        && (!category || event.category === category)
        && (!entityKey || event.entityKeys.includes(entityKey))
        && (!source || event.source?.adapter === source)
        && !excludeClasses.includes(event.class)
        && (!keyword || JSON.stringify(event).toLowerCase().includes(keyword.toLowerCase()))) selected.push(event);
      selected.sort((a, b) => b.time.localeCompare(a.time) || a.id.localeCompare(b.id));
      if (selected.length > Math.max(0, Math.min(limit, 10000))) selected.length = Math.max(0, Math.min(limit, 10000));
    }
    return selected;
  }

  async recordsAfter(sequence = 0, { limit = 10000 } = {}) {
    await this.initialize();
    if (!Number.isSafeInteger(sequence) || sequence < 0) throw new Error('Event sequence must be a non-negative safe integer');
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 10000) throw new Error('Event record limit must be between 1 and 10000');
    const selected = [];
    for await (const record of this.#records({ afterLine: sequence })) if (selected.length < limit) selected.push({ sequence: record.sequence, event: structuredClone(record.event) });
    return selected;
  }

  async recordsExcluding(eventIds, { limit = 10000 } = {}) {
    await this.initialize();
    const excluded = eventIds instanceof Set ? eventIds : new Set(eventIds || []);
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 10000) throw new Error('Event record limit must be between 1 and 10000');
    const selected = [];
    for await (const record of this.#records()) if (!excluded.has(record.event.id) && selected.length < limit) selected.push({ sequence: record.sequence, event: structuredClone(record.event) });
    return selected;
  }

  async eventIds() {
    await this.initialize();
    return [...this.#tail.ids].sort();
  }

  async byIds(eventIds, { limit = 10000 } = {}) {
    await this.initialize();
    const ids = eventIds instanceof Set ? eventIds : new Set(eventIds || []);
    if ([...ids].some((id) => typeof id !== 'string')) throw new Error('Event IDs must be strings');
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 10000) throw new Error('Event ID query limit must be between 1 and 10000');
    const selected = [];
    for await (const record of this.#records()) if (ids.has(record.event.id) && selected.length < limit) selected.push(record.event);
    return selected.sort((left, right) => left.time.localeCompare(right.time) || left.id.localeCompare(right.id));
  }

  async metadata() {
    await this.initialize();
    return { sequence: this.#tail.sequence, events: this.#tail.sequence, recentIds: this.#tail.ids.size, digest: this.#tail.previousDigest, bytes: (await fs.stat(this.file)).size, maximumBytes: this.maximumBytes, oldestTime: this.#tail.oldestTime, newestTime: this.#tail.newestTime, retentionSeconds: this.#tail.oldestTime && this.#tail.newestTime ? Math.max(0, Math.floor((Date.parse(this.#tail.newestTime) - Date.parse(this.#tail.oldestTime)) / 1000)) : 0, evictedSinceStart: this.#evicted };
  }

  setMaximumBytes(maximumBytes) {
    if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 1024 * 1024) throw new Error('Event storage byte limit must be at least 1 MiB');
    this.maximumBytes = maximumBytes;
  }

  async #compactUnlocked({ retainAfter, maximumBytes = this.maximumBytes }) {
      await assertSafePath(this.file, { allowMissing: false });
      const cutoff = Date.parse(retainAfter);
      if (Number.isNaN(cutoff)) throw new Error('retainAfter must be an ISO-compatible timestamp');
      if (maximumBytes) this.maximumBytes = maximumBytes;
      const groups = new Map();
      let originalCount = 0;
      let estimatedBytes = 0;
      for await (const record of this.#records()) {
        originalCount += 1;
        if (Date.parse(record.event.time) < cutoff) continue;
        const bytes = Buffer.byteLength(encodeJournalRecord(record, record.sequence, this.protector, this.contextPrefix), 'utf8') + 1;
        const key = String(record.event.source?.instance || 'unknown');
        const group = groups.get(key) || { items: [], index: 0, bytes: 0 };
        group.items.push({ sequence: record.sequence, bytes });
        group.bytes += bytes;
        estimatedBytes += bytes;
        groups.set(key, group);
      }
      const targetBytes = maximumBytes ? Math.floor(maximumBytes * 0.98) : Infinity;
      while (estimatedBytes > targetBytes) {
        const largest = [...groups.values()].filter((group) => group.index < group.items.length).sort((left, right) => right.bytes - left.bytes)[0];
        if (!largest) break;
        const removed = largest.items[largest.index++];
        largest.bytes -= removed.bytes;
        estimatedBytes -= removed.bytes;
      }
      const retainedSequences = new Set([...groups.values()].flatMap((group) => group.items.slice(group.index).map((item) => item.sequence)));
      const temporary = path.join(this.directory, `.events.${process.pid}.${crypto.randomUUID()}.tmp`);
      let previousDigest = GENESIS;
      let sequence = 0;
      const recentIds = new Set();
      let oldestTime = null;
      let newestTime = null;
      try {
        const handle = await fs.open(temporary, 'wx', 0o600);
        try {
          for await (const record of this.#records()) {
            if (!retainedSequences.has(record.sequence)) continue;
            sequence += 1;
            const digest = digestRecord(previousDigest, sequence, record.event);
            const line = encodeJournalRecord({ sequence, previousDigest, digest, event: record.event }, sequence, this.protector, this.contextPrefix);
            await handle.writeFile(`${line}\n`, { encoding: 'utf8' });
            previousDigest = digest;
            recentIds.add(record.event.id);
            while (recentIds.size > MAXIMUM_RECENT_IDS) recentIds.delete(recentIds.values().next().value);
            if (!oldestTime || record.event.time < oldestTime) oldestTime = record.event.time;
            if (!newestTime || record.event.time > newestTime) newestTime = record.event.time;
          }
          await handle.sync();
        } finally { await handle.close(); }
        await fs.rename(temporary, this.file);
        await syncDirectory(this.directory);
      } catch (error) {
        await fs.rm(temporary, { force: true });
        throw error;
      }
      const removed = originalCount - sequence;
      this.#evicted += removed;
      this.#tail = { previousDigest, sequence, ids: recentIds, oldestTime, newestTime };
      return { retained: sequence, removed };
  }

  async compact({ retainAfter, maximumBytes = this.maximumBytes }) {
    const work = async () => {
      await this.initialize();
      return this.#compactUnlocked({ retainAfter, maximumBytes });
    };
    const result = this.#queue.then(work, work);
    this.#queue = result.then(() => undefined, () => undefined);
    return result;
  }
}

module.exports = { GENESIS, EventStore, digestRecord, parseJournal, encodeJournalRecord, verifyRecords };

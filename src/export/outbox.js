'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');
const { canonicalJson } = require('../core/canonical');
const { SnapshotStore } = require('../storage/snapshot-store');
const { assertSafePath, syncDirectory, writeFileDurably } = require('../storage/safe-files');

const GENESIS = '0'.repeat(64);

function recordDigest(previousDigest, sequence, event) {
  return crypto.createHash('sha256')
    .update(previousDigest).update('\0').update(String(sequence)).update('\0').update(canonicalJson(event))
    .digest('hex');
}

function encodeRecord(record, protector, contextPrefix) {
  const serialized = canonicalJson(record);
  return protector
    // Keep only the monotonically increasing sequence outside the envelope. It
    // is not sensitive and lets startup authenticate compacted journals without
    // trusting a separately-written checkpoint.
    ? canonicalJson({ sequence: record.sequence, protected: protector.sealString(serialized, `${contextPrefix}-record:${record.sequence}`) })
    : serialized;
}

function decodeRecords(text, { protector, requireEncryption, contextPrefix }) {
  if (!text.trim()) return [];
  return text.trimEnd().split('\n').map((line, index) => {
    let outer;
    try { outer = JSON.parse(line); }
    catch { throw new Error(`Invalid export outbox JSON at line ${index + 1}`); }
    if (protector && Number.isSafeInteger(outer.sequence) && protector.constructor.isEnvelope(outer.protected)) return outer;
    if (requireEncryption) throw new Error(`Encrypted export record required at line ${index + 1}`);
    return outer;
  });
}

function openEncryptedRecords(records, { protector, contextPrefix }) {
  return records.map((record) => {
    if (!protector?.constructor.isEnvelope(record.protected)) return record;
    const sequence = record.sequence;
    try {
      const opened = JSON.parse(protector.openString(record.protected, `${contextPrefix}-record:${sequence}`));
      if (opened.sequence !== sequence) throw new Error('outer and protected sequence differ');
      return opened;
    }
    catch (error) { throw new Error(`Unable to open export outbox record ${sequence}: ${error.message}`); }
  });
}

function verifyRecords(records, firstSequence = 1) {
  let previousDigest = GENESIS;
  let sequence = firstSequence - 1;
  const ids = new Set();
  for (const record of records) {
    sequence += 1;
    if (record.sequence !== sequence) throw new Error(`Export outbox sequence mismatch at ${sequence}`);
    if (record.previousDigest !== previousDigest) throw new Error(`Export outbox chain mismatch at ${sequence}`);
    if (!record.event || typeof record.event !== 'object' || Array.isArray(record.event)) throw new Error(`Invalid export event at sequence ${sequence}`);
    if (typeof record.event.id !== 'string' || !record.event.id) throw new Error(`Export event ID is required at sequence ${sequence}`);
    const expected = recordDigest(previousDigest, sequence, record.event);
    if (record.digest !== expected) throw new Error(`Export outbox integrity check failed at ${sequence}`);
    if (ids.has(record.event.id)) throw new Error(`Duplicate event ID in export outbox: ${record.event.id}`);
    ids.add(record.event.id);
    previousDigest = expected;
  }
  return { previousDigest, sequence, ids };
}

function defaultCheckpoint() {
  return { schemaVersion: 1, acknowledgedThrough: 0, compactedThrough: 0, lastBatchId: null, retry: null, blocked: null };
}

function validateCheckpoint(value) {
  if (!value) return defaultCheckpoint();
  const normalized = { ...defaultCheckpoint(), ...value };
  if (normalized.schemaVersion !== 1 || !Number.isSafeInteger(normalized.acknowledgedThrough) || normalized.acknowledgedThrough < 0 ||
      !Number.isSafeInteger(normalized.compactedThrough) || normalized.compactedThrough < 0 ||
      normalized.compactedThrough > normalized.acknowledgedThrough) throw new Error('Invalid export checkpoint');
  if (normalized.lastBatchId !== null && (typeof normalized.lastBatchId !== 'string' || !normalized.lastBatchId)) throw new Error('Invalid export checkpoint batch ID');
  if (normalized.retry !== null) {
    if (!normalized.retry || !Number.isSafeInteger(normalized.retry.attempts) || normalized.retry.attempts < 1 ||
        !Number.isSafeInteger(normalized.retry.throughSequence) || normalized.retry.throughSequence <= normalized.acknowledgedThrough ||
        Number.isNaN(Date.parse(normalized.retry.nextAttemptAt)) || !/^[a-zA-Z0-9_-]{1,64}$/.test(normalized.retry.errorCode || '')) throw new Error('Invalid export retry checkpoint');
  }
  if (normalized.blocked !== null) {
    if (!normalized.blocked || !Number.isSafeInteger(normalized.blocked.attempts) || normalized.blocked.attempts < 1 ||
        !Number.isSafeInteger(normalized.blocked.throughSequence) || normalized.blocked.throughSequence <= normalized.acknowledgedThrough ||
        Number.isNaN(Date.parse(normalized.blocked.blockedAt)) || !/^[a-zA-Z0-9_-]{1,64}$/.test(normalized.blocked.errorCode || '')) throw new Error('Invalid blocked export checkpoint');
  }
  if (normalized.retry && normalized.blocked) throw new Error('Export checkpoint cannot be retrying and blocked');
  return structuredClone(normalized);
}

class DurableExportOutbox {
  #ready = null;
  #queue = Promise.resolve();
  #records = [];
  #checkpoint = defaultCheckpoint();
  #tail = { previousDigest: GENESIS, sequence: 0, ids: new Set() };

  constructor(directory, { protector = null, requireEncryption = false, maxPending = 50000, filename = 'cloud-export.jsonl' } = {}) {
    if (!path.isAbsolute(directory)) throw new Error('Export outbox directory must be an absolute path');
    if (!/^[a-z0-9][a-z0-9._-]*\.jsonl$/i.test(filename)) throw new Error('Export outbox filename is invalid');
    if (!Number.isSafeInteger(maxPending) || maxPending < 1) throw new Error('maxPending must be a positive integer');
    this.directory = path.resolve(directory);
    this.file = path.join(this.directory, filename);
    this.contextPrefix = path.basename(filename, '.jsonl');
    this.checkpointStore = new SnapshotStore(this.directory, `${this.contextPrefix}.checkpoint.json`, { protector, requireEncryption });
    this.protector = protector;
    this.requireEncryption = requireEncryption;
    this.maxPending = maxPending;
  }

  async initialize() {
    if (!this.#ready) this.#ready = this.#initialize();
    return this.#ready;
  }

  async #initialize() {
    await fs.mkdir(this.directory, { recursive: true, mode: 0o700 });
    await assertSafePath(this.directory, { allowMissing: false, type: 'directory', privateDirectory: true });
    this.#checkpoint = validateCheckpoint(await this.checkpointStore.load());
    let text;
    try {
      await assertSafePath(this.file, { allowMissing: false });
      text = await fs.readFile(this.file, 'utf8');
    }
    catch (error) {
      if (error.code !== 'ENOENT') throw error;
      await writeFileDurably(this.file, '', { mode: 0o600, flag: 'wx' });
      await syncDirectory(this.directory);
      text = '';
    }
    const decoded = decodeRecords(text, this);
    this.#records = openEncryptedRecords(decoded, this);
    const firstSequence = this.#records[0]?.sequence ?? this.#checkpoint.acknowledgedThrough + 1;
    this.#tail = verifyRecords(this.#records, firstSequence);
    if (!this.#records.length) this.#tail.sequence = this.#checkpoint.acknowledgedThrough;
    if (firstSequence > this.#checkpoint.acknowledgedThrough + 1) throw new Error('Export outbox has a gap after its checkpoint');
    if (this.#checkpoint.acknowledgedThrough > this.#tail.sequence) throw new Error('Export checkpoint is ahead of the outbox journal');
  }

  async enqueue(events) {
    if (!Array.isArray(events)) throw new Error('Export events must be an array');
    return this.#serialized(async () => {
      const pendingCount = this.#tail.sequence - this.#checkpoint.acknowledgedThrough;
      const newEvents = [];
      const batchIds = new Set();
      for (const event of events) {
        if (!event || typeof event !== 'object' || Array.isArray(event) || typeof event.id !== 'string' || !event.id) throw new Error('Export event must have a non-empty ID');
        if (this.#tail.ids.has(event.id) || batchIds.has(event.id)) continue;
        batchIds.add(event.id);
        newEvents.push(structuredClone(event));
      }
      if (pendingCount + newEvents.length > this.maxPending) throw new Error(`Export outbox capacity exceeded (${this.maxPending})`);
      let { previousDigest, sequence } = this.#tail;
      const records = [];
      for (const event of newEvents) {
        sequence += 1;
        const digest = recordDigest(previousDigest, sequence, event);
        records.push({ sequence, previousDigest, digest, event });
        previousDigest = digest;
      }
      if (records.length) {
        await assertSafePath(this.file, { allowMissing: false });
        const handle = await fs.open(this.file, 'a');
        try {
          await handle.writeFile(`${records.map((record) => encodeRecord(record, this.protector, this.contextPrefix)).join('\n')}\n`, { encoding: 'utf8' });
          await handle.sync();
        } finally { await handle.close(); }
        this.#records.push(...records);
        for (const event of newEvents) this.#tail.ids.add(event.id);
        this.#tail = { previousDigest, sequence, ids: this.#tail.ids };
      }
      return { enqueued: records.length, duplicates: events.length - records.length, pending: this.#tail.sequence - this.#checkpoint.acknowledgedThrough };
    });
  }

  async pending({ limit = 100 } = {}) {
    await this.initialize();
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1000) throw new Error('Export batch limit must be between 1 and 1000');
    return this.#records.filter((record) => record.sequence > this.#checkpoint.acknowledgedThrough).slice(0, limit).map((record) => structuredClone(record));
  }

  async acknowledge({ throughSequence, batchId }) {
    return this.#serialized(async () => {
      if (!Number.isSafeInteger(throughSequence) || throughSequence <= this.#checkpoint.acknowledgedThrough || throughSequence > this.#tail.sequence) throw new Error('Invalid export acknowledgement sequence');
      if (typeof batchId !== 'string' || !batchId) throw new Error('Export acknowledgement requires a batch ID');
      this.#checkpoint = { ...this.#checkpoint, acknowledgedThrough: throughSequence, lastBatchId: batchId, retry: null, blocked: null };
      await this.checkpointStore.save(this.#checkpoint);
      return this.stats();
    });
  }

  async recordFailure({ throughSequence, attempts, nextAttemptAt = null, errorCode, retryable = true, failedAt = new Date().toISOString() }) {
    return this.#serialized(async () => {
      if (!/^[a-zA-Z0-9_-]{1,64}$/.test(errorCode || '')) throw new Error('Export retry error code is invalid');
      if (throughSequence > this.#tail.sequence) throw new Error('Export retry sequence is ahead of the journal');
      if (retryable) {
        const retry = { throughSequence, attempts, nextAttemptAt, errorCode };
        validateCheckpoint({ ...this.#checkpoint, retry, blocked: null });
        this.#checkpoint = { ...this.#checkpoint, retry, blocked: null };
      } else {
        const blocked = { throughSequence, attempts, blockedAt: failedAt, errorCode };
        validateCheckpoint({ ...this.#checkpoint, retry: null, blocked });
        this.#checkpoint = { ...this.#checkpoint, retry: null, blocked };
      }
      await this.checkpointStore.save(this.#checkpoint);
      return this.#checkpoint.retry ? structuredClone(this.#checkpoint.retry) : structuredClone(this.#checkpoint.blocked);
    });
  }

  async resumeBlocked({ includeRetry = false, errorCodes = null } = {}) {
    return this.#serialized(async () => {
      if (errorCodes !== null && (!Array.isArray(errorCodes) || errorCodes.some((code) => !/^[a-zA-Z0-9_-]{1,64}$/.test(code || '')))) throw new Error('Export resume error codes are invalid');
      const failure = this.#checkpoint.blocked || (includeRetry ? this.#checkpoint.retry : null);
      if (!failure || (errorCodes && !errorCodes.includes(failure.errorCode))) return false;
      this.#checkpoint = { ...this.#checkpoint, blocked: null, retry: null };
      await this.checkpointStore.save(this.#checkpoint);
      return true;
    });
  }

  async compact() {
    return this.#serialized(async () => {
      const priorCount = this.#records.length;
      const retained = this.#records.filter((record) => record.sequence > this.#checkpoint.acknowledgedThrough);
      let previousDigest = GENESIS;
      const rewritten = retained.map(({ sequence, event }) => {
        const digest = recordDigest(previousDigest, sequence, event);
        const record = { sequence, previousDigest, digest, event };
        previousDigest = digest;
        return record;
      });
      const temporary = path.join(this.directory, `.export.${process.pid}.${crypto.randomUUID()}.tmp`);
      const output = rewritten.map((record) => encodeRecord(record, this.protector, this.contextPrefix));
      try {
        await assertSafePath(this.file, { allowMissing: false });
        await writeFileDurably(temporary, output.length ? `${output.join('\n')}\n` : '', { encoding: 'utf8', mode: 0o600, flag: 'wx' });
        const checkpoint = { ...this.#checkpoint, compactedThrough: this.#checkpoint.acknowledgedThrough };
        await this.checkpointStore.save(checkpoint);
        await fs.rename(temporary, this.file);
        await syncDirectory(this.directory);
        this.#checkpoint = checkpoint;
      } catch (error) {
        await fs.rm(temporary, { force: true });
        throw error;
      }
      this.#records = rewritten;
      this.#tail = { previousDigest, sequence: rewritten.at(-1)?.sequence ?? this.#checkpoint.compactedThrough, ids: new Set(rewritten.map((record) => record.event.id)) };
      return { removed: priorCount - rewritten.length, retained: rewritten.length };
    });
  }

  stats() {
    return {
      pending: this.#tail.sequence - this.#checkpoint.acknowledgedThrough,
      acknowledgedThrough: this.#checkpoint.acknowledgedThrough,
      compactedThrough: this.#checkpoint.compactedThrough,
      lastBatchId: this.#checkpoint.lastBatchId,
      retry: this.#checkpoint.retry ? structuredClone(this.#checkpoint.retry) : null,
      blocked: this.#checkpoint.blocked ? structuredClone(this.#checkpoint.blocked) : null
    };
  }

  async #serialized(work) {
    const execute = async () => { await this.initialize(); return work(); };
    const result = this.#queue.then(execute, execute);
    this.#queue = result.then(() => undefined, () => undefined);
    return result;
  }
}

module.exports = { GENESIS, DurableExportOutbox, recordDigest, verifyRecords };

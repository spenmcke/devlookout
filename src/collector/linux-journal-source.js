'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');
const { linuxJournalNormalizer } = require('../normalizers/linux-journal');
const { createEvent } = require('../events/schema');

const MAX_LINE_BYTES = 1024 * 1024;

function validCursor(cursor) {
  return typeof cursor === 'string' && Boolean(cursor) && Buffer.byteLength(cursor, 'utf8') <= 4096 && !/[\r\n]/.test(cursor);
}

function cursorFromDamagedJson(line) {
  const match = /(?<!\\)"__CURSOR"\s*:\s*"((?:[^"\\]|\\.)*)"/.exec(line);
  if (!match) return null;
  try {
    const cursor = JSON.parse(`"${match[1]}"`);
    return validCursor(cursor) ? cursor : null;
  } catch { return null; }
}

class LinuxJournalSource {
  constructor({ cursorPath = null, journalctlPath = '/usr/bin/journalctl', spawnImpl = spawn, fsImpl = fs, maxRecords = 1000, maxOutputBytes = 8 * 1024 * 1024, normalizer = linuxJournalNormalizer(), collectorId = null, entityKey = null } = {}) {
    if (cursorPath !== null && !path.isAbsolute(cursorPath)) throw new Error('Linux journal cursor path must be absolute');
    if (!path.isAbsolute(journalctlPath)) throw new Error('journalctl path must be absolute');
    if (!Number.isSafeInteger(maxRecords) || maxRecords < 1 || maxRecords > 10000) throw new Error('maxRecords must be between 1 and 10000');
    this.cursorPath = cursorPath;
    this.journalctlPath = journalctlPath;
    this.spawnImpl = spawnImpl;
    this.fs = fsImpl;
    this.maxRecords = maxRecords;
    this.maxOutputBytes = maxOutputBytes;
    if (!normalizer || typeof normalizer.normalize !== 'function') throw new Error('Linux journal source requires a normalizer');
    this.id = 'linux-journal';
    this.normalizer = normalizer;
    this.entityKey = entityKey || (collectorId ? `collector-endpoint:${collectorId}` : null);
    this.status = { journal_stream: 'unknown', authentication: 'unknown', privilege_use: 'unknown', account_change: 'unknown', process_execution: 'unknown', service_state: 'unknown', configuration_change: 'unknown', log_clearing: 'unknown', linux_audit: 'unknown' };
    this.lastError = null;
    this.auditObserved = false;
    this.stagedCursors = new Set();
  }

  readCursor() {
    if (!this.cursorPath) return null;
    try {
      const cursor = this.fs.readFileSync(this.cursorPath, 'utf8').trim();
      return cursor && Buffer.byteLength(cursor, 'utf8') <= 4096 ? cursor : null;
    } catch (error) {
      if (error.code === 'ENOENT') return null;
      throw error;
    }
  }

  writeCursor(cursor) {
    if (!this.cursorPath) throw new Error('Cursor persistence is owned by the continuous collector');
    if (typeof cursor !== 'string' || !cursor || Buffer.byteLength(cursor, 'utf8') > 4096 || /[\r\n]/.test(cursor)) throw new Error('Invalid journal cursor');
    const directory = path.dirname(this.cursorPath);
    this.fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
    const temporary = `${this.cursorPath}.${process.pid}.tmp`;
    this.fs.writeFileSync(temporary, `${cursor}\n`, { encoding: 'utf8', mode: 0o600, flag: 'w' });
    this.fs.renameSync(temporary, this.cursorPath);
  }

  commit(cursor) {
    if (!this.stagedCursors.has(cursor)) throw new Error('Journal cursor was not staged by this source');
    this.writeCursor(cursor);
    for (const staged of this.stagedCursors) {
      this.stagedCursors.delete(staged);
      if (staged === cursor) break;
    }
    return cursor;
  }

  capabilities() {
    return Object.entries(this.status).map(([capability, status]) => ({ capability, status, reason: status === 'unavailable' ? this.lastError : status === 'degraded' ? 'No Linux audit records have been observable; journal-only visibility is partial and privileged audit collection may be disabled or inaccessible' : null }));
  }

  commandArgs({ follow = false, cursor: suppliedCursor = undefined } = {}) {
    const cursor = suppliedCursor === undefined ? this.readCursor() : suppliedCursor;
    if (cursor !== null && (typeof cursor !== 'string' || !cursor || Buffer.byteLength(cursor, 'utf8') > 4096 || /[\r\n]/.test(cursor))) throw new Error('Invalid journal cursor');
    const args = ['--no-pager', '--output=json', '--quiet'];
    if (follow) args.push('--follow');
    else args.push(`--lines=${this.maxRecords}`);
    if (cursor) args.push('--after-cursor', cursor);
    // Re-read a small bounded overlap when no durable cursor exists so a
    // process start/restart cannot create a blind instant. Stable journal
    // cursors make normalized events idempotent at the server.
    else args.push('--since', '-1min');
    return args;
  }

  async poll({ onRecord = async () => {} } = {}) {
    return this.#run(this.commandArgs(), onRecord, null);
  }

  async follow({ onRecord = async () => {}, signal } = {}) {
    return this.#run(this.commandArgs({ follow: true }), onRecord, signal || null);
  }

  async *events({ signal, cursor = null } = {}) {
    const controller = new AbortController();
    const abort = () => controller.abort(signal?.reason || new Error('Linux journal source stopped'));
    if (signal?.aborted) abort();
    else signal?.addEventListener('abort', abort, { once: true });
    const queued = [];
    const consumers = [];
    let finished = false;
    let failure = null;
    const push = (value) => new Promise((resolve) => {
      const consumer = consumers.shift();
      if (consumer) { consumer({ value, done: false }); resolve(); }
      else queued.push({ value, resolve });
    });
    const finish = (error = null) => {
      finished = true;
      failure = error;
      while (consumers.length) consumers.shift()(error ? Promise.reject(error) : { value: undefined, done: true });
    };
    const next = () => {
      const entry = queued.shift();
      if (entry) { entry.resolve(); return Promise.resolve({ value: entry.value, done: false }); }
      if (failure) return Promise.reject(failure);
      if (finished) return Promise.resolve({ value: undefined, done: true });
      return new Promise((resolve) => consumers.push(resolve)).then((result) => result);
    };
    const task = this.#run(this.commandArgs({ follow: true, cursor }), async (record, acknowledgement) => {
      const context = { receivedAt: new Date().toISOString(), instance: this.id, entityKey: this.entityKey };
      let normalized;
      if (acknowledgement.gapReason) normalized = [this.#telemetryGap(acknowledgement.cursor, acknowledgement.gapReason, acknowledgement.recordBytes, context.receivedAt)];
      else {
        try { normalized = this.normalizer.normalize(record, context); }
        catch (error) {
          if (!validCursor(acknowledgement.cursor)) throw error;
          normalized = [this.#telemetryGap(acknowledgement.cursor, 'normalization_rejected', acknowledgement.recordBytes, context.receivedAt)];
        }
      }
      for (const event of normalized) await push({ event, cursor: acknowledgement.cursor });
    }, controller.signal, false).then(() => finish(), (error) => finish(error));
    try {
      while (true) {
        const item = await next();
        if (item.done) break;
        yield item.value;
      }
    } finally {
      controller.abort(new Error('Linux journal event iterator closed'));
      signal?.removeEventListener('abort', abort);
      await task.catch(() => {});
    }
  }

  async #run(args, onRecord, signal, stageCursors = true) {
    if (typeof onRecord !== 'function') throw new Error('onRecord must be a function');
    let child;
    try {
      child = this.spawnImpl(this.journalctlPath, args, { shell: false, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    } catch (error) {
      this.#unavailable(error);
      throw error;
    }
    let forcedKill = null;
    const abort = () => {
      child.kill('SIGTERM');
      forcedKill ||= setTimeout(() => child.kill('SIGKILL'), 2000);
      forcedKill.unref?.();
    };
    if (signal) {
      if (signal.aborted) abort();
      else signal.addEventListener('abort', abort, { once: true });
    }
    let stdout = '';
    let stderr = '';
    let count = 0;
    let queued = 0;
    let chain = Promise.resolve();
    let processingError = null;
    const enqueue = (record, cursor, gapReason, recordBytes) => {
      queued += 1;
      if (queued > this.maxRecords * 2) { processingError = new Error('journal event processing fell behind the bounded queue'); child.kill('SIGTERM'); return; }
      chain = chain.then(async () => {
        if (cursor && stageCursors) {
          this.stagedCursors.add(cursor);
          if (this.stagedCursors.size > this.maxRecords * 2) throw new Error('Too many uncommitted journal cursors');
        }
        await onRecord(record, { cursor: cursor || null, commit: cursor ? () => this.commit(cursor) : null, gapReason, recordBytes });
        count += 1;
        this.#recordSuccessfulActivity(record);
      }).catch((error) => { processingError = error; child.kill('SIGTERM'); }).finally(() => { queued -= 1; });
    };
    const consume = (line) => {
      if (!line.trim() || processingError) return;
      const recordBytes = Buffer.byteLength(line, 'utf8');
      if (recordBytes > MAX_LINE_BYTES) {
        const cursor = cursorFromDamagedJson(line);
        if (!cursor) { processingError = new Error('journalctl produced an overlong record without a recoverable cursor'); child.kill('SIGTERM'); return; }
        enqueue({ __CURSOR: cursor }, cursor, 'record_too_large', recordBytes);
        return;
      }
      let record;
      try { record = JSON.parse(line); }
      catch {
        const cursor = cursorFromDamagedJson(line);
        if (!cursor) { processingError = new Error('journalctl produced invalid JSON without a recoverable cursor'); child.kill('SIGTERM'); return; }
        enqueue({ __CURSOR: cursor }, cursor, 'invalid_json', recordBytes);
        return;
      }
      const cursor = record.__CURSOR;
      if (cursor !== undefined && !validCursor(cursor)) { processingError = new Error('journalctl produced an invalid cursor'); child.kill('SIGTERM'); return; }
      enqueue(record, cursor, null, recordBytes);
    };
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk) => {
      stdout += chunk;
      if (Buffer.byteLength(stdout, 'utf8') > this.maxOutputBytes) { processingError = new Error('journalctl buffered output exceeded configured bound'); child.kill('SIGTERM'); return; }
      let newline;
      while ((newline = stdout.indexOf('\n')) >= 0) { const line = stdout.slice(0, newline); stdout = stdout.slice(newline + 1); consume(line); }
    });
    child.stderr.on('data', (chunk) => { if (Buffer.byteLength(stderr, 'utf8') < 8192) stderr += chunk; });
    const result = await new Promise((resolve, reject) => {
      child.once('error', reject);
      child.once('close', (code, terminationSignal) => {
        if (forcedKill) clearTimeout(forcedKill);
        resolve({ code, terminationSignal });
      });
    }).catch((error) => { this.#unavailable(error); throw error; });
    if (stdout.trim()) consume(stdout);
    await chain;
    if (signal) signal.removeEventListener('abort', abort);
    if (processingError) { this.#unavailable(processingError); throw processingError; }
    if (result.code !== 0 && !(signal?.aborted && result.terminationSignal)) {
      const error = new Error(`journalctl exited with status ${result.code}: ${stderr.trim().slice(0, 512)}`);
      this.#unavailable(error);
      throw error;
    }
    this.#markReadable();
    return { count, committedCursor: this.readCursor(), stagedCursors: [...this.stagedCursors], capabilities: this.capabilities() };
  }

  #recordSuccessfulActivity(record) {
    if (record._TRANSPORT === 'audit' || /^(?:type=)?[A-Z_]+\s+msg=audit\(/.test(String(record.MESSAGE || ''))) this.auditObserved = true;
    this.#markReadable();
  }

  #telemetryGap(cursor, reason, recordBytes, observedAt) {
    const recordId = `telemetry-gap:${crypto.createHash('sha256').update(cursor).digest('hex')}`;
    return createEvent({
      time: observedAt, ingestedAt: observedAt, category: 'health', class: 'sensor_activity', activity: 'stop', outcome: 'failure', severity: 8,
      source: { adapter: this.id, instance: this.id, recordId }, entityKeys: this.entityKey ? [this.entityKey] : [],
      attributes: { reason, recordBytes }
    });
  }

  #markReadable() {
    this.status.journal_stream = 'available';
    this.status.authentication = 'available';
    this.status.privilege_use = this.auditObserved ? 'available' : 'degraded';
    this.status.account_change = 'available';
    this.status.service_state = 'available';
    this.status.linux_audit = this.auditObserved ? 'available' : 'degraded';
    this.status.process_execution = this.auditObserved ? 'available' : 'degraded';
    this.status.configuration_change = this.auditObserved ? 'available' : 'degraded';
    this.status.log_clearing = this.auditObserved ? 'available' : 'degraded';
    this.lastError = null;
  }

  #unavailable(error) {
    this.lastError = error.code ? `${error.code}: ${error.message}` : error.message;
    for (const capability of Object.keys(this.status)) this.status[capability] = 'unavailable';
  }
}

module.exports = { MAX_LINE_BYTES, LinuxJournalSource };

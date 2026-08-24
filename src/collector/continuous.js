'use strict';

const crypto = require('node:crypto');
const { SnapshotStore } = require('../storage/snapshot-store');
const { validateEvent } = require('../events/schema');
const { validateFact, assertBoundedValue, assertNoSecretMaterial } = require('../core/validation');
const { validateOperationalHealthSample } = require('./operational-telemetry');
const { signPayload, verifyEnvelope, MAXIMUM_EVENTS, MAXIMUM_FACTS, MAXIMUM_OPERATIONAL_HEALTH } = require('./envelope');

const PERIODIC_SOURCE_ID = '__periodic__';

function validDate(value, field) {
  if (typeof value !== 'string' || Number.isNaN(Date.parse(value))) throw new Error(`Continuous collector state contains invalid ${field}`);
}

/**
 * Durable, low-latency delivery for normalized endpoint events.
 *
 * An event source implements { id, events({ signal, cursor }) }, returning an
 * async iterable. Each yielded value is { event, cursor }. The cursor and event
 * are committed atomically, so a restarted source can resume without a gap.
 */
class ContinuousCollector {
  #operations = Promise.resolve();
  #capacityWaiters = [];

  constructor({
    dataDirectory, collectorId, privateKeyPem, sender, sources = [],
    batchMaximumEvents = 250, batchMaximumWaitMs = 2000, queueCapacity = 10000, queueMaximumBytes = 8 * 1024 * 1024,
    retryBaseMs = 250, retryMaximumMs = 30000, random = Math.random,
    clock = () => new Date(), protector = null, requireEncryption = false,
    periodicModules = [], periodicIntervalMs = 300000,
    sourceRetryBaseMs = 250, sourceRetryMaximumMs = 30000,
    legacyStateFilename = 'collector-state.json'
  } = {}) {
    if (typeof sender !== 'function') throw new Error('ContinuousCollector requires a sender');
    if (!collectorId || !privateKeyPem) throw new Error('ContinuousCollector requires a collector identity and private key');
    if (!Array.isArray(sources)) throw new Error('Continuous collector sources must be an array');
    if (!Array.isArray(periodicModules)) throw new Error('Continuous collector periodic modules must be an array');
    const ids = sources.map((source) => source?.id);
    if (ids.some((id) => typeof id !== 'string' || !id) || new Set(ids).size !== ids.length) throw new Error('Continuous collector sources require unique non-empty ids');
    if (!Number.isSafeInteger(batchMaximumEvents) || batchMaximumEvents < 1 || batchMaximumEvents > MAXIMUM_EVENTS) throw new Error('Continuous collector batch size is invalid');
    if (!Number.isSafeInteger(batchMaximumWaitMs) || batchMaximumWaitMs < 1 || batchMaximumWaitMs > 2000) throw new Error('Continuous collector batch wait must be between 1 and 2000 milliseconds');
    if (!Number.isSafeInteger(queueCapacity) || queueCapacity < batchMaximumEvents) throw new Error('Continuous collector queue capacity must be at least the batch size');
    if (!Number.isSafeInteger(queueMaximumBytes) || queueMaximumBytes < 1024 * 1024 || queueMaximumBytes > 64 * 1024 * 1024) throw new Error('Continuous collector byte capacity must be between 1 MiB and 64 MiB');
    if (!Number.isSafeInteger(retryBaseMs) || retryBaseMs < 1 || !Number.isSafeInteger(retryMaximumMs) || retryMaximumMs < retryBaseMs) throw new Error('Continuous collector retry settings are invalid');
    if (!Number.isSafeInteger(sourceRetryBaseMs) || sourceRetryBaseMs < 1 || !Number.isSafeInteger(sourceRetryMaximumMs) || sourceRetryMaximumMs < sourceRetryBaseMs) throw new Error('Continuous collector source retry settings are invalid');
    if (!Number.isSafeInteger(periodicIntervalMs) || periodicIntervalMs < 1000) throw new Error('Continuous collector periodic interval must be at least one second');
    if (typeof random !== 'function') throw new Error('Continuous collector random source is invalid');
    this.store = new SnapshotStore(dataDirectory, 'continuous-collector-state.json', { protector, requireEncryption });
    this.legacyStore = legacyStateFilename ? new SnapshotStore(dataDirectory, legacyStateFilename, { protector, requireEncryption }) : null;
    this.collectorId = collectorId;
    this.privateKeyPem = privateKeyPem;
    this.sender = sender;
    this.sources = sources;
    this.batchMaximumEvents = batchMaximumEvents;
    this.batchMaximumWaitMs = batchMaximumWaitMs;
    this.queueCapacity = queueCapacity;
    this.queueMaximumBytes = queueMaximumBytes;
    this.retryBaseMs = retryBaseMs;
    this.retryMaximumMs = retryMaximumMs;
    this.random = random;
    this.clock = clock;
    this.periodicModules = periodicModules;
    this.periodicIntervalMs = periodicIntervalMs;
    this.sourceRetryBaseMs = sourceRetryBaseMs;
    this.sourceRetryMaximumMs = sourceRetryMaximumMs;
    this.state = {
      schemaVersion: 1, collectorId: this.collectorId, sequence: 0, recordSequence: 0, periodicSequence: 0, entries: [], cursors: {}, moduleState: {}, pending: null,
      failureCount: 0, retryAt: null, lastSuccessAt: null, lastFailureAt: null, lastFailure: null
    };
    this.sourceStatus = Object.fromEntries([...ids, ...(periodicModules.length ? [PERIODIC_SOURCE_ID] : [])].map((id) => [id, { running: false, lastEventAt: null, lastError: null, restartCount: 0 }]));
    this.abortController = null;
    this.sourceTasks = [];
    this.timer = null;
    this.periodicTimer = null;
    this.keepaliveTimer = null;
    this.initialized = false;
  }

  async initialize() {
    let stored = await this.store.load();
    if (!stored && this.legacyStore) {
      const legacy = await this.legacyStore.load();
      if (legacy) {
        stored = this.#migrateLegacyState(legacy);
        await this.store.save(stored);
      }
    }
    let identityMigrated = false;
    if (stored) {
      identityMigrated = this.#bindStateIdentity(stored);
      this.#validateState(stored);
      if (identityMigrated) await this.store.save(stored);
    }
    if (stored) this.state = stored;
    this.initialized = true;
    return this;
  }

  #bindStateIdentity(state) {
    if (state.collectorId !== undefined) {
      if (state.collectorId !== this.collectorId) throw new Error('Continuous collector state belongs to a different collector identity');
      return false;
    }
    // State written before identity binding can be upgraded once. A pending
    // envelope provides cryptographic proof; otherwise the configured identity
    // becomes the durable binding and all subsequent changes fail closed.
    if (state.pending?.envelope) {
      let publicKey;
      try { publicKey = crypto.createPublicKey(crypto.createPrivateKey(this.privateKeyPem)); }
      catch { throw new Error('Collector private key is invalid'); }
      const payload = verifyEnvelope(state.pending.envelope, publicKey);
      if (payload.collectorId !== this.collectorId) throw new Error('Continuous collector state belongs to a different collector identity');
    }
    state.collectorId = this.collectorId;
    return true;
  }

  #migrateLegacyState(legacy) {
    if (legacy?.schemaVersion !== 1 || !Number.isSafeInteger(legacy.sequence) || legacy.sequence < 0) throw new Error('Legacy collector state has an invalid sequence');
    const migrated = {
      schemaVersion: 1, collectorId: this.collectorId, sequence: legacy.sequence, recordSequence: 0, periodicSequence: legacy.sequence,
      entries: [], cursors: {}, moduleState: {}, pending: null,
      failureCount: Number.isSafeInteger(legacy.failureCount) && legacy.failureCount >= 0 ? legacy.failureCount : 0,
      retryAt: null, lastSuccessAt: legacy.lastSuccessAt || null, lastFailureAt: null,
      lastFailure: legacy.pending ? 'Migrated unacknowledged legacy collector submission' : null
    };
    if (!legacy.pending) return migrated;
    let publicKey;
    try { publicKey = crypto.createPublicKey(crypto.createPrivateKey(this.privateKeyPem)); }
    catch { throw new Error('Collector private key is invalid'); }
    const payload = verifyEnvelope(legacy.pending, publicKey);
    if (payload.collectorId !== this.collectorId || payload.sequence !== legacy.sequence) throw new Error('Pending legacy collector envelope does not match its identity or sequence');
    const queuedAt = payload.collectedAt;
    for (const fact of payload.facts) {
      migrated.recordSequence += 1;
      migrated.entries.push({ id: migrated.recordSequence, sourceId: '__legacy__', queuedAt, kind: 'fact', fact: structuredClone(fact) });
    }
    for (const event of payload.events) {
      migrated.recordSequence += 1;
      migrated.entries.push({ id: migrated.recordSequence, sourceId: '__legacy__', queuedAt, kind: 'event', event: structuredClone(event) });
    }
    for (const sample of payload.operationalHealth || []) {
      migrated.recordSequence += 1;
      migrated.entries.push({ id: migrated.recordSequence, sourceId: '__legacy__', queuedAt, kind: 'operationalHealth', operationalHealth: structuredClone(sample) });
    }
    if (migrated.entries.length > this.queueCapacity) throw new Error('Pending legacy collector envelope exceeds continuous queue capacity');
    migrated.pending = { entryIds: migrated.entries.map((entry) => entry.id), envelope: structuredClone(legacy.pending) };
    return migrated;
  }

  #validateState(state) {
    if (state?.schemaVersion !== 1 || !Number.isSafeInteger(state.sequence) || state.sequence < 0 || !Number.isSafeInteger(state.recordSequence) || state.recordSequence < 0) throw new Error('Unsupported or invalid continuous collector state');
    if (state.collectorId !== this.collectorId) throw new Error('Continuous collector state belongs to a different collector identity');
    if (state.periodicSequence === undefined) state.periodicSequence = 0;
    if (!Number.isSafeInteger(state.periodicSequence) || state.periodicSequence < 0) throw new Error('Continuous collector state has an invalid periodic sequence');
    if (!Array.isArray(state.entries) || state.entries.length > this.queueCapacity) throw new Error('Continuous collector state has an invalid queue');
    if (Buffer.byteLength(JSON.stringify(state.entries), 'utf8') > this.queueMaximumBytes) throw new Error('Continuous collector state exceeds its byte capacity');
    if (!state.cursors || typeof state.cursors !== 'object' || Array.isArray(state.cursors)) throw new Error('Continuous collector state has invalid cursors');
    if (state.moduleState === undefined) state.moduleState = {};
    if (!state.moduleState || typeof state.moduleState !== 'object' || Array.isArray(state.moduleState)) throw new Error('Continuous collector state has invalid module state');
    const moduleIssues = [...assertBoundedValue(state.moduleState, '$.moduleState'), ...assertNoSecretMaterial(state.moduleState, '$.moduleState')];
    if (moduleIssues.length) throw new Error(`Continuous collector module state is invalid: ${moduleIssues.join('; ')}`);
    const ids = new Set();
    for (const entry of state.entries) {
      if (!Number.isSafeInteger(entry.id) || entry.id < 1 || ids.has(entry.id) || typeof entry.sourceId !== 'string') throw new Error('Continuous collector state has an invalid queue entry');
      ids.add(entry.id);
      validDate(entry.queuedAt, 'queuedAt');
      if ((entry.kind || 'event') === 'event') validateEvent(entry.event);
      else if (entry.kind === 'fact') validateFact(entry.fact);
      else if (entry.kind === 'operationalHealth') validateOperationalHealthSample(entry.operationalHealth);
      else throw new Error('Continuous collector state has an invalid observation kind');
    }
    for (const field of ['retryAt', 'lastSuccessAt', 'lastFailureAt']) if (state[field] !== null) validDate(state[field], field);
    if (!Number.isSafeInteger(state.failureCount) || state.failureCount < 0) throw new Error('Continuous collector state has an invalid failure count');
    if (state.pending) {
      let publicKey;
      try { publicKey = crypto.createPublicKey(crypto.createPrivateKey(this.privateKeyPem)); }
      catch { throw new Error('Collector private key is invalid'); }
      const payload = verifyEnvelope(state.pending.envelope, publicKey);
      if (payload.collectorId !== this.collectorId || payload.sequence !== state.sequence) throw new Error('Pending continuous collector envelope does not match its identity or sequence');
      if (!Array.isArray(state.pending.entryIds) || state.pending.entryIds.some((id) => !ids.has(id)) || state.pending.entryIds.length !== payload.events.length + payload.facts.length + (payload.operationalHealth || []).length) throw new Error('Pending continuous collector envelope does not match its queue entries');
    }
  }

  #serialize(operation) {
    const result = this.#operations.then(operation, operation);
    this.#operations = result.then(() => undefined, () => undefined);
    return result;
  }

  #now() {
    const now = this.clock();
    if (!(now instanceof Date) || Number.isNaN(now.getTime())) throw new Error('Continuous collector clock returned an invalid date');
    return now;
  }

  async ingest(sourceId, event, cursor) {
    return this.ingestBatch(sourceId, { events: [event] }, cursor);
  }

  async ingestBatch(sourceId, { events = [], facts = [], operationalHealth = [] } = {}, cursor) {
    if (!this.initialized) throw new Error('ContinuousCollector must be initialized before use');
    if (!Object.hasOwn(this.sourceStatus, sourceId)) throw new Error(`Unknown continuous event source: ${sourceId}`);
    if (!Array.isArray(events) || !Array.isArray(facts) || !Array.isArray(operationalHealth) || events.length + facts.length + operationalHealth.length < 1) throw new Error('Continuous collector batch requires observations');
    if (events.length > MAXIMUM_EVENTS || facts.length > MAXIMUM_FACTS || operationalHealth.length > MAXIMUM_OPERATIONAL_HEALTH || events.length + facts.length + operationalHealth.length > this.queueCapacity) throw new Error('Continuous collector input batch exceeds capacity');
    events.forEach(validateEvent);
    facts.forEach(validateFact);
    operationalHealth.forEach(validateOperationalHealthSample);
    const preview = { schemaVersion: 1, collectorId: this.collectorId, sequence: Math.max(1, this.state.sequence + 1), collectedAt: this.#now().toISOString(), facts, events, operationalHealth };
    try { signPayload(preview, this.privateKeyPem); }
    catch (error) {
      if (events.length + facts.length + operationalHealth.length === 1) throw new Error('Continuous collector observation cannot fit in a signed payload', { cause: error });
      // A large input batch may still be queued because delivery will split it.
    }
    const needed = events.length + facts.length + operationalHealth.length;
    const incomingBytes = Buffer.byteLength(JSON.stringify({ events, facts, operationalHealth }), 'utf8');
    if (incomingBytes > this.queueMaximumBytes) throw new Error('Continuous collector input batch exceeds byte capacity');
    const exceedsCapacity = () => this.state.entries.length + needed > this.queueCapacity
      || Buffer.byteLength(JSON.stringify(this.state.entries), 'utf8') + incomingBytes > this.queueMaximumBytes;
    while (exceedsCapacity()) {
      if (this.abortController?.signal.aborted) throw new Error('Continuous collector is stopping');
      await new Promise((resolve, reject) => this.#capacityWaiters.push({ resolve, reject }));
    }
    const result = await this.#serialize(async () => {
      if (exceedsCapacity()) return false;
      const now = this.#now().toISOString();
      for (const fact of facts) {
        this.state.recordSequence += 1;
        this.state.entries.push({ id: this.state.recordSequence, sourceId, queuedAt: now, kind: 'fact', fact: structuredClone(fact) });
      }
      for (const event of events) {
        this.state.recordSequence += 1;
        this.state.entries.push({ id: this.state.recordSequence, sourceId, queuedAt: now, kind: 'event', event: structuredClone(event) });
      }
      for (const sample of operationalHealth) {
        this.state.recordSequence += 1;
        this.state.entries.push({ id: this.state.recordSequence, sourceId, queuedAt: now, kind: 'operationalHealth', operationalHealth: structuredClone(sample) });
      }
      if (cursor !== undefined) this.state.cursors[sourceId] = structuredClone(cursor);
      await this.store.save(this.state);
      this.sourceStatus[sourceId].lastEventAt = now;
      return true;
    });
    if (!result) return this.ingestBatch(sourceId, { events, facts, operationalHealth }, cursor);
    this.#schedule();
    return result;
  }

  async flush({ force = false } = {}) {
    if (!this.initialized) throw new Error('ContinuousCollector must be initialized before use');
    return this.#serialize(async () => {
      const now = this.#now();
      if (!this.state.pending) {
        if (!this.state.entries.length) return { status: 'empty' };
        const oldest = Date.parse(this.state.entries[0].queuedAt);
        if (!force && this.state.entries.length < this.batchMaximumEvents && now.getTime() - oldest < this.batchMaximumWaitMs) return { status: 'waiting' };
        const entries = [];
        let operationalCount = 0;
        for (const entry of this.state.entries.slice(0, this.batchMaximumEvents)) {
          if (entry.kind === 'operationalHealth' && operationalCount >= MAXIMUM_OPERATIONAL_HEALTH) break;
          entries.push(entry);
          if (entry.kind === 'operationalHealth') operationalCount += 1;
        }
        const nextSequence = this.state.sequence + 1;
        let envelope;
        while (entries.length) {
          const payload = {
            schemaVersion: 1, collectorId: this.collectorId, sequence: nextSequence,
            collectedAt: now.toISOString(),
            facts: entries.filter((entry) => entry.kind === 'fact').map((entry) => structuredClone(entry.fact)),
            events: entries.filter((entry) => (entry.kind || 'event') === 'event').map((entry) => structuredClone(entry.event)),
            operationalHealth: entries.filter((entry) => entry.kind === 'operationalHealth').map((entry) => structuredClone(entry.operationalHealth))
          };
          try { envelope = signPayload(payload, this.privateKeyPem); break; }
          catch (error) {
            if (!/encoded payload exceeds the maximum size/.test(error.message) || entries.length === 1) throw new Error('Queued observations cannot fit in a signed collector payload', { cause: error });
            entries.pop();
          }
        }
        this.state.sequence = nextSequence;
        this.state.pending = { entryIds: entries.map((entry) => entry.id), envelope };
        await this.store.save(this.state);
      }
      if (!force && this.state.retryAt && Date.parse(this.state.retryAt) > now.getTime()) return { status: 'backoff', retryAt: this.state.retryAt };
      try {
        const result = await this.sender(this.state.pending.envelope);
        const delivered = new Set(this.state.pending.entryIds);
        const count = delivered.size;
        this.state.entries = this.state.entries.filter((entry) => !delivered.has(entry.id));
        this.state.pending = null;
        this.state.failureCount = 0;
        this.state.retryAt = null;
        this.state.lastFailure = null;
        this.state.lastSuccessAt = now.toISOString();
        await this.store.save(this.state);
        this.#releaseCapacity();
        this.#schedule();
        return { status: 'submitted', sequence: this.state.sequence, count, result };
      } catch (error) {
        this.state.failureCount += 1;
        const exponential = Math.min(this.retryMaximumMs, this.retryBaseMs * (2 ** Math.min(20, this.state.failureCount - 1)));
        const sample = Number(this.random());
        if (!Number.isFinite(sample) || sample < 0 || sample >= 1) throw new Error('Continuous collector random source returned an invalid value', { cause: error });
        const delay = Math.max(1, Math.round(exponential * (0.5 + sample)));
        this.state.retryAt = new Date(now.getTime() + delay).toISOString();
        this.state.lastFailureAt = now.toISOString();
        this.state.lastFailure = String(error?.message || error).slice(0, 512);
        await this.store.save(this.state);
        this.#schedule();
        throw error;
      }
    });
  }

  #releaseCapacity() {
    while (this.state.entries.length < this.queueCapacity && this.#capacityWaiters.length) this.#capacityWaiters.shift().resolve();
  }

  #schedule() {
    if (!this.abortController || this.abortController.signal.aborted) return;
    if (this.timer) clearTimeout(this.timer);
    if (!this.state.entries.length && !this.state.pending) { this.timer = null; return; }
    const now = this.#now().getTime();
    const target = this.state.pending
      ? (this.state.retryAt ? Date.parse(this.state.retryAt) : now)
      : this.state.entries.length >= this.batchMaximumEvents
        ? now
        : Date.parse(this.state.entries[0].queuedAt) + this.batchMaximumWaitMs;
    this.timer = setTimeout(async () => {
      this.timer = null;
      try { await this.flush(); } catch { /* durable failure state is exposed by status() */ }
      this.#schedule();
    }, Math.max(0, target - now));
    this.timer.unref?.();
  }

  #jitteredDelay(attempt, base = this.sourceRetryBaseMs, maximum = this.sourceRetryMaximumMs) {
    const sample = Number(this.random());
    if (!Number.isFinite(sample) || sample < 0 || sample >= 1) throw new Error('Continuous collector random source returned an invalid value');
    const exponential = Math.min(maximum, base * (2 ** Math.min(20, Math.max(0, attempt - 1))));
    return Math.max(1, Math.round(exponential * (0.5 + sample)));
  }

  #wait(milliseconds) {
    const signal = this.abortController.signal;
    if (signal.aborted) return Promise.resolve();
    return new Promise((resolve) => {
      const done = () => { clearTimeout(timer); signal.removeEventListener('abort', done); resolve(); };
      const timer = setTimeout(done, milliseconds);
      signal.addEventListener('abort', done, { once: true });
    });
  }

  async #runSource(source) {
    const status = this.sourceStatus[source.id];
    status.running = true;
    let failures = 0;
    try {
      while (!this.abortController.signal.aborted) {
        try {
          if (typeof source.events !== 'function') throw new Error('Event source must implement events(context)');
          const iterable = await source.events({ signal: this.abortController.signal, cursor: structuredClone(this.state.cursors[source.id]) });
          if (!iterable || typeof iterable[Symbol.asyncIterator] !== 'function') throw new Error('Event source did not return an async iterable');
          status.lastError = null;
          for await (const observation of iterable) {
            if (this.abortController.signal.aborted) break;
            if (!observation || (!Object.hasOwn(observation, 'event') && !Array.isArray(observation.events) && !Array.isArray(observation.facts))) throw new Error('Event source yielded an invalid observation');
            await this.ingestBatch(source.id, { events: observation.events || (observation.event ? [observation.event] : []), facts: observation.facts || [] }, observation.cursor);
            failures = 0;
          }
          if (this.abortController.signal.aborted) break;
          throw new Error('Event source exited unexpectedly');
        } catch (error) {
          if (this.abortController.signal.aborted) break;
          failures += 1;
          status.restartCount += 1;
          status.lastError = String(error?.message || error).slice(0, 512);
          await this.#wait(this.#jitteredDelay(failures));
        }
      }
    } finally { status.running = false; }
  }

  async #runPeriodic() {
    const status = this.sourceStatus[PERIODIC_SOURCE_ID];
    status.running = true;
    try {
      while (!this.abortController.signal.aborted) {
        await this.#wait(this.periodicIntervalMs);
        if (this.abortController.signal.aborted) break;
        try {
          await this.collectPeriodicOnce();
          status.lastError = null;
        } catch (error) {
          if (!this.abortController.signal.aborted) status.lastError = String(error?.message || error).slice(0, 512);
        }
      }
    } finally { status.running = false; }
  }

  async collectPeriodicOnce() {
    if (!this.periodicModules.length) return { facts: 0, events: 0 };
    const collectedAt = this.#now().toISOString();
    const sequence = this.state.periodicSequence + 1;
    const facts = [];
    const events = [];
    const operationalHealth = [];
    const moduleState = structuredClone(this.state.moduleState || {});
    for (const module of this.periodicModules) {
      if (!module || typeof module.collect !== 'function') throw new Error('Periodic collector module must implement collect(context)');
      const moduleId = module.manifest?.id || null;
      const output = await module.collect({ collectorId: this.collectorId, collectedAt, sequence, state: moduleId ? structuredClone(moduleState[moduleId] || null) : null });
      facts.push(...(output?.facts || []));
      events.push(...(output?.events || []));
      operationalHealth.push(...(output?.operationalHealth || []));
      if (output?.state !== undefined) {
        if (!moduleId) throw new Error('A stateful periodic collector module requires manifest.id');
        const issues = [...assertBoundedValue(output.state, '$.moduleState'), ...assertNoSecretMaterial(output.state, '$.moduleState')];
        if (issues.length) throw new Error(`Periodic collector module returned invalid state: ${issues.join('; ')}`);
        moduleState[moduleId] = structuredClone(output.state);
      }
    }
    this.state.periodicSequence = sequence;
    this.state.moduleState = moduleState;
    if (facts.length || events.length || operationalHealth.length) await this.ingestBatch(PERIODIC_SOURCE_ID, { facts, events, operationalHealth });
    else await this.#serialize(() => this.store.save(this.state));
    return { facts: facts.length, events: events.length, operationalHealth: operationalHealth.length, sequence };
  }

  async start() {
    if (!this.initialized) throw new Error('ContinuousCollector must be initialized before use');
    if (this.abortController) return;
    this.abortController = new AbortController();
    // The delivery timer is intentionally unreferenced, but a daemon must stay
    // alive while idle or while a platform source is temporarily unavailable.
    this.keepaliveTimer = setInterval(() => {}, 60 * 60 * 1000);
    this.sourceTasks = this.sources.map((source) => this.#runSource(source));
    if (this.periodicModules.length) {
      try { await this.collectPeriodicOnce(); }
      catch (error) {
        this.abortController.abort(error);
        if (this.keepaliveTimer) clearInterval(this.keepaliveTimer);
        this.keepaliveTimer = null;
        await Promise.allSettled(this.sourceTasks);
        this.sourceTasks = [];
        this.abortController = null;
        throw error;
      }
      this.sourceTasks.push(this.#runPeriodic());
    }
    this.#schedule();
  }

  async stop({ flush = true } = {}) {
    if (!this.abortController) return;
    this.abortController.abort(new Error('Continuous collector stopped'));
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
    if (this.keepaliveTimer) clearInterval(this.keepaliveTimer);
    this.keepaliveTimer = null;
    for (const waiter of this.#capacityWaiters.splice(0)) waiter.reject(new Error('Continuous collector stopped'));
    await Promise.allSettled(this.sourceTasks);
    if (flush && (this.state.entries.length || this.state.pending)) {
      try { await this.flush({ force: true }); } catch { /* pending batch remains durable */ }
    }
    this.sourceTasks = [];
    this.abortController = null;
  }

  status() {
    const oldest = this.state.entries[0]?.queuedAt || null;
    return {
      running: Boolean(this.abortController && !this.abortController.signal.aborted),
      healthy: !this.state.lastFailure && Object.values(this.sourceStatus).every((source) => !source.lastError),
      queue: { depth: this.state.entries.length, capacity: this.queueCapacity, oldestAt: oldest, pending: Boolean(this.state.pending) },
      delivery: { sequence: this.state.sequence, failureCount: this.state.failureCount, retryAt: this.state.retryAt, lastSuccessAt: this.state.lastSuccessAt, lastFailureAt: this.state.lastFailureAt, lastFailure: this.state.lastFailure },
      cursors: structuredClone(this.state.cursors),
      sources: structuredClone(this.sourceStatus),
      periodic: this.sourceStatus[PERIODIC_SOURCE_ID] ? structuredClone(this.sourceStatus[PERIODIC_SOURCE_ID]) : null
    };
  }
}

module.exports = { ContinuousCollector, PERIODIC_SOURCE_ID };

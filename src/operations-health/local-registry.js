'use strict';

const { SnapshotStore } = require('../storage/snapshot-store');
const { stableId } = require('../core/canonical');
const { validateOperationalHealthSample } = require('../collector/operational-telemetry');

const MAXIMUM_COLLECTORS = 10000;

function emptyState() {
  return { schemaVersion: 1, collectors: {} };
}

function validateState(value) {
  if (!value) return emptyState();
  if (value.schemaVersion !== 1 || !value.collectors || typeof value.collectors !== 'object' || Array.isArray(value.collectors)) throw new Error('Operational health registry state is invalid');
  const entries = Object.entries(value.collectors);
  if (entries.length > MAXIMUM_COLLECTORS) throw new Error('Operational health registry exceeds collector capacity');
  for (const [collectorId, record] of entries) {
    if (!record || record.collectorId !== collectorId || !Number.isSafeInteger(record.collectorSequence) || record.collectorSequence < 1) throw new Error('Operational health registry record is invalid');
    validateOperationalHealthSample(record.sample);
    if (record.sample.collectorId !== collectorId) throw new Error('Operational health registry identity is invalid');
  }
  return structuredClone(value);
}

class LocalOperationalHealthRegistry {
  #queue = Promise.resolve();

  constructor({ dataDirectory, protector = null, requireEncryption = false } = {}) {
    this.store = new SnapshotStore(dataDirectory, 'operational-health.latest.json', { protector, requireEncryption });
    this.state = emptyState();
  }

  async initialize() {
    this.state = validateState(await this.store.load());
    return this;
  }

  async accept({ collectorId, sequence, samples } = {}) {
    if (typeof collectorId !== 'string' || !collectorId || !Number.isSafeInteger(sequence) || sequence < 1 || !Array.isArray(samples)) throw new Error('Operational health submission is invalid');
    for (const sample of samples) {
      validateOperationalHealthSample(sample);
      if (sample.collectorId !== collectorId) throw new Error('Operational health collector identity mismatch');
    }
    if (!samples.length) return { accepted: 0 };
    const operation = this.#queue.then(async () => {
      const existing = this.state.collectors[collectorId];
      if (existing && sequence < existing.collectorSequence) return { accepted: 0, stale: true };
      if (!existing && Object.keys(this.state.collectors).length >= MAXIMUM_COLLECTORS) throw new Error('Operational health registry collector capacity reached');
      const sample = samples.reduce((latest, candidate) => Date.parse(candidate.observedAt) > Date.parse(latest.observedAt) ? candidate : latest, samples[0]);
      this.state.collectors[collectorId] = { collectorId, collectorSequence: sequence, sample: structuredClone(sample) };
      await this.store.save(this.state);
      return { accepted: samples.length };
    }, async () => {
      throw new Error('Operational health registry is unavailable');
    });
    this.#queue = operation.then(() => undefined, () => undefined);
    return operation;
  }

  snapshot({ deploymentId, generatedAt = null } = {}) {
    if (typeof deploymentId !== 'string' || !deploymentId || deploymentId.length > 256) throw new Error('Operational health deployment identity is invalid');
    const nodes = Object.values(this.state.collectors)
      .sort((left, right) => left.collectorId.localeCompare(right.collectorId))
      .map((record) => ({ collectorSequence: record.collectorSequence, ...structuredClone(record.sample) }));
    const latest = nodes.reduce((value, node) => value > node.observedAt ? value : node.observedAt, '1970-01-01T00:00:00.000Z');
    const timestamp = generatedAt || latest;
    const payload = { schemaVersion: 1, kind: 'lookout_operational_health', deploymentId, generatedAt: timestamp, nodes };
    return { ...payload, id: stableId('operational_health', payload) };
  }
}

module.exports = { LocalOperationalHealthRegistry, validateOperationalHealthRegistryState: validateState };

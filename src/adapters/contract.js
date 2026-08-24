'use strict';

const { stableId } = require('../core/canonical');
const { validateAdapterManifest, validateFact } = require('../core/validation');

function createFact({ kind, observedAt, confidence = 1, source, data }) {
  const identity = { adapter: source.adapter, instance: source.instance, recordId: source.recordId, kind };
  return validateFact({
    schemaVersion: 1,
    id: stableId('fact', identity),
    kind,
    observedAt,
    confidence,
    source: { ...source },
    data: structuredClone(data)
  });
}

class AdapterRegistry {
  #adapters = new Map();

  register(adapter) {
    if (!adapter || typeof adapter.survey !== 'function') throw new TypeError('Adapter must implement survey(context)');
    const manifest = validateAdapterManifest(adapter.manifest);
    if (this.#adapters.has(manifest.id)) throw new Error(`Adapter already registered: ${manifest.id}`);
    this.#adapters.set(manifest.id, adapter);
    return this;
  }

  manifests() {
    return [...this.#adapters.values()].map((adapter) => structuredClone(adapter.manifest)).sort((a, b) => a.id.localeCompare(b.id));
  }

  async survey(id, context = {}) {
    const adapter = this.#adapters.get(id);
    if (!adapter) throw new Error(`Unknown adapter: ${id}`);
    const output = await adapter.survey(Object.freeze({ ...context }));
    const facts = [];
    if (output && typeof output[Symbol.asyncIterator] === 'function') {
      for await (const fact of output) facts.push(this.#validateEmission(adapter, fact));
    } else if (output && typeof output[Symbol.iterator] === 'function') {
      for (const fact of output) facts.push(this.#validateEmission(adapter, fact));
    } else throw new TypeError(`Adapter ${id} survey() must return an iterable or async iterable`);
    return facts.sort((a, b) => a.id.localeCompare(b.id));
  }

  #validateEmission(adapter, fact) {
    validateFact(fact);
    if (fact.source.adapter !== adapter.manifest.id) throw new Error(`Adapter ${adapter.manifest.id} emitted a fact attributed to ${fact.source.adapter}`);
    if (fact.kind === 'capability' && !adapter.manifest.capabilities.includes(fact.data.capability)) {
      throw new Error(`Adapter ${adapter.manifest.id} emitted undeclared capability ${fact.data.capability}`);
    }
    return structuredClone(fact);
  }
}

module.exports = { createFact, AdapterRegistry };

'use strict';

const { validateEvent } = require('../events/schema');

function validateManifest(manifest) {
  if (!manifest || typeof manifest.id !== 'string' || typeof manifest.version !== 'string') throw new Error('Normalizer manifest requires id and version');
  if (!Array.isArray(manifest.inputTypes) || !manifest.inputTypes.length) throw new Error('Normalizer manifest requires inputTypes');
  if (!Array.isArray(manifest.capabilities) || !manifest.capabilities.length) throw new Error('Normalizer manifest requires capabilities');
  return manifest;
}

class NormalizerRegistry {
  #normalizers = new Map();

  register(normalizer) {
    if (!normalizer || typeof normalizer.normalize !== 'function') throw new Error('Normalizer must implement normalize(record, context)');
    const manifest = validateManifest(normalizer.manifest);
    if (this.#normalizers.has(manifest.id)) throw new Error(`Normalizer already registered: ${manifest.id}`);
    this.#normalizers.set(manifest.id, normalizer);
    return this;
  }

  manifests() {
    return [...this.#normalizers.values()].map((normalizer) => structuredClone(normalizer.manifest)).sort((a, b) => a.id.localeCompare(b.id));
  }

  normalize(id, record, context = {}) {
    const normalizer = this.#normalizers.get(id);
    if (!normalizer) throw new Error(`Unknown normalizer: ${id}`);
    const events = normalizer.normalize(structuredClone(record), Object.freeze({ ...context }));
    if (!Array.isArray(events)) throw new Error(`Normalizer ${id} must return an event array`);
    return events.map(validateEvent).sort((a, b) => a.time.localeCompare(b.time) || a.id.localeCompare(b.id));
  }
}

module.exports = { validateManifest, NormalizerRegistry };

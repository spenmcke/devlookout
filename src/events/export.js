'use strict';

const { validateEvent } = require('./schema');

const DEFAULT_FIELDS = new Set(['schemaVersion', 'id', 'time', 'category', 'class', 'activity', 'outcome', 'severity', 'entityKeys', 'actor', 'sourceEndpoint', 'destinationEndpoint', 'service', 'correlation', 'attributes']);

function selectExportEvent(event, policy = {}) {
  validateEvent(event);
  if (policy.enabled !== true) return null;
  if (policy.categories && !policy.categories.includes(event.category)) return null;
  const allowedFields = new Set(policy.fields || DEFAULT_FIELDS);
  const output = {};
  for (const key of Object.keys(event).sort()) if (allowedFields.has(key)) output[key] = structuredClone(event[key]);
  if (output.attributes && Array.isArray(policy.attributeAllowlist)) {
    output.attributes = Object.fromEntries(Object.entries(output.attributes).filter(([key]) => policy.attributeAllowlist.includes(key)).sort(([a], [b]) => a.localeCompare(b)));
  } else if (output.attributes && policy.allowAllAttributes !== true) output.attributes = {};
  if (output.actor && policy.includeActor !== true) output.actor = { id: output.actor.id || null, type: output.actor.type || null };
  return output;
}

class ExportManager {
  constructor({ policy = { enabled: false }, exporter = null } = {}) {
    this.policy = structuredClone(policy);
    this.exporter = exporter;
  }

  async send(events) {
    if (this.policy.enabled !== true) return { exported: 0, disabled: true };
    if (!this.exporter || typeof this.exporter.send !== 'function') throw new Error('Cloud export is enabled but no exporter is configured');
    const batch = events.map((event) => selectExportEvent(event, this.policy)).filter(Boolean);
    if (!batch.length) return { exported: 0, disabled: false };
    await this.exporter.send(batch);
    return { exported: batch.length, disabled: false };
  }
}

module.exports = { DEFAULT_FIELDS, selectExportEvent, ExportManager };

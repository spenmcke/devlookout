'use strict';

const { createFact } = require('./contract');

function declarationAdapter(configuration, { id = 'declaration', instance = 'local-config' } = {}) {
  const declaredCapabilities = [...new Set([
    'inventory', 'ownership', 'criticality', 'expected_relationship',
    ...(configuration.capabilities || []).map((item) => item.capability)
  ])].sort();
  return {
    manifest: {
      id,
      version: '1.0.0',
      kind: 'declaration',
      capabilities: declaredCapabilities,
      permissions: ['read configured declarations']
    },
    survey(context = {}) {
      const observedAt = context.observedAt || new Date().toISOString();
      const facts = [];
      for (const item of configuration.entities || []) {
        facts.push(createFact({
          kind: 'entity', observedAt, confidence: item.confidence ?? 1,
          source: { adapter: id, instance, recordId: `entity:${item.key}` },
          data: { entityKey: item.key, entityType: item.type, name: item.name, attributes: { ...(item.attributes || {}), declared: true } }
        }));
      }
      for (const item of configuration.relationships || []) {
        facts.push(createFact({
          kind: 'relationship', observedAt, confidence: item.confidence ?? 1,
          source: { adapter: id, instance, recordId: `relationship:${item.from}:${item.relation}:${item.to}` },
          data: { from: item.from, to: item.to, relation: item.relation, attributes: { ...(item.attributes || {}), declared: true } }
        }));
      }
      for (const item of configuration.capabilities || []) {
        facts.push(createFact({
          kind: 'capability', observedAt, confidence: item.confidence ?? 1,
          source: { adapter: id, instance, recordId: `capability:${item.entityKey}:${item.capability}` },
          data: { entityKey: item.entityKey, capability: item.capability, status: item.status, freshnessSeconds: item.freshnessSeconds }
        }));
      }
      return facts;
    }
  };
}

module.exports = { declarationAdapter };

'use strict';

const { stableId } = require('../core/canonical');
const { validateFact } = require('../core/validation');
const GRAPH_LIMITS = Object.freeze({ entities: 10000, relationships: 20000, capabilities: 20000 });

function trimMap(map, limit, timeOf) {
  if (map.size <= limit) return;
  const remove = [...map.entries()].sort((left, right) => String(timeOf(left[1]) || '').localeCompare(String(timeOf(right[1]) || '')) || left[0].localeCompare(right[0])).slice(0, map.size - limit);
  for (const [key] of remove) map.delete(key);
}

function compareClaims(left, right) {
  if (left.confidence !== right.confidence) return right.confidence - left.confidence;
  const time = right.observedAt.localeCompare(left.observedAt);
  return time || left.factId.localeCompare(right.factId);
}

function materializeClaims(claims) {
  const output = {};
  for (const key of Object.keys(claims).sort()) output[key] = [...claims[key]].sort(compareClaims)[0].value;
  return output;
}

function addClaim(target, key, value, fact) {
  if (value === undefined) return;
  if (!target[key]) target[key] = [];
  const claim = { value: structuredClone(value), factId: fact.id, confidence: fact.confidence, observedAt: fact.observedAt, source: structuredClone(fact.source) };
  const existing = target[key].findIndex((item) => item.factId === fact.id);
  if (existing >= 0) target[key][existing] = claim;
  else target[key].push(claim);
  target[key].sort(compareClaims);
  target[key] = target[key].slice(0, 4);
}

function addProvenance(target, factId) {
  target.add(factId);
  while (target.size > 32) target.delete(target.values().next().value);
}

class SecurityGraph {
  #entities = new Map();
  #relationships = new Map();
  #capabilities = new Map();

  apply(facts) {
    const validated = [...facts].map(validateFact).sort((a, b) => a.id.localeCompare(b.id));
    const entityKeys = new Set(validated.filter((fact) => fact.kind === 'entity').map((fact) => fact.data.entityKey));
    const known = (key) => this.#entities.has(key) || entityKeys.has(key);
    for (const fact of validated.filter((item) => item.kind === 'relationship')) {
      if (!known(fact.data.from)) throw new Error(`Relationship references unknown source entity: ${fact.data.from}`);
      if (!known(fact.data.to)) throw new Error(`Relationship references unknown target entity: ${fact.data.to}`);
    }
    for (const fact of validated.filter((item) => item.kind === 'capability')) if (!known(fact.data.entityKey)) throw new Error(`Capability references unknown entity: ${fact.data.entityKey}`);
    for (const fact of validated.filter((item) => item.kind === 'entity')) this.#applyEntity(fact);
    for (const fact of validated.filter((item) => item.kind === 'relationship')) this.#applyRelationship(fact, entityKeys);
    for (const fact of validated.filter((item) => item.kind === 'capability')) this.#applyCapability(fact);
    trimMap(this.#entities, GRAPH_LIMITS.entities, (entity) => entity.lastSeen);
    trimMap(this.#relationships, GRAPH_LIMITS.relationships, (edge) => edge.lastSeen);
    trimMap(this.#capabilities, GRAPH_LIMITS.capabilities, (record) => record.claims.status?.[0]?.observedAt);
    const knownEntities = new Set(this.#entities.keys());
    for (const [key, edge] of this.#relationships) if (!knownEntities.has(edge.from) || !knownEntities.has(edge.to)) this.#relationships.delete(key);
    for (const [key, record] of this.#capabilities) if (!knownEntities.has(record.entityKey)) this.#capabilities.delete(key);
    return this;
  }

  #applyEntity(fact) {
    const key = fact.data.entityKey;
    const entity = this.#entities.get(key) || { id: stableId('entity', key), key, claims: {}, provenance: new Set(), firstSeen: fact.observedAt, lastSeen: fact.observedAt };
    addClaim(entity.claims, 'type', fact.data.entityType, fact);
    addClaim(entity.claims, 'name', fact.data.name, fact);
    for (const [name, value] of Object.entries(fact.data.attributes || {})) addClaim(entity.claims, name, value, fact);
    entity.firstSeen = entity.firstSeen < fact.observedAt ? entity.firstSeen : fact.observedAt;
    entity.lastSeen = entity.lastSeen > fact.observedAt ? entity.lastSeen : fact.observedAt;
    addProvenance(entity.provenance, fact.id);
    this.#entities.set(key, entity);
  }

  #applyRelationship(fact, batchEntityKeys) {
    const { from, to, relation } = fact.data;
    if (!this.#entities.has(from) && !batchEntityKeys.has(from)) throw new Error(`Relationship references unknown source entity: ${from}`);
    if (!this.#entities.has(to) && !batchEntityKeys.has(to)) throw new Error(`Relationship references unknown target entity: ${to}`);
    const key = `${from}\0${relation}\0${to}`;
    const edge = this.#relationships.get(key) || { id: stableId('relationship', { from, relation, to }), from, to, relation, claims: {}, provenance: new Set(), firstSeen: fact.observedAt, lastSeen: fact.observedAt };
    for (const [name, value] of Object.entries(fact.data.attributes || {})) addClaim(edge.claims, name, value, fact);
    edge.firstSeen = edge.firstSeen < fact.observedAt ? edge.firstSeen : fact.observedAt;
    edge.lastSeen = edge.lastSeen > fact.observedAt ? edge.lastSeen : fact.observedAt;
    addProvenance(edge.provenance, fact.id);
    this.#relationships.set(key, edge);
  }

  #applyCapability(fact) {
    if (!this.#entities.has(fact.data.entityKey)) throw new Error(`Capability references unknown entity: ${fact.data.entityKey}`);
    const key = `${fact.data.entityKey}\0${fact.data.capability}`;
    const record = this.#capabilities.get(key) || { entityKey: fact.data.entityKey, capability: fact.data.capability, claims: {}, provenance: new Set() };
    addClaim(record.claims, 'status', fact.data.status, fact);
    addClaim(record.claims, 'freshnessSeconds', fact.data.freshnessSeconds, fact);
    addProvenance(record.provenance, fact.id);
    this.#capabilities.set(key, record);
  }

  snapshot() {
    const entities = [...this.#entities.values()].map((entity) => ({
      id: entity.id, key: entity.key, ...materializeClaims(entity.claims), firstSeen: entity.firstSeen, lastSeen: entity.lastSeen,
      provenance: [...entity.provenance].sort()
    })).filter((entity) => entity.present !== false).sort((a, b) => a.id.localeCompare(b.id));
    const entityId = new Map(entities.map((entity) => [entity.key, entity.id]));
    const relationships = [...this.#relationships.values()].filter((edge) => entityId.has(edge.from) && entityId.has(edge.to)).map((edge) => ({
      id: edge.id, from: entityId.get(edge.from), to: entityId.get(edge.to), fromKey: edge.from, toKey: edge.to,
      relation: edge.relation, attributes: materializeClaims(edge.claims), firstSeen: edge.firstSeen, lastSeen: edge.lastSeen,
      provenance: [...edge.provenance].sort()
    })).sort((a, b) => a.id.localeCompare(b.id));
    const capabilities = [...this.#capabilities.values()].filter((record) => entityId.has(record.entityKey)).map((record) => ({
      entityId: entityId.get(record.entityKey), entityKey: record.entityKey, capability: record.capability,
      ...materializeClaims(record.claims), provenance: [...record.provenance].sort()
    })).sort((a, b) => `${a.entityId}:${a.capability}`.localeCompare(`${b.entityId}:${b.capability}`));
    return { schemaVersion: 1, entities, relationships, capabilities };
  }

  static fromSnapshot(snapshot) {
    if (!snapshot || snapshot.schemaVersion !== 1) throw new Error('Unsupported graph snapshot');
    const graph = new SecurityGraph();
    for (const entity of snapshot.entities || []) {
      graph.#entities.set(entity.key, {
        id: entity.id, key: entity.key,
        claims: Object.fromEntries(Object.entries(entity).filter(([key]) => !['id', 'key', 'firstSeen', 'lastSeen', 'provenance'].includes(key)).map(([key, value]) => [key, [{ value, factId: entity.provenance[0] || 'snapshot', confidence: 1, observedAt: entity.lastSeen, source: { adapter: 'snapshot', instance: 'local', recordId: entity.id } }]])),
        provenance: new Set(entity.provenance || []), firstSeen: entity.firstSeen, lastSeen: entity.lastSeen
      });
    }
    for (const edge of snapshot.relationships || []) {
      const key = `${edge.fromKey}\0${edge.relation}\0${edge.toKey}`;
      graph.#relationships.set(key, { id: edge.id, from: edge.fromKey, to: edge.toKey, relation: edge.relation, claims: Object.fromEntries(Object.entries(edge.attributes || {}).map(([name, value]) => [name, [{ value, factId: edge.provenance[0] || 'snapshot', confidence: 1, observedAt: edge.lastSeen, source: { adapter: 'snapshot', instance: 'local', recordId: edge.id } }]])), provenance: new Set(edge.provenance || []), firstSeen: edge.firstSeen, lastSeen: edge.lastSeen });
    }
    for (const capability of snapshot.capabilities || []) {
      const key = `${capability.entityKey}\0${capability.capability}`;
      graph.#capabilities.set(key, { entityKey: capability.entityKey, capability: capability.capability, claims: { status: [{ value: capability.status, factId: capability.provenance[0] || 'snapshot', confidence: 1, observedAt: snapshot.generatedAt || new Date(0).toISOString(), source: { adapter: 'snapshot', instance: 'local', recordId: key } }] }, provenance: new Set(capability.provenance || []) });
    }
    return graph;
  }
}

module.exports = { GRAPH_LIMITS, SecurityGraph, compareClaims };

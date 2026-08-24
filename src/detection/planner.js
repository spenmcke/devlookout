'use strict';

function capabilityIndex(graphSnapshot) {
  const index = new Map();
  for (const item of graphSnapshot.capabilities || []) {
    if (!index.has(item.capability)) index.set(item.capability, []);
    index.get(item.capability).push(item);
  }
  return index;
}

function addToIndex(index, key, value) {
  if (!index.has(key)) index.set(key, []);
  index.get(key).push(value);
}

function buildPlannerIndex(graphSnapshot) {
  const entities = graphSnapshot.entities || [];
  const relationships = graphSnapshot.relationships || [];
  const capabilityRecords = graphSnapshot.capabilities || [];
  const entitiesByKey = new Map(entities.map((entity) => [entity.key, entity]));
  const capabilitiesByName = new Map();
  const capabilitiesByEntity = new Map();
  const coverageEdgesBySource = new Map();
  const serviceEndpoints = new Map();
  for (const [ordinal, record] of capabilityRecords.entries()) {
    addToIndex(capabilitiesByName, record.capability, record);
    if (!capabilitiesByEntity.has(record.entityKey)) capabilitiesByEntity.set(record.entityKey, new Map());
    addToIndex(capabilitiesByEntity.get(record.entityKey), record.capability, { ordinal, record });
  }
  for (const edge of relationships) {
    if (edge.relation === 'member_of') addToIndex(coverageEdgesBySource, edge.fromKey, edge.toKey);
    if (edge.relation === 'observes') addToIndex(coverageEdgesBySource, edge.toKey, edge.fromKey);
    if (edge.relation === 'observed_by') addToIndex(coverageEdgesBySource, edge.fromKey, edge.toKey);
    if (edge.relation === 'runs') {
      addToIndex(serviceEndpoints, edge.fromKey, edge.toKey);
      addToIndex(serviceEndpoints, edge.toKey, edge.fromKey);
    }
  }
  return { entities, entitiesByKey, capabilitiesByName, capabilitiesByEntity, coverageEdgesBySource, serviceEndpoints, coverageSourcesByEntity: new Map(), recordsByEntityAndCapability: new Map() };
}

function usable(records) {
  return Boolean(records?.some((record) => record.status === 'available' || record.status === 'degraded'));
}

const NETWORK_SCOPED_CAPABILITIES = new Set(['inventory', 'identity', 'network_policy', 'network_flow', 'route', 'dns', 'tls', 'configuration_change', 'sensor_health']);
const COVERAGE_ENTITY_TYPES = new Set(['endpoint', 'service', 'network', 'cloud_resource', 'data_resource']);

function coverageSources(graphSnapshot, entity, plannerIndex = buildPlannerIndex(graphSnapshot)) {
  const cached = plannerIndex.coverageSourcesByEntity.get(entity.key);
  if (cached) return cached;
  const sources = new Set([entity.key]);
  if (entity.type === 'service') {
    for (const endpoint of plannerIndex.serviceEndpoints.get(entity.key) || []) sources.add(endpoint);
  }
  const pending = [...sources];
  for (let index = 0; index < pending.length; index += 1) {
    for (const candidate of plannerIndex.coverageEdgesBySource.get(pending[index]) || []) {
      if (!sources.has(candidate)) {
        sources.add(candidate);
        pending.push(candidate);
      }
    }
  }
  plannerIndex.coverageSourcesByEntity.set(entity.key, sources);
  return sources;
}

function recordsForEntity(graphSnapshot, entity, capability, plannerIndex = buildPlannerIndex(graphSnapshot)) {
  if (!plannerIndex.recordsByEntityAndCapability.has(entity.key)) plannerIndex.recordsByEntityAndCapability.set(entity.key, new Map());
  const cache = plannerIndex.recordsByEntityAndCapability.get(entity.key);
  if (cache.has(capability)) return cache.get(capability);
  const matches = [];
  for (const sourceKey of coverageSources(graphSnapshot, entity, plannerIndex)) {
    const source = plannerIndex.entitiesByKey.get(sourceKey);
    if (sourceKey !== entity.key && source?.type !== 'telemetry' && source?.type !== 'endpoint' && !(source?.type === 'network' && NETWORK_SCOPED_CAPABILITIES.has(capability))) continue;
    matches.push(...(plannerIndex.capabilitiesByEntity.get(sourceKey)?.get(capability) || []));
  }
  const direct = matches.sort((left, right) => left.ordinal - right.ordinal).map(({ record }) => record);
  cache.set(capability, direct);
  return direct;
}

function requirementResult(requirements, records) {
  const requiredAll = [...(requirements.all || [])].sort();
  const oneOf = (requirements.oneOf || []).map((group) => [...group].sort());
  const optional = [...(requirements.optional || [])].sort();
  const missingRequired = requiredAll.filter((name) => !usable(records(name)));
  const unsatisfiedAlternatives = oneOf.filter((group) => !group.some((name) => usable(records(name))));
  const missingOptional = optional.filter((name) => !usable(records(name)));
  const degraded = [...requiredAll, ...oneOf.flat()].filter((name) => records(name)?.some((record) => record.status === 'degraded'));
  const state = missingRequired.length || unsatisfiedAlternatives.length ? 'blocked' : missingOptional.length || degraded.length ? 'degraded' : 'ready';
  return { state, missingRequired, unsatisfiedAlternatives, missingOptional, degradedCapabilities: [...new Set(degraded)].sort() };
}

function planAnalytics(analytics, graphSnapshot) {
  const plannerIndex = buildPlannerIndex(graphSnapshot);
  const capabilities = plannerIndex.capabilitiesByName;
  return [...analytics].sort((a, b) => a.id.localeCompare(b.id)).map((analytic) => {
    const requirements = analytic.requirements || {};
    const global = requirementResult(requirements, (name) => capabilities.get(name));
    const coverage = plannerIndex.entities.filter((entity) => COVERAGE_ENTITY_TYPES.has(entity.type)).map((entity) => ({
      entityKey: entity.key, entityType: entity.type,
      ...requirementResult(requirements, (name) => recordsForEntity(graphSnapshot, entity, name, plannerIndex))
    })).sort((a, b) => a.entityKey.localeCompare(b.entityKey));
    const covered = coverage.filter((item) => item.state !== 'blocked');
    const state = !coverage.length ? global.state : covered.length === 0 ? 'blocked' : covered.length === coverage.length && covered.every((item) => item.state === 'ready') ? 'ready' : 'partial';
    return {
      analyticId: analytic.id,
      state,
      deploy: coverage.length ? covered.length > 0 : global.state !== 'blocked',
      missingRequired: global.missingRequired,
      unsatisfiedAlternatives: global.unsatisfiedAlternatives,
      missingOptional: global.missingOptional,
      degradedCapabilities: global.degradedCapabilities,
      coverage,
      coveredEntityKeys: covered.map((item) => item.entityKey),
      gapEntityKeys: coverage.filter((item) => item.state === 'blocked').map((item) => item.entityKey)
    };
  });
}

module.exports = { NETWORK_SCOPED_CAPABILITIES, COVERAGE_ENTITY_TYPES, capabilityIndex, buildPlannerIndex, coverageSources, recordsForEntity, requirementResult, planAnalytics };

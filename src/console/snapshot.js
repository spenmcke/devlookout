'use strict';

const { stableId } = require('../core/canonical');
const { assertBoundedValue, assertNoSecretMaterial, ValidationError } = require('../core/validation');

const CONSOLE_LIMITS = Object.freeze({ entities: 256, relationships: 256, capabilities: 256, tagsPerEntity: 4, alerts: 64, incidents: 64, detections: 64, entityKeysPerSummary: 4, missingRequirementsPerDetection: 4 });
const TOPOLOGY_ENTITY_TYPES = new Set(['network', 'endpoint']);

function sortedUnique(values, limit = Infinity) { return [...new Set(values.filter((value) => typeof value === 'string' && value))].sort().slice(0, limit); }
function recentFirst(left, right) {
  const leftTime = Date.parse(left.lastSeen || left.firstSeen || '') || 0;
  const rightTime = Date.parse(right.lastSeen || right.firstSeen || '') || 0;
  return rightTime - leftTime || String(left.key || left.id || '').localeCompare(String(right.key || right.id || ''));
}

function hasManagedTelemetry(entityKey, capabilities) {
  return capabilities.some((record) => record.entityKey === entityKey
    && record.capability === 'sensor_health'
    && ['available', 'degraded'].includes(record.status));
}

function selectGraph(graph) {
  const source = { entities: Array.isArray(graph.entities) ? graph.entities : [], relationships: Array.isArray(graph.relationships) ? graph.relationships : [], capabilities: Array.isArray(graph.capabilities) ? graph.capabilities : [] };
  const entities = [...source.entities]
    .sort((left, right) => Number(TOPOLOGY_ENTITY_TYPES.has(right.type)) - Number(TOPOLOGY_ENTITY_TYPES.has(left.type)) || recentFirst(left, right))
    .slice(0, CONSOLE_LIMITS.entities)
    .map((entity) => ({
      key: entity.key, type: entity.type, name: entity.name, role: entity.role || null,
      platform: entity.platform || null, tags: sortedUnique(entity.tags || [], CONSOLE_LIMITS.tagsPerEntity),
      managed: entity.type === 'endpoint' ? hasManagedTelemetry(entity.key, source.capabilities) : undefined,
      lastSeen: entity.lastSeen
    }));
  const entityKeys = new Set(entities.map((entity) => entity.key));
  const relationships = source.relationships.filter((edge) => entityKeys.has(edge.fromKey) && entityKeys.has(edge.toKey)).slice(0, CONSOLE_LIMITS.relationships).map((edge) => ({ fromKey: edge.fromKey, toKey: edge.toKey, relation: edge.relation }));
  const capabilities = source.capabilities.filter((record) => entityKeys.has(record.entityKey)).slice(0, CONSOLE_LIMITS.capabilities).map((record) => ({ entityKey: record.entityKey, capability: record.capability, status: record.status }));
  const sourceCounts = Object.fromEntries(Object.entries(source).map(([key, values]) => [key, values.length]));
  const publishedCounts = { entities: entities.length, relationships: relationships.length, capabilities: capabilities.length };
  return { entities, relationships, capabilities, selection: { strategy: 'topology_then_recent', sourceCounts, publishedCounts, truncated: Object.keys(sourceCounts).some((key) => sourceCounts[key] > publishedCounts[key]) } };
}

function buildConsoleSnapshot({ graph, cases, detectionPlan, analytics = [], status, generatedAt = new Date().toISOString(), deploymentId = 'local' } = {}) {
  if (!graph || !cases || !Array.isArray(detectionPlan) || !status) throw new Error('Console snapshot requires graph, cases, detection plan, and status');
  if (Number.isNaN(Date.parse(generatedAt)) || typeof deploymentId !== 'string' || !deploymentId || deploymentId.length > 256) throw new Error('Console snapshot identity is invalid');
  const selectedGraph = selectGraph(graph);
  const ruleById = new Map(analytics.map((rule) => [rule.id, rule]));
  const payload = {
    schemaVersion: 1,
    kind: 'lookout_console_snapshot',
    generatedAt,
    deploymentId,
    graph: selectedGraph,
    alerts: [...(cases.alerts || [])].sort(recentFirst).slice(0, CONSOLE_LIMITS.alerts).map((alert) => ({
      id: alert.id, ruleId: alert.ruleId, title: alert.title, severity: alert.severity, status: alert.status,
      time: alert.time || alert.lastSeen || alert.firstSeen, firstSeen: alert.firstSeen, lastSeen: alert.lastSeen,
      entities: sortedUnique(alert.entities || [], CONSOLE_LIMITS.entityKeysPerSummary), evidenceCount: (alert.evidence || []).length,
      confidence: typeof alert.confidence === 'number' ? alert.confidence : null,
      matchReason: typeof alert.matchReason === 'string' && alert.matchReason ? alert.matchReason : null,
      statusHistory: (alert.statusHistory || []).slice(-32).map((entry) => ({ status: entry.status, actor: entry.actor, at: entry.at, ...(entry.reason ? { reason: entry.reason } : {}) }))
    })),
    incidents: [...(cases.incidents || [])].sort(recentFirst).slice(0, CONSOLE_LIMITS.incidents).map((incident) => ({ id: incident.id, title: incident.title, severity: incident.severity, status: incident.status, firstSeen: incident.firstSeen, lastSeen: incident.lastSeen, entities: sortedUnique(incident.entities || [], CONSOLE_LIMITS.entityKeysPerSummary), findingCount: (incident.findings || []).length })),
    detections: detectionPlan.slice(0, CONSOLE_LIMITS.detections).map((item) => ({ analyticId: item.analyticId, title: ruleById.get(item.analyticId)?.title || item.title || item.analyticId, severity: ruleById.get(item.analyticId)?.severity || item.severity || null, deploy: item.deploy !== false && item.state !== 'blocked', state: item.state, coveredEntityKeys: sortedUnique(item.coveredEntityKeys || [], CONSOLE_LIMITS.entityKeysPerSummary), gapEntityKeys: sortedUnique(item.gapEntityKeys || [], CONSOLE_LIMITS.entityKeysPerSummary), missingRequired: sortedUnique(item.missingRequired || [], CONSOLE_LIMITS.missingRequirementsPerDetection) })),
    selection: { limits: CONSOLE_LIMITS, sourceCounts: { alerts: (cases.alerts || []).length, incidents: (cases.incidents || []).length, detections: detectionPlan.length }, publishedCounts: { alerts: Math.min((cases.alerts || []).length, CONSOLE_LIMITS.alerts), incidents: Math.min((cases.incidents || []).length, CONSOLE_LIMITS.incidents), detections: Math.min(detectionPlan.length, CONSOLE_LIMITS.detections) } },
    health: { status: status.status, graph: status.graph, detections: status.detections, cases: status.cases, memory: status.memory || null, storage: status.storage || null, cloudExport: status.cloudExport?.enabled ? { enabled: true, pending: status.cloudExport.pending, lastDeliveryAt: status.cloudExport.lastDeliveryAt, lastErrorAt: status.cloudExport.lastErrorAt } : { enabled: false } }
  };
  const snapshot = { ...payload, id: stableId('console_snapshot', payload) };
  return validateConsoleSnapshot(snapshot);
}

function buildUninstalledConsoleSnapshot({ generatedAt = new Date().toISOString(), deploymentId } = {}) {
  if (Number.isNaN(Date.parse(generatedAt)) || typeof deploymentId !== 'string' || !deploymentId || deploymentId.length > 256) throw new Error('Console snapshot identity is invalid');
  const payload = {
    schemaVersion: 1,
    kind: 'lookout_console_snapshot',
    generatedAt,
    deploymentId,
    graph: { entities: [], relationships: [], capabilities: [], selection: { strategy: 'uninstalled', sourceCounts: { entities: 0, relationships: 0, capabilities: 0 }, publishedCounts: { entities: 0, relationships: 0, capabilities: 0 }, truncated: false } },
    alerts: [],
    incidents: [],
    detections: [],
    selection: { limits: CONSOLE_LIMITS, sourceCounts: { alerts: 0, incidents: 0, detections: 0 }, publishedCounts: { alerts: 0, incidents: 0, detections: 0 } },
    health: { status: 'uninstalled', graph: {}, detections: {}, cases: {}, cloudExport: { enabled: false } }
  };
  return validateConsoleSnapshot({ ...payload, id: stableId('console_snapshot', payload) });
}

function validateConsoleSnapshot(snapshot) {
  const issues = [];
  assertBoundedValue(snapshot, '$', issues);
  assertNoSecretMaterial(snapshot, '$', issues);
  if (!snapshot || snapshot.schemaVersion !== 1 || snapshot.kind !== 'lookout_console_snapshot' || typeof snapshot.id !== 'string' || !snapshot.id) issues.push('$ must be a Lookout console snapshot');
  if (!snapshot.graph || !Array.isArray(snapshot.graph.entities) || !Array.isArray(snapshot.graph.relationships) || !Array.isArray(snapshot.graph.capabilities)) issues.push('$.graph is invalid');
  if (!Array.isArray(snapshot.alerts) || !Array.isArray(snapshot.incidents) || !Array.isArray(snapshot.detections)) issues.push('$ case and detection summaries are invalid');
  if (issues.length) throw new ValidationError('Invalid console snapshot', issues);
  return snapshot;
}

module.exports = { CONSOLE_LIMITS, buildConsoleSnapshot, buildUninstalledConsoleSnapshot, validateConsoleSnapshot };

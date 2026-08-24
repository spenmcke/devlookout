'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { planAnalytics } = require('../src/detection/planner');
const { buildConsoleSnapshot, validateConsoleSnapshot, CONSOLE_LIMITS } = require('../src/console/snapshot');
const { LookoutRuntime } = require('../src/runtime');

test('planner indexes each graph collection once for a large rule set', () => {
  const source = {
    entities: [{ key: 'endpoint:a', type: 'endpoint' }, { key: 'network:a', type: 'network' }],
    relationships: [{ fromKey: 'endpoint:a', toKey: 'network:a', relation: 'member_of' }],
    capabilities: [{ entityKey: 'endpoint:a', capability: 'authentication', status: 'available' }]
  };
  const reads = { entities: 0, relationships: 0, capabilities: 0 };
  const graph = {};
  for (const name of Object.keys(reads)) Object.defineProperty(graph, name, { get() { reads[name] += 1; return source[name]; } });
  const analytics = Array.from({ length: 100 }, (_, index) => ({ id: `rule-${index}`, requirements: { all: ['authentication'] } }));
  assert.equal(planAnalytics(analytics, graph).length, 100);
  assert.deepEqual(reads, { entities: 1, relationships: 1, capabilities: 1 });
});

test('console snapshot bounds inventory while preserving topology and referential integrity', () => {
  const endpoint = { key: 'endpoint:a', type: 'endpoint', name: 'VM A', lastSeen: '2026-08-20T12:00:00.000Z' };
  const network = { key: 'network:a', type: 'network', name: 'Private network' };
  const software = Array.from({ length: 1000 }, (_, index) => ({ key: `software:${index}`, type: 'software', name: `Package ${index}`, lastSeen: '2026-08-20T12:01:00.000Z' }));
  const snapshot = buildConsoleSnapshot({
    graph: { entities: [endpoint, network, ...software], relationships: [{ fromKey: endpoint.key, toKey: network.key, relation: 'member_of' }], capabilities: software.map((item) => ({ entityKey: item.key, capability: 'inventory', status: 'available' })) },
    cases: { alerts: [], incidents: [] }, detectionPlan: [],
    status: { status: 'ok', graph: {}, detections: {}, cases: {}, cloudExport: { enabled: false } },
    deploymentId: 'dpl_test', generatedAt: '2026-08-20T12:00:00.000Z'
  });
  assert.equal(snapshot.graph.entities.length, CONSOLE_LIMITS.entities);
  assert.deepEqual(snapshot.graph.entities.slice(0, 2).map((item) => item.key).sort(), ['endpoint:a', 'network:a']);
  assert.deepEqual(snapshot.graph.relationships, [{ fromKey: 'endpoint:a', toKey: 'network:a', relation: 'member_of' }]);
  assert.equal(snapshot.graph.selection.truncated, true);
  assert.equal(validateConsoleSnapshot(snapshot), snapshot);
});

test('status and console snapshot calculate one detection plan each', async () => {
  const runtime = new LookoutRuntime({ dataDirectory: '/tmp/lookout-performance-test' });
  runtime.graph = { snapshot: () => ({ entities: [], relationships: [], capabilities: [] }) };
  runtime.cases = { snapshot: () => ({ findings: [], alerts: [], incidents: [] }) };
  let calls = 0;
  runtime.detectionPlan = () => { calls += 1; return [{ analyticId: 'ready', state: 'ready', coveredEntityKeys: [], gapEntityKeys: [], missingRequired: [] }]; };
  await runtime.status();
  assert.equal(calls, 1);
  calls = 0;
  await runtime.consoleSnapshot({ deploymentId: 'dpl_test' });
  assert.equal(calls, 1);
});

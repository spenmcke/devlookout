'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { AdapterRegistry } = require('../src/adapters/contract');
const { declarationAdapter } = require('../src/adapters/declaration');
const { tailscaleAdapter } = require('../src/adapters/tailscale');
const { SecurityGraph } = require('../src/graph/security-graph');
const { planAnalytics } = require('../src/detection/planner');
const { analytics } = require('../src/detection/catalog');

const observedAt = '2026-08-17T20:00:00.000Z';

test('declaration adapter models otherwise uninstrumented systems', async () => {
  const adapter = declarationAdapter({
    entities: [{ key: 'appliance:1', type: 'endpoint', name: 'Printer', attributes: { platform: 'embedded' } }],
    capabilities: [{ entityKey: 'appliance:1', capability: 'inventory', status: 'available' }]
  });
  const facts = await new AdapterRegistry().register(adapter).survey('declaration', { observedAt });
  const snapshot = new SecurityGraph().apply(facts).snapshot();
  assert.equal(snapshot.entities[0].name, 'Printer');
  assert.equal(snapshot.capabilities[0].capability, 'inventory');
});

test('tailscale adapter emits identities, devices, tags, routes, policy, and capability state', async () => {
  const client = {
    listDevices: async () => ({ devices: [{ id: 'node-1', name: 'vm.example.ts.net.', os: 'linux', addresses: ['100.64.0.1'], user: 'user-1', tags: ['tag:server'], advertisedRoutes: ['10.0.0.0/24'], enabledRoutes: ['10.0.0.0/24'], authorized: true }] }),
    listUsers: async () => ({ users: [{ id: 'user-1', loginName: 'owner@example.com', displayName: 'Owner', role: 'owner', status: 'active' }] }),
    getPolicy: async () => ({ grants: [{ src: ['owner@example.com'], dst: ['tag:server'], ip: ['*'] }], tests: [{}], tagOwners: { 'tag:server': ['owner@example.com'] } })
  };
  const adapter = tailscaleAdapter({ client, tailnet: '-' });
  const facts = await new AdapterRegistry().register(adapter).survey('tailscale', { observedAt });
  const snapshot = new SecurityGraph().apply(facts).snapshot();
  assert.equal(snapshot.entities.find((item) => item.type === 'network').name, 'Tailnet');
  assert.ok(snapshot.entities.some((item) => item.type === 'endpoint' && item.platform === 'linux'));
  assert.ok(snapshot.entities.some((item) => item.type === 'identity' && item.identityKind === 'device_tag'));
  assert.ok(snapshot.entities.some((item) => item.type === 'route'));
  assert.ok(snapshot.entities.some((item) => item.type === 'control' && item.policyDigest));
  assert.ok(snapshot.relationships.some((item) => item.relation === 'owns'));
});

test('capability planner blocks unsupported analytics without hiding optional gaps', async () => {
  const adapter = declarationAdapter({
    entities: [{ key: 'sensor:1', type: 'telemetry', name: 'Sensor' }],
    capabilities: [
      { entityKey: 'sensor:1', capability: 'network_flow', status: 'available' },
      { entityKey: 'sensor:1', capability: 'process_execution', status: 'degraded' }
    ]
  });
  const graph = new SecurityGraph().apply(await new AdapterRegistry().register(adapter).survey('declaration', { observedAt })).snapshot();
  const plan = planAnalytics([
    { id: 'a-ready', requirements: { all: ['network_flow'] } },
    { id: 'b-alternative', requirements: { all: ['network_flow'], oneOf: [['service_auth', 'process_execution']], optional: ['dns'] } },
    { id: 'c-blocked', requirements: { all: ['authentication'] } }
  ], graph);
  assert.equal(plan.find((item) => item.analyticId === 'a-ready').state, 'ready');
  assert.equal(plan.find((item) => item.analyticId === 'b-alternative').state, 'degraded');
  assert.equal(plan.find((item) => item.analyticId === 'c-blocked').deploy, false);
  assert.deepEqual(plan.find((item) => item.analyticId === 'c-blocked').missingRequired, ['authentication']);
});

test('native new or unapproved access rule deploys without graph capability claims', () => {
  const rule = analytics.find((item) => item.id === 'new-or-unapproved-access');
  const plan = planAnalytics([rule], { capabilities: [] });
  assert.equal(plan[0].state, 'ready');
  assert.equal(plan[0].deploy, true);
  assert.deepEqual(plan[0].missingRequired, []);
});

test('coverage is calculated per endpoint and does not spread host telemetry across the fleet', async () => {
  const adapter = declarationAdapter({
    entities: [
      { key: 'endpoint:covered', type: 'endpoint', name: 'Covered host' },
      { key: 'endpoint:gap', type: 'endpoint', name: 'Uncovered host' }
    ],
    capabilities: [{ entityKey: 'endpoint:covered', capability: 'process_execution', status: 'available' }]
  });
  const graph = new SecurityGraph().apply(await new AdapterRegistry().register(adapter).survey('declaration', { observedAt })).snapshot();
  const [plan] = planAnalytics([{ id: 'host-execution', requirements: { all: ['process_execution'] } }], graph);
  assert.equal(plan.state, 'partial');
  assert.equal(plan.deploy, true);
  assert.deepEqual(plan.coveredEntityKeys, ['endpoint:covered']);
  assert.deepEqual(plan.gapEntityKeys, ['endpoint:gap']);
});

test('network capabilities propagate only through membership while host capabilities reach hosted services', async () => {
  const adapter = declarationAdapter({
    entities: [
      { key: 'network:one', type: 'network', name: 'Network' },
      { key: 'endpoint:one', type: 'endpoint', name: 'Host' },
      { key: 'service:one', type: 'service', name: 'Service' }
    ],
    relationships: [
      { from: 'endpoint:one', to: 'network:one', relation: 'member_of' },
      { from: 'endpoint:one', to: 'service:one', relation: 'runs' }
    ],
    capabilities: [
      { entityKey: 'network:one', capability: 'network_flow', status: 'available' },
      { entityKey: 'endpoint:one', capability: 'process_execution', status: 'available' }
    ]
  });
  const graph = new SecurityGraph().apply(await new AdapterRegistry().register(adapter).survey('declaration', { observedAt })).snapshot();
  const plan = planAnalytics([
    { id: 'flows', requirements: { all: ['network_flow'] } },
    { id: 'execution', requirements: { all: ['process_execution'] } }
  ], graph);
  assert.ok(plan.find((item) => item.analyticId === 'flows').coveredEntityKeys.includes('endpoint:one'));
  assert.ok(plan.find((item) => item.analyticId === 'execution').coveredEntityKeys.includes('service:one'));
  assert.ok(!plan.find((item) => item.analyticId === 'execution').coveredEntityKeys.includes('network:one'));
});

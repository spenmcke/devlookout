'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { once } = require('node:events');
const { LookoutRuntime } = require('../src/runtime');
const { AdapterRegistry } = require('../src/adapters/contract');
const { declarationAdapter } = require('../src/adapters/declaration');
const { createEvent } = require('../src/events/schema');
const { createServer } = require('../src/server');
const { generateApiToken, ApiAuthenticator } = require('../src/security/auth');
const { CollectorEnrollmentAuthority, createCollectorEnrollmentRequest } = require('../src/collector/enrollment');
const { CollectorRegistry } = require('../src/collector/registry');
const { signPayload } = require('../src/collector/envelope');

async function runtimeFixture() {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-runtime-'));
  const runtime = await new LookoutRuntime({ dataDirectory: directory }).initialize();
  const adapter = declarationAdapter({
    entities: [{ key: 'sensor:host', type: 'telemetry', name: 'Host sensor' }],
    capabilities: [
      { entityKey: 'sensor:host', capability: 'authentication', status: 'available' },
      { entityKey: 'sensor:host', capability: 'process_execution', status: 'available' },
      { entityKey: 'sensor:host', capability: 'sensor_health', status: 'available' },
      { entityKey: 'sensor:host', capability: 'configuration_change', status: 'available' }
    ]
  });
  await runtime.applySurveyFacts(await new AdapterRegistry().register(adapter).survey('declaration', { observedAt: '2026-08-17T20:00:00.000Z' }));
  return { directory, runtime };
}

function normalized(recordId, time, outcome = 'failure') {
  return createEvent({ time, ingestedAt: time, category: 'identity', class: 'authentication', activity: 'logon', outcome, source: { adapter: 'fixture', instance: 'site', recordId }, entityKeys: ['endpoint:client', 'endpoint:server'], sourceEndpoint: { id: 'endpoint:client' }, destinationEndpoint: { id: 'endpoint:server' }, attributes: {} });
}

test('runtime persists graph, events, and detection state across restart', async () => {
  const { directory, runtime } = await runtimeFixture();
  try {
    const events = Array.from({ length: 12 }, (_, index) => normalized(`auth-${index}`, `2026-08-17T20:00:${String(index).padStart(2, '0')}.000Z`));
    const result = await runtime.ingest(events);
    assert.equal(result.accepted.length, 12);
    assert.ok(result.alerts.some((alert) => alert.title === 'Repeated authentication failures from one source'));
    const restarted = await new LookoutRuntime({ dataDirectory: directory }).initialize();
    assert.equal((await restarted.status()).graph.entities, 2);
    assert.ok(restarted.graph.snapshot().entities.some((entity) => entity.key === 'telemetry:fixture:site'));
    assert.ok((await restarted.status()).cases.alerts >= 1);
    assert.equal((await restarted.eventStore.query()).length, 12);
  } finally { await fs.rm(directory, { recursive: true, force: true }); }
});

test('versioned API requires configured bearer token', async () => {
  const { directory, runtime } = await runtimeFixture();
  const server = createServer({ runtime, apiToken: 'test-token-value' });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const { port } = server.address();
  try {
    const unauthorized = await fetch(`http://127.0.0.1:${port}/api/v1/graph`);
    assert.equal(unauthorized.status, 401);
    const authorized = await fetch(`http://127.0.0.1:${port}/api/v1/graph`, { headers: { Authorization: 'Bearer test-token-value' } });
    assert.equal(authorized.status, 200);
    assert.equal((await authorized.json()).entities.length, 1);
    const identity = await fetch(`http://127.0.0.1:${port}/api/v1/me`, { headers: { Authorization: 'Bearer test-token-value' } });
    assert.equal(identity.status, 200);
    assert.deepEqual(await identity.json(), { id: 'legacy-api-token', displayName: null, loginName: null, roles: ['admin'], authentication: 'bearer' });
    const health = await fetch(`http://127.0.0.1:${port}/health`);
    assert.equal(health.status, 200);
    assert.equal((await health.json()).releaseVersion, `v${require('../package.json').version}`);
  } finally {
    server.close(); await once(server, 'close');
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('collector-scoped credentials cannot submit for another collector identity', async () => {
  const { directory, runtime } = await runtimeFixture();
  let registryCalled = false;
  const authenticator = {
    authenticate: () => ({ id: 'collector:one', collectorId: 'collector-one', roles: ['collector'] }),
    authorize: () => true
  };
  const collectorRegistry = { accept: async () => { registryCalled = true; throw new Error('must not verify mismatched identity'); } };
  const server = createServer({ runtime, authenticator, collectorRegistry });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const { port } = server.address();
  try {
    const response = await fetch(`http://127.0.0.1:${port}/api/v1/collector/submissions`, {
      method: 'POST', headers: { Authorization: 'Bearer endpoint-token', 'Content-Type': 'application/json' },
      body: JSON.stringify({ algorithm: 'Ed25519', payload: { collectorId: 'collector-two' }, signature: 'invalid' })
    });
    assert.equal(response.status, 403);
    assert.equal(registryCalled, false);
    const audit = await runtime.auditStore.query();
    assert.ok(audit.some((event) => event.activity === 'collector.submit' && event.outcome === 'failure' && event.actor.id === 'collector:one'));
  } finally {
    server.close(); await once(server, 'close');
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('asset-bound enrollment dynamically registers collectors and binds bearer to signed identity', async () => {
  const { directory, runtime } = await runtimeFixture();
  const authority = await new CollectorEnrollmentAuthority({ dataDirectory: directory }).initialize();
  const registry = await new CollectorRegistry({ dataDirectory: directory }).initialize();
  const roleAuthorizer = new ApiAuthenticator();
  const authenticator = {
    authenticate(req) { return authority.authenticateBearer(req.headers.authorization); },
    authorize(principal, permission) { return roleAuthorizer.authorize(principal, permission); }
  };
  const server = createServer({ runtime, authenticator, collectorRegistry: registry, enrollmentAuthority: authority });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const { port } = server.address();
  try {
    const bundles = [];
    for (const assetId of ['site/host-a', 'site/host-b']) {
      const invitation = await authority.issueInvitation({ assetId, deploymentId: 'fleet-test' });
      const bundle = createCollectorEnrollmentRequest(invitation.token, { assetId, deploymentId: 'fleet-test' });
      bundles.push(bundle);
      const enrolled = await fetch(`http://127.0.0.1:${port}/api/v1/collector/enroll`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(bundle.request) });
      assert.equal(enrolled.status, 201);
    }
    const payload = { schemaVersion: 1, collectorId: bundles[0].private.collectorId, sequence: 1, collectedAt: new Date().toISOString(), facts: [], events: [] };
    const envelope = signPayload(payload, bundles[0].private.privateKeyPem);
    const mismatched = await fetch(`http://127.0.0.1:${port}/api/v1/collector/submissions`, { method: 'POST', headers: { Authorization: `Bearer ${bundles[1].private.submissionToken}`, 'Content-Type': 'application/json' }, body: JSON.stringify(envelope) });
    assert.equal(mismatched.status, 403);
    const accepted = await fetch(`http://127.0.0.1:${port}/api/v1/collector/submissions`, { method: 'POST', headers: { Authorization: `Bearer ${bundles[0].private.submissionToken}`, 'Content-Type': 'application/json' }, body: JSON.stringify(envelope) });
    assert.equal(accepted.status, 202);
  } finally {
    server.close(); await once(server, 'close');
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('raw ingestion endpoint normalizes Zeek records before storage', async () => {
  const { directory, runtime } = await runtimeFixture();
  const server = createServer({ runtime, apiToken: 'test-token-value' });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const { port } = server.address();
  try {
    const response = await fetch(`http://127.0.0.1:${port}/api/v1/ingest/zeek?logType=conn`, { method: 'POST', headers: { Authorization: 'Bearer test-token-value', 'Content-Type': 'application/json' }, body: JSON.stringify([{ ts: 1787011200, uid: 'flow-raw', 'id.orig_h': '10.0.0.1', 'id.resp_h': '10.0.0.2', proto: 'tcp', conn_state: 'SF' }]) });
    assert.equal(response.status, 202);
    const stored = await runtime.eventStore.query();
    assert.equal(stored.find((event) => event.correlation.flowId === 'flow-raw').correlation.flowId, 'flow-raw');
  } finally {
    server.close(); await once(server, 'close');
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('raw telemetry is attributed only to graph assets it actually observes', async () => {
  const { directory, runtime } = await runtimeFixture();
  try {
    const adapter = declarationAdapter({ entities: [{ key: 'endpoint:known-host', type: 'endpoint', name: 'Known host' }, { key: 'endpoint:unobserved-host', type: 'endpoint', name: 'Unobserved host' }] });
    await runtime.applySurveyFacts(await new AdapterRegistry().register(adapter).survey('declaration', { observedAt: '2026-08-18T00:00:00.000Z' }));
    await runtime.ingestRaw('opentelemetry-log', [{ Timestamp: '1787011200000000000', EventName: 'process', Resource: { 'host.id': 'known-host' }, Attributes: { 'security.category': 'system', 'security.class': 'process_activity', 'security.activity': 'start', executable: '/usr/bin/true' } }], { receivedAt: '2026-08-18T00:00:00.000Z', instance: 'host-sensor' });
    const relationships = runtime.graph.snapshot().relationships;
    assert.ok(relationships.some((relationship) => relationship.fromKey === 'telemetry:opentelemetry-log:host-sensor' && relationship.toKey === 'endpoint:known-host' && relationship.relation === 'observes'));
    assert.equal(relationships.some((relationship) => relationship.toKey === 'endpoint:unobserved-host' && relationship.relation === 'observes'), false);
  } finally { await fs.rm(directory, { recursive: true, force: true }); }
});

test('authenticated Lookout control-plane reads do not create detection feedback', async () => {
  const { directory, runtime } = await runtimeFixture();
  const server = createServer({ runtime, apiToken: 'test-token-value', approvedSourceAddresses: [] });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const { port } = server.address();
  try {
    const response = await fetch(`http://127.0.0.1:${port}/api/v1/graph`, { headers: { Authorization: 'Bearer test-token-value' } });
    assert.equal(response.status, 200);
    const access = (await runtime.eventStore.query()).find((event) => event.source.adapter === 'lookout-service-auth');
    assert.equal(access, undefined);
  } finally {
    server.close(); await once(server, 'close');
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('Sigma imports persist across runtime restart', async () => {
  const { directory, runtime } = await runtimeFixture();
  try {
    const { parseSigmaYaml } = require('../src/detection/sigma');
    const [rule] = parseSigmaYaml('title: Imported Process Rule\nid: imported-rule-1\nlogsource:\n  category: process_creation\ndetection:\n  selection:\n    Image|endswith: /custom-tool\n  condition: selection\nlevel: high\n');
    await runtime.importAnalytics([rule]);
    const restarted = await new LookoutRuntime({ dataDirectory: directory }).initialize();
    assert.ok(restarted.analytics.some((item) => item.id === 'imported-rule-1'));
    assert.equal(restarted.detectionPlan().find((item) => item.analyticId === 'imported-rule-1').state, 'ready');
  } finally { await fs.rm(directory, { recursive: true, force: true }); }
});

test('API RBAC denies mutation to viewers and records security audit events', async () => {
  const { directory, runtime } = await runtimeFixture();
  const viewer = generateApiToken();
  const authenticator = new ApiAuthenticator({ credentials: [{ id: 'viewer', tokenHash: viewer.hash, roles: ['viewer'] }] });
  const server = createServer({ runtime, authenticator });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const { port } = server.address();
  try {
    const allowed = await fetch(`http://127.0.0.1:${port}/api/v1/graph`, { headers: { Authorization: `Bearer ${viewer.token}` } });
    assert.equal(allowed.status, 200);
    const denied = await fetch(`http://127.0.0.1:${port}/api/v1/events`, { method: 'POST', headers: { Authorization: `Bearer ${viewer.token}`, 'Content-Type': 'application/json' }, body: '[]' });
    assert.equal(denied.status, 403);
    const audit = await runtime.auditStore.query();
    assert.ok(audit.some((event) => event.activity === 'api.authorize' && event.outcome === 'failure' && event.actor.id === 'viewer'));
  } finally {
    server.close(); await once(server, 'close');
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('SaaS console credential can read the summary projection but not local event logs', async () => {
  const { directory, runtime } = await runtimeFixture();
  const credential = generateApiToken();
  const authenticator = new ApiAuthenticator({ credentials: [{ id: 'saas-console', tokenHash: credential.hash, roles: ['console'] }] });
  const server = createServer({ runtime, authenticator });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const { port } = server.address();
  try {
    const headers = { Authorization: `Bearer ${credential.token}` };
    const summary = await fetch(`http://127.0.0.1:${port}/api/v1/console-snapshot`, { headers });
    assert.equal(summary.status, 200);
    const projection = await summary.json();
    assert.equal(projection.kind, 'lookout_console_snapshot');
    assert.equal(Object.hasOwn(projection, 'events'), false);
    assert.equal((await fetch(`http://127.0.0.1:${port}/api/v1/events`, { headers })).status, 403);
  } finally {
    server.close(); await once(server, 'close');
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('failed authorized mutations are audited without leaking internal errors', async () => {
  const { directory, runtime } = await runtimeFixture();
  const administrator = generateApiToken();
  const authenticator = new ApiAuthenticator({ credentials: [{ id: 'administrator', tokenHash: administrator.hash, roles: ['admin'] }] });
  const server = createServer({ runtime, authenticator });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const { port } = server.address();
  try {
    const response = await fetch(`http://127.0.0.1:${port}/api/v1/rules/import/sigma`, { method: 'POST', headers: { Authorization: `Bearer ${administrator.token}`, 'Content-Type': 'text/plain' }, body: 'not: [valid' });
    assert.equal(response.status, 400);
    assert.equal(typeof (await response.json()).error, 'string');
    const audit = await runtime.auditStore.query();
    assert.ok(audit.some((event) => event.activity === 'rules.import' && event.outcome === 'failure' && event.actor.id === 'administrator'));
  } finally {
    server.close(); await once(server, 'close');
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('runtime applies separate event and audit retention windows', async () => {
  const { directory, runtime } = await runtimeFixture();
  try {
    await runtime.ingest([normalized('old-event', '2026-01-01T00:00:00.000Z'), normalized('new-event', '2026-08-16T00:00:00.000Z')]);
    await runtime.recordAudit({ principal: 'tester', action: 'old', target: 'test', outcome: 'success' });
    const result = await runtime.compactRetention({ eventRetentionDays: 14, auditRetentionDays: 365, now: new Date('2026-08-17T00:00:00.000Z') });
    assert.equal(result.events.removed, 1);
    assert.equal(result.events.retained, 1);
    assert.equal(result.audit.retained, 1);
    assert.equal(runtime.processedThroughSequence, 1);
  } finally { await fs.rm(directory, { recursive: true, force: true }); }
});

test('stored events are replayed when derived detection state persistence fails', async () => {
  const { directory, runtime } = await runtimeFixture();
  const events = Array.from({ length: 12 }, (_, index) => normalized(`replay-${index}`, `2026-08-17T20:00:${String(index).padStart(2, '0')}.000Z`));
  const save = runtime.detectionStateStore.save.bind(runtime.detectionStateStore);
  try {
    runtime.detectionStateStore.save = async () => { throw new Error('derived state unavailable'); };
    await assert.rejects(() => runtime.ingest(events), /derived state unavailable/);
    assert.equal((await runtime.eventStore.query()).length, 12);
    runtime.detectionStateStore.save = save;
    const replayed = await runtime.ingest(events);
    assert.equal(replayed.accepted.length, 0);
    assert.ok(replayed.alerts.some((alert) => alert.title === 'Repeated authentication failures from one source'));
    const restarted = await new LookoutRuntime({ dataDirectory: directory }).initialize();
    assert.ok((await restarted.status()).cases.alerts >= 1);
  } finally {
    runtime.detectionStateStore.save = save;
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('cloud export failure never prevents local persistence or detection processing', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-runtime-export-'));
  const cloudExport = {
    outbox: { initialize: async () => {}, stats: () => ({ pending: 0 }) },
    enqueue: async () => { throw new Error('cloud unavailable'); },
    flush: async () => { throw new Error('cloud unavailable'); }
  };
  try {
    const runtime = await new LookoutRuntime({ dataDirectory: directory, cloudExport }).initialize();
    const event = normalized('local-first', '2026-08-17T20:00:00.000Z');
    const result = await runtime.ingest([event]);
    assert.deepEqual(result.accepted, [event.id]);
    assert.equal((await runtime.eventStore.query()).length, 1);
    assert.match((await runtime.status()).cloudExport.lastError, /cloud unavailable/);
    await assert.rejects(() => runtime.flushCloudExport(), /cloud unavailable/);
    assert.equal((await runtime.eventStore.query()).length, 1);
  } finally { await fs.rm(directory, { recursive: true, force: true }); }
});

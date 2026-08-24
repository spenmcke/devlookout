'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { Readable } = require('node:stream');
const { SetupSessionAuthority } = require('../src/onboarding/setup-session-authority');
const { SaasConsoleStore } = require('../src/console/saas-store');
const { createHostedSaasApi } = require('../src/hosting/saas-api');
const { createProofMessage } = require('../src/onboarding/setup-session-client');
const { CliAuthorizationAuthority } = require('../src/onboarding/cli-authorization-authority');
const { batchIdFor } = require('../src/export/service');

function memoryStore() { let value = null; return { load: async () => structuredClone(value), save: async (next) => { value = structuredClone(next); } }; }
function request(method, path, body, headers = {}, principal = null) {
  const bytes = body === undefined ? Buffer.alloc(0) : Buffer.from(JSON.stringify(body));
  const req = Readable.from(bytes.length ? [bytes] : []);
  req.method = method; req.url = path; req.headers = { ...headers }; req.testPrincipal = principal;
  if (body !== undefined) { req.headers['content-type'] = 'application/json'; req.headers['content-length'] = String(bytes.length); }
  return req;
}
function response() { return { status: null, headers: {}, body: '', writeHead(status, headers) { this.status = status; this.headers = headers; }, end(body) { this.body = Buffer.isBuffer(body) ? body.toString() : String(body || ''); }, json() { return JSON.parse(this.body); } }; }
async function invoke(handler, req) { const res = response(); assert.equal(await handler(req, res, new URL(req.url, 'https://app.example')), true); return res; }
function operationalNode(collectorId, observedAt) {
  return {
    collectorSequence: 1, schemaVersion: 1, collectorId, entityKey: 'endpoint:test', observedAt,
    host: { uptimeSeconds: 100, cpu: { logicalProcessors: 2, usedPercent: 20, loadAverage: [0.1, 0.2, 0.3] }, memory: { totalBytes: 1000, usedBytes: 500, availableBytes: 500, usedPercent: 50 }, filesystems: { status: 'available', truncated: false, volumes: [] } },
    lookout: { process: { uptimeSeconds: 90, cpu: { usedPercent: 5, cumulativeMilliseconds: 100 }, memory: { residentBytes: 100, heapUsedBytes: 50, externalBytes: 5 } }, dataStorage: { status: 'available', bytes: 10, entries: 1, truncated: false }, delivery: { status: 'available', queues: [] } }
  };
}

test('hosted onboarding progresses to a tenant-isolated dashboard snapshot', async () => {
  const consoleStore = await new SaasConsoleStore({ snapshotStore: memoryStore() }).initialize();
  const authority = await new SetupSessionAuthority({
    store: memoryStore(),
    activeDeploymentChecker: async ({ tenantId, deploymentIds }) => {
      const deployments = await consoleStore.listDeployments({ tenantId });
      return deployments.some((deployment) => deploymentIds.includes(deployment.deployment_id) && deployment.status !== 'uninstalled');
    },
    provisioningFactory: ({ deploymentId }) => ({
      console_sync: { endpoint: `https://app.example/v1/console-sync/${deploymentId}`, credential: crypto.randomBytes(32).toString('base64url') },
      dashboard_url: 'https://app.example/map'
    })
  }).initialize();
  let deletedAuthUser = null;
  const operationalSnapshots = [];
  const operationalHealthService = {
    async acceptSnapshot(principal, snapshot) { operationalSnapshots.push({ principal, snapshot }); return { accepted: snapshot.nodes.length }; },
    async listAlerts() { return [{ alert_key: 'collector:vm_memory' }]; },
    async recentDeploymentSamples() { return [{ sample_id: 'sample-one' }]; }
  };
  const api = createHostedSaasApi({
    setupAuthority: authority, consoleStore, authenticateBrowser: async (req) => req.testPrincipal,
    operationalHealthService, operationsApiToken: 'o'.repeat(40),
    deleteAccount: async ({ tenantId, userId }) => {
      await authority.deleteTenant({ tenantId, userId });
      await consoleStore.deleteTenant({ tenantId });
      deletedAuthUser = userId;
    }
  });
  const browser = { tenantId: 'tenant-a', userId: 'tenant-a', email: 'a@example.test' };

  assert.deepEqual((await invoke(api, request('GET', '/v1/me', undefined, {}, browser))).json(), { id: 'tenant-a', email: 'a@example.test', displayName: null, avatarUrl: null });
  const ruleCatalog = (await invoke(api, request('GET', '/v1/rules', undefined, {}, browser))).json();
  assert.ok(ruleCatalog.some((rule) => rule.id === 'credential-created' && rule.title === 'Long-lived credential added or changed' && rule.severity === 'medium'));
  assert.equal((await invoke(api, request('GET', '/v1/rules'))).status, 401);

  const pairingPageRequest = request('GET', '/setup?pairing=set_abcdefghijklmnop');
  const pairingPageResponse = response();
  assert.equal(await api(pairingPageRequest, pairingPageResponse, new URL(pairingPageRequest.url, 'https://app.example')), false);
  assert.equal(pairingPageResponse.status, null);
  assert.equal((await invoke(api, request('GET', '/v1/me?pairing=set_abcdefghijklmnop'))).status, 400);

  const keys = crypto.generateKeyPairSync('ed25519');
  const publicKey = keys.publicKey.export({ type: 'spki', format: 'pem' }).toString('utf8');
  const created = (await invoke(api, request('POST', '/v1/setup-sessions', {}, {}, browser))).json();
  assert.deepEqual((await invoke(api, request('POST', '/v1/setup-sessions/connect', { setup_token: created.setup_token }))).json(), { accepted: true });
  const activeSetup = (await invoke(api, request('GET', '/v1/setup-sessions/active', undefined, {}, browser))).json();
  assert.equal(activeSetup.setup.session_id, created.session_id);
  assert.equal(activeSetup.setup.status, 'connected');
  assert.equal((await invoke(api, request('GET', `/v1/setup-sessions/${created.session_id}`, undefined, {}, browser))).json().status, 'connected');
  const claim = (await invoke(api, request('POST', '/v1/setup-sessions/claim', {
    setup_token: created.setup_token,
    deployment_identity: { public_key_spki_pem: publicKey },
    installation_scope: { central_vm_id: 'vm-central', vms: [{ id: 'vm-central', provider: 'test', platform: 'linux', local: true }] }
  }))).json();
  const sessionHeaders = { authorization: `Bearer ${claim.session_token}` };
  const signature = crypto.sign(null, createProofMessage(claim.session_id, claim.challenge), keys.privateKey).toString('base64url');
  const proof = (await invoke(api, request('POST', `/v1/setup-sessions/${claim.session_id}/prove`, { signature_base64url: signature }, sessionHeaders))).json();

  const snapshot = {
    schemaVersion: 1, kind: 'lookout_console_snapshot', id: 'snapshot-a', deploymentId: claim.deployment_id, generatedAt: '2026-08-20T00:00:00.000Z',
    graph: { entities: [], relationships: [], capabilities: [] }, alerts: [{ id: 'alert_one', title: 'Test alert', severity: 'high', status: 'open', time: '2026-08-20T00:00:00.000Z', entities: [], evidenceCount: 1, statusHistory: [] }], incidents: [], detections: [],
    health: { status: 'ok', graph: {}, detections: {}, cases: {}, cloudExport: { enabled: false } }
  };
  const records = [{ sequence: 1, event: snapshot }];
  const batchId = batchIdFor(records);
  const batch = { schemaVersion: 1, batchId, firstSequence: 1, lastSequence: 1, events: [snapshot] };
  const syncHeaders = { authorization: `Bearer ${proof.provisioning.console_sync.credential}`, 'idempotency-key': batchId, 'x-lookout-batch-id': batchId };
  assert.equal((await invoke(api, request('POST', `/v1/console-sync/${claim.deployment_id}`, batch, syncHeaders))).status, 202);
  const operationalSnapshot = { schemaVersion: 1, kind: 'lookout_operational_health', id: 'ops-one', deploymentId: claim.deployment_id, generatedAt: '2026-08-20T00:00:00.000Z', nodes: [operationalNode('collector-one', '2026-08-20T00:00:00.000Z')] };
  const operationalBatch = { schemaVersion: 1, batchId: batchIdFor([{ sequence: 1, event: operationalSnapshot }]), firstSequence: 1, lastSequence: 1, events: [operationalSnapshot] };
  const operationalHeaders = { authorization: `Bearer ${proof.provisioning.console_sync.credential}`, 'idempotency-key': operationalBatch.batchId, 'x-lookout-batch-id': operationalBatch.batchId };
  assert.equal((await invoke(api, request('POST', `/v1/operational-health/${claim.deployment_id}`, operationalBatch, operationalHeaders))).status, 202);
  assert.equal(operationalSnapshots.length, 1);
  assert.equal((await invoke(api, request('GET', '/v1/internal/operational-health/alerts', undefined, { authorization: 'Bearer wrong-token-value-that-is-long-enough' }))).status, 404);
  assert.equal((await invoke(api, request('GET', '/v1/internal/operational-health/alerts', undefined, { authorization: `Bearer ${'o'.repeat(40)}` }))).json().alerts.length, 1);
  const deployments = (await invoke(api, request('GET', '/v1/deployments', undefined, {}, browser))).json().deployments;
  assert.equal(deployments.length, 1);
  assert.equal(deployments[0].deployment_id, claim.deployment_id);
  assert.equal(deployments[0].status, 'active');
  assert.ok(Number.isFinite(Date.parse(deployments[0].updated_at)));
  assert.deepEqual((await invoke(api, request('GET', '/v1/deployments', undefined, {}, { tenantId: 'tenant-b', userId: 'user-b' }))).json(), { deployments: [] });
  assert.equal((await invoke(api, request('GET', '/v1/deployments'))).status, 401);

  const recovery = await authority.createRecovery({ tenantId: browser.tenantId, deploymentId: claim.deployment_id });
  await consoleStore.markCentralMissing({ tenantId: browser.tenantId, deploymentId: claim.deployment_id, recoverySessionId: recovery.session_id, notifiedAt: '2026-08-21T01:00:00.000Z' });
  const missing = (await invoke(api, request('GET', '/v1/deployments', undefined, {}, browser))).json().deployments[0];
  assert.equal(missing.status, 'central_missing');
  assert.match(missing.recovery.setup_token, /^lrc_[A-Za-z0-9_-]{43}$/);

  assert.equal((await invoke(api, request('POST', `/v1/console-sync/${claim.deployment_id}`, batch, syncHeaders))).status, 202);
  const reportingRestored = (await invoke(api, request('GET', '/v1/deployments', undefined, {}, browser))).json().deployments[0];
  assert.equal(reportingRestored.status, 'active');
  assert.equal(Object.hasOwn(reportingRestored, 'recovery'), false);
  assert.equal(await authority.browserRecovery({ tenantId: browser.tenantId, deploymentId: claim.deployment_id }), null);

  for (const phase of ['installing', 'enrolling', 'surveying', 'configuring', 'validating', 'complete']) {
    assert.equal((await invoke(api, request('POST', `/v1/setup-sessions/${claim.session_id}/phases`, { phase }, sessionHeaders))).status, 200);
  }
  const complete = (await invoke(api, request('GET', `/v1/setup-sessions/${claim.session_id}`, undefined, {}, browser))).json();
  assert.equal(complete.status, 'complete');
  assert.equal(complete.dashboard_url, 'https://app.example/map');
  assert.equal((await invoke(api, request('GET', `/v1/deployments/${claim.deployment_id}/snapshot`, undefined, {}, browser))).json().id, snapshot.id);
  assert.equal((await invoke(api, request('GET', `/v1/deployments/${claim.deployment_id}/snapshot`, undefined, {}, { tenantId: 'tenant-b', userId: 'user-b' }))).status, 404);
  const updatedAlert = (await invoke(api, request('PATCH', `/v1/deployments/${claim.deployment_id}/alerts/alert_one`, { status: 'to_fix' }, {}, browser))).json();
  assert.equal(updatedAlert.status, 'to_fix');
  assert.equal(Object.hasOwn(updatedAlert.statusHistory[0], 'reason'), false);
  assert.equal((await invoke(api, request('GET', `/v1/deployments/${claim.deployment_id}/snapshot`, undefined, {}, browser))).json().alerts[0].status, 'to_fix');
  assert.equal((await invoke(api, request('PATCH', `/v1/deployments/${claim.deployment_id}/alerts/alert_one`, { status: 'closed' }, {}, { tenantId: 'tenant-b', userId: 'user-b' }))).status, 404);

  assert.equal((await invoke(api, request('DELETE', `/v1/console-sync/${claim.deployment_id}`))).status, 401);
  assert.deepEqual((await invoke(api, request('DELETE', `/v1/console-sync/${claim.deployment_id}`, undefined, syncHeaders))).json(), { status: 'uninstalled', idempotent: false });
  assert.equal((await invoke(api, request('GET', `/v1/deployments/${claim.deployment_id}/snapshot`, undefined, {}, browser))).json().health.status, 'uninstalled');
  assert.equal((await invoke(api, request('GET', '/v1/deployments', undefined, {}, browser))).json().deployments[0].status, 'uninstalled');
  const reinstall = await invoke(api, request('POST', '/v1/setup-sessions', {}, {}, browser));
  assert.equal(reinstall.status, 201);
  assert.match(reinstall.json().setup_token, /^lst_[A-Za-z0-9_-]{43}$/);

  assert.equal((await invoke(api, request('DELETE', '/v1/account', { confirmation: 'wrong' }, {}, browser))).status, 400);
  assert.equal((await invoke(api, request('DELETE', '/v1/account', { confirmation: 'DELETE' }))).status, 401);
  assert.deepEqual((await invoke(api, request('DELETE', '/v1/account', { confirmation: 'DELETE' }, {}, browser))).json(), { deleted: true });
  assert.equal(deletedAuthUser, browser.userId);
  assert.equal((await invoke(api, request('GET', `/v1/deployments/${claim.deployment_id}/snapshot`, undefined, {}, browser))).status, 404);
  assert.equal((await invoke(api, request('POST', `/v1/console-sync/${claim.deployment_id}`, batch, syncHeaders))).status, 401);
  await assert.rejects(() => authority.create(browser), /deleted/);
});

test('hosted CLI login requires browser approval and exchanges once', async () => {
  const setupAuthority = await new SetupSessionAuthority({
    provisioningFactory: () => ({ console_sync: { endpoint: 'https://app.example/v1/console-sync/test', credential: 'x'.repeat(43) }, dashboard_url: 'https://app.example/map' })
  }).initialize();
  const cliAuthorizationAuthority = await new CliAuthorizationAuthority({ setupAuthority }).initialize();
  const api = createHostedSaasApi({
    setupAuthority, cliAuthorizationAuthority, consoleStore: {},
    authenticateBrowser: async (req) => req.testPrincipal,
    deleteAccount: async () => {}
  });
  const verifier = 'v'.repeat(43);
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  const deploymentPublicKey = crypto.generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' });
  const installationScope = { central_vm_id: 'api-1', vms: [{ id: 'api-1', name: 'api-1', address: '10.0.1.10', platform: 'linux', provider: 'openssh', local: false }] };
  const created = (await invoke(api, request('POST', '/v1/cli-authorizations', {
    code_challenge: challenge, redirect_uri: 'http://127.0.0.1:41234/callback', state: 's'.repeat(32),
    deployment_public_key_spki_pem: deploymentPublicKey, installation_scope: installationScope
  }))).json();
  assert.match(created.request_id, /^cla_/);
  assert.equal((await invoke(api, request('POST', `/v1/cli-authorizations/${created.request_id}/approve`))).status, 401);
  const approved = (await invoke(api, request('POST', `/v1/cli-authorizations/${created.request_id}/approve`, { verification_code: created.verification_code }, {}, { tenantId: 'tenant-a', userId: 'user-a' }))).json();
  const code = new URL(approved.redirect_uri).searchParams.get('code');
  const exchanged = await invoke(api, request('POST', '/v1/cli-authorizations/exchange', { request_id: created.request_id, code, code_verifier: verifier }));
  assert.equal(exchanged.status, 200);
  assert.match(exchanged.json().setup_token, /^lst_/);
  assert.equal((await invoke(api, request('POST', '/v1/cli-authorizations/exchange', { request_id: created.request_id, code, code_verifier: verifier }))).status, 400);
});

test('hosted CLI authorization logs a safe reason without authentication secrets', async () => {
  const setupAuthority = await new SetupSessionAuthority({
    provisioningFactory: () => ({ console_sync: { endpoint: 'https://app.example/v1/console-sync/test', credential: 'x'.repeat(43) }, dashboard_url: 'https://app.example/map' })
  }).initialize();
  const records = [];
  const requestId = `cla_${'r'.repeat(32)}`;
  const code = 'authorization-code-value-that-must-not-be-logged';
  const verifier = 'v'.repeat(43);
  const api = createHostedSaasApi({
    setupAuthority, consoleStore: {}, authenticateBrowser: async () => null, deleteAccount: async () => {},
    cliAuthorizationAuthority: {
      async exchange() { throw new Error('Account already has an active network'); }
    },
    logger: (record) => records.push(record)
  });

  const result = await invoke(api, request('POST', '/v1/cli-authorizations/exchange', {
    request_id: requestId, code, code_verifier: verifier
  }));

  assert.equal(result.status, 400);
  assert.deepEqual(records, [{
    event: 'lookout_cli_authorization', outcome: 'rejected', phase: 'exchange',
    reason: 'active_network', request_id: requestId
  }]);
  assert.doesNotMatch(JSON.stringify(records), new RegExp(`${code}|${verifier}`));
});

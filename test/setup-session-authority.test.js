'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { SetupSessionAuthority } = require('../src/onboarding/setup-session-authority');
const { createProofMessage } = require('../src/onboarding/setup-session-client');
const { SaasConsoleStore } = require('../src/console/saas-store');
const { batchIdFor } = require('../src/export/service');

class MemoryStore {
  constructor() { this.value = null; this.failNextSave = false; }
  async load() { return this.value === null ? null : structuredClone(this.value); }
  async save(value) {
    if (this.failNextSave) { this.failNextSave = false; throw new Error('injected save failure'); }
    this.value = structuredClone(value);
  }
}

function identity() {
  const pair = crypto.generateKeyPairSync('ed25519');
  return { pair, pem: pair.publicKey.export({ type: 'spki', format: 'pem' }).toString('utf8') };
}

const SCOPE = { central_vm_id: 'vm-central', vms: [{ id: 'vm-central', provider: 'test', name: 'central', instance_id: 'i-central', region: 'test-1', address: '10.0.0.10', ssh_user: 'root', platform: 'linux', local: true }] };

function fixture(overrides = {}) {
  const store = overrides.store || new MemoryStore();
  let now = Date.parse('2026-08-19T00:00:00.000Z');
  const calls = [];
  const authority = new SetupSessionAuthority({
    store,
    now: () => new Date(now),
    codeTtlMs: 60_000,
    sessionTtlMs: 60_000,
    provisioningFactory: async (context) => {
      calls.push(context);
      return {
        console_sync: {
          endpoint: `https://sync.example.test/deployments/${context.deploymentId}`,
          credential: crypto.randomBytes(32).toString('base64url')
        },
        dashboard_url: `https://console.example.test/deployments/${context.deploymentId}`
      };
    },
    ...overrides
  });
  return { authority, store, calls, advance(milliseconds) { now += milliseconds; } };
}

async function claimed(f, tenantId = 'tenant-a', key = identity()) {
  const created = await f.authority.create({ tenantId, userId: 'user-1' });
  const claim = await f.authority.claim({ setup_token: created.setup_token, deployment_identity: { public_key_spki_pem: key.pem }, installation_scope: SCOPE });
  return { created, claim, key };
}

function signature(item, pair = item.key.pair) {
  return crypto.sign(null, createProofMessage(item.claim.session_id, item.claim.challenge), pair.privateKey).toString('base64url');
}

function consoleSnapshot(deploymentId, suffix) {
  return {
    schemaVersion: 1,
    kind: 'lookout_console_snapshot',
    id: `snapshot-${suffix}`,
    deploymentId,
    generatedAt: `2026-08-19T00:0${suffix}:00.000Z`,
    graph: { entities: [], relationships: [], capabilities: [] },
    alerts: [],
    incidents: [],
    detections: [],
    health: { status: 'ok', graph: {}, detections: {}, cases: {}, cloudExport: { enabled: false } }
  };
}

function consoleBatch(event, sequence) {
  const records = [{ sequence, event }];
  return { schemaVersion: 1, batchId: batchIdFor(records), firstSequence: sequence, lastSequence: sequence, events: [event] };
}

test('setup tokens remain valid for 30 days by default', async () => {
  const f = fixture({ codeTtlMs: undefined });
  const created = await f.authority.create({ tenantId: 'tenant-a', userId: 'user-1' });
  assert.equal(created.expires_at, '2026-09-18T00:00:00.000Z');
});

test('installation scope may defer central VM selection to the installer', async () => {
  const f = fixture();
  const key = identity();
  const created = await f.authority.create({ tenantId: 'tenant-a', userId: 'user-1' });
  const scope = { vms: [{ id: 'aws:i-0123456789abcdef0', provider: 'aws', instance_id: 'i-0123456789abcdef0', address: '10.0.0.10', platform: 'linux' }] };
  const claim = await f.authority.claim({ setup_token: created.setup_token, deployment_identity: { public_key_spki_pem: key.pem }, installation_scope: scope });
  assert.deepEqual(claim.installation_scope, scope);
});

test('installation scope preserves stable IDs independently from provider instance IDs', async () => {
  const f = fixture();
  const key = identity();
  const created = await f.authority.create({ tenantId: 'tenant-a', userId: 'user-1' });
  const scope = { vms: [{ id: 'stable-node-id', provider: 'aws', instance_id: 'i-0123456789abcdef0', platform: 'linux' }] };
  const claim = await f.authority.claim({ setup_token: created.setup_token, deployment_identity: { public_key_spki_pem: key.pem }, installation_scope: scope });
  assert.deepEqual(claim.installation_scope, scope);
});

test('tokens are high entropy, hashed at rest, tenant-bound, and scoped', async () => {
  const f = fixture();
  const sharedKey = identity();
  const a = await claimed(f, 'tenant-a', sharedKey);
  const b = await claimed(f, 'tenant-b', sharedKey);
  assert.match(a.created.setup_token, /^lst_[A-Za-z0-9_-]{43}$/);
  assert.match(a.created.support_token, /^ldw_[A-Za-z0-9_-]{43}$/);
  assert.notEqual(a.claim.deployment_id, b.claim.deployment_id);
  assert.equal(JSON.stringify(f.store.value).includes(a.created.setup_token), false);
  assert.equal(JSON.stringify(f.store.value).includes(a.created.support_token), false);
  assert.deepEqual(a.claim.installation_scope, SCOPE);
  for (const result of [a.created, a.claim, await f.authority.status({ sessionId: a.claim.session_id, sessionToken: a.claim.session_token })]) {
    assert.equal(Object.hasOwn(result, 'tenantId'), false);
    assert.equal(Object.hasOwn(result, 'tenant_id'), false);
    assert.equal(Object.hasOwn(result, 'codeHash'), false);
  }
  await f.authority.prove({ sessionId: a.claim.session_id, sessionToken: a.claim.session_token, signatureBase64url: signature(a) });
  assert.equal(f.calls[0].tenantId, 'tenant-a');
  await assert.rejects(() => f.authority.claim({ setupToken: b.created.setup_token, publicKeySpkiPem: sharedKey.pem, installationScope: SCOPE, tenantId: 'tenant-a' }), /may not supply/);
  assert.equal((await f.authority.browserStatus({ sessionId: b.created.session_id, tenantId: 'tenant-b', userId: 'user-1' })).status, 'claimed');
  await assert.rejects(() => f.authority.status({ sessionId: b.created.session_id, sessionToken: 'z'.repeat(43) }), /unavailable/);
});

test('browser-bound setup permission rejects deployment key and VM scope substitution', async () => {
  const f = fixture();
  const approved = identity();
  const attacker = identity();
  const created = await f.authority.create({
    tenantId: 'tenant-a', userId: 'user-a', authorizedPublicKeySpkiPem: approved.pem,
    authorizedInstallationScope: SCOPE
  });
  await assert.rejects(() => f.authority.claim({
    setup_token: created.setup_token,
    deployment_identity: { public_key_spki_pem: attacker.pem }, installation_scope: SCOPE
  }), /unavailable/);
  await assert.rejects(() => f.authority.claim({
    setup_token: created.setup_token,
    deployment_identity: { public_key_spki_pem: approved.pem },
    installation_scope: { ...SCOPE, vms: [{ ...SCOPE.vms[0], address: '10.0.0.99' }] }
  }), /unavailable/);
  const claim = await f.authority.claim({
    setup_token: created.setup_token,
    deployment_identity: { public_key_spki_pem: approved.pem }, installation_scope: SCOPE
  });
  assert.match(claim.deployment_id, /^dpl_/);
});

test('browser authorization reserves the exact deployment ID before account approval completes', async () => {
  const f = fixture();
  const approved = identity();
  const deploymentId = `dpl_${'p'.repeat(32)}`;
  const created = await f.authority.create({
    tenantId: 'tenant-a', userId: 'user-a', authorizedPublicKeySpkiPem: approved.pem,
    authorizedInstallationScope: SCOPE, authorizedDeploymentId: deploymentId
  });
  const claim = await f.authority.claim({
    setup_token: created.setup_token,
    deployment_identity: { public_key_spki_pem: approved.pem }, installation_scope: SCOPE
  });
  assert.equal(claim.deployment_id, deploymentId);
  await assert.rejects(() => f.authority.create({
    tenantId: 'tenant-b', userId: 'user-b', authorizedPublicKeySpkiPem: approved.pem,
    authorizedInstallationScope: SCOPE, authorizedDeploymentId: deploymentId
  }), /unavailable/);
});

test('diagnostic context is derived only from the hashed setup token', async () => {
  const f = fixture();
  const created = await f.authority.create({ tenantId: 'tenant-a', userId: 'user-a', email: 'owner@example.com' });
  assert.deepEqual(await f.authority.diagnosticContextBySetupToken({ setupToken: created.setup_token }), {
    tenantId: 'tenant-a', userId: 'user-a', email: 'owner@example.com', sessionId: created.session_id, deploymentId: null
  });
  assert.deepEqual(await f.authority.diagnosticContextBySupportToken({ supportToken: created.support_token }), {
    tenantId: 'tenant-a', userId: 'user-a', email: 'owner@example.com', sessionId: created.session_id, deploymentId: null
  });
  await assert.rejects(f.authority.diagnosticContextBySetupToken({ setupToken: created.setup_token, tenantId: 'tenant-b' }), /may not supply/);
  await assert.rejects(f.authority.diagnosticContextBySetupToken({ setupToken: `lst_${'z'.repeat(43)}` }), /unavailable/);
  await assert.rejects(f.authority.diagnosticContextBySupportToken({ supportToken: `ldw_${'z'.repeat(43)}` }), /unavailable/);
});

test('concurrent claims remain bound to one setup and the token stays retryable', async () => {
  const f = fixture();
  const key = identity();
  const created = await f.authority.create({ tenantId: 'tenant-a', userId: 'user-1' });
  await f.authority.connect({ setupToken: created.setup_token });
  const attempts = await Promise.allSettled([
    f.authority.claim({ setupToken: created.setup_token, publicKeySpkiPem: key.pem, installationScope: SCOPE }),
    f.authority.claim({ setupToken: created.setup_token, publicKeySpkiPem: key.pem, installationScope: SCOPE })
  ]);
  assert.equal(attempts.filter((entry) => entry.status === 'fulfilled').length, 2);
  const claims = attempts.map((entry) => entry.value);
  assert.equal(claims[0].session_id, claims[1].session_id);
  assert.equal(claims[0].deployment_id, claims[1].deployment_id);
  const retry = await f.authority.claim({ setupToken: created.setup_token, publicKeySpkiPem: key.pem, installationScope: SCOPE });
  assert.equal(retry.session_id, created.session_id);
});

test('setup token remains valid after a proved installation failure and is consumed only on completion', async () => {
  const f = fixture();
  const key = identity();
  const created = await f.authority.create({ tenantId: 'tenant-a', userId: 'user-1' });
  await f.authority.connect({ setupToken: created.setup_token });
  const first = await f.authority.claim({ setupToken: created.setup_token, publicKeySpkiPem: key.pem, installationScope: SCOPE });
  await f.authority.prove({
    sessionId: first.session_id,
    sessionToken: first.session_token,
    signatureBase64url: crypto.sign(null, createProofMessage(first.session_id, first.challenge), key.pair.privateKey).toString('base64url')
  });
  const firstBootstrapKey = { authorized_keys_line: `restrict ssh-ed25519 ${Buffer.alloc(32, 7).toString('base64')} lookout-bootstrap:first`, fingerprint: `SHA256:${Buffer.alloc(24, 8).toString('base64').replace(/=+$/, '')}` };
  await f.authority.publishBootstrapKey({ sessionId: first.session_id, sessionToken: first.session_token, bootstrapKey: firstBootstrapKey });
  await f.authority.reportPhase({ sessionId: first.session_id, sessionToken: first.session_token, phase: 'failed' });

  assert.deepEqual(await f.authority.connect({ setupToken: created.setup_token }), { accepted: true });
  const retry = await f.authority.claim({ setupToken: created.setup_token, publicKeySpkiPem: key.pem, installationScope: SCOPE });
  assert.equal(retry.session_id, first.session_id);
  assert.equal(retry.deployment_id, first.deployment_id);
  assert.notEqual(retry.session_token, first.session_token);
  const retriedProof = await f.authority.prove({
    sessionId: retry.session_id,
    sessionToken: retry.session_token,
    signatureBase64url: crypto.sign(null, createProofMessage(retry.session_id, retry.challenge), key.pair.privateKey).toString('base64url')
  });
  assert.equal(retriedProof.provisioning.console_sync.credential, f.store.value.sessions[0].provisioning.console_sync.credential);
  const retryBootstrapKey = { authorized_keys_line: `restrict ssh-ed25519 ${Buffer.alloc(32, 9).toString('base64')} lookout-bootstrap:retry`, fingerprint: `SHA256:${Buffer.alloc(24, 10).toString('base64').replace(/=+$/, '')}` };
  assert.deepEqual(await f.authority.publishBootstrapKey({ sessionId: retry.session_id, sessionToken: retry.session_token, bootstrapKey: retryBootstrapKey }), { accepted: true });
  assert.deepEqual((await f.authority.status({ sessionId: retry.session_id, sessionToken: retry.session_token })).bootstrap_key, retryBootstrapKey);
  await f.authority.reportPhase({ sessionId: retry.session_id, sessionToken: retry.session_token, phase: 'complete' });
  await assert.rejects(() => f.authority.connect({ setupToken: created.setup_token }), /unavailable/);
  await assert.rejects(() => f.authority.claim({ setupToken: created.setup_token, publicKeySpkiPem: key.pem, installationScope: SCOPE }), /unavailable/);
});

test('a failed setup token replaces an old deployment identity directly', async () => {
  const replacements = [];
  const f = fixture({ deploymentReplacementHandler: async (replacement) => replacements.push(replacement) });
  const oldIdentity = identity();
  const newIdentity = identity();
  const created = await f.authority.create({ tenantId: 'tenant-a', userId: 'user-1' });
  await f.authority.connect({ setupToken: created.setup_token });
  const first = await f.authority.claim({ setupToken: created.setup_token, publicKeySpkiPem: oldIdentity.pem, installationScope: SCOPE });
  const firstProof = await f.authority.prove({
    sessionId: first.session_id,
    sessionToken: first.session_token,
    signatureBase64url: crypto.sign(null, createProofMessage(first.session_id, first.challenge), oldIdentity.pair.privateKey).toString('base64url')
  });
  await f.authority.reportPhase({ sessionId: first.session_id, sessionToken: first.session_token, phase: 'failed' });

  const retry = await f.authority.claim({ setupToken: created.setup_token, publicKeySpkiPem: newIdentity.pem, installationScope: SCOPE });
  assert.equal(retry.session_id, first.session_id);
  assert.notEqual(retry.deployment_id, first.deployment_id);
  assert.deepEqual(replacements, [{ tenantId: 'tenant-a', deploymentId: first.deployment_id, replacementDeploymentId: retry.deployment_id }]);
  await assert.rejects(() => f.authority.authenticateConsoleCredential({
    deploymentId: first.deployment_id,
    credential: firstProof.provisioning.console_sync.credential
  }), /unavailable/);
  const retryProof = await f.authority.prove({
    sessionId: retry.session_id,
    sessionToken: retry.session_token,
    signatureBase64url: crypto.sign(null, createProofMessage(retry.session_id, retry.challenge), newIdentity.pair.privateKey).toString('base64url')
  });
  assert.notEqual(retryProof.provisioning.console_sync.credential, firstProof.provisioning.console_sync.credential);
});

test('same identity retry resets the existing deployment before fresh snapshot sequencing', async () => {
  const replacements = [];
  const f = fixture({ deploymentReplacementHandler: async (replacement) => replacements.push(replacement) });
  const key = identity();
  const created = await f.authority.create({ tenantId: 'tenant-a', userId: 'user-1' });
  const first = await f.authority.claim({ setupToken: created.setup_token, publicKeySpkiPem: key.pem, installationScope: SCOPE });
  await f.authority.prove({ sessionId: first.session_id, sessionToken: first.session_token, signatureBase64url: crypto.sign(null, createProofMessage(first.session_id, first.challenge), key.pair.privateKey).toString('base64url') });
  await f.authority.reportPhase({ sessionId: first.session_id, sessionToken: first.session_token, phase: 'failed' });
  const retry = await f.authority.claim({ setupToken: created.setup_token, publicKeySpkiPem: key.pem, installationScope: SCOPE });
  assert.deepEqual(replacements, [{ tenantId: 'tenant-a', deploymentId: first.deployment_id, replacementDeploymentId: first.deployment_id }]);
  assert.equal(retry.deployment_id, first.deployment_id);
});

test('same identity retry accepts a fresh sequence one snapshot through the real Console store', async () => {
  const consoleStore = await new SaasConsoleStore({ snapshotStore: new MemoryStore() }).initialize();
  const f = fixture({
    deploymentReplacementHandler: ({ tenantId, deploymentId, replacementDeploymentId }) => {
      assert.equal(replacementDeploymentId, deploymentId);
      return consoleStore.resetForRetry({ tenantId, deploymentId });
    }
  });
  const key = identity();
  const created = await f.authority.create({ tenantId: 'tenant-a', userId: 'user-1' });
  const first = await f.authority.claim({ setupToken: created.setup_token, publicKeySpkiPem: key.pem, installationScope: SCOPE });
  await f.authority.prove({
    sessionId: first.session_id,
    sessionToken: first.session_token,
    signatureBase64url: crypto.sign(null, createProofMessage(first.session_id, first.challenge), key.pair.privateKey).toString('base64url')
  });
  const principal = { tenantId: 'tenant-a', deploymentId: first.deployment_id };
  await consoleStore.acceptBatch(principal, consoleBatch(consoleSnapshot(first.deployment_id, 1), 1));
  await consoleStore.acceptBatch(principal, consoleBatch(consoleSnapshot(first.deployment_id, 2), 2));
  await f.authority.reportPhase({ sessionId: first.session_id, sessionToken: first.session_token, phase: 'failed' });

  const retry = await f.authority.claim({ setupToken: created.setup_token, publicKeySpkiPem: key.pem, installationScope: SCOPE });
  assert.equal(retry.deployment_id, first.deployment_id);
  assert.deepEqual(await consoleStore.acceptBatch(principal, consoleBatch(consoleSnapshot(first.deployment_id, 3), 1)), { accepted: 1, idempotent: false });
  assert.equal((await consoleStore.snapshot(principal)).id, 'snapshot-3');
});

test('lightweight bootstrap connection is immediate, idempotent, and does not consume the setup token', async () => {
  const f = fixture();
  const key = identity();
  const created = await f.authority.create({ tenantId: 'tenant-a', userId: 'user-1' });
  assert.deepEqual(await f.authority.connect({ setup_token: created.setup_token }), { accepted: true });
  assert.deepEqual(await f.authority.connect({ setup_token: created.setup_token }), { accepted: true });
  assert.equal((await f.authority.browserStatus({ sessionId: created.session_id, tenantId: 'tenant-a', userId: 'user-1' })).status, 'connected');
  assert.match(f.store.value.sessions[0].bootstrapConnectedAt, /^2026-08-19T/);
  assert.equal(JSON.stringify(f.store.value).includes(created.setup_token), false);
  const claim = await f.authority.claim({ setupToken: created.setup_token, publicKeySpkiPem: key.pem, installationScope: SCOPE });
  assert.equal(claim.session_id, created.session_id);
  const claimedStatus = await f.authority.browserStatus({ sessionId: created.session_id, tenantId: 'tenant-a', userId: 'user-1' });
  assert.equal(claimedStatus.deployment_id, claim.deployment_id);
  assert.equal(claimedStatus.total, 1);
  assert.deepEqual(await f.authority.connect({ setup_token: created.setup_token }), { accepted: true });
});

test('a browser refresh cannot replace a connected installer session', async () => {
  const f = fixture();
  const key = identity();
  const created = await f.authority.create({ tenantId: 'tenant-a', userId: 'user-1' });
  await f.authority.connect({ setup_token: created.setup_token });
  await assert.rejects(
    () => f.authority.create({ tenantId: 'tenant-a', userId: 'user-1' }),
    /active setup/
  );
  const claim = await f.authority.claim({ setupToken: created.setup_token, publicKeySpkiPem: key.pem, installationScope: SCOPE });
  assert.equal(claim.session_id, created.session_id);
});

test('the first pending setup to connect atomically wins across browser tabs', async () => {
  const f = fixture();
  const key = identity();
  const first = await f.authority.create({ tenantId: 'tenant-a', userId: 'user-1' });
  const second = await f.authority.create({ tenantId: 'tenant-a', userId: 'user-1' });
  assert.equal((await f.authority.browserStatus({ sessionId: first.session_id, tenantId: 'tenant-a', userId: 'user-1' })).status, 'pending');
  assert.equal((await f.authority.browserStatus({ sessionId: second.session_id, tenantId: 'tenant-a', userId: 'user-1' })).status, 'pending');
  await f.authority.connect({ setup_token: first.setup_token });
  assert.equal((await f.authority.browserStatus({ sessionId: second.session_id, tenantId: 'tenant-a', userId: 'user-1' })).status, 'failed');
  await assert.rejects(() => f.authority.connect({ setup_token: second.setup_token }), /unavailable/);
  const claim = await f.authority.claim({ setupToken: first.setup_token, publicKeySpkiPem: key.pem, installationScope: SCOPE });
  assert.equal(claim.session_id, first.session_id);
});

test('pre-claim failure reporting accepts only safe codes and makes Connected terminally failed', async () => {
  const f = fixture();
  const created = await f.authority.create({ tenantId: 'tenant-a', userId: 'user-1' });
  await f.authority.connect({ setup_token: created.setup_token });
  assert.deepEqual(await f.authority.reportPreclaimFailure({ setup_token: created.setup_token, code: 'cloud_discovery' }), { accepted: true });
  assert.equal((await f.authority.browserStatus({ sessionId: created.session_id, tenantId: 'tenant-a', userId: 'user-1' })).status, 'failed');
  assert.deepEqual(await f.authority.connect({ setup_token: created.setup_token }), { accepted: true });
  assert.equal(JSON.stringify(f.store.value).includes(created.setup_token), false);
  assert.equal(JSON.stringify(f.store.value).includes('arbitrary local failure text'), false);
  await assert.rejects(() => f.authority.reportPreclaimFailure({ setup_token: created.setup_token, code: 'arbitrary local failure text' }), /unavailable/);
  await assert.rejects(() => f.authority.reportPreclaimFailure({ setup_token: `lst_${'z'.repeat(43)}`, code: 'cloud_discovery' }), /unavailable/);
});

test('artifact failure before connection preserves the original setup token for retry', async () => {
  const f = fixture();
  const key = identity();
  const created = await f.authority.create({ tenantId: 'tenant-a', userId: 'user-1' });
  await f.authority.reportPreclaimFailure({ setupToken: created.setup_token, code: 'artifact_download' });
  assert.deepEqual(await f.authority.connect({ setupToken: created.setup_token }), { accepted: true });
  const claim = await f.authority.claim({ setupToken: created.setup_token, publicKeySpkiPem: key.pem, installationScope: SCOPE });
  assert.equal(claim.session_id, created.session_id);
});

test('invalid claim traffic is durably rate bounded', async () => {
  const f = fixture({ maxClaimsPerWindow: 2, maxAttemptHistory: 2 });
  const key = identity();
  for (const token of [`lst_${'a'.repeat(43)}`, `lst_${'b'.repeat(43)}`]) {
    await assert.rejects(() => f.authority.claim({ setupToken: token, publicKeySpkiPem: key.pem, installationScope: SCOPE }), /unavailable/);
  }
  const created = await f.authority.create({ tenantId: 'tenant-a', userId: 'user-1' });
  await assert.rejects(() => f.authority.claim({ setupToken: created.setup_token, publicKeySpkiPem: key.pem, installationScope: SCOPE }), /rate limit/);
  assert.equal(f.store.value.claimAttempts.length, 2);
});

test('expired tokens and sessions fail safely while authenticated status reports expiry', async () => {
  const f = fixture();
  const key = identity();
  const expiredCode = await f.authority.create({ tenantId: 'tenant-a', userId: 'user-1' });
  f.advance(60_001);
  await assert.rejects(() => f.authority.claim({ setupToken: expiredCode.setup_token, publicKeySpkiPem: key.pem, installationScope: SCOPE }), /unavailable/);
  const active = await claimed(f, 'tenant-a', key);
  f.advance(60_001);
  assert.deepEqual((await f.authority.status({ sessionId: active.claim.session_id, sessionToken: active.claim.session_token })).status, 'expired');
  await assert.rejects(() => f.authority.prove({ sessionId: active.claim.session_id, sessionToken: active.claim.session_token, signatureBase64url: signature(active) }), /expired/);
});

test('proof rejects key substitution and only replays the exact successful proof', async () => {
  const f = fixture();
  const item = await claimed(f);
  const attacker = identity();
  await assert.rejects(() => f.authority.prove({ sessionId: item.claim.session_id, sessionToken: item.claim.session_token, signatureBase64url: signature(item, attacker.pair) }), /invalid/);
  const result = await f.authority.prove({ sessionId: item.claim.session_id, sessionToken: item.claim.session_token, signatureBase64url: signature(item) });
  assert.equal(result.verified, true);
  assert.equal(result.provisioning.console_sync.endpoint.includes(item.claim.deployment_id), true);
  assert.deepEqual(await f.authority.prove({ sessionId: item.claim.session_id, sessionToken: item.claim.session_token, signatureBase64url: signature(item) }), result);
  const different = Buffer.from(signature(item), 'base64url');
  different[0] ^= 1;
  await assert.rejects(() => f.authority.prove({ sessionId: item.claim.session_id, sessionToken: item.claim.session_token, signatureBase64url: different.toString('base64url') }), /unavailable/);
});

test('invalid proofs are durably attempt-bounded', async () => {
  const f = fixture({ maxProofAttempts: 2 });
  const item = await claimed(f);
  const attacker = identity();
  for (let attempt = 0; attempt < 2; attempt += 1) {
    await assert.rejects(() => f.authority.prove({ sessionId: item.claim.session_id, sessionToken: item.claim.session_token, signatureBase64url: signature(item, attacker.pair) }), /invalid/);
  }
  await assert.rejects(() => f.authority.prove({ sessionId: item.claim.session_id, sessionToken: item.claim.session_token, signatureBase64url: signature(item) }), /unavailable/);
});

test('phase reports require the session credential and are monotonic', async () => {
  const f = fixture();
  const item = await claimed(f);
  await assert.rejects(() => f.authority.reportPhase({ sessionId: item.claim.session_id, sessionToken: 'x'.repeat(32), phase: 'installing' }), /unavailable/);
  await assert.rejects(() => f.authority.reportPhase({ sessionId: item.claim.session_id, sessionToken: item.claim.session_token, phase: 'installing' }), /proof/);
  await f.authority.prove({ sessionId: item.claim.session_id, sessionToken: item.claim.session_token, signatureBase64url: signature(item) });
  await f.authority.reportPhase({ sessionId: item.claim.session_id, sessionToken: item.claim.session_token, phase: 'connected' });
  await f.authority.reportPhase({ sessionId: item.claim.session_id, sessionToken: item.claim.session_token, phase: 'verifying' });
  await assert.rejects(() => f.authority.reportPhase({ sessionId: item.claim.session_id, sessionToken: item.claim.session_token, phase: 'discovering' }), /backwards/);
  await f.authority.reportPhase({ sessionId: item.claim.session_id, sessionToken: item.claim.session_token, phase: 'complete' });
  assert.equal((await f.authority.status({ sessionId: item.claim.session_id, sessionToken: item.claim.session_token })).status, 'complete');
  const browser = await f.authority.browserStatus({ sessionId: item.claim.session_id, tenantId: 'tenant-a', userId: 'user-1' });
  assert.equal(browser.status, 'complete');
  assert.match(browser.dashboard_url, /^https:\/\//);
  await assert.rejects(() => f.authority.browserStatus({ sessionId: item.claim.session_id, tenantId: 'tenant-b', userId: 'user-1' }), /unavailable/);
  await assert.rejects(() => f.authority.reportPhase({ sessionId: item.claim.session_id, sessionToken: item.claim.session_token, phase: 'failed' }), /terminal/);
});

test('one active network is enforced and recovery rotates its console credential', async () => {
  const f = fixture();
  const first = await claimed(f, 'tenant-a');
  const firstProof = await f.authority.prove({ sessionId: first.claim.session_id, sessionToken: first.claim.session_token, signatureBase64url: signature(first) });
  const principal = await f.authority.authenticateConsoleCredential({ deploymentId: first.claim.deployment_id, credential: firstProof.provisioning.console_sync.credential });
  assert.deepEqual(principal, { tenantId: 'tenant-a', userId: 'user-1', deploymentId: first.claim.deployment_id });
  assert.deepEqual(await f.authority.authorizeBrowserDeployment({ tenantId: 'tenant-a', deploymentId: first.claim.deployment_id }), { tenantId: 'tenant-a', deploymentId: first.claim.deployment_id, status: 'claimed' });
  await assert.rejects(() => f.authority.authorizeBrowserDeployment({ tenantId: 'tenant-b', deploymentId: first.claim.deployment_id }), /unavailable/);

  await assert.rejects(() => f.authority.create({ tenantId: 'tenant-a', userId: 'user-1' }), /active network/);
  const secondCreated = await f.authority.createRecovery({ tenantId: 'tenant-a', deploymentId: first.claim.deployment_id });
  const secondClaim = await f.authority.claim({ setup_token: secondCreated.setup_token, deployment_identity: { public_key_spki_pem: first.key.pem }, installation_scope: SCOPE });
  const second = { created: secondCreated, claim: secondClaim, key: first.key };
  const secondProof = await f.authority.prove({ sessionId: second.claim.session_id, sessionToken: second.claim.session_token, signatureBase64url: signature(second) });
  assert.equal(second.claim.deployment_id, first.claim.deployment_id);
  await assert.rejects(() => f.authority.authenticateConsoleCredential({ deploymentId: first.claim.deployment_id, credential: firstProof.provisioning.console_sync.credential }), /unavailable/);
  assert.equal((await f.authority.authenticateConsoleCredential({ deploymentId: second.claim.deployment_id, credential: secondProof.provisioning.console_sync.credential })).tenantId, 'tenant-a');
});

test('the authenticated account can recover its one active setup ID', async () => {
  const f = fixture();
  assert.deepEqual(await f.authority.browserActiveStatus({ tenantId: 'tenant-a', userId: 'user-1' }), { setup: null });
  const item = await claimed(f, 'tenant-a');
  await f.authority.prove({ sessionId: item.claim.session_id, sessionToken: item.claim.session_token, signatureBase64url: signature(item) });
  await f.authority.reportPhase({ sessionId: item.claim.session_id, sessionToken: item.claim.session_token, phase: 'deploying', completed: 2, total: 7 });
  const active = await f.authority.browserActiveStatus({ tenantId: 'tenant-a', userId: 'user-1' });
  assert.deepEqual(active.setup, { session_id: item.claim.session_id, status: 'deploying', expires_at: item.claim.expires_at, completed: 2, total: 7, deployment_id: item.claim.deployment_id });
  assert.equal((await f.authority.browserActiveStatus({ tenantId: 'tenant-a', userId: 'other-user' })).setup.session_id, item.claim.session_id);
  assert.deepEqual(await f.authority.browserActiveStatus({ tenantId: 'tenant-b', userId: 'user-1' }), { setup: null });
  await f.authority.reportPhase({ sessionId: item.claim.session_id, sessionToken: item.claim.session_token, phase: 'complete' });
  assert.deepEqual(await f.authority.browserActiveStatus({ tenantId: 'tenant-a', userId: 'user-1' }), { setup: null });
});

test('the authenticated account retains a proved failed setup until expiry', async () => {
  const f = fixture();
  const item = await claimed(f);
  await f.authority.prove({ sessionId: item.claim.session_id, sessionToken: item.claim.session_token, signatureBase64url: signature(item) });
  await f.authority.reportPhase({ sessionId: item.claim.session_id, sessionToken: item.claim.session_token, phase: 'failed' });
  const active = await f.authority.browserActiveStatus({ tenantId: 'tenant-a', userId: 'user-1' });
  assert.equal(active.setup.session_id, item.claim.session_id);
  assert.equal(active.setup.status, 'failed');
  assert.equal(active.setup.total, 1);
  assert.deepEqual(await f.authority.dismissFailed({ tenantId: 'tenant-a', userId: 'user-1' }), { dismissed: 1 });
  assert.deepEqual(await f.authority.browserActiveStatus({ tenantId: 'tenant-a', userId: 'user-1' }), { setup: null });
});

test('a stalled unproved claim stops blocking a fresh setup session', async () => {
  const f = fixture();
  const item = await claimed(f, 'tenant-a');
  f.advance(30_001);
  assert.deepEqual(await f.authority.browserActiveStatus({ tenantId: 'tenant-a', userId: 'user-1' }), { setup: null });
  assert.equal((await f.authority.browserStatus({ sessionId: item.claim.session_id, tenantId: 'tenant-a', userId: 'user-1' })).status, 'expired');
  const replacement = await f.authority.create({ tenantId: 'tenant-a', userId: 'user-1' });
  assert.match(replacement.setup_token, /^lst_/);
  assert.equal((await f.authority.browserStatus({ sessionId: item.claim.session_id, tenantId: 'tenant-a', userId: 'user-1' })).status, 'failed');
});

test('failed saves do not publish mutations or consume setup tokens', async () => {
  const f = fixture();
  const key = identity();
  const created = await f.authority.create({ tenantId: 'tenant-a', userId: 'user-1' });
  f.store.failNextSave = true;
  await assert.rejects(() => f.authority.claim({ setupToken: created.setup_token, publicKeySpkiPem: key.pem, installationScope: SCOPE }), /save failure/);
  const retry = await f.authority.claim({ setupToken: created.setup_token, publicKeySpkiPem: key.pem, installationScope: SCOPE });
  assert.equal(typeof retry.session_token, 'string');
});

test('failed account deletion can clear its marker without restoring removed sessions', async () => {
  const f = fixture();
  await f.authority.create({ tenantId: 'user-1', userId: 'user-1' });
  assert.deepEqual(await f.authority.deleteTenant({ tenantId: 'user-1', userId: 'user-1' }), { removedSessions: 1 });
  await assert.rejects(() => f.authority.create({ tenantId: 'user-1', userId: 'user-1' }), /deleted/);
  assert.deepEqual(await f.authority.restoreTenantAfterFailedDeletion({ tenantId: 'user-1', userId: 'user-1' }), { restored: true });
  assert.match((await f.authority.create({ tenantId: 'user-1', userId: 'user-1' })).setup_token, /^lst_/);
});

test('completion is not published until the deployment snapshot is ready', async () => {
  let ready = false;
  const f = fixture({ completionValidator: async () => { if (!ready) throw new Error('Setup provisioning is not ready'); } });
  const item = await claimed(f);
  await f.authority.prove({ sessionId: item.claim.session_id, sessionToken: item.claim.session_token, signatureBase64url: signature(item) });
  await f.authority.reportPhase({ sessionId: item.claim.session_id, sessionToken: item.claim.session_token, phase: 'validating' });
  await assert.rejects(() => f.authority.reportPhase({ sessionId: item.claim.session_id, sessionToken: item.claim.session_token, phase: 'complete' }), /not ready/);
  assert.equal((await f.authority.status({ sessionId: item.claim.session_id, sessionToken: item.claim.session_token })).status, 'verifying');
  ready = true;
  await f.authority.reportPhase({ sessionId: item.claim.session_id, sessionToken: item.claim.session_token, phase: 'complete' });
  assert.equal((await f.authority.status({ sessionId: item.claim.session_id, sessionToken: item.claim.session_token })).status, 'complete');
});

test('shared setup stores refresh state before reads', async () => {
  let persisted = null;
  const store = {
    shared: true,
    async load() { return persisted && structuredClone(persisted); },
    async save(value) { persisted = structuredClone(value); }
  };
  const provisioningFactory = () => ({
    console_sync: { endpoint: 'https://app.example.test/v1/sync', credential: 'x'.repeat(40) },
    dashboard_url: 'https://app.example.test/deployments/example'
  });
  const first = new SetupSessionAuthority({ snapshotStore: store, provisioningFactory });
  const second = new SetupSessionAuthority({ snapshotStore: store, provisioningFactory });
  const created = await first.create({ tenantId: 'tenant-shared', userId: 'user-shared' });
  const status = await second.browserStatus({ sessionId: created.session_id, tenantId: 'tenant-shared', userId: 'user-shared' });
  assert.equal(status.status, 'pending');
});

test('bootstrap key publication requires the installer session and is visible to the bound browser', async () => {
  const f = fixture();
  const item = await claimed(f);
  await f.authority.prove({ sessionId: item.claim.session_id, sessionToken: item.claim.session_token, signatureBase64url: signature(item) });
  const key = { authorized_keys_line: `restrict ssh-ed25519 ${Buffer.alloc(32, 7).toString('base64')} lookout-bootstrap:deployment`, fingerprint: `SHA256:${Buffer.alloc(24, 8).toString('base64').replace(/=+$/, '')}` };
  await assert.rejects(() => f.authority.publishBootstrapKey({ sessionId: item.claim.session_id, sessionToken: 'x'.repeat(32), bootstrapKey: key }), /unavailable/);
  assert.deepEqual(await f.authority.publishBootstrapKey({ sessionId: item.claim.session_id, sessionToken: item.claim.session_token, bootstrapKey: key }), { accepted: true });
  const status = await f.authority.status({ sessionId: item.claim.session_id, sessionToken: item.claim.session_token });
  assert.deepEqual(status.bootstrap_key, key);
  const browser = await f.authority.browserStatus({ sessionId: item.claim.session_id, tenantId: 'tenant-a', userId: 'user-1' });
  assert.deepEqual(browser.bootstrap_key, key);
});

test('proved installations can report bounded redacted diagnostics to the browser', async () => {
  const f = fixture();
  const item = await claimed(f);
  await f.authority.prove({ sessionId: item.claim.session_id, sessionToken: item.claim.session_token, signatureBase64url: signature(item) });
  const receipt = await f.authority.recordDiagnostic({
    sessionId: item.claim.session_id, sessionToken: item.claim.session_token,
    diagnostic: { phase: 'installing', vm: 'api-1', error_code: 'ssh_failed', message: 'SSH connection failed' }
  });
  assert.match(receipt.diagnostic_id, /^diag_/);
  const browser = await f.authority.browserStatus({ sessionId: item.claim.session_id, tenantId: 'tenant-a', userId: 'user-1' });
  assert.equal(browser.diagnostics[0].vm, 'api-1');
  await assert.rejects(() => f.authority.recordDiagnostic({
    sessionId: item.claim.session_id, sessionToken: item.claim.session_token,
    diagnostic: { phase: 'installing', message: 'Bearer secret-value' }
  }), /unsafe/);
});

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { CliAuthorizationAuthority } = require('../src/onboarding/cli-authorization-authority');

const publicKey = crypto.generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' });
const scope = { central_vm_id: 'api-1', vms: [{ id: 'api-1', name: 'api-1', address: '10.0.1.10', platform: 'linux', provider: 'openssh', local: false }] };
const binding = { deploymentPublicKeySpkiPem: publicKey, installationScope: scope };

function fixture() {
  const setupCalls = [];
  const authority = new CliAuthorizationAuthority({
    setupAuthority: { async create(input) { setupCalls.push(input); return { setup_token: `lst_${'s'.repeat(43)}`, expires_at: '2026-08-22T12:10:00.000Z' }; } },
    clock: () => new Date('2026-08-22T12:00:00.000Z')
  });
  return { authority, setupCalls };
}

test('browser approval exchanges a PKCE-bound code for one installation permission', async () => {
  const { authority, setupCalls } = fixture();
  const verifier = 'v'.repeat(43);
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  const created = await authority.create({ codeChallenge: challenge, redirectUri: 'http://127.0.0.1:43210/callback', state: 'x'.repeat(32), ...binding });
  assert.match(created.request_id, /^cla_[A-Za-z0-9_-]{32}$/);
  const description = await authority.describe({ requestId: created.request_id });
  assert.equal(description.permission, 'create_one_deployment');
  assert.deepEqual(description.installation_scope, scope);
  assert.match(description.deployment_key_fingerprint, /^SHA256:/);
  assert.equal(Object.hasOwn(description, 'verification_code'), false);
  await assert.rejects(() => authority.approve({ requestId: created.request_id, tenantId: 'tenant-a', userId: 'user-a', verificationCode: '00000000' }), /verification failed/);
  const approved = await authority.approve({ requestId: created.request_id, tenantId: 'tenant-a', userId: 'user-a', email: 'a@example.test', verificationCode: created.verification_code });
  const redirect = new URL(approved.redirect_uri);
  assert.equal(redirect.origin, 'http://127.0.0.1:43210');
  assert.equal(redirect.searchParams.get('state'), 'x'.repeat(32));
  const exchanged = await authority.exchange({ requestId: created.request_id, code: redirect.searchParams.get('code'), codeVerifier: verifier });
  assert.equal(exchanged.setup_token, `lst_${'s'.repeat(43)}`);
  assert.deepEqual(setupCalls, [{ tenantId: 'tenant-a', userId: 'user-a', email: 'a@example.test', ttlMs: 10 * 60 * 1000, authorizedPublicKeySpkiPem: publicKey, authorizedInstallationScope: scope, authorizedDeploymentId: created.deployment_id }]);
  assert.equal(exchanged.deployment_id, created.deployment_id);
  await assert.rejects(() => authority.exchange({ requestId: created.request_id, code: redirect.searchParams.get('code'), codeVerifier: verifier }), /unavailable/);
});

test('CLI login rejects redirect, code, and verifier substitution', async () => {
  const { authority } = fixture();
  const verifier = 'z'.repeat(43);
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  await assert.rejects(() => authority.create({ codeChallenge: challenge, redirectUri: 'https://attacker.example/callback', state: 'x'.repeat(32) }), /loopback/);
  const created = await authority.create({ codeChallenge: challenge, redirectUri: 'http://127.0.0.1:43211/callback', state: 'x'.repeat(32), ...binding });
  const approved = await authority.approve({ requestId: created.request_id, tenantId: 'tenant-a', userId: 'user-a', verificationCode: created.verification_code });
  const code = new URL(approved.redirect_uri).searchParams.get('code');
  await assert.rejects(() => authority.exchange({ requestId: created.request_id, code, codeVerifier: 'q'.repeat(43) }), /unavailable/);
  await assert.rejects(() => authority.exchange({ requestId: created.request_id, code: 'bad', codeVerifier: verifier }), /invalid/);
});

test('CLI exchange returns the installation permission expiry', async () => {
  const requestExpiry = '2026-08-22T12:10:00.000Z';
  const setupExpiry = '2026-08-22T12:05:00.000Z';
  const authority = new CliAuthorizationAuthority({
    clock: () => new Date('2026-08-22T12:00:00.000Z'),
    setupAuthority: { create: async () => ({ setup_token: `lst_${'s'.repeat(43)}`, expires_at: setupExpiry }) }
  });
  const verifier = 'v'.repeat(43);
  const created = await authority.create({
    codeChallenge: crypto.createHash('sha256').update(verifier).digest('base64url'),
    redirectUri: 'http://127.0.0.1:43123/callback',
    state: 's'.repeat(43), ...binding
  });
  assert.equal(created.expires_at, requestExpiry);
  const approved = await authority.approve({ requestId: created.request_id, tenantId: 'tenant-1', userId: 'user-1', verificationCode: created.verification_code });
  const code = new URL(approved.redirect_uri).searchParams.get('code');
  const exchanged = await authority.exchange({ requestId: created.request_id, code, codeVerifier: verifier });
  assert.equal(exchanged.expires_at, setupExpiry);
});

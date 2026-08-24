'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { generateApiToken, hashToken, ApiAuthenticator } = require('../src/security/auth');
const { EnvironmentSecretProvider, FileSecretProvider, CompositeSecretProvider } = require('../src/security/secrets');

function request(token, address = '192.0.2.1') { return { headers: token ? { authorization: `Bearer ${token}` } : {}, socket: { remoteAddress: address } }; }

test('API tokens authenticate principals and roles enforce least privilege', () => {
  const viewer = generateApiToken();
  const ingestor = generateApiToken();
  const auth = new ApiAuthenticator({ credentials: [
    { id: 'viewer-1', tokenHash: viewer.hash, roles: ['viewer'] },
    { id: 'ingestor-1', tokenHash: ingestor.hash, roles: ['ingestor'], expiresAt: '2027-01-01T00:00:00.000Z' }
  ] });
  const principal = auth.authenticate(request(viewer.token), new Date('2026-08-17T00:00:00.000Z'));
  assert.equal(principal.id, 'viewer-1');
  assert.equal(auth.authorize(principal, 'read:graph'), true);
  assert.equal(auth.authorize(principal, 'manage:rules'), false);
  assert.equal(auth.authenticate(request('incorrect-but-long-enough')), null);
  assert.equal(hashToken(viewer.token), viewer.hash);
});

test('loopback administrator is explicit and never applies remotely', () => {
  const auth = new ApiAuthenticator({ allowLocalAdmin: true });
  assert.deepEqual(auth.authenticate(request(null, '127.0.0.1')).roles, ['admin']);
  assert.equal(auth.authenticate(request(null, '192.0.2.10')), null);
});

test('secret providers resolve only allowlisted references and enforce file permissions', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-secrets-'));
  const file = path.join(directory, 'token');
  try {
    const environment = new EnvironmentSecretProvider({ 'tailscale-token': 'TEST_TS_TOKEN' }, { TEST_TS_TOKEN: 'env-value' });
    assert.equal(await environment.get('tailscale-token'), 'env-value');
    await assert.rejects(() => environment.get('unknown'), /not allowlisted/);
    await fs.writeFile(file, 'file-value\n', { mode: 0o600 });
    const fromFile = new FileSecretProvider({ 'api-token': file });
    assert.equal(await fromFile.get('api-token'), 'file-value');
    const composite = new CompositeSecretProvider([environment, fromFile]);
    assert.equal(await composite.get('api-token'), 'file-value');
    await fs.chmod(file, 0o644);
    await assert.rejects(() => fromFile.get('api-token'), /permissions are too broad/);
  } finally { await fs.rm(directory, { recursive: true, force: true }); }
});

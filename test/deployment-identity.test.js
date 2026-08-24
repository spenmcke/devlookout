'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { loadOrCreateDeploymentIdentity, signSetupChallenge } = require('../src/onboarding/deployment-identity');

test('deployment identity is private, stable, and proves Ed25519 key possession', async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-deployment-identity-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const first = await loadOrCreateDeploymentIdentity(directory, { now: new Date('2026-08-19T00:00:00Z') });
  const second = await loadOrCreateDeploymentIdentity(directory);
  assert.equal(second.publicKeyPem, first.publicKeyPem);
  assert.equal((await fs.stat(path.join(directory, 'deployment-identity.json'))).mode & 0o777, 0o600);
  const challenge = crypto.randomBytes(32).toString('base64url');
  const signature = signSetupChallenge(first, challenge);
  assert.equal(crypto.verify(null, Buffer.from(challenge), first.publicKeyPem, Buffer.from(signature, 'base64url')), true);
});

test('deployment identity refuses broad permissions and mismatched keys', async (t) => {
  if (process.platform === 'win32') return t.skip('Unix permissions required');
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-deployment-identity-mode-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  await loadOrCreateDeploymentIdentity(directory);
  const filename = path.join(directory, 'deployment-identity.json');
  await fs.chmod(filename, 0o644);
  await assert.rejects(() => loadOrCreateDeploymentIdentity(directory), /must be private/);
});

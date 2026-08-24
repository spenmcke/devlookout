'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const { createBootstrapKey } = require('../src/fleet/bootstrap-key');

test('temporary bootstrap key is OpenSSH-compatible, private, marked, and non-overwriting', async (t) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-bootstrap-key-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const directory = path.join(root, 'keys');
  const created = await createBootstrapKey(directory, { deploymentId: 'fleet-test', now: new Date('2026-08-19T00:00:00.000Z') });
  assert.match(created.authorizedKeysLine, /^restrict ssh-ed25519 [A-Za-z0-9+/]+={0,2} lookout-bootstrap:fleet-test$/);
  assert.match(created.fingerprint, /^SHA256:/);
  if (process.platform !== 'win32') {
    assert.equal((await fs.stat(directory)).mode & 0o777, 0o700);
    for (const filename of [created.privateKeyFile, created.publicKeyFile, path.join(directory, 'lookout-bootstrap-key.json')]) assert.equal((await fs.stat(filename)).mode & 0o777, 0o600);
  }
  const parsed = execFileSync('/usr/bin/ssh-keygen', ['-y', '-f', created.privateKeyFile], { encoding: 'utf8' }).trim();
  assert.deepEqual(created.authorizedKeysLine.split(/\s+/).slice(1, 3), parsed.split(/\s+/).slice(0, 2));
  await assert.rejects(() => createBootstrapKey(directory, { deploymentId: 'fleet-test-2' }), /Refusing to replace/);
});

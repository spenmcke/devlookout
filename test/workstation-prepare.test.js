'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { WorkstationConfigStore, installationScopeDigest } = require('../src/cli/workstation-config');
const { prepare, validatePreparation, releaseFingerprint, PREPARATION_TTL_MS } = require('../src/cli/workstation-prepare');

const environment = {
  LOOKOUT_SSH_KNOWN_HOSTS: '/tmp/verified-known-hosts',
  LOOKOUT_RELEASE_TARGETS: JSON.stringify({
    amd64: { url: 'https://releases.example/amd64.tar.gz', sha256: 'a'.repeat(64) },
    arm64: { url: 'https://releases.example/arm64.tar.gz', sha256: 'b'.repeat(64) }
  })
};

function config() { return { schemaVersion: 1, centralVm: 'vm-1', vms: [{ name: 'vm-1', address: '10.0.0.1' }, { name: 'vm-2', address: '10.0.0.2' }] }; }

function manifest(configuration, preparedAt = new Date()) {
  return {
    schemaVersion: 1, scopeDigest: installationScopeDigest(configuration), releaseFingerprint: releaseFingerprint(environment), centralVm: configuration.centralVm,
    preparedAt: preparedAt.toISOString(), expiresAt: new Date(preparedAt.getTime() + PREPARATION_TTL_MS).toISOString(),
    nodes: configuration.vms.map((vm, index) => ({
      id: vm.name, platform: 'linux', architecture: index ? 'arm64' : 'amd64', reachable: true,
      preparedArtifact: { root: `/var/tmp/lookout-preflight-prepare-binding-${index + 1}`, source: `/var/tmp/lookout-preflight-prepare-binding-${index + 1}/source` }
    }))
  };
}

test('lookout prepare binds parallel staging to the exact configuration and release', async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-prepare-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const store = new WorkstationConfigStore({ directory });
  const configuration = config();
  let childEnvironment;
  const result = await prepare({
    config: configuration, store, environment, output: { write() {} },
    runImpl: (_source, value) => { childEnvironment = value; return JSON.stringify(manifest(configuration)); }
  });
  assert.equal(result.nodes.length, 2);
  assert.equal(childEnvironment.LOOKOUT_PREPARE_ONLY, '1');
  assert.equal(childEnvironment.LOOKOUT_SSH_KNOWN_HOSTS, environment.LOOKOUT_SSH_KNOWN_HOSTS);
  assert.equal((await store.loadPreparation()).scopeDigest, installationScopeDigest(configuration));
  assert.equal((await fs.stat(store.preparationFile)).mode & 0o777, 0o600);
  const reused = await prepare({ config: configuration, store, environment, output: { write() {} }, runImpl: () => { throw new Error('must not rerun'); } });
  assert.equal(reused.expiresAt, result.expiresAt);
});

test('prepared VM state expires and cannot be reused for another VM list or release', () => {
  const configuration = config();
  const value = manifest(configuration);
  assert.equal(validatePreparation(value, { config: configuration, environment }), value);
  assert.equal(validatePreparation(value, { config: configuration, environment, now: Date.parse(value.expiresAt) }), null);
  assert.equal(validatePreparation(value, { config: { ...configuration, vms: configuration.vms.slice(0, 1) }, environment }), null);
  const changed = { ...environment, LOOKOUT_RELEASE_TARGETS: JSON.stringify({ amd64: { url: 'https://releases.example/new-amd64.tar.gz', sha256: 'c'.repeat(64) }, arm64: { url: 'https://releases.example/new-arm64.tar.gz', sha256: 'd'.repeat(64) } }) };
  assert.equal(validatePreparation(value, { config: configuration, environment: changed }), null);
});

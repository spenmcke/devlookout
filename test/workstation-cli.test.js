'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const cli = path.resolve(__dirname, '../bin/lookout.js');
const { refreshInstalledCliTargets } = require('../bin/lookout');

function run(args, directory) {
  return spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8', env: { ...process.env, LOOKOUT_CLI_STATE_DIR: directory } });
}

test('agent can configure and inspect a workstation fleet through the CLI', async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-workstation-cli-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  let result = run(['vm', 'add', '--name', 'api-1', '--address', '10.0.1.10', '--ssh-host', 'production-api', '--ssh-user', 'ubuntu'], directory);
  assert.equal(result.status, 0, result.stderr);
  result = run(['vm', 'add', '--name', 'db-1', '--address', '10.0.1.11'], directory);
  assert.equal(result.status, 0, result.stderr);
  result = run(['vm', 'central', 'api-1'], directory);
  assert.equal(result.status, 0, result.stderr);
  result = run(['vm', 'list'], directory);
  assert.equal(result.status, 0, result.stderr);
  const config = JSON.parse(result.stdout);
  assert.equal(config.centralVm, 'api-1');
  assert.deepEqual(config.vms.map((vm) => vm.name), ['api-1', 'db-1']);
  assert.equal(config.vms[0].sshHost, 'production-api');
});

test('CLI reports its installed release version', () => {
  const result = spawnSync(process.execPath, [cli, 'version'], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /^Lookout CLI v\d+\.\d+\.\d+\n$/);
});

test('installed CLI refreshes pinned targets from its authenticated SaaS origin', async () => {
  const original = {
    amd64: { url: 'https://app.example.test/old-amd64.tar.gz', sha256: 'a'.repeat(64) },
    arm64: { url: 'https://app.example.test/old-arm64.tar.gz', sha256: 'b'.repeat(64) }
  };
  const replacement = {
    amd64: { url: 'https://app.example.test/new-amd64.tar.gz', sha256: 'c'.repeat(64) },
    arm64: { url: 'https://app.example.test/new-arm64.tar.gz', sha256: 'd'.repeat(64) }
  };
  const environment = { LOOKOUT_RELEASE_TARGETS: JSON.stringify(original) };
  await refreshInstalledCliTargets({
    async loadLogin() { return { origin: 'https://app.example.test' }; }
  }, {
    environment,
    refreshImpl: async ({ pinnedTargets, origin }) => {
      assert.deepEqual(pinnedTargets, original);
      assert.equal(origin, 'https://app.example.test');
      return replacement;
    }
  });
  assert.deepEqual(JSON.parse(environment.LOOKOUT_RELEASE_TARGETS), replacement);
});

test('CLI exposes account-bound support reporting without a token argument', async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-workstation-report-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const result = run(['report'], directory);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /run lookout login/);
  assert.doesNotMatch(result.stderr, /support token/i);
});

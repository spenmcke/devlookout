'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { purgeLocalOrchestrationState, purgeCompleteLocalState, purgeWorkstationCli } = require('../install/uninstall-fleet');

test('successful fleet purge removes only exact local Lookout orchestration state', (t) => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'lookout-local-purge-'));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  const root = path.join(home, '.lookout');
  const install = path.join(root, 'install');
  fs.mkdirSync(install, { recursive: true });
  for (const filename of ['security-observability-config.json', 'fleet.json', 'deployment-state.json', 'known_hosts']) fs.writeFileSync(path.join(root, filename), 'fixture');
  fs.writeFileSync(path.join(install, 'onboarding-state.json'), 'fixture');
  const unrelated = path.join(home, 'keep-me');
  fs.writeFileSync(unrelated, 'untouched');

  purgeLocalOrchestrationState(home);

  assert.equal(fs.existsSync(root), false);
  assert.equal(fs.readFileSync(unrelated, 'utf8'), 'untouched');
});

test('local purge preserves unrelated files inside the Lookout root', (t) => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'lookout-local-purge-bounded-'));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  const root = path.join(home, '.lookout');
  fs.mkdirSync(root, { recursive: true });
  const unrelated = path.join(root, 'unrelated-user-file');
  fs.writeFileSync(unrelated, 'untouched');

  purgeLocalOrchestrationState(home);

  assert.equal(fs.readFileSync(unrelated, 'utf8'), 'untouched');
});

test('explicit complete removal clears recognized workstation state', (t) => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'lookout-local-complete-'));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  const root = path.join(home, '.lookout');
  fs.mkdirSync(root, { recursive: true });
  fs.writeFileSync(path.join(root, 'fleet.json'), '{}');
  fs.writeFileSync(path.join(root, 'login.json'), 'credential fixture');
  purgeCompleteLocalState(home);
  assert.equal(fs.existsSync(root), false);
});

test('complete removal deletes only an ownership-verified workstation CLI', (t) => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'lookout-cli-complete-'));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  const dataRoot = path.join(home, '.local', 'share', 'lookout', 'cli');
  const release = path.join(dataRoot, 'releases', 'v0.1.0-fixture');
  const executable = path.join(release, 'bin', 'lookout.js');
  const launcher = path.join(home, '.local', 'bin', 'lookout');
  fs.mkdirSync(path.dirname(executable), { recursive: true });
  fs.mkdirSync(path.dirname(launcher), { recursive: true });
  fs.writeFileSync(path.join(release, '.lookout-cli-release.json'), JSON.stringify({ schemaVersion: 1, releaseVersion: 'v0.1.0', artifactSha256: 'a'.repeat(64) }));
  fs.writeFileSync(executable, 'fixture');
  fs.symlinkSync(executable, launcher);
  purgeWorkstationCli({ homeDirectory: home, environment: {}, platform: 'linux' });
  assert.equal(fs.existsSync(dataRoot), false);
  assert.equal(fs.existsSync(launcher), false);
});

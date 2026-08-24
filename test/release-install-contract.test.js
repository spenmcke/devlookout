'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');
const { artifactPreflightScript } = require('../src/fleet/release-artifact');

function run(command, args) {
  const result = spawnSync(command, args, { encoding: 'utf8' });
  if (result.status !== 0) throw new Error(result.stderr || `${command} failed`);
  return result.stdout;
}

function fixture(t, { wrapped = true, missing = null } = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'lookout-release-contract-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const source = path.join(directory, wrapped ? 'lookout-v0.1.0' : 'source');
  for (const filename of ['package.json', 'package-lock.json', 'install/install.sh', 'src/server.js', 'runtime/bin/node', 'node_modules/yaml/package.json']) {
    if (filename === missing) continue;
    const target = path.join(source, filename);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, filename.endsWith('install.sh') || filename.endsWith('/node') ? '#!/bin/sh\nexit 0\n' : '{}\n', { mode: filename.endsWith('install.sh') || filename.endsWith('/node') ? 0o755 : 0o644 });
  }
  const archive = path.join(directory, 'release.tar.gz');
  run('tar', ['-C', wrapped ? directory : source, '-czf', archive, wrapped ? 'lookout-v0.1.0' : '.']);
  return { directory, archive, output: path.join(directory, 'output'), listing: path.join(directory, 'listing') };
}

function preflight(value) {
  const digest = crypto.createHash('sha256').update(fs.readFileSync(value.archive)).digest('hex');
  return spawnSync('sh', ['-c', artifactPreflightScript(), 'lookout-artifact-preflight', value.archive, digest, value.output, value.listing, '0'], { encoding: 'utf8' });
}

for (const wrapped of [true, false]) {
  test(`release preflight normalizes ${wrapped ? 'version-wrapped' : 'flat'} archives to the installer contract`, (t) => {
    const value = fixture(t, { wrapped });
    const result = preflight(value);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(fs.statSync(path.join(value.output, 'install/install.sh')).isFile(), true);
    assert.equal(run(path.join(value.output, 'install/install.sh'), []).trim(), '');
  });
}

test('release preflight rejects a missing installer before extraction can be activated', (t) => {
  const value = fixture(t, { missing: 'install/install.sh' });
  const result = preflight(value);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /no unique install root|missing install\/install\.sh/);
});

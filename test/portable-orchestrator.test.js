'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { Writable } = require('node:stream');
const { runInstaller, userStateDirectory } = require('../install/onboard');
const { resolveExecutable } = require('../src/platform/executable');

test('Windows and macOS use per-user orchestration state directories', () => {
  assert.equal(userStateDirectory({ platform: 'darwin', home: '/Users/operator', environment: {} }), path.join('/Users/operator', '.lookout', 'install'));
  assert.equal(userStateDirectory({ platform: 'win32', home: 'C:\\Users\\operator', environment: { LOCALAPPDATA: 'C:\\Users\\operator\\AppData\\Local' } }), path.win32.join('C:\\Users\\operator\\AppData\\Local', 'Lookout', 'install'));
});

test('executable resolution supports Windows PATHEXT without shell interpolation', async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-executable-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const executable = path.join(directory, 'ssh.EXE');
  await fs.writeFile(executable, 'fixture');
  assert.equal(resolveExecutable('ssh', { platform: 'win32', environment: { PATH: directory, PATHEXT: '.EXE;.CMD' } }), executable);
  assert.equal(resolveExecutable('ssh;whoami', { platform: 'win32', environment: { PATH: directory, PATHEXT: '.EXE' } }), null);
});

test('runInstaller launches fleet.js directly with process.execPath and never fleet.sh', async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-direct-fleet-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  await fs.mkdir(path.join(directory, 'install'));
  const shellMarker = path.join(directory, 'shell-ran');
  await fs.writeFile(path.join(directory, 'install', 'fleet.sh'), `#!/bin/sh\ntouch '${shellMarker}'\n`, { mode: 0o755 });
  await fs.writeFile(path.join(directory, 'install', 'fleet.js'), "process.stdout.write(JSON.stringify({ mode: 'direct', execPath: process.execPath }) + '\\n');\n");
  const output = new Writable({ write(chunk, encoding, callback) { callback(); } });
  const result = await runInstaller({ sourceDirectory: directory, environment: process.env, output });
  assert.equal(result.mode, 'direct');
  assert.equal(result.execPath, process.execPath);
  await assert.rejects(fs.access(shellMarker), { code: 'ENOENT' });
});

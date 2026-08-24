'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {
  createSshControlDirectory,
  expandedControlPath,
  fitsOpenSshControlPath,
  SAFE_CONTROL_PATH_BYTES
} = require('../src/cli/ssh-control-path');

test('SSH control sockets fall back from a long macOS-style temporary path', { skip: process.platform === 'win32' }, (t) => {
  const root = fs.mkdtempSync('/tmp/lookout-control-test-');
  const longTemporaryDirectory = path.join(root, 'a'.repeat(80));
  fs.mkdirSync(longTemporaryDirectory);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));

  const directory = createSshControlDirectory({
    temporaryDirectory: longTemporaryDirectory,
    fallbackDirectory: root,
    platform: 'darwin'
  });

  assert.equal(directory.startsWith(`${root}${path.sep}lo-ssh-`), true);
  assert.equal(fitsOpenSshControlPath(directory), true);
  assert.equal(Buffer.byteLength(expandedControlPath(directory)) <= SAFE_CONTROL_PATH_BYTES, true);
  assert.equal(fs.statSync(directory).mode & 0o777, 0o700);
});

test('SSH multiplexing is disabled on Windows', () => {
  assert.equal(createSshControlDirectory({ platform: 'win32' }), null);
});

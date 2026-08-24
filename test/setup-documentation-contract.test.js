'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const repository = path.resolve(__dirname, '..');

function read(filename) {
  return fs.readFileSync(path.join(repository, filename), 'utf8');
}

test('installation docs preserve the CLI authentication and retry contract', () => {
  const install = read('docs/content/docs/install.mdx');

  assert.match(install, /Authentication is performed only by you through `lookout login`/);
  assert.match(install, /does not receive your password or browser session/);
  assert.match(install, /short-lived permission that can create one deployment/);
  assert.match(install, /`lookout diagnose`/);
  assert.match(install, /`lookout install --retry`/);
  assert.match(install, /resumes a saved deployment when possible and otherwise starts a new installation attempt/);
});

test('installation docs keep the supported human setup contract', () => {
  const install = read('docs/content/docs/install.mdx');

  assert.match(install, /https:\/\/app\.devlookout\.com\/setup/);
  assert.match(install, /agent configures the workstation CLI/);
  assert.match(install, /You run `lookout login`/);
  assert.match(install, /agent runs `lookout install`/);
  assert.match(install, /source-checkout installer does not perform the browser login flow/);
  assert.match(install, /The existing installation is not removed/);
  assert.match(install, /Selecting \*\*Try again\*\* creates a support ticket/);
  assert.match(install, /support@devlookout\.com/);
  assert.match(install, /will never ask for your installation permission, password, private key/);
});

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { WorkstationConfigStore, installationScope } = require('../src/cli/workstation-config');

test('workstation configuration stores VMs without SSH secrets', async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-workstation-config-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const store = new WorkstationConfigStore({ directory });
  await store.addVm({ name: 'api-1', address: '10.0.1.10', sshHost: 'production-api', sshUser: 'ubuntu' });
  await store.addVm({ name: 'db-1', address: 'db-1.internal' });
  const config = await store.setCentral('api-1');
  assert.deepEqual(config.vms.map((vm) => vm.name), ['api-1', 'db-1']);
  assert.equal(JSON.stringify(config).includes('private'), false);
  assert.equal(JSON.stringify(config).includes('password'), false);
  assert.deepEqual(installationScope(config), {
    central_vm_id: 'api-1',
    vms: [
      { id: 'api-1', name: 'api-1', address: '10.0.1.10', ssh_host: 'production-api', ssh_user: 'ubuntu', platform: 'linux', provider: 'openssh', local: false },
      { id: 'db-1', name: 'db-1', address: 'db-1.internal', platform: 'linux', provider: 'openssh', local: false }
    ]
  });
  assert.equal((await fs.stat(store.configFile)).mode & 0o777, 0o600);
});

test('installation permission is private, expires, and can be cleared', async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-workstation-login-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const store = new WorkstationConfigStore({ directory });
  await store.saveLogin({ setupToken: `lst_${'a'.repeat(43)}`, deploymentId: `dpl_${'d'.repeat(32)}`, expiresAt: new Date(Date.now() + 60000).toISOString(), origin: 'https://app.example' });
  assert.match((await store.loadLogin()).setupToken, /^lst_/);
  assert.equal((await fs.stat(store.loginFile)).mode & 0o777, 0o600);
  await store.saveLogin({ setupToken: `lst_${'a'.repeat(43)}`, deploymentId: `dpl_${'d'.repeat(32)}`, expiresAt: new Date(Date.now() - 60000).toISOString(), origin: 'https://app.example' });
  await assert.rejects(() => store.loadLogin(), /missing or expired/);
  assert.match((await store.loadLogin({ allowExpired: true })).setupToken, /^lst_/);
  await store.clearLogin();
  await assert.rejects(() => store.loadLogin(), /missing or expired/);
});

test('pending browser login exposes only the bound deployment metadata', async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-workstation-pending-login-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const store = new WorkstationConfigStore({ directory });
  await store.savePendingLogin({
    deploymentId: `dpl_${'p'.repeat(32)}`, expiresAt: new Date(Date.now() + 60000).toISOString(),
    origin: 'https://app.example', scopeDigest: 's'.repeat(43), keyFingerprint: 'SHA256:test'
  });
  const pending = await store.loadPendingLogin();
  assert.equal(pending.deploymentId, `dpl_${'p'.repeat(32)}`);
  assert.equal(Object.hasOwn(pending, 'setupToken'), false);
  assert.equal((await fs.stat(store.pendingLoginFile)).mode & 0o777, 0o600);
  await store.clearPendingLogin();
  await assert.rejects(() => store.loadPendingLogin(), /has not started/);
});

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { deleteHostedAccount } = require('../src/onboarding/account-delete');

test('failed auth deletion clears deletion markers so the active account is not stranded', async () => {
  const calls = [];
  const setupAuthority = {
    async deleteTenant() { calls.push('setup-delete'); },
    async restoreTenantAfterFailedDeletion() { calls.push('setup-restore'); return { restored: true }; }
  };
  const consoleStore = {
    async deleteTenant() { calls.push('console-delete'); },
    async restoreTenantAfterFailedDeletion() { calls.push('console-restore'); return { restored: true }; }
  };
  await assert.rejects(() => deleteHostedAccount({
    tenantId: 'user-1', userId: 'user-1', setupAuthority, consoleStore,
    deleteAuthUser: async () => { calls.push('auth-delete'); throw new Error('not deleted'); }
  }), /not deleted/);
  assert.deepEqual(calls, ['setup-delete', 'console-delete', 'auth-delete', 'console-restore', 'setup-restore']);
});

test('successful account deletion keeps deletion markers', async () => {
  let restored = false;
  const setupAuthority = { async deleteTenant() {}, async restoreTenantAfterFailedDeletion() { restored = true; } };
  const consoleStore = { async deleteTenant() {}, async restoreTenantAfterFailedDeletion() { restored = true; } };
  assert.deepEqual(await deleteHostedAccount({
    tenantId: 'user-1', userId: 'user-1', setupAuthority, consoleStore, deleteAuthUser: async () => {}
  }), { deleted: true });
  assert.equal(restored, false);
});

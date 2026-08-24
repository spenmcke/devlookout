'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { CentralRecoveryMonitor } = require('../src/hosting/central-recovery');

test('missing central heartbeat creates one recovery token and sends dashboard email', async () => {
  const marked = [];
  const emails = [];
  const consoleStore = {
    async missingCentral() {
      return [
        { tenantId: 'tenant-a', deploymentId: `dpl_${'a'.repeat(32)}`, updatedAt: '2026-08-21T00:00:00.000Z', recovery: null },
        { tenantId: 'tenant-b', deploymentId: `dpl_${'b'.repeat(32)}`, updatedAt: '2026-08-21T00:00:00.000Z', recovery: { session_id: 'existing' } }
      ];
    },
    async markCentralMissing(value) { marked.push(value); }
  };
  const setupAuthority = {
    async activeRecovery() { return true; },
    async createRecovery({ deploymentId }) {
      return { session_id: 'set_recovery_session_1234', setup_token: `lrc_${'r'.repeat(43)}`, deployment_id: deploymentId, notification_email: 'owner@example.test' };
    }
  };
  const emailNotifier = { async sendCentralRecovery(value) { emails.push(value); } };
  const monitor = new CentralRecoveryMonitor({ consoleStore, setupAuthority, emailNotifier, clock: () => new Date('2026-08-21T01:00:00.000Z') });
  assert.deepEqual(await monitor.sweep(), [`dpl_${'a'.repeat(32)}`]);
  assert.equal(marked.length, 1);
  assert.equal(marked[0].recoverySessionId, 'set_recovery_session_1234');
  assert.deepEqual(emails, [{ to: 'owner@example.test', deploymentId: `dpl_${'a'.repeat(32)}`, lastHeartbeatAt: '2026-08-21T00:00:00.000Z' }]);
});

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { notifyConfiguredConsoleUninstall } = require('../src/console/configured');

function config(enabled = true) {
  return {
    consoleSync: { enabled, endpoint: 'https://app.example/v1/console-sync/dpl_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', credentialReference: 'console-token' },
    secrets: { environment: { 'console-token': 'LOOKOUT_TEST_CONSOLE_TOKEN' }, files: {} }
  };
}

test('local uninstall sends an authenticated bounded SaaS lifecycle notification', async () => {
  const calls = [];
  const result = await notifyConfiguredConsoleUninstall(config(), {
    environment: { LOOKOUT_TEST_CONSOLE_TOKEN: 'secret-console-token' },
    fetchImpl: async (url, options) => {
      calls.push({ url, options });
      return new Response('{"status":"uninstalled"}', { status: 200, headers: { 'content-type': 'application/json' } });
    }
  });
  assert.deepEqual(result, { notified: true });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, config().consoleSync.endpoint);
  assert.equal(calls[0].options.method, 'DELETE');
  assert.equal(calls[0].options.headers.Authorization, 'Bearer secret-console-token');
  assert.equal(calls[0].options.body, undefined);
});

test('uninstall notification skips non-SaaS installs and fails closed on rejection', async () => {
  assert.deepEqual(await notifyConfiguredConsoleUninstall(config(false)), { notified: false, reason: 'not_configured' });
  await assert.rejects(() => notifyConfiguredConsoleUninstall(config(), {
    environment: { LOOKOUT_TEST_CONSOLE_TOKEN: 'secret-console-token' },
    fetchImpl: async () => new Response('{}', { status: 503 })
  }), /HTTP 503/);
});

test('uninstaller stops services before notifying as the credential-owning service account', () => {
  const source = fs.readFileSync(path.resolve(__dirname, '../install/uninstall.sh'), 'utf8');
  const stop = source.indexOf('run_systemctl disable --now lookout.service');
  const notify = source.indexOf('runuser -u lookout -- "$LOOKOUT_COMMAND" deployment-uninstall');
  const remove = source.indexOf('note "Removing Lookout application and systemd units..."');
  assert.ok(stop >= 0 && notify > stop && remove > notify);
});

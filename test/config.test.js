'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { validateConfig, loadConfig, readSecureJson, configFromEnvironment } = require('../src/config');
const { readTlsFile } = require('../src/server');

test('configuration is strict, deterministic, and resolves paths relative to its file', async () => {
  const directory = await fsp.mkdtemp(path.join(os.tmpdir(), 'lookout-config-'));
  try {
    const filename = path.join(directory, 'lookout.json');
    await fsp.writeFile(filename, JSON.stringify({ schemaVersion: 1, server: { host: '127.0.0.1', port: 9443, allowLoopbackAdmin: false }, storage: { dataDirectory: 'state', requireEncryption: true, retentionDays: 30 }, auth: { credentialsFile: 'auth.json' }, collectors: { keysFile: 'collectors.json' }, export: { enabled: false } }));
    const config = loadConfig({ filename, environment: {}, cwd: '/' });
    assert.equal(config.storage.dataDirectory, path.join(directory, 'state'));
    assert.equal(config.auth.credentialsFile, path.join(directory, 'auth.json'));
    assert.equal(config.server.allowLoopbackAdmin, false);
    assert.deepEqual(config.server.approvedSourceAddresses, ['127.0.0.1', '::1', '::ffff:127.0.0.1']);
    assert.equal(config.storage.retentionDays, 30);
    assert.equal(config.storage.auditRetentionDays, 7);
    assert.equal(config.storage.maximumPercent, 2);
  } finally { await fsp.rm(directory, { recursive: true, force: true }); }
});

test('configuration rejects unknown fields, unsafe exposure, literal secrets, and insecure export', () => {
  assert.throws(() => validateConfig({ server: { host: '0.0.0.0' } }), /Invalid Lookout configuration/);
  assert.throws(() => validateConfig({ server: { host: '0.0.0.0' }, storage: { requireEncryption: false }, auth: { legacyTokenEnvironment: 'LOOKOUT_API_TOKEN' } }), (error) => error.issues.some((issue) => issue.includes('requireEncryption')));
  assert.throws(() => validateConfig({ auth: { apiToken: 'do-not-store-this' } }), (error) => error.issues.some((issue) => issue.includes('apiToken')));
  assert.throws(() => validateConfig({ server: { approvedSourceAddresses: ['not-an-ip'] } }), (error) => error.issues.some((issue) => issue.includes('approvedSourceAddresses')));
  assert.throws(() => validateConfig({ export: { enabled: true, type: 'https', endpoint: 'http://logs.example' } }), /Invalid Lookout configuration/);
});

test('cloud export requires explicit categories and an allowlisted secret reference', () => {
  const config = validateConfig({
    secrets: { environment: { 'cloud-token': 'LOOKOUT_CLOUD_TOKEN' } },
    export: { enabled: true, type: 'https', endpoint: 'https://logs.example.test/v1/events', credentialReference: 'cloud-token', categories: ['identity', 'configuration'] }
  });
  assert.deepEqual(config.export.categories, ['configuration', 'identity']);
  assert.equal(config.secrets.environment['cloud-token'], 'LOOKOUT_CLOUD_TOKEN');
  assert.throws(() => validateConfig({ export: { enabled: true, type: 'https', endpoint: 'https://logs.example.test' } }), (error) => error.issues.some((issue) => issue.includes('categories')));
  assert.throws(() => validateConfig({ export: { enabled: true, type: 'https', endpoint: 'https://logs.example.test', categories: ['identity'], credentialReference: 'missing' } }), (error) => error.issues.some((issue) => issue.includes('credentialReference')));
});

test('SaaS console sync is a separate HTTPS-only summary channel', () => {
  const config = validateConfig({
    secrets: { files: { 'console-token': '/run/secrets/lookout-console-token' } },
    consoleSync: { enabled: true, endpoint: 'https://console.example.test/v1/snapshots', credentialReference: 'console-token', deploymentId: 'deployment-123' }
  });
  assert.equal(config.consoleSync.enabled, true);
  assert.equal(config.consoleSync.intervalSeconds, 30);
  assert.equal(config.consoleSync.deploymentId, 'deployment-123');
  assert.equal(config.export.enabled, false);
  assert.throws(() => validateConfig({ consoleSync: { enabled: true, endpoint: 'http://console.example.test', credentialReference: 'missing' } }), (error) => error.issues.some((issue) => issue.includes('consoleSync.endpoint')));
  assert.throws(() => validateConfig({ secrets: { files: { token: '/run/token' } }, consoleSync: { enabled: true, endpoint: 'https://console.example.test/?tenant=wrong', credentialReference: 'token', deploymentId: 'deployment-123' } }), (error) => error.issues.some((issue) => issue.includes('consoleSync.endpoint')));
  assert.throws(() => validateConfig({ secrets: { files: { token: '/run/token' } }, consoleSync: { enabled: true, endpoint: 'https://console.example.test', credentialReference: 'token' } }), (error) => error.issues.some((issue) => issue.includes('deploymentId')));
});

test('continuous Tailscale collection and alert webhooks require allowlisted credentials', () => {
  const config = validateConfig({
    secrets: { environment: { 'tailscale-token': 'TAILSCALE_API_TOKEN', 'webhook-token': 'LOOKOUT_WEBHOOK_TOKEN' } },
    collectors: { tailscale: { enabled: true, tailnet: 'example.com', credentialReference: 'tailscale-token', modes: ['network-flow', 'configuration-audit'] } },
    alertWebhook: { enabled: true, endpoint: 'https://alerts.example.test/lookout', credentialReference: 'webhook-token' }
  });
  assert.equal(config.collectors.tailscale.pollIntervalSeconds, 15);
  assert.equal(config.collectors.tailscale.authMode, 'api-token');
  assert.equal(config.alertWebhook.flushIntervalSeconds, 5);
  assert.throws(() => validateConfig({ collectors: { tailscale: { enabled: true, tailnet: 'example.com', credentialReference: 'missing' } } }), (error) => error.issues.some((issue) => issue.includes('credentialReference')));
  assert.throws(() => validateConfig({ alertWebhook: { enabled: true, endpoint: 'http://alerts.example.test' } }), (error) => error.issues.some((issue) => issue.includes('https')));
  const environmentConfig = validateConfig(configFromEnvironment({ LOOKOUT_TAILSCALE_TAILNET: 'example.com', TAILSCALE_API_TOKEN: 'secret-not-persisted' }));
  assert.equal(environmentConfig.collectors.tailscale.enabled, true);
  assert.equal(environmentConfig.secrets.environment['tailscale-log-token'], 'TAILSCALE_API_TOKEN');
});

test('current alert webhook configuration supports cooldown and allowlisted credentials', () => {
  const config = validateConfig({
    secrets: { environment: { 'webhook-token': 'LOOKOUT_WEBHOOK_TOKEN' } },
    webhook: { enabled: true, type: 'https', endpoint: 'https://hooks.example.test/lookout', credentialReference: 'webhook-token', cooldownSeconds: 600 }
  });
  assert.equal(config.webhook.enabled, true);
  assert.equal(config.webhook.cooldownSeconds, 600);
  assert.throws(() => validateConfig({ webhook: { enabled: true, type: 'https', endpoint: 'http://hooks.example.test' } }), (error) => error.issues.some((issue) => issue.includes('webhook.endpoint')));
  assert.throws(() => validateConfig({ webhook: { enabled: true, type: 'https', endpoint: 'https://hooks.example.test', credentialReference: 'missing' } }), (error) => error.issues.some((issue) => issue.includes('webhook.credentialReference')));
});

test('sensitive JSON files require owner-only permissions', async () => {
  const directory = await fsp.mkdtemp(path.join(os.tmpdir(), 'lookout-secure-json-'));
  const filename = path.join(directory, 'auth.json');
  try {
    await fsp.writeFile(filename, '{"credentials":[]}', { mode: 0o600 });
    assert.deepEqual(readSecureJson(filename), { credentials: [] });
    if (process.platform !== 'win32') {
      fs.chmodSync(filename, 0o644);
      assert.throws(() => readSecureJson(filename), /must not be accessible/);
      fs.chmodSync(filename, 0o600);
      const link = path.join(directory, 'auth-link.json');
      await fsp.symlink(filename, link);
      assert.throws(() => readSecureJson(link), /non-symlink/);
    }
  } finally { await fsp.rm(directory, { recursive: true, force: true }); }
});

test('server TLS configuration is path-resolved and private keys require owner-only permissions', async () => {
  const directory = await fsp.mkdtemp(path.join(os.tmpdir(), 'lookout-tls-config-'));
  try {
    const config = validateConfig({ server: { tls: { certificateFile: 'tls/server.crt', privateKeyFile: 'tls/server.key' } } }, { cwd: directory });
    assert.equal(config.server.tls.certificateFile, path.join(directory, 'tls/server.crt'));
    assert.equal(config.server.tls.privateKeyFile, path.join(directory, 'tls/server.key'));
    assert.throws(() => validateConfig({ server: { tls: { certificateFile: 'server.crt' } } }), /Invalid Lookout configuration/);
    const key = path.join(directory, 'server.key');
    await fsp.writeFile(key, 'private material', { mode: 0o600 });
    assert.equal(readTlsFile(key, 'TLS key', { privateFile: true }), 'private material');
    if (process.platform !== 'win32') {
      await fsp.chmod(key, 0o644);
      assert.throws(() => readTlsFile(key, 'TLS key', { privateFile: true }), /owner-only/);
    }
  } finally { await fsp.rm(directory, { recursive: true, force: true }); }
});

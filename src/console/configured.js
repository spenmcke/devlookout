'use strict';

const { EnvironmentSecretProvider, FileSecretProvider, CompositeSecretProvider } = require('../security/secrets');
const { createConsoleSyncService } = require('./sync');
const { createOperationalHealthSyncService } = require('../operations-health/sync');

function consoleCredentialProvider(config, environment) {
  const providers = [];
  if (Object.keys(config.secrets.environment).length) providers.push(new EnvironmentSecretProvider(config.secrets.environment, environment));
  if (Object.keys(config.secrets.files).length) providers.push(new FileSecretProvider(config.secrets.files));
  return new CompositeSecretProvider(providers);
}

function createConfiguredConsoleSync(config, { protector = null, environment = process.env } = {}) {
  if (!config?.consoleSync?.enabled) return null;
  return createConsoleSyncService({
    dataDirectory: config.storage.dataDirectory, endpoint: config.consoleSync.endpoint,
    credentialProvider: consoleCredentialProvider(config, environment), credentialReference: config.consoleSync.credentialReference,
    deploymentId: config.consoleSync.deploymentId,
    protector, requireEncryption: config.storage.requireEncryption,
    maxPending: config.consoleSync.maxPending, batchSize: 1
  });
}

function createConfiguredOperationalHealthSync(config, { protector = null, environment = process.env } = {}) {
  if (!config?.consoleSync?.enabled) return null;
  return createOperationalHealthSyncService({
    dataDirectory: config.storage.dataDirectory, consoleEndpoint: config.consoleSync.endpoint,
    credentialProvider: consoleCredentialProvider(config, environment), credentialReference: config.consoleSync.credentialReference,
    protector, requireEncryption: config.storage.requireEncryption
  });
}

async function notifyConfiguredConsoleUninstall(config, { environment = process.env, fetchImpl = globalThis.fetch, timeoutMs = 10000 } = {}) {
  if (!config?.consoleSync?.enabled) return { notified: false, reason: 'not_configured' };
  if (typeof fetchImpl !== 'function' || !Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 30000) throw new Error('Console uninstall notification configuration is invalid');
  const credential = await consoleCredentialProvider(config, environment).get(config.consoleSync.credentialReference);
  if (typeof credential !== 'string' || !credential || /[\r\n]/.test(credential)) throw new Error('Console uninstall credential is invalid');
  let response;
  try {
    response = await fetchImpl(config.consoleSync.endpoint, {
      method: 'DELETE', redirect: 'error', signal: AbortSignal.timeout(timeoutMs),
      headers: { Accept: 'application/json', Authorization: `Bearer ${credential}`, 'User-Agent': 'lookout-uninstall/1' }
    });
  } catch { throw new Error('SaaS uninstall notification failed'); }
  const reader = response.body?.getReader();
  let size = 0;
  if (reader) {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > 64 * 1024) { await reader.cancel(); throw new Error('SaaS uninstall response is too large'); }
    }
  }
  if (response.status !== 200 && response.status !== 204) throw new Error(`SaaS uninstall notification returned HTTP ${response.status}`);
  return { notified: true };
}

module.exports = { createConfiguredConsoleSync, createConfiguredOperationalHealthSync, notifyConfiguredConsoleUninstall };

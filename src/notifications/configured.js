'use strict';

const { EnvironmentSecretProvider, FileSecretProvider, CompositeSecretProvider } = require('../security/secrets');
const { createAlertWebhookService } = require('./alert-webhook');

function createConfiguredAlertWebhook(config, { protector = null, environment = process.env, fetchImpl = globalThis.fetch } = {}) {
  if (!config?.webhook?.enabled) return null;
  const providers = [];
  if (Object.keys(config.secrets.environment).length) providers.push(new EnvironmentSecretProvider(config.secrets.environment, environment));
  if (Object.keys(config.secrets.files).length) providers.push(new FileSecretProvider(config.secrets.files));
  const credentialProvider = providers.length ? new CompositeSecretProvider(providers) : null;
  return createAlertWebhookService({
    dataDirectory: config.storage.dataDirectory,
    endpoint: config.webhook.endpoint,
    credentialProvider,
    credentialReference: config.webhook.credentialReference,
    protector,
    requireEncryption: config.storage.requireEncryption,
    maxPending: config.webhook.maxPending,
    batchSize: config.webhook.batchSize,
    cooldownSeconds: config.webhook.cooldownSeconds,
    fetchImpl
  });
}

module.exports = { createConfiguredAlertWebhook };

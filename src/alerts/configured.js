'use strict';

const { DurableExportOutbox } = require('../export/outbox');
const { EnvironmentSecretProvider, FileSecretProvider, CompositeSecretProvider } = require('../security/secrets');
const { AlertWebhookExporter, AlertWebhookService } = require('./webhook');

function configuredSecretProvider(config, environment) {
  const providers = [];
  if (Object.keys(config.secrets.environment).length) providers.push(new EnvironmentSecretProvider(config.secrets.environment, environment));
  if (Object.keys(config.secrets.files).length) providers.push(new FileSecretProvider(config.secrets.files));
  return providers.length ? new CompositeSecretProvider(providers) : null;
}

function createConfiguredAlertWebhook(config, { protector = null, environment = process.env, fetchImpl = globalThis.fetch } = {}) {
  if (!config?.alertWebhook?.enabled) return null;
  const credentialProvider = configuredSecretProvider(config, environment);
  const outbox = new DurableExportOutbox(config.storage.dataDirectory, {
    protector, requireEncryption: config.storage.requireEncryption,
    maxPending: config.alertWebhook.maxPending, filename: 'alert-webhook.jsonl'
  });
  const exporter = new AlertWebhookExporter({
    endpoint: config.alertWebhook.endpoint, credentialProvider,
    credentialReference: config.alertWebhook.credentialReference, fetchImpl
  });
  return new AlertWebhookService({ outbox, exporter, batchSize: config.alertWebhook.batchSize });
}

module.exports = { configuredSecretProvider, createConfiguredAlertWebhook };

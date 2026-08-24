'use strict';

const { EnvironmentSecretProvider, FileSecretProvider, CompositeSecretProvider } = require('../security/secrets');
const { createHttpsExportService } = require('./index');

function createConfiguredCloudExport(config, { protector = null, environment = process.env } = {}) {
  if (!config?.export?.enabled) return null;
  const providers = [];
  if (Object.keys(config.secrets.environment).length) providers.push(new EnvironmentSecretProvider(config.secrets.environment, environment));
  if (Object.keys(config.secrets.files).length) providers.push(new FileSecretProvider(config.secrets.files));
  const credentialProvider = providers.length ? new CompositeSecretProvider(providers) : null;
  return createHttpsExportService({
    dataDirectory: config.storage.dataDirectory, endpoint: config.export.endpoint, credentialProvider,
    credentialReference: config.export.credentialReference, protector, requireEncryption: config.storage.requireEncryption,
    maxPending: config.export.maxPending, batchSize: config.export.batchSize,
    policy: { enabled: true, categories: config.export.categories, attributeAllowlist: config.export.attributeAllowlist, includeActor: config.export.includeActor }
  });
}

module.exports = { createConfiguredCloudExport };

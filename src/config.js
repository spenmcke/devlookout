'use strict';

const fs = require('node:fs');
const path = require('node:path');
const net = require('node:net');
const { isPlainObject, ValidationError } = require('./core/validation');

const LOOPBACK_HOSTS = new Set(['127.0.0.1', '::1', 'localhost']);

function rejectUnknown(value, allowed, location, issues) {
  if (!isPlainObject(value)) { issues.push(`${location} must be an object`); return; }
  for (const key of Object.keys(value)) if (!allowed.includes(key)) issues.push(`${location}.${key} is not supported`);
}

function integer(value, location, minimum, maximum, issues) {
  if (!Number.isInteger(value) || value < minimum || value > maximum) issues.push(`${location} must be an integer between ${minimum} and ${maximum}`);
}

function optionalPath(value, location, issues) {
  if (value !== null && (typeof value !== 'string' || !value.trim())) issues.push(`${location} must be null or a non-empty path`);
}

function secureHttpsEndpoint(value) {
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && !url.username && !url.password && !url.search && !url.hash;
  } catch { return false; }
}

function validateConfig(input, { cwd = process.cwd() } = {}) {
  const issues = [];
  rejectUnknown(input, ['schemaVersion', 'server', 'storage', 'auth', 'collectors', 'secrets', 'export', 'consoleSync', 'alertWebhook', 'webhook'], '$', issues);
  if (!isPlainObject(input)) throw new ValidationError('Invalid Lookout configuration', issues);
  if (input.schemaVersion !== undefined && input.schemaVersion !== 1) issues.push('$.schemaVersion must equal 1');

  const server = input.server ?? {};
  rejectUnknown(server, ['host', 'port', 'allowLoopbackAdmin', 'approvedSourceAddresses', 'tls'], '$.server', issues);
  const host = server.host ?? '127.0.0.1';
  if (typeof host !== 'string' || !host.trim()) issues.push('$.server.host must be a non-empty string');
  const port = server.port ?? 4173;
  integer(port, '$.server.port', 1, 65535, issues);
  const allowLoopbackAdmin = server.allowLoopbackAdmin ?? true;
  if (typeof allowLoopbackAdmin !== 'boolean') issues.push('$.server.allowLoopbackAdmin must be a boolean');
  const approvedSourceAddresses = server.approvedSourceAddresses ?? ['127.0.0.1', '::1', '::ffff:127.0.0.1'];
  if (!Array.isArray(approvedSourceAddresses) || approvedSourceAddresses.some((value) => typeof value !== 'string' || net.isIP(value.replace(/^::ffff:/, '')) === 0)) issues.push('$.server.approvedSourceAddresses must be an array of IP addresses');
  const tls = server.tls ?? null;
  if (tls !== null) {
    rejectUnknown(tls, ['certificateFile', 'privateKeyFile'], '$.server.tls', issues);
    if (typeof tls?.certificateFile !== 'string' || !tls.certificateFile.trim()) issues.push('$.server.tls.certificateFile must be a non-empty path');
    if (typeof tls?.privateKeyFile !== 'string' || !tls.privateKeyFile.trim()) issues.push('$.server.tls.privateKeyFile must be a non-empty path');
  }

  const storage = input.storage ?? {};
  rejectUnknown(storage, ['dataDirectory', 'requireEncryption', 'retentionDays', 'auditRetentionDays', 'maximumPercent'], '$.storage', issues);
  const dataDirectoryValue = storage.dataDirectory ?? './data';
  if (typeof dataDirectoryValue !== 'string' || !dataDirectoryValue.trim()) issues.push('$.storage.dataDirectory must be a non-empty path');
  const requireEncryption = storage.requireEncryption ?? !LOOPBACK_HOSTS.has(host);
  if (typeof requireEncryption !== 'boolean') issues.push('$.storage.requireEncryption must be a boolean');
  const retentionDays = storage.retentionDays ?? 7;
  integer(retentionDays, '$.storage.retentionDays', 1, 3650, issues);
  const auditRetentionDays = storage.auditRetentionDays ?? 7;
  integer(auditRetentionDays, '$.storage.auditRetentionDays', 1, 3650, issues);
  const maximumPercent = storage.maximumPercent ?? 2;
  if (typeof maximumPercent !== 'number' || !Number.isFinite(maximumPercent) || maximumPercent < 0.1 || maximumPercent > 20) issues.push('$.storage.maximumPercent must be a number between 0.1 and 20');

  const auth = input.auth ?? {};
  rejectUnknown(auth, ['credentialsFile', 'legacyTokenEnvironment', 'tailscale'], '$.auth', issues);
  const credentialsFile = auth.credentialsFile ?? null;
  optionalPath(credentialsFile, '$.auth.credentialsFile', issues);
  const legacyTokenEnvironment = auth.legacyTokenEnvironment ?? null;
  if (legacyTokenEnvironment !== null && !/^[A-Z][A-Z0-9_]*$/.test(legacyTokenEnvironment)) issues.push('$.auth.legacyTokenEnvironment must be null or an uppercase environment-variable name');
  const tailscaleAuth = auth.tailscale ?? {};
  rejectUnknown(tailscaleAuth, ['enabled', 'socketPath', 'allowedUserIds', 'allowedNodeIds', 'roles'], '$.auth.tailscale', issues);
  const tailscaleAuthEnabled = tailscaleAuth.enabled ?? false;
  const tailscaleSocketPath = tailscaleAuth.socketPath ?? '/var/run/tailscale/tailscaled.sock';
  const tailscaleAllowedUserIds = tailscaleAuth.allowedUserIds ?? [];
  const tailscaleAllowedNodeIds = tailscaleAuth.allowedNodeIds ?? [];
  const tailscaleRoles = tailscaleAuth.roles ?? ['admin'];
  if (typeof tailscaleAuthEnabled !== 'boolean') issues.push('$.auth.tailscale.enabled must be a boolean');
  if (typeof tailscaleSocketPath !== 'string' || !path.isAbsolute(tailscaleSocketPath)) issues.push('$.auth.tailscale.socketPath must be absolute');
  if (!Array.isArray(tailscaleAllowedUserIds) || tailscaleAllowedUserIds.some((id) => !/^\d+$/.test(String(id)))) issues.push('$.auth.tailscale.allowedUserIds must contain numeric IDs');
  if (!Array.isArray(tailscaleAllowedNodeIds) || tailscaleAllowedNodeIds.some((id) => typeof id !== 'string' || !/^[A-Za-z0-9]+$/.test(id))) issues.push('$.auth.tailscale.allowedNodeIds contains an invalid stable node ID');
  if (!Array.isArray(tailscaleRoles) || !tailscaleRoles.length || tailscaleRoles.some((role) => !['viewer', 'analyst', 'rule_admin', 'admin'].includes(role))) issues.push('$.auth.tailscale.roles contains an unsupported interactive role');
  if (tailscaleAuthEnabled && !tailscaleAllowedUserIds.length && !tailscaleAllowedNodeIds.length) issues.push('$.auth.tailscale requires at least one allowed user or node ID when enabled');

  const collectors = input.collectors ?? {};
  rejectUnknown(collectors, ['keysFile', 'tailscale'], '$.collectors', issues);
  const keysFile = collectors.keysFile ?? null;
  optionalPath(keysFile, '$.collectors.keysFile', issues);
  const tailscale = collectors.tailscale ?? {};
  rejectUnknown(tailscale, ['enabled', 'tailnet', 'credentialReference', 'authMode', 'baseUrl', 'modes', 'pollIntervalSeconds', 'initialLookbackSeconds', 'ingestionDelaySeconds'], '$.collectors.tailscale', issues);
  const tailscaleEnabled = tailscale.enabled ?? false;
  const tailscaleModes = tailscale.modes ?? ['network-flow', 'configuration-audit'];
  if (typeof tailscaleEnabled !== 'boolean') issues.push('$.collectors.tailscale.enabled must be a boolean');
  if (tailscaleEnabled && (typeof tailscale.tailnet !== 'string' || !tailscale.tailnet.trim())) issues.push('$.collectors.tailscale.tailnet is required when enabled');
  if (tailscaleEnabled && (typeof tailscale.credentialReference !== 'string' || !tailscale.credentialReference.trim())) issues.push('$.collectors.tailscale.credentialReference is required when enabled');
  if (!['api-token', 'oauth'].includes(tailscale.authMode ?? 'api-token')) issues.push('$.collectors.tailscale.authMode must be api-token or oauth');
  if (tailscale.baseUrl !== undefined && (typeof tailscale.baseUrl !== 'string' || !tailscale.baseUrl.startsWith('https://'))) issues.push('$.collectors.tailscale.baseUrl must use https');
  if (!Array.isArray(tailscaleModes) || !tailscaleModes.length || tailscaleModes.some((mode) => !['network-flow', 'configuration-audit'].includes(mode))) issues.push('$.collectors.tailscale.modes must select network-flow and/or configuration-audit');
  const tailscalePollIntervalSeconds = tailscale.pollIntervalSeconds ?? 15;
  const tailscaleInitialLookbackSeconds = tailscale.initialLookbackSeconds ?? 300;
  const tailscaleIngestionDelaySeconds = tailscale.ingestionDelaySeconds ?? 30;
  integer(tailscalePollIntervalSeconds, '$.collectors.tailscale.pollIntervalSeconds', 1, 3600, issues);
  integer(tailscaleInitialLookbackSeconds, '$.collectors.tailscale.initialLookbackSeconds', 0, 86400, issues);
  integer(tailscaleIngestionDelaySeconds, '$.collectors.tailscale.ingestionDelaySeconds', 0, 3600, issues);

  const secrets = input.secrets ?? {};
  rejectUnknown(secrets, ['environment', 'files'], '$.secrets', issues);
  const environmentSecrets = secrets.environment ?? {};
  const fileSecrets = secrets.files ?? {};
  for (const [location, mapping, validator] of [
    ['$.secrets.environment', environmentSecrets, (value) => /^[A-Z][A-Z0-9_]*$/.test(value)],
    ['$.secrets.files', fileSecrets, (value) => typeof value === 'string' && Boolean(value.trim())]
  ]) {
    if (!isPlainObject(mapping)) issues.push(`${location} must be an object`);
    else for (const [reference, value] of Object.entries(mapping)) {
      if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/.test(reference)) issues.push(`${location} contains an invalid reference name`);
      if (!validator(value)) issues.push(`${location}.${reference} is invalid`);
    }
  }

  const exporter = input.export ?? {};
  rejectUnknown(exporter, ['enabled', 'type', 'endpoint', 'credentialReference', 'batchSize', 'maxPending', 'flushIntervalSeconds', 'categories', 'attributeAllowlist', 'includeActor'], '$.export', issues);
  const exportEnabled = exporter.enabled ?? false;
  if (typeof exportEnabled !== 'boolean') issues.push('$.export.enabled must be a boolean');
  if (exportEnabled && exporter.type !== 'https') issues.push('$.export.type must equal https when export is enabled');
  if (exporter.endpoint !== undefined && exporter.endpoint !== null && (typeof exporter.endpoint !== 'string' || !exporter.endpoint.startsWith('https://'))) issues.push('$.export.endpoint must use https');
  if (exportEnabled && !exporter.endpoint) issues.push('$.export.endpoint is required when export is enabled');
  if (exporter.credentialReference !== undefined && exporter.credentialReference !== null && (typeof exporter.credentialReference !== 'string' || !exporter.credentialReference.trim())) issues.push('$.export.credentialReference must be a non-empty secret reference');
  const batchSize = exporter.batchSize ?? 100;
  integer(batchSize, '$.export.batchSize', 1, 1000, issues);
  const maxPending = exporter.maxPending ?? 50000;
  integer(maxPending, '$.export.maxPending', batchSize, 1000000, issues);
  const flushIntervalSeconds = exporter.flushIntervalSeconds ?? 30;
  integer(flushIntervalSeconds, '$.export.flushIntervalSeconds', 1, 3600, issues);
  const categories = exporter.categories ?? [];
  if (!Array.isArray(categories) || categories.some((value) => typeof value !== 'string' || !value)) issues.push('$.export.categories must be an array of non-empty strings');
  const attributeAllowlist = exporter.attributeAllowlist ?? [];
  if (!Array.isArray(attributeAllowlist) || attributeAllowlist.some((value) => typeof value !== 'string' || !value)) issues.push('$.export.attributeAllowlist must be an array of non-empty strings');
  const includeActor = exporter.includeActor ?? false;
  if (typeof includeActor !== 'boolean') issues.push('$.export.includeActor must be a boolean');
  if (exportEnabled && categories.length === 0) issues.push('$.export.categories must explicitly select at least one category when export is enabled');
  if (exporter.credentialReference && !Object.hasOwn(environmentSecrets, exporter.credentialReference) && !Object.hasOwn(fileSecrets, exporter.credentialReference)) issues.push('$.export.credentialReference must resolve through $.secrets.environment or $.secrets.files');

  const consoleSync = input.consoleSync ?? {};
  rejectUnknown(consoleSync, ['enabled', 'endpoint', 'credentialReference', 'deploymentId', 'batchSize', 'maxPending', 'intervalSeconds'], '$.consoleSync', issues);
  const consoleSyncEnabled = consoleSync.enabled ?? false;
  const consoleSyncBatchSize = consoleSync.batchSize ?? 10;
  const consoleSyncMaxPending = consoleSync.maxPending ?? 1000;
  const consoleSyncIntervalSeconds = consoleSync.intervalSeconds ?? 30;
  if (typeof consoleSyncEnabled !== 'boolean') issues.push('$.consoleSync.enabled must be a boolean');
  if (consoleSync.endpoint !== undefined && consoleSync.endpoint !== null && (typeof consoleSync.endpoint !== 'string' || !secureHttpsEndpoint(consoleSync.endpoint))) issues.push('$.consoleSync.endpoint must use https without credentials, query parameters, or fragments');
  if (consoleSyncEnabled && !consoleSync.endpoint) issues.push('$.consoleSync.endpoint is required when enabled');
  if (consoleSync.credentialReference !== undefined && consoleSync.credentialReference !== null && (typeof consoleSync.credentialReference !== 'string' || !consoleSync.credentialReference.trim())) issues.push('$.consoleSync.credentialReference must be null or a non-empty secret reference');
  if (consoleSyncEnabled && !consoleSync.credentialReference) issues.push('$.consoleSync.credentialReference is required when enabled');
  if (consoleSync.deploymentId !== undefined && consoleSync.deploymentId !== null && (typeof consoleSync.deploymentId !== 'string' || !/^[A-Za-z0-9._:-]{1,128}$/.test(consoleSync.deploymentId))) issues.push('$.consoleSync.deploymentId must be a stable deployment identifier');
  if (consoleSyncEnabled && !consoleSync.deploymentId) issues.push('$.consoleSync.deploymentId is required when enabled');
  integer(consoleSyncBatchSize, '$.consoleSync.batchSize', 1, 100, issues);
  integer(consoleSyncMaxPending, '$.consoleSync.maxPending', consoleSyncBatchSize, 100000, issues);
  integer(consoleSyncIntervalSeconds, '$.consoleSync.intervalSeconds', 5, 3600, issues);
  if (consoleSync.credentialReference && !Object.hasOwn(environmentSecrets, consoleSync.credentialReference) && !Object.hasOwn(fileSecrets, consoleSync.credentialReference)) issues.push('$.consoleSync.credentialReference must resolve through $.secrets.environment or $.secrets.files');

  const alertWebhook = input.alertWebhook ?? {};
  rejectUnknown(alertWebhook, ['enabled', 'endpoint', 'credentialReference', 'batchSize', 'maxPending', 'flushIntervalSeconds'], '$.alertWebhook', issues);
  const alertWebhookEnabled = alertWebhook.enabled ?? false;
  const alertWebhookBatchSize = alertWebhook.batchSize ?? 100;
  const alertWebhookMaxPending = alertWebhook.maxPending ?? 50000;
  const alertWebhookFlushIntervalSeconds = alertWebhook.flushIntervalSeconds ?? 5;
  if (typeof alertWebhookEnabled !== 'boolean') issues.push('$.alertWebhook.enabled must be a boolean');
  if (alertWebhook.endpoint !== undefined && (typeof alertWebhook.endpoint !== 'string' || !alertWebhook.endpoint.startsWith('https://'))) issues.push('$.alertWebhook.endpoint must use https');
  if (alertWebhookEnabled && !alertWebhook.endpoint) issues.push('$.alertWebhook.endpoint is required when enabled');
  integer(alertWebhookBatchSize, '$.alertWebhook.batchSize', 1, 1000, issues);
  integer(alertWebhookMaxPending, '$.alertWebhook.maxPending', alertWebhookBatchSize, 1000000, issues);
  integer(alertWebhookFlushIntervalSeconds, '$.alertWebhook.flushIntervalSeconds', 1, 3600, issues);
  if (alertWebhook.credentialReference !== undefined && (typeof alertWebhook.credentialReference !== 'string' || !alertWebhook.credentialReference.trim())) issues.push('$.alertWebhook.credentialReference must be a non-empty secret reference');
  for (const [location, reference] of [['$.collectors.tailscale.credentialReference', tailscale.credentialReference], ['$.alertWebhook.credentialReference', alertWebhook.credentialReference]]) {
    if (reference && !Object.hasOwn(environmentSecrets, reference) && !Object.hasOwn(fileSecrets, reference)) issues.push(`${location} must resolve through $.secrets.environment or $.secrets.files`);
  }

  const webhook = input.webhook ?? {};
  rejectUnknown(webhook, ['enabled', 'type', 'endpoint', 'credentialReference', 'batchSize', 'maxPending', 'flushIntervalSeconds', 'cooldownSeconds'], '$.webhook', issues);
  const webhookEnabled = webhook.enabled ?? false;
  const webhookBatchSize = webhook.batchSize ?? 50;
  const webhookMaxPending = webhook.maxPending ?? 10000;
  const webhookFlushIntervalSeconds = webhook.flushIntervalSeconds ?? 15;
  const webhookCooldownSeconds = webhook.cooldownSeconds ?? 300;
  if (typeof webhookEnabled !== 'boolean') issues.push('$.webhook.enabled must be a boolean');
  if (webhookEnabled && webhook.type !== 'https') issues.push('$.webhook.type must equal https when enabled');
  if (webhook.endpoint !== undefined && webhook.endpoint !== null && (typeof webhook.endpoint !== 'string' || !webhook.endpoint.startsWith('https://'))) issues.push('$.webhook.endpoint must use https');
  if (webhookEnabled && !webhook.endpoint) issues.push('$.webhook.endpoint is required when enabled');
  if (webhook.credentialReference !== undefined && webhook.credentialReference !== null && (typeof webhook.credentialReference !== 'string' || !webhook.credentialReference.trim())) issues.push('$.webhook.credentialReference must be null or a non-empty secret reference');
  integer(webhookBatchSize, '$.webhook.batchSize', 1, 1000, issues);
  integer(webhookMaxPending, '$.webhook.maxPending', webhookBatchSize, 1000000, issues);
  integer(webhookFlushIntervalSeconds, '$.webhook.flushIntervalSeconds', 1, 3600, issues);
  integer(webhookCooldownSeconds, '$.webhook.cooldownSeconds', 0, 86400, issues);
  if (webhook.credentialReference && !Object.hasOwn(environmentSecrets, webhook.credentialReference) && !Object.hasOwn(fileSecrets, webhook.credentialReference)) issues.push('$.webhook.credentialReference must resolve through $.secrets.environment or $.secrets.files');
  if (alertWebhookEnabled && webhookEnabled) issues.push('configure only $.webhook; $.alertWebhook is retained solely for backward compatibility');

  if (!LOOPBACK_HOSTS.has(host) && !credentialsFile && !legacyTokenEnvironment) issues.push('non-loopback binding requires $.auth.credentialsFile or $.auth.legacyTokenEnvironment');
  if (!LOOPBACK_HOSTS.has(host) && requireEncryption !== true) issues.push('non-loopback binding requires $.storage.requireEncryption to be true');
  if (issues.length) throw new ValidationError('Invalid Lookout configuration', issues);

  const resolveFile = (value) => value ? path.resolve(cwd, value) : null;
  return Object.freeze({
    schemaVersion: 1,
    server: Object.freeze({ host, port, allowLoopbackAdmin, approvedSourceAddresses: Object.freeze([...new Set(approvedSourceAddresses)].sort()), tls: tls ? Object.freeze({ certificateFile: path.resolve(cwd, tls.certificateFile), privateKeyFile: path.resolve(cwd, tls.privateKeyFile) }) : null }),
    storage: Object.freeze({ dataDirectory: path.resolve(cwd, dataDirectoryValue), requireEncryption, retentionDays, auditRetentionDays, maximumPercent }),
    auth: Object.freeze({ credentialsFile: resolveFile(credentialsFile), legacyTokenEnvironment, tailscale: Object.freeze({ enabled: tailscaleAuthEnabled, socketPath: tailscaleSocketPath, allowedUserIds: Object.freeze([...new Set(tailscaleAllowedUserIds.map(String))].sort()), allowedNodeIds: Object.freeze([...new Set(tailscaleAllowedNodeIds)].sort()), roles: Object.freeze([...new Set(tailscaleRoles)].sort()) }) }),
    collectors: Object.freeze({ keysFile: resolveFile(keysFile), tailscale: Object.freeze({ enabled: tailscaleEnabled, tailnet: tailscale.tailnet ?? null, credentialReference: tailscale.credentialReference ?? null, authMode: tailscale.authMode ?? 'api-token', baseUrl: tailscale.baseUrl ?? 'https://api.tailscale.com', modes: Object.freeze([...new Set(tailscaleModes)]), pollIntervalSeconds: tailscalePollIntervalSeconds, initialLookbackSeconds: tailscaleInitialLookbackSeconds, ingestionDelaySeconds: tailscaleIngestionDelaySeconds }) }),
    secrets: Object.freeze({ environment: Object.freeze({ ...environmentSecrets }), files: Object.freeze(Object.fromEntries(Object.entries(fileSecrets).map(([key, value]) => [key, path.resolve(cwd, value)]))) }),
    export: Object.freeze({ enabled: exportEnabled, type: exporter.type ?? null, endpoint: exporter.endpoint ?? null, credentialReference: exporter.credentialReference ?? null, batchSize, maxPending, flushIntervalSeconds, categories: Object.freeze([...new Set(categories)].sort()), attributeAllowlist: Object.freeze([...new Set(attributeAllowlist)].sort()), includeActor }),
    consoleSync: Object.freeze({ enabled: consoleSyncEnabled, endpoint: consoleSync.endpoint ?? null, credentialReference: consoleSync.credentialReference ?? null, deploymentId: consoleSync.deploymentId ?? null, batchSize: consoleSyncBatchSize, maxPending: consoleSyncMaxPending, intervalSeconds: consoleSyncIntervalSeconds }),
    alertWebhook: Object.freeze({ enabled: alertWebhookEnabled, endpoint: alertWebhook.endpoint ?? null, credentialReference: alertWebhook.credentialReference ?? null, batchSize: alertWebhookBatchSize, maxPending: alertWebhookMaxPending, flushIntervalSeconds: alertWebhookFlushIntervalSeconds }),
    webhook: Object.freeze({ enabled: webhookEnabled, type: webhook.type ?? null, endpoint: webhook.endpoint ?? null, credentialReference: webhook.credentialReference ?? null, batchSize: webhookBatchSize, maxPending: webhookMaxPending, flushIntervalSeconds: webhookFlushIntervalSeconds, cooldownSeconds: webhookCooldownSeconds })
  });
}

function readSecureJson(filename, label = 'Sensitive configuration') {
  const file = path.resolve(filename);
  let descriptor;
  try {
    descriptor = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
    const stat = fs.fstatSync(descriptor);
    if (!stat.isFile()) throw new Error(`${label} must be a regular file: ${file}`);
    if (stat.size > 4 * 1024 * 1024) throw new Error(`${label} exceeds the 4 MiB size limit: ${file}`);
    if (process.platform !== 'win32') {
      if ((stat.mode & 0o077) !== 0) throw new Error(`${label} file must not be accessible by group or other users: ${file}`);
      if (typeof process.geteuid === 'function' && stat.uid !== process.geteuid()) throw new Error(`${label} file must be owned by the current user: ${file}`);
    }
    try { return JSON.parse(fs.readFileSync(descriptor, 'utf8')); }
    catch (error) { throw new Error(`${label} is not valid JSON: ${error.message}`); }
  } catch (error) {
    if (['ELOOP', 'EMLINK'].includes(error.code)) throw new Error(`${label} must be a regular, non-symlink file: ${file}`);
    throw error;
  } finally { if (descriptor !== undefined) fs.closeSync(descriptor); }
}

function configFromEnvironment(environment = process.env, cwd = process.cwd()) {
  const tailscaleTokenVariable = environment.TAILSCALE_OAUTH_ACCESS_TOKEN ? 'TAILSCALE_OAUTH_ACCESS_TOKEN' : environment.TAILSCALE_API_TOKEN ? 'TAILSCALE_API_TOKEN' : null;
  const tailscaleTailnet = environment.LOOKOUT_TAILSCALE_TAILNET || null;
  return {
    schemaVersion: 1,
    server: { host: environment.LOOKOUT_HOST || '127.0.0.1', port: Number(environment.PORT || 4173), allowLoopbackAdmin: environment.LOOKOUT_ALLOW_LOOPBACK_ADMIN !== 'false', approvedSourceAddresses: environment.LOOKOUT_APPROVED_SOURCE_ADDRESSES ? environment.LOOKOUT_APPROVED_SOURCE_ADDRESSES.split(',').map((value) => value.trim()).filter(Boolean) : undefined, ...((environment.LOOKOUT_TLS_CERT_FILE || environment.LOOKOUT_TLS_KEY_FILE) ? { tls: { certificateFile: environment.LOOKOUT_TLS_CERT_FILE, privateKeyFile: environment.LOOKOUT_TLS_KEY_FILE } } : {}) },
    storage: { dataDirectory: environment.LOOKOUT_DATA_DIR || './data', requireEncryption: environment.LOOKOUT_REQUIRE_ENCRYPTION === 'true' || !LOOPBACK_HOSTS.has(environment.LOOKOUT_HOST || '127.0.0.1') },
    auth: { credentialsFile: environment.LOOKOUT_AUTH_FILE || null, legacyTokenEnvironment: environment.LOOKOUT_API_TOKEN ? 'LOOKOUT_API_TOKEN' : null, tailscale: { enabled: Boolean(environment.LOOKOUT_TAILSCALE_ALLOWED_USER_IDS || environment.LOOKOUT_TAILSCALE_ALLOWED_NODE_IDS), allowedUserIds: (environment.LOOKOUT_TAILSCALE_ALLOWED_USER_IDS || '').split(',').filter(Boolean), allowedNodeIds: (environment.LOOKOUT_TAILSCALE_ALLOWED_NODE_IDS || '').split(',').filter(Boolean) } },
    collectors: { keysFile: environment.LOOKOUT_COLLECTOR_KEYS_FILE || null, tailscale: { enabled: Boolean(tailscaleTailnet), tailnet: tailscaleTailnet, credentialReference: tailscaleTokenVariable ? 'tailscale-log-token' : null, authMode: environment.TAILSCALE_OAUTH_ACCESS_TOKEN ? 'oauth' : 'api-token' } },
    secrets: { environment: tailscaleTokenVariable ? { 'tailscale-log-token': tailscaleTokenVariable } : {}, files: {} }
  };
}

function loadConfig({ filename = process.env.LOOKOUT_CONFIG, environment = process.env, cwd = process.cwd() } = {}) {
  if (!filename) return validateConfig(configFromEnvironment(environment, cwd), { cwd });
  const file = path.resolve(cwd, filename);
  let document;
  try { document = JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch (error) { throw new Error(`Unable to load Lookout configuration ${file}: ${error.message}`); }
  return validateConfig(document, { cwd: path.dirname(file) });
}

module.exports = { LOOPBACK_HOSTS, validateConfig, readSecureJson, configFromEnvironment, loadConfig };

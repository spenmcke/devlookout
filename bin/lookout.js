#!/usr/bin/env node
'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');
const { LookoutRuntime } = require('../src/runtime');
const { AdapterRegistry } = require('../src/adapters/contract');
const { declarationAdapter } = require('../src/adapters/declaration');
const { tailscaleAdapter } = require('../src/adapters/tailscale');
const { TailscaleClient } = require('../src/adapters/tailscale-client');
const { generateCollectorKeyPair } = require('../src/collector/envelope');
const { systemCollector } = require('../src/collector/system');
const { operationalHealthCollector } = require('../src/collector/operational-telemetry');
const { linuxSecuritySurvey } = require('../src/collector/linux-security-survey');
const { submitEnvelope } = require('../src/collector/runner');
const { CollectorScheduler } = require('../src/collector/scheduler');
const { ContinuousCollector } = require('../src/collector/continuous');
const { loadOrCreateEnrollmentBundle, validateCollectorEnrollmentBundle, submitEnrollment, CollectorEnrollmentAuthority } = require('../src/collector/enrollment');
const { LinuxJournalSource } = require('../src/collector/linux-journal-source');
const { TailscaleLogSource } = require('../src/collector/tailscale-log-source');
const { createFact } = require('../src/adapters/contract');
const { parseSigmaYaml } = require('../src/detection/sigma');
const { protectorFromEnvironment } = require('../src/security/data-protector');
const { generateApiToken, ROLE_PERMISSIONS } = require('../src/security/auth');
const { BackupManager } = require('../src/storage/backup');
const { loadConfig, readSecureJson } = require('../src/config');
const { EnvironmentSecretProvider, FileSecretProvider, CompositeSecretProvider } = require('../src/security/secrets');
const { runDoctor } = require('../src/operations/doctor');
const { stableId } = require('../src/core/canonical');
const { createConfiguredCloudExport } = require('../src/export/configured');
const { CollectorRegistry } = require('../src/collector/registry');
const { createConfiguredAlertWebhook: createLegacyAlertWebhook } = require('../src/alerts/configured');
const { createConfiguredAlertWebhook } = require('../src/notifications/configured');
const { notifyConfiguredConsoleUninstall } = require('../src/console/configured');

function loadCliRelease() {
  try {
    const value = JSON.parse(require('node:fs').readFileSync(path.resolve(__dirname, '..', '.lookout-cli-release.json'), 'utf8'));
    if (value.schemaVersion !== 1 || !/^v\d+\.\d+\.\d+$/.test(value.releaseVersion || '')) return null;
    const targets = {};
    for (const architecture of ['amd64', 'arm64']) {
      const item = value.targets?.[architecture];
      if (!/^[a-f0-9]{64}$/.test(item?.sha256 || '')) return null;
      const target = new URL(item.url);
      if (target.protocol !== 'https:' || target.username || target.password || target.hash) return null;
      targets[architecture] = { url: target.toString(), sha256: item.sha256 };
    }
    process.env.LOOKOUT_RELEASE_TARGETS ||= JSON.stringify(targets);
    return value;
  } catch { return null; }
}

const cliRelease = loadCliRelease();

async function refreshInstalledCliTargets(store, { environment = process.env, refreshImpl = null } = {}) {
  if (!environment.LOOKOUT_RELEASE_TARGETS) return;
  let origin = environment.LOOKOUT_SAAS_ORIGIN || 'https://app.devlookout.com';
  try { origin = (await store.loadLogin({ allowExpired: true })).origin; }
  catch {
    try { origin = (await store.loadPendingLogin()).origin; } catch { /* The default SaaS origin remains authoritative before login. */ }
  }
  const refreshReleaseTargets = refreshImpl || require('../src/cli/release-channel').refreshReleaseTargets;
  const targets = await refreshReleaseTargets({ store, pinnedTargets: JSON.parse(environment.LOOKOUT_RELEASE_TARGETS), origin });
  environment.LOOKOUT_RELEASE_TARGETS = JSON.stringify(targets);
}

function commandOptions(argv) {
  const options = {};
  const positional = [];
  for (let index = 0; index < argv.length; index += 1) {
    const item = argv[index];
    if (!item.startsWith('--')) { positional.push(item); continue; }
    const key = item.slice(2);
    if (!key || key.includes('=')) throw new Error(`Invalid option: ${item}`);
    const value = argv[index + 1];
    if (value === undefined || value.startsWith('--')) throw new Error(`Missing value for --${key}`);
    options[key] = value;
    index += 1;
  }
  return { options, positional };
}

async function runWorkstationCommand(argv) {
  const [command, subcommand, ...rest] = argv;
  if (command === 'version' || command === '--version') {
    if (subcommand) throw new Error('Usage: lookout version');
    console.log(`Lookout CLI ${cliRelease?.releaseVersion || `v${require('../package.json').version}`}`);
    return true;
  }
  if (!['vm', 'login', 'prepare', 'install', 'diagnose', 'report'].includes(command)) return false;
  const { WorkstationConfigStore } = require('../src/cli/workstation-config');
  const store = new WorkstationConfigStore();
  if (command === 'vm') {
    if (subcommand === 'add') {
      const { options, positional } = commandOptions(rest);
      const name = options.name || positional[0];
      const address = options.address || positional[1];
      if (!name || !address) throw new Error('Usage: lookout vm add --name <name> --address <private-address> [--ssh-host <ssh-config-host>] [--ssh-user <user>]');
      const config = await store.addVm({ name, address, sshHost: options['ssh-host'], sshUser: options['ssh-user'] });
      console.log(JSON.stringify(config, null, 2));
      return true;
    }
    if (subcommand === 'central') {
      const { positional } = commandOptions(rest);
      if (!positional[0]) throw new Error('Usage: lookout vm central <name>');
      console.log(JSON.stringify(await store.setCentral(positional[0]), null, 2));
      return true;
    }
    if (subcommand === 'list') {
      console.log(JSON.stringify(await store.load(), null, 2));
      return true;
    }
    throw new Error('Usage: lookout vm add|central|list');
  }
  if (command === 'login') {
    if (subcommand && subcommand.startsWith('--') === false) throw new Error('Usage: lookout login [--origin <https-origin>]');
    const { options } = commandOptions([subcommand, ...rest].filter(Boolean));
    const origin = options.origin || process.env.LOOKOUT_SAAS_ORIGIN || 'https://app.devlookout.com';
    const { login, formatAuthorizationPrompt } = require('../src/onboarding/cli-authorization-client');
    const { loadOrCreateDeploymentIdentity } = require('../src/onboarding/deployment-identity');
    const { installationScope } = require('../src/cli/workstation-config');
    const config = await store.load();
    const deploymentIdentity = await loadOrCreateDeploymentIdentity(path.join(store.directory, 'deployment-identity'));
    const result = await login({
      origin, allowInsecureLoopback: process.env.LOOKOUT_ALLOW_INSECURE_LOOPBACK === '1',
      deploymentIdentity, installationScope: installationScope(config),
      onAuthorization: (binding) => store.savePendingLogin(binding),
      onUrl: (url, binding) => console.log(formatAuthorizationPrompt(url, binding))
    });
    await store.saveLogin(result);
    return true;
  }
  if (command === 'prepare') {
    if (subcommand) throw new Error('Usage: lookout prepare');
    await refreshInstalledCliTargets(store);
    const config = await store.load();
    const { prepare } = require('../src/cli/workstation-prepare');
    const result = await prepare({ config, store });
    console.log(JSON.stringify({ status: 'prepared', vms: result.nodes.length, expiresAt: result.expiresAt }, null, 2));
    return true;
  }
  if (command === 'install') {
    if (subcommand && subcommand !== '--retry') throw new Error('Usage: lookout install [--retry]');
    await refreshInstalledCliTargets(store);
    const config = await store.load();
    const installation = await store.loadInstallation();
    const { install, resume, installationRetryAction } = require('../src/cli/workstation-install');
    const { installationScopeDigest } = require('../src/cli/workstation-config');
    let currentBinding = null;
    try { currentBinding = await store.loadPendingLogin(); } catch { /* Login may not have started yet. */ }
    if (!currentBinding) {
      try { currentBinding = await store.loadLogin(); } catch { /* Login may not have completed yet. */ }
    }
    const action = installationRetryAction(installation, {
      retry: subcommand === '--retry', centralVm: config.centralVm,
      scopeDigest: installationScopeDigest(config), deploymentId: currentBinding?.deploymentId || null
    });
    if (action === 'resume') console.log(JSON.stringify(await resume({ config, state: installation, store }), null, 2));
    else if (action === 'install' || action === 'restart') {
      const preparation = await store.loadPreparation();
      console.log(JSON.stringify(await install({ config, preparation, store }), null, 2));
    } else throw new Error('There is no incomplete Lookout installation to retry');
    return true;
  }
  if (command === 'diagnose') {
    if (subcommand) throw new Error('Usage: lookout diagnose');
    const filename = path.join(store.directory, 'last-diagnostic.json');
    try { console.log(await fs.readFile(filename, 'utf8')); }
    catch (error) { if (error.code === 'ENOENT') throw new Error('No workstation installation diagnostic is available'); throw error; }
    return true;
  }
  if (command === 'report') {
    const reporter = require('../tools/lookout-support-report');
    const stateRoot = path.join(store.directory, 'support');
    if (!subcommand) {
      const loginResult = await store.loadLogin({ allowExpired: true });
      await reporter.survey({
        origin: new URL(loginResult.origin), setupToken: loginResult.setupToken, stateRoot,
        submitCommand: 'lookout report submit'
      });
      return true;
    }
    if (subcommand === 'submit' && rest.length === 1) {
      await reporter.submit({ surveyFile: rest[0], stateRoot });
      return true;
    }
    throw new Error('Usage: lookout report | lookout report submit <survey-file>');
  }
  return false;
}

async function ensurePrivateDirectory(directory) {
  const target = path.resolve(directory);
  await fs.mkdir(target, { recursive: true, mode: 0o700 });
  const stat = await fs.lstat(target);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error(`Sensitive directory must be a non-symlink directory: ${target}`);
  if (process.platform !== 'win32') {
    if ((stat.mode & 0o077) !== 0) throw new Error(`Sensitive directory permissions are too broad: ${target}`);
    if (typeof process.geteuid === 'function' && stat.uid !== process.geteuid()) throw new Error(`Sensitive directory must be owned by the current user: ${target}`);
  }
  return target;
}

async function loadCollectorCredentials(directory) {
  const identityDirectory = await ensurePrivateDirectory(directory);
  try {
    const bundle = validateCollectorEnrollmentBundle(readSecureJson(path.join(identityDirectory, 'enrollment.json'), 'Collector enrollment identity'));
    return { collectorId: bundle.private.collectorId, privateKeyPem: bundle.private.privateKeyPem, apiToken: bundle.private.submissionToken, assetId: bundle.request.assetId };
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  const identity = readSecureJson(path.join(identityDirectory, 'collector.json'), 'Collector identity');
  const secretFiles = { 'collector-private-key': path.join(identityDirectory, 'collector-private.pem') };
  if (process.env.LOOKOUT_API_TOKEN_FILE) secretFiles['collector-api-token'] = process.env.LOOKOUT_API_TOKEN_FILE;
  const secretProvider = new FileSecretProvider(secretFiles);
  const privateKeyPem = await secretProvider.get('collector-private-key');
  let privateKey;
  try { privateKey = crypto.createPrivateKey(privateKeyPem); } catch { throw new Error('Collector private key is invalid'); }
  if (privateKey.asymmetricKeyType !== 'ed25519') throw new Error('Collector private key must be Ed25519');
  const publicKeyPem = crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'pem' });
  if (identity.schemaVersion !== 1 || typeof identity.collectorId !== 'string' || identity.collectorId !== stableId('collector', publicKeyPem)) throw new Error('Collector identity does not match its private key');
  if (identity.assetId !== undefined && (typeof identity.assetId !== 'string' || !identity.assetId || identity.assetId.length > 512)) throw new Error('Collector asset identity is invalid');
  const apiToken = process.env.LOOKOUT_API_TOKEN || (process.env.LOOKOUT_API_TOKEN_FILE ? await secretProvider.get('collector-api-token') : null);
  return { collectorId: identity.collectorId, privateKeyPem, apiToken, assetId: identity.assetId || null };
}

async function readCollectorCa(filename) {
  if (!filename) return null;
  const target = path.resolve(filename);
  const stat = await fs.lstat(target);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 1024 * 1024) throw new Error('Collector CA bundle must be a bounded, non-symlink regular file');
  return fs.readFile(target, 'utf8');
}

function capabilityCollector(collectorId, source, entityKey = `collector-endpoint:${collectorId}`) {
  return {
    collect({ collectedAt, sequence }) {
      const facts = source.capabilities().map(({ capability, status }) => createFact({
        kind: 'capability', observedAt: collectedAt,
        source: { adapter: source.id, instance: collectorId, recordId: `capability:${sequence}:${capability}` },
        data: { entityKey, capability, status, freshnessSeconds: 120 }
      }));
      return { facts, events: [] };
    }
  };
}

async function main() {
  if (await runWorkstationCommand(process.argv.slice(2))) return;
  const [command = 'status', argument, secondArgument, thirdArgument, fourthArgument, fifthArgument] = process.argv.slice(2);
  if (command === 'bootstrap-key-create') {
    if (!argument) throw new Error('Usage: lookout bootstrap-key-create <private-directory> [deployment-id]');
    const { createBootstrapKey } = require('../src/fleet/bootstrap-key');
    console.log(JSON.stringify(await createBootstrapKey(argument, { deploymentId: secondArgument || crypto.randomUUID() }), null, 2));
    return;
  }
  const config = loadConfig();
  const dataDirectory = config.storage.dataDirectory;
  const protector = protectorFromEnvironment();
  const requireEncryption = config.storage.requireEncryption;
  let runtime;
  const getRuntime = async () => {
    if (requireEncryption && !protector) throw new Error('Encrypted storage is required but no master key is configured');
    runtime ||= await new LookoutRuntime({ dataDirectory, protector, requireEncryption }).initialize();
    return runtime;
  };
  if (command === 'status') console.log(JSON.stringify(await (await getRuntime()).status(), null, 2));
  else if (command === 'plan') console.log(JSON.stringify((await getRuntime()).detectionPlan(), null, 2));
  else if (command === 'ingest') {
    if (!argument) throw new Error('Usage: lookout ingest <events.json>');
    const input = JSON.parse(await fs.readFile(path.resolve(argument), 'utf8'));
    const events = Array.isArray(input) ? input : input.events;
    if (!Array.isArray(events)) throw new Error('Input must be an event array or { events: [] }');
    console.log(JSON.stringify(await (await getRuntime()).ingest(events), null, 2));
  } else if (command === 'survey-declaration') {
    if (!argument) throw new Error('Usage: lookout survey-declaration <survey.json>');
    const configuration = JSON.parse(await fs.readFile(path.resolve(argument), 'utf8'));
    const adapter = declarationAdapter(configuration);
    const facts = await new AdapterRegistry().register(adapter).survey('declaration');
    const graph = await (await getRuntime()).applySurveyFacts(facts);
    console.log(JSON.stringify({ facts: facts.length, entities: graph.entities.length, relationships: graph.relationships.length, capabilities: graph.capabilities.length }, null, 2));
  } else if (command === 'survey-declaration-replace') {
    if (!argument) throw new Error('Usage: lookout survey-declaration-replace <survey.json>');
    const configuration = JSON.parse(await fs.readFile(path.resolve(argument), 'utf8'));
    const adapter = declarationAdapter(configuration);
    const facts = await new AdapterRegistry().register(adapter).survey('declaration');
    const graph = await (await getRuntime()).replaceSurveyFacts(facts);
    console.log(JSON.stringify({ facts: facts.length, entities: graph.entities.length, relationships: graph.relationships.length, capabilities: graph.capabilities.length }, null, 2));
  } else if (command === 'survey-tailscale') {
    if (!argument) throw new Error('Usage: lookout survey-tailscale <tailnet-id>');
    const oauthToken = process.env.TAILSCALE_OAUTH_ACCESS_TOKEN;
    const apiToken = process.env.TAILSCALE_API_TOKEN;
    if (!oauthToken && !apiToken) throw new Error('Set TAILSCALE_OAUTH_ACCESS_TOKEN or TAILSCALE_API_TOKEN');
    const client = new TailscaleClient({ tokenProvider: async () => oauthToken || apiToken, authMode: oauthToken ? 'oauth' : 'api-token' });
    const adapter = tailscaleAdapter({ client, tailnet: argument, includeUsers: process.env.LOOKOUT_TAILSCALE_USERS !== 'false', includePolicy: process.env.LOOKOUT_TAILSCALE_POLICY !== 'false' });
    const facts = await new AdapterRegistry().register(adapter).survey('tailscale');
    const graph = await (await getRuntime()).applySurveyFacts(facts);
    console.log(JSON.stringify({ facts: facts.length, entities: graph.entities.length, relationships: graph.relationships.length, capabilities: graph.capabilities.length }, null, 2));
  } else if (command === 'compact') {
    if (!argument || Number.isNaN(Number(argument))) throw new Error('Usage: lookout compact <retention-days>');
    const retainAfter = new Date(Date.now() - Number(argument) * 86400000).toISOString();
    console.log(JSON.stringify(await (await getRuntime()).eventStore.compact({ retainAfter }), null, 2));
  } else if (command === 'collector-keygen') {
    if (!argument) throw new Error('Usage: lookout collector-keygen <key-directory>');
    const directory = await ensurePrivateDirectory(argument);
    const keys = generateCollectorKeyPair();
    await fs.writeFile(path.join(directory, 'collector-private.pem'), keys.privateKeyPem, { mode: 0o600, flag: 'wx' });
    await fs.writeFile(path.join(directory, 'collector-public.pem'), keys.publicKeyPem, { mode: 0o644, flag: 'wx' });
    await fs.writeFile(path.join(directory, 'collector.json'), `${JSON.stringify({ schemaVersion: 1, collectorId: keys.collectorId }, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
    console.log(JSON.stringify({ collectorId: keys.collectorId, publicKeyFile: path.join(directory, 'collector-public.pem') }, null, 2));
  } else if (command === 'collector-submit') {
    if (!argument || !secondArgument) throw new Error('Usage: lookout collector-submit <key-directory> <server-url>');
    const { collectorId, privateKeyPem, apiToken, assetId } = await loadCollectorCredentials(argument);
    const endpoint = new URL('/api/v1/collector/submissions', secondArgument).toString();
    const caPem = await readCollectorCa(process.env.LOOKOUT_COLLECTOR_CA_FILE || thirdArgument);
    const scheduler = await new CollectorScheduler({ dataDirectory, collectorId, privateKeyPem, modules: [systemCollector({ collectorId, entityKey: assetId })], protector, requireEncryption, sender: (envelope) => submitEnvelope(endpoint, envelope, { apiToken, caPem }) }).initialize();
    console.log(JSON.stringify(await scheduler.runCycle(), null, 2));
  } else if (command === 'collector-enroll') {
    if (!argument || !secondArgument || !thirdArgument || !fourthArgument || !fifthArgument || !process.env.LOOKOUT_ENROLLMENT_TOKEN_FILE) throw new Error('Usage: LOOKOUT_ENROLLMENT_TOKEN_FILE=<private-file> lookout collector-enroll <identity-dir> <server-url> <asset-id> <deployment-id> <ca-file>');
    const enrollmentToken = await new FileSecretProvider({ invitation: process.env.LOOKOUT_ENROLLMENT_TOKEN_FILE }).get('invitation');
    const bundle = await loadOrCreateEnrollmentBundle(argument, enrollmentToken, { assetId: thirdArgument, deploymentId: fourthArgument });
    const caPem = await readCollectorCa(fifthArgument);
    console.log(JSON.stringify(await submitEnrollment(secondArgument, bundle.request, { caPem }), null, 2));
  } else if (command === 'collector-invite') {
    if (!argument || !secondArgument) throw new Error('Usage: lookout collector-invite <asset-id> <deployment-id>');
    if (requireEncryption && !protector) throw new Error('Encrypted storage is required but no master key is configured');
    const authority = await new CollectorEnrollmentAuthority({ dataDirectory, protector, requireEncryption }).initialize();
    console.log(JSON.stringify(await authority.issueInvitation({ assetId: argument, deploymentId: secondArgument, replaceActive: thirdArgument === 'replace' }), null, 2));
  } else if (command === 'collector-invite-batch') {
    if (!argument || !secondArgument) throw new Error('Usage: lookout collector-invite-batch <deployment-id> <asset-id-json>');
    let assetIds;
    try { assetIds = JSON.parse(secondArgument); } catch { throw new Error('Collector invitation batch must be valid JSON'); }
    if (!Array.isArray(assetIds) || assetIds.length > 256 || assetIds.some((item) => typeof item !== 'string') || new Set(assetIds).size !== assetIds.length) throw new Error('Collector invitation batch is invalid');
    if (requireEncryption && !protector) throw new Error('Encrypted storage is required but no master key is configured');
    const authority = await new CollectorEnrollmentAuthority({ dataDirectory, protector, requireEncryption }).initialize();
    const invitations = [];
    for (const assetId of assetIds) invitations.push({ assetId, ...await authority.issueInvitation({ assetId, deploymentId: argument, replaceActive: true }) });
    console.log(JSON.stringify({ invitations }, null, 2));
  } else if (command === 'collector-run') {
    if (!argument || !secondArgument) throw new Error('Usage: lookout collector-run <key-directory> <server-url>');
    const { collectorId, privateKeyPem, apiToken, assetId } = await loadCollectorCredentials(argument);
    const endpoint = new URL('/api/v1/collector/submissions', secondArgument).toString();
    const caPem = await readCollectorCa(process.env.LOOKOUT_COLLECTOR_CA_FILE || thirdArgument);
    const entityKey = assetId || `collector-endpoint:${collectorId}`;
    const sources = process.platform === 'linux' ? [new LinuxJournalSource({ collectorId, entityKey })] : [];
    if (config.collectors.tailscale.enabled) {
      const secretProviders = [];
      if (Object.keys(config.secrets.environment).length) secretProviders.push(new EnvironmentSecretProvider(config.secrets.environment));
      if (Object.keys(config.secrets.files).length) secretProviders.push(new FileSecretProvider(config.secrets.files));
      const credentialProvider = new CompositeSecretProvider(secretProviders);
      const tailscaleConfig = config.collectors.tailscale;
      const client = new TailscaleClient({
        tokenProvider: () => credentialProvider.get(tailscaleConfig.credentialReference),
        authMode: tailscaleConfig.authMode, baseUrl: tailscaleConfig.baseUrl
      });
      sources.push(new TailscaleLogSource({
        client, tailnet: tailscaleConfig.tailnet, modes: tailscaleConfig.modes,
        pollIntervalMs: tailscaleConfig.pollIntervalSeconds * 1000,
        initialLookbackMs: tailscaleConfig.initialLookbackSeconds * 1000,
        ingestionDelayMs: tailscaleConfig.ingestionDelaySeconds * 1000
      }));
    }
    const periodicModules = [
      systemCollector({ collectorId, entityKey }),
      operationalHealthCollector({ collectorId, entityKey, dataDirectory }),
      ...(process.platform === 'linux' ? [linuxSecuritySurvey({
        collectorId, entityKey,
        excludedListenerPorts: String(process.env.LOOKOUT_SURVEY_EXCLUDED_LISTENER_PORTS || '').split(',').filter(Boolean).map(Number)
      })] : []),
      ...sources.map((source) => capabilityCollector(collectorId, source, entityKey))
    ];
    const collector = await new ContinuousCollector({
      dataDirectory, collectorId, privateKeyPem, sources, periodicModules, periodicIntervalMs: 60000,
      protector, requireEncryption,
      sender: (envelope) => submitEnvelope(endpoint, envelope, { apiToken, caPem })
    }).initialize();
    let resolveStop;
    const stopped = new Promise((resolve) => { resolveStop = resolve; });
    const requestStop = () => resolveStop();
    process.once('SIGINT', requestStop);
    process.once('SIGTERM', requestStop);
    await collector.start();
    console.log(JSON.stringify({ status: 'running', releaseVersion: `v${require('../package.json').version}`, collectorId, sources: sources.map((source) => source.id), maximumBatchLatencyMs: collector.batchMaximumWaitMs }));
    await stopped;
    await collector.stop();
    process.removeListener('SIGINT', requestStop);
    process.removeListener('SIGTERM', requestStop);
  } else if (command === 'collector-status') {
    if (!argument) throw new Error('Usage: lookout collector-status <collector-id>');
    if (requireEncryption && !protector) throw new Error('Encrypted storage is required but no master key is configured');
    const authority = await new CollectorEnrollmentAuthority({ dataDirectory, protector, requireEncryption }).initialize();
    const registry = await new CollectorRegistry({ dataDirectory, publicKeys: authority.publicKeys(), protector, requireEncryption }).initialize();
    const sequence = registry.snapshot().sequences[argument] || 0;
    console.log(JSON.stringify({ collectorId: argument, enrolled: Object.hasOwn(authority.publicKeys(), argument), acceptedSequence: sequence, active: sequence > 0 }));
  } else if (command === 'import-sigma') {
    if (!argument) throw new Error('Usage: lookout import-sigma <rules.yml>');
    const rules = parseSigmaYaml(await fs.readFile(path.resolve(argument), 'utf8'));
    console.log(JSON.stringify(await (await getRuntime()).importAnalytics(rules), null, 2));
  } else if (command === 'api-token-generate') {
    if (!argument || !secondArgument) throw new Error(`Usage: lookout api-token-generate <principal-id> <role> [expires-at]\nRoles: ${Object.keys(ROLE_PERMISSIONS).join(', ')}`);
    if (!ROLE_PERMISSIONS[secondArgument]) throw new Error(`Unknown role: ${secondArgument}`);
    if (thirdArgument && Number.isNaN(Date.parse(thirdArgument))) throw new Error('expires-at must be an ISO-compatible timestamp');
    const generated = generateApiToken();
    console.log(JSON.stringify({ token: generated.token, credential: { id: argument, tokenHash: generated.hash, roles: [secondArgument], ...(thirdArgument ? { expiresAt: new Date(thirdArgument).toISOString() } : {}) } }, null, 2));
  } else if (command === 'storage-keygen') {
    if (!argument) throw new Error('Usage: lookout storage-keygen <key-file>');
    const target = path.resolve(argument);
    await ensurePrivateDirectory(path.dirname(target));
    await fs.writeFile(target, `${crypto.randomBytes(32).toString('base64')}\n`, { mode: 0o600, flag: 'wx' });
    console.log(JSON.stringify({ keyFile: target, environment: 'LOOKOUT_MASTER_KEY_FILE' }, null, 2));
  } else if (command === 'backup-create') {
    if (!argument) throw new Error('Usage: lookout backup-create <backup-file>');
    if (!protector) throw new Error('Backup creation requires a configured master key');
    console.log(JSON.stringify(await new BackupManager({ dataDirectory, protector }).create(argument), null, 2));
  } else if (command === 'backup-inspect') {
    if (!argument) throw new Error('Usage: lookout backup-inspect <backup-file>');
    if (!protector) throw new Error('Backup inspection requires the backup master key');
    const bundle = await new BackupManager({ dataDirectory, protector }).inspect(argument);
    console.log(JSON.stringify({ schemaVersion: bundle.schemaVersion, createdAt: bundle.createdAt, entries: bundle.entries.map(({ name, bytes, digest }) => ({ name, bytes, digest })) }, null, 2));
  } else if (command === 'backup-restore') {
    if (!argument || !secondArgument) throw new Error('Usage: lookout backup-restore <backup-file> <new-data-directory>');
    if (!protector) throw new Error('Backup restoration requires the backup master key');
    console.log(JSON.stringify(await new BackupManager({ dataDirectory, protector }).restoreToNewDirectory(argument, secondArgument), null, 2));
  } else if (command === 'config-check') {
    console.log(JSON.stringify({ valid: true, config: { ...config, auth: { ...config.auth, legacyTokenEnvironment: config.auth.legacyTokenEnvironment || null } } }, null, 2));
  } else if (command === 'deployment-uninstall') {
    console.log(JSON.stringify(await notifyConfiguredConsoleUninstall(config)));
  } else if (command === 'validate-detection-pipeline' || command === 'validate-detections') {
    const { runAttackSimulations } = require('../scripts/run-attack-simulations');
    const report = await runAttackSimulations();
    console.log(JSON.stringify(report, null, 2));
    if (!report.passed) process.exitCode = 1;
  } else if (command === 'validate-live-linux') {
    if (!argument || !secondArgument || !thirdArgument || !fourthArgument) throw new Error('Usage: lookout validate-live-linux <target-ip> <ssh-user> <private-known-hosts-file> <private-identity-file>');
    const { configuredLiveApi, runLiveLinuxValidation } = require('../src/validation/live-linux');
    const api = await configuredLiveApi(config, process.env.LOOKOUT_ADMIN_TOKEN_FILE || '/etc/lookout/admin-token');
    const report = await runLiveLinuxValidation({ address: argument, user: secondArgument, knownHostsFile: thirdArgument, identityFile: fourthArgument, api });
    console.log(JSON.stringify(report, null, 2));
    if (!report.passed) process.exitCode = 1;
  } else if (command === 'doctor' || command === 'preflight-upgrade') {
    const report = await runDoctor({ config, protector, sensitiveFiles: { config: process.env.LOOKOUT_CONFIG ? path.resolve(process.env.LOOKOUT_CONFIG) : null, masterKey: process.env.LOOKOUT_MASTER_KEY_FILE ? path.resolve(process.env.LOOKOUT_MASTER_KEY_FILE) : null } });
    console.log(JSON.stringify(report, null, 2));
    if (report.status === 'fail') process.exitCode = 1;
  } else if (command === 'export-resume') {
    if (!config.export.enabled) throw new Error('Cloud export is not enabled in the active configuration');
    if (requireEncryption && !protector) throw new Error('Encrypted storage is required but no master key is configured');
    const cloudExport = createConfiguredCloudExport(config, { protector });
    await cloudExport.outbox.initialize();
    console.log(JSON.stringify(await cloudExport.resume(), null, 2));
  } else if (command === 'alert-webhook-resume') {
    if (!config.alertWebhook.enabled) throw new Error('Alert webhook is not enabled in the active configuration');
    if (requireEncryption && !protector) throw new Error('Encrypted storage is required but no master key is configured');
    const alertWebhook = createLegacyAlertWebhook(config, { protector });
    await alertWebhook.outbox.initialize();
    console.log(JSON.stringify(await alertWebhook.resume(), null, 2));
  } else if (command === 'webhook-resume') {
    if (!config.webhook.enabled) throw new Error('Alert webhook is not enabled in the active configuration');
    if (requireEncryption && !protector) throw new Error('Encrypted storage is required but no master key is configured');
    const alertWebhook = createConfiguredAlertWebhook(config, { protector });
    await alertWebhook.initialize();
    console.log(JSON.stringify({ resumed: await alertWebhook.resume() }, null, 2));
  } else throw new Error(`Unknown command: ${command}`);
}

if (require.main === module) main().catch((error) => { console.error(error.message); process.exitCode = 1; });

module.exports = { refreshInstalledCliTargets };

'use strict';

const fsp = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');
const { canonicalJson } = require('../core/canonical');
const { installationScope, installationScopeDigest } = require('./workstation-config');
const { knownHostsFile, releaseTargets } = require('./workstation-install');

const PREPARATION_TTL_MS = 10 * 60 * 1000;

function releaseFingerprint(environment = process.env) {
  const targets = releaseTargets(environment);
  const release = targets || {
    url: environment.LOOKOUT_RELEASE_URL || null,
    sha256: environment.LOOKOUT_RELEASE_SHA256 || null,
    sourceVersion: require('../../package.json').version
  };
  return crypto.createHash('sha256').update(canonicalJson(release)).digest('hex');
}

function validatePreparation(value, { config, environment = process.env, now = Date.now(), allowExpired = false } = {}) {
  const scope = installationScope(config);
  const expectedIds = scope.vms.map((vm) => vm.id).sort();
  const preparedIds = Array.isArray(value?.nodes) ? value.nodes.map((node) => node.id).sort() : [];
  if (!value || value.schemaVersion !== 1 || value.scopeDigest !== installationScopeDigest(config) || value.releaseFingerprint !== releaseFingerprint(environment) || value.centralVm !== config.centralVm || Number.isNaN(Date.parse(value.preparedAt)) || Number.isNaN(Date.parse(value.expiresAt)) || Date.parse(value.expiresAt) - Date.parse(value.preparedAt) > PREPARATION_TTL_MS || (!allowExpired && Date.parse(value.expiresAt) <= now) || expectedIds.length !== preparedIds.length || expectedIds.some((id, index) => id !== preparedIds[index])) return null;
  for (const node of value.nodes) {
    if (!node || !expectedIds.includes(node.id) || node.platform !== 'linux' || node.reachable !== true || !['amd64', 'arm64'].includes(node.architecture) || !node.preparedArtifact || !/^\/var\/tmp\/lookout-preflight-[A-Za-z0-9._:-]{1,128}-[A-Za-z0-9-]{1,128}$/.test(node.preparedArtifact.root || '') || node.preparedArtifact.source !== `${node.preparedArtifact.root}/source`) return null;
  }
  return value;
}

function runFleet(sourceDirectory, environment) {
  const result = spawnSync(process.execPath, [path.join(sourceDirectory, 'install/fleet.js')], { env: environment, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, timeout: 30 * 60 * 1000, killSignal: 'SIGKILL' });
  if (result.error || result.status !== 0) {
    const detail = String(result.stderr || result.error?.message || '').trim().slice(-8192);
    throw new Error(`Lookout preparation failed${detail ? `: ${detail}` : ''}`);
  }
  return result.stdout;
}

async function prepare({ config, store, sourceDirectory = path.resolve(__dirname, '../..'), environment = process.env, output = process.stdout, runImpl = runFleet } = {}) {
  const existing = validatePreparation(await store.loadPreparation(), { config, environment });
  if (existing) {
    output.write(`Preparation is already complete and can be reused until ${existing.expiresAt}.\n`);
    return existing;
  }
  const temporary = await fsp.mkdtemp(path.join(os.tmpdir(), 'lookout-workstation-prepare-'));
  const scopeFile = path.join(temporary, 'scope.json');
  try {
    await fsp.writeFile(scopeFile, `${JSON.stringify(installationScope(config))}\n`, { mode: 0o600 });
    const scopeDigest = installationScopeDigest(config);
    const fingerprint = releaseFingerprint(environment);
    output.write(`Preparing ${config.vms.length} VM${config.vms.length === 1 ? '' : 's'} in parallel...\n`);
    const raw = runImpl(sourceDirectory, {
      ...environment,
      LOOKOUT_WORKSTATION: '1', LOOKOUT_PREPARE_ONLY: '1', LOOKOUT_SOURCE_DIR: sourceDirectory,
      LOOKOUT_INSTALLATION_SCOPE_FILE: scopeFile, LOOKOUT_SSH_KNOWN_HOSTS: knownHostsFile(environment),
      LOOKOUT_PREPARATION_SCOPE_DIGEST: scopeDigest, LOOKOUT_PREPARATION_RELEASE_FINGERPRINT: fingerprint
    });
    const value = JSON.parse(String(raw).slice(String(raw).lastIndexOf('\n{') + 1));
    const validated = validatePreparation(value, { config, environment });
    if (!validated) throw new Error('Lookout preparation returned invalid or stale state');
    await store.savePreparation(validated);
    output.write(`Preparation complete. It can be reused until ${validated.expiresAt}.\n`);
    return validated;
  } finally { await fsp.rm(temporary, { recursive: true, force: true }); }
}

module.exports = { prepare, validatePreparation, releaseFingerprint, PREPARATION_TTL_MS };

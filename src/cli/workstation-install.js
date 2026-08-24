'use strict';

const fs = require('node:fs');
const fsp = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');
const { quoteRemote } = require('../fleet/deployment');
const { artifactPreflightScript } = require('../fleet/release-artifact');
const { requireExecutable } = require('../platform/executable');
const { installationScope, atomicWrite } = require('./workstation-config');
const { installationScopeDigest } = require('./workstation-config');
const { validateIdentity, loadOrCreateDeploymentIdentity } = require('../onboarding/deployment-identity');
const { createSshControlDirectory } = require('./ssh-control-path');

async function waitForLogin(store, { timeoutMs = 10 * 60 * 1000, intervalMs = 500, output = process.stdout, deploymentId = null, scopeDigest = null, keyFingerprint = null } = {}) {
  const deadline = Date.now() + timeoutMs;
  output.write('Waiting for browser login to complete...\n');
  while (Date.now() < deadline) {
    try {
      const login = await store.loadLogin();
      if (deploymentId && login.deploymentId !== deploymentId) {
        await new Promise((resolve) => setTimeout(resolve, intervalMs));
        continue;
      }
      if (scopeDigest && login.scopeDigest && login.scopeDigest !== scopeDigest) {
        await new Promise((resolve) => setTimeout(resolve, intervalMs));
        continue;
      }
      if (keyFingerprint && login.keyFingerprint && login.keyFingerprint !== keyFingerprint) {
        await new Promise((resolve) => setTimeout(resolve, intervalMs));
        continue;
      }
      return login;
    }
    catch (error) {
      if (!/permission is missing or expired/i.test(error.message)) throw error;
      await new Promise((resolve) => setTimeout(resolve, intervalMs));
    }
  }
  throw new Error('Browser login did not complete; finish lookout login and run lookout install --retry');
}

async function waitForPendingLogin(store, { timeoutMs = 30 * 1000, intervalMs = 250 } = {}) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try { return await store.loadPendingLogin(); }
    catch (error) {
      if (!/browser login has not started/i.test(error.message)) throw error;
      await new Promise((resolve) => setTimeout(resolve, intervalMs));
    }
  }
  throw new Error('Lookout browser login has not started; run lookout login in the other terminal');
}

function run(binary, args, { input, binaryOutput = false, environment = process.env, timeoutMs = 120000, label } = {}) {
  const result = spawnSync(binary, args, { input, env: environment, encoding: binaryOutput ? null : 'utf8', maxBuffer: 64 * 1024 * 1024, timeout: timeoutMs, killSignal: 'SIGKILL' });
  if (result.error || result.status !== 0) {
    const error = new Error(label || `${path.basename(binary)} failed`);
    error.detail = String(result.stderr || result.error?.message || '').slice(0, 8192);
    error.status = result.status;
    error.stdout = result.stdout;
    throw error;
  }
  return result.stdout;
}

function knownHostsFile(environment = process.env) {
  return path.resolve(environment.LOOKOUT_SSH_KNOWN_HOSTS || path.join(os.homedir(), '.ssh', 'known_hosts'));
}

function validateKnownHosts(filename) {
  const stat = fs.lstatSync(filename);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 4 * 1024 * 1024 || (process.platform !== 'win32' && (stat.mode & 0o022) !== 0)) throw new Error('SSH known-hosts file is missing or unsafe');
}

function sshDestination(vm) {
  const host = vm.sshHost || vm.address;
  return vm.sshUser ? `${vm.sshUser}@${host}` : host;
}

let sshControlDirectory = null;
function sshMultiplexOptions() {
  if (process.platform === 'win32') return [];
  if (!sshControlDirectory) {
    sshControlDirectory = createSshControlDirectory();
    process.once('exit', () => { if (sshControlDirectory) fs.rmSync(sshControlDirectory, { recursive: true, force: true }); });
  }
  return ['-o', 'ControlMaster=auto', '-o', 'ControlPersist=30', '-o', `ControlPath=${sshControlDirectory}/%C`];
}

function remote(vm, argv, { input, environment = process.env, timeoutMs = 120000 } = {}) {
  const knownHosts = knownHostsFile(environment);
  validateKnownHosts(knownHosts);
  const remoteCommand = ['sudo', '-n', ...argv].map(quoteRemote).join(' ');
  return run(requireExecutable('ssh', { environment }), [
    '-o', 'BatchMode=yes', '-o', 'PasswordAuthentication=no', '-o', 'StrictHostKeyChecking=yes',
    '-o', `UserKnownHostsFile=${knownHosts}`, '-o', 'ForwardAgent=no', ...sshMultiplexOptions(), '--', sshDestination(vm), remoteCommand
  ], { input, environment, timeoutMs, label: `Remote operation failed for ${vm.name}` });
}

function archiveSource(sourceDirectory) {
  return run(requireExecutable('tar'), ['-C', sourceDirectory, '--exclude=.git', '--exclude=node_modules', '--exclude=data', '--exclude=.env*', '--exclude=._*', '--exclude=.DS_Store', '-czf', '-', '.'], {
    binaryOutput: true, environment: { ...process.env, COPYFILE_DISABLE: '1' }, label: 'Unable to package Lookout source'
  });
}

function normalizeLinuxArchitecture(value) {
  const architecture = String(value || '').trim().toLowerCase();
  if (['x86_64', 'amd64'].includes(architecture)) return 'amd64';
  if (['aarch64', 'arm64'].includes(architecture)) return 'arm64';
  return null;
}

function releaseTargets(environment = process.env) {
  if (!environment.LOOKOUT_RELEASE_TARGETS) return null;
  let value;
  try { value = JSON.parse(environment.LOOKOUT_RELEASE_TARGETS); } catch { throw new Error('Installed CLI has invalid Linux release metadata'); }
  const targets = {};
  for (const architecture of ['amd64', 'arm64']) {
    const item = value?.[architecture];
    let parsed;
    try { parsed = new URL(item?.url); } catch { throw new Error('Installed CLI has invalid Linux release metadata'); }
    if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.hash || !/^[a-f0-9]{64}$/.test(item?.sha256 || '')) throw new Error('Installed CLI has invalid Linux release metadata');
    targets[architecture] = { url: parsed.toString(), sha256: item.sha256 };
  }
  return targets;
}

function centralRelease(central, environment, remoteImpl) {
  const targets = releaseTargets(environment);
  if (!targets) {
    if (!environment.LOOKOUT_RELEASE_URL) return null;
    const release = new URL(environment.LOOKOUT_RELEASE_URL);
    if (release.protocol !== 'https:' || release.username || release.password || release.hash || !/^[a-f0-9]{64}$/.test(environment.LOOKOUT_RELEASE_SHA256 || '')) throw new Error('Installed CLI has invalid Linux release metadata');
    return { url: release.toString(), sha256: environment.LOOKOUT_RELEASE_SHA256 };
  }
  const reported = String(remoteImpl(central, ['uname', '-m'], { environment })).trim();
  const architecture = normalizeLinuxArchitecture(reported);
  if (!architecture) throw new Error(`Central VM ${central.name} has unsupported Linux architecture: ${reported || 'unknown'}`);
  return targets[architecture];
}

const RESTARTABLE_INSTALLATION_STATES = new Set(['preparing', 'installing_local']);
const RESUMABLE_INSTALLATION_STATES = new Set(['awaiting_login', 'attaching', 'installing', 'finalizing']);

function installationRetryAction(state, { retry = false, centralVm = null, scopeDigest = null, deploymentId = null } = {}) {
  if (RESUMABLE_INSTALLATION_STATES.has(state?.status)) {
    if ((centralVm && state.centralVm !== centralVm) || (scopeDigest && state.scopeDigest !== scopeDigest) || (deploymentId && state.deploymentId !== deploymentId)) return 'restart';
    return 'resume';
  }
  if (RESTARTABLE_INSTALLATION_STATES.has(state?.status)) return 'restart';
  return retry ? 'reject' : 'install';
}

async function install({ config, login, preparation = null, store, sourceDirectory = path.resolve(__dirname, '../..'), environment = process.env, output = process.stdout, remoteImpl = remote, runImpl = run, archiveImpl = archiveSource } = {}) {
  const scope = installationScope(config);
  const central = config.vms.find((vm) => vm.name === config.centralVm);
  if (!central) throw new Error('Central VM is not configured');
  const temporary = await fsp.mkdtemp(path.join(os.tmpdir(), 'lookout-workstation-'));
  const stageRoot = `/var/tmp/lookout-workstation-source-${crypto.randomUUID()}`;
  let stage = stageRoot;
  const remoteState = '/var/lib/lookout-workstation-link';
  const remoteToken = `${remoteState}/setup-token`;
  const remoteScope = `${remoteState}/scope.json`;
  const remoteIdentity = `${remoteState}/deployment-identity.json`;
  const localScope = path.join(temporary, 'scope.json');
  const localIdentity = path.join(store.directory, 'deployment-identity', 'deployment-identity.json');
  const sshKnownHosts = knownHostsFile(environment);
  const { validatePreparation } = require('./workstation-prepare');
  const prepared = validatePreparation(preparation, { config, environment });
  let preparedCentral = prepared?.nodes.find((node) => node.id === central.name)?.preparedArtifact || null;
  let link;
  let remoteNode;
  const validatedIdentity = await loadOrCreateDeploymentIdentity(path.dirname(localIdentity));
  const identityText = `${JSON.stringify(validatedIdentity)}\n`;
  const pendingLogin = login?.deploymentId ? login : await waitForPendingLogin(store);
  const deploymentId = pendingLogin.deploymentId;
  const keyFingerprint = `SHA256:${crypto.createHash('sha256').update(crypto.createPublicKey(validatedIdentity.publicKeyPem).export({ type: 'spki', format: 'der' })).digest('base64')}`;
  let savedState = { schemaVersion: 1, status: 'preparing', centralVm: central.name, deploymentId, scopeDigest: installationScopeDigest(config), startedAt: new Date().toISOString() };
  try {
    await atomicWrite(store.installationFile, savedState);
    await fsp.writeFile(localScope, `${JSON.stringify(scope)}\n`, { mode: 0o600 });
    if (preparedCentral) {
      try { remoteImpl(central, ['test', '-f', `${preparedCentral.source}/package.json`, '-a', '-f', `${preparedCentral.source}/install/workstation-link.js`], { environment }); }
      catch { preparedCentral = null; }
    }
    if (!preparedCentral) remoteImpl(central, ['mkdir', '-p', stageRoot], { environment });
    remoteImpl(central, ['install', '-d', '-m', '700', remoteState], { environment });
    const selectedRelease = preparedCentral ? null : centralRelease(central, environment, remoteImpl);
    if (preparedCentral) {
      stage = preparedCentral.source;
      remoteNode = `${stage}/runtime/bin/node`;
    } else if (selectedRelease) {
      const incoming = `${stageRoot}/release.tar.gz`;
      const listing = `${stageRoot}/archive-members`;
      stage = `${stageRoot}/source`;
      try {
        remoteImpl(central, ['curl', '--proto', '=https', '--proto-redir', '=https', '--tlsv1.2', '--fail', '--silent', '--show-error', '--location', '--retry', '8', '--retry-all-errors', '--retry-delay', '3', '--retry-max-time', '120', '--output', incoming, selectedRelease.url], { environment, timeoutMs: 300000 });
      } catch (cause) {
        const error = new Error('The pinned Lookout release artifact is unavailable; reinstall the Lookout CLI, then run lookout install --retry');
        error.code = 'artifact_download';
        error.failurePhase = 'artifact_download';
        error.detail = cause?.detail || cause?.message || null;
        throw error;
      }
      remoteImpl(central, ['sh', '-c', artifactPreflightScript(), 'lookout-artifact-preflight', incoming, selectedRelease.sha256, stage, listing, '1'], { environment, timeoutMs: 300000 });
      remoteNode = `${stage}/runtime/bin/node`;
    } else {
      const archive = archiveImpl(sourceDirectory);
      remoteImpl(central, ['tar', '-xzf', '-', '-C', stage], { input: archive, environment, timeoutMs: 300000 });
      remoteNode = String(remoteImpl(central, ['env', `LOOKOUT_SOURCE_DIR=${stage}`, 'LOOKOUT_PROVISION_ONLY=1', `${stage}/install/install.sh`], { environment, timeoutMs: 300000 })).trim();
    }
    if (!/^\/[A-Za-z0-9._/-]{1,1023}$/.test(remoteNode) || remoteNode.includes('/../')) throw new Error('Central VM returned an invalid Node.js path');
    remoteImpl(central, ['install', '-m', '600', '/dev/stdin', remoteIdentity], { input: identityText, environment });
    remoteImpl(central, ['install', '-m', '600', '/dev/stdin', remoteScope], { input: `${JSON.stringify(scope)}\n`, environment });
    savedState = { ...savedState, status: 'installing_local', remoteState, remoteNode, stage, stageRoot: preparedCentral?.root || stageRoot, knownHostsFile: sshKnownHosts, releaseFingerprint: prepared?.releaseFingerprint || null };
    await atomicWrite(store.installationFile, savedState);
    const fleetEnvironment = {
      ...environment,
      LOOKOUT_WORKSTATION: '1', LOOKOUT_SOURCE_DIR: sourceDirectory, LOOKOUT_INSTALLATION_SCOPE_FILE: localScope,
      LOOKOUT_SSH_KNOWN_HOSTS: sshKnownHosts,
      LOOKOUT_PREPARED_CENTRAL_VM: central.name, LOOKOUT_PREPARED_CENTRAL_SOURCE: stage,
      ...(prepared ? { LOOKOUT_PREPARED_FLEET_FILE: store.preparationFile, LOOKOUT_PREPARATION_SCOPE_DIGEST: prepared.scopeDigest, LOOKOUT_PREPARATION_RELEASE_FINGERPRINT: prepared.releaseFingerprint } : {}),
      LOOKOUT_DEPLOYMENT_ID: deploymentId
    };
    const fleetOutput = runImpl(process.execPath, [path.join(sourceDirectory, 'install/fleet.js')], { environment: fleetEnvironment, timeoutMs: 30 * 60 * 1000, label: 'Lookout fleet installation failed' });
    output.write(String(fleetOutput));
    stage = '/opt/lookout/current';
    remoteNode = String(remoteImpl(central, ['sh', '-c', 'if test -x /opt/lookout/current/runtime/bin/node; then printf %s /opt/lookout/current/runtime/bin/node; else command -v node; fi'], { environment })).trim();
    if (!/^\/[A-Za-z0-9._/-]{1,1023}$/.test(remoteNode) || remoteNode.includes('/../')) throw new Error('Installed central VM returned an invalid Node.js path');
    remoteImpl(central, ['test', '-f', `${stage}/install/workstation-link.js`], { environment });
    savedState = { ...savedState, status: 'awaiting_login', stage, remoteNode };
    await atomicWrite(store.installationFile, savedState);
    login ||= await waitForLogin(store, { output, deploymentId, scopeDigest: savedState.scopeDigest, keyFingerprint });
    if (login.deploymentId !== deploymentId) throw new Error('Browser login does not match this installation; run lookout login again');
    if (login.scopeDigest && login.scopeDigest !== savedState.scopeDigest) throw new Error('Configured VMs changed after login; run lookout login again to approve the new VM list');
    if (login.keyFingerprint && login.keyFingerprint !== keyFingerprint) throw new Error('Deployment identity changed after login; run lookout login again');
    remoteImpl(central, ['install', '-m', '600', '/dev/stdin', remoteToken], { input: `${login.setupToken}\n`, environment });
    const linkResponse = remoteImpl(central, ['env', `LOOKOUT_SETUP_ORIGIN=${login.origin}`, remoteNode, `${stage}/install/workstation-link.js`, 'prepare', remoteToken, remoteScope, remoteState], { environment });
    const parsedLink = JSON.parse(String(linkResponse));
    if (parsedLink.deploymentId !== deploymentId || !parsedLink.consoleEndpoint || !parsedLink.credentialFile) throw new Error('Central VM returned invalid SaaS link details');
    link = parsedLink;
    savedState = { ...savedState, ...link, status: 'attaching', origin: login.origin };
    await atomicWrite(store.installationFile, savedState);
    output.write(`SaaS account linked to pending deployment ${link.deploymentId}.\n`);
    const attachOutput = runImpl(process.execPath, [path.join(sourceDirectory, 'install/fleet.js')], {
      environment: {
        ...fleetEnvironment, LOOKOUT_ATTACH_CONSOLE: '1', LOOKOUT_CONSOLE_DEPLOYMENT_ID: link.deploymentId,
        LOOKOUT_CONSOLE_ENDPOINT: link.consoleEndpoint, LOOKOUT_CONSOLE_CREDENTIAL_REMOTE: link.credentialFile
      },
      timeoutMs: 5 * 60 * 1000, label: 'Lookout SaaS attachment failed'
    });
    output.write(String(attachOutput));
    savedState = { ...savedState, status: 'finalizing' };
    await atomicWrite(store.installationFile, savedState);
    const finished = JSON.parse(String(remoteImpl(central, ['env', `LOOKOUT_SETUP_ORIGIN=${login.origin}`, remoteNode, `${stage}/install/workstation-link.js`, 'finish', remoteState], { environment, timeoutMs: 180000 })));
    await atomicWrite(store.installationFile, { schemaVersion: 1, status: 'complete', centralVm: central.name, deploymentId: finished.deploymentId, dashboardUrl: finished.dashboardUrl, completedAt: new Date().toISOString() });
    await store.clearLogin();
    await store.clearPendingLogin?.();
    await store.clearPreparation?.();
    try { remoteImpl(central, ['rm', '-f', link.credentialFile, `${remoteState}/link.json`, `${remoteState}/complete.json`, `${remoteState}/claim.json`, remoteScope], { environment }); } catch { /* Installation is complete; later cleanup is safe. */ }
    try { remoteImpl(central, ['find', stageRoot, '-depth', '-delete'], { environment }); } catch { /* Installation is complete; later cleanup is safe. */ }
    return { ...finished, status: 'complete' };
  } catch (error) {
    const diagnostic = {
      schemaVersion: 1, occurredAt: new Date().toISOString(), centralVm: central.name,
      phase: error.failurePhase || (link ? 'installing' : 'linking'), error: error.message, detail: error.detail || null,
      failures: error.failures || null
    };
    if (link) {
      const remoteDiagnostic = `${remoteState}/diagnostic-${crypto.randomUUID()}.json`;
      const report = { phase: 'installing', vm: central.name, error_code: 'installation_failed', message: String(error.message).slice(0, 2048), cli_version: require('../../package.json').version };
      try {
        remoteImpl(central, ['install', '-m', '600', '/dev/stdin', remoteDiagnostic], { input: `${JSON.stringify(report)}\n`, environment });
        const receipt = JSON.parse(String(remoteImpl(central, ['env', `LOOKOUT_SETUP_ORIGIN=${login.origin}`, remoteNode, `${stage}/install/workstation-link.js`, 'diagnose', remoteState, remoteDiagnostic], { environment })));
        diagnostic.diagnosticId = receipt.diagnosticId;
      } catch { /* Preserve the installation failure when diagnostics are unavailable. */ }
    } else if (['preparing', 'installing_local'].includes(savedState.status)) {
      try { remoteImpl(central, ['rm', '-f', remoteToken, remoteScope, remoteIdentity], { environment }); } catch { /* Cleanup must not mask the installation failure. */ }
      try {
        remoteImpl(central, ['sh', '-c', 'target=$1; case "$target" in /var/tmp/lookout-workstation-source-[0-9a-f]* ) ;; * ) exit 64 ;; esac; [ ! -e "$target" ] && exit 0; [ ! -L "$target" ] || exit 65; find "$target" -xdev -depth -delete', 'lookout-workstation-cleanup', stageRoot], { environment });
      } catch { /* Cleanup must not mask the installation failure. */ }
    }
    await atomicWrite(path.join(store.directory, 'last-diagnostic.json'), diagnostic).catch(() => {});
    await atomicWrite(store.installationFile, { ...savedState, lastFailure: { occurredAt: diagnostic.occurredAt, phase: diagnostic.phase, error: diagnostic.error } }).catch(() => {});
    throw error;
  } finally {
    await fsp.rm(temporary, { recursive: true, force: true });
  }
}

async function resume({ config, state: initialState, store, sourceDirectory = path.resolve(__dirname, '../..'), environment = process.env, output = process.stdout, remoteImpl = remote, runImpl = run } = {}) {
  let state = initialState;
  if (!state || state.schemaVersion !== 1 || !['awaiting_login', 'attaching', 'installing', 'finalizing'].includes(state.status) || typeof state.deploymentId !== 'string' || typeof state.stage !== 'string' || typeof state.remoteState !== 'string' || typeof state.remoteNode !== 'string') throw new Error('There is no incomplete Lookout installation to retry');
  if (['attaching', 'installing', 'finalizing'].includes(state.status) && (typeof state.consoleEndpoint !== 'string' || typeof state.credentialFile !== 'string' || typeof state.origin !== 'string')) throw new Error('There is no incomplete Lookout installation to retry');
  const scope = installationScope(config);
  const central = config.vms.find((vm) => vm.name === state.centralVm);
  if (!central) throw new Error('The configured central VM changed after installation began');
  const sshKnownHosts = path.resolve(state.knownHostsFile || knownHostsFile(environment));
  const { validatePreparation } = require('./workstation-prepare');
  const preparation = validatePreparation(store.loadPreparation ? await store.loadPreparation() : null, { config, environment });
  const temporary = await fsp.mkdtemp(path.join(os.tmpdir(), 'lookout-workstation-retry-'));
  const localScope = path.join(temporary, 'scope.json');
  try {
    await fsp.writeFile(localScope, `${JSON.stringify(scope)}\n`, { mode: 0o600 });
    if (state.status === 'awaiting_login') {
      const identity = validateIdentity(JSON.parse(await fsp.readFile(path.join(store.directory, 'deployment-identity', 'deployment-identity.json'), 'utf8')));
      const fingerprint = `SHA256:${crypto.createHash('sha256').update(crypto.createPublicKey(identity.publicKeyPem).export({ type: 'spki', format: 'der' })).digest('base64')}`;
      const login = await waitForLogin(store, { output, deploymentId: state.deploymentId, scopeDigest: state.scopeDigest, keyFingerprint: fingerprint });
      if (login.deploymentId !== state.deploymentId) throw new Error('Browser login does not match this installation; run lookout login again');
      if (login.scopeDigest && login.scopeDigest !== installationScopeDigest(config)) throw new Error('Configured VMs changed after login; run lookout login again to approve the new VM list');
      if (login.keyFingerprint && login.keyFingerprint !== fingerprint) throw new Error('Deployment identity changed after login; run lookout login again');
      const tokenFile = `${state.remoteState}/setup-token`;
      const scopeFile = `${state.remoteState}/scope.json`;
      remoteImpl(central, ['install', '-m', '600', '/dev/stdin', tokenFile], { input: `${login.setupToken}\n`, environment });
      const parsedLink = JSON.parse(String(remoteImpl(central, ['env', `LOOKOUT_SETUP_ORIGIN=${login.origin}`, state.remoteNode, `${state.stage}/install/workstation-link.js`, 'prepare', tokenFile, scopeFile, state.remoteState], { environment })));
      if (parsedLink.deploymentId !== state.deploymentId || !parsedLink.consoleEndpoint || !parsedLink.credentialFile) throw new Error('Central VM returned invalid SaaS link details');
      state = { ...state, ...parsedLink, status: 'attaching', origin: login.origin };
      await atomicWrite(store.installationFile, state);
    }
    if (state.status === 'attaching') {
      const attachEnvironment = {
        ...environment, LOOKOUT_WORKSTATION: '1', LOOKOUT_SOURCE_DIR: sourceDirectory,
        LOOKOUT_INSTALLATION_SCOPE_FILE: localScope, LOOKOUT_SSH_KNOWN_HOSTS: sshKnownHosts,
        LOOKOUT_DEPLOYMENT_ID: state.deploymentId, LOOKOUT_ATTACH_CONSOLE: '1',
        LOOKOUT_CONSOLE_DEPLOYMENT_ID: state.deploymentId, LOOKOUT_CONSOLE_ENDPOINT: state.consoleEndpoint,
        LOOKOUT_CONSOLE_CREDENTIAL_REMOTE: state.credentialFile
      };
      output.write(String(runImpl(process.execPath, [path.join(sourceDirectory, 'install/fleet.js')], { environment: attachEnvironment, timeoutMs: 5 * 60 * 1000, label: 'Lookout SaaS attachment retry failed' })));
      state = { ...state, status: 'finalizing' };
      await atomicWrite(store.installationFile, state);
    }
    if (state.status === 'installing') {
      const fleetEnvironment = {
        ...environment,
        LOOKOUT_WORKSTATION: '1', LOOKOUT_SOURCE_DIR: sourceDirectory, LOOKOUT_INSTALLATION_SCOPE_FILE: localScope,
        LOOKOUT_SSH_KNOWN_HOSTS: sshKnownHosts,
        LOOKOUT_PREPARED_CENTRAL_VM: central.name, LOOKOUT_PREPARED_CENTRAL_SOURCE: state.stage,
        ...(preparation ? { LOOKOUT_PREPARED_FLEET_FILE: store.preparationFile, LOOKOUT_PREPARATION_SCOPE_DIGEST: preparation.scopeDigest, LOOKOUT_PREPARATION_RELEASE_FINGERPRINT: preparation.releaseFingerprint } : {}),
        LOOKOUT_DEPLOYMENT_ID: state.deploymentId, LOOKOUT_CONSOLE_DEPLOYMENT_ID: state.deploymentId,
        LOOKOUT_CONSOLE_ENDPOINT: state.consoleEndpoint, LOOKOUT_CONSOLE_CREDENTIAL_REMOTE: state.credentialFile
      };
      const keepaliveCommand = `nohup env LOOKOUT_SETUP_ORIGIN=${quoteRemote(state.origin)} ${quoteRemote(state.remoteNode)} ${quoteRemote(`${state.stage}/install/workstation-link.js`)} keepalive ${quoteRemote(state.remoteState)} >${quoteRemote(`${state.remoteState}/keepalive.log`)} 2>&1 & echo $!`;
      const keepalivePid = String(remoteImpl(central, ['sh', '-c', keepaliveCommand], { environment })).trim();
      if (!/^\d{1,12}$/.test(keepalivePid)) throw new Error('Central VM did not restart the setup keepalive');
      try {
        const fleetOutput = runImpl(process.execPath, [path.join(sourceDirectory, 'install/fleet.js')], { environment: fleetEnvironment, timeoutMs: 30 * 60 * 1000, label: 'Lookout fleet installation retry failed' });
        output.write(String(fleetOutput));
      } finally {
        try { remoteImpl(central, ['kill', keepalivePid], { environment }); } catch { /* Keepalive exits when setup becomes terminal. */ }
      }
      await atomicWrite(store.installationFile, { ...state, status: 'finalizing' });
    }
    const finished = JSON.parse(String(remoteImpl(central, ['env', `LOOKOUT_SETUP_ORIGIN=${state.origin}`, state.remoteNode, `${state.stage}/install/workstation-link.js`, 'finish', state.remoteState], { environment, timeoutMs: 180000 })));
    await atomicWrite(store.installationFile, { schemaVersion: 1, status: 'complete', centralVm: central.name, deploymentId: finished.deploymentId, dashboardUrl: finished.dashboardUrl, completedAt: new Date().toISOString() });
    await store.clearLogin();
    await store.clearPendingLogin?.();
    await store.clearPreparation?.();
    try { remoteImpl(central, ['rm', '-f', state.credentialFile, `${state.remoteState}/link.json`, `${state.remoteState}/complete.json`, `${state.remoteState}/claim.json`, `${state.remoteState}/scope.json`], { environment }); } catch { /* Installation is complete; later cleanup is safe. */ }
    try { remoteImpl(central, ['find', state.stageRoot || state.stage, '-depth', '-delete'], { environment }); } catch { /* Installation is complete; later cleanup is safe. */ }
    return { ...finished, status: 'complete' };
  } catch (error) {
    const failure = { occurredAt: new Date().toISOString(), phase: 'retrying', error: error.message };
    await atomicWrite(path.join(store.directory, 'last-diagnostic.json'), {
      schemaVersion: 1, ...failure, centralVm: central.name, detail: error.detail || null
    }).catch(() => {});
    await atomicWrite(store.installationFile, { ...state, lastFailure: failure }).catch(() => {});
    throw error;
  } finally { await fsp.rm(temporary, { recursive: true, force: true }); }
}

module.exports = { install, resume, remote, archiveSource, knownHostsFile, normalizeLinuxArchitecture, releaseTargets, centralRelease, installationRetryAction };

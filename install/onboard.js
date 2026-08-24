#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');
const net = require('node:net');
const os = require('node:os');
const { spawn, spawnSync } = require('node:child_process');
const readline = require('node:readline/promises');
const { stdout } = require('node:process');
const { SetupSessionClient, readSetupTokenFromFile } = require('../src/onboarding/setup-session-client');
const { validateInstallationScope } = require('../src/onboarding/setup-session-authority');
const { loadOrCreateDeploymentIdentity, signSetupProof } = require('../src/onboarding/deployment-identity');
const { createBootstrapKey } = require('../src/fleet/bootstrap-key');
const { discoverCloudFleetAsync, installationScope } = require('../src/fleet/cloud-discovery');
const { resolveExecutable } = require('../src/platform/executable');

const DEFAULT_SETUP_ORIGIN = 'https://app.devlookout.com';

function userStateDirectory({ platform = process.platform, environment = process.env, home = os.homedir() } = {}) {
  if (platform === 'win32') return path.win32.join(environment.LOCALAPPDATA || environment.APPDATA || path.win32.join(home, 'AppData', 'Local'), 'Lookout', 'install');
  return path.join(home, '.lookout', 'install');
}

async function privateDirectory(directory) {
  const target = path.resolve(directory);
  await fsp.mkdir(target, { recursive: true, mode: 0o700 });
  const stat = await fsp.lstat(target);
  if (!stat.isDirectory() || stat.isSymbolicLink() || (process.platform !== 'win32' && ((stat.mode & 0o077) !== 0 || stat.uid !== process.geteuid?.()))) throw new Error('Onboarding state directory must be private and owned by the current user');
  return target;
}

async function readApprovedScope(filename) {
  if (typeof filename !== 'string' || !filename) return null;
  const target = path.resolve(filename);
  const handle = await fsp.open(target, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  try {
    const stat = await handle.stat();
    const permittedOwners = new Set([process.geteuid?.(), Number(process.env.SUDO_UID)].filter(Number.isSafeInteger));
    if (!stat.isFile() || stat.size < 2 || stat.size > 128 * 1024 || (process.platform !== 'win32' && ((stat.mode & 0o022) !== 0 || !permittedOwners.has(stat.uid)))) throw new Error('Approved installation scope must be a bounded, non-writable regular file owned by root or the invoking user');
    const value = JSON.parse(await handle.readFile('utf8'));
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Approved installation scope must be a JSON object');
    return value;
  } catch (error) {
    if (error instanceof SyntaxError) throw new Error('Approved installation scope is not valid JSON');
    throw error;
  } finally { await handle.close(); }
}

function commandOutput(command, args, { input, maximumBytes = 4 * 1024 * 1024 } = {}) {
  const result = spawnSync(command, args, { input, encoding: 'utf8', timeout: 15000, maxBuffer: maximumBytes, env: { PATH: process.env.PATH } });
  if (result.error || result.status !== 0) return null;
  return result.stdout;
}

function discoveredSshAddresses() {
  const addresses = new Set();
  const tailnet = commandOutput('tailscale', ['status', '--json']);
  if (tailnet) {
    try {
      const status = JSON.parse(tailnet);
      for (const peer of Object.values(status.Peer || {})) {
        if (peer?.Online === false || String(peer?.OS || '').toLowerCase() !== 'linux') continue;
        const address = (peer.TailscaleIPs || []).find((item) => net.isIP(item) === 4);
        if (address) addresses.add(address);
      }
    } catch { /* Untrusted discovery output cannot authorize a target. */ }
  }
  if (process.platform === 'linux') {
    const neighbors = commandOutput('ip', ['-j', 'neigh', 'show']);
    if (neighbors) {
      try {
        for (const item of JSON.parse(neighbors)) if (net.isIP(item?.dst) && !['FAILED', 'INCOMPLETE'].includes(item.state)) addresses.add(item.dst);
      } catch { /* Passive neighbor evidence is optional. */ }
    }
  }
  return [...addresses].sort((a, b) => a.localeCompare(b));
}

async function confirmQuestion(question, { input = null, output = stdout } = {}) {
  if (process.env.LOOKOUT_ONBOARD_NONINTERACTIVE === '1') throw new Error('Noninteractive onboarding requires a pre-pinned LOOKOUT_SSH_KNOWN_HOSTS file');
  let ownedInput = false;
  if (!input) { input = fs.createReadStream('/dev/tty'); ownedInput = true; }
  const prompt = readline.createInterface({ input, output, terminal: Boolean(input.isTTY) });
  try { return (await prompt.question(question)).trim().toLowerCase() === 'yes'; }
  finally { prompt.close(); if (ownedInput) input.destroy(); }
}

async function prepareKnownHosts({ stateDirectory, input = null, output = stdout } = {}) {
  if (process.env.LOOKOUT_SSH_KNOWN_HOSTS) return path.resolve(process.env.LOOKOUT_SSH_KNOWN_HOSTS);
  const addresses = discoveredSshAddresses();
  if (!addresses.length) return null;
  const accepted = [];
  const displayed = [];
  const sshKeyscan = resolveExecutable('ssh-keyscan');
  const sshKeygen = resolveExecutable('ssh-keygen');
  if (!sshKeyscan || !sshKeygen) return null;
  for (const address of addresses) {
    const scanned = commandOutput(sshKeyscan, ['-T', '5', '-t', 'ed25519,rsa', address], { maximumBytes: 256 * 1024 });
    if (!scanned) continue;
    for (const line of scanned.split('\n').filter((item) => item && !item.startsWith('#'))) {
      const fields = line.trim().split(/\s+/);
      if (fields.length !== 3 || ![address, `[${address}]:22`].includes(fields[0]) || !['ssh-ed25519', 'ssh-rsa'].includes(fields[1]) || !/^[A-Za-z0-9+/]+={0,2}$/.test(fields[2])) continue;
      const fingerprint = commandOutput(sshKeygen, ['-lf', '-', '-E', 'sha256'], { input: `${line}\n`, maximumBytes: 4096 });
      if (!fingerprint) continue;
      accepted.push(line.trim());
      displayed.push(`${address}  ${fingerprint.trim()}`);
    }
  }
  if (!accepted.length) return null;
  output.write('\nSSH host-key fingerprints discovered from the private network:\n');
  output.write(`${displayed.join('\n')}\n`);
  output.write('Compare these fingerprints with your VM/cloud console. Discovery alone is not authorization.\n');
  if (!await confirmQuestion('Type yes to pin these exact host keys and continue: ', { input, output })) throw new Error('SSH host keys were not approved');
  return writePrivate(path.join(stateDirectory, 'known_hosts'), `${[...new Set(accepted)].sort().join('\n')}\n`);
}

async function writePrivate(filename, contents) {
  const target = path.resolve(filename);
  const temporary = `${target}.${process.pid}.${crypto.randomUUID()}.tmp`;
  await fsp.writeFile(temporary, contents, { mode: 0o600, flag: 'wx' });
  try { await fsp.rename(temporary, target); }
  finally { await fsp.rm(temporary, { force: true }); }
  return target;
}

async function readPrivateRegular(filename, label, maximumBytes = 64 * 1024) {
  const target = path.resolve(filename);
  const handle = await fsp.open(target, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size > maximumBytes) throw new Error(`${label} must be a bounded regular file`);
    if (process.platform !== 'win32' && ((stat.mode & 0o077) !== 0 || stat.uid !== process.geteuid?.())) throw new Error(`${label} must be private and owned by the current user`);
    return handle.readFile('utf8');
  } finally { await handle.close(); }
}

async function loadExistingBootstrap(directory) {
  const target = path.resolve(directory);
  const manifestFile = path.join(target, 'lookout-bootstrap-key.json');
  let manifest;
  try { manifest = JSON.parse(await readPrivateRegular(manifestFile, 'Bootstrap key manifest')); }
  catch (error) { if (error instanceof SyntaxError) throw new Error('Bootstrap key manifest is not valid JSON'); throw error; }
  const privateKeyFile = path.join(target, 'lookout-bootstrap-key');
  const publicKeyFile = path.join(target, 'lookout-bootstrap-key.pub');
  if (manifest.schemaVersion !== 1 || manifest.privateKeyFile !== privateKeyFile || manifest.publicKeyFile !== publicKeyFile || !/^lookout-bootstrap:[A-Za-z0-9._:-]{1,128}$/.test(manifest.comment || '') || !/^SHA256:[A-Za-z0-9+/]+$/.test(manifest.fingerprint || '')) throw new Error('Bootstrap key manifest does not match its directory');
  await readPrivateRegular(privateKeyFile, 'Bootstrap private key');
  const publicLine = (await readPrivateRegular(publicKeyFile, 'Bootstrap public key')).trim();
  const fields = publicLine.split(/\s+/);
  if (fields.length !== 3 || fields[0] !== 'ssh-ed25519' || fields[2] !== manifest.comment) throw new Error('Bootstrap public key does not match its manifest');
  const blob = Buffer.from(fields[1], 'base64');
  const fingerprint = `SHA256:${crypto.createHash('sha256').update(blob).digest('base64').replace(/=+$/, '')}`;
  if (fingerprint !== manifest.fingerprint) throw new Error('Bootstrap public key fingerprint does not match its manifest');
  return { ...manifest, authorizedKeysLine: `restrict ${publicLine}` };
}

async function loadOnboardingState(filename) {
  let value;
  try { value = JSON.parse(await readPrivateRegular(filename, 'Onboarding state', 256 * 1024)); }
  catch (error) {
    if (error.code === 'ENOENT') return null;
    if (error instanceof SyntaxError) throw new Error('Onboarding state is not valid JSON');
    throw error;
  }
  const provisioning = value?.proof?.provisioning;
  if (value.schemaVersion !== 1 || (value.setupTokenHash !== undefined && !/^[A-Za-z0-9_-]{43}$/.test(value.setupTokenHash)) || !/^[A-Za-z0-9_-]{16,128}$/.test(value.claim?.sessionId || '') || typeof value.claim?.sessionToken !== 'string' || value.claim.sessionToken.length < 24 || typeof value.claim?.deploymentId !== 'string' || !value.claim?.installationScope || typeof provisioning?.consoleSync?.credential !== 'string' || typeof provisioning?.consoleSync?.endpoint !== 'string' || typeof provisioning?.dashboardUrl !== 'string') throw new Error('Onboarding state is invalid');
  return value;
}

async function runInstaller({ sourceDirectory, environment = process.env, output = stdout, onProgress = null } = {}) {
  const executable = path.join(path.resolve(sourceDirectory), 'install', 'fleet.js');
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [executable], { env: environment, stdio: ['ignore', 'pipe', 'pipe'] });
    const chunks = [];
    let progressUpdates = Promise.resolve();
    let stderrBuffer = '';
    let lastProgress = null;
    let lastFailure = null;
    child.stdout.on('data', (chunk) => { chunks.push(chunk); output.write(chunk); });
    child.stderr.on('data', (chunk) => {
      const text = chunk.toString('utf8');
      process.stderr.write(text);
      stderrBuffer += text;
      const lines = stderrBuffer.split('\n');
      stderrBuffer = lines.pop();
      for (const line of lines) {
        const match = /^\[fleet-status\] (\{.*\})$/.exec(line);
        if (!match) {
          if (/^lookout-fleet: /.test(line)) lastFailure = line.replace(/^lookout-fleet: /, '').trim().slice(-2048);
          continue;
        }
        if (!onProgress) continue;
        try {
          lastProgress = JSON.parse(match[1]);
          progressUpdates = progressUpdates.then(() => onProgress(lastProgress)).catch(() => {});
        } catch { /* Status reporting must not stop local protection. */ }
      }
    });
    child.once('error', reject);
    child.once('close', async (code) => {
      await progressUpdates;
      if (code !== 0) {
        if (/^lookout-fleet: /.test(stderrBuffer)) lastFailure = stderrBuffer.replace(/^lookout-fleet: /, '').trim().slice(-2048);
        const error = new Error(`Lookout fleet installation failed${lastFailure ? `: ${lastFailure}` : ''}. The setup token, temporary state, and SSH key were retained. Run the same setup prompt again after correcting the reported failure`);
        error.failurePhase = lastProgress?.phase;
        return reject(error);
      }
      const text = Buffer.concat(chunks).toString('utf8');
      try { resolve(JSON.parse(text.slice(text.lastIndexOf('\n{') + 1))); }
      catch { resolve({ mode: 'installed' }); }
    });
  });
}

async function completeSetupSession({ client, sessionId, sessionToken, attempts = 30, intervalMs = 2000, sleep = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)) }) {
  let lastError;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      await client.reportPhase({ sessionId, sessionToken, phase: 'complete' });
      return;
    } catch (error) {
      if (error.status !== 409) throw error;
      lastError = error;
      if (attempt + 1 < attempts) await sleep(intervalMs);
    }
  }
  const error = new Error('Lookout console did not receive its first deployment snapshot before setup timed out');
  error.cause = lastError;
  throw error;
}

async function loadDiagnosticOutbox(filename) {
  if (!filename) return [];
  let value;
  try { value = JSON.parse(await readPrivateRegular(filename, 'Installation diagnostics outbox', 128 * 1024)); }
  catch (error) { if (error.code === 'ENOENT') return []; throw error; }
  if (!value || value.schemaVersion !== 1 || !Array.isArray(value.events) || value.events.length > 100) throw new Error('Installation diagnostics outbox is invalid');
  for (const event of value.events) {
    if (!event || !['failure', 'diagnostic'].includes(event.kind) || !/^[a-z][a-z0-9_]{0,63}$/.test(event.code || '') || !/^[a-z][a-z0-9_]{0,63}$/.test(event.phase || '') || !/^[A-Za-z0-9_-]{16,128}$/.test(event.idempotencyKey || '')) throw new Error('Installation diagnostics outbox is invalid');
  }
  return value.events;
}

async function saveDiagnosticOutbox(filename, events) {
  if (!filename) return;
  if (!events.length) { await fsp.rm(filename, { force: true }); return; }
  await writePrivate(filename, `${JSON.stringify({ schemaVersion: 1, events })}\n`);
}

async function reportInstallerDiagnostic({ client, setupToken, kind, code, phase, outboxFile = null, enqueue = true, attempts = 5, sleep = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)) } = {}) {
  if (typeof client?.reportDiagnosticEvent !== 'function') return { skipped: true };
  const events = await loadDiagnosticOutbox(outboxFile);
  if (enqueue) {
    if (!['failure', 'diagnostic'].includes(kind) || !/^[a-z][a-z0-9_]{0,63}$/.test(code || '') || !/^[a-z][a-z0-9_]{0,63}$/.test(phase || '')) throw new Error('Installation diagnostic is invalid');
    if (events.length >= 100) events.shift();
    events.push({ kind, code, phase, idempotencyKey: crypto.randomBytes(24).toString('base64url') });
    await saveDiagnosticOutbox(outboxFile, events);
  }
  let lastResult = { accepted: true };
  while (events.length) {
    const event = events[0];
    let lastError;
    for (let attempt = 0; attempt < attempts; attempt += 1) {
      try {
        lastResult = await client.reportDiagnosticEvent({
          setupToken, kind: event.kind, code: event.code, phase: event.phase,
          platform: { os: process.platform, architecture: process.arch, installer_version: '0.1.0' },
          idempotencyKey: event.idempotencyKey
        });
        lastError = null;
        break;
      } catch (reportError) {
        lastError = reportError;
        if (attempt + 1 < attempts) await sleep(Math.min(8000, 500 * (2 ** attempt)) + crypto.randomInt(0, 250));
      }
    }
    if (lastError) { await saveDiagnosticOutbox(outboxFile, events); throw lastError; }
    events.shift();
    await saveDiagnosticOutbox(outboxFile, events);
  }
  return lastResult;
}

async function reportInstallationFailure({ client, setupToken, error, outboxFile = null, attempts = 5, sleep = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)) } = {}) {
  const safeCodes = new Set(['artifact_checksum', 'artifact_download', 'artifact_extract', 'cloud_discovery', 'local_state', 'orchestration_failed', 'needs_access', 'fleet_installation', 'setup_completion']);
  const phase = typeof error?.failurePhase === 'string' && /^[a-z][a-z0-9_]{0,63}$/.test(error.failurePhase) ? error.failurePhase : 'orchestration';
  const candidate = error?.code === 'LOOKOUT_LOCAL_STATE' ? 'local_state'
    : phase === 'cloud_discovery' ? 'cloud_discovery'
    : phase === 'needs_access' ? 'needs_access'
      : phase === 'verifying' ? 'setup_completion'
        : phase === 'deploying' ? 'fleet_installation'
          : 'orchestration_failed';
  const code = safeCodes.has(candidate) ? candidate : 'orchestration_failed';
  return reportInstallerDiagnostic({ client, setupToken, kind: 'failure', code, phase, outboxFile, attempts, sleep });
}

async function runOnboarding({
  sourceDirectory = path.resolve(__dirname, '..'), stateDirectory = process.platform === 'linux' && process.geteuid?.() === 0 ? '/var/lib/lookout-install' : userStateDirectory(),
  client = new SetupSessionClient({ baseUrl: process.env.LOOKOUT_SETUP_ORIGIN || DEFAULT_SETUP_ORIGIN }),
  installer = runInstaller, hostTrustPreparer = prepareKnownHosts, bootstrapAuthorizer = null, input = null, output = stdout, allowTestMode = false
} = {}) {
  const state = await privateDirectory(stateDirectory);
  const identity = await loadOrCreateDeploymentIdentity(state);
  const bootstrapDirectory = path.join(state, 'bootstrap');
  let bootstrap;
  let claim;
  let setupToken;
  let setupTokenFile;
  let supportTokenFile;
  let connected = false;
  let stagingCredential;
  let stagingScope;
  const stateFile = path.join(state, 'onboarding-state.json');
  const legacyStateFile = path.join(state, 'onboarding-resume.json');
  const diagnosticOutboxFile = path.join(state, 'installation-diagnostics-outbox.json');
  try {
    let saved = await loadOnboardingState(stateFile);
    if (!saved) {
      saved = await loadOnboardingState(legacyStateFile);
      if (saved) {
        await writePrivate(stateFile, `${JSON.stringify(saved)}\n`);
        await fsp.unlink(legacyStateFile);
      }
    }
    setupTokenFile = process.env.LOOKOUT_SETUP_TOKEN_FILE;
    if (typeof setupTokenFile !== 'string') throw new Error('LOOKOUT_SETUP_TOKEN_FILE is required');
    setupToken = await readSetupTokenFromFile(setupTokenFile);
    supportTokenFile = typeof process.env.LOOKOUT_SUPPORT_TOKEN_FILE === 'string' ? path.resolve(process.env.LOOKOUT_SUPPORT_TOKEN_FILE) : null;
    try { await reportInstallerDiagnostic({ client, setupToken, outboxFile: diagnosticOutboxFile, enqueue: false }); }
    catch { /* A retained diagnostic is retried again before setup exits. */ }
    const setupTokenHash = crypto.createHash('sha256').update(setupToken).digest('base64url');
    const matchingSaved = saved && (!saved.setupTokenHash || saved.setupTokenHash === setupTokenHash) ? saved : null;
    await client.connectSession({ setupToken });
    connected = true;
    output.write('Connected. The local orchestrator is running and confirmed by the control plane. Keep this terminal open while installation continues; data will appear in the Lookout console as systems connect.\n');
    const approvedScope = await readApprovedScope(process.env.LOOKOUT_INSTALLATION_SCOPE_FILE);
    const validatedScope = approvedScope ? validateInstallationScope(approvedScope) : null;
    if (!validatedScope && !saved) output.write('Discovering running Linux VMs from available cloud accounts...\n');
    const requestedScope = validatedScope
      || matchingSaved?.claim.installationScope
      || installationScope(await discoverCloudFleetAsync({ markLocal: process.platform === 'linux' && process.geteuid?.() === 0 }));
    claim = await client.claimSession({ setupTokenProvider: async () => setupToken, deploymentIdentity: identity, installationScope: requestedScope });
    const proof = await client.proveSession({
      sessionId: claim.sessionId, sessionToken: claim.sessionToken, challenge: claim.challenge,
      signatureProvider: (message) => signSetupProof(identity, message)
    });
    await writePrivate(stateFile, `${JSON.stringify({ schemaVersion: 1, setupTokenHash, claim, proof })}\n`);
    output.write(`Selected ${claim.installationScope.vms.length} Linux VM${claim.installationScope.vms.length === 1 ? '' : 's'}; installation is continuing.\n`);
    try { bootstrap = await createBootstrapKey(bootstrapDirectory, { deploymentId: `setup-${crypto.randomUUID()}` }); }
    catch (error) {
      if (!/Refusing to replace/.test(error.message)) throw error;
      bootstrap = await loadExistingBootstrap(bootstrapDirectory);
    }
    await client.publishBootstrapKey({ sessionId: claim.sessionId, sessionToken: claim.sessionToken, authorizedKeysLine: bootstrap.authorizedKeysLine, fingerprint: bootstrap.fingerprint });
    if (bootstrapAuthorizer) await bootstrapAuthorizer({ scope: claim.installationScope, bootstrap, input, output });
    const { consoleSync, dashboardUrl } = proof.provisioning;
    stagingCredential = await writePrivate(path.join(state, `.console-credential.${claim.deploymentId}`), `${consoleSync.credential}\n`);
    stagingScope = await writePrivate(path.join(state, `.installation-scope.${claim.deploymentId}.json`), `${JSON.stringify(claim.installationScope)}\n`);
    await client.reportPhase({ sessionId: claim.sessionId, sessionToken: claim.sessionToken, phase: 'discovering' });
    const knownHostsFile = process.env.LOOKOUT_SSH_KNOWN_HOSTS
      ? await hostTrustPreparer({ stateDirectory: state, input, output })
      : null;
    const installerPhases = new Set();
    const result = await installer({
      sourceDirectory,
      environment: {
        ...process.env,
        LOOKOUT_SOURCE_DIR: path.resolve(sourceDirectory),
        LOOKOUT_SSH_IDENTITY: bootstrap.privateKeyFile,
        LOOKOUT_BOOTSTRAP_PUBLIC_KEY_FILE: bootstrap.publicKeyFile,
        LOOKOUT_INSTALLATION_SCOPE_FILE: stagingScope,
        ...(claim.recovery ? { LOOKOUT_RECOVERY: '1' } : {}),
        ...(knownHostsFile ? { LOOKOUT_SSH_KNOWN_HOSTS: knownHostsFile } : {}),
        LOOKOUT_DEPLOYMENT_ID: claim.deploymentId,
        LOOKOUT_CONSOLE_DEPLOYMENT_ID: claim.deploymentId,
        LOOKOUT_CONSOLE_ENDPOINT: consoleSync.endpoint,
        LOOKOUT_CONSOLE_CREDENTIAL_SOURCE: stagingCredential
      },
      output,
      onProgress: ({ phase, completed, total }) => {
        if (!['deploying', 'verifying', 'needs_access', 'reporting_interrupted'].includes(phase)) return;
        const firstReport = !installerPhases.has(phase);
        installerPhases.add(phase);
        const status = client.reportPhase({ sessionId: claim.sessionId, sessionToken: claim.sessionToken, phase, completed, total });
        if (firstReport && ['needs_access', 'reporting_interrupted'].includes(phase)) {
          return Promise.all([status, reportInstallerDiagnostic({ client, setupToken, kind: 'diagnostic', code: phase, phase, outboxFile: diagnosticOutboxFile }).catch(() => {})]);
        }
        return status;
      }
    });
    if (result.mode === 'standalone') {
      for (const filename of [bootstrap.privateKeyFile, bootstrap.publicKeyFile, path.join(bootstrapDirectory, 'lookout-bootstrap-key.json')]) await fsp.rm(filename, { force: true });
    }
    if (!installerPhases.has('deploying') && !installerPhases.has('verifying')) await client.reportPhase({ sessionId: claim.sessionId, sessionToken: claim.sessionToken, phase: 'deploying' });
    if (!installerPhases.has('verifying')) await client.reportPhase({ sessionId: claim.sessionId, sessionToken: claim.sessionToken, phase: 'verifying' });
    await completeSetupSession({ client, sessionId: claim.sessionId, sessionToken: claim.sessionToken });
    await fsp.rm(stateFile, { force: true });
    try { await fsp.unlink(path.resolve(setupTokenFile)); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
    setupTokenFile = null;
    delete process.env.LOOKOUT_SETUP_TOKEN_FILE;
    if (supportTokenFile) {
      try { await fsp.unlink(supportTokenFile); }
      catch (error) { if (error.code !== 'ENOENT') throw error; }
      supportTokenFile = null;
      delete process.env.LOOKOUT_SUPPORT_TOKEN_FILE;
    }
    output.write(`\nLookout setup is complete. Open ${dashboardUrl}\n`);
    return { deploymentId: claim.deploymentId, dashboardUrl, installation: result };
  } catch (error) {
    if (claim) {
      try {
        if (error.failurePhase === 'needs_access') await client.reportPhase({ sessionId: claim.sessionId, sessionToken: claim.sessionToken, phase: 'needs_access' });
        else await client.reportPhase({ sessionId: claim.sessionId, sessionToken: claim.sessionToken, phase: 'failed' });
      } catch { /* Preserve the installation error when SaaS is also unavailable. */ }
    } else if (setupToken && connected && error.status !== 400) {
      try { await client.reportPreclaimFailure({ setupToken, code: error.code === 'LOOKOUT_LOCAL_STATE' ? 'local_state' : 'cloud_discovery' }); }
      catch { /* Preserve the local failure when SaaS reporting is unavailable. */ }
    }
    if (setupToken) {
      const diagnosticError = error.failurePhase ? error : Object.assign(Object.create(Object.getPrototypeOf(error)), error, { message: error.message, code: error.code, failurePhase: claim ? 'orchestration' : 'cloud_discovery' });
      try { await reportInstallationFailure({ client, setupToken, error: diagnosticError, outboxFile: diagnosticOutboxFile }); }
      catch { /* Preserve the installation error when diagnostics are unavailable. */ }
    }
    throw error;
  } finally {
    if (stagingCredential) await fsp.rm(stagingCredential, { force: true });
    if (stagingScope) await fsp.rm(stagingScope, { force: true });
  }
}

if (require.main === module) runOnboarding().catch((error) => { console.error(`lookout-setup: ${error.message}`); process.exitCode = 1; });

module.exports = { runOnboarding, runInstaller, completeSetupSession, loadDiagnosticOutbox, saveDiagnosticOutbox, reportInstallerDiagnostic, reportInstallationFailure, writePrivate, readApprovedScope, loadExistingBootstrap, loadOnboardingState, discoveredSshAddresses, prepareKnownHosts, userStateDirectory };

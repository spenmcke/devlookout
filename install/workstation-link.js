#!/usr/bin/env node
'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');
const { SetupSessionClient, readSetupTokenFromFile } = require('../src/onboarding/setup-session-client');
const { loadOrCreateDeploymentIdentity, signSetupProof } = require('../src/onboarding/deployment-identity');
const { readApprovedScope, writePrivate } = require('./onboard');

const DEFAULT_SETUP_ORIGIN = 'https://app.devlookout.com';

async function ensurePrivateStateDirectory(stateDirectory) {
  const directory = path.resolve(stateDirectory);
  await fs.mkdir(directory, { recursive: true, mode: 0o700 });
  const before = await fs.lstat(directory);
  if (!before.isDirectory() || before.isSymbolicLink()) throw new Error('Workstation link state must be a non-symlink directory');
  if (process.platform !== 'win32' && before.uid !== process.geteuid?.()) throw new Error('Workstation link state must be private and owned by the current user');
  if (process.platform !== 'win32') await fs.chmod(directory, 0o700);
  const after = await fs.lstat(directory);
  if (process.platform !== 'win32' && ((after.mode & 0o077) !== 0 || after.uid !== process.geteuid?.())) throw new Error('Workstation link state must be private and owned by the current user');
  return directory;
}

async function prepare({ tokenFile, scopeFile, stateDirectory, client = new SetupSessionClient({ baseUrl: process.env.LOOKOUT_SETUP_ORIGIN || DEFAULT_SETUP_ORIGIN }) } = {}) {
  const directory = await ensurePrivateStateDirectory(stateDirectory);
  const claimFile = path.join(directory, 'claim.json');
  try {
    const existing = await loadState(directory);
    await fs.rm(tokenFile, { force: true });
    await fs.rm(scopeFile, { force: true });
    await fs.rm(claimFile, { force: true });
    await client.reportPhase({ sessionId: existing.sessionId, sessionToken: existing.sessionToken, phase: 'installing' });
    return { deploymentId: existing.deploymentId, consoleEndpoint: existing.consoleEndpoint, credentialFile: existing.credentialFile, dashboardUrl: existing.dashboardUrl };
  } catch (error) { if (error.code !== 'ENOENT') throw error; }
  const identity = await loadOrCreateDeploymentIdentity(directory);
  const scope = await readApprovedScope(scopeFile);
  const scopeDigest = crypto.createHash('sha256').update(JSON.stringify(scope)).digest('hex');
  let claim;
  try {
    claim = JSON.parse(await fs.readFile(claimFile, 'utf8'));
    if (claim.schemaVersion !== 1 || typeof claim.sessionId !== 'string' || typeof claim.sessionToken !== 'string' || typeof claim.challenge !== 'string' || typeof claim.deploymentId !== 'string' || claim.scopeDigest !== scopeDigest) throw new Error('Workstation link claim state is invalid');
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
    const setupToken = await readSetupTokenFromFile(tokenFile);
    claim = await client.claimSession({ setupTokenProvider: async () => setupToken, deploymentIdentity: identity, installationScope: scope });
    await writePrivate(claimFile, `${JSON.stringify({ schemaVersion: 1, ...claim, scopeDigest })}\n`);
  }
  await fs.rm(tokenFile, { force: true });
  const proof = await client.proveSession({
    sessionId: claim.sessionId, sessionToken: claim.sessionToken, challenge: claim.challenge,
    signatureProvider: (message) => signSetupProof(identity, message)
  });
  const credentialFile = await writePrivate(path.join(directory, 'console-credential'), `${proof.provisioning.consoleSync.credential}\n`);
  const state = {
    schemaVersion: 1, sessionId: claim.sessionId, sessionToken: claim.sessionToken, deploymentId: claim.deploymentId,
    consoleEndpoint: proof.provisioning.consoleSync.endpoint, credentialFile, dashboardUrl: proof.provisioning.dashboardUrl
  };
  await writePrivate(path.join(directory, 'link.json'), `${JSON.stringify(state)}\n`);
  await fs.rm(claimFile, { force: true });
  await client.reportPhase({ sessionId: state.sessionId, sessionToken: state.sessionToken, phase: 'installing' });
  return { deploymentId: state.deploymentId, consoleEndpoint: state.consoleEndpoint, credentialFile, dashboardUrl: state.dashboardUrl };
}

async function loadState(stateDirectory) {
  const filename = path.join(path.resolve(stateDirectory), 'link.json');
  const value = JSON.parse(await fs.readFile(filename, 'utf8'));
  if (value.schemaVersion !== 1 || typeof value.sessionId !== 'string' || typeof value.sessionToken !== 'string' || typeof value.deploymentId !== 'string' || typeof value.consoleEndpoint !== 'string' || typeof value.credentialFile !== 'string' || typeof value.dashboardUrl !== 'string') throw new Error('Workstation link state is invalid');
  return value;
}

async function finish({ stateDirectory, client = new SetupSessionClient({ baseUrl: process.env.LOOKOUT_SETUP_ORIGIN || DEFAULT_SETUP_ORIGIN }) } = {}) {
  const completionFile = path.join(path.resolve(stateDirectory), 'complete.json');
  try {
    const completed = JSON.parse(await fs.readFile(completionFile, 'utf8'));
    if (completed.schemaVersion === 1 && typeof completed.deploymentId === 'string' && typeof completed.dashboardUrl === 'string') return { deploymentId: completed.deploymentId, dashboardUrl: completed.dashboardUrl };
    throw new Error('Workstation completion state is invalid');
  } catch (error) { if (error.code !== 'ENOENT') throw error; }
  const state = await loadState(stateDirectory);
  await client.reportPhase({ sessionId: state.sessionId, sessionToken: state.sessionToken, phase: 'verifying' });
  let lastError;
  for (let attempt = 0; attempt < 30; attempt += 1) {
    try {
      await client.reportPhase({ sessionId: state.sessionId, sessionToken: state.sessionToken, phase: 'complete' });
      lastError = null;
      break;
    } catch (error) {
      lastError = error;
      await new Promise((resolve) => setTimeout(resolve, 2000));
    }
  }
  if (lastError) throw new Error('Lookout SaaS did not receive the first deployment status report');
  const result = { schemaVersion: 1, deploymentId: state.deploymentId, dashboardUrl: state.dashboardUrl, completedAt: new Date().toISOString() };
  await writePrivate(completionFile, `${JSON.stringify(result)}\n`);
  await fs.rm(state.credentialFile, { force: true });
  await fs.rm(path.join(path.resolve(stateDirectory), 'link.json'), { force: true });
  return { deploymentId: result.deploymentId, dashboardUrl: result.dashboardUrl };
}

async function fail({ stateDirectory, client = new SetupSessionClient({ baseUrl: process.env.LOOKOUT_SETUP_ORIGIN || DEFAULT_SETUP_ORIGIN }) } = {}) {
  const state = await loadState(stateDirectory);
  await client.reportPhase({ sessionId: state.sessionId, sessionToken: state.sessionToken, phase: 'failed' });
  return { deploymentId: state.deploymentId, failed: true };
}

async function diagnose({ stateDirectory, diagnosticFile, client = new SetupSessionClient({ baseUrl: process.env.LOOKOUT_SETUP_ORIGIN || DEFAULT_SETUP_ORIGIN }) } = {}) {
  const state = await loadState(stateDirectory);
  const diagnostic = JSON.parse(await fs.readFile(path.resolve(diagnosticFile), 'utf8'));
  try { return await client.reportDiagnostic({ sessionId: state.sessionId, sessionToken: state.sessionToken, diagnostic }); }
  finally { await fs.rm(path.resolve(diagnosticFile), { force: true }); }
}

async function keepalive({ stateDirectory, client = new SetupSessionClient({ baseUrl: process.env.LOOKOUT_SETUP_ORIGIN || DEFAULT_SETUP_ORIGIN }), intervalMs = 4 * 60 * 1000, attempts = 30 } = {}) {
  const state = await loadState(stateDirectory);
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    if (attempt > 0) await new Promise((resolve) => setTimeout(resolve, intervalMs));
    try { await client.reportPhase({ sessionId: state.sessionId, sessionToken: state.sessionToken, phase: 'deploying' }); }
    catch (error) { if (/terminal|expired|unavailable/i.test(error.message)) return { stopped: true }; throw error; }
  }
  return { stopped: false };
}

async function main() {
  const [command, first, second, third] = process.argv.slice(2);
  if (command === 'prepare' && first && second && third) console.log(JSON.stringify(await prepare({ tokenFile: first, scopeFile: second, stateDirectory: third })));
  else if (command === 'finish' && first) console.log(JSON.stringify(await finish({ stateDirectory: first })));
  else if (command === 'fail' && first) console.log(JSON.stringify(await fail({ stateDirectory: first })));
  else if (command === 'diagnose' && first && second) console.log(JSON.stringify(await diagnose({ stateDirectory: first, diagnosticFile: second })));
  else if (command === 'keepalive' && first) console.log(JSON.stringify(await keepalive({ stateDirectory: first })));
  else throw new Error('Usage: workstation-link prepare <token-file> <scope-file> <state-directory> | finish <state-directory> | fail <state-directory> | diagnose <state-directory> <diagnostic-file> | keepalive <state-directory>');
}

if (require.main === module) main().catch((error) => { console.error(`lookout-link: ${error.message}`); process.exitCode = 1; });

module.exports = { prepare, finish, fail, diagnose, keepalive, loadState, ensurePrivateStateDirectory };

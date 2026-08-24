'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { Readable, Writable } = require('node:stream');
const { runOnboarding, loadExistingBootstrap, loadOnboardingState, completeSetupSession } = require('../install/onboard');

test('onboarding binds SaaS provisioning, installs with paths not secrets, reports phases, and cleans staging credential', async (t) => {
  const stateDirectory = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-onboarding-flow-'));
  t.after(() => fs.rm(stateDirectory, { recursive: true, force: true }));
  const phases = [];
  const phaseOrder = ['discovering', 'deploying', 'verifying', 'complete'];
  const setupEvents = [];
  let claimedIdentity;
  const scope = { central_vm_id: 'vm-central', vms: [{ id: 'vm-central', provider: 'test', name: 'central', address: '10.0.0.10', platform: 'linux', local: true }] };
  const scopeFile = path.join(stateDirectory, 'approved-scope.json');
  await fs.writeFile(scopeFile, JSON.stringify(scope), { mode: 0o600 });
  const tokenFile = path.join(stateDirectory, 'setup-token');
  const supportTokenFile = path.join(stateDirectory, 'support-token');
  await fs.writeFile(tokenFile, `lst_${'a'.repeat(43)}\n`, { mode: 0o600 });
  await fs.writeFile(supportTokenFile, `ldw_${'s'.repeat(43)}\n`, { mode: 0o600 });
  process.env.LOOKOUT_SETUP_TOKEN_FILE = tokenFile;
  process.env.LOOKOUT_SUPPORT_TOKEN_FILE = supportTokenFile;
  process.env.LOOKOUT_INSTALLATION_SCOPE_FILE = scopeFile;
  t.after(() => { delete process.env.LOOKOUT_SETUP_TOKEN_FILE; delete process.env.LOOKOUT_SUPPORT_TOKEN_FILE; delete process.env.LOOKOUT_INSTALLATION_SCOPE_FILE; });
  const client = {
    async connectSession() { setupEvents.push('connected'); return { accepted: true }; },
    async claimSession({ deploymentIdentity, installationScope }) {
      setupEvents.push('claimed');
      claimedIdentity = deploymentIdentity;
      assert.deepEqual(installationScope, scope);
      return { sessionId: 'session_abcdefghijklmnop', sessionToken: 'session-token-abcdefghijklmnopqrstuvwxyz', deploymentId: 'deployment_12345678', challenge: 'A'.repeat(43), installationScope: scope, recovery: false };
    },
    async proveSession({ signatureProvider }) {
      const signature = await signatureProvider(Buffer.from('lookout-setup-possession-v1\0session\0challenge'));
      assert.equal(signature.length, 64);
      return { provisioning: { consoleSync: { endpoint: 'https://ingest.lookout.example/v1/console-sync', credential: 'console-credential-abcdefghijklmnopqrstuvwxyz' }, dashboardUrl: 'https://app.lookout.example/deployments/deployment_12345678' } };
    },
    async publishBootstrapKey({ authorizedKeysLine, fingerprint }) { setupEvents.push('key-published'); assert.match(authorizedKeysLine, /^restrict ssh-ed25519 /); assert.match(fingerprint, /^SHA256:/); return { accepted: true }; },
    async reportPhase({ phase }) {
      if (phases.length && phaseOrder.indexOf(phase) < phaseOrder.indexOf(phases.at(-1))) {
        const error = new Error('phase moved backwards');
        error.status = 409;
        throw error;
      }
      phases.push(phase);
      return { accepted: true };
    }
  };
  let installerEnvironment;
  const outputChunks = [];
  const output = new Writable({ write(chunk, encoding, callback) { outputChunks.push(Buffer.from(chunk)); callback(); } });
  const result = await runOnboarding({
    sourceDirectory: path.resolve(__dirname, '..'), stateDirectory, client,
    hostTrustPreparer: async () => null, bootstrapAuthorizer: async () => true, input: Readable.from(['\n']), output, allowTestMode: true,
    installer: async ({ environment, onProgress }) => {
      installerEnvironment = environment;
      const staged = await fs.readFile(environment.LOOKOUT_CONSOLE_CREDENTIAL_SOURCE, 'utf8');
      assert.equal(staged, 'console-credential-abcdefghijklmnopqrstuvwxyz\n');
      assert.equal((await fs.stat(environment.LOOKOUT_CONSOLE_CREDENTIAL_SOURCE)).mode & 0o777, 0o600);
      await onProgress({ phase: 'deploying', completed: 0, total: 1 });
      await onProgress({ phase: 'verifying' });
      return { mode: 'standalone' };
    }
  });
  assert.match(claimedIdentity.publicKeyPem, /BEGIN PUBLIC KEY/);
  assert.ok(setupEvents.indexOf('connected') < setupEvents.indexOf('claimed'));
  assert.ok(setupEvents.indexOf('claimed') < setupEvents.indexOf('key-published'));
  assert.equal(installerEnvironment.LOOKOUT_CONSOLE_DEPLOYMENT_ID, 'deployment_12345678');
  assert.equal(installerEnvironment.LOOKOUT_DEPLOYMENT_ID, 'deployment_12345678');
  assert.equal(installerEnvironment.LOOKOUT_CONSOLE_ENDPOINT, 'https://ingest.lookout.example/v1/console-sync');
  assert.deepEqual(phases, ['discovering', 'deploying', 'verifying', 'complete']);
  assert.equal(result.dashboardUrl, 'https://app.lookout.example/deployments/deployment_12345678');
  await assert.rejects(fs.access(installerEnvironment.LOOKOUT_CONSOLE_CREDENTIAL_SOURCE), { code: 'ENOENT' });
  await assert.rejects(fs.access(tokenFile), { code: 'ENOENT' });
  assert.equal(process.env.LOOKOUT_SETUP_TOKEN_FILE, undefined);
  await assert.rejects(fs.access(supportTokenFile), { code: 'ENOENT' });
  const rendered = Buffer.concat(outputChunks).toString('utf8');
  assert.match(rendered, /Connected\. The local orchestrator is running and confirmed by the control plane\. Keep this terminal open while installation continues/);
  assert.match(rendered, /Selected 1 Linux VM; installation is continuing/);
  assert.doesNotMatch(rendered, /restrict ssh-ed25519/);
  assert.doesNotMatch(rendered, /Pairing code|Verification phrase|console-credential/);
});

test('onboarding reports failure and retains the temporary key for retry cleanup', async (t) => {
  const stateDirectory = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-onboarding-failure-'));
  t.after(() => fs.rm(stateDirectory, { recursive: true, force: true }));
  const phases = [];
  const scope = { central_vm_id: 'vm-central', vms: [{ id: 'vm-central', local: true }] };
  const scopeFile = path.join(stateDirectory, 'approved-scope.json');
  await fs.writeFile(scopeFile, JSON.stringify(scope), { mode: 0o600 });
  const tokenFile = path.join(stateDirectory, 'setup-token');
  const supportTokenFile = path.join(stateDirectory, 'support-token');
  await fs.writeFile(tokenFile, `lst_${'b'.repeat(43)}\n`, { mode: 0o600 });
  await fs.writeFile(supportTokenFile, `ldw_${'t'.repeat(43)}\n`, { mode: 0o600 });
  process.env.LOOKOUT_SETUP_TOKEN_FILE = tokenFile;
  process.env.LOOKOUT_SUPPORT_TOKEN_FILE = supportTokenFile;
  process.env.LOOKOUT_INSTALLATION_SCOPE_FILE = scopeFile;
  t.after(() => { delete process.env.LOOKOUT_SETUP_TOKEN_FILE; delete process.env.LOOKOUT_SUPPORT_TOKEN_FILE; delete process.env.LOOKOUT_INSTALLATION_SCOPE_FILE; });
  const client = {
    async connectSession() { return { accepted: true }; },
    async claimSession() { return { sessionId: 'session_abcdefghijklmnop', sessionToken: 'session-token-abcdefghijklmnopqrstuvwxyz', deploymentId: 'deployment_12345678', challenge: 'A'.repeat(43), installationScope: scope }; },
    async proveSession({ signatureProvider }) { await signatureProvider(Buffer.alloc(64)); return { provisioning: { consoleSync: { endpoint: 'https://ingest.lookout.example/', credential: 'console-credential-abcdefghijklmnopqrstuvwxyz' }, dashboardUrl: 'https://app.lookout.example/' } }; },
    async publishBootstrapKey() { return { accepted: true }; },
    async reportPhase({ phase }) { phases.push(phase); return { accepted: true }; }
  };
  const output = new Writable({ write(chunk, encoding, callback) { callback(); } });
  await assert.rejects(runOnboarding({
    sourceDirectory: path.resolve(__dirname, '..'), stateDirectory, client, hostTrustPreparer: async () => null, bootstrapAuthorizer: async () => true, input: Readable.from(['\n']), output, allowTestMode: true,
    installer: async () => { throw new Error('fixture install failure'); }
  }), /fixture install failure/);
  assert.deepEqual(phases, ['discovering', 'failed']);
  const saved = await loadOnboardingState(path.join(stateDirectory, 'onboarding-state.json'));
  assert.match(saved.setupTokenHash, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(saved.claim.deploymentId, 'deployment_12345678');
  assert.equal(saved.proof.provisioning.consoleSync.credential, 'console-credential-abcdefghijklmnopqrstuvwxyz');
  await fs.access(tokenFile);
  assert.equal((await fs.stat(tokenFile)).mode & 0o777, 0o600);
  await fs.access(supportTokenFile);
  await fs.access(path.join(stateDirectory, 'bootstrap/lookout-bootstrap-key'));
  if (process.platform !== 'win32') {
    await fs.chmod(path.join(stateDirectory, 'bootstrap/lookout-bootstrap-key.json'), 0o644);
    await assert.rejects(loadExistingBootstrap(path.join(stateDirectory, 'bootstrap')), /must be private/);
  }
});

test('the same setup token pairs directly with the current approved scope after an interrupted install', async (t) => {
  const stateDirectory = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-onboarding-direct-retry-'));
  t.after(() => fs.rm(stateDirectory, { recursive: true, force: true }));
  t.after(() => { delete process.env.LOOKOUT_SETUP_TOKEN_FILE; delete process.env.LOOKOUT_INSTALLATION_SCOPE_FILE; });
  const originalScope = { vms: [{ id: 'vm-central', provider: 'test', name: 'central', address: '10.0.0.10', platform: 'linux', local: true }] };
  const recreatedScope = { vms: [{ id: 'vm-central', provider: 'test', name: 'central-renamed', address: '10.0.0.11', platform: 'linux', local: true }] };
  const scopeFile = path.join(stateDirectory, 'approved-scope.json');
  const tokenFile = path.join(stateDirectory, 'setup-token');
  await fs.writeFile(scopeFile, JSON.stringify(originalScope), { mode: 0o600 });
  await fs.writeFile(tokenFile, `lst_${'g'.repeat(43)}\n`, { mode: 0o600 });
  process.env.LOOKOUT_SETUP_TOKEN_FILE = tokenFile;
  process.env.LOOKOUT_INSTALLATION_SCOPE_FILE = scopeFile;

  const claim = { sessionId: 'session_direct_retry_1234', sessionToken: 'session-token-first-abcdefghijklmnopqrstuvwxyz', deploymentId: 'deployment_direct_retry', challenge: 'A'.repeat(43), installationScope: originalScope };
  const provisioning = { consoleSync: { endpoint: 'https://ingest.lookout.example/', credential: 'console-credential-abcdefghijklmnopqrstuvwxyz' }, dashboardUrl: 'https://app.lookout.example/' };
  const firstClient = {
    async connectSession() { return { accepted: true }; },
    async claimSession({ installationScope }) { assert.deepEqual(installationScope, originalScope); return claim; },
    async proveSession() { return { provisioning }; },
    async publishBootstrapKey() { return { accepted: true }; },
    async reportPhase() { return { accepted: true }; }
  };
  await assert.rejects(runOnboarding({
    sourceDirectory: path.resolve(__dirname, '..'), stateDirectory, client: firstClient,
    output: new Writable({ write(chunk, encoding, callback) { callback(); } }),
    installer: async () => { throw new Error('fixture interrupted'); }
  }), /fixture interrupted/);

  await fs.rename(path.join(stateDirectory, 'onboarding-state.json'), path.join(stateDirectory, 'onboarding-resume.json'));
  await fs.writeFile(scopeFile, JSON.stringify(recreatedScope), { mode: 0o600 });
  let paired = false;
  const retryClient = {
    async connectSession() { return { accepted: true }; },
    async claimSession({ installationScope }) {
      paired = true;
      assert.deepEqual(installationScope, recreatedScope);
      return { ...claim, sessionToken: 'session-token-retry-abcdefghijklmnopqrstuvwxyz', challenge: 'B'.repeat(43), installationScope };
    },
    async proveSession() { return { provisioning }; },
    async publishBootstrapKey() { return { accepted: true }; },
    async reportPhase() { return { accepted: true }; }
  };
  await runOnboarding({
    sourceDirectory: path.resolve(__dirname, '..'), stateDirectory, client: retryClient,
    output: new Writable({ write(chunk, encoding, callback) { callback(); } }),
    installer: async () => ({ mode: 'standalone' })
  });
  assert.equal(paired, true);
  await assert.rejects(fs.access(path.join(stateDirectory, 'onboarding-resume.json')), { code: 'ENOENT' });
});

test('claim schema rejection preserves the connected setup session for a corrected retry', async (t) => {
  const stateDirectory = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-onboarding-schema-'));
  t.after(() => fs.rm(stateDirectory, { recursive: true, force: true }));
  const scopeFile = path.join(stateDirectory, 'approved-scope.json');
  const tokenFile = path.join(stateDirectory, 'setup-token');
  await fs.writeFile(scopeFile, JSON.stringify({ vms: [{ id: 'vm-one', provider: 'test', platform: 'linux' }] }), { mode: 0o600 });
  await fs.writeFile(tokenFile, `lst_${'e'.repeat(43)}\n`, { mode: 0o600 });
  process.env.LOOKOUT_SETUP_TOKEN_FILE = tokenFile;
  process.env.LOOKOUT_INSTALLATION_SCOPE_FILE = scopeFile;
  t.after(() => { delete process.env.LOOKOUT_SETUP_TOKEN_FILE; delete process.env.LOOKOUT_INSTALLATION_SCOPE_FILE; });
  let failureReports = 0;
  const rejection = Object.assign(new Error('schema rejected'), { status: 400 });
  await assert.rejects(runOnboarding({
    stateDirectory,
    client: {
      async connectSession() { return { accepted: true }; },
      async claimSession() { throw rejection; },
      async reportPreclaimFailure() { failureReports += 1; }
    },
    output: new Writable({ write(chunk, encoding, callback) { callback(); } })
  }), (error) => error === rejection);
  assert.equal(failureReports, 0);
  await fs.access(tokenFile);
  assert.equal((await fs.stat(tokenFile)).mode & 0o777, 0o600);
});

test('connection rejection preserves the setup token file for diagnosis or retry', async (t) => {
  const stateDirectory = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-onboarding-connect-'));
  t.after(() => fs.rm(stateDirectory, { recursive: true, force: true }));
  const scopeFile = path.join(stateDirectory, 'approved-scope.json');
  const tokenFile = path.join(stateDirectory, 'setup-token');
  await fs.writeFile(scopeFile, JSON.stringify({ vms: [{ id: 'vm-one', provider: 'test', platform: 'linux' }] }), { mode: 0o600 });
  await fs.writeFile(tokenFile, `lst_${'f'.repeat(43)}\n`, { mode: 0o600 });
  process.env.LOOKOUT_SETUP_TOKEN_FILE = tokenFile;
  process.env.LOOKOUT_INSTALLATION_SCOPE_FILE = scopeFile;
  t.after(() => { delete process.env.LOOKOUT_SETUP_TOKEN_FILE; delete process.env.LOOKOUT_INSTALLATION_SCOPE_FILE; });
  const rejection = Object.assign(new Error('setup unavailable'), { status: 404 });
  await assert.rejects(runOnboarding({
    stateDirectory,
    client: { async connectSession() { throw rejection; } },
    output: new Writable({ write(chunk, encoding, callback) { callback(); } })
  }), (error) => error === rejection);
  await fs.access(tokenFile);
  assert.equal((await fs.stat(tokenFile)).mode & 0o777, 0o600);
});

test('a new setup token starts fresh instead of resuming an interrupted deployment', async (t) => {
  const stateDirectory = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-onboarding-rebind-'));
  t.after(() => fs.rm(stateDirectory, { recursive: true, force: true }));
  t.after(() => { delete process.env.LOOKOUT_SETUP_TOKEN_FILE; delete process.env.LOOKOUT_INSTALLATION_SCOPE_FILE; });
  const scope = { central_vm_id: 'vm-central', vms: [{ id: 'vm-central', provider: 'test', name: 'central', address: '10.0.0.10', platform: 'linux', local: true }] };
  const scopeFile = path.join(stateDirectory, 'approved-scope.json');
  const firstTokenFile = path.join(stateDirectory, 'first-token');
  await fs.writeFile(scopeFile, JSON.stringify(scope), { mode: 0o600 });
  await fs.writeFile(firstTokenFile, `lst_${'c'.repeat(43)}\n`, { mode: 0o600 });
  process.env.LOOKOUT_SETUP_TOKEN_FILE = firstTokenFile;
  process.env.LOOKOUT_INSTALLATION_SCOPE_FILE = scopeFile;
  const firstClient = {
    async connectSession() { return { accepted: true }; },
    async claimSession() { return { sessionId: 'session_first_abcdefgh', sessionToken: 'first-session-token-abcdefghijklmnopqrstuvwxyz', deploymentId: 'deployment_12345678', challenge: 'A'.repeat(43), installationScope: scope }; },
    async proveSession() { return { provisioning: { consoleSync: { endpoint: 'https://ingest.lookout.example/', credential: 'first-console-credential-abcdefghijklmnopqrstuvwxyz' }, dashboardUrl: 'https://app.lookout.example/' } }; },
    async publishBootstrapKey() { return { accepted: true }; },
    async reportPhase() { return { accepted: true }; }
  };
  await assert.rejects(runOnboarding({
    sourceDirectory: path.resolve(__dirname, '..'), stateDirectory, client: firstClient, output: new Writable({ write(chunk, encoding, callback) { callback(); } }),
    installer: async () => { throw new Error('fixture interrupted'); }
  }), /fixture interrupted/);

  const replacementTokenFile = path.join(stateDirectory, 'replacement-token');
  await fs.writeFile(replacementTokenFile, `lst_${'d'.repeat(43)}\n`, { mode: 0o600 });
  process.env.LOOKOUT_SETUP_TOKEN_FILE = replacementTokenFile;
  const events = [];
  const secondClient = {
    async connectSession() { events.push('connected-new-session'); return { accepted: true }; },
    async claimSession({ installationScope }) {
      events.push('claimed-new-session');
      assert.deepEqual(installationScope, scope);
      return { sessionId: 'session_second_abcdefg', sessionToken: 'second-session-token-abcdefghijklmnopqrstuvwxyz', deploymentId: 'deployment_87654321', challenge: 'B'.repeat(43), installationScope };
    },
    async proveSession() { events.push('proved-new-session'); return { provisioning: { consoleSync: { endpoint: 'https://ingest.lookout.example/', credential: 'second-console-credential-abcdefghijklmnopqrstuvwxyz' }, dashboardUrl: 'https://app.lookout.example/' } }; },
    async publishBootstrapKey() { events.push('key-published'); return { accepted: true }; },
    async reportPhase() { return { accepted: true }; }
  };
  const result = await runOnboarding({
    sourceDirectory: path.resolve(__dirname, '..'), stateDirectory, client: secondClient, output: new Writable({ write(chunk, encoding, callback) { callback(); } }),
    installer: async () => ({ mode: 'standalone' })
  });
  assert.equal(result.deploymentId, 'deployment_87654321');
  assert.deepEqual(events, ['connected-new-session', 'claimed-new-session', 'proved-new-session', 'key-published']);
  await assert.rejects(fs.access(replacementTokenFile), { code: 'ENOENT' });
  await assert.rejects(fs.access(path.join(stateDirectory, 'onboarding-state.json')), { code: 'ENOENT' });
});

test('console completion retries only the snapshot-not-ready conflict', async () => {
  let attempts = 0;
  const client = {
    async reportPhase() {
      attempts += 1;
      if (attempts < 3) throw Object.assign(new Error('not ready'), { status: 409 });
    }
  };
  await completeSetupSession({ client, sessionId: 'session', sessionToken: 'token', attempts: 3, intervalMs: 1, sleep: async () => {} });
  assert.equal(attempts, 3);

  const unauthorized = Object.assign(new Error('unauthorized'), { status: 401 });
  await assert.rejects(completeSetupSession({
    client: { async reportPhase() { throw unauthorized; } },
    sessionId: 'session', sessionToken: 'token', attempts: 30, intervalMs: 1, sleep: async () => { throw new Error('must not sleep'); }
  }), (error) => error === unauthorized);
});

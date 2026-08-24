'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { install, resume, centralRelease, installationRetryAction } = require('../src/cli/workstation-install');
const { releaseFingerprint } = require('../src/cli/workstation-prepare');

test('workstation selects the central VM artifact by reported architecture', () => {
  const environment = { LOOKOUT_RELEASE_TARGETS: JSON.stringify({
    amd64: { url: 'https://releases.example/amd64.tar.gz', sha256: 'a'.repeat(64) },
    arm64: { url: 'https://releases.example/arm64.tar.gz', sha256: 'b'.repeat(64) }
  }) };
  const arm = centralRelease({ name: 'central' }, environment, () => 'aarch64\n');
  assert.equal(arm.url, 'https://releases.example/arm64.tar.gz');
  assert.throws(() => centralRelease({ name: 'central' }, environment, () => 'riscv64\n'), /unsupported Linux architecture/);
});

test('workstation retry restarts pre-link failures and resumes later checkpoints', () => {
  for (const status of ['preparing', 'installing_local']) assert.equal(installationRetryAction({ status }, { retry: true }), 'restart');
  for (const status of ['awaiting_login', 'attaching', 'installing', 'finalizing']) assert.equal(installationRetryAction({ status }, { retry: true }), 'resume');
  assert.equal(installationRetryAction(null, { retry: true }), 'reject');
  assert.equal(installationRetryAction({ status: 'complete' }, { retry: true }), 'reject');
  assert.equal(installationRetryAction({ status: 'complete' }), 'install');
});

test('workstation retry restarts when saved state does not match the current login binding', () => {
  const state = {
    status: 'awaiting_login', centralVm: 'old-central',
    scopeDigest: 'a'.repeat(43), deploymentId: `dpl_${'a'.repeat(32)}`
  };
  assert.equal(installationRetryAction(state, { retry: true, centralVm: 'new-central' }), 'restart');
  assert.equal(installationRetryAction(state, { retry: true, scopeDigest: 'b'.repeat(43) }), 'restart');
  assert.equal(installationRetryAction(state, { retry: true, deploymentId: `dpl_${'b'.repeat(32)}` }), 'restart');
  assert.equal(installationRetryAction(state, {
    retry: true, centralVm: state.centralVm, scopeDigest: state.scopeDigest, deploymentId: state.deploymentId
  }), 'resume');
});

async function writeDeploymentIdentity(directory) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  const target = path.join(directory, 'deployment-identity');
  await fs.mkdir(target, { mode: 0o700 });
  await fs.writeFile(path.join(target, 'deployment-identity.json'), JSON.stringify({
    schemaVersion: 1, createdAt: new Date().toISOString(),
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }),
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' })
  }), { mode: 0o600 });
}

test('workstation install links on central and keeps the setup token out of arguments', async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-workstation-install-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  await writeDeploymentIdentity(directory);
  const calls = [];
  const setupToken = `lst_${'a'.repeat(43)}`;
  const remoteImpl = (_vm, argv, options = {}) => {
    calls.push({ argv, input: options.input });
    if (argv.includes('LOOKOUT_PROVISION_ONLY=1')) return '/usr/bin/node\n';
    if (argv.some((item) => String(item).includes('command -v node'))) return '/usr/bin/node\n';
    if (argv.includes('prepare')) return JSON.stringify({ deploymentId: `dpl_${'d'.repeat(32)}`, consoleEndpoint: `https://app.example/v1/console-sync/dpl_${'d'.repeat(32)}`, credentialFile: '/var/lib/lookout-workstation-link/console-credential', dashboardUrl: 'https://app.example/map' });
    if (argv.includes('finish')) return JSON.stringify({ deploymentId: `dpl_${'d'.repeat(32)}`, dashboardUrl: 'https://app.example/map' });
    if (argv.some((item) => String(item).includes('nohup env LOOKOUT_SETUP_ORIGIN'))) return '1234\n';
    return '';
  };
  const states = [];
  const store = {
    directory, installationFile: path.join(directory, 'installation.json'),
    async clearLogin() { this.cleared = true; }
  };
  const result = await install({
    config: { schemaVersion: 1, centralVm: 'api-1', vms: [{ name: 'api-1', address: '10.0.1.10', sshUser: 'ubuntu' }, { name: 'db-1', address: '10.0.1.11', sshUser: 'ubuntu' }] },
    login: { setupToken, deploymentId: `dpl_${'d'.repeat(32)}`, origin: 'https://app.example' }, store, remoteImpl,
    environment: { LOOKOUT_SSH_KNOWN_HOSTS: '/tmp/lookout-verified-known-hosts' },
    archiveImpl: () => Buffer.from('archive'), runImpl: (_binary, _args, options) => { states.push(options.environment); return '{"status":"installed"}\n'; },
    output: { write() {} }
  });
  assert.equal(result.status, 'complete');
  assert.equal(store.cleared, true);
  assert.equal(calls.some((call) => call.argv.some((arg) => arg.includes(setupToken))), false);
  assert.equal(calls.some((call) => String(call.input || '').includes(setupToken)), true);
  assert.equal(states[0].LOOKOUT_WORKSTATION, '1');
  assert.equal(states[0].LOOKOUT_CONSOLE_CREDENTIAL_REMOTE, undefined);
  assert.equal(states[1].LOOKOUT_ATTACH_CONSOLE, '1');
  assert.equal(states[1].LOOKOUT_CONSOLE_CREDENTIAL_REMOTE, '/var/lib/lookout-workstation-link/console-credential');
  assert.equal(states[0].LOOKOUT_SSH_KNOWN_HOSTS, '/tmp/lookout-verified-known-hosts');
  assert.equal(states[0].LOOKOUT_PREPARED_CENTRAL_VM, 'api-1');
  assert.match(states[0].LOOKOUT_PREPARED_CENTRAL_SOURCE, /^\/var\/tmp\/lookout-workstation-source-/);
  assert.equal(calls.some((call) => call.argv.join(' ') === 'install -d -m 700 /var/lib/lookout-workstation-link'), true);
  assert.equal(calls.some((call) => call.argv.some((arg) => arg.startsWith('/var/tmp/lookout-workstation-source-'))), true);
  const completed = JSON.parse(await fs.readFile(store.installationFile, 'utf8'));
  assert.equal(completed.status, 'complete');
});

test('workstation installs the fleet before browser login supplies a credential', async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-workstation-overlap-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  await writeDeploymentIdentity(directory);
  const deploymentId = `dpl_${'p'.repeat(32)}`;
  const setupToken = `lst_${'t'.repeat(43)}`;
  let fleetInstalled = false;
  const calls = [];
  const store = {
    directory, installationFile: path.join(directory, 'installation.json'),
    async loadPendingLogin() { return { deploymentId, expiresAt: new Date(Date.now() + 60000).toISOString() }; },
    async loadLogin() {
      assert.equal(fleetInstalled, true);
      return { setupToken, deploymentId, origin: 'https://app.example' };
    },
    async clearLogin() {}, async clearPendingLogin() {}
  };
  const remoteImpl = (_vm, argv, options = {}) => {
    calls.push({ argv, input: options.input });
    if (argv.includes('LOOKOUT_PROVISION_ONLY=1')) return '/usr/bin/node\n';
    if (argv.some((item) => String(item).includes('command -v node'))) return '/usr/bin/node\n';
    if (argv.includes('prepare')) return JSON.stringify({ deploymentId, consoleEndpoint: 'https://app.example/sync', credentialFile: '/var/lib/lookout-workstation-link/console-credential' });
    if (argv.includes('finish')) return JSON.stringify({ deploymentId, dashboardUrl: 'https://app.example/map' });
    return '';
  };
  const environments = [];
  await install({
    config: { schemaVersion: 1, centralVm: 'api-1', vms: [{ name: 'api-1', address: '10.0.1.10' }] },
    store, remoteImpl, archiveImpl: () => Buffer.from('archive'),
    runImpl: (_binary, _args, options) => {
      environments.push(options.environment);
      if (!options.environment.LOOKOUT_ATTACH_CONSOLE) {
        assert.equal(calls.some((call) => String(call.input || '').includes(setupToken)), false);
        fleetInstalled = true;
      }
      return '{}\n';
    },
    output: { write() {} }
  });
  assert.equal(environments[0].LOOKOUT_DEPLOYMENT_ID, deploymentId);
  assert.equal(environments[0].LOOKOUT_CONSOLE_ENDPOINT, undefined);
  assert.equal(environments[1].LOOKOUT_ATTACH_CONSOLE, '1');
  assert.equal(calls.some((call) => String(call.input || '').includes(setupToken)), true);
});

test('workstation retry retains the remote SaaS credential until all VMs complete', async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-workstation-retry-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const state = {
    schemaVersion: 1, status: 'installing', centralVm: 'api-1', deploymentId: `dpl_${'d'.repeat(32)}`,
    consoleEndpoint: `https://app.example/v1/console-sync/dpl_${'d'.repeat(32)}`,
    credentialFile: '/var/lib/lookout-workstation-link/console-credential',
    stage: '/var/tmp/lookout-workstation-source-test', remoteState: '/var/lib/lookout-workstation-link',
    remoteNode: '/usr/bin/node', origin: 'https://app.example',
    knownHostsFile: '/tmp/lookout-original-known-hosts'
  };
  let fleetEnvironment;
  const remoteImpl = (_vm, argv) => {
    if (argv.includes('finish')) return JSON.stringify({ deploymentId: state.deploymentId, dashboardUrl: 'https://app.example/map' });
    if (argv.some((item) => String(item).includes('nohup env LOOKOUT_SETUP_ORIGIN'))) return '4321\n';
    return '';
  };
  const store = { directory, installationFile: path.join(directory, 'installation.json'), async clearLogin() { this.cleared = true; } };
  const result = await resume({
    config: { schemaVersion: 1, centralVm: 'api-1', vms: [{ name: 'api-1', address: '10.0.1.10', sshUser: 'ubuntu' }] },
    state, store, remoteImpl,
    runImpl: (_binary, _args, options) => { fleetEnvironment = options.environment; return '{}\n'; },
    output: { write() {} }
  });
  assert.equal(result.status, 'complete');
  assert.equal(fleetEnvironment.LOOKOUT_CONSOLE_CREDENTIAL_REMOTE, state.credentialFile);
  assert.equal(fleetEnvironment.LOOKOUT_CONSOLE_ENDPOINT, state.consoleEndpoint);
  assert.equal(fleetEnvironment.LOOKOUT_SSH_KNOWN_HOSTS, state.knownHostsFile);
  assert.equal(fleetEnvironment.LOOKOUT_PREPARED_CENTRAL_SOURCE, state.stage);
  assert.equal(store.cleared, true);
});

test('workstation install reuses prepared central and fleet artifacts', async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-workstation-prepared-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  await writeDeploymentIdentity(directory);
  const config = { schemaVersion: 1, centralVm: 'api-1', vms: [{ name: 'api-1', address: '10.0.1.10' }] };
  const root = '/var/tmp/lookout-preflight-prepare-binding-1234';
  const now = new Date();
  const preparation = {
    schemaVersion: 1, scopeDigest: require('../src/cli/workstation-config').installationScopeDigest(config), releaseFingerprint: releaseFingerprint({}), centralVm: 'api-1',
    preparedAt: now.toISOString(), expiresAt: new Date(now.getTime() + 600000).toISOString(),
    nodes: [{ id: 'api-1', platform: 'linux', architecture: 'amd64', reachable: true, preparedArtifact: { root, source: `${root}/source` } }]
  };
  const calls = []; let fleetEnvironment;
  const remoteImpl = (_vm, argv) => {
    calls.push(argv);
    if (argv.some((item) => String(item).includes('command -v node'))) return '/usr/bin/node\n';
    if (argv.includes('prepare')) return JSON.stringify({ deploymentId: `dpl_${'d'.repeat(32)}`, consoleEndpoint: 'https://app.example/sync', credentialFile: '/var/lib/lookout-workstation-link/console-credential' });
    if (argv.includes('finish')) return JSON.stringify({ deploymentId: `dpl_${'d'.repeat(32)}`, dashboardUrl: 'https://app.example/map' });
    if (argv.some((item) => String(item).includes('nohup env LOOKOUT_SETUP_ORIGIN'))) return '1234\n';
    return '';
  };
  const store = { directory, preparationFile: path.join(directory, 'preparation.json'), installationFile: path.join(directory, 'installation.json'), async clearLogin() {}, async clearPreparation() {} };
  await install({ config, login: { setupToken: `lst_${'a'.repeat(43)}`, deploymentId: `dpl_${'d'.repeat(32)}`, origin: 'https://app.example' }, preparation, store, environment: {}, remoteImpl, runImpl: (_binary, _args, options) => { fleetEnvironment = options.environment; return '{}\n'; }, output: { write() {} } });
  assert.equal(calls.some((argv) => argv.includes('curl')), false);
  assert.equal(fleetEnvironment.LOOKOUT_PREPARED_FLEET_FILE, store.preparationFile);
  assert.equal(fleetEnvironment.LOOKOUT_PREPARED_CENTRAL_SOURCE, `${root}/source`);
});

test('workstation retry only finalizes after fleet installation already succeeded', async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-workstation-finalize-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const state = {
    schemaVersion: 1, status: 'finalizing', centralVm: 'api-1', deploymentId: `dpl_${'d'.repeat(32)}`,
    consoleEndpoint: `https://app.example/v1/console-sync/dpl_${'d'.repeat(32)}`,
    credentialFile: '/var/lib/lookout-workstation-link/console-credential',
    stage: '/var/tmp/lookout-workstation-source-test', remoteState: '/var/lib/lookout-workstation-link',
    remoteNode: '/usr/bin/node', origin: 'https://app.example'
  };
  let fleetRan = false;
  const result = await resume({
    config: { schemaVersion: 1, centralVm: 'api-1', vms: [{ name: 'api-1', address: '10.0.1.10', sshUser: 'ubuntu' }] },
    state, store: { directory, installationFile: path.join(directory, 'installation.json'), async clearLogin() {} },
    remoteImpl: (_vm, argv) => argv.includes('finish') ? JSON.stringify({ deploymentId: state.deploymentId, dashboardUrl: 'https://app.example/map' }) : '',
    runImpl: () => { fleetRan = true; return ''; }, output: { write() {} }
  });
  assert.equal(result.status, 'complete');
  assert.equal(fleetRan, false);
});

test('workstation install retains login permission when installation fails', async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-workstation-failure-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  await writeDeploymentIdentity(directory);
  const store = {
    directory, installationFile: path.join(directory, 'installation.json'),
    async clearLogin() { this.cleared = true; }
  };
  const remoteImpl = (_vm, argv) => {
    if (argv.includes('LOOKOUT_PROVISION_ONLY=1')) return '/usr/bin/node\n';
    if (argv.includes('prepare')) return JSON.stringify({ deploymentId: `dpl_${'d'.repeat(32)}`, consoleEndpoint: `https://app.example/v1/console-sync/dpl_${'d'.repeat(32)}`, credentialFile: '/var/lib/lookout-workstation-link/console-credential' });
    if (argv.some((item) => String(item).includes('nohup env LOOKOUT_SETUP_ORIGIN'))) return '1234\n';
    return '';
  };
  await assert.rejects(install({
    config: { schemaVersion: 1, centralVm: 'api-1', vms: [{ name: 'api-1', address: '10.0.1.10' }] },
    login: { setupToken: `lst_${'a'.repeat(43)}`, deploymentId: `dpl_${'d'.repeat(32)}`, origin: 'https://app.example' }, store, remoteImpl,
    archiveImpl: () => Buffer.from('archive'), runImpl: () => { throw new Error('fleet failed'); }, output: { write() {} }
  }), /fleet failed/);
  assert.notEqual(store.cleared, true);
  const retained = JSON.parse(await fs.readFile(store.installationFile, 'utf8'));
  assert.equal(retained.status, 'installing_local');
  assert.equal(retained.lastFailure.error, 'fleet failed');
});

test('workstation install saves retry state before its first central operation', async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-workstation-preflight-state-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const store = { directory, installationFile: path.join(directory, 'installation.json') };
  await assert.rejects(install({
    config: { schemaVersion: 1, centralVm: 'api-1', vms: [{ name: 'api-1', address: '10.0.1.10' }] },
    login: { setupToken: `lst_${'a'.repeat(43)}`, deploymentId: `dpl_${'d'.repeat(32)}`, origin: 'https://app.example' }, store,
    remoteImpl: () => { throw new Error('ssh unavailable'); }, output: { write() {} }
  }), /ssh unavailable/);
  const retained = JSON.parse(await fs.readFile(store.installationFile, 'utf8'));
  assert.equal(retained.status, 'preparing');
  assert.equal(retained.lastFailure.phase, 'linking');
});

test('central artifact download tolerates a bounded transient outage and remains retryable', async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-workstation-artifact-outage-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  await writeDeploymentIdentity(directory);
  const calls = [];
  const remoteImpl = (_vm, argv) => {
    calls.push(argv);
    if (argv[0] === 'uname') return 'x86_64\n';
    if (argv[0] === 'curl') throw new Error('curl: (22) The requested URL returned error: 503');
    return '';
  };
  const store = { directory, installationFile: path.join(directory, 'installation.json') };
  const targets = {
    amd64: { url: 'https://releases.example/amd64.tar.gz', sha256: 'a'.repeat(64) },
    arm64: { url: 'https://releases.example/arm64.tar.gz', sha256: 'b'.repeat(64) }
  };
  await assert.rejects(install({
    config: { schemaVersion: 1, centralVm: 'api-1', vms: [{ name: 'api-1', address: '10.0.1.10' }] },
    login: { setupToken: `lst_${'a'.repeat(43)}`, deploymentId: `dpl_${'d'.repeat(32)}`, origin: 'https://app.example' },
    store, remoteImpl, environment: { LOOKOUT_RELEASE_TARGETS: JSON.stringify(targets) }, output: { write() {} }
  }), /reinstall the Lookout CLI, then run lookout install --retry/);
  const download = calls.find((argv) => argv[0] === 'curl');
  assert.deepEqual(download.slice(download.indexOf('--retry'), download.indexOf('--output')), ['--retry', '8', '--retry-all-errors', '--retry-delay', '3', '--retry-max-time', '120']);
  const retained = JSON.parse(await fs.readFile(store.installationFile, 'utf8'));
  assert.equal(retained.status, 'preparing');
  assert.equal(retained.lastFailure.phase, 'artifact_download');
  assert.equal(installationRetryAction(retained, { retry: true }), 'restart');
});

test('workstation install removes exact remote inputs and staging after a pre-link failure', async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-workstation-cleanup-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  await writeDeploymentIdentity(directory);
  const calls = [];
  const remoteImpl = (_vm, argv) => {
    calls.push(argv);
    if (argv.includes('LOOKOUT_PROVISION_ONLY=1')) return '/usr/bin/node\n';
    if (argv.includes('/var/lib/lookout-workstation-link/scope.json') && argv[0] === 'install') throw new Error('scope copy failed');
    return '';
  };
  const store = { directory, installationFile: path.join(directory, 'installation.json') };
  await assert.rejects(install({
    config: { schemaVersion: 1, centralVm: 'api-1', vms: [{ name: 'api-1', address: '10.0.1.10' }] },
    login: { setupToken: `lst_${'a'.repeat(43)}`, deploymentId: `dpl_${'d'.repeat(32)}`, origin: 'https://app.example' }, store, remoteImpl,
    archiveImpl: () => Buffer.from('archive'), output: { write() {} }
  }), /scope copy failed/);
  assert.equal(calls.some((argv) => argv.join(' ') === 'rm -f /var/lib/lookout-workstation-link/setup-token /var/lib/lookout-workstation-link/scope.json /var/lib/lookout-workstation-link/deployment-identity.json'), true);
  const cleanup = calls.find((argv) => argv[0] === 'sh' && argv[1] === '-c' && argv[3] === 'lookout-workstation-cleanup');
  assert.ok(cleanup);
  assert.match(cleanup[4], /^\/var\/tmp\/lookout-workstation-source-[0-9a-f-]+$/);
});

test('workstation install preserves remote link state after it becomes retryable', async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-workstation-retryable-link-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  await writeDeploymentIdentity(directory);
  const deploymentId = `dpl_${'d'.repeat(32)}`;
  const calls = [];
  const remoteImpl = (_vm, argv) => {
    calls.push(argv);
    if (argv.includes('LOOKOUT_PROVISION_ONLY=1')) return '/usr/bin/node\n';
    if (argv.some((item) => String(item).includes('command -v node'))) return '/usr/bin/node\n';
    if (argv.includes('prepare')) throw new Error('link response interrupted');
    return '';
  };
  const store = { directory, installationFile: path.join(directory, 'installation.json') };
  await assert.rejects(install({
    config: { schemaVersion: 1, centralVm: 'api-1', vms: [{ name: 'api-1', address: '10.0.1.10' }] },
    login: { setupToken: `lst_${'a'.repeat(43)}`, deploymentId, origin: 'https://app.example' }, store, remoteImpl,
    archiveImpl: () => Buffer.from('archive'), runImpl: () => '{}\n', output: { write() {} }
  }), /link response interrupted/);
  assert.equal(calls.some((argv) => argv[0] === 'rm' && argv.includes('/var/lib/lookout-workstation-link/deployment-identity.json')), false);
  const retained = JSON.parse(await fs.readFile(store.installationFile, 'utf8'));
  assert.equal(retained.status, 'awaiting_login');
});

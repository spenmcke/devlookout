'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { buildFleetSurvey, chooseCentral, loadApprovedScope, stableDeploymentId, fleetConcurrency, runBounded, spawnProbeWorker, deploymentArchive, encryptSecretForPublicKey, leastPrivilegeAccess, assertApprovedLinuxAccess, sshCandidates, sshConnectionOptions, shouldRetrySshCandidate, probeFailureAction, awsArguments, freshUninstallSelected, preflightBeforeUninstall, reusableCentralArtifact, shouldRetireBootstrap, normalizeLinuxArchitecture, releaseForArchitecture, assertSupportedReleaseArchitectures } = require('../install/fleet');

test('approved scope is exact and requires the installer to run on its central VM', (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'lookout-scope-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const file = path.join(directory, 'scope.json');
  fs.writeFileSync(file, JSON.stringify({
    central_vm_id: 'aws:i-central',
    vms: [
      { id: 'aws:i-central', provider: 'aws', name: 'central', address: '10.0.0.10', platform: 'linux', local: true },
      { id: 'aws:i-collector', provider: 'aws', name: 'collector', address: '10.0.0.11', ssh_user: 'ubuntu', platform: 'linux' }
    ]
  }), { mode: 0o600 });
  const scope = loadApprovedScope(file);
  assert.equal(scope.centralVmId, 'aws:i-central');
  assert.deepEqual(scope.nodes.map((node) => node.id), ['aws:i-central', 'aws:i-collector']);
  assert.equal(chooseCentral(scope.nodes.map((node) => ({ ...node, reachable: true })), [], scope.centralVmId).id, 'aws:i-central');
  fs.writeFileSync(file, JSON.stringify({ central_vm_id: 'aws:i-other', vms: [{ id: 'aws:i-central', local: true }] }), { mode: 0o600 });
  assert.throws(() => loadApprovedScope(file), /outside the approved VM list/);
});

test('fleet orchestration may select a remote central VM without a local target', (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'lookout-remote-scope-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const file = path.join(directory, 'scope.json');
  fs.writeFileSync(file, JSON.stringify({
    central_vm_id: 'aws:i-central',
    vms: [
      { id: 'aws:i-central', provider: 'aws', name: 'central', instance_id: 'i-central', zone: 'us-west-2a', address: '10.0.0.10', platform: 'linux', local: false },
      { id: 'gcp:collector', provider: 'gcp', name: 'collector', instance_id: 'collector', zone: 'us-central1-a', address: '10.1.0.11', platform: 'linux', local: false }
    ]
  }), { mode: 0o600 });
  const scope = loadApprovedScope(file);
  assert.equal(scope.nodes.some((node) => node.local), false);
  assert.equal(chooseCentral(scope.nodes.map((node) => ({ ...node, reachable: true })), [], scope.centralVmId).id, 'aws:i-central');
});

test('workstation scope keeps every managed VM remote and preserves configured SSH users', (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'lookout-workstation-scope-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const file = path.join(directory, 'scope.json');
  fs.writeFileSync(file, JSON.stringify({
    central_vm_id: 'api-1',
    vms: [
      { id: 'api-1', address: '10.0.0.10', ssh_user: 'ubuntu', platform: 'linux', local: false },
      { id: 'db-1', address: 'db.internal', ssh_user: 'debian', platform: 'linux', local: false }
    ]
  }), { mode: 0o600 });
  const scope = loadApprovedScope(file, { workstation: true });
  assert.equal(scope.centralVmId, 'api-1');
  assert.equal(scope.nodes.every((node) => node.local === false), true);
  assert.deepEqual(scope.nodes.map((node) => node.sshUser), ['ubuntu', 'debian']);
});

test('fresh reinstall cleans every selected VM and stops before install when cleanup fails', async () => {
  const nodes = [{ id: 'aws:a' }, { id: 'gcp:b' }];
  const cleaned = [];
  assert.deepEqual(await freshUninstallSelected(nodes, async (node) => {
    cleaned.push(node.id);
    return { nodeId: node.id, cleaned: node.id === 'aws:a' };
  }), [{ nodeId: 'aws:a', cleaned: true }, { nodeId: 'gcp:b', cleaned: false }]);
  assert.deepEqual(cleaned, ['aws:a', 'gcp:b']);
  await assert.rejects(
    freshUninstallSelected(nodes, async (node) => {
      if (node.id === 'gcp:b') throw new Error('fixture cleanup failed');
      return { nodeId: node.id, cleaned: true };
    }),
    /Fresh reinstall cleanup failed: gcp:b: fixture cleanup failed/
  );
});

test('release preflight must finish before any existing installation is removed', async () => {
  let uninstallCalls = 0;
  await assert.rejects(
    preflightBeforeUninstall(async () => { throw new Error('invalid release fixture'); }, async () => { uninstallCalls += 1; }),
    /invalid release fixture/
  );
  assert.equal(uninstallCalls, 0);
  const result = await preflightBeforeUninstall(async () => 'prepared', async () => { uninstallCalls += 1; return 'cleaned'; });
  assert.deepEqual(result, { prepared: 'prepared', cleanup: 'cleaned' });
  assert.equal(uninstallCalls, 1);
});

test('workstation fleet reuses only its verified central release', () => {
  const calls = [];
  const central = { id: 'central-1' };
  const sourceDirectory = '/var/tmp/lookout-workstation-source-12345678/source';
  assert.deepEqual(reusableCentralArtifact(central, {
    workstation: true, vm: central.id, sourceDirectory,
    remoteImpl: (_node, argv) => calls.push(argv)
  }), { root: null, source: sourceDirectory });
  assert.equal(calls.length, 1);
  assert.equal(reusableCentralArtifact(central, { workstation: true, vm: null, sourceDirectory: null }), null);
  assert.equal(reusableCentralArtifact(central, { workstation: true, vm: central.id, sourceDirectory, remoteImpl() { throw new Error('missing'); } }), null);
  assert.deepEqual(reusableCentralArtifact(central, { workstation: true, vm: central.id, sourceDirectory: '/var/tmp/lookout-preflight-prepare-binding-1234/source', remoteImpl() {} }), { root: null, source: '/var/tmp/lookout-preflight-prepare-binding-1234/source' });
  assert.throws(() => reusableCentralArtifact(central, { workstation: true, vm: 'other', sourceDirectory, remoteImpl() {} }), /metadata is invalid/);
  assert.throws(() => reusableCentralArtifact(central, { workstation: true, vm: central.id, sourceDirectory: '/tmp/unverified', remoteImpl() {} }), /metadata is invalid/);
});

test('bootstrap access is retained until every selected deployment succeeds', () => {
  const nodes = [{ id: 'central', platform: 'linux', reachable: true }, { id: 'collector', platform: 'linux', reachable: true }];
  assert.equal(shouldRetireBootstrap([], nodes), true);
  assert.equal(shouldRetireBootstrap([{ assetId: 'collector', status: 'deployment-failed' }], nodes), false);
  assert.equal(shouldRetireBootstrap([], [{ ...nodes[0], reachable: false }]), false);
});

test('approved scope may omit central VM and selects one deterministically after access checks', (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'lookout-automatic-central-scope-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const file = path.join(directory, 'scope.json');
  fs.writeFileSync(file, JSON.stringify({
    vms: [
      { id: 'gcp:z', provider: 'gcp', address: '10.1.0.12', platform: 'linux' },
      { id: 'aws:a', provider: 'aws', address: '10.0.0.10', platform: 'linux' }
    ]
  }), { mode: 0o600 });
  const scope = loadApprovedScope(file);
  assert.equal(scope.centralVmId, null);
  assert.equal(chooseCentral(scope.nodes.map((node) => ({ ...node, reachable: true })), [], scope.centralVmId).id, 'aws:a');
});

test('approved scope preserves public address and AWS profile for local access tools', (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'lookout-access-scope-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const file = path.join(directory, 'scope.json');
  fs.writeFileSync(file, JSON.stringify({
    central_vm_id: 'aws:i-central',
    vms: [{ id: 'aws:i-central', provider: 'aws', instance_id: 'i-central', region: 'us-west-2', zone: 'us-west-2a', address: '10.0.0.10', public_address: '203.0.113.10', aws_profile: 'production', platform: 'linux' }]
  }), { mode: 0o600 });
  const node = loadApprovedScope(file).nodes[0];
  assert.equal(node.publicAddress, '203.0.113.10');
  assert.equal(node.awsProfile, 'production');
  assert.deepEqual(sshCandidates(node, '/tmp/bootstrap-key'), [
    { address: '203.0.113.10', identityMode: 'existing' },
    { address: '203.0.113.10', identityMode: 'bootstrap' },
    { address: '10.0.0.10', identityMode: 'existing' },
    { address: '10.0.0.10', identityMode: 'bootstrap' }
  ]);
  assert.deepEqual(awsArguments(['ssm', 'send-command'], { region: node.region, profile: node.awsProfile }), ['ssm', 'send-command', '--region', 'us-west-2', '--profile', 'production']);
});

test('OpenSSH connections fail fast when a saved management address is stale', () => {
  assert.deepEqual(sshConnectionOptions, [
    '-o', 'ConnectTimeout=5',
    '-o', 'ConnectionAttempts=1',
    '-o', 'ServerAliveInterval=5',
    '-o', 'ServerAliveCountMax=1'
  ]);
});

test('OpenSSH retries connection failures but preserves remote command failures', () => {
  for (const failureKind of ['timeout', 'transport', 'identity', 'authentication']) {
    assert.equal(shouldRetrySshCandidate({ failureKind }), true);
  }
  assert.equal(shouldRetrySshCandidate(new Error('remote command exited nonzero')), false);
});

test('access probes preserve local OpenSSH errors instead of reporting missing VM access', () => {
  const error = new Error('ControlPath too long (>= 104 bytes)');
  assert.throws(() => probeFailureAction(error), /ControlPath too long/);
  assert.equal(probeFailureAction({ failureKind: 'authentication' }), 'continue');
  assert.equal(probeFailureAction({ code: 'LOOKOUT_NEEDS_ACCESS' }), 'needs-access');
});

test('fleet central choice is deterministic and limited to reachable Linux nodes', () => {
  const nodes = [
    { id: 'provider:z', platform: 'linux', reachable: true },
    { id: 'provider:a', platform: 'macos', reachable: true },
    { id: 'provider:b', platform: 'linux', reachable: false },
    { id: 'provider:c', platform: 'linux', reachable: true }
  ];
  assert.equal(chooseCentral(nodes).id, 'provider:c');
  assert.equal(chooseCentral(nodes.reverse()).id, 'provider:c');
  assert.equal(stableDeploymentId(nodes), stableDeploymentId([...nodes].reverse()));
  const local = { id: 'provider:z-local', platform: 'linux', reachable: true, local: true };
  assert.equal(chooseCentral([...nodes, local]), local);
});

test('fleet survey emits network and endpoint topology without exposing Lookout infrastructure', () => {
  const nodes = [
    { id: 'tailscale:central', hostname: 'central', address: '100.64.0.1', platform: 'linux', reachable: true, transport: 'tailscale' },
    { id: 'tailscale:collector', hostname: 'collector', address: '100.64.0.2', platform: 'linux', reachable: true, transport: 'tailscale' },
    { id: 'tailscale:phone', hostname: 'phone', address: '100.64.0.3', platform: 'ios', reachable: false, transport: 'tailscale' },
    { id: 'tailscale:laptop', hostname: 'laptop', address: '100.64.0.4', platform: 'macos', reachable: false, transport: 'tailscale' }
  ];
  const survey = buildFleetSurvey(nodes, nodes[0], 'fleet-test');
  assert.equal(survey.entities.filter((item) => item.type === 'network').length, 1);
  assert.equal(survey.entities.filter((item) => item.type === 'endpoint').length, 4);
  assert.equal(survey.entities.filter((item) => item.type === 'service').length, 0);
  assert.equal(survey.relationships.filter((item) => item.relation === 'member_of').length, 4);
  assert.equal(survey.relationships.filter((item) => item.relation === 'runs').length, 0);
  assert.ok(!survey.entities.some((item) => item.key === 'service:lookout' || item.key.includes('lookout-collector')));
  for (const edge of survey.relationships) {
    assert.ok(survey.entities.some((item) => item.key === edge.from));
    assert.ok(survey.entities.some((item) => item.key === edge.to));
  }
});

test('fleet reuses one existing central and rejects split brain', () => {
  const first = { id: 'provider:a', platform: 'linux', reachable: true };
  const second = { id: 'provider:b', platform: 'linux', reachable: true };
  assert.equal(chooseCentral([first, second], [second]), second);
  assert.throws(() => chooseCentral([first, second], [first, second]), /Multiple existing/);
  assert.throws(() => chooseCentral([{ id: 'x', platform: 'windows', reachable: true }]), /No reachable supported Linux/);
});

test('fleet collector concurrency is bounded and configurable', () => {
  const previous = process.env.LOOKOUT_FLEET_CONCURRENCY;
  try {
    delete process.env.LOOKOUT_FLEET_CONCURRENCY;
    assert.equal(fleetConcurrency(0), 0);
    assert.equal(fleetConcurrency(2), 2);
    assert.equal(fleetConcurrency(12), 8);
    process.env.LOOKOUT_FLEET_CONCURRENCY = '6';
    assert.equal(fleetConcurrency(12), 6);
    assert.equal(fleetConcurrency(3), 3);
    process.env.LOOKOUT_FLEET_CONCURRENCY = '0';
    assert.throws(() => fleetConcurrency(3), /between 1 and 16/);
  } finally {
    if (previous === undefined) delete process.env.LOOKOUT_FLEET_CONCURRENCY;
    else process.env.LOOKOUT_FLEET_CONCURRENCY = previous;
  }
});

test('fleet access probes run in isolated workers and preserve a reachable local Linux result', async () => {
  const node = await spawnProbeWorker({ id: 'local:test', hostname: 'test', platform: 'linux', local: true, online: true, transport: 'local' });
  assert.equal(node.id, 'local:test');
  assert.equal(node.reachable, true);
});

test('pinned direct distribution skips local release repackaging', () => {
  const archive = deploymentArchive({ url: 'https://releases.example/lookout.tar.gz', sha256: 'a'.repeat(64) });
  assert.equal(archive.length, 0);
  assert.throws(() => deploymentArchive({ url: 'https://releases.example/lookout.tar.gz', sha256: 'invalid' }), /SHA-256 is required/);
});

test('pinned target distribution selects each Linux architecture independently', () => {
  const targets = {
    amd64: { url: 'https://releases.example/amd64.tar.gz', sha256: 'a'.repeat(64) },
    arm64: { url: 'https://releases.example/arm64.tar.gz', sha256: 'b'.repeat(64) }
  };
  assert.equal(normalizeLinuxArchitecture('x86_64'), 'amd64');
  assert.equal(normalizeLinuxArchitecture('aarch64'), 'arm64');
  assert.equal(releaseForArchitecture('x86_64', { targets }).url, targets.amd64.url);
  assert.equal(releaseForArchitecture('arm64', { targets }).url, targets.arm64.url);
  assert.doesNotThrow(() => assertSupportedReleaseArchitectures([
    { id: 'one', platform: 'linux', reachable: true, architecture: 'amd64' },
    { id: 'two', platform: 'linux', reachable: true, architecture: 'arm64' }
  ], targets));
  assert.throws(() => assertSupportedReleaseArchitectures([
    { id: 'three', platform: 'linux', reachable: true, architecture: null }
  ], targets), /before release download.*three/);
});

test('provider-native secret transfer exposes only RSA-OAEP ciphertext to command transport', () => {
  const keys = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const secret = Buffer.from('short-lived-console-credential');
  const encrypted = encryptSecretForPublicKey(keys.publicKey, secret);
  assert.notEqual(encrypted.includes(secret), true);
  const decrypted = crypto.privateDecrypt({ key: keys.privateKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, encrypted);
  assert.deepEqual(decrypted, secret);
  assert.throws(() => encryptSecretForPublicKey(keys.publicKey, Buffer.alloc(191)), /too large/);
});

test('bounded fleet work runs concurrently, preserves result order, and isolates failures', async () => {
  let active = 0;
  let maximumActive = 0;
  const results = await runBounded([40, 10, 25, 5], 2, async (delay, index) => {
    active += 1;
    maximumActive = Math.max(maximumActive, active);
    await new Promise((resolve) => setTimeout(resolve, delay));
    active -= 1;
    if (index === 2) throw new Error('expected failure');
    return `node-${index}`;
  });
  assert.equal(maximumActive, 2);
  assert.deepEqual(results.map((result) => result.status), ['fulfilled', 'fulfilled', 'rejected', 'fulfilled']);
  assert.equal(results[0].value, 'node-0');
  assert.match(results[2].reason.message, /expected failure/);
  assert.equal(results[3].value, 'node-3');
});

test('fleet refuses partial installation when an approved Linux VM lacks administrative access', () => {
  const nodes = [
    { id: 'provider:central', hostname: 'central', platform: 'linux', reachable: true },
    { id: 'provider:collector', hostname: 'collector', platform: 'linux', reachable: false },
    { id: 'provider:laptop', hostname: 'laptop', platform: 'macos', reachable: false }
  ];
  assert.throws(() => assertApprovedLinuxAccess(nodes), /Needs access: provider:collector.*temporary Lookout SSH public key/);
  assert.doesNotThrow(() => assertApprovedLinuxAccess(nodes.filter((node) => node.id !== 'provider:collector')));
  assert.match(leastPrivilegeAccess({ provider: 'aws', instanceId: 'i-123' }), /ssm:SendCommand.*i-123/);
});

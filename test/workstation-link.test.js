'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { keepalive, prepare, ensurePrivateStateDirectory } = require('../install/workstation-link');

test('workstation link repairs an existing state directory to mode 0700', async (t) => {
  const parent = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-link-mode-'));
  t.after(() => fs.rm(parent, { recursive: true, force: true }));
  const directory = path.join(parent, 'state');
  await fs.mkdir(directory, { mode: 0o755 });
  assert.equal(await ensurePrivateStateDirectory(directory), directory);
  if (process.platform !== 'win32') assert.equal((await fs.lstat(directory)).mode & 0o777, 0o700);
});

test('central keepalive renews the proved setup session during fleet installation', async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-link-keepalive-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  await fs.writeFile(path.join(directory, 'link.json'), JSON.stringify({
    schemaVersion: 1, sessionId: 'set_abcdefghijklmnopqrstuvwx', sessionToken: 'session-token',
    deploymentId: `dpl_${'d'.repeat(32)}`, consoleEndpoint: `https://app.example/v1/console-sync/dpl_${'d'.repeat(32)}`,
    credentialFile: path.join(directory, 'console-credential'), dashboardUrl: 'https://app.example/map'
  }), { mode: 0o600 });
  const phases = [];
  const result = await keepalive({
    stateDirectory: directory, attempts: 2, intervalMs: 1,
    client: { reportPhase: async (value) => phases.push(value) }
  });
  assert.equal(result.stopped, false);
  assert.deepEqual(phases.map((item) => item.phase), ['deploying', 'deploying']);
  assert.equal(phases[0].sessionToken, 'session-token');
});

test('workstation link resumes from durable link state after its response is interrupted', async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-link-resume-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  await fs.writeFile(path.join(directory, 'deployment-identity.json'), JSON.stringify({
    schemaVersion: 1, createdAt: new Date().toISOString(),
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }),
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' })
  }), { mode: 0o600 });
  const scope = { central_vm_id: 'api-1', vms: [{ id: 'api-1', name: 'api-1', address: '10.0.0.1', platform: 'linux', provider: 'openssh', local: false }] };
  const writeInputs = async () => {
    await fs.writeFile(path.join(directory, 'setup-token'), `lst_${'a'.repeat(43)}\n`, { mode: 0o600 });
    await fs.writeFile(path.join(directory, 'scope.json'), `${JSON.stringify(scope)}\n`, { mode: 0o600 });
  };
  let claims = 0; let proofs = 0; let phases = 0;
  const client = {
    async claimSession() { claims += 1; return { sessionId: 'set_abcdefghijklmnopqrstuvwx', sessionToken: 's'.repeat(32), challenge: 'c'.repeat(32), deploymentId: `dpl_${'d'.repeat(32)}` }; },
    async proveSession() { proofs += 1; return { provisioning: { consoleSync: { endpoint: `https://app.example/v1/console-sync/dpl_${'d'.repeat(32)}`, credential: 'credential-value' }, dashboardUrl: 'https://app.example/map' } }; },
    async reportPhase() { phases += 1; if (phases === 1) throw new Error('response interrupted'); }
  };
  await writeInputs();
  await assert.rejects(prepare({ tokenFile: path.join(directory, 'setup-token'), scopeFile: path.join(directory, 'scope.json'), stateDirectory: directory, client }), /response interrupted/);
  await writeInputs();
  const result = await prepare({ tokenFile: path.join(directory, 'setup-token'), scopeFile: path.join(directory, 'scope.json'), stateDirectory: directory, client });
  assert.equal(result.deploymentId, `dpl_${'d'.repeat(32)}`);
  assert.equal(claims, 1);
  assert.equal(proofs, 1);
  assert.equal(phases, 2);
  await assert.rejects(fs.access(path.join(directory, 'setup-token')), { code: 'ENOENT' });
  await assert.rejects(fs.access(path.join(directory, 'scope.json')), { code: 'ENOENT' });
  await assert.rejects(fs.access(path.join(directory, 'claim.json')), { code: 'ENOENT' });
});

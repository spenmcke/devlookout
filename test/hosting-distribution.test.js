'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const net = require('node:net');
const { spawn } = require('node:child_process');
const { once } = require('node:events');

const repository = path.resolve(__dirname, '..');

async function availablePort() {
  const server = net.createServer();
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const { port } = server.address();
  server.close();
  await once(server, 'close');
  return port;
}

test('hosting publishes separate immutable orchestration and Linux target artifacts with both bootstraps', async (t) => {
  const temporary = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-distribution-'));
  t.after(() => fs.rm(temporary, { recursive: true, force: true }));
  const artifacts = path.join(temporary, 'artifacts');
  const data = path.join(temporary, 'data');
  await fs.mkdir(artifacts);
  const fixtures = [
    ['lookout-orchestration-v0.1.0.tar.gz', 'mac-orchestration'],
    ['lookout-orchestration-v0.1.0.zip', 'windows-orchestration'],
    ['lookout-target-linux-amd64-v0.1.0.tar.gz', 'linux-target-amd64'],
    ['lookout-target-linux-arm64-v0.1.0.tar.gz', 'linux-target-arm64']
  ];
  const digests = {};
  for (const [name, contents] of fixtures) {
    const bytes = Buffer.from(contents);
    const digest = crypto.createHash('sha256').update(bytes).digest('hex');
    digests[name] = digest;
    await fs.writeFile(path.join(artifacts, name), bytes);
    await fs.writeFile(path.join(artifacts, `${name}.sha256`), `${digest}\n`);
  }
  const port = await availablePort();
  const child = spawn(process.execPath, ['hosting/distribution-server.js'], {
    cwd: repository,
    env: {
      ...process.env,
      PORT: String(port),
      PUBLIC_BASE_URL: `https://127.0.0.1:${port}`,
      LOOKOUT_ARTIFACT_ROOT: artifacts,
      LOOKOUT_HOSTING_DATA_DIR: data,
      LOOKOUT_MASTER_KEY: '00'.repeat(32),
      LOOKOUT_SUPABASE_URL: 'https://supabase.example.test',
      LOOKOUT_SUPABASE_PUBLISHABLE_KEY: 'p'.repeat(32)
    },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  t.after(() => { if (child.exitCode === null) child.kill('SIGTERM'); });
  let output = '';
  child.stdout.on('data', (chunk) => { output += chunk; });
  child.stderr.on('data', (chunk) => { output += chunk; });
  for (let attempt = 0; attempt < 100 && !output.includes('distribution listening'); attempt += 1) await new Promise((resolve) => setTimeout(resolve, 20));
  assert.match(output, /distribution listening/, output);
  const origin = `http://127.0.0.1:${port}`;
  const health = await fetch(`${origin}/health`).then((response) => response.json());
  assert.equal(health.status, 'ok');
  assert.deepEqual(health.features.support_ai, { configured: false, single_replica: false });
  assert.deepEqual(health.artifacts, {
    orchestration_tar_sha256: digests['lookout-orchestration-v0.1.0.tar.gz'],
    orchestration_zip_sha256: digests['lookout-orchestration-v0.1.0.zip'],
    linux_target_amd64_sha256: digests['lookout-target-linux-amd64-v0.1.0.tar.gz'],
    linux_target_arm64_sha256: digests['lookout-target-linux-arm64-v0.1.0.tar.gz']
  });
  const shell = await fetch(`${origin}/install.sh`).then((response) => response.text());
  const powershell = await fetch(`${origin}/install.ps1`).then((response) => response.text());
  const cliShell = await fetch(`${origin}/cli/install.sh`).then((response) => response.text());
  const cliPowershell = await fetch(`${origin}/cli/install.ps1`).then((response) => response.text());
  assert.match(shell, new RegExp(digests['lookout-orchestration-v0.1.0.tar.gz']));
  assert.match(powershell, new RegExp(digests['lookout-orchestration-v0.1.0.zip']));
  assert.match(shell, new RegExp(digests['lookout-target-linux-amd64-v0.1.0.tar.gz']));
  assert.match(powershell, new RegExp(digests['lookout-target-linux-amd64-v0.1.0.tar.gz']));
  assert.match(cliShell, new RegExp(digests['lookout-orchestration-v0.1.0.tar.gz']));
  assert.match(cliPowershell, new RegExp(digests['lookout-orchestration-v0.1.0.zip']));
  for (const architecture of ['amd64', 'arm64']) {
    assert.match(cliShell, new RegExp(digests[`lookout-target-linux-${architecture}-v0.1.0.tar.gz`]));
    assert.match(cliPowershell, new RegExp(digests[`lookout-target-linux-${architecture}-v0.1.0.tar.gz`]));
  }
  for (const [name] of fixtures) {
    const digest = digests[name];
    const response = await fetch(`${origin}/releases/v0.1.0/${digest}/${name}`);
    assert.equal(response.status, 200);
    assert.equal(response.headers.get('cache-control'), 'public, max-age=31536000, immutable');
    assert.equal(response.headers.get('etag'), `"sha256-${digest}"`);
  }
});

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { generateCollectorKeyPair, verifyEnvelope } = require('../src/collector/envelope');

test('collector-run submits periodic observations and shuts down cleanly', { timeout: 15000 }, async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-collector-run-'));
  const identity = path.join(root, 'identity');
  const data = path.join(root, 'data');
  await fs.mkdir(identity, { mode: 0o700 });
  await fs.mkdir(data, { mode: 0o700 });
  const keys = generateCollectorKeyPair();
  await fs.writeFile(path.join(identity, 'collector-private.pem'), keys.privateKeyPem, { mode: 0o600 });
  await fs.writeFile(path.join(identity, 'collector.json'), JSON.stringify({ schemaVersion: 1, collectorId: keys.collectorId }), { mode: 0o600 });

  let received;
  const server = http.createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    received = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    response.writeHead(200, { 'Content-Type': 'application/json' });
    response.end('{"accepted":true}');
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  const child = spawn(process.execPath, [path.join(__dirname, '../bin/lookout.js'), 'collector-run', identity, `http://127.0.0.1:${address.port}`], {
    env: { ...process.env, LOOKOUT_CONFIG: '', LOOKOUT_DATA_DIR: data, LOOKOUT_REQUIRE_ENCRYPTION: 'false', LOOKOUT_MASTER_KEY: '', LOOKOUT_MASTER_KEY_FILE: '', LOOKOUT_API_TOKEN: '', LOOKOUT_API_TOKEN_FILE: '' },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  let output = '';
  let errors = '';
  child.stdout.setEncoding('utf8');
  child.stderr.setEncoding('utf8');
  child.stdout.on('data', (chunk) => { output += chunk; });
  child.stderr.on('data', (chunk) => { errors += chunk; });
  try {
    for (let attempt = 0; attempt < 200 && !received; attempt += 1) await new Promise((resolve) => setTimeout(resolve, 25));
    assert.ok(received, `collector did not submit (exit=${child.exitCode}, signal=${child.signalCode}, stdout=${output}): ${errors}`);
    const payload = verifyEnvelope(received, keys.publicKeyPem);
    assert.equal(payload.collectorId, keys.collectorId);
    assert.ok(payload.facts.some((fact) => fact.kind === 'entity'));
    assert.ok(payload.events.some((event) => event.activity === 'heartbeat'));
    assert.match(output, /"status":"running"/);
    assert.equal(JSON.parse(output.trim()).releaseVersion, `v${require('../package.json').version}`);
    child.kill('SIGTERM');
    const exit = await new Promise((resolve) => child.once('exit', (code, signal) => resolve({ code, signal })));
    assert.deepEqual(exit, { code: 0, signal: null });
  } finally {
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    await new Promise((resolve) => server.close(resolve));
    await fs.rm(root, { recursive: true, force: true });
  }
});

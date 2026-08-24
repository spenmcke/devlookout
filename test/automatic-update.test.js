'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const http = require('node:http');
const { once } = require('node:events');
const { signManifest, verifyManifest } = require('../src/update/manifest');
const { createUpdateChannelHttp } = require('../src/update/http');
const { SupabaseUpdateChannelStore } = require('../src/update/supabase-channel-store');
const { updateOnce, validateRollingCompatibility, installPreparedRelease } = require('../scripts/lookout-update');

test('both updater installers create and safely expose the private systemd runtime directory', () => {
  for (const relative of ['install/install.sh', 'install/seed-updater.sh']) {
    const source = fs.readFileSync(path.resolve(__dirname, '..', relative), 'utf8');
    assert.match(source, /^RuntimeDirectory=lookout-update$/m, relative);
    assert.match(source, /^RuntimeDirectoryMode=0700$/m, relative);
    assert.match(source, /^Environment=LOOKOUT_UPDATE_LOCK=\/run\/lookout-update\/update\.lock$/m, relative);
    assert.match(source, /^ReadWritePaths=.* -\/run\/lookout-update["']?$/m, relative);
    assert.match(source, /^OnActiveSec=1min$/m, relative);
    assert.doesNotMatch(source, /^OnBootSec=/m, relative);
    assert.doesNotMatch(source, /\/run\/lookout-update\.lock/, relative);
  }
});

test('CLI publication signs verified hosted artifacts on a separate channel', () => {
  const source = fs.readFileSync(path.resolve(__dirname, '../.github/workflows/publish-cli-update.yml'), 'utf8');
  assert.match(source, /HOSTED_ORIGIN: https:\/\/app\.devlookout\.com/);
  assert.match(source, /Number\.isSafeInteger\(value\)/);
  assert.match(source, /test "\$\(sha256sum "\$file" \| awk '\{print \$1\}'\)" = "\$digest"/);
  assert.match(source, /artifact_base="https:\/\/app\.devlookout\.com\/releases\/\$release_tag"/);
  assert.match(source, /channel:"cli-stable"/);
  assert.match(source, /rollback/);
  assert.match(source, /action:"pause"/);
});

function keys() {
  const pair = crypto.generateKeyPairSync('ed25519');
  return {
    keyId: 'test-key',
    privateKeyPem: pair.privateKey.export({ type: 'pkcs8', format: 'pem' }),
    publicKeySpkiPem: pair.publicKey.export({ type: 'spki', format: 'pem' })
  };
}

function payload(overrides = {}) {
  return { schemaVersion: 1, channel: 'stable', sequence: 1, action: 'pause', release: 'v1.2.3', publishedAt: '2026-08-22T12:00:00.000Z', ...overrides };
}

function jsonResponse(value, { status = 200, headers = {} } = {}) {
  const body = Buffer.from(JSON.stringify(value));
  return new Response(body, { status, headers: { 'content-type': 'application/json', 'content-length': String(body.length), ...headers } });
}

test('signed manifests reject tampering and unknown keys', () => {
  const key = keys();
  const envelope = signManifest(payload(), key);
  assert.equal(verifyManifest(envelope, [{ keyId: key.keyId, publicKeySpkiPem: key.publicKeySpkiPem }]).sequence, 1);
  assert.throws(() => verifyManifest({ ...envelope, payload: { ...envelope.payload, sequence: 2 } }, [{ keyId: key.keyId, publicKeySpkiPem: key.publicKeySpkiPem }]), /signature/);
  assert.throws(() => verifyManifest(envelope, [{ keyId: 'different', publicKeySpkiPem: key.publicKeySpkiPem }]), /not trusted/);
  assert.throws(() => verifyManifest(envelope, [{ keyId: key.keyId, publicKeySpkiPem: key.publicKeySpkiPem }], { channel: 'cli-stable' }), /channel/);
});

test('updater records signed pause, ETag, public status, and rejects replay equivocation', async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'lookout-update-state-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const key = keys();
  const configFile = path.join(directory, 'update.json');
  const stateFile = path.join(directory, 'state.json');
  const lockFile = path.join(directory, 'update.lock');
  const statusFile = path.join(directory, 'status.json');
  fs.writeFileSync(configFile, JSON.stringify({ schemaVersion: 1, channelUrl: 'https://updates.example.test/stable', artifactOrigins: ['https://github.com'], trustedKeys: [{ keyId: key.keyId, publicKeySpkiPem: key.publicKeySpkiPem }] }));
  const first = signManifest(payload(), key);
  const result = await updateOnce({ configFile, stateFile, lockFile, statusFile, allowNonRoot: true, fetchImpl: async () => jsonResponse(first, { headers: { etag: '"one"' } }) });
  assert.equal(result.status, 'paused');
  assert.equal(JSON.parse(fs.readFileSync(stateFile)).highestSequence, 1);
  assert.equal(JSON.parse(fs.readFileSync(statusFile)).sequence, 1);
  const conflicting = signManifest(payload({ release: 'v1.2.4' }), key);
  await assert.rejects(updateOnce({ configFile, stateFile, lockFile, statusFile, allowNonRoot: true, fetchImpl: async () => jsonResponse(conflicting) }), /replay or equivocation/);
  assert.equal(JSON.parse(fs.readFileSync(statusFile)).status, 'failed');
});

test('stable update endpoint supports HEAD and conditional ETags', async (t) => {
  const key = keys();
  const manifest = signManifest(payload(), key);
  const handler = createUpdateChannelHttp({ store: { get: async () => manifest } });
  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, 'https://updates.example.test');
    if (!await handler(req, res, url)) res.writeHead(404).end();
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => server.close());
  const origin = `http://127.0.0.1:${server.address().port}`;
  const first = await fetch(`${origin}/v1/updates/stable`);
  assert.equal(first.status, 200);
  assert.deepEqual(await first.json(), manifest);
  const etag = first.headers.get('etag');
  assert.match(etag, /^"sha256-[a-f0-9]{64}"$/);
  const conditional = await fetch(`${origin}/v1/updates/stable`, { headers: { 'If-None-Match': etag } });
  assert.equal(conditional.status, 304);
  const head = await fetch(`${origin}/v1/updates/stable`, { method: 'HEAD' });
  assert.equal(head.status, 200);
  assert.equal(await head.text(), '');
});

test('CLI update endpoint reads the isolated signed channel', async () => {
  const key = keys();
  const manifest = signManifest(payload({ channel: 'cli-stable' }), key);
  let requested = null;
  const handler = createUpdateChannelHttp({ store: { get: async (channel) => { requested = channel; return manifest; } } });
  const response = { writeHead(status) { this.status = status; return this; }, end() {} };
  assert.equal(await handler({ method: 'HEAD', headers: {} }, response, new URL('https://updates.example.test/v1/updates/cli-stable')), true);
  assert.equal(response.status, 200);
  assert.equal(requested, 'cli-stable');
});

test('hosted channel store validates signatures and caches bounded Supabase responses', async () => {
  const key = keys();
  const manifest = signManifest(payload(), key);
  let requests = 0;
  const store = new SupabaseUpdateChannelStore({
    supabaseUrl: 'https://supabase.example.test', serviceKey: 's'.repeat(32),
    trustedKeys: [{ keyId: key.keyId, publicKeySpkiPem: key.publicKeySpkiPem }],
    fetchImpl: async () => { requests += 1; return jsonResponse([{ manifest }]); }
  });
  assert.deepEqual(await store.get(), manifest);
  assert.deepEqual(await store.get(), manifest);
  assert.equal(requests, 1);
  const invalid = new SupabaseUpdateChannelStore({
    supabaseUrl: 'https://supabase.example.test', serviceKey: 's'.repeat(32),
    trustedKeys: [{ keyId: key.keyId, publicKeySpkiPem: key.publicKeySpkiPem }],
    fetchImpl: async () => jsonResponse([{ manifest: { ...manifest, payload: { ...manifest.payload, sequence: 2 } } }])
  });
  await assert.rejects(invalid.get(), /signature/);
});

function makeRelease(directory, { protocol = 1, minimum = 1, failHealth = false } = {}) {
  fs.mkdirSync(path.join(directory, 'runtime/bin'), { recursive: true });
  fs.mkdirSync(path.join(directory, 'bin'), { recursive: true });
  fs.symlinkSync(process.execPath, path.join(directory, 'runtime/bin/node'));
  fs.writeFileSync(path.join(directory, 'bin/lookout.js'), '#!/usr/bin/env node\nprocess.exit(0);\n', { mode: 0o755 });
  fs.writeFileSync(path.join(directory, 'package.json'), JSON.stringify({ lookout: { collectorProtocol: protocol, minimumCollectorProtocol: minimum } }));
  if (failHealth) fs.writeFileSync(path.join(directory, 'FAIL_HEALTH'), '1');
}

test('rolling compatibility rejects an incompatible central and collector protocol', (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'lookout-compatibility-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const current = path.join(directory, 'current-release');
  const compatible = path.join(directory, 'compatible-release');
  const incompatible = path.join(directory, 'incompatible-release');
  makeRelease(current);
  makeRelease(compatible, { protocol: 2, minimum: 1 });
  makeRelease(incompatible, { protocol: 2, minimum: 2 });
  assert.doesNotThrow(() => validateRollingCompatibility(current, compatible));
  assert.throws(() => validateRollingCompatibility(current, incompatible), /rolling central and collector/);
});

test('atomic release activation restores the previous release when health verification fails', (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'lookout-atomic-update-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const prefix = path.join(directory, 'lookout');
  const releases = path.join(prefix, 'releases');
  const oldRelease = path.join(releases, 'old');
  const prepared = path.join(directory, 'prepared');
  fs.mkdirSync(releases, { recursive: true });
  makeRelease(oldRelease);
  makeRelease(prepared, { failHealth: true });
  fs.writeFileSync(path.join(oldRelease, '.lookout-release'), 'old\n');
  fs.symlinkSync(oldRelease, path.join(prefix, 'current'));
  const systemctl = path.join(directory, 'systemctl');
  fs.writeFileSync(systemctl, `#!/bin/sh\nset -eu\ncase "$1" in\nis-active) exit 0;;\nrestart) target=$(readlink "${prefix}/current"); test ! -f "$target/FAIL_HEALTH";;\n*) exit 0;;\nesac\n`, { mode: 0o755 });
  const priorPath = process.env.PATH;
  process.env.PATH = `${directory}:${priorPath}`;
  try {
    assert.throws(() => installPreparedRelease({ prepared, artifact: { sha256: 'a'.repeat(64) }, release: 'v1.2.3', prefix }), /previous release was restored/);
  } finally { process.env.PATH = priorPath; }
  assert.equal(fs.realpathSync(path.join(prefix, 'current')), fs.realpathSync(oldRelease));
});

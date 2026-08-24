'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { signManifest } = require('../src/update/manifest');
const { refreshReleaseTargets } = require('../src/cli/release-channel');
const { WorkstationConfigStore } = require('../src/cli/workstation-config');
const { centralRelease } = require('../src/cli/workstation-install');

function signingKey() {
  const pair = crypto.generateKeyPairSync('ed25519');
  return {
    keyId: 'test-key',
    privateKeyPem: pair.privateKey.export({ type: 'pkcs8', format: 'pem' }),
    publicKeySpkiPem: pair.publicKey.export({ type: 'spki', format: 'pem' })
  };
}

function targets(prefix = 'old') {
  return {
    amd64: { url: `https://releases.example.test/${prefix}-amd64.tar.gz`, sha256: (prefix === 'old' ? 'a' : 'c').repeat(64) },
    arm64: { url: `https://releases.example.test/${prefix}-arm64.tar.gz`, sha256: (prefix === 'old' ? 'b' : 'd').repeat(64) }
  };
}

function payload(sequence, replacements = targets('new'), overrides = {}) {
  return {
    schemaVersion: 1, channel: 'cli-stable', sequence, action: 'install', release: 'v0.2.0', publishedAt: '2026-08-23T22:00:00.000Z',
    artifacts: Object.fromEntries(Object.entries(replacements).map(([architecture, item]) => [architecture, { ...item, size: 1024 }])),
    ...overrides
  };
}

function response(value, { status = 200, contentType = 'application/json' } = {}) {
  const body = Buffer.from(JSON.stringify(value));
  return new Response(body, { status, headers: { 'content-type': contentType, 'content-length': String(body.length) } });
}

async function fixture(t) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-cli-release-channel-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  return { store: new WorkstationConfigStore({ directory }), key: signingKey() };
}

test('CLI replaces pinned targets from a verified signed release manifest', async (t) => {
  const { store, key } = await fixture(t);
  const envelope = signManifest(payload(2), key);
  const refreshed = await refreshReleaseTargets({
    store, pinnedTargets: targets(), origin: 'https://app.example.test', trustedKeys: [{ keyId: key.keyId, publicKeySpkiPem: key.publicKeySpkiPem }],
    fetchImpl: async (url, options) => {
      assert.equal(url, 'https://app.example.test/v1/updates/cli-stable');
      assert.equal(options.redirect, 'error');
      return response(envelope);
    }
  });
  assert.deepEqual(refreshed, targets('new'));
  assert.equal(centralRelease({ name: 'central' }, { LOOKOUT_RELEASE_TARGETS: JSON.stringify(refreshed) }, () => 'x86_64').sha256, 'c'.repeat(64));
  const saved = await store.loadReleaseChannelState();
  assert.equal(saved.channels[0].highestSequence, 2);
  assert.equal(saved.channels[0].targetsRelease, 'v0.2.0');
  assert.deepEqual(saved.channels[0].targets, targets('new'));
});

test('same-version channel targets cannot replace the artifact embedded in the CLI', async (t) => {
  const { store, key } = await fixture(t);
  const trustedKeys = [{ keyId: key.keyId, publicKeySpkiPem: key.publicKeySpkiPem }];
  const stale = signManifest(payload(1, targets('new'), { release: 'v0.1.0' }), key);
  assert.deepEqual(await refreshReleaseTargets({ store, pinnedTargets: targets(), pinnedRelease: 'v0.1.0', origin: 'https://app.example.test', trustedKeys, fetchImpl: async () => response(stale) }), targets());
  const saved = await store.loadReleaseChannelState();
  assert.equal(saved.channels[0].targets, null);
  assert.equal(saved.channels[0].targetsRelease, null);
  assert.deepEqual(await refreshReleaseTargets({ store, pinnedTargets: targets(), pinnedRelease: 'v0.1.0', origin: 'https://app.example.test', trustedKeys, retryDelayMs: 0, fetchImpl: async () => { throw new Error('offline'); } }), targets());
});

test('signed pause keeps the installed pin and an outage reuses a verified cached release', async (t) => {
  const { store, key } = await fixture(t);
  const trustedKeys = [{ keyId: key.keyId, publicKeySpkiPem: key.publicKeySpkiPem }];
  const pause = signManifest({ schemaVersion: 1, channel: 'cli-stable', sequence: 1, action: 'pause', release: 'v0.1.0', publishedAt: '2026-08-23T22:00:00.000Z' }, key);
  assert.deepEqual(await refreshReleaseTargets({ store, pinnedTargets: targets(), origin: 'https://app.example.test', trustedKeys, fetchImpl: async () => response(pause) }), targets());
  assert.equal((await store.loadReleaseChannelState()).channels[0].targets, null);
  const install = signManifest(payload(2), key);
  assert.deepEqual(await refreshReleaseTargets({ store, pinnedTargets: targets(), origin: 'https://app.example.test', trustedKeys, fetchImpl: async () => response(install) }), targets('new'));
  const laterPause = signManifest({ schemaVersion: 1, channel: 'cli-stable', sequence: 3, action: 'pause', release: 'v0.2.0', publishedAt: '2026-08-23T22:30:00.000Z' }, key);
  assert.deepEqual(await refreshReleaseTargets({ store, pinnedTargets: targets(), origin: 'https://app.example.test', trustedKeys, fetchImpl: async () => response(laterPause) }), targets('new'));
  assert.deepEqual(await refreshReleaseTargets({ store, pinnedTargets: targets(), origin: 'https://app.example.test', trustedKeys, retryDelayMs: 0, fetchImpl: async () => { throw new Error('offline'); } }), targets('new'));
});

test('CLI rejects tampering, replay equivocation, and signed targets outside allowed origins', async (t) => {
  const { store, key } = await fixture(t);
  const trustedKeys = [{ keyId: key.keyId, publicKeySpkiPem: key.publicKeySpkiPem }];
  const signed = signManifest(payload(2), key);
  await assert.rejects(refreshReleaseTargets({
    store, pinnedTargets: targets(), origin: 'https://app.example.test', trustedKeys,
    fetchImpl: async () => response({ ...signed, payload: { ...signed.payload, release: 'v9.9.9' } })
  }), /signature/);
  await refreshReleaseTargets({ store, pinnedTargets: targets(), origin: 'https://app.example.test', trustedKeys, fetchImpl: async () => response(signed) });
  const conflicting = signManifest(payload(2, targets('new'), { release: 'v0.2.1' }), key);
  await assert.rejects(refreshReleaseTargets({ store, pinnedTargets: targets(), origin: 'https://app.example.test', trustedKeys, fetchImpl: async () => response(conflicting) }), /replay or equivocation/);
  const outside = targets('new');
  outside.amd64.url = 'https://untrusted.example.test/amd64.tar.gz';
  const newer = signManifest(payload(3, outside), key);
  await assert.rejects(refreshReleaseTargets({ store, pinnedTargets: targets(), origin: 'https://app.example.test', trustedKeys, fetchImpl: async () => response(newer) }), /targets are invalid/);
});

test('invalid successful channel responses fail closed while HTTP outages keep the pin', async (t) => {
  const { store, key } = await fixture(t);
  const options = { store, pinnedTargets: targets(), origin: 'https://app.example.test', trustedKeys: [{ keyId: key.keyId, publicKeySpkiPem: key.publicKeySpkiPem }] };
  let attempts = 0;
  assert.deepEqual(await refreshReleaseTargets({ ...options, retryDelayMs: 0, fetchImpl: async () => { attempts += 1; return response({ error: 'unavailable' }, { status: 503 }); } }), targets());
  assert.equal(attempts, 3);
  attempts = 0;
  assert.deepEqual(await refreshReleaseTargets({ ...options, retryDelayMs: 0, fetchImpl: async () => { attempts += 1; return response({ error: 'busy' }, { status: 429 }); } }), targets());
  assert.equal(attempts, 3);
  await assert.rejects(refreshReleaseTargets({ ...options, fetchImpl: async () => response({}, { contentType: 'text/html' }) }), /content type/);
});

test('replay state is retained per origin and envelope key order is irrelevant', async (t) => {
  const { store, key } = await fixture(t);
  const trustedKeys = [{ keyId: key.keyId, publicKeySpkiPem: key.publicKeySpkiPem }];
  const signed = signManifest(payload(2), key);
  const common = { store, pinnedTargets: targets(), trustedKeys };
  await refreshReleaseTargets({ ...common, origin: 'https://app.example.test', fetchImpl: async () => response(signed) });
  const reordered = { signature: signed.signature, payload: Object.fromEntries(Object.entries(signed.payload).reverse()), keyId: signed.keyId, schemaVersion: signed.schemaVersion };
  assert.deepEqual(await refreshReleaseTargets({ ...common, origin: 'https://app.example.test', fetchImpl: async () => response(reordered) }), targets('new'));
  const other = signManifest(payload(1), key);
  await refreshReleaseTargets({ ...common, origin: 'https://other-app.example.test', fetchImpl: async () => response(other) });
  const replay = signManifest(payload(1), key);
  await assert.rejects(refreshReleaseTargets({ ...common, origin: 'https://app.example.test', fetchImpl: async () => response(replay) }), /replay or equivocation/);
  assert.equal((await store.loadReleaseChannelState()).channels.length, 2);
});

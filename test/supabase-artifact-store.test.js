'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { SupabaseArtifactStore, artifactRoute } = require('../src/hosting/supabase-artifact-store');

function memoryStorage() {
  const objects = new Map();
  let bucket = null;
  const fetchImpl = async (url, options = {}) => {
    const pathname = new URL(url).pathname;
    if (pathname === '/storage/v1/bucket' && options.method === 'POST') {
      if (bucket) return new Response('{}', { status: 400, headers: { 'content-type': 'application/json' } });
      bucket = JSON.parse(options.body);
      return new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } });
    }
    if (pathname === '/storage/v1/bucket/lookout-release-artifacts') return new Response(JSON.stringify(bucket), { status: bucket ? 200 : 404, headers: { 'content-type': 'application/json' } });
    const prefix = '/storage/v1/object/lookout-release-artifacts/';
    const key = decodeURIComponent(pathname.slice(prefix.length));
    if (options.method === 'POST') {
      if (objects.has(key)) return new Response('{}', { status: 400, headers: { 'content-type': 'application/json' } });
      objects.set(key, Buffer.from(options.body));
      return new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } });
    }
    const body = objects.get(key);
    if (!body) return new Response(null, { status: 404 });
    return new Response(body, { status: 200, headers: { 'content-length': String(body.length), 'content-type': key.endsWith('.zip') ? 'application/zip' : 'application/gzip' } });
  };
  return { objects, fetchImpl };
}

async function fixture(directory, contents) {
  const name = 'lookout-target-linux-amd64-v0.1.0.tar.gz';
  const bytes = Buffer.from(contents);
  const digest = crypto.createHash('sha256').update(bytes).digest('hex');
  const filename = path.join(directory, `${digest}.tar.gz`);
  await fs.writeFile(filename, bytes);
  return { name, filename, digest, route: `/releases/v0.1.0/${digest}/${name}`, contentType: 'application/gzip' };
}

test('artifact routes accept only supported content-addressed release names', () => {
  const digest = 'a'.repeat(64);
  assert.equal(artifactRoute(`/releases/v0.1.0/${digest}/lookout-target-linux-amd64-v0.1.0.tar.gz`).digest, digest);
  assert.equal(artifactRoute(`/releases/v0.1.0/${digest}/lookout-target-linux-amd64-v0.1.1.tar.gz`), null);
  assert.equal(artifactRoute(`/releases/v0.1.0/${digest}/lookout-target-linux-amd64-v0.1.0.zip`), null);
  assert.equal(artifactRoute(`/releases/v0.1.0/${digest}/other.tar.gz`), null);
});

test('publishing a new build retains and serves the previous digest', async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-artifact-retention-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const backend = memoryStorage();
  const store = new SupabaseArtifactStore({ supabaseUrl: 'https://supabase.example.test', serviceKey: 's'.repeat(32), fetchImpl: backend.fetchImpl });
  const first = await fixture(directory, 'build-a');
  const second = await fixture(directory, 'build-b');
  await store.publishAll([first]);
  await store.publishAll([second]);
  assert.equal((await store.publish(first)).stored, false);
  assert.equal(Buffer.from(await (await store.download(first.route)).arrayBuffer()).toString(), 'build-a');
  assert.equal(Buffer.from(await (await store.download(second.route)).arrayBuffer()).toString(), 'build-b');
  assert.equal(backend.objects.size, 2);
});

test('Supabase NoSuchKey responses become HTTP 404 for artifact clients', async () => {
  const store = new SupabaseArtifactStore({
    supabaseUrl: 'https://supabase.example.test', serviceKey: 's'.repeat(32),
    fetchImpl: async () => new Response(JSON.stringify({ statusCode: '404', error: 'not_found', code: 'NoSuchKey' }), {
      status: 400, headers: { 'content-type': 'application/json' }
    })
  });
  const route = `/releases/v0.1.0/${'a'.repeat(64)}/lookout-target-linux-amd64-v0.1.0.tar.gz`;
  assert.equal((await store.download(route)).status, 404);
});

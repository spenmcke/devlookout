'use strict';

const fs = require('node:fs/promises');
const crypto = require('node:crypto');

const DEFAULT_BUCKET = 'lookout-release-artifacts';
const MAXIMUM_ARTIFACT_BYTES = 512 * 1024 * 1024;
const MAXIMUM_STORAGE_ERROR_BYTES = 4096;

async function storageProblem(response) {
  const chunks = [];
  let size = 0;
  for await (const chunk of response.clone().body || []) {
    const bytes = Buffer.from(chunk);
    size += bytes.length;
    if (size > MAXIMUM_STORAGE_ERROR_BYTES) return null;
    chunks.push(bytes);
  }
  try { return JSON.parse(Buffer.concat(chunks, size).toString('utf8')); } catch { return null; }
}

function artifactRoute(value) {
  const match = /^\/releases\/(v\d+\.\d+\.\d+)\/([a-f0-9]{64})\/(lookout-(?:orchestration|target-linux-(?:amd64|arm64))-v\d+\.\d+\.\d+\.(?:tar\.gz|zip))$/.exec(value || '');
  if (!match || !match[3].includes(`-${match[1]}.`)) return null;
  if (match[3].endsWith('.zip') && !match[3].startsWith('lookout-orchestration-')) return null;
  return { route: value, version: match[1], digest: match[2], name: match[3], objectPath: value.slice(1) };
}

class SupabaseArtifactStore {
  constructor({ supabaseUrl, serviceKey, bucket = DEFAULT_BUCKET, fetchImpl = globalThis.fetch, maximumArtifactBytes = MAXIMUM_ARTIFACT_BYTES } = {}) {
    let base;
    try { base = new URL(supabaseUrl); } catch { throw new Error('Supabase artifact URL is invalid'); }
    if (base.protocol !== 'https:' || base.username || base.password || base.search || base.hash) throw new Error('Supabase artifact URL must use HTTPS');
    if (typeof serviceKey !== 'string' || serviceKey.length < 32 || serviceKey.length > 8192 || /[\r\n]/.test(serviceKey)) throw new Error('Supabase artifact service key is invalid');
    if (!/^[a-z0-9][a-z0-9-]{0,62}$/.test(bucket || '')) throw new Error('Supabase artifact bucket is invalid');
    if (typeof fetchImpl !== 'function') throw new TypeError('Supabase artifact store requires fetch support');
    if (!Number.isSafeInteger(maximumArtifactBytes) || maximumArtifactBytes < 1024 || maximumArtifactBytes > 2 * 1024 * 1024 * 1024) throw new Error('Supabase artifact size limit is invalid');
    this.base = base;
    this.serviceKey = serviceKey;
    this.bucket = bucket;
    this.fetchImpl = fetchImpl;
    this.maximumArtifactBytes = maximumArtifactBytes;
  }

  #url(objectPath) {
    return new URL(`/storage/v1/object/${this.bucket}/${objectPath.split('/').map(encodeURIComponent).join('/')}`, this.base);
  }

  #bucketUrl() {
    return new URL(`/storage/v1/bucket/${this.bucket}`, this.base);
  }

  #headers(extra = {}) {
    return { apikey: this.serviceKey, authorization: `Bearer ${this.serviceKey}`, ...extra };
  }

  async #storedDigest(route) {
    const response = await this.download(route);
    if (response.status === 404) return null;
    if (!response.ok) throw new Error('Supabase artifact verification was rejected');
    const declared = response.headers.get('content-length');
    if (declared && (!/^\d+$/.test(declared) || Number(declared) > this.maximumArtifactBytes)) throw new Error('Supabase artifact is too large');
    const hash = crypto.createHash('sha256');
    let size = 0;
    for await (const chunk of response.body || []) {
      const bytes = Buffer.from(chunk);
      size += bytes.length;
      if (size > this.maximumArtifactBytes) throw new Error('Supabase artifact is too large');
      hash.update(bytes);
    }
    return hash.digest('hex');
  }

  async publish(artifact) {
    const parsed = artifactRoute(artifact?.route);
    if (!parsed || parsed.digest !== artifact.digest || typeof artifact.filename !== 'string') throw new Error('Published artifact metadata is invalid');
    const bytes = await fs.readFile(artifact.filename);
    if (bytes.length > this.maximumArtifactBytes || crypto.createHash('sha256').update(bytes).digest('hex') !== parsed.digest) throw new Error(`Published artifact checksum is invalid: ${parsed.name}`);
    const response = await this.fetchImpl(this.#url(parsed.objectPath), {
      method: 'POST', redirect: 'error', headers: this.#headers({ 'content-type': artifact.contentType, 'cache-control': 'max-age=31536000', 'x-upsert': 'false' }), body: bytes
    });
    if (response.ok) return { stored: true, route: parsed.route };
    const existingDigest = await this.#storedDigest(parsed.route);
    if (existingDigest === parsed.digest) return { stored: false, route: parsed.route };
    throw new Error(`Supabase artifact publication failed: ${parsed.name}`);
  }

  async ensureBucket() {
    const response = await this.fetchImpl(new URL('/storage/v1/bucket', this.base), {
      method: 'POST', redirect: 'error', headers: this.#headers({ 'content-type': 'application/json' }),
      body: JSON.stringify({ id: this.bucket, name: this.bucket, public: false, file_size_limit: this.maximumArtifactBytes, allowed_mime_types: ['application/gzip', 'application/zip'] })
    });
    if (response.ok) return;
    const existing = await this.fetchImpl(this.#bucketUrl(), { method: 'GET', redirect: 'error', headers: this.#headers({ accept: 'application/json' }) });
    if (!existing.ok) throw new Error('Supabase artifact bucket is unavailable');
    const value = await existing.json();
    if (value?.id !== this.bucket || value.public !== false) throw new Error('Supabase artifact bucket configuration is invalid');
  }

  async publishAll(artifacts) {
    await this.ensureBucket();
    for (const artifact of artifacts) await this.publish(artifact);
  }

  async download(route) {
    const parsed = artifactRoute(route);
    if (!parsed) return new Response(null, { status: 404 });
    const response = await this.fetchImpl(this.#url(parsed.objectPath), { method: 'GET', redirect: 'error', headers: this.#headers() });
    if (response.status !== 400 || !/^application\/json(?:;|$)/i.test(response.headers.get('content-type') || '')) return response;
    const problem = await storageProblem(response);
    if (problem?.code === 'NoSuchKey' || (problem?.statusCode === '404' && problem?.error === 'not_found')) return new Response(null, { status: 404 });
    return response;
  }
}

module.exports = { SupabaseArtifactStore, artifactRoute, DEFAULT_BUCKET, MAXIMUM_ARTIFACT_BYTES };

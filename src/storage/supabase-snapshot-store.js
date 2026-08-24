'use strict';

const crypto = require('node:crypto');
const { canonicalJson } = require('../core/canonical');

const STATE_KEY = /^[a-z][a-z0-9_-]{0,63}$/;

async function limitedText(response, maximumBytes = 2 * 1024 * 1024) {
  if (!response.body?.getReader) {
    const text = await response.text();
    if (Buffer.byteLength(text) > maximumBytes) throw new Error('Supabase state response is too large');
    return text;
  }
  const reader = response.body.getReader();
  const chunks = [];
  let length = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    length += value.byteLength;
    if (length > maximumBytes) {
      await reader.cancel();
      throw new Error('Supabase state response is too large');
    }
    chunks.push(Buffer.from(value));
  }
  return Buffer.concat(chunks, length).toString('utf8');
}

function validateConfiguration({ supabaseUrl, serviceKey, stateKey, protector, fetchImpl }) {
  let base;
  try { base = new URL(supabaseUrl); } catch { throw new Error('Supabase state URL is invalid'); }
  if (base.protocol !== 'https:' || base.username || base.password || base.search || base.hash) throw new Error('Supabase state URL must use HTTPS');
  if (typeof serviceKey !== 'string' || serviceKey.length < 32 || serviceKey.length > 8192 || /[\r\n]/.test(serviceKey)) throw new Error('Supabase service key is invalid');
  if (!STATE_KEY.test(stateKey || '')) throw new Error('Supabase state key is invalid');
  if (!protector || typeof protector.sealString !== 'function' || typeof protector.openString !== 'function') throw new Error('Supabase state encryption is required');
  if (typeof fetchImpl !== 'function') throw new Error('Supabase state fetch implementation is invalid');
  return base;
}

class SupabaseSnapshotStore {
  constructor({ supabaseUrl, serviceKey, stateKey, protector, fetchImpl = globalThis.fetch, timeoutMs = 10000 } = {}) {
    this.base = validateConfiguration({ supabaseUrl, serviceKey, stateKey, protector, fetchImpl });
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 60000) throw new Error('Supabase state timeout is invalid');
    this.serviceKey = serviceKey;
    this.stateKey = stateKey;
    this.protector = protector;
    this.fetchImpl = fetchImpl;
    this.timeoutMs = timeoutMs;
    this.revision = 0;
    this.shared = true;
  }

  #headers(extra = {}) {
    return { apikey: this.serviceKey, authorization: `Bearer ${this.serviceKey}`, accept: 'application/json', ...extra };
  }

  async #request(pathname, options) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    let response;
    try {
      response = await this.fetchImpl(new URL(pathname, this.base), { ...options, redirect: 'error', signal: controller.signal });
    } catch (error) {
      if (error?.name === 'AbortError') throw new Error('Supabase state request timed out');
      throw new Error('Supabase state request failed');
    } finally { clearTimeout(timer); }
    const text = await limitedText(response);
    if (!response.ok) {
      if (response.status === 409 || /revision conflict/i.test(text)) throw new Error('Supabase state revision conflict');
      throw new Error('Supabase state request was rejected');
    }
    if (!/^application\/json(?:;|$)/i.test(response.headers.get('content-type') || '')) throw new Error('Supabase state response is invalid');
    try { return text ? JSON.parse(text) : null; } catch { throw new Error('Supabase state response is invalid'); }
  }

  async load() {
    const query = `/rest/v1/lookout_hosted_state?state_key=eq.${encodeURIComponent(this.stateKey)}&select=revision,payload`;
    const rows = await this.#request(query, { method: 'GET', headers: this.#headers() });
    if (!Array.isArray(rows) || rows.length > 1) throw new Error('Supabase state response is invalid');
    if (rows.length === 0) { this.revision = 0; return null; }
    const row = rows[0];
    if (!Number.isSafeInteger(row.revision) || row.revision < 1 || !this.protector.constructor.isEnvelope(row.payload)) throw new Error('Supabase state record is invalid');
    const serialized = this.protector.openString(row.payload, `supabase-state:${this.stateKey}`);
    let document;
    try { document = JSON.parse(serialized); } catch { throw new Error('Supabase state record is invalid'); }
    const { integrity, ...snapshot } = document;
    const digest = crypto.createHash('sha256').update(canonicalJson(snapshot)).digest('hex');
    if (!integrity || integrity.algorithm !== 'sha256' || integrity.digest !== digest) throw new Error('Supabase state integrity check failed');
    this.revision = row.revision;
    return snapshot;
  }

  async save(snapshot) {
    const document = { ...snapshot, integrity: { algorithm: 'sha256', digest: crypto.createHash('sha256').update(canonicalJson(snapshot)).digest('hex') } };
    const payload = this.protector.sealString(canonicalJson(document), `supabase-state:${this.stateKey}`);
    const result = await this.#request('/rest/v1/rpc/lookout_save_hosted_state', {
      method: 'POST',
      headers: this.#headers({ 'content-type': 'application/json' }),
      body: JSON.stringify({ p_state_key: this.stateKey, p_expected_revision: this.revision, p_payload: payload })
    });
    if (!Number.isSafeInteger(result) || result !== this.revision + 1) throw new Error('Supabase state revision is invalid');
    this.revision = result;
  }
}

module.exports = { SupabaseSnapshotStore, limitedText };

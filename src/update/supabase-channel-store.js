'use strict';

const { verifyManifest } = require('./manifest');

async function boundedJson(response, maximum = 256 * 1024) {
  const declared = response.headers.get('content-length');
  if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > maximum)) throw new Error('Update channel response is too large');
  const text = await response.text();
  if (Buffer.byteLength(text) > maximum) throw new Error('Update channel response is too large');
  try { return text ? JSON.parse(text) : null; } catch { throw new Error('Update channel store returned invalid JSON'); }
}

class SupabaseUpdateChannelStore {
  constructor({ supabaseUrl, serviceKey, trustedKeys, fetchImpl = globalThis.fetch, timeoutMs = 5000, cacheMs = 30000 } = {}) {
    let base;
    try { base = new URL(supabaseUrl); } catch { throw new Error('Supabase update channel URL is invalid'); }
    if (base.protocol !== 'https:' || base.username || base.password || base.search || base.hash) throw new Error('Supabase update channel URL must use HTTPS');
    if (typeof serviceKey !== 'string' || serviceKey.length < 32 || serviceKey.length > 8192 || /[\r\n]/.test(serviceKey)) throw new Error('Supabase update channel service key is invalid');
    if (!Array.isArray(trustedKeys) || trustedKeys.length < 1) throw new Error('Update channel trusted keys are required');
    this.endpoint = new URL('/rest/v1/lookout_update_channels', base);
    this.serviceKey = serviceKey;
    this.trustedKeys = trustedKeys;
    this.fetchImpl = fetchImpl;
    this.timeoutMs = timeoutMs;
    this.cacheMs = cacheMs;
    this.cache = new Map();
  }

  async get(channel = 'stable') {
    if (!['stable', 'cli-stable'].includes(channel)) throw new Error('Update channel is invalid');
    const cached = this.cache.get(channel);
    if (cached && cached.expiresAt > Date.now()) return cached.value;
    const url = new URL(this.endpoint);
    url.searchParams.set('channel', `eq.${channel}`);
    url.searchParams.set('select', 'manifest');
    url.searchParams.set('limit', '1');
    const response = await this.fetchImpl(url, {
      headers: { apikey: this.serviceKey, Authorization: `Bearer ${this.serviceKey}`, Accept: 'application/json' },
      redirect: 'error', signal: AbortSignal.timeout(this.timeoutMs)
    });
    const rows = await boundedJson(response);
    if (!response.ok) throw new Error(`Supabase update channel request returned HTTP ${response.status}`);
    if (!Array.isArray(rows) || rows.length > 1 || (rows[0] && !rows[0].manifest)) throw new Error('Supabase update channel response is invalid');
    const value = rows[0]?.manifest || null;
    if (value) verifyManifest(value, this.trustedKeys, { channel });
    this.cache.set(channel, { value, expiresAt: Date.now() + this.cacheMs });
    return value;
  }
}

module.exports = { SupabaseUpdateChannelStore, boundedUpdateChannelJson: boundedJson };

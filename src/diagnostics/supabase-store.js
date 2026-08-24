'use strict';

const TABLE = 'lookout_installation_diagnostics';

async function boundedJson(response, maximum = 1024 * 1024) {
  const text = await response.text();
  if (Buffer.byteLength(text) > maximum) throw new Error('Diagnostics store response is too large');
  if (!text) return null;
  try { return JSON.parse(text); } catch { throw new Error('Diagnostics store returned invalid JSON'); }
}

class SupabaseDiagnosticsStore {
  constructor({ supabaseUrl, serviceKey, fetchImpl = globalThis.fetch, timeoutMs = 10000 } = {}) {
    let base;
    try { base = new URL(supabaseUrl); } catch { throw new Error('Supabase diagnostics URL is invalid'); }
    if (base.protocol !== 'https:' || base.username || base.password || base.search || base.hash) throw new Error('Supabase diagnostics URL must use HTTPS');
    if (typeof serviceKey !== 'string' || serviceKey.length < 32 || serviceKey.length > 8192 || /[\r\n]/.test(serviceKey)) throw new Error('Supabase diagnostics service key is invalid');
    if (typeof fetchImpl !== 'function') throw new Error('Supabase diagnostics fetch implementation is invalid');
    this.endpoint = new URL(`/rest/v1/${TABLE}`, base);
    this.serviceKey = serviceKey;
    this.fetchImpl = fetchImpl;
    this.timeoutMs = timeoutMs;
  }

  async request(url, { method = 'GET', body, prefer } = {}) {
    const headers = { apikey: this.serviceKey, Authorization: `Bearer ${this.serviceKey}`, Accept: 'application/json' };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    if (prefer) headers.Prefer = prefer;
    const response = await this.fetchImpl(url, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), redirect: 'error', signal: AbortSignal.timeout(this.timeoutMs) });
    const value = await boundedJson(response);
    if (!response.ok) throw new Error(`Supabase diagnostics request returned HTTP ${response.status}`);
    return value;
  }

  async insert(record) {
    const rows = await this.request(this.endpoint, { method: 'POST', body: record, prefer: 'return=representation' });
    if (!Array.isArray(rows) || rows.length !== 1 || rows[0].report_id !== record.report_id) throw new Error('Supabase diagnostics insert was not acknowledged');
    return rows[0];
  }

  async get(reportId) {
    const url = new URL(this.endpoint);
    url.searchParams.set('report_id', `eq.${reportId}`);
    url.searchParams.set('limit', '1');
    const rows = await this.request(url);
    if (!Array.isArray(rows) || rows.length > 1) throw new Error('Supabase diagnostics lookup is invalid');
    return rows[0] || null;
  }

  async getByIdempotency(idempotencyKey) {
    const url = new URL(this.endpoint);
    url.searchParams.set('idempotency_key', `eq.${idempotencyKey}`);
    url.searchParams.set('limit', '1');
    const rows = await this.request(url);
    if (!Array.isArray(rows) || rows.length > 1) throw new Error('Supabase diagnostics idempotency lookup is invalid');
    return rows[0] || null;
  }

  async update(reportId, patch) {
    const url = new URL(this.endpoint);
    url.searchParams.set('report_id', `eq.${reportId}`);
    const rows = await this.request(url, { method: 'PATCH', body: patch, prefer: 'return=representation' });
    if (!Array.isArray(rows) || rows.length !== 1 || rows[0].report_id !== reportId) throw new Error('Supabase diagnostics update was not acknowledged');
    return rows[0];
  }

  async pendingSlack(now, limit) {
    const url = new URL(this.endpoint);
    url.searchParams.set('slack_status', 'in.(pending,delivering)');
    url.searchParams.set('slack_next_attempt_at', `lte.${now}`);
    url.searchParams.set('order', 'slack_next_attempt_at.asc');
    url.searchParams.set('limit', String(limit));
    const rows = await this.request(url);
    if (!Array.isArray(rows)) throw new Error('Supabase diagnostics pending response is invalid');
    return rows;
  }

  async claimSlack(report, now) {
    const url = new URL(this.endpoint);
    url.searchParams.set('report_id', `eq.${report.report_id}`);
    url.searchParams.set('slack_status', `eq.${report.slack_status}`);
    url.searchParams.set('slack_next_attempt_at', `lte.${now}`);
    const leaseUntil = new Date(Date.parse(now) + 5 * 60 * 1000).toISOString();
    const rows = await this.request(url, { method: 'PATCH', body: { slack_status: 'delivering', slack_next_attempt_at: leaseUntil }, prefer: 'return=representation' });
    if (!Array.isArray(rows) || rows.length > 1) throw new Error('Supabase diagnostics Slack claim is invalid');
    return rows[0] || null;
  }

  async deleteExpired(now) {
    const url = new URL(this.endpoint);
    url.searchParams.set('expires_at', `lt.${now}`);
    await this.request(url, { method: 'DELETE', prefer: 'return=minimal' });
    return { deleted: true };
  }

  async deleteTenant(tenantId) {
    const url = new URL(this.endpoint);
    url.searchParams.set('tenant_id', `eq.${tenantId}`);
    await this.request(url, { method: 'DELETE', prefer: 'return=minimal' });
    return { deleted: true };
  }
}

module.exports = { SupabaseDiagnosticsStore, boundedDiagnosticsJson: boundedJson };

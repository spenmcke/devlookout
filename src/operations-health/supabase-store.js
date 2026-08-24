'use strict';

const MAXIMUM_RESPONSE_BYTES = 2 * 1024 * 1024;

async function boundedJson(response, maximumBytes = MAXIMUM_RESPONSE_BYTES) {
  const text = await response.text();
  if (Buffer.byteLength(text) > maximumBytes) throw new Error('Operational health storage response is too large');
  if (!text) return null;
  try { return JSON.parse(text); } catch { throw new Error('Operational health storage response is invalid'); }
}

function timestamp(value, label) {
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) throw new Error(`Operational health ${label} is invalid`);
  return date.toISOString();
}

function required(value, label, maximum = 256) {
  if (typeof value !== 'string' || !value || value.length > maximum || /[\r\n]/.test(value)) throw new Error(`Operational health ${label} is invalid`);
  return value;
}

class SupabaseOperationalHealthStore {
  constructor({ supabaseUrl, serviceKey, fetchImpl = globalThis.fetch, timeoutMs = 10000 } = {}) {
    let origin;
    try { origin = new URL(supabaseUrl); } catch { throw new Error('Operational health Supabase URL is invalid'); }
    if (origin.protocol !== 'https:' || origin.username || origin.password || origin.search || origin.hash) throw new Error('Operational health Supabase URL must use HTTPS');
    if (typeof serviceKey !== 'string' || serviceKey.length < 32 || serviceKey.length > 8192 || /[\r\n]/.test(serviceKey)) throw new Error('Operational health Supabase service key is invalid');
    if (typeof fetchImpl !== 'function') throw new Error('Operational health fetch implementation is invalid');
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 60000) throw new Error('Operational health timeout is invalid');
    this.origin = origin;
    this.serviceKey = serviceKey;
    this.fetchImpl = fetchImpl;
    this.timeoutMs = timeoutMs;
  }

  async request(pathname, { method = 'GET', body } = {}) {
    let response;
    try {
      response = await this.fetchImpl(new URL(pathname, this.origin), {
        method, redirect: 'error', signal: AbortSignal.timeout(this.timeoutMs),
        headers: { apikey: this.serviceKey, Authorization: `Bearer ${this.serviceKey}`, Accept: 'application/json', ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
        body: body === undefined ? undefined : JSON.stringify(body)
      });
    } catch { throw Object.assign(new Error('Operational health storage is unavailable'), { status: 503 }); }
    const value = await boundedJson(response);
    if (!response.ok) {
      if (response.status === 409 || response.status === 422) throw Object.assign(new Error('Operational health storage conflict'), { status: 409 });
      throw Object.assign(new Error('Operational health storage is unavailable'), { status: 503 });
    }
    return value;
  }

  rpc(name, body) { return this.request(`/rest/v1/rpc/${name}`, { method: 'POST', body }); }

  insertSample(value) {
    required(value?.sampleId, 'sample identifier'); required(value?.tenantId, 'tenant identifier'); required(value?.deploymentId, 'deployment identifier'); required(value?.collectorId, 'collector identifier');
    const sampledAt = timestamp(value.sampledAt, 'sample time');
    if (!value.payload || typeof value.payload !== 'object' || Array.isArray(value.payload)) throw new Error('Operational health sample payload is invalid');
    return this.rpc('lookout_operational_insert_sample', { p_input: { ...value, sampledAt } });
  }

  async recentSamples({ tenantId, deploymentId, collectorId = null, since, limit = 288 } = {}) {
    required(tenantId, 'tenant identifier'); required(deploymentId, 'deployment identifier');
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 2016) throw new Error('Operational health sample limit is invalid');
    const query = new URLSearchParams({ tenant_id: `eq.${tenantId}`, deployment_id: `eq.${deploymentId}`, sampled_at: `gte.${timestamp(since, 'sample lower bound')}`, order: 'sampled_at.desc', limit: String(limit) });
    if (collectorId !== null) query.set('collector_id', `eq.${required(collectorId, 'collector identifier')}`);
    const rows = await this.request(`/rest/v1/lookout_operational_samples?${query}`);
    if (!Array.isArray(rows)) throw new Error('Operational health samples response is invalid');
    return rows;
  }

  async recentDeploymentSamples({ deploymentId, since, limit = 2016 } = {}) {
    required(deploymentId, 'deployment identifier');
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 5000) throw new Error('Operational health sample limit is invalid');
    const query = new URLSearchParams({ deployment_id: `eq.${deploymentId}`, sampled_at: `gte.${timestamp(since, 'sample lower bound')}`, order: 'sampled_at.desc', limit: String(limit) });
    const rows = await this.request(`/rest/v1/lookout_operational_samples?${query}`);
    if (!Array.isArray(rows)) throw new Error('Operational health samples response is invalid');
    return rows;
  }

  upsertAlertState(value) {
    required(value?.tenantId, 'tenant identifier'); required(value?.deploymentId, 'deployment identifier'); required(value?.alertKey, 'alert key');
    if (!['pending', 'open', 'resolved'].includes(value.status) || !['warning', 'critical'].includes(value.severity)) throw new Error('Operational health alert state is invalid');
    return this.rpc('lookout_operational_upsert_alert', { p_input: { ...value, openedAt: timestamp(value.openedAt, 'alert open time'), updatedAt: timestamp(value.updatedAt, 'alert update time'), resolvedAt: value.resolvedAt == null ? null : timestamp(value.resolvedAt, 'alert resolution time'), lastNotifiedAt: value.lastNotifiedAt == null ? null : timestamp(value.lastNotifiedAt, 'alert notification time') } });
  }

  async getAlertState({ tenantId, deploymentId, alertKey } = {}) {
    required(tenantId, 'tenant identifier'); required(deploymentId, 'deployment identifier'); required(alertKey, 'alert key');
    const query = new URLSearchParams({ tenant_id: `eq.${tenantId}`, deployment_id: `eq.${deploymentId}`, alert_key: `eq.${alertKey}`, limit: '1' });
    const rows = await this.request(`/rest/v1/lookout_operational_alert_state?${query}`);
    if (!Array.isArray(rows) || rows.length > 1) throw new Error('Operational health alert response is invalid');
    return rows[0] || null;
  }

  async listAlertStates({ status = 'open', limit = 1000 } = {}) {
    if (!['pending', 'open', 'resolved'].includes(status) || !Number.isSafeInteger(limit) || limit < 1 || limit > 5000) throw new Error('Operational health alert query is invalid');
    const rows = await this.request(`/rest/v1/lookout_operational_alert_state?${new URLSearchParams({ status: `eq.${status}`, order: 'updated_at.desc', limit: String(limit) })}`);
    if (!Array.isArray(rows)) throw new Error('Operational health alerts response is invalid');
    return rows;
  }

  enqueueNotification(value) {
    required(value?.outboxId, 'outbox identifier'); required(value?.idempotencyKey, 'notification idempotency key');
    required(value?.tenantId, 'tenant identifier'); required(value?.deploymentId, 'deployment identifier'); required(value?.alertKey, 'alert key');
    if (!['slack', 'email'].includes(value.channel) || !value.payload || typeof value.payload !== 'object' || Array.isArray(value.payload)) throw new Error('Operational health notification is invalid');
    return this.rpc('lookout_operational_enqueue_notification', { p_input: { ...value, nextAttemptAt: value.nextAttemptAt == null ? null : timestamp(value.nextAttemptAt, 'notification attempt time') } });
  }

  claimNotification({ now, leaseSeconds = 300, maximumAttempts = 10 } = {}) {
    if (!Number.isSafeInteger(leaseSeconds) || leaseSeconds < 30 || leaseSeconds > 3600 || !Number.isSafeInteger(maximumAttempts) || maximumAttempts < 1 || maximumAttempts > 100) throw new Error('Operational health notification claim is invalid');
    return this.rpc('lookout_operational_claim_notification', { p_now: timestamp(now, 'claim time'), p_lease_seconds: leaseSeconds, p_maximum_attempts: maximumAttempts });
  }

  acknowledgeNotification({ outboxId, attempt, now, providerMessageId = null } = {}) {
    required(outboxId, 'outbox identifier');
    if (!Number.isSafeInteger(attempt) || attempt < 1) throw new Error('Operational health notification attempt is invalid');
    if (providerMessageId !== null) required(providerMessageId, 'provider message identifier', 512);
    return this.rpc('lookout_operational_ack_notification', { p_outbox_id: outboxId, p_attempt: attempt, p_now: timestamp(now, 'acknowledgement time'), p_provider_message_id: providerMessageId });
  }

  failNotification({ outboxId, attempt, now, nextAttemptAt, error, maximumAttempts = 10 } = {}) {
    required(outboxId, 'outbox identifier'); required(error, 'notification failure', 500);
    if (!Number.isSafeInteger(attempt) || attempt < 1) throw new Error('Operational health notification attempt is invalid');
    if (!Number.isSafeInteger(maximumAttempts) || maximumAttempts < 1 || maximumAttempts > 100) throw new Error('Operational health maximum notification attempts is invalid');
    return this.rpc('lookout_operational_fail_notification', { p_outbox_id: outboxId, p_attempt: attempt, p_now: timestamp(now, 'failure time'), p_next_attempt_at: timestamp(nextAttemptAt, 'retry time'), p_error: error, p_maximum_attempts: maximumAttempts });
  }

  async missingTelemetry({ now, thresholdMinutes = 15, limit = 5000 } = {}) {
    if (!Number.isSafeInteger(thresholdMinutes) || thresholdMinutes < 5 || thresholdMinutes > 10080 || !Number.isSafeInteger(limit) || limit < 1 || limit > 5000) throw new Error('Operational health missing telemetry query is invalid');
    const cutoff = new Date(Date.parse(timestamp(now, 'missing telemetry time')) - thresholdMinutes * 60000).toISOString();
    const rows = await this.request(`/rest/v1/lookout_operational_targets?${new URLSearchParams({ last_seen_at: `lte.${cutoff}`, order: 'last_seen_at.asc', limit: String(limit) })}`);
    if (!Array.isArray(rows)) throw new Error('Operational health missing telemetry response is invalid');
    return rows;
  }

  deleteExpired({ now } = {}) { return this.rpc('lookout_operational_delete_expired', { p_now: timestamp(now, 'expiry time') }); }
  deleteDeployment({ tenantId, deploymentId } = {}) { return this.rpc('lookout_operational_delete_deployment', { p_tenant_id: required(tenantId, 'tenant identifier'), p_deployment_id: required(deploymentId, 'deployment identifier') }); }
  deleteTenant(tenantId) { return this.rpc('lookout_operational_delete_tenant', { p_tenant_id: required(tenantId, 'tenant identifier') }); }
}

module.exports = { SupabaseOperationalHealthStore, boundedOperationalHealthJson: boundedJson };

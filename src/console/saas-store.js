'use strict';

const crypto = require('node:crypto');
const { canonicalJson } = require('../core/canonical');
const { SnapshotStore } = require('../storage/snapshot-store');
const { buildUninstalledConsoleSnapshot, validateConsoleSnapshot } = require('./snapshot');

const DEPLOYMENT_ID = /^dpl_[A-Za-z0-9_-]{32}$/;
const BATCH_ID = /^[a-f0-9]{64}$/;
const TENANT_ID = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$/;
const ALERT_ID = /^[A-Za-z0-9._:-]{1,256}$/;
const ALERT_STATUSES = new Set(['open', 'to_fix', 'closed']);

function copy(value) { return structuredClone(value); }

function validateAlertOverride(override) {
  if (!override || !ALERT_STATUSES.has(override.status) || !Array.isArray(override.statusHistory) || override.statusHistory.length > 32) throw new Error('Persisted SaaS alert override is invalid');
  for (const entry of override.statusHistory) {
    if (!entry || !ALERT_STATUSES.has(entry.status) || typeof entry.actor !== 'string' || !entry.actor || Number.isNaN(Date.parse(entry.at)) || (entry.reason !== undefined && (typeof entry.reason !== 'string' || entry.reason.length < 3 || entry.reason.length > 1000))) throw new Error('Persisted SaaS alert history is invalid');
  }
  return override;
}

function applyAlertOverrides(snapshot, overrides = {}) {
  const projected = copy(snapshot);
  for (const alert of projected.alerts || []) {
    const override = overrides[alert.id];
    if (!override) continue;
    alert.status = override.status;
    alert.statusHistory = copy(override.statusHistory);
  }
  return projected;
}

function validateBatch(batch, deploymentId) {
  if (!batch || batch.schemaVersion !== 1 || !BATCH_ID.test(batch.batchId || '') || !Number.isSafeInteger(batch.firstSequence) || !Number.isSafeInteger(batch.lastSequence) || batch.firstSequence < 1 || batch.lastSequence < batch.firstSequence || !Array.isArray(batch.events) || batch.events.length < 1 || batch.events.length > 100) throw new Error('Console snapshot batch is invalid');
  if (batch.lastSequence - batch.firstSequence + 1 !== batch.events.length) throw new Error('Console snapshot batch sequence is invalid');
  const events = batch.events.map((event) => copy(validateConsoleSnapshot(event)));
  if (events.some((event) => event.deploymentId !== deploymentId)) throw new Error('Console snapshot deployment does not match its credential');
  const records = events.map((event, index) => ({ sequence: batch.firstSequence + index, id: event.id }));
  const expected = crypto.createHash('sha256').update(canonicalJson(records)).digest('hex');
  if (expected !== batch.batchId) throw new Error('Console snapshot batch identifier is invalid');
  return { ...copy(batch), events };
}

function validateState(value, maximumDeployments) {
  if (!value) return { schemaVersion: 1, deployments: {}, deletedTenants: [] };
  if (value.schemaVersion !== 1 || !value.deployments || typeof value.deployments !== 'object' || Array.isArray(value.deployments) || Object.keys(value.deployments).length > maximumDeployments) throw new Error('Persisted SaaS console state is invalid');
  const normalized = copy(value);
  normalized.deletedTenants ||= [];
  if (!Array.isArray(normalized.deletedTenants) || normalized.deletedTenants.length > 100000 || new Set(normalized.deletedTenants).size !== normalized.deletedTenants.length || normalized.deletedTenants.some((tenantId) => !TENANT_ID.test(tenantId))) throw new Error('Persisted SaaS tenant deletion state is invalid');
  for (const [deploymentId, record] of Object.entries(normalized.deployments)) {
    if (!DEPLOYMENT_ID.test(deploymentId) || !record || record.deploymentId !== deploymentId || typeof record.tenantId !== 'string' || !record.tenantId || !Number.isSafeInteger(record.lastSequence) || record.lastSequence < 1 || !BATCH_ID.test(record.lastBatchId || '') || Number.isNaN(Date.parse(record.updatedAt))) throw new Error('Persisted SaaS deployment state is invalid');
    validateConsoleSnapshot(record.snapshot);
    record.status ||= 'active';
    if (!['active', 'central_missing', 'uninstalled'].includes(record.status) || (record.status === 'uninstalled' && Number.isNaN(Date.parse(record.uninstalledAt)))) throw new Error('Persisted SaaS deployment lifecycle is invalid');
    record.alertOverrides ||= {};
    if (!record.alertOverrides || typeof record.alertOverrides !== 'object' || Array.isArray(record.alertOverrides) || Object.keys(record.alertOverrides).length > 64) throw new Error('Persisted SaaS alert overrides are invalid');
    for (const [alertId, override] of Object.entries(record.alertOverrides)) {
      if (!ALERT_ID.test(alertId)) throw new Error('Persisted SaaS alert identifier is invalid');
      validateAlertOverride(override);
    }
  }
  return normalized;
}

class SaasConsoleStore {
  constructor({ snapshotStore, dataDirectory, protector = null, requireEncryption = false, maximumDeployments = 10000, clock = () => new Date() } = {}) {
    if (!Number.isSafeInteger(maximumDeployments) || maximumDeployments < 1 || maximumDeployments > 100000) throw new Error('SaaS console deployment limit is invalid');
    if (!snapshotStore && (!dataDirectory || requireEncryption !== true)) throw new Error('Persistent SaaS console storage requires encrypted storage');
    this.store = snapshotStore || new SnapshotStore(dataDirectory, 'saas-console.json', { protector, requireEncryption });
    this.maximumDeployments = maximumDeployments;
    this.clock = clock;
    this.state = { schemaVersion: 1, deployments: {}, deletedTenants: [] };
    this.serial = Promise.resolve();
    this.ready = null;
  }

  async initialize() {
    if (!this.ready) this.ready = (async () => {
      this.state = validateState(await this.store.load(), this.maximumDeployments);
      return this;
    })();
    return this.ready;
  }

  async acceptBatch(principal, input) {
    await this.initialize();
    if (!principal || typeof principal.tenantId !== 'string' || !DEPLOYMENT_ID.test(principal.deploymentId || '')) throw new Error('Console principal is invalid');
    const batch = validateBatch(input, principal.deploymentId);
    const operation = this.serial.then(async () => {
      if (this.store.shared) this.state = validateState(await this.store.load(), this.maximumDeployments);
      const next = copy(this.state);
      if (next.deletedTenants.includes(principal.tenantId)) throw new Error('Console tenant has been deleted');
      const existing = next.deployments[principal.deploymentId];
      if (existing?.tenantId !== undefined && existing.tenantId !== principal.tenantId) throw new Error('Console deployment tenant mismatch');
      if (existing?.lastBatchId === batch.batchId && existing.lastSequence === batch.lastSequence) {
        if (existing.status === 'central_missing') {
          const now = this.clock();
          existing.status = 'active';
          existing.updatedAt = (now instanceof Date ? now : new Date(now)).toISOString();
          existing.snapshot = applyAlertOverrides(batch.events.at(-1), existing.alertOverrides);
          delete existing.recovery;
          await this.store.save(next);
          this.state = next;
        }
        return { accepted: batch.events.length, idempotent: true };
      }
      const expected = existing ? existing.lastSequence + 1 : 1;
      if (batch.firstSequence !== expected) throw new Error('Console snapshot sequence conflict');
      if (!existing && Object.keys(next.deployments).length >= this.maximumDeployments) throw new Error('SaaS console deployment capacity reached');
      const now = this.clock();
      const updatedAt = (now instanceof Date ? now : new Date(now)).toISOString();
      const incoming = batch.events.at(-1);
      const incomingAlertIds = new Set((incoming.alerts || []).map((alert) => alert.id));
      const alertOverrides = Object.fromEntries(Object.entries(existing?.alertOverrides || {}).filter(([alertId]) => incomingAlertIds.has(alertId)));
      next.deployments[principal.deploymentId] = {
        deploymentId: principal.deploymentId,
        tenantId: principal.tenantId,
        status: 'active',
        lastSequence: batch.lastSequence,
        lastBatchId: batch.batchId,
        updatedAt,
        snapshot: applyAlertOverrides(incoming, alertOverrides),
        alertOverrides
      };
      await this.store.save(next);
      this.state = next;
      return { accepted: batch.events.length, idempotent: false };
    });
    this.serial = operation.catch(() => {});
    return operation;
  }

  async snapshot({ tenantId, deploymentId } = {}) {
    await this.initialize();
    await this.serial;
    if (this.store.shared) this.state = validateState(await this.store.load(), this.maximumDeployments);
    const record = this.state.deployments[deploymentId];
    if (!record || record.tenantId !== tenantId) throw new Error('Console deployment is unavailable');
    return copy(record.snapshot);
  }

  async updateAlert({ tenantId, deploymentId } = {}, alertId, { status, actor, reason, at = this.clock() } = {}) {
    if (!TENANT_ID.test(tenantId || '') || !DEPLOYMENT_ID.test(deploymentId || '') || !ALERT_ID.test(alertId || '')) throw new Error('SaaS alert update identity is invalid');
    if (!ALERT_STATUSES.has(status) || typeof actor !== 'string' || !actor.trim()) throw new Error('SaaS alert update is invalid');
    if (reason !== undefined && typeof reason !== 'string') throw new Error('SaaS alert reason must be text');
    const normalizedReason = reason?.trim() || '';
    if (normalizedReason && (normalizedReason.length < 3 || normalizedReason.length > 1000)) throw new Error('SaaS alert reason must be between 3 and 1000 characters when provided');
    const timestamp = at instanceof Date ? at : new Date(at);
    if (Number.isNaN(timestamp.getTime())) throw new Error('SaaS alert update time is invalid');
    await this.initialize();
    const operation = this.serial.then(async () => {
      if (this.store.shared) this.state = validateState(await this.store.load(), this.maximumDeployments);
      const next = copy(this.state);
      const record = next.deployments[deploymentId];
      if (!record || record.tenantId !== tenantId || record.status === 'uninstalled') throw new Error('Console deployment is unavailable');
      const alert = record.snapshot.alerts.find((item) => item.id === alertId);
      if (!alert) throw new Error('Console alert is unavailable');
      if (alert.status === status) return copy(alert);
      alert.status = status;
      alert.statusHistory = Array.isArray(alert.statusHistory) ? alert.statusHistory : [];
      alert.statusHistory.push({ status, actor: actor.trim(), at: timestamp.toISOString(), ...(normalizedReason ? { reason: normalizedReason } : {}) });
      alert.statusHistory = alert.statusHistory.slice(-32);
      record.alertOverrides[alertId] = { status, statusHistory: copy(alert.statusHistory) };
      await this.store.save(next);
      this.state = next;
      return copy(alert);
    });
    this.serial = operation.catch(() => {});
    return operation;
  }

  async listDeployments({ tenantId } = {}) {
    if (typeof tenantId !== 'string' || !TENANT_ID.test(tenantId)) throw new Error('Console tenant is invalid');
    await this.initialize();
    await this.serial;
    if (this.store.shared) this.state = validateState(await this.store.load(), this.maximumDeployments);
    return Object.values(this.state.deployments)
      .filter((record) => record.tenantId === tenantId)
      .sort((left, right) => Date.parse(right.updatedAt) - Date.parse(left.updatedAt) || left.deploymentId.localeCompare(right.deploymentId))
      .map((record) => ({ deployment_id: record.deploymentId, status: record.status, updated_at: record.updatedAt, ...(record.uninstalledAt ? { uninstalled_at: record.uninstalledAt } : {}), ...(record.recovery ? { recovery: copy(record.recovery) } : {}) }));
  }

  async missingCentral({ thresholdMs = 5 * 60 * 1000, now = this.clock() } = {}) {
    if (!Number.isSafeInteger(thresholdMs) || thresholdMs < 1000) throw new Error('Central heartbeat threshold is invalid');
    await this.initialize();
    await this.serial;
    if (this.store.shared) this.state = validateState(await this.store.load(), this.maximumDeployments);
    const timestamp = (now instanceof Date ? now : new Date(now)).getTime();
    return Object.values(this.state.deployments).filter((record) => record.status !== 'uninstalled' && timestamp - Date.parse(record.updatedAt) >= thresholdMs).map((record) => ({ tenantId: record.tenantId, deploymentId: record.deploymentId, updatedAt: record.updatedAt, recovery: copy(record.recovery || null) }));
  }

  async markCentralMissing({ tenantId, deploymentId, recoverySessionId, notifiedAt } = {}) {
    if (!TENANT_ID.test(tenantId || '') || !DEPLOYMENT_ID.test(deploymentId || '') || typeof recoverySessionId !== 'string' || Number.isNaN(Date.parse(notifiedAt))) throw new Error('Central recovery state is invalid');
    await this.initialize();
    const operation = this.serial.then(async () => {
      if (this.store.shared) this.state = validateState(await this.store.load(), this.maximumDeployments);
      const next = copy(this.state);
      const record = next.deployments[deploymentId];
      if (!record || record.tenantId !== tenantId || record.status === 'uninstalled') throw new Error('Console deployment is unavailable');
      record.status = 'central_missing';
      record.recovery = { session_id: recoverySessionId, notified_at: notifiedAt };
      record.snapshot.health.status = 'central_missing';
      await this.store.save(next);
      this.state = next;
      return { status: record.status };
    });
    this.serial = operation.catch(() => {});
    return operation;
  }

  async markUninstalled(principal) {
    if (!principal || typeof principal.tenantId !== 'string' || !TENANT_ID.test(principal.tenantId) || !DEPLOYMENT_ID.test(principal.deploymentId || '')) throw new Error('Console principal is invalid');
    await this.initialize();
    const operation = this.serial.then(async () => {
      if (this.store.shared) this.state = validateState(await this.store.load(), this.maximumDeployments);
      const next = copy(this.state);
      const existing = next.deployments[principal.deploymentId];
      if (!existing || existing.tenantId !== principal.tenantId) throw new Error('Console deployment is unavailable');
      if (existing.status === 'uninstalled') return { status: 'uninstalled', idempotent: true };
      const now = this.clock();
      const uninstalledAt = (now instanceof Date ? now : new Date(now)).toISOString();
      next.deployments[principal.deploymentId] = {
        ...existing,
        status: 'uninstalled',
        uninstalledAt,
        updatedAt: uninstalledAt,
        snapshot: buildUninstalledConsoleSnapshot({ deploymentId: principal.deploymentId, generatedAt: uninstalledAt }),
        alertOverrides: {}
      };
      await this.store.save(next);
      this.state = next;
      return { status: 'uninstalled', idempotent: false };
    });
    this.serial = operation.catch(() => {});
    return operation;
  }

  async markReplaced({ tenantId, deploymentId } = {}) {
    if (typeof tenantId !== 'string' || !TENANT_ID.test(tenantId) || !DEPLOYMENT_ID.test(deploymentId || '')) throw new Error('Console replacement is invalid');
    await this.initialize();
    const operation = this.serial.then(async () => {
      if (this.store.shared) this.state = validateState(await this.store.load(), this.maximumDeployments);
      const next = copy(this.state);
      const existing = next.deployments[deploymentId];
      if (!existing) return { status: 'absent', idempotent: true };
      if (existing.tenantId !== tenantId) throw new Error('Console deployment is unavailable');
      if (existing.status === 'uninstalled') return { status: 'uninstalled', idempotent: true };
      const now = this.clock();
      const uninstalledAt = (now instanceof Date ? now : new Date(now)).toISOString();
      next.deployments[deploymentId] = {
        ...existing,
        status: 'uninstalled',
        uninstalledAt,
        updatedAt: uninstalledAt,
        snapshot: buildUninstalledConsoleSnapshot({ deploymentId, generatedAt: uninstalledAt }),
        alertOverrides: {}
      };
      await this.store.save(next);
      this.state = next;
      return { status: 'uninstalled', idempotent: false };
    });
    this.serial = operation.catch(() => {});
    return operation;
  }

  async resetForRetry({ tenantId, deploymentId } = {}) {
    if (typeof tenantId !== 'string' || !TENANT_ID.test(tenantId) || !DEPLOYMENT_ID.test(deploymentId || '')) throw new Error('Console deployment retry is invalid');
    await this.initialize();
    const operation = this.serial.then(async () => {
      if (this.store.shared) this.state = validateState(await this.store.load(), this.maximumDeployments);
      const next = copy(this.state);
      const existing = next.deployments[deploymentId];
      if (!existing) return { status: 'absent', idempotent: true };
      if (existing.tenantId !== tenantId) throw new Error('Console deployment is unavailable');
      delete next.deployments[deploymentId];
      await this.store.save(next);
      this.state = next;
      return { status: 'reset', idempotent: false };
    });
    this.serial = operation.catch(() => {});
    return operation;
  }

  async deleteTenant({ tenantId } = {}) {
    if (typeof tenantId !== 'string' || !TENANT_ID.test(tenantId)) throw new Error('Console tenant is invalid');
    await this.initialize();
    const operation = this.serial.then(async () => {
      if (this.store.shared) this.state = validateState(await this.store.load(), this.maximumDeployments);
      const next = copy(this.state);
      const deployments = Object.values(next.deployments).filter((record) => record.tenantId === tenantId).map((record) => record.deploymentId);
      for (const deploymentId of deployments) delete next.deployments[deploymentId];
      if (!next.deletedTenants.includes(tenantId)) {
        if (next.deletedTenants.length >= 100000) throw new Error('Console tenant deletion capacity reached');
        next.deletedTenants.push(tenantId);
        next.deletedTenants.sort();
      }
      await this.store.save(next);
      this.state = next;
      return { removedDeployments: deployments.length };
    });
    this.serial = operation.catch(() => {});
    return operation;
  }

  async restoreTenantAfterFailedDeletion({ tenantId } = {}) {
    if (typeof tenantId !== 'string' || !TENANT_ID.test(tenantId)) throw new Error('Console tenant is invalid');
    await this.initialize();
    const operation = this.serial.then(async () => {
      if (this.store.shared) this.state = validateState(await this.store.load(), this.maximumDeployments);
      const next = copy(this.state);
      const before = next.deletedTenants.length;
      next.deletedTenants = next.deletedTenants.filter((candidate) => candidate !== tenantId);
      await this.store.save(next);
      this.state = next;
      return { restored: next.deletedTenants.length !== before };
    });
    this.serial = operation.catch(() => {});
    return operation;
  }
}

module.exports = { SaasConsoleStore, validateConsoleBatch: validateBatch };

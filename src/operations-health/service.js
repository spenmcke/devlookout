'use strict';

const { stableId } = require('../core/canonical');
const { validateOperationalHealthSnapshot } = require('./snapshot');

const GIB = 1024 * 1024 * 1024;
const SEVERITY_RANK = { warning: 1, critical: 2 };

function finitePercent(value) {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= 100 ? value : null;
}

function conditionsForNode(node) {
  const conditions = [];
  const memory = finitePercent(node.host.memory.usedPercent);
  if (memory !== null) conditions.push({ key: `${node.collectorId}:vm_memory`, label: 'VM memory usage', value: memory, unit: 'percent', warning: memory >= 85, critical: memory >= 95 });
  const cpu = finitePercent(node.host.cpu.usedPercent);
  if (cpu !== null) conditions.push({ key: `${node.collectorId}:vm_cpu`, label: 'VM CPU usage', value: cpu, unit: 'percent', warning: cpu >= 90, critical: false });
  for (const volume of node.host.filesystems.volumes) {
    const used = finitePercent(volume.usedPercent);
    if (used === null) continue;
    conditions.push({
      key: `${node.collectorId}:filesystem:${volume.id}`, label: volume.dataVolume ? 'Lookout data filesystem usage' : 'VM filesystem usage', value: used, unit: 'percent',
      warning: used >= 80, critical: used >= 90 || ((volume.dataVolume || volume.root) && Number.isFinite(volume.availableBytes) && volume.availableBytes <= 5 * GIB),
      availableBytes: volume.availableBytes, dataVolume: volume.dataVolume, root: volume.root
    });
  }
  const totalMemory = node.host.memory.totalBytes;
  const resident = node.lookout.process.memory.residentBytes;
  if (Number.isFinite(totalMemory) && totalMemory > 0 && Number.isFinite(resident)) {
    const processPercent = Math.round((resident / totalMemory * 100) * 100) / 100;
    conditions.push({ key: `${node.collectorId}:lookout_memory`, label: 'Lookout process memory usage', value: processPercent, unit: 'percent_of_vm', warning: processPercent >= 25, critical: processPercent >= 40 });
  }
  const lookoutCpu = finitePercent(node.lookout.process.cpu.usedPercent);
  if (lookoutCpu !== null) conditions.push({ key: `${node.collectorId}:lookout_cpu`, label: 'Lookout process CPU usage', value: lookoutCpu, unit: 'percent', warning: lookoutCpu >= 90, critical: false });
  for (const queue of node.lookout.delivery.queues) {
    if (!Number.isSafeInteger(queue.pending)) continue;
    conditions.push({ key: `${node.collectorId}:queue:${queue.id}`, label: 'Lookout delivery backlog', value: queue.pending, unit: 'records', warning: queue.pending >= 1000, critical: queue.pending >= 5000 });
  }
  return conditions;
}

function rowToState(row) {
  if (!row) return null;
  return {
    status: row.status, severity: row.severity, openedAt: row.opened_at, updatedAt: row.updated_at,
    resolvedAt: row.resolved_at, lastNotifiedAt: row.last_notified_at, details: row.details || {}
  };
}

class OperationalHealthService {
  constructor({ store, now = () => new Date(), notificationChannel = null } = {}) {
    if (!store || typeof store.insertSample !== 'function' || typeof store.getAlertState !== 'function') throw new TypeError('Operational health store is required');
    if (![null, 'slack', 'email'].includes(notificationChannel)) throw new Error('Operational health notification channel is invalid');
    this.store = store;
    this.now = now;
    this.notificationChannel = notificationChannel;
  }

  async acceptSnapshot(principal, snapshot) {
    validateOperationalHealthSnapshot(snapshot);
    if (!principal || principal.deploymentId !== snapshot.deploymentId || typeof principal.tenantId !== 'string') throw new Error('Operational health deployment identity mismatch');
    const receivedAt = this.now();
    if (!(receivedAt instanceof Date) || Number.isNaN(receivedAt.getTime())) throw new Error('Operational health clock is invalid');
    let accepted = 0;
    for (const node of snapshot.nodes) {
      const observed = Date.parse(node.observedAt);
      if (observed > receivedAt.getTime() + 10 * 60 * 1000) throw new Error('Operational health sample timestamp is outside the accepted window');
      if (observed < receivedAt.getTime() - 8 * 24 * 60 * 60 * 1000) continue;
      const sampleId = stableId('ops_sample', { deploymentId: principal.deploymentId, collectorId: node.collectorId, collectorSequence: node.collectorSequence });
      const inserted = await this.store.insertSample({ sampleId, tenantId: principal.tenantId, deploymentId: principal.deploymentId, collectorId: node.collectorId, sampledAt: node.observedAt, payload: node });
      accepted += 1;
      if (inserted?.inserted === false) continue;
      for (const condition of conditionsForNode(node)) await this.#evaluate(principal, condition, receivedAt);
      await this.#evaluate(principal, { key: `${node.collectorId}:telemetry_missing`, label: 'VM operational telemetry missing', value: 0, unit: 'missing', warning: false, critical: false }, receivedAt);
    }
    return { accepted };
  }

  async #evaluate(principal, condition, now, { forceOpen = false } = {}) {
    const row = await this.store.getAlertState({ tenantId: principal.tenantId, deploymentId: principal.deploymentId, alertKey: condition.key });
    const existing = rowToState(row);
    const desiredSeverity = condition.critical ? 'critical' : condition.warning ? 'warning' : null;
    if (!desiredSeverity) {
      if (!existing || existing.status === 'resolved') return;
      if (existing.status === 'pending') {
        await this.#save(principal, condition, { status: 'resolved', severity: existing.severity, openedAt: existing.openedAt, updatedAt: now.toISOString(), resolvedAt: now.toISOString(), lastNotifiedAt: existing.lastNotifiedAt, details: { ...existing.details, healthySamples: 1 } });
        return;
      }
      const healthySamples = Number(existing.details.healthySamples || 0) + 1;
      if (healthySamples < 2) {
        await this.#save(principal, condition, { ...existing, updatedAt: now.toISOString(), details: { ...existing.details, healthySamples } });
        return;
      }
      const next = { ...existing, status: 'resolved', updatedAt: now.toISOString(), resolvedAt: now.toISOString(), details: { ...existing.details, healthySamples } };
      await this.#notify(principal, condition, next, 'recovered');
      await this.#save(principal, condition, next);
      return;
    }

    const severityChanged = existing?.severity !== desiredSeverity;
    const conditionSince = existing && existing.status !== 'resolved' && !severityChanged ? existing.details.conditionSince : now.toISOString();
    const requiredMs = forceOpen ? 0 : desiredSeverity === 'critical' ? 5 * 60 * 1000 : 15 * 60 * 1000;
    const mature = now.getTime() - Date.parse(conditionSince) >= requiredMs;
    const remainsOpen = existing?.status === 'open' && SEVERITY_RANK[existing.severity] >= SEVERITY_RANK[desiredSeverity];
    const status = mature || remainsOpen ? 'open' : 'pending';
    const openedAt = existing && existing.status !== 'resolved' ? existing.openedAt : now.toISOString();
    const next = {
      status, severity: desiredSeverity, openedAt, updatedAt: now.toISOString(), resolvedAt: null,
      lastNotifiedAt: existing?.lastNotifiedAt || null,
      details: { ...condition, conditionSince, healthySamples: 0 }
    };
    if (status === 'open' && (existing?.status !== 'open' || SEVERITY_RANK[desiredSeverity] > SEVERITY_RANK[existing.severity])) {
      const transition = existing?.status === 'open' ? 'escalated' : 'opened';
      if (!existing) await this.#save(principal, condition, { ...next, status: 'pending' });
      await this.#notify(principal, condition, next, transition);
    }
    await this.#save(principal, condition, next);
  }

  #save(principal, condition, state) {
    return this.store.upsertAlertState({ tenantId: principal.tenantId, deploymentId: principal.deploymentId, alertKey: condition.key, ...state });
  }

  async #notify(principal, condition, state, transition) {
    if (!this.notificationChannel) return;
    const transitionAt = state.updatedAt;
    const transitionAnchor = transition === 'recovered' ? state.openedAt : state.details.conditionSince;
    const idempotencyKey = stableId('ops_notification', { deploymentId: principal.deploymentId, alertKey: condition.key, transition, transitionAnchor, severity: state.severity, channel: this.notificationChannel });
    await this.store.enqueueNotification({
      outboxId: stableId('ops_outbox', idempotencyKey), idempotencyKey, tenantId: principal.tenantId, deploymentId: principal.deploymentId,
      alertKey: condition.key, channel: this.notificationChannel, nextAttemptAt: transitionAt,
      payload: { transition, severity: state.severity, deploymentId: principal.deploymentId, resource: condition.key, label: condition.label, value: condition.value, unit: condition.unit, observedAt: transitionAt }
    });
  }

  async sweepMissing() {
    const now = this.now();
    const missing = await this.store.missingTelemetry({ now, thresholdMinutes: 15 });
    for (const target of missing) {
      const principal = { tenantId: target.tenant_id, deploymentId: target.deployment_id };
      await this.#evaluate(principal, { key: `${target.collector_id}:telemetry_missing`, label: 'VM operational telemetry missing', value: 1, unit: 'missing', warning: false, critical: true }, now, { forceOpen: true });
    }
    return { missing: missing.length };
  }

  listAlerts(options) { return this.store.listAlertStates(options); }
  recentSamples(options) { return this.store.recentSamples(options); }
  recentDeploymentSamples(options) { return this.store.recentDeploymentSamples(options); }
  deleteExpired() { return this.store.deleteExpired({ now: this.now() }); }
  deleteDeployment(principal) { return this.store.deleteDeployment(principal); }
  deleteTenant(tenantId) { return this.store.deleteTenant(tenantId); }
}

module.exports = { OperationalHealthService, conditionsForNode };

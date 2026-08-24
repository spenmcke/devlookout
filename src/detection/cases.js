'use strict';

const { stableId } = require('../core/canonical');
const ALERT_STATUSES = new Set(['open', 'to_fix', 'closed']);
const CASE_LIMITS = Object.freeze({ findings: 4096, alerts: 2048, incidents: 1024, audit: 2048 });

function trimMap(map, limit, timeField) {
  if (map.size <= limit) return;
  const retained = [...map.values()].sort((left, right) => String(right[timeField] || '').localeCompare(String(left[timeField] || '')) || left.id.localeCompare(right.id)).slice(0, limit);
  map.clear();
  for (const value of retained) map.set(value.id, value);
}

function overlap(left, right) {
  const values = new Set(left);
  return right.some((value) => values.has(value));
}

function duplicateSequenceAlert(left, right) {
  return left.analyticKind === 'sequence' && right.analyticKind === 'sequence'
    && left.ruleId === right.ruleId && left.time === right.time
    && Array.isArray(left.evidence) && left.evidence.length > 0
    && Array.isArray(right.evidence) && overlap(left.evidence, right.evidence);
}

function toAlert(finding) {
  return {
    schemaVersion: 1,
    id: stableId('alert', finding.id),
    findingId: finding.id,
    title: finding.title,
    ruleId: finding.ruleId,
    severity: finding.severity,
    severityScore: finding.severityScore,
    time: finding.time,
    firstSeen: finding.firstSeen,
    status: 'open',
    statusHistory: [{ status: 'open', actor: 'lookout', at: finding.time, reason: 'Created from a detection rule match.' }],
    entities: [...finding.entities],
    evidence: [...finding.evidence],
    confidence: finding.confidence,
    analyticKind: finding.kind,
    matchReason: finding.rationale
  };
}

// Findings are the complete evidence stream. The review queue is intentionally
// narrower: behavioral anomalies and medium-confidence observations must first
// correlate with stronger deterministic evidence.
function alertEligible(finding) {
  if (finding.alertDisposition === 'always') return true;
  if (finding.alertDisposition === 'correlation_only') return false;
  return finding.kind !== 'behavioral' && finding.severityScore >= 8;
}

function correlateFindings(findings, { windowSeconds = 900 } = {}) {
  const sorted = [...findings].sort((a, b) => a.time.localeCompare(b.time) || a.id.localeCompare(b.id));
  const clusters = [];
  for (const finding of sorted) {
    const candidates = clusters.filter((cluster) => Date.parse(finding.time) - Date.parse(cluster.lastSeen) <= windowSeconds * 1000 && overlap(cluster.entities, finding.entities));
    if (!candidates.length) {
      clusters.push({ findings: [finding], entities: [...finding.entities], firstSeen: finding.firstSeen, lastSeen: finding.time });
      continue;
    }
    const target = candidates[0];
    target.findings.push(finding);
    target.entities = [...new Set([...target.entities, ...finding.entities])].sort();
    target.firstSeen = target.firstSeen < finding.firstSeen ? target.firstSeen : finding.firstSeen;
    target.lastSeen = target.lastSeen > finding.time ? target.lastSeen : finding.time;
  }
  return clusters;
}

function incidentEligible(cluster) {
  const distinctRules = new Set(cluster.findings.map((finding) => finding.ruleId));
  const allBehavioral = cluster.findings.every((finding) => finding.kind === 'behavioral');
  const strongEvidence = cluster.findings.some((finding) => ['sequence', 'threshold', 'event'].includes(finding.kind) && finding.severityScore >= 8);
  return cluster.findings.length >= 2 && distinctRules.size >= 2 && !allBehavioral && strongEvidence;
}

function incidentFromCluster(cluster) {
  const findings = cluster.findings.map((finding) => finding.id).sort();
  const evidence = [...new Set(cluster.findings.flatMap((finding) => finding.evidence))].sort();
  const maximum = [...cluster.findings].sort((a, b) => b.severityScore - a.severityScore || a.id.localeCompare(b.id))[0];
  return {
    schemaVersion: 1,
    id: stableId('incident', { findings }),
    title: maximum.title,
    severity: maximum.severity,
    severityScore: maximum.severityScore,
    status: 'open',
    firstSeen: cluster.firstSeen,
    lastSeen: cluster.lastSeen,
    findings,
    evidence,
    entities: [...cluster.entities],
    rationale: `${findings.length} distinct findings share security-relevant entities within the correlation window.`
  };
}

class CaseManager {
  #findings = new Map();
  #alerts = new Map();
  #incidents = new Map();
  #audit = [];

  ingest(findings, options) {
    for (const finding of findings) {
      if (this.#findings.has(finding.id)) continue;
      this.#findings.set(finding.id, structuredClone(finding));
      if (alertEligible(finding)) {
        const alert = toAlert(finding);
        this.#alerts.set(alert.id, alert);
      }
    }
    for (const cluster of correlateFindings([...this.#findings.values()], options)) {
      if (!incidentEligible(cluster)) continue;
      const incident = incidentFromCluster(cluster);
      this.#incidents.set(incident.id, incident);
    }
    this.#prune();
    return this.snapshot();
  }

  #prune() {
    trimMap(this.#findings, CASE_LIMITS.findings, 'time');
    trimMap(this.#alerts, CASE_LIMITS.alerts, 'time');
    trimMap(this.#incidents, CASE_LIMITS.incidents, 'lastSeen');
    if (this.#audit.length > CASE_LIMITS.audit) this.#audit = this.#audit.slice(-CASE_LIMITS.audit);
  }

  promote(alertIds, { actor, reason, at = new Date().toISOString() }) {
    if (typeof actor !== 'string' || !actor || typeof reason !== 'string' || reason.length < 10) throw new Error('Manual promotion requires an actor and meaningful reason');
    const alerts = [...new Set(alertIds)].map((id) => this.#alerts.get(id));
    if (alerts.some((alert) => !alert)) throw new Error('Cannot promote an unknown alert');
    const findings = alerts.map((alert) => this.#findings.get(alert.findingId));
    const cluster = {
      findings,
      entities: [...new Set(alerts.flatMap((alert) => alert.entities))].sort(),
      firstSeen: [...findings].sort((a, b) => a.firstSeen.localeCompare(b.firstSeen))[0].firstSeen,
      lastSeen: [...findings].sort((a, b) => b.time.localeCompare(a.time))[0].time
    };
    const incident = incidentFromCluster(cluster);
    incident.manual = true;
    incident.promotion = { actor, reason, at };
    this.#incidents.set(incident.id, incident);
    this.#audit.push({ action: 'incident.promote', actor, reason, at, incidentId: incident.id, alertIds: alerts.map((alert) => alert.id).sort() });
    this.#prune();
    return structuredClone(incident);
  }

  updateAlert(alertId, { status, actor, reason, at = new Date().toISOString() } = {}) {
    const alert = this.#alerts.get(alertId);
    if (!alert) throw Object.assign(new Error('Alert not found'), { statusCode: 404 });
    if (!ALERT_STATUSES.has(status)) throw Object.assign(new Error('Alert status must be open, to_fix, or closed'), { statusCode: 400 });
    if (typeof actor !== 'string' || !actor.trim()) throw Object.assign(new Error('Alert status change requires an actor'), { statusCode: 400 });
    if (reason !== undefined && typeof reason !== 'string') throw Object.assign(new Error('Alert status change reason must be text'), { statusCode: 400 });
    const normalizedReason = reason?.trim() || '';
    if (normalizedReason && (normalizedReason.length < 3 || normalizedReason.length > 1000)) throw Object.assign(new Error('Alert status change reason must be between 3 and 1000 characters when provided'), { statusCode: 400 });
    if (Number.isNaN(Date.parse(at))) throw Object.assign(new Error('Alert status change time must be ISO-compatible'), { statusCode: 400 });
    if (alert.status === status) return structuredClone(alert);
    alert.status = status;
    alert.statusHistory ||= [];
    alert.statusHistory.push({ status, actor: actor.trim(), at: new Date(at).toISOString(), ...(normalizedReason ? { reason: normalizedReason } : {}) });
    return structuredClone(alert);
  }

  snapshot() {
    return {
      schemaVersion: 1,
      findings: [...this.#findings.values()].sort((a, b) => b.time.localeCompare(a.time) || a.id.localeCompare(b.id)),
      alerts: [...this.#alerts.values()].sort((a, b) => b.time.localeCompare(a.time) || a.id.localeCompare(b.id)),
      incidents: [...this.#incidents.values()].sort((a, b) => b.lastSeen.localeCompare(a.lastSeen) || a.id.localeCompare(b.id)),
      audit: [...this.#audit].sort((a, b) => a.at.localeCompare(b.at))
    };
  }

  static fromSnapshot(snapshot) {
    const manager = new CaseManager();
    if (!snapshot) return manager;
    if (snapshot.schemaVersion !== 1) throw new Error('Unsupported case snapshot');
    for (const finding of snapshot.findings || []) manager.#findings.set(finding.id, structuredClone(finding));
    const restoredAlerts = (snapshot.alerts || []).map((alert) => {
      const restored = structuredClone(alert);
      if (restored.status === 'in_review') restored.status = 'to_fix';
      if (restored.status === 'dismissed') restored.status = 'closed';
      if (!ALERT_STATUSES.has(restored.status)) throw new Error(`Unsupported alert status: ${restored.status}`);
      restored.statusHistory = Array.isArray(restored.statusHistory) ? restored.statusHistory : [];
      return restored;
    }).sort((left, right) => Number(right.status !== 'open') - Number(left.status !== 'open') || left.id.localeCompare(right.id));
    for (const restored of restoredAlerts) {
      if ([...manager.#alerts.values()].some((existing) => duplicateSequenceAlert(existing, restored))) continue;
      manager.#alerts.set(restored.id, restored);
    }
    for (const incident of snapshot.incidents || []) manager.#incidents.set(incident.id, structuredClone(incident));
    manager.#audit = structuredClone(snapshot.audit || []);
    manager.#prune();
    return manager;
  }
}

module.exports = { ALERT_STATUSES, CASE_LIMITS, alertEligible, toAlert, correlateFindings, incidentEligible, incidentFromCluster, CaseManager };

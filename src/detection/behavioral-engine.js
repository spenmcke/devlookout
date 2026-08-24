'use strict';

const { stableId } = require('../core/canonical');
const { getPath, matches } = require('./predicates');
const { SetBaseline, RobustNumericBaseline } = require('./baselines');

const defaultBehavioralAnalytics = [
  {
    id: 'novel-identity-authentication-target', version: '1.0.0', title: 'Identity authenticated to a new system', severity: 'medium', severityScore: 5,
    selector: { class: 'authentication', outcome: 'success' }, scopePath: 'actor.id', featurePath: 'destinationEndpoint.id', model: 'set',
    parameters: { minimumObservations: 3, noveltySeconds: 259200, maximumValues: 512 }
  },
  {
    id: 'novel-network-relationship', version: '1.0.0', title: 'New network relationship', severity: 'medium', severityScore: 5,
    selector: { category: 'network' }, scopePath: 'sourceEndpoint.id', featurePath: 'destinationEndpoint.id', model: 'set',
    parameters: { minimumObservations: 3, noveltySeconds: 259200, maximumValues: 1024 }
  },
  {
    id: 'novel-host-executable', version: '1.0.0', title: 'Host executed a previously unseen program', severity: 'medium', severityScore: 5,
    selector: { class: 'process_activity', activity: 'start' }, scopePath: 'destinationEndpoint.id', featurePath: 'attributes.executable', model: 'set',
    parameters: { minimumObservations: 5, noveltySeconds: 259200, maximumValues: 1024 }
  },
  {
    id: 'novel-process-destination', version: '1.0.0', title: 'Process contacted a new destination', severity: 'medium', severityScore: 5,
    selector: { category: 'network', 'attributes.processExecutable': { exists: true } }, scopePath: 'attributes.processExecutable', featurePath: 'destinationEndpoint.id', model: 'set',
    parameters: { minimumObservations: 3, noveltySeconds: 259200, maximumValues: 1024 }
  },
  {
    id: 'novel-privilege-target', version: '1.0.0', title: 'Identity used a new privilege target', severity: 'medium', severityScore: 5,
    selector: { class: 'privilege_use' }, scopePath: 'actor.id', featurePath: 'actor.targetId', model: 'set',
    parameters: { minimumObservations: 3, noveltySeconds: 259200, maximumValues: 256 }
  },
  {
    id: 'novel-resource-access', version: '1.0.0', title: 'Identity accessed a new protected resource', severity: 'medium', severityScore: 5,
    selector: { class: 'resource_access', outcome: 'success' }, scopePath: 'actor.id', featurePath: 'attributes.resourceId', model: 'set',
    parameters: { minimumObservations: 3, noveltySeconds: 259200, maximumValues: 1024 }
  },
  {
    id: 'unusual-identity-hour-of-week', version: '1.0.0', title: 'Identity acted during an unusual hour of the week', severity: 'medium', severityScore: 5,
    selector: { category: 'identity', 'actor.id': { exists: true } }, scopePath: 'actor.id', featureDerived: 'hour_of_week', model: 'set',
    parameters: { minimumObservations: 3, noveltySeconds: 1209600, maximumValues: 168 }
  },
  {
    id: 'peer-group-executable-novelty', version: '1.0.0', title: 'Endpoint behavior differed from comparable peers', severity: 'medium', severityScore: 5,
    selector: { class: 'process_activity', activity: 'start' }, scopeDerived: 'endpoint_peer_group', endpointPath: 'destinationEndpoint.id', featurePath: 'attributes.executable', model: 'set',
    parameters: { minimumObservations: 5, noveltySeconds: 259200, maximumValues: 1024 }
  },
  {
    id: 'novel-data-movement-path', version: '1.0.0', title: 'Data resource moved to a new destination', severity: 'medium', severityScore: 5,
    selector: { category: 'network', 'attributes.resourceId': { exists: true } }, scopePath: 'attributes.resourceId', featurePath: 'destinationEndpoint.id', model: 'set',
    parameters: { minimumObservations: 3, noveltySeconds: 259200, maximumValues: 512 }
  },
  {
    id: 'unusual-egress-volume', version: '1.0.0', title: 'Unusual outbound data volume', severity: 'medium', severityScore: 5,
    selector: { category: 'network' }, scopePath: 'sourceEndpoint.id', featurePath: 'attributes.bytesSent', model: 'robust_numeric',
    parameters: { minimumSamples: 12, warningDeviations: 6, criticalDeviations: 10, maximumSamples: 672 }
  }
];

function derivedValue(kind, event, analytic, context) {
  if (kind === 'hour_of_week') {
    const date = new Date(event.time);
    if (Number.isNaN(date.getTime())) return null;
    return date.getUTCDay() * 24 + date.getUTCHours();
  }
  if (kind === 'endpoint_peer_group') {
    const endpoint = getPath(event, analytic.endpointPath || 'destinationEndpoint.id');
    return endpoint == null ? null : context.endpointPeerGroups?.[String(endpoint)] || null;
  }
  return null;
}

function dimension(analytic, name, event, context) {
  const derived = analytic[`${name}Derived`];
  if (derived) return derivedValue(derived, event, analytic, context);
  return getPath(event, analytic[`${name}Path`]);
}

class BehavioralEngine {
  constructor({ analytics = defaultBehavioralAnalytics, maximumModels = 256 } = {}) {
    if (!Number.isSafeInteger(maximumModels) || maximumModels < 1) throw new Error('maximumModels must be a positive safe integer');
    this.analytics = structuredClone(analytics);
    this.maximumModels = maximumModels;
    this.models = new Map();
  }

  #model(analytic, scope) {
    const key = `${analytic.id}\0${scope}`;
    if (!this.models.has(key)) {
      if (this.models.size >= this.maximumModels) return null;
      const model = analytic.model === 'set' ? new SetBaseline(analytic.parameters) : new RobustNumericBaseline(analytic.parameters);
      this.models.set(key, model);
    }
    return this.models.get(key);
  }

  observe(events, { protectedEventIds = new Set(), context = {} } = {}) {
    const findings = [];
    for (const event of [...events].sort((a, b) => a.time.localeCompare(b.time) || a.id.localeCompare(b.id))) {
      for (const analytic of this.analytics) {
        if (!matches(event, analytic.selector)) continue;
        const scope = dimension(analytic, 'scope', event, context);
        const feature = dimension(analytic, 'feature', event, context);
        if (scope == null || feature == null || (analytic.model === 'robust_numeric' && !Number.isFinite(feature))) continue;
        const model = this.#model(analytic, String(scope));
        if (!model) continue;
        const result = model.observe
          ? model.observe(String(feature), event.time, { activeAlert: protectedEventIds.has(event.id) })
          : model.score(feature, { activeAlert: protectedEventIds.has(event.id) });
        if (!result.anomaly) continue;
        findings.push({
          schemaVersion: 1,
          id: stableId('finding', { analytic: analytic.id, version: analytic.version, event: event.id, scope, feature }),
          ruleId: analytic.id,
          ruleVersion: analytic.version,
          title: analytic.title,
          severity: analytic.severity,
          severityScore: analytic.severityScore,
          alertDisposition: 'correlation_only',
          kind: 'behavioral',
          time: event.time,
          firstSeen: event.time,
          confidence: result.state === 'critical' ? 0.9 : analytic.model === 'set' ? 0.65 : 0.7,
          status: 'open',
          evidence: [event.id],
          entities: [...event.entityKeys],
          rationale: analytic.model === 'set' ? result.reason : `Value ${feature} is ${result.robustDeviation.toFixed(2)} robust deviations from baseline center ${result.center}.`,
          baseline: { analyticId: analytic.id, scope: String(scope), feature, result }
        });
      }
    }
    return findings.sort((a, b) => b.time.localeCompare(a.time) || a.id.localeCompare(b.id));
  }

  snapshot() {
    return {
      schemaVersion: 1,
      maximumModels: this.maximumModels,
      analytics: structuredClone(this.analytics),
      models: [...this.models.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([key, model]) => ({ key, state: model.snapshot() }))
    };
  }

  static fromSnapshot(snapshot) {
    if (!snapshot) return new BehavioralEngine();
    if (snapshot.schemaVersion !== 1) throw new Error('Unsupported behavioral baseline snapshot');
    const defaultIds = new Set(defaultBehavioralAnalytics.map((analytic) => analytic.id));
    const customAnalytics = (snapshot.analytics || []).filter((analytic) => !defaultIds.has(analytic.id));
    const engine = new BehavioralEngine({ analytics: [...defaultBehavioralAnalytics, ...customAnalytics], maximumModels: snapshot.maximumModels || 256 });
    if ((snapshot.models || []).length > engine.maximumModels) throw new Error('Behavioral baseline snapshot exceeds model capacity');
    for (const item of snapshot.models || []) {
      const model = item.state.kind === 'set' ? SetBaseline.fromSnapshot(item.state) : RobustNumericBaseline.fromSnapshot(item.state);
      engine.models.set(item.key, model);
    }
    return engine;
  }
}

module.exports = { defaultBehavioralAnalytics, derivedValue, dimension, BehavioralEngine };

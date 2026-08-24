'use strict';

const path = require('node:path');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const v8 = require('node:v8');
const { version } = require('../package.json');
const { SecurityGraph } = require('./graph/security-graph');
const { SnapshotStore } = require('./storage/snapshot-store');
const { EventStore } = require('./storage/event-store');
const { validateEvent, createEvent } = require('./events/schema');
const { planAnalytics } = require('./detection/planner');
const { evaluate } = require('./detection/engine');
const { validateRule } = require('./detection/engine');
const { CaseManager } = require('./detection/cases');
const { analytics: defaultAnalytics } = require('./detection/catalog');
const { prioritizeBehaviors } = require('./detection/behaviors');
const { BehavioralEngine } = require('./detection/behavioral-engine');
const { NormalizerRegistry } = require('./normalizers/contract');
const { zeekNormalizer } = require('./normalizers/zeek');
const { syslogNormalizer } = require('./normalizers/syslog');
const { openTelemetryNormalizer } = require('./normalizers/opentelemetry');
const { tailscaleLogNormalizer } = require('./normalizers/tailscale-logs');
const { linuxJournalNormalizer } = require('./normalizers/linux-journal');
const { createFact } = require('./adapters/contract');
const { buildConsoleSnapshot } = require('./console/snapshot');

function telemetryFacts(events, knownEntityKeys = new Set()) {
  if (!events.length) return [];
  const capabilities = new Set();
  for (const event of events) {
    if (event.category === 'network' && event.class === 'network_activity') capabilities.add('network_flow');
    if (event.class === 'dns_activity') capabilities.add('dns');
    if (['authentication', 'authentication_log'].includes(event.class)) capabilities.add('authentication');
    if (event.category === 'configuration') capabilities.add('configuration_change');
    if (['resource_access', 'authorization'].includes(event.class)) capabilities.add('resource_access');
    if (event.class === 'process_activity') capabilities.add('process_execution');
    if (['file_activity', 'archive_activity'].includes(event.class)) capabilities.add('file_access');
    if (event.class === 'group_management') capabilities.add('privilege_use');
    if (event.category === 'health' && event.class === 'sensor_activity') capabilities.add('sensor_health');
    if (event.class === 'http_activity') capabilities.add('http_transaction');
  }
  if (!capabilities.size) return [];
  const { adapter, instance } = events[0].source;
  const entityKey = `telemetry:${adapter}:${instance}`;
  const observedAt = events.reduce((latest, event) => event.ingestedAt > latest ? event.ingestedAt : latest, events[0].ingestedAt);
  const source = (recordId) => ({ adapter: 'normalizer-observation', instance: `${adapter}:${instance}`, recordId });
  return [
    createFact({ kind: 'entity', observedAt, source: source('source'), data: { entityKey, entityType: 'telemetry', name: `${adapter} · ${instance}`, attributes: { adapter, instance } } }),
    ...[...capabilities].sort().map((capability) => createFact({ kind: 'capability', observedAt, source: source(`capability:${capability}`), data: { entityKey, capability, status: 'available' } })),
    ...[...new Set(events.flatMap((event) => event.entityKeys).filter((key) => knownEntityKeys.has(key)))].sort().map((observedKey) => createFact({
      kind: 'relationship', observedAt, source: source(`observes:${observedKey}`), data: { from: entityKey, to: observedKey, relation: 'observes' }
    }))
  ];
}

function behavioralContext(graphSnapshot) {
  const endpointPeerGroups = {};
  for (const entity of graphSnapshot.entities || []) {
    if (entity.type !== 'endpoint') continue;
    const role = typeof entity.role === 'string' && entity.role ? `role:${entity.role}` : null;
    const tags = Array.isArray(entity.tags) && entity.tags.length ? `tags:${[...entity.tags].sort().join(',')}` : null;
    const platform = typeof entity.platform === 'string' && entity.platform ? `platform:${entity.platform}` : null;
    endpointPeerGroups[entity.key] = role || tags || platform || 'endpoint:unclassified';
  }
  return { endpointPeerGroups };
}

async function directoryBytes(directory) {
  let total = 0;
  for (const entry of await fs.readdir(directory, { withFileTypes: true })) {
    const filename = path.join(directory, entry.name);
    if (entry.isSymbolicLink()) continue;
    if (entry.isDirectory()) total += await directoryBytes(filename);
    else if (entry.isFile()) total += (await fs.stat(filename)).size;
  }
  return total;
}

class LookoutRuntime {
  constructor({ dataDirectory, analytics = defaultAnalytics, normalizers = [], protector = null, requireEncryption = false, maximumStoragePercent = 2, cloudExport = null, alertWebhook = null } = {}) {
    if (!dataDirectory || !path.isAbsolute(dataDirectory)) throw new Error('LookoutRuntime requires an absolute dataDirectory');
    this.dataDirectory = path.resolve(dataDirectory);
    if (typeof maximumStoragePercent !== 'number' || !Number.isFinite(maximumStoragePercent) || maximumStoragePercent < 0.1 || maximumStoragePercent > 20) throw new Error('LookoutRuntime storage percentage is invalid');
    this.maximumStoragePercent = maximumStoragePercent;
    this.storageBudget = null;
    const storageOptions = { protector, requireEncryption };
    this.graphStore = new SnapshotStore(this.dataDirectory, 'graph.snapshot.json', storageOptions);
    this.caseStore = new SnapshotStore(this.dataDirectory, 'cases.snapshot.json', storageOptions);
    this.baselineStore = new SnapshotStore(this.dataDirectory, 'baselines.snapshot.json', storageOptions);
    this.detectionStateStore = new SnapshotStore(this.dataDirectory, 'detection-state.snapshot.json', storageOptions);
    this.ruleStore = new SnapshotStore(this.dataDirectory, 'rules.snapshot.json', storageOptions);
    this.eventStore = new EventStore(this.dataDirectory, storageOptions);
    this.auditStore = new EventStore(this.dataDirectory, { ...storageOptions, filename: 'audit.jsonl' });
    this.analytics = structuredClone(analytics);
    this.graph = new SecurityGraph();
    this.cases = new CaseManager();
    this.behavioral = new BehavioralEngine();
    this.cloudExport = cloudExport;
    this.cloudExportHealth = { enabled: Boolean(cloudExport), lastEnqueueAt: null, lastDeliveryAt: null, lastErrorAt: null, lastError: null };
    this.alertWebhook = alertWebhook;
    this.alertWebhookReady = false;
    this.alertWebhookHealth = { enabled: Boolean(alertWebhook), lastEnqueueAt: null, lastDeliveryAt: null, lastErrorAt: null, lastError: null };
    this.processedThroughSequence = 0;
    this.processingQueue = Promise.resolve();
    this.operationQueue = Promise.resolve();
    this.normalizers = new NormalizerRegistry()
      .register(zeekNormalizer())
      .register(syslogNormalizer())
      .register(openTelemetryNormalizer())
      .register(tailscaleLogNormalizer())
      .register(linuxJournalNormalizer());
    for (const normalizer of normalizers) this.normalizers.register(normalizer);
  }

  async initialize() {
    await fs.mkdir(this.dataDirectory, { recursive: true, mode: 0o700 });
    const filesystem = await fs.statfs(this.dataDirectory);
    const totalBytes = Number(filesystem.blocks) * Number(filesystem.bsize);
    const maximumBytes = Math.max(16 * 1024 * 1024, Math.floor(totalBytes * this.maximumStoragePercent / 100));
    this.storageBudget = { maximumBytes, eventBytes: Math.floor(maximumBytes * 0.75), auditBytes: Math.floor(maximumBytes * 0.10) };
    this.eventStore.setMaximumBytes(this.storageBudget.eventBytes);
    this.auditStore.setMaximumBytes(this.storageBudget.auditBytes);
    const [graphSnapshot, caseSnapshot, baselineSnapshot, ruleSnapshot, detectionState] = await Promise.all([this.graphStore.load(), this.caseStore.load(), this.baselineStore.load(), this.ruleStore.load(), this.detectionStateStore.load(), this.eventStore.initialize(), this.auditStore.initialize()]);
    if (this.cloudExport) {
      try { await this.cloudExport.outbox.initialize(); }
      catch (error) { this.cloudExportHealth = { ...this.cloudExportHealth, lastErrorAt: new Date().toISOString(), lastError: error.message }; }
    }
    if (this.alertWebhook) {
      try {
        if (typeof this.alertWebhook.initialize === 'function') await this.alertWebhook.initialize();
        else await this.alertWebhook.outbox.initialize();
        this.alertWebhookReady = true;
      } catch (error) {
        this.alertWebhookHealth = { ...this.alertWebhookHealth, lastErrorAt: new Date().toISOString(), lastError: error.message };
      }
    }
    if (graphSnapshot) this.graph = SecurityGraph.fromSnapshot(graphSnapshot);
    if (detectionState) {
      if (detectionState.schemaVersion !== 1 || !Number.isSafeInteger(detectionState.processedThroughSequence) || detectionState.processedThroughSequence < 0) throw new Error('Unsupported detection processing state');
      this.cases = CaseManager.fromSnapshot(detectionState.cases);
      this.behavioral = BehavioralEngine.fromSnapshot(detectionState.behavioral);
      this.processedThroughSequence = detectionState.processedThroughSequence;
    } else {
      if (caseSnapshot) this.cases = CaseManager.fromSnapshot(caseSnapshot);
      if (baselineSnapshot) this.behavioral = BehavioralEngine.fromSnapshot(baselineSnapshot);
      if (caseSnapshot || baselineSnapshot) {
        this.processedThroughSequence = (await this.eventStore.metadata()).sequence;
      }
    }
    if (ruleSnapshot) {
      if (ruleSnapshot.schemaVersion !== 1) throw new Error('Unsupported rule snapshot');
      const existing = new Set(this.analytics.map((rule) => rule.id));
      for (const rule of ruleSnapshot.imported || []) {
        validateRule(rule);
        if (existing.has(rule.id)) throw new Error(`Imported rule collides with built-in rule: ${rule.id}`);
        this.analytics.push(rule);
        existing.add(rule.id);
      }
    }
    await this.processPendingEvents();
    return this;
  }

  async applySurveyFacts(facts) {
    return this.serializedOperation(async () => {
      const nextGraph = SecurityGraph.fromSnapshot(this.graph.snapshot());
      nextGraph.apply(facts);
      const snapshot = nextGraph.snapshot();
      await this.graphStore.save(snapshot);
      this.graph = nextGraph;
      return snapshot;
    });
  }

  async replaceSurveyFacts(facts) {
    return this.serializedOperation(async () => {
      const nextGraph = new SecurityGraph().apply(facts);
      const snapshot = nextGraph.snapshot();
      await this.graphStore.save(snapshot);
      this.graph = nextGraph;
      return snapshot;
    });
  }

  async refreshGraph() {
    return this.serializedOperation(async () => {
      const snapshot = await this.graphStore.load();
      if (snapshot) this.graph = SecurityGraph.fromSnapshot(snapshot);
      return this.graph.snapshot();
    });
  }

  detectionPlan(graphSnapshot = this.graph.snapshot()) {
    return planAnalytics(this.analytics, graphSnapshot);
  }

  behaviorPlan() {
    return prioritizeBehaviors(this.graph.snapshot(), this.analytics);
  }

  async consoleSnapshot({ deploymentId = 'local', generatedAt = new Date().toISOString() } = {}) {
    const graph = this.graph.snapshot();
    const cases = this.cases.snapshot();
    const detectionPlan = this.detectionPlan(graph);
    const status = await this.status({ graph, cases, detectionPlan });
    return buildConsoleSnapshot({ graph, cases, detectionPlan, analytics: this.analytics, status, deploymentId, generatedAt });
  }

  async importAnalytics(rules) {
    const existing = new Set(this.analytics.map((rule) => rule.id));
    const imported = [];
    for (const rule of rules) {
      validateRule(rule);
      if (existing.has(rule.id)) throw new Error(`Rule ID already exists: ${rule.id}`);
      existing.add(rule.id);
      imported.push(structuredClone(rule));
    }
    this.analytics.push(...imported);
    const persisted = this.analytics.filter((rule) => rule.source?.format === 'sigma').sort((a, b) => a.id.localeCompare(b.id));
    await this.ruleStore.save({ schemaVersion: 1, imported: persisted });
    return imported;
  }

  async promoteIncident(alertIds, context) {
    return this.serializedOperation(async () => {
      const nextCases = CaseManager.fromSnapshot(this.cases.snapshot());
      const incident = nextCases.promote(alertIds, context);
      await this.saveDetectionState(nextCases, this.behavioral, this.processedThroughSequence);
      this.cases = nextCases;
      return incident;
    });
  }

  async updateAlert(alertId, context) {
    return this.serializedOperation(async () => {
      const nextCases = CaseManager.fromSnapshot(this.cases.snapshot());
      const alert = nextCases.updateAlert(alertId, context);
      await this.saveDetectionState(nextCases, this.behavioral, this.processedThroughSequence);
      this.cases = nextCases;
      return alert;
    });
  }

  async alertDetail(alertId) {
    const snapshot = this.cases.snapshot();
    const alert = snapshot.alerts.find((item) => item.id === alertId);
    if (!alert) throw Object.assign(new Error('Alert not found'), { statusCode: 404 });
    const finding = snapshot.findings.find((item) => item.id === alert.findingId);
    const evidenceTimeline = await this.eventStore.byIds(alert.evidence || []);
    const entities = new Map(this.graph.snapshot().entities.map((entity) => [entity.key, entity]));
    const affectedSystems = (alert.entities || []).map((key) => {
      const entity = entities.get(key);
      return entity ? { key, name: entity.name, type: entity.type } : { key, name: key.split(':').at(-1), type: 'unknown' };
    });
    const rule = this.analytics.find((item) => item.id === (finding?.ruleId || alert.ruleId));
    return {
      ...alert,
      affectedSystems,
      matchReason: finding?.rationale || alert.matchReason || 'The alert matched its detection rule.',
      evidenceTimeline,
      rule: rule ? { id: rule.id, title: rule.title, kind: rule.kind, severity: rule.severity } : null,
      baseline: finding?.baseline || null
    };
  }

  async saveDetectionState(cases = this.cases, behavioral = this.behavioral, processedThroughSequence = this.processedThroughSequence) {
    await this.detectionStateStore.save({ schemaVersion: 1, processedThroughSequence, cases: cases.snapshot(), behavioral: behavioral.snapshot() });
  }

  async recordAudit({ principal = 'anonymous', action, target, outcome, sourceAddress = null, attributes = {} }) {
    const time = new Date().toISOString();
    const event = createEvent({
      time, ingestedAt: time, category: 'configuration', class: 'api_audit', activity: action, outcome,
      source: { adapter: 'lookout-api', instance: 'local', recordId: crypto.randomUUID() }, entityKeys: [],
      actor: { id: principal, type: 'api_principal' }, sourceEndpoint: sourceAddress ? { id: `network-address:${sourceAddress}`, address: sourceAddress } : null,
      attributes: { target, ...attributes }
    });
    await this.auditStore.append([event]);
    if (this.storageBudget && (await this.auditStore.metadata()).bytes > this.storageBudget.auditBytes) await this.auditStore.compact({ retainAfter: new Date(0).toISOString(), maximumBytes: this.storageBudget.auditBytes });
    return event.id;
  }

  async recordServiceAccess({ principal, sourceAddress = null, method, path: requestPath, accessDecision = 'approved' }) {
    if (typeof principal !== 'string' || !principal) throw new Error('Service access requires an authenticated principal');
    if (!['approved', 'new_device', 'unapproved_device', 'new_service', 'unapproved_service'].includes(accessDecision)) throw new Error('Service access decision is invalid');
    const time = new Date().toISOString();
    const sourceKey = sourceAddress ? `network-address:${sourceAddress}` : null;
    const event = createEvent({
      time, ingestedAt: time, category: 'identity', class: 'authentication', activity: 'service_access', outcome: 'success', severity: accessDecision === 'approved' ? 1 : 8,
      source: { adapter: 'lookout-service-auth', instance: 'local', recordId: crypto.randomUUID() },
      entityKeys: [`identity:${principal}`, 'service:lookout', sourceKey].filter(Boolean),
      actor: { id: principal, type: 'api_principal' },
      sourceEndpoint: sourceAddress ? { id: sourceKey, address: sourceAddress } : null,
      service: { name: 'lookout' },
      attributes: { accessDecision, method: String(method || 'UNKNOWN').toUpperCase(), path: String(requestPath || '/').slice(0, 2048) }
    });
    const result = await this.ingest([event]);
    return { eventId: event.id, alerts: result.alerts };
  }

  async ingest(events) {
    return this.serializedOperation(() => this.ingestUnlocked(events));
  }

  async ingestUnlocked(events) {
    const normalized = [...events].map(validateEvent);
    await this.applyTelemetryObservations(normalized);
    const accepted = await this.eventStore.append(normalized);
    if (!accepted.length) {
      await this.processPendingEvents();
      return { accepted: [], ...this.cases.snapshot() };
    }
    const acceptedIds = new Set(accepted);
    const acceptedEvents = normalized.filter((event) => acceptedIds.has(event.id));
    if (this.cloudExport) {
      try {
        await this.cloudExport.enqueue(acceptedEvents);
        this.cloudExportHealth = { ...this.cloudExportHealth, lastEnqueueAt: new Date().toISOString() };
      } catch (error) {
        this.cloudExportHealth = { ...this.cloudExportHealth, lastErrorAt: new Date().toISOString(), lastError: error.message };
      }
    }
    await this.processPendingEvents();
    await this.enforceStorageBudgets();
    return { accepted, ...this.cases.snapshot() };
  }

  async enforceStorageBudgets() {
    if (!this.storageBudget) return { events: null, audit: null };
    const [eventMetadata, auditMetadata] = await Promise.all([this.eventStore.metadata(), this.auditStore.metadata()]);
    const totalBytes = await directoryBytes(this.dataDirectory);
    const otherBytes = Math.max(0, totalBytes - eventMetadata.bytes - auditMetadata.bytes);
    const logBudget = Math.max(2 * 1024 * 1024, this.storageBudget.maximumBytes - otherBytes);
    const eventLimit = Math.max(1024 * 1024, Math.floor(logBudget * 0.85));
    const auditLimit = Math.max(1024 * 1024, logBudget - eventLimit);
    let events = null;
    let audit = null;
    if (eventMetadata.bytes > eventLimit) {
      events = await this.eventStore.compact({ retainAfter: new Date(0).toISOString(), maximumBytes: eventLimit });
      this.processedThroughSequence = events.retained;
      await this.saveDetectionState();
    }
    if (auditMetadata.bytes > auditLimit) audit = await this.auditStore.compact({ retainAfter: new Date(0).toISOString(), maximumBytes: auditLimit });
    return { events, audit };
  }

  async applyTelemetryObservations(events) {
    const graphSnapshot = this.graph.snapshot();
    const knownEntityKeys = new Set(graphSnapshot.entities.map((entity) => entity.key));
    const groups = new Map();
    for (const event of events) {
      if (event.source.adapter.startsWith('lookout-')) continue;
      const key = `${event.source.adapter}\0${event.source.instance}`;
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(event);
    }
    const facts = [...groups.values()].flatMap((group) => telemetryFacts(group, knownEntityKeys));
    if (!facts.length) return graphSnapshot;
    const nextGraph = SecurityGraph.fromSnapshot(graphSnapshot).apply(facts);
    const snapshot = nextGraph.snapshot();
    await this.graphStore.save(snapshot);
    this.graph = nextGraph;
    return snapshot;
  }

  async processPendingEvents() {
    const work = async () => {
      while (true) {
        const records = await this.eventStore.recordsAfter(this.processedThroughSequence, { limit: 10000 });
        if (!records.length) return this.cases.snapshot();
        const pendingEvents = records.map((record) => record.event);
        const detectionEvents = pendingEvents.filter((event) => event.class !== 'journal_record');
        const nextSequence = records.at(-1).sequence;
        if (!detectionEvents.length) {
          await this.saveDetectionState(this.cases, this.behavioral, nextSequence);
          this.processedThroughSequence = nextSequence;
          continue;
        }
        const earliest = detectionEvents.reduce((value, event) => value < event.time ? value : event.time, detectionEvents[0].time);
        const contextStart = new Date(Date.parse(earliest) - 24 * 60 * 60 * 1000).toISOString();
        const context = await this.eventStore.query({ since: contextStart, excludeClasses: ['journal_record'], limit: 10000 });
        const deployable = new Set(this.detectionPlan().filter((item) => item.deploy).map((item) => item.analyticId));
        const deterministicFindings = evaluate(this.analytics.filter((rule) => deployable.has(rule.id)), context);
        const protectedEventIds = new Set(deterministicFindings.flatMap((finding) => finding.evidence));
        const nextBehavioral = BehavioralEngine.fromSnapshot(this.behavioral.snapshot());
        const behavioralFindings = nextBehavioral.observe(detectionEvents, { protectedEventIds, context: behavioralContext(this.graph.snapshot()) });
        const nextCases = CaseManager.fromSnapshot(this.cases.snapshot());
        nextCases.ingest([...deterministicFindings, ...behavioralFindings]);
        if (this.alertWebhook) {
          const priorAlertIds = new Set(this.cases.snapshot().alerts.map((alert) => alert.id));
          const newAlerts = nextCases.snapshot().alerts.filter((alert) => !priorAlertIds.has(alert.id));
          if (newAlerts.length) {
            await this.alertWebhook.enqueue(newAlerts);
            this.alertWebhookHealth = { ...this.alertWebhookHealth, lastEnqueueAt: new Date().toISOString(), lastError: null };
          }
        }
        await this.saveDetectionState(nextCases, nextBehavioral, nextSequence);
        this.cases = nextCases;
        this.behavioral = nextBehavioral;
        this.processedThroughSequence = nextSequence;
      }
    };
    const result = this.processingQueue.then(work, work);
    this.processingQueue = result.then(() => undefined, () => undefined);
    return result;
  }

  async ingestRaw(normalizerId, records, context = {}) {
    if (!Array.isArray(records)) throw new Error('Raw ingestion requires a record array');
    const events = records.flatMap((record, index) => this.normalizers.normalize(normalizerId, record, { ...context, recordId: context.recordId ? `${context.recordId}:${index}` : undefined, recordIndex: index }));
    return this.ingest(events);
  }

  async compactRetention({ eventRetentionDays = 7, auditRetentionDays = 7, now = new Date() } = {}) {
    return this.serializedOperation(async () => {
      for (const [name, value] of Object.entries({ eventRetentionDays, auditRetentionDays })) if (!Number.isInteger(value) || value < 1) throw new Error(`${name} must be a positive integer`);
      await this.processPendingEvents();
      const eventCutoff = new Date(now.getTime() - eventRetentionDays * 86400000).toISOString();
      const auditCutoff = new Date(now.getTime() - auditRetentionDays * 86400000).toISOString();
      const [events, audit] = await Promise.all([this.eventStore.compact({ retainAfter: eventCutoff, maximumBytes: this.storageBudget?.eventBytes }), this.auditStore.compact({ retainAfter: auditCutoff, maximumBytes: this.storageBudget?.auditBytes })]);
      this.processedThroughSequence = events.retained;
      await this.saveDetectionState();
      return { events, audit, eventCutoff, auditCutoff };
    });
  }

  serializedOperation(work) {
    const result = this.operationQueue.then(work, work);
    this.operationQueue = result.then(() => undefined, () => undefined);
    return result;
  }

  async flushCloudExport() {
    if (!this.cloudExport) return { disabled: true, delivered: 0, pending: 0 };
    try {
      const result = await this.cloudExport.flush();
      if (result.delivered) this.cloudExportHealth.lastDeliveryAt = new Date().toISOString();
      if (result.delivered || (result.pending === 0 && !result.deferred && !result.blocked)) this.cloudExportHealth.lastError = null;
      return result;
    } catch (error) {
      this.cloudExportHealth.lastErrorAt = new Date().toISOString();
      this.cloudExportHealth.lastError = error.message;
      throw error;
    }
  }

  async flushAlertWebhook() {
    if (!this.alertWebhook) return { disabled: true, delivered: 0, pending: 0 };
    if (!this.alertWebhookReady) return { unavailable: true, delivered: 0, pending: 0, error: this.alertWebhookHealth.lastError };
    try {
      const result = await this.alertWebhook.flush();
      if (result.delivered) this.alertWebhookHealth.lastDeliveryAt = new Date().toISOString();
      if (result.delivered || (result.pending === 0 && !result.deferred && !result.blocked)) this.alertWebhookHealth.lastError = null;
      return result;
    } catch (error) {
      this.alertWebhookHealth.lastErrorAt = new Date().toISOString();
      this.alertWebhookHealth.lastError = error.message;
      throw error;
    }
  }

  async status({ graph = this.graph.snapshot(), cases = this.cases.snapshot(), detectionPlan = null } = {}) {
    const plan = detectionPlan || this.detectionPlan(graph);
    const [eventsStorage, auditStorage] = this.storageBudget
      ? await Promise.all([this.eventStore.metadata(), this.auditStore.metadata()])
      : [{ sequence: 0, events: 0, bytes: 0, maximumBytes: null }, { sequence: 0, events: 0, bytes: 0, maximumBytes: null }];
    return {
      status: 'ok',
      releaseVersion: `v${version}`,
      memory: { rssBytes: process.memoryUsage().rss, heapUsedBytes: process.memoryUsage().heapUsed, heapLimitBytes: v8.getHeapStatistics().heap_size_limit },
      graph: { entities: graph.entities.length, relationships: graph.relationships.length, capabilities: graph.capabilities.length },
      detections: { ready: plan.filter((item) => item.state === 'ready').length, partial: plan.filter((item) => item.state === 'partial').length, degraded: plan.filter((item) => item.state === 'degraded').length, blocked: plan.filter((item) => item.state === 'blocked').length },
      cases: { alerts: cases.alerts.length, incidents: cases.incidents.length },
      storage: { maximumBytes: this.storageBudget?.maximumBytes || null, usedBytes: this.storageBudget ? await directoryBytes(this.dataDirectory) : 0, events: eventsStorage, audit: auditStorage },
      cloudExport: this.cloudExport ? { ...this.cloudExportHealth, ...this.cloudExport.outbox.stats() } : { enabled: false },
      alertWebhook: this.alertWebhook ? { ...this.alertWebhookHealth, ...(typeof this.alertWebhook.stats === 'function' ? this.alertWebhook.stats() : this.alertWebhook.outbox.stats()) } : { enabled: false },
      normalizers: this.normalizers.manifests().map((manifest) => manifest.id)
    };
  }
}

module.exports = { behavioralContext, LookoutRuntime };

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createEvent } = require('../src/events/schema');
const { applyOverlay } = require('../src/detection/overlays');
const { evaluate } = require('../src/detection/engine');
const { median, SetBaseline, RobustNumericBaseline } = require('../src/detection/baselines');
const { CaseManager } = require('../src/detection/cases');
const { BehavioralEngine } = require('../src/detection/behavioral-engine');
const { analytics } = require('../src/detection/catalog');
const { assertReplay } = require('../src/detection/replay');

function auth(recordId, time, outcome = 'failure', source = 'endpoint:client') {
  return createEvent({ time, ingestedAt: time, category: 'identity', class: 'authentication', activity: 'logon', outcome, source: { adapter: 'fixture', instance: 'site', recordId }, entityKeys: [source, 'identity:admin'], sourceEndpoint: { id: source }, destinationEndpoint: { id: 'endpoint:server' }, attributes: {} });
}

function execution(recordId, time, source = 'endpoint:client') {
  return createEvent({ time, ingestedAt: time, category: 'system', class: 'process_activity', activity: 'start', outcome: 'success', source: { adapter: 'fixture', instance: 'site', recordId }, entityKeys: [source, 'endpoint:server'], sourceEndpoint: { id: source }, destinationEndpoint: { id: 'endpoint:server' }, attributes: { parentType: 'remote_session' } });
}

const thresholdRule = { id: 'auth-failures', version: '1.0.0', title: 'Repeated authentication failures', kind: 'threshold', severity: 'high', selector: { class: 'authentication', outcome: 'failure' }, threshold: 3, windowSeconds: 60, groupBy: ['sourceEndpoint.id'] };

test('tuning overlays are expiring, attributable, and narrowly scoped', () => {
  const tuned = applyOverlay(thresholdRule, { id: 'overlay-1', ruleId: thresholdRule.id, owner: 'security@example.test', reason: 'Known scanner has a documented test schedule', expiresAt: '2027-01-01T00:00:00.000Z', threshold: 5, exclusions: [{ selector: { 'sourceEndpoint.id': 'endpoint:scanner' }, reason: 'Scanner identity is stable and independently monitored' }] }, new Date('2026-08-17T00:00:00.000Z'));
  assert.equal(tuned.threshold, 5);
  assert.equal(tuned.tuning.overlayId, 'overlay-1');
  assert.throws(() => applyOverlay(thresholdRule, { id: 'bad', ruleId: thresholdRule.id, owner: 'x', reason: 'Too broad exclusion reason', expiresAt: '2027-01-01T00:00:00.000Z', exclusions: [{ selector: { outcome: 'failure' }, reason: 'This would hide virtually every useful match' }] }, new Date('2026-08-17T00:00:00.000Z')), /narrowly scoped/);
});

test('engine evaluates threshold and causal sequence rules', () => {
  const events = [auth('a1', '2026-08-17T20:00:00.000Z'), auth('a2', '2026-08-17T20:00:10.000Z'), auth('a3', '2026-08-17T20:00:20.000Z'), auth('success', '2026-08-17T20:01:00.000Z', 'success'), execution('exec', '2026-08-17T20:01:20.000Z')];
  const sequenceRule = { id: 'remote-exec', version: '1.0.0', title: 'Authentication followed by remote execution', kind: 'sequence', severity: 'critical', sequence: [{ class: 'authentication', outcome: 'success' }, { class: 'process_activity', 'attributes.parentType': 'remote_session' }], windowSeconds: 60, groupBy: ['sourceEndpoint.id'] };
  const findings = evaluate([thresholdRule, sequenceRule], events);
  assert.equal(findings.length, 2);
  assert.ok(findings.some((item) => item.ruleId === 'auth-failures' && item.evidence.length === 3));
  assert.ok(findings.some((item) => item.ruleId === 'remote-exec' && item.evidence.length === 2));
});

test('set baseline does not learn from active alerts', () => {
  const baseline = new SetBaseline({ defaults: ['endpoint:known'], minimumObservations: 2, noveltySeconds: 0 });
  assert.equal(baseline.observe('endpoint:new', '2026-08-17T20:00:00.000Z', { activeAlert: true }).anomaly, true);
  assert.equal(baseline.snapshot().values['endpoint:new'], undefined);
  baseline.observe('endpoint:new', '2026-08-17T20:01:00.000Z');
  baseline.observe('endpoint:new', '2026-08-17T20:02:00.000Z');
  assert.equal(baseline.observe('endpoint:new', '2026-08-17T20:03:00.000Z').anomaly, false);
});

test('robust numeric baseline is explainable and contamination-aware', () => {
  assert.equal(median([1, 10, 3, 2]), 2.5);
  const baseline = new RobustNumericBaseline({ defaults: [100, 101, 99, 100, 102, 98], minimumSamples: 6, warningDeviations: 4, criticalDeviations: 8 });
  const result = baseline.score(1000, { activeAlert: true });
  assert.equal(result.state, 'critical');
  assert.ok(result.robustDeviation > 8);
  assert.equal(baseline.snapshot().samples.length, 6);
});

test('behavioral anomalies remain correlation evidence and cannot create alerts or incidents alone', () => {
  const anomalyA = { schemaVersion: 1, id: 'finding-a', ruleId: 'novel-edge', ruleVersion: '1', title: 'Novel edge', severity: 'high', severityScore: 8, kind: 'behavioral', time: '2026-08-17T20:00:00.000Z', firstSeen: '2026-08-17T20:00:00.000Z', confidence: 0.7, status: 'open', evidence: ['event-a'], entities: ['endpoint:1'], rationale: 'novel' };
  const anomalyB = { ...anomalyA, id: 'finding-b', ruleId: 'rare-destination', title: 'Rare destination', time: '2026-08-17T20:01:00.000Z', evidence: ['event-b'] };
  const snapshot = new CaseManager().ingest([anomalyA, anomalyB]);
  assert.equal(snapshot.findings.length, 2);
  assert.equal(snapshot.alerts.length, 0);
  assert.equal(snapshot.incidents.length, 0);
});

test('only deterministic high and critical findings enter the alert queue', () => {
  const base = { schemaVersion: 1, ruleVersion: '1', kind: 'event', time: '2026-08-17T20:00:00.000Z', firstSeen: '2026-08-17T20:00:00.000Z', confidence: 1, status: 'open', evidence: ['event-a'], entities: ['endpoint:1'], rationale: 'matched' };
  const medium = { ...base, id: 'medium', ruleId: 'medium-rule', title: 'Medium evidence', severity: 'medium', severityScore: 5, alertDisposition: 'correlation_only' };
  const high = { ...base, id: 'high', ruleId: 'high-rule', title: 'High alert', severity: 'high', severityScore: 8, alertDisposition: 'high_confidence' };
  const snapshot = new CaseManager().ingest([medium, high]);
  assert.equal(snapshot.findings.length, 2);
  assert.deepEqual(snapshot.alerts.map((item) => item.findingId), ['high']);
});

test('alert review states are open, to fix, and closed', () => {
  const finding = { schemaVersion: 1, id: 'high', ruleId: 'high-rule', ruleVersion: '1', title: 'High alert', severity: 'high', severityScore: 8, kind: 'event', time: '2026-08-17T20:00:00.000Z', firstSeen: '2026-08-17T20:00:00.000Z', confidence: 1, status: 'open', evidence: ['event-a'], entities: ['endpoint:1'], rationale: 'matched' };
  const manager = new CaseManager();
  const alert = manager.ingest([finding]).alerts[0];
  const toFix = manager.updateAlert(alert.id, { status: 'to_fix', actor: 'owner' });
  assert.equal(toFix.status, 'to_fix');
  assert.equal(Object.hasOwn(toFix.statusHistory.at(-1), 'reason'), false);
  assert.equal(manager.updateAlert(alert.id, { status: 'closed', actor: 'owner', reason: 'Remediation verified' }).status, 'closed');
  assert.throws(() => manager.updateAlert(alert.id, { status: 'in_review', actor: 'owner', reason: 'Legacy state' }), /open, to_fix, or closed/);
});

test('sequence findings do not reuse one follow-up event across duplicate alerts', () => {
  const rule = analytics.find((item) => item.id === 'remote-auth-then-privilege-use');
  const event = (recordId, time, eventClass, activity) => createEvent({
    time, ingestedAt: time, category: 'identity', class: eventClass, activity, outcome: 'success',
    source: { adapter: 'fixture', instance: 'site', recordId }, entityKeys: ['identity:alice', 'endpoint:server'],
    actor: { id: 'alice' }, sourceEndpoint: eventClass === 'authentication' ? { id: 'endpoint:client' } : null,
    destinationEndpoint: { id: 'endpoint:server' }, attributes: {}
  });
  const events = [
    event('login-1', '2026-08-17T20:00:00.000Z', 'authentication', 'remote_logon'),
    event('login-2', '2026-08-17T20:00:01.000Z', 'authentication', 'remote_logon'),
    event('sudo-1', '2026-08-17T20:00:02.000Z', 'privilege_use', 'sudo')
  ];
  const findings = evaluate([rule], events);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].evidence.length, 2);
});

test('restoring legacy state removes sequence alerts that reused the same follow-up evidence', () => {
  const base = { id: 'alert_a', findingId: 'finding_a', ruleId: 'remote-auth-then-privilege-use', title: 'Remote authentication followed by privileged execution', severity: 'critical', severityScore: 10, time: '2026-08-17T20:00:02.000Z', firstSeen: '2026-08-17T20:00:00.000Z', status: 'open', statusHistory: [], entities: ['endpoint:server'], confidence: 1, analyticKind: 'sequence' };
  const manager = CaseManager.fromSnapshot({ schemaVersion: 1, findings: [], incidents: [], audit: [], alerts: [
    { ...base, evidence: ['login-1', 'sudo-1'] },
    { ...base, id: 'alert_b', findingId: 'finding_b', evidence: ['login-2', 'sudo-1'] }
  ] });
  assert.equal(manager.snapshot().alerts.length, 1);
});

test('distinct correlated high-confidence findings create an incident', () => {
  const events = [auth('a1', '2026-08-17T20:00:00.000Z'), auth('a2', '2026-08-17T20:00:10.000Z'), auth('a3', '2026-08-17T20:00:20.000Z'), auth('success', '2026-08-17T20:01:00.000Z', 'success'), execution('exec', '2026-08-17T20:01:20.000Z')];
  const sequenceRule = { id: 'remote-exec', version: '1.0.0', title: 'Authentication followed by remote execution', kind: 'sequence', severity: 'critical', sequence: [{ class: 'authentication', outcome: 'success' }, { class: 'process_activity' }], windowSeconds: 60, groupBy: ['sourceEndpoint.id'] };
  const snapshot = new CaseManager().ingest(evaluate([thresholdRule, sequenceRule], events));
  assert.equal(snapshot.incidents.length, 1);
  assert.equal(snapshot.incidents[0].findings.length, 2);
  assert.ok(snapshot.incidents[0].evidence.length >= 4);
});

test('behavioral engine persists explainable relationship baselines', () => {
  const networkEvent = createEvent({ time: '2026-08-17T20:00:00.000Z', ingestedAt: '2026-08-17T20:00:00.000Z', category: 'network', class: 'network_activity', activity: 'connect', source: { adapter: 'fixture', instance: 'site', recordId: 'net-1' }, entityKeys: ['endpoint:a', 'endpoint:b'], sourceEndpoint: { id: 'endpoint:a' }, destinationEndpoint: { id: 'endpoint:b' }, attributes: { bytesSent: 100 } });
  const engine = new BehavioralEngine();
  const findings = engine.observe([networkEvent]);
  assert.equal(findings.length, 0, 'initial learning must not create anomaly noise');
  assert.ok(engine.snapshot().models.some((item) => item.key === 'novel-network-relationship\0endpoint:a'));
  const restored = BehavioralEngine.fromSnapshot(engine.snapshot());
  assert.deepEqual(restored.snapshot(), engine.snapshot());
});

test('behavioral baselines cover identity, process, privilege, resource, schedule, peer, network, and data movement context', () => {
  const ids = new Set(new BehavioralEngine().analytics.map((analytic) => analytic.id));
  for (const id of ['novel-identity-authentication-target', 'novel-host-executable', 'novel-process-destination', 'novel-privilege-target', 'novel-resource-access', 'unusual-identity-hour-of-week', 'peer-group-executable-novelty', 'novel-network-relationship', 'novel-data-movement-path', 'unusual-egress-volume']) assert.equal(ids.has(id), true, id);
  assert.ok(new BehavioralEngine().analytics.every((analytic) => analytic.parameters.maximumValues || analytic.parameters.maximumSamples));
});

test('derived schedule and peer-group baselines are explainable and shared only by comparable endpoints', () => {
  const engine = new BehavioralEngine();
  const process = (recordId, endpoint, executable) => createEvent({ time: '2026-08-17T20:00:00.000Z', ingestedAt: '2026-08-17T20:00:00.000Z', category: 'system', class: 'process_activity', activity: 'start', outcome: 'success', source: { adapter: 'fixture', instance: 'site', recordId }, entityKeys: [endpoint], destinationEndpoint: { id: endpoint }, attributes: { executable } });
  const identity = createEvent({ time: '2026-08-17T20:00:00.000Z', ingestedAt: '2026-08-17T20:00:00.000Z', category: 'identity', class: 'authentication', activity: 'logon', outcome: 'success', source: { adapter: 'fixture', instance: 'site', recordId: 'schedule' }, entityKeys: ['identity:alice', 'endpoint:a'], actor: { id: 'alice' }, destinationEndpoint: { id: 'endpoint:a' }, attributes: {} });
  const findings = engine.observe([process('p1', 'endpoint:a', '/usr/bin/tool'), process('p2', 'endpoint:b', '/usr/bin/tool'), identity], { context: { endpointPeerGroups: { 'endpoint:a': 'platform:linux', 'endpoint:b': 'platform:linux' } } });
  assert.equal(findings.length, 0, 'initial schedule and peer learning must remain quiet');
  const scheduleModels = engine.snapshot().models.filter((item) => item.key.startsWith('unusual-identity-hour-of-week\0'));
  assert.equal(scheduleModels.length, 1);
  const peerModels = engine.snapshot().models.filter((item) => item.key.startsWith('peer-group-executable-novelty\0'));
  assert.equal(peerModels.length, 1);
  assert.match(peerModels[0].key, /platform:linux$/);
});

test('small-tailnet scan rule ignores repeats and four distinct destinations', () => {
  const scanRule = analytics.find((rule) => rule.id === 'network-destination-scan');
  const network = (recordId, destination) => createEvent({ time: `2026-08-17T20:00:${String(Number(recordId) % 60).padStart(2, '0')}.000Z`, ingestedAt: '2026-08-17T20:01:00.000Z', category: 'network', class: 'network_activity', activity: 'connection', source: { adapter: 'fixture', instance: 'site', recordId }, entityKeys: ['endpoint:source', destination], sourceEndpoint: { id: 'endpoint:source' }, destinationEndpoint: { id: destination }, attributes: {} });
  const repeats = Array.from({ length: 50 }, (_, index) => network(String(index), 'endpoint:one'));
  assert.equal(evaluate([scanRule], repeats).length, 0);
  const benign = Array.from({ length: 4 }, (_, index) => network(String(index + 100), `endpoint:${index}`));
  assert.equal(evaluate([scanRule], benign).length, 0);
});

test('small-tailnet scan rule detects five distinct destinations', () => {
  const scanRule = analytics.find((rule) => rule.id === 'network-destination-scan');
  const distinct = Array.from({ length: 5 }, (_, index) => createEvent({ time: `2026-08-17T20:00:0${index}.000Z`, ingestedAt: '2026-08-17T20:01:00.000Z', category: 'network', class: 'network_activity', activity: 'connection', source: { adapter: 'fixture', instance: 'site', recordId: `scan-${index}` }, entityKeys: ['endpoint:source', `endpoint:${index}`], sourceEndpoint: { id: 'endpoint:source' }, destinationEndpoint: { id: `endpoint:${index}` }, attributes: {} }));
  assert.equal(evaluate([scanRule], distinct).length, 1);
});

test('new or unapproved device and service access is detected without flagging approved access', () => {
  const rule = analytics.find((item) => item.id === 'new-or-unapproved-access');
  const access = (recordId, category, accessDecision) => createEvent({
    time: '2026-08-17T20:00:00.000Z', ingestedAt: '2026-08-17T20:00:01.000Z', category,
    class: category === 'network' ? 'network_activity' : 'authentication', activity: category === 'identity' ? 'service_access' : 'access', outcome: 'success',
    source: { adapter: 'fixture', instance: 'site', recordId }, entityKeys: ['endpoint:client', 'service:app'],
    sourceEndpoint: { id: 'endpoint:client' }, service: { name: 'self-hosted-app' }, attributes: { accessDecision }
  });
  const events = [
    access('approved', 'application', 'approved'),
    access('new-device', 'network', 'new_device'),
    access('unapproved-device', 'network', 'unapproved_device'),
    access('new-service', 'application', 'new_service'),
    access('unapproved-service', 'identity', 'unapproved_service')
  ];
  const findings = evaluate([rule], events);
  assert.equal(findings.length, 4);
  assert.ok(findings.every((finding) => finding.ruleId === rule.id && finding.severity === 'high'));
});

test('high-value post-authentication chains match while isolated administration stays evidence-only', () => {
  const endpoint = 'endpoint:server';
  const event = (recordId, time, eventClass, activity, extra = {}) => createEvent({
    time, ingestedAt: time, category: extra.category || 'configuration', class: eventClass, activity,
    outcome: extra.outcome || 'success', source: { adapter: 'fixture', instance: 'site', recordId },
    entityKeys: [endpoint, 'identity:alice'], actor: extra.actor === false ? null : { id: 'alice', targetId: extra.targetId },
    sourceEndpoint: extra.sourceEndpoint || null, destinationEndpoint: { id: endpoint }, attributes: extra.attributes || {}
  });
  const login = event('login', '2026-08-17T20:00:00.000Z', 'authentication', 'remote_logon', { category: 'identity', sourceEndpoint: { id: 'address:client' } });
  const scenarios = [
    ['remote-auth-then-privilege-use', event('sudo', '2026-08-17T20:01:00.000Z', 'privilege_use', 'sudo', { category: 'identity', targetId: 'root' })],
    ['remote-auth-then-account-created', event('account', '2026-08-17T20:02:00.000Z', 'account_management', 'create', { category: 'identity', actor: false, attributes: { loginEnabled: true } })],
    ['remote-auth-then-persistence', event('service', '2026-08-17T20:03:00.000Z', 'service_activity', 'enable', { actor: false, attributes: { serviceName: 'unexpected.service' } })],
    ['remote-auth-then-listener-created', event('listener', '2026-08-17T20:04:00.000Z', 'exposure_activity', 'listener_create', { actor: false, attributes: { exposureScope: 'all_interfaces', port: 4444 } })]
  ];
  for (const [ruleId, followup] of scenarios) {
    const rule = analytics.find((item) => item.id === ruleId);
    assert.equal(evaluate([rule], [login, followup]).length, 1, ruleId);
    assert.equal(evaluate([rule], [followup]).length, 0, `${ruleId} must require its causal login`);
  }
});

test('remote execution correlation requires explicit remote-session process context', () => {
  const rule = analytics.find((item) => item.id === 'remote-auth-then-execution');
  const login = auth('login-success', '2026-08-17T20:00:00.000Z', 'success');
  const ordinary = createEvent({ time: '2026-08-17T20:00:30.000Z', ingestedAt: '2026-08-17T20:00:30.000Z', category: 'system', class: 'process_activity', activity: 'start', outcome: 'success', source: { adapter: 'fixture', instance: 'site', recordId: 'ordinary' }, entityKeys: ['endpoint:client', 'endpoint:server'], sourceEndpoint: { id: 'endpoint:client' }, destinationEndpoint: { id: 'endpoint:server' }, attributes: {} });
  const remote = createEvent({ ...ordinary, source: { ...ordinary.source, recordId: 'remote' }, attributes: { parentType: 'remote_session' } });
  assert.equal(evaluate([rule], [login, ordinary]).length, 0);
  assert.equal(evaluate([rule], [login, remote]).length, 1);
});

test('replay harness asserts malicious and benign catalog outcomes', () => {
  const failures = Array.from({ length: 12 }, (_, index) => auth(`replay-${index}`, `2026-08-17T20:00:${String(index).padStart(2, '0')}.000Z`));
  const result = assertReplay({ name: 'authentication burst', rules: analytics, events: failures, expectedRuleIds: ['auth-failure-burst'], forbiddenRuleIds: ['remote-auth-then-execution'] });
  assert.equal(result.passed, true);
  const benign = [auth('benign-1', '2026-08-17T20:00:00.000Z'), auth('benign-2', '2026-08-17T20:10:00.000Z')];
  assertReplay({ name: 'spaced authentication failures', rules: analytics, events: benign, forbiddenRuleIds: ['auth-failure-burst'] });
});

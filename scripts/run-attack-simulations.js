#!/usr/bin/env node
'use strict';

const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { LookoutRuntime } = require('../src/runtime');
const { createFact } = require('../src/adapters/contract');
const { analytics } = require('../src/detection/catalog');

const TIME = '2026-08-19T20:00:00.000Z';

function otel(recordId, eventClass, activity, attributes = {}, resource = {}) {
  return {
    Timestamp: String((BigInt(Date.parse(TIME)) + BigInt(recordId.replace(/\D/g, '') || 0)) * 1000000n),
    TraceId: `attack-${recordId}`,
    SpanId: recordId,
    SeverityNumber: 20,
    EventName: activity,
    Resource: { 'host.id': 'attack-target', 'host.name': 'attack-target', ...resource },
    Attributes: {
      'security.category': attributes.category || 'configuration',
      'security.class': eventClass,
      'security.activity': activity,
      'event.outcome': attributes.outcome || 'success',
      'enduser.id': attributes.actor || 'attacker',
      'client.address': attributes.sourceAddress || '192.0.2.10',
      ...Object.fromEntries(Object.entries(attributes).filter(([key]) => !['category', 'outcome', 'actor', 'sourceAddress'].includes(key)))
    },
    Body: 'Lookout attack-validation record; no secret or command content retained.'
  };
}

function linuxJournal(cursor, identifier, message) {
  return { __CURSOR: cursor, __REALTIME_TIMESTAMP: String(Date.parse(TIME) * 1000), _HOSTNAME: 'attack-target', SYSLOG_IDENTIFIER: identifier, MESSAGE: message };
}

function capabilityFacts(capabilities) {
  const source = { adapter: 'attack-validation', instance: 'isolated', recordId: 'sensor' };
  return [
    createFact({ kind: 'entity', observedAt: TIME, source, data: { entityKey: 'telemetry:attack-validation', entityType: 'telemetry', name: 'Attack validation sensor' } }),
    ...capabilities.map((capability, index) => createFact({
      kind: 'capability', observedAt: TIME,
      source: { ...source, recordId: `capability:${index}:${capability}` },
      data: { entityKey: 'telemetry:attack-validation', capability, status: 'available' }
    }))
  ];
}

const one = (ruleId, capabilities, records, normalizer = 'opentelemetry-log', context = {}) => ({
  id: ruleId, expectedRuleId: ruleId, capabilities, steps: [{ normalizer, records, context }]
});

const correlationOnly = (ruleId, capabilities, records, normalizer = 'opentelemetry-log', context = {}) => ({
  ...one(ruleId, capabilities, records, normalizer, context), expectedAlert: false
});

const scenarios = [
  one('auth-failure-burst', ['authentication'], Array.from({ length: 12 }, (_, index) => linuxJournal(`s=auth-${index}`, 'sshd', `Failed password for root from 192.0.2.10 port ${2200 + index} ssh2`)), 'linux-journal'),
  one('auth-source-many-identities', ['authentication'], Array.from({ length: 6 }, (_, index) => linuxJournal(`s=spray-${index}`, 'sshd', `Failed password for user${index} from 192.0.2.11 port ${2300 + index} ssh2`)), 'linux-journal'),
  one('remote-auth-then-execution', ['authentication', 'process_execution'], [
    otel('101', 'authentication', 'remote_logon', { category: 'identity' }),
    otel('102', 'process_activity', 'start', { category: 'system', parentType: 'remote_session', executable: '/bin/sh' })
  ]),
  one('remote-auth-then-privilege-use', ['authentication', 'privilege_use'], [
    otel('201', 'authentication', 'remote_logon', { category: 'identity' }),
    otel('202', 'privilege_use', 'sudo', { category: 'identity', 'security.actor.target_id': 'root' })
  ]),
  one('remote-auth-then-account-created', ['authentication', 'identity_inventory'], [
    otel('301', 'authentication', 'remote_logon', { category: 'identity' }),
    otel('302', 'account_management', 'create', { category: 'identity', loginEnabled: true })
  ]),
  one('remote-auth-then-persistence', ['authentication', 'service_inventory'], [
    otel('401', 'authentication', 'remote_logon', { category: 'identity' }),
    otel('402', 'service_activity', 'enable', { serviceName: 'attack-validation.service' })
  ]),
  one('remote-auth-then-listener-created', ['authentication', 'network_listener'], [
    otel('501', 'authentication', 'remote_logon', { category: 'identity' }),
    otel('502', 'exposure_activity', 'listener_create', { exposureScope: 'all_interfaces', port: 4444 })
  ]),
  one('service-spawned-command-interpreter', ['process_execution'], [otel('601', 'process_activity', 'start', { category: 'system', parentType: 'network_service', processType: 'command_interpreter', executable: '/bin/sh' })]),
  one('telemetry-disabled', ['sensor_health'], [otel('701', 'sensor_activity', 'stop', { category: 'health' })]),
  one('security-log-cleared', ['configuration_change'], [{ __CURSOR: 's=log-clear', _HOSTNAME: 'attack-target', MESSAGE: 'type=EXECVE msg=audit(1787169600.000:99): argc=3 a0="journalctl" a1="--vacuum-time=1s" a2="/var/log"' }], 'linux-journal'),
  one('route-or-exit-node-enabled', ['configuration_change', 'route'], [{ id: 'route-1', eventTime: TIME, actor: { id: 'operator' }, action: 'approve', target: { id: 'route:10.0.0.0/8', type: 'route' } }], 'tailscale-logs', { logType: 'configuration-audit', tailnet: 'attack.example' }),
  one('privileged-role-granted', ['privilege_inventory'], [otel('801', 'group_management', 'grant_privilege', { category: 'identity' })]),
  one('mfa-protection-disabled', ['configuration_change'], [otel('901', 'authentication_factor_activity', 'disable', { category: 'identity' })]),
  one('privileged-ssh-credential-changed', ['credential_inventory', 'privilege_inventory'], [otel('1001', 'credential_management', 'add_credential', { category: 'identity', credentialKind: 'ssh_authorized_keys', privilegedOwner: true })]),
  one('local-account-created', ['identity_inventory'], [otel('1101', 'account_management', 'create', { category: 'identity', loginEnabled: true })]),
  one('new-or-unapproved-access', [], [otel('1201', 'authentication', 'service_access', { category: 'identity', accessDecision: 'unapproved_device' })]),
  one('large-egress-transfer', ['network_flow'], [{ ts: Date.parse(TIME) / 1000, uid: 'egress-1', 'id.orig_h': '192.0.2.10', 'id.orig_p': 50000, 'id.resp_h': '198.51.100.20', 'id.resp_p': 443, proto: 'tcp', conn_state: 'SF', orig_bytes: 2000000000 }], 'zeek', { logType: 'conn' }),
  one('backup-protection-disabled', ['configuration_change'], [otel('1301', 'backup_activity', 'disable')]),
  one('public-share-created', ['configuration_change', 'resource_access'], [otel('1401', 'sharing_activity', 'public_create')]),
  {
    id: 'data-staging-then-egress', expectedRuleId: 'data-staging-then-egress', capabilities: ['file_access', 'network_flow'],
    steps: [
      { normalizer: 'opentelemetry-log', records: [otel('1501', 'archive_activity', 'create', { category: 'data' })], context: {} },
      { normalizer: 'zeek', records: [{ ts: Date.parse(TIME) / 1000 + 2, uid: 'staged-egress', 'id.orig_h': '192.0.2.10', 'id.orig_p': 50001, 'id.resp_h': '198.51.100.21', 'id.resp_p': 443, proto: 'tcp', conn_state: 'SF', orig_bytes: 100000000 }], context: { logType: 'conn' } }
    ]
  },
  one('network-listener-created', ['network_listener'], [otel('1601', 'exposure_activity', 'listener_create', { exposureScope: 'all_interfaces', port: 8443 })]),
  one('security-control-disabled', ['control_state'], [otel('1701', 'security_control_activity', 'disable')]),
  correlationOnly('auth-identity-many-targets', ['authentication'], Array.from({ length: 8 }, (_, index) => otel(`400${index}`, 'authentication', 'remote_logon', { category: 'identity' }, { 'host.id': `target-${index}` }))),
  correlationOnly('auth-failure-then-success', ['authentication'], [otel('4101', 'authentication', 'remote_logon', { category: 'identity', outcome: 'failure' }), otel('4102', 'authentication', 'remote_logon', { category: 'identity', outcome: 'success' })]),
  correlationOnly('security-policy-changed', ['configuration_change'], [{ id: 'policy-change', eventTime: TIME, actor: { id: 'operator' }, action: 'update', target: { id: 'policy', type: 'acl' } }], 'tailscale-logs', { logType: 'configuration-audit', tailnet: 'attack.example' }),
  correlationOnly('credential-created', ['credential_inventory'], [otel('4201', 'credential_management', 'create_key', { category: 'identity', credentialKind: 'api_key', privilegedOwner: false })]),
  correlationOnly('persistent-service-created', ['service_inventory'], [otel('4301', 'service_activity', 'create', { serviceName: 'validation.service' })]),
  correlationOnly('authorization-failure-burst', ['resource_access'], Array.from({ length: 20 }, (_, index) => otel(`440${index}`, 'authorization', 'access', { category: 'application', outcome: 'failure' }, { 'service.name': 'validation-app' }))),
  correlationOnly('resource-enumeration', ['resource_access'], Array.from({ length: 50 }, (_, index) => otel(`450${index}`, 'resource_access', 'read', { category: 'application', resourceId: `resource-${index}` }, { 'service.name': 'validation-app' }))),
  correlationOnly('dns-failure-burst', ['dns'], Array.from({ length: 30 }, (_, index) => ({ ts: Date.parse(TIME) / 1000 + index, uid: `dns-${index}`, 'id.orig_h': '192.0.2.10', 'id.resp_h': '192.0.2.53', query: `missing-${index}.example`, qtype_name: 'A', rcode_name: 'NXDOMAIN' })), 'zeek', { logType: 'dns' }),
  correlationOnly('network-destination-scan', ['network_flow'], Array.from({ length: 5 }, (_, index) => ({ ts: Date.parse(TIME) / 1000 + index, uid: `scan-${index}`, 'id.orig_h': '192.0.2.10', 'id.resp_h': `192.0.2.${20 + index}`, proto: 'tcp', conn_state: 'S0', orig_bytes: 0 })), 'zeek', { logType: 'conn' }),
  correlationOnly('sensitive-resource-created', ['data_resource_inventory'], [otel('4601', 'resource_activity', 'create', { category: 'data', resourceId: 'sensitive-validation' })])
];

const nearMissSteps = {
  'auth-failure-burst': [{ normalizer: 'linux-journal', records: Array.from({ length: 11 }, (_, index) => linuxJournal(`s=benign-auth-${index}`, 'sshd', `Failed password for root from 192.0.2.10 port ${3200 + index} ssh2`)), context: {} }],
  'auth-source-many-identities': [{ normalizer: 'linux-journal', records: Array.from({ length: 5 }, (_, index) => linuxJournal(`s=benign-spray-${index}`, 'sshd', `Failed password for user${index} from 192.0.2.11 port ${3300 + index} ssh2`)), context: {} }],
  'remote-auth-then-execution': [{ normalizer: 'opentelemetry-log', records: [otel('2001', 'authentication', 'remote_logon', { category: 'identity' }), otel('2002', 'process_activity', 'start', { category: 'system', parentType: 'scheduled_task', executable: '/usr/bin/true' })], context: {} }],
  'remote-auth-then-privilege-use': [{ normalizer: 'opentelemetry-log', records: [otel('2101', 'privilege_use', 'sudo', { category: 'identity', 'security.actor.target_id': 'root' })], context: {} }],
  'remote-auth-then-account-created': [{ normalizer: 'opentelemetry-log', records: [otel('2201', 'account_management', 'create', { category: 'identity', loginEnabled: true })], context: {} }],
  'remote-auth-then-persistence': [{ normalizer: 'opentelemetry-log', records: [otel('2301', 'service_activity', 'enable', { serviceName: 'approved.service' })], context: {} }],
  'remote-auth-then-listener-created': [{ normalizer: 'opentelemetry-log', records: [otel('2401', 'exposure_activity', 'listener_create', { exposureScope: 'all_interfaces', port: 8443 })], context: {} }],
  'service-spawned-command-interpreter': [{ normalizer: 'opentelemetry-log', records: [otel('2501', 'process_activity', 'start', { category: 'system', parentType: 'network_service', processType: 'worker', executable: '/usr/bin/worker' })], context: {} }],
  'telemetry-disabled': [{ normalizer: 'opentelemetry-log', records: [otel('2601', 'sensor_activity', 'heartbeat', { category: 'health' })], context: {} }],
  'security-log-cleared': [{ normalizer: 'linux-journal', records: [{ __CURSOR: 's=benign-exec', _HOSTNAME: 'attack-target', MESSAGE: 'type=EXECVE msg=audit(1787169600.000:100): argc=1 a0="/usr/bin/id"' }], context: {} }],
  'route-or-exit-node-enabled': [{ normalizer: 'tailscale-logs', records: [{ id: 'policy-1', eventTime: TIME, actor: { id: 'operator' }, action: 'update', target: { id: 'policy', type: 'acl' } }], context: { logType: 'configuration-audit', tailnet: 'attack.example' } }],
  'privileged-role-granted': [{ normalizer: 'opentelemetry-log', records: [otel('2701', 'group_management', 'add_member', { category: 'identity' })], context: {} }],
  'mfa-protection-disabled': [{ normalizer: 'opentelemetry-log', records: [otel('2801', 'authentication_factor_activity', 'enable', { category: 'identity' })], context: {} }],
  'privileged-ssh-credential-changed': [{ normalizer: 'opentelemetry-log', records: [otel('2901', 'credential_management', 'add_credential', { category: 'identity', credentialKind: 'ssh_authorized_keys', privilegedOwner: false })], context: {} }],
  'local-account-created': [{ normalizer: 'opentelemetry-log', records: [otel('3001', 'account_management', 'create', { category: 'identity', loginEnabled: false })], context: {} }],
  'new-or-unapproved-access': [{ normalizer: 'opentelemetry-log', records: [otel('3101', 'authentication', 'service_access', { category: 'identity', accessDecision: 'approved' })], context: {} }],
  'large-egress-transfer': [{ normalizer: 'zeek', records: [{ ts: Date.parse(TIME) / 1000, uid: 'small-egress', 'id.orig_h': '192.0.2.10', 'id.resp_h': '198.51.100.20', proto: 'tcp', conn_state: 'SF', orig_bytes: 1999999999 }], context: { logType: 'conn' } }],
  'backup-protection-disabled': [{ normalizer: 'opentelemetry-log', records: [otel('3201', 'backup_activity', 'enable')], context: {} }],
  'public-share-created': [{ normalizer: 'opentelemetry-log', records: [otel('3301', 'sharing_activity', 'internal_create')], context: {} }],
  'data-staging-then-egress': [{ normalizer: 'opentelemetry-log', records: [otel('3401', 'archive_activity', 'create', { category: 'data' })], context: {} }],
  'network-listener-created': [{ normalizer: 'opentelemetry-log', records: [otel('3501', 'exposure_activity', 'listener_create', { exposureScope: 'loopback', port: 8080 })], context: {} }],
  'security-control-disabled': [{ normalizer: 'opentelemetry-log', records: [otel('3601', 'security_control_activity', 'enable')], context: {} }]
};

Object.assign(nearMissSteps, {
  'auth-identity-many-targets': [{ normalizer: 'opentelemetry-log', records: Array.from({ length: 7 }, (_, index) => otel(`500${index}`, 'authentication', 'remote_logon', { category: 'identity' }, { 'host.id': `benign-target-${index}` })), context: {} }],
  'auth-failure-then-success': [{ normalizer: 'opentelemetry-log', records: [otel('5101', 'authentication', 'remote_logon', { category: 'identity', outcome: 'success' })], context: {} }],
  'security-policy-changed': [{ normalizer: 'tailscale-logs', records: [{ id: 'policy-read', eventTime: TIME, actor: { id: 'operator' }, action: 'read', target: { id: 'policy', type: 'acl' } }], context: { logType: 'configuration-audit', tailnet: 'attack.example' } }],
  'credential-created': [{ normalizer: 'opentelemetry-log', records: [otel('5201', 'credential_management', 'inspect', { category: 'identity' })], context: {} }],
  'persistent-service-created': [{ normalizer: 'opentelemetry-log', records: [otel('5301', 'service_activity', 'start', { serviceName: 'existing.service' })], context: {} }],
  'authorization-failure-burst': [{ normalizer: 'opentelemetry-log', records: Array.from({ length: 19 }, (_, index) => otel(`540${index}`, 'authorization', 'access', { category: 'application', outcome: 'failure' }, { 'service.name': 'validation-app' })), context: {} }],
  'resource-enumeration': [{ normalizer: 'opentelemetry-log', records: Array.from({ length: 49 }, (_, index) => otel(`550${index}`, 'resource_access', 'read', { category: 'application', resourceId: `resource-${index}` }, { 'service.name': 'validation-app' })), context: {} }],
  'dns-failure-burst': [{ normalizer: 'zeek', records: Array.from({ length: 29 }, (_, index) => ({ ts: Date.parse(TIME) / 1000 + index, uid: `benign-dns-${index}`, 'id.orig_h': '192.0.2.10', 'id.resp_h': '192.0.2.53', query: `missing-${index}.example`, qtype_name: 'A', rcode_name: 'NXDOMAIN' })), context: { logType: 'dns' } }],
  'network-destination-scan': [{ normalizer: 'zeek', records: Array.from({ length: 4 }, (_, index) => ({ ts: Date.parse(TIME) / 1000 + index, uid: `benign-scan-${index}`, 'id.orig_h': '192.0.2.10', 'id.resp_h': `192.0.2.${40 + index}`, proto: 'tcp', conn_state: 'S0', orig_bytes: 0 })), context: { logType: 'conn' } }],
  'sensitive-resource-created': [{ normalizer: 'opentelemetry-log', records: [otel('5601', 'resource_activity', 'read', { category: 'data', resourceId: 'known-resource' })], context: {} }]
});

for (const scenario of scenarios) scenario.nearMissSteps = nearMissSteps[scenario.id] || [];

async function runScenario(scenario) {
  const execute = async (steps, label) => {
    const directory = await fs.mkdtemp(path.join(os.tmpdir(), `lookout-attack-${scenario.id}-${label}-`));
    try {
      const runtime = await new LookoutRuntime({ dataDirectory: directory }).initialize();
      await runtime.applySurveyFacts(capabilityFacts(scenario.capabilities));
      for (const step of steps) await runtime.ingestRaw(step.normalizer, step.records, { receivedAt: TIME, instance: `attack:${scenario.id}:${label}`, ...step.context });
      return runtime.cases.snapshot();
    } finally {
      await fs.rm(directory, { recursive: true, force: true });
    }
  };
  try {
    const snapshot = await execute(scenario.steps, 'positive');
    const finding = snapshot.findings.find((item) => item.ruleId === scenario.expectedRuleId);
    const alert = snapshot.alerts.find((item) => item.ruleId === scenario.expectedRuleId);
    const nearMiss = await execute(scenario.nearMissSteps, 'near-miss');
    const falsePositive = nearMiss.findings.find((item) => item.ruleId === scenario.expectedRuleId);
    const expectedAlert = scenario.expectedAlert !== false;
    const dispositionCorrect = expectedAlert ? Boolean(alert) : !alert;
    return { id: scenario.id, passed: Boolean(finding) && dispositionCorrect && !falsePositive, findingId: finding?.id || null, alertId: alert?.id || null, expectedDisposition: expectedAlert ? 'alert' : 'correlation_only', nearMissRejected: !falsePositive, findings: snapshot.findings.map((item) => item.ruleId), alerts: snapshot.alerts.map((item) => item.ruleId) };
  } catch (error) {
    return { id: scenario.id, passed: false, error: error.message };
  }
}

async function runAttackSimulations() {
  const alertingRules = analytics.map((rule) => rule.id).sort();
  const covered = scenarios.map((scenario) => scenario.expectedRuleId).sort();
  const missingScenarios = alertingRules.filter((id) => !covered.includes(id));
  const unexpectedScenarios = covered.filter((id) => !alertingRules.includes(id));
  const duplicateScenarios = covered.filter((id, index) => covered.indexOf(id) !== index);
  if (missingScenarios.length || unexpectedScenarios.length || duplicateScenarios.length) return { passed: false, missingScenarios, unexpectedScenarios, duplicateScenarios, results: [] };
  const results = [];
  for (const scenario of scenarios) results.push(await runScenario(scenario));
  return { passed: results.every((result) => result.passed), missingScenarios: [], unexpectedScenarios: [], duplicateScenarios: [], results };
}

async function main() {
  const report = await runAttackSimulations();
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  if (!report.passed) process.exitCode = 1;
}

if (require.main === module) main().catch((error) => { console.error(error.message); process.exitCode = 1; });

module.exports = { scenarios, nearMissSteps, runScenario, runAttackSimulations };

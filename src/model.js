'use strict';

const nodes = [
  { id: 'zone-internet', type: 'zone', name: 'Internet', status: 'external', risk: 0 },
  { id: 'zone-lan', type: 'zone', name: 'Private LAN', status: 'healthy', risk: 4 },
  { id: 'asset-gateway', type: 'asset', name: 'Gateway', subtype: 'network', os: 'OpenWrt', status: 'warning', risk: 58, address: '192.168.1.1' },
  { id: 'asset-nas', type: 'asset', name: 'Storage', subtype: 'server', os: 'Linux', status: 'healthy', risk: 22, address: '192.168.1.20' },
  { id: 'asset-automation', type: 'asset', name: 'Automation', subtype: 'service', os: 'Linux', status: 'healthy', risk: 18, address: '192.168.1.30' },
  { id: 'asset-camera', type: 'asset', name: 'Camera', subtype: 'endpoint', os: 'Embedded Linux', status: 'critical', risk: 81, address: '192.168.1.44' },
  { id: 'asset-admin', type: 'asset', name: 'Admin laptop', subtype: 'endpoint', os: 'macOS', status: 'healthy', risk: 14, address: '192.168.1.103' },
  { id: 'service-ssh', type: 'service', name: 'SSH', status: 'healthy', risk: 19, port: 22 },
  { id: 'service-web', type: 'service', name: 'Admin UI', status: 'warning', risk: 46, port: 443 },
  { id: 'identity-admin', type: 'identity', name: 'local-admin', status: 'healthy', risk: 36, privilege: 'administrator' },
  { id: 'credential-ssh', type: 'credential', name: 'SSH key', status: 'healthy', risk: 42, storage: 'hardware-backed' },
  { id: 'telemetry-zeek', type: 'telemetry', name: 'Network sensor', status: 'healthy', risk: 0, freshnessSeconds: 12, capabilities: ['network_flow', 'dns', 'tls', 'dhcp', 'sensor_health'] },
  { id: 'telemetry-host', type: 'telemetry', name: 'Endpoint sensor', status: 'degraded', risk: 0, freshnessSeconds: 311, capabilities: ['authentication', 'privilege_use', 'process_execution', 'service_state', 'configuration_change', 'file_access', 'network_flow', 'sensor_health'] },
  { id: 'control-firewall', type: 'control', name: 'Default-deny firewall', status: 'healthy', risk: 0 }
];

const edges = [
  { from: 'zone-internet', to: 'asset-gateway', relation: 'reachable_from' },
  { from: 'asset-gateway', to: 'zone-lan', relation: 'routes_to' },
  { from: 'zone-lan', to: 'asset-nas', relation: 'contains' },
  { from: 'zone-lan', to: 'asset-automation', relation: 'contains' },
  { from: 'zone-lan', to: 'asset-camera', relation: 'contains' },
  { from: 'zone-lan', to: 'asset-admin', relation: 'contains' },
  { from: 'asset-nas', to: 'service-ssh', relation: 'runs' },
  { from: 'asset-gateway', to: 'service-web', relation: 'runs' },
  { from: 'identity-admin', to: 'asset-nas', relation: 'administers' },
  { from: 'identity-admin', to: 'asset-gateway', relation: 'administers' },
  { from: 'identity-admin', to: 'credential-ssh', relation: 'uses' },
  { from: 'credential-ssh', to: 'service-ssh', relation: 'authenticates_to' },
  { from: 'telemetry-zeek', to: 'zone-lan', relation: 'observes' },
  { from: 'telemetry-host', to: 'asset-nas', relation: 'observes' },
  { from: 'control-firewall', to: 'asset-gateway', relation: 'protects' }
];

const behaviors = [
  {
    id: 'behavior-exploit-public-service',
    name: 'Exploit an exposed service',
    priority: 'critical',
    rationale: 'The gateway is the only internet-adjacent trust boundary.',
    appliesWhen: { nodeType: 'asset', relation: 'reachable_from', sourceType: 'zone' },
    telemetry: ['network_flow', 'http_transaction', 'service_auth', 'process_execution'],
    rules: ['rule-exposure-drift', 'rule-web-to-shell']
  },
  {
    id: 'behavior-valid-account-abuse',
    name: 'Abuse a privileged identity',
    priority: 'high',
    rationale: 'One identity administers multiple high-impact systems.',
    appliesWhen: { nodeType: 'identity', relation: 'administers' },
    telemetry: ['authentication', 'privilege_use', 'process_execution', 'network_flow'],
    rules: ['rule-auth-spray', 'rule-admin-novel-target']
  },
  {
    id: 'behavior-lateral-movement',
    name: 'Move laterally between private services',
    priority: 'high',
    rationale: 'A flat private segment permits reachable relationships not required by normal operation.',
    appliesWhen: { nodeType: 'zone', relation: 'contains' },
    telemetry: ['network_flow', 'dns', 'authentication', 'process_execution'],
    rules: ['rule-new-east-west-edge', 'rule-remote-service-chain']
  },
  {
    id: 'behavior-disable-telemetry',
    name: 'Impair monitoring or logging',
    priority: 'high',
    rationale: 'Small deployments have few sensors; loss of one creates a material blind spot.',
    appliesWhen: { nodeType: 'telemetry', relation: 'observes' },
    telemetry: ['sensor_health', 'service_state', 'configuration_change'],
    rules: ['rule-sensor-silence']
  },
  {
    id: 'behavior-data-exfiltration',
    name: 'Stage or transfer unusual data volumes',
    priority: 'high',
    rationale: 'Storage services concentrate sensitive data and normally contact few external peers.',
    appliesWhen: { nodeType: 'asset', subtype: 'server' },
    telemetry: ['network_flow', 'dns', 'file_access', 'process_execution'],
    rules: ['rule-egress-volume', 'rule-rare-destination']
  }
];

const rules = [
  { id: 'rule-exposure-drift', name: 'Unexpected externally reachable service', severity: 'critical', kind: 'deterministic', state: 'enabled', evidence: ['listener', 'NAT/firewall change', 'external reachability check'] },
  { id: 'rule-web-to-shell', name: 'Internet-facing service spawns command interpreter', severity: 'critical', kind: 'correlation', state: 'enabled', evidence: ['web service process', 'child process', 'outbound connection'] },
  { id: 'rule-auth-spray', name: 'Authentication failures across identities or services', severity: 'high', kind: 'threshold', state: 'enabled', evidence: ['authentication result', 'source', 'target identity', 'time window'] },
  { id: 'rule-admin-novel-target', name: 'Privileged identity accesses a novel target', severity: 'medium', kind: 'behavioral', state: 'learning', evidence: ['identity', 'target', 'privilege', 'peer group'] },
  { id: 'rule-new-east-west-edge', name: 'New private network relationship', severity: 'medium', kind: 'behavioral', state: 'enabled', evidence: ['source', 'destination', 'service', 'first seen'] },
  { id: 'rule-remote-service-chain', name: 'Remote authentication followed by execution', severity: 'high', kind: 'correlation', state: 'enabled', evidence: ['authentication', 'session', 'process ancestry'] },
  { id: 'rule-sensor-silence', name: 'Expected sensor heartbeat missing', severity: 'high', kind: 'deterministic', state: 'enabled', evidence: ['last event time', 'sensor schedule', 'host availability'] },
  { id: 'rule-egress-volume', name: 'Outbound transfer exceeds host baseline', severity: 'medium', kind: 'behavioral', state: 'learning', evidence: ['bytes sent', 'host role', 'destination class', 'time bucket'] },
  { id: 'rule-rare-destination', name: 'Sensitive host contacts a rare destination', severity: 'medium', kind: 'behavioral', state: 'enabled', evidence: ['destination age', 'prevalence', 'DNS context', 'transfer volume'] }
];

const baselines = [
  { entity: 'identity-admin', feature: 'admin_target_set', default: ['asset-gateway', 'asset-nas'], method: 'set-membership', learning: '30d rolling with 7d warm-up', guardrail: 'never auto-promote a target observed during an active alert' },
  { entity: 'asset-nas', feature: 'outbound_bytes_per_hour', default: { warning: 500000000, critical: 2000000000 }, method: 'median + MAD by hour-of-week', learning: '28d rolling with minimum 12 buckets', guardrail: 'cap learned threshold change at 20% per week' },
  { entity: 'zone-lan', feature: 'network_relationships', default: [], method: 'decayed edge frequency', learning: '14d rolling with 48h warm-up', guardrail: 'new edges remain novel for at least 72h' },
  { entity: 'telemetry-host', feature: 'heartbeat_interval_seconds', default: { expected: 60, warning: 180, critical: 600 }, method: 'fixed schedule plus jitter', learning: 'not learned', guardrail: 'host availability suppresses incident escalation, not the evidence' }
];

const alerts = [
  { id: 'alert-101', title: 'Camera contacted a new external peer', severity: 'critical', status: 'investigating', asset: 'asset-camera', rule: 'rule-rare-destination', occurredAt: '2026-08-17T20:41:00-07:00', confidence: 0.86, evidenceCount: 4 },
  { id: 'alert-102', title: 'Host sensor heartbeat is delayed', severity: 'high', status: 'open', asset: 'asset-nas', rule: 'rule-sensor-silence', occurredAt: '2026-08-17T20:38:00-07:00', confidence: 0.98, evidenceCount: 2 },
  { id: 'alert-103', title: 'Gateway admin UI exposure changed', severity: 'medium', status: 'triaged', asset: 'asset-gateway', rule: 'rule-exposure-drift', occurredAt: '2026-08-17T18:09:00-07:00', confidence: 0.72, evidenceCount: 3 }
];

const adapterKinds = [
  { id: 'network-overlay', examples: ['tailscale'], emits: ['inventory', 'identity', 'network_policy', 'network_flow', 'route', 'configuration_change'] },
  { id: 'network-passive', examples: ['zeek'], emits: ['network_flow', 'dns', 'tls', 'dhcp', 'http_transaction'] },
  { id: 'endpoint', examples: ['linux-agent', 'macos-agent', 'windows-agent', 'edr-api'], emits: ['authentication', 'privilege_use', 'process_execution', 'file_access', 'service_state', 'configuration_change'] },
  { id: 'service', examples: ['audit-api', 'webhook', 'syslog', 'otel-logs'], emits: ['service_auth', 'resource_access', 'configuration_change', 'data_movement', 'sensor_health'] },
  { id: 'infrastructure', examples: ['firewall-api', 'cloud-api', 'hypervisor-api', 'snmp'], emits: ['inventory', 'network_policy', 'route', 'configuration_change', 'sensor_health'] },
  { id: 'declaration', examples: ['config-file', 'manual-survey'], emits: ['inventory', 'ownership', 'criticality', 'expected_relationship'] }
];

function sorted(items) {
  return [...items].sort((a, b) => a.id.localeCompare(b.id));
}

function buildGraph() {
  const nodeById = new Map(nodes.map((node) => [node.id, node]));
  const graphNodes = sorted(nodes).map((node) => ({
    ...node,
    degree: edges.filter((edge) => edge.from === node.id || edge.to === node.id).length,
    behaviors: behaviors
      .filter((behavior) => behavior.appliesWhen.nodeType === node.type && (!behavior.appliesWhen.subtype || behavior.appliesWhen.subtype === node.subtype))
      .map((behavior) => behavior.id)
      .sort()
  }));
  const graphEdges = [...edges]
    .filter((edge) => nodeById.has(edge.from) && nodeById.has(edge.to))
    .sort((a, b) => `${a.from}:${a.to}:${a.relation}`.localeCompare(`${b.from}:${b.to}:${b.relation}`));
  return { nodes: graphNodes, edges: graphEdges };
}

function coverage() {
  const ruleIds = new Set(rules.map((rule) => rule.id));
  return sorted(behaviors).map((behavior) => ({
    ...behavior,
    rules: behavior.rules.filter((id) => ruleIds.has(id)).sort(),
    coverageState: behavior.rules.some((id) => ruleIds.has(id)) ? 'covered' : 'gap'
  }));
}

function capabilityPlan() {
  const available = new Set(nodes.filter((node) => node.type === 'telemetry' && node.status !== 'offline').flatMap((node) => node.capabilities || []));
  return sorted(behaviors).map((behavior) => {
    const present = behavior.telemetry.filter((capability) => available.has(capability)).sort();
    const missing = behavior.telemetry.filter((capability) => !available.has(capability)).sort();
    return {
      behavior: behavior.id,
      desired: [...behavior.telemetry].sort(),
      present,
      missing,
      state: present.length === 0 ? 'gap' : missing.length === 0 ? 'full' : 'partial'
    };
  });
}

function snapshot() {
  return {
    generatedAt: new Date().toISOString(),
    graph: buildGraph(),
    behaviors: coverage(),
    rules: sorted(rules),
    adapters: sorted(adapterKinds),
    capabilityPlan: capabilityPlan(),
    baselines: [...baselines].sort((a, b) => `${a.entity}:${a.feature}`.localeCompare(`${b.entity}:${b.feature}`)),
    alerts: [...alerts].sort((a, b) => b.occurredAt.localeCompare(a.occurredAt)),
    summary: {
      assets: nodes.filter((node) => node.type === 'asset').length,
      activeAlerts: alerts.filter((alert) => alert.status !== 'closed').length,
      criticalAlerts: alerts.filter((alert) => alert.severity === 'critical' && alert.status !== 'closed').length,
      enabledRules: rules.filter((rule) => rule.state === 'enabled').length,
      telemetryHealth: nodes.filter((node) => node.type === 'telemetry' && node.status === 'healthy').length + '/' + nodes.filter((node) => node.type === 'telemetry').length
    }
  };
}

module.exports = { nodes, edges, behaviors, rules, baselines, alerts, adapterKinds, buildGraph, coverage, capabilityPlan, snapshot };

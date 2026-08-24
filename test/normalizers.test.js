'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { NormalizerRegistry } = require('../src/normalizers/contract');
const { zeekNormalizer } = require('../src/normalizers/zeek');
const { parseRFC5424, syslogNormalizer } = require('../src/normalizers/syslog');
const { openTelemetryNormalizer } = require('../src/normalizers/opentelemetry');
const { splitEndpoint, tailscaleLogNormalizer } = require('../src/normalizers/tailscale-logs');

const receivedAt = '2026-08-18T00:00:00.000Z';

test('Zeek normalizer preserves flow correlation and causal network fields', () => {
  const registry = new NormalizerRegistry().register(zeekNormalizer());
  const [event] = registry.normalize('zeek', { ts: 1787011200, uid: 'flow-1', 'id.orig_h': '100.64.0.10', 'id.orig_p': 45000, 'id.resp_h': '100.64.0.20', 'id.resp_p': 22, proto: 'tcp', service: 'ssh', duration: 1.2, orig_bytes: 120, resp_bytes: 90, conn_state: 'SF' }, { logType: 'conn', receivedAt });
  assert.equal(event.class, 'network_activity');
  assert.equal(event.correlation.flowId, 'flow-1');
  assert.equal(event.attributes.bytesSent, 120);
  assert.equal(event.destinationEndpoint.port, 22);
});

test('Zeek DNS and SSH events normalize into behavior-oriented classes', () => {
  const registry = new NormalizerRegistry().register(zeekNormalizer());
  const dns = registry.normalize('zeek', { ts: 1787011200, uid: 'dns-1', 'id.orig_h': '10.0.0.1', 'id.resp_h': '10.0.0.53', query: 'example.test', qtype_name: 'A', rcode_name: 'NOERROR', answers: ['192.0.2.1'] }, { logType: 'dns', receivedAt })[0];
  const ssh = registry.normalize('zeek', { ts: 1787011201, uid: 'ssh-1', 'id.orig_h': '10.0.0.1', 'id.resp_h': '10.0.0.2', auth_success: false, auth_attempts: 3 }, { logType: 'ssh', receivedAt })[0];
  assert.equal(dns.class, 'dns_activity');
  assert.equal(ssh.class, 'authentication');
  assert.equal(ssh.outcome, 'failure');
});

test('RFC 5424 parser handles structured data and hashes message bodies by default', () => {
  const line = '<34>1 2026-08-17T20:00:00Z server.example sshd 123 ID47 [origin software="sshd" ip="192.0.2.1"] Authentication log content';
  const parsed = parseRFC5424(line);
  assert.equal(parsed.facility, 4);
  assert.equal(parsed.structuredData.origin.ip, '192.0.2.1');
  const [event] = new NormalizerRegistry().register(syslogNormalizer()).normalize('syslog-rfc5424', line, { receivedAt });
  assert.equal(event.category, 'identity');
  assert.equal(event.attributes.message, undefined);
  assert.equal(event.attributes.messageDigest.length, 64);
});

test('OpenTelemetry normalization uses timestamp/resource/trace semantics without retaining body', () => {
  const record = { Timestamp: '1787011200000000000', ObservedTimestamp: '1787011201000000000', SeverityNumber: 17, EventName: 'admin.login', TraceId: 'trace-1', SpanId: 'span-1', Body: 'potentially sensitive text', Resource: { 'host.id': 'host-1', 'service.name': 'console' }, Attributes: { 'security.category': 'identity', 'security.class': 'authentication', 'security.activity': 'logon', 'event.outcome': 'success', 'enduser.id': 'user-1' } };
  const [event] = new NormalizerRegistry().register(openTelemetryNormalizer()).normalize('opentelemetry-log', record, { receivedAt });
  assert.equal(event.category, 'identity');
  assert.equal(event.correlation.traceId, 'trace-1');
  assert.ok(event.entityKeys.includes('endpoint:host-1'));
  assert.equal(event.attributes.body, undefined);
  assert.equal(event.attributes.bodyDigest.length, 64);
});

test('Tailscale flow normalization marks reporter identity separately from unverified flow detail', () => {
  assert.deepEqual(splitEndpoint('[fd7a:115c:a1e0::1]:443'), { address: 'fd7a:115c:a1e0::1', port: 443 });
  const normalizer = tailscaleLogNormalizer({ tailnet: 'tailnet-1' });
  const record = { nodeId: 'node-a', start: '2026-08-17T20:00:00Z', end: '2026-08-17T20:01:00Z', srcNode: { nodeId: 'node-a', addresses: ['100.64.0.1'], os: 'linux' }, dstNodes: [{ nodeId: 'node-b', addresses: ['100.64.0.2'] }], virtualTraffic: [{ proto: 6, src: '100.64.0.1:50000', dst: '100.64.0.2:443', txPkts: 4, txBytes: 500, rxPkts: 3, rxBytes: 900 }] };
  const [event] = new NormalizerRegistry().register(normalizer).normalize('tailscale-logs', record, { logType: 'network-flow', receivedAt });
  assert.equal(event.sourceEndpoint.id, 'tailscale:tailnet-1:device:node-a');
  assert.equal(event.destinationEndpoint.id, 'tailscale:tailnet-1:device:node-b');
  assert.equal(event.attributes.reporterIdentityVerified, true);
  assert.equal(event.attributes.flowDetailsVerified, false);
});

test('Tailscale configuration audit activity preserves actor and target context', () => {
  const [event] = new NormalizerRegistry().register(tailscaleLogNormalizer({ tailnet: 'tailnet-1' })).normalize('tailscale-logs', { id: 'audit-1', time: '2026-08-17T20:00:00Z', actor: { id: 'admin@example.test' }, action: 'update', target: { id: 'policy', type: 'acl' }, success: true }, { logType: 'configuration-audit', receivedAt });
  assert.equal(event.class, 'network_policy_activity');
  assert.equal(event.actor.id, 'admin@example.test');
  assert.equal(event.attributes.targetType, 'acl');
});

test('Tailscale route audit activity is classified for route-change detection', () => {
  const [event] = tailscaleLogNormalizer({ tailnet: 'example.test' }).normalize({ id: 'route-1', eventTime: receivedAt, actor: { id: 'admin' }, action: 'approve', target: { id: '10.0.0.0/8', type: 'route' } }, { logType: 'configuration-audit' });
  assert.equal(event.class, 'route_activity');
  assert.equal(event.activity, 'approve');
  assert.equal(event.attributes.targetType, 'route');
});

test('Tailscale normalizer can isolate multiple tailnets from ingestion context', () => {
  const registry = new NormalizerRegistry().register(tailscaleLogNormalizer());
  const record = { id: 'audit-context', time: '2026-08-17T20:00:00Z', actor: 'admin', action: 'update', target: 'policy' };
  const first = registry.normalize('tailscale-logs', record, { logType: 'configuration-audit', tailnet: 'tailnet-a', receivedAt })[0];
  const second = registry.normalize('tailscale-logs', record, { logType: 'configuration-audit', tailnet: 'tailnet-b', receivedAt })[0];
  assert.deepEqual(first.entityKeys, ['tailscale:tailnet-a:network']);
  assert.deepEqual(second.entityKeys, ['tailscale:tailnet-b:network']);
});

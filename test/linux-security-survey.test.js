'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { validateFact } = require('../src/core/validation');
const { linuxSecuritySurvey, commandRunner, parseListeners } = require('../src/collector/linux-security-survey');
const { systemCollector } = require('../src/collector/system');
const { LookoutRuntime } = require('../src/runtime');
const { analytics } = require('../src/detection/catalog');
const { evaluate } = require('../src/detection/engine');

function fakeRunner(fixtures) {
  return (name, args) => fixtures[`${name}:${args[0]}`] || fixtures[name] || { ok: false, stdout: '', reason: 'missing' };
}

test('Linux security survey inventories detection terrain without secret contents', () => {
  const runner = fakeRunner({
    ss: { ok: true, stdout: 'tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))\ntcp LISTEN 0 128 127.0.0.1:5432 0.0.0.0:* users:(("postgres",pid=2,fd=4))\ntcp LISTEN 0 128 100.64.0.1:4173 0.0.0.0:*\n' },
    'systemctl:list-unit-files': { ok: true, stdout: 'sshd.service enabled enabled\nauditd.service enabled enabled\nlookout.service enabled enabled\nunused.service disabled disabled\n' },
    'systemctl:list-units': { ok: true, stdout: 'sshd.service loaded active running OpenSSH\nauditd.service loaded active running Audit\nlookout.service loaded active running Lookout\n' },
    'getent:passwd': { ok: true, stdout: 'root:x:0:0:root:/root:/bin/bash\napp:x:1001:1001::/srv/app:/usr/sbin/nologin\n' },
    'getent:group': { ok: true, stdout: 'sudo:x:27:root\napp:x:1001:app\n' },
    dpkg: { ok: true, stdout: 'openssh-server\t1:9.0\npostgresql\t16.2\n' },
    findmnt: { ok: true, stdout: JSON.stringify({ filesystems: [{ target: '/', source: '/dev/vda1', fstype: 'ext4', options: 'rw' }, { target: '/srv/data', source: '/dev/vdb1', fstype: 'xfs', options: 'rw' }] }) }
  });
  const fsImpl = { lstatSync(filename) { if (filename === '/root/.ssh/authorized_keys') return { isFile: () => true, isSymbolicLink: () => false, uid: 0, mode: 0o100600, size: 99, mtime: new Date('2026-08-18T00:00:00Z') }; throw Object.assign(new Error('missing'), { code: 'ENOENT' }); } };
  const output = linuxSecuritySurvey({ collectorId: 'collector:test', entityKey: 'endpoint:test', runner, fsImpl, platform: 'linux', excludedListenerPorts: [4173] }).collect({ collectedAt: '2026-08-18T00:00:00.000Z' });
  output.facts.forEach(validateFact);
  const entities = output.facts.filter((fact) => fact.kind === 'entity').map((fact) => fact.data);
  const relationships = output.facts.filter((fact) => fact.kind === 'relationship').map((fact) => fact.data);
  const capabilities = new Map(output.facts.filter((fact) => fact.kind === 'capability').map((fact) => [fact.data.capability, fact.data.status]));
  assert.ok(entities.some((item) => item.entityType === 'service' && item.attributes.port === 22 && item.attributes.exposureScope === 'all_interfaces'));
  assert.ok(entities.some((item) => item.entityType === 'service' && item.name === 'auditd.service'));
  assert.ok(!entities.some((item) => item.name === 'unused.service'));
  assert.ok(!entities.some((item) => item.name === 'lookout.service' || item.attributes.port === 4173));
  assert.ok(entities.some((item) => item.entityType === 'identity' && item.name === 'root' && item.attributes.privileged));
  assert.ok(entities.some((item) => item.entityType === 'credential' && item.attributes.credentialKind === 'ssh_authorized_keys'));
  assert.ok(entities.some((item) => item.entityType === 'software' && item.name === 'openssh-server'));
  assert.ok(entities.some((item) => item.entityType === 'data_resource' && item.name === '/srv/data' && item.attributes.sensitivity === 'potentially_high'));
  assert.ok(entities.some((item) => item.entityType === 'control' && item.name === 'Audit logging'));
  assert.ok(relationships.some((item) => item.from === 'endpoint:test' && item.relation === 'runs'));
  assert.equal(capabilities.get('service_inventory'), 'available');
  assert.equal(capabilities.get('exposure'), 'degraded');
  assert.equal(capabilities.get('privilege_inventory'), 'degraded');
  const encoded = JSON.stringify(output);
  assert.doesNotMatch(encoded, /PRIVATE KEY|password=|secret=/i);
});

test('listener parsing distinguishes loopback and all-interface exposure', () => {
  const listeners = parseListeners('tcp LISTEN 0 10 [::]:443 [::]:*\ntcp LISTEN 0 10 127.0.0.1:8080 0.0.0.0:*\n');
  assert.equal(listeners.find((item) => item.port === 443).exposureScope, 'all_interfaces');
  assert.equal(listeners.find((item) => item.port === 8080).exposureScope, 'loopback');
});

test('survey persists a baseline and emits only security-relevant inventory changes', () => {
  const base = {
    ss: { ok: true, stdout: 'tcp LISTEN 0 128 127.0.0.1:22 0.0.0.0:*\n' },
    'systemctl:list-unit-files': { ok: true, stdout: 'auditd.service enabled enabled\n' },
    'systemctl:list-units': { ok: true, stdout: 'auditd.service loaded active running Audit\n' },
    'getent:passwd': { ok: true, stdout: 'root:x:0:0:root:/root:/bin/bash\n' },
    'getent:group': { ok: true, stdout: 'sudo:x:27:root\n' },
    dpkg: { ok: true, stdout: 'openssh-server\t9.0\n' },
    findmnt: { ok: true, stdout: JSON.stringify({ filesystems: [{ target: '/', source: '/dev/vda1', fstype: 'ext4', options: 'rw' }] }) }
  };
  const noKeys = { lstatSync() { throw Object.assign(new Error('missing'), { code: 'ENOENT' }); } };
  const first = linuxSecuritySurvey({ collectorId: 'collector:test', entityKey: 'endpoint:test', runner: fakeRunner(base), fsImpl: noKeys, platform: 'linux' }).collect({ collectedAt: '2026-08-18T00:00:00.000Z', state: null });
  assert.equal(first.events.length, 0);
  const changed = { ...base, ss: { ok: true, stdout: `${base.ss.stdout}tcp LISTEN 0 128 0.0.0.0:8443 0.0.0.0:*\n` } };
  const second = linuxSecuritySurvey({ collectorId: 'collector:test', entityKey: 'endpoint:test', runner: fakeRunner(changed), fsImpl: noKeys, platform: 'linux' }).collect({ collectedAt: '2026-08-18T00:05:00.000Z', state: first.state });
  assert.equal(second.events.length, 1);
  assert.equal(second.events[0].class, 'exposure_activity');
  assert.equal(second.events[0].attributes.port, 8443);
  const persistenceChange = {
    ...base,
    'getent:passwd': { ok: true, stdout: `${base['getent:passwd'].stdout}operator:x:1002:1002::/home/operator:/bin/bash\n` },
    'systemctl:list-unit-files': { ok: true, stdout: `${base['systemctl:list-unit-files'].stdout}backdoor.service enabled enabled\n` },
    'systemctl:list-units': { ok: true, stdout: `${base['systemctl:list-units'].stdout}backdoor.service loaded active running Unknown\n` }
  };
  const persistence = linuxSecuritySurvey({ collectorId: 'collector:test', entityKey: 'endpoint:test', runner: fakeRunner(persistenceChange), fsImpl: noKeys, platform: 'linux' }).collect({ collectedAt: '2026-08-18T00:05:00.000Z', state: first.state });
  assert.ok(persistence.events.some((event) => event.class === 'account_management' && event.activity === 'create'));
  assert.ok(persistence.events.some((event) => event.class === 'service_activity' && event.activity === 'create'));
});

test('survey identifies privileged SSH credential drift for a high-confidence rule', () => {
  const fixtures = {
    ss: { ok: true, stdout: '' }, 'systemctl:list-unit-files': { ok: true, stdout: '' }, 'systemctl:list-units': { ok: true, stdout: '' },
    'getent:passwd': { ok: true, stdout: 'root:x:0:0:root:/root:/bin/bash\n' }, 'getent:group': { ok: true, stdout: 'sudo:x:27:root\n' },
    dpkg: { ok: true, stdout: '' }, findmnt: { ok: true, stdout: '{"filesystems":[]}' }
  };
  const absent = { lstatSync() { throw Object.assign(new Error('missing'), { code: 'ENOENT' }); } };
  const present = { lstatSync(filename) { if (filename !== '/root/.ssh/authorized_keys') throw new Error('unexpected'); return { isFile: () => true, isSymbolicLink: () => false, uid: 0, mode: 0o100600, size: 80, mtime: new Date('2026-08-18T00:05:00Z') }; } };
  const first = linuxSecuritySurvey({ collectorId: 'collector:test', entityKey: 'endpoint:test', runner: fakeRunner(fixtures), fsImpl: absent, platform: 'linux' }).collect({ collectedAt: '2026-08-18T00:00:00.000Z' });
  const second = linuxSecuritySurvey({ collectorId: 'collector:test', entityKey: 'endpoint:test', runner: fakeRunner(fixtures), fsImpl: present, platform: 'linux' }).collect({ collectedAt: '2026-08-18T00:05:00.000Z', state: first.state });
  const credentialEvent = second.events.find((event) => event.class === 'credential_management');
  assert.equal(credentialEvent.attributes.privilegedOwner, true);
  assert.equal(credentialEvent.attributes.credentialKind, 'ssh_authorized_keys');
  const rule = analytics.find((item) => item.id === 'privileged-ssh-credential-changed');
  assert.equal(evaluate([rule], second.events).length, 1);
});

test('non-Linux collectors do not claim Linux survey capabilities', () => {
  const output = linuxSecuritySurvey({ collectorId: 'collector:test', entityKey: 'endpoint:test', platform: 'darwin' }).collect({ collectedAt: '2026-08-18T00:00:00.000Z' });
  assert.deepEqual(output, { facts: [], events: [] });
});

test('bounded command runner preserves record separators without invoking a shell', () => {
  let invocation;
  const run = commandRunner({
    fsImpl: { statSync() { return { isFile: () => true }; } },
    execFileSyncImpl(binary, args, options) { invocation = { binary, args, options }; return 'one\t1\ntwo\t2\n'; }
  });
  const result = run('dpkg', ['-W']);
  assert.equal(result.stdout, 'one\t1\ntwo\t2\n');
  assert.equal(invocation.binary, '/usr/bin/dpkg-query');
  assert.deepEqual(invocation.args, ['-W']);
  assert.equal(invocation.options.stdio[0], 'ignore');
});

test('survey drift activates a matching rule and becomes an alert end to end', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-security-survey-'));
  const base = {
    ss: { ok: true, stdout: 'tcp LISTEN 0 128 127.0.0.1:22 0.0.0.0:*\n' },
    'systemctl:list-unit-files': { ok: true, stdout: '' }, 'systemctl:list-units': { ok: true, stdout: '' },
    'getent:passwd': { ok: true, stdout: 'root:x:0:0:root:/root:/bin/bash\n' }, 'getent:group': { ok: true, stdout: 'root:x:0:\n' },
    dpkg: { ok: true, stdout: '' }, findmnt: { ok: true, stdout: '{"filesystems":[]}' }
  };
  const noMetadata = { lstatSync() { throw Object.assign(new Error('missing'), { code: 'ENOENT' }); } };
  try {
    const system = systemCollector({ collectorId: 'collector:test', entityKey: 'endpoint:test' }).collect({ collectedAt: '2026-08-18T00:00:00.000Z', sequence: 1 });
    const first = linuxSecuritySurvey({ collectorId: 'collector:test', entityKey: 'endpoint:test', runner: fakeRunner(base), fsImpl: noMetadata, platform: 'linux' }).collect({ collectedAt: '2026-08-18T00:00:00.000Z', state: null });
    const runtime = await new LookoutRuntime({ dataDirectory: directory }).initialize();
    await runtime.applySurveyFacts([...system.facts, ...first.facts]);
    assert.equal(runtime.detectionPlan().find((item) => item.analyticId === 'network-listener-created').deploy, true);
    const changed = { ...base, ss: { ok: true, stdout: `${base.ss.stdout}tcp LISTEN 0 128 0.0.0.0:8443 0.0.0.0:*\n` } };
    const second = linuxSecuritySurvey({ collectorId: 'collector:test', entityKey: 'endpoint:test', runner: fakeRunner(changed), fsImpl: noMetadata, platform: 'linux' }).collect({ collectedAt: '2026-08-18T00:05:00.000Z', state: first.state });
    const result = await runtime.ingest(second.events);
    assert.ok(result.alerts.some((alert) => alert.ruleId === 'network-listener-created'));
    await runtime.applySurveyFacts(second.facts);
    assert.ok(runtime.graph.snapshot().entities.some((entity) => entity.key === 'endpoint:test:service:tcp:8443'));
    const third = linuxSecuritySurvey({ collectorId: 'collector:test', entityKey: 'endpoint:test', runner: fakeRunner(base), fsImpl: noMetadata, platform: 'linux' }).collect({ collectedAt: '2026-08-18T00:10:00.000Z', state: second.state });
    await runtime.applySurveyFacts(third.facts);
    assert.ok(!runtime.graph.snapshot().entities.some((entity) => entity.key === 'endpoint:test:service:tcp:8443'));
  } finally { await fs.rm(directory, { recursive: true, force: true }); }
});

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { EventEmitter } = require('node:events');
const { PassThrough } = require('node:stream');
const { NormalizerRegistry } = require('../src/normalizers/contract');
const { parseAuditFields, linuxJournalNormalizer } = require('../src/normalizers/linux-journal');
const { LinuxJournalSource } = require('../src/collector/linux-journal-source');

const receivedAt = '2026-08-18T01:00:00.000Z';

function normalize(record) {
  return new NormalizerRegistry().register(linuxJournalNormalizer()).normalize('linux-journal', record, { receivedAt });
}

function fakeSpawn(lines, { code = 0, error = null } = {}) {
  const calls = [];
  const implementation = (command, args, options) => {
    calls.push({ command, args, options });
    const child = new EventEmitter();
    child.stdout = new PassThrough();
    child.stderr = new PassThrough();
    child.kill = (signal) => { queueMicrotask(() => child.emit('close', null, signal)); };
    queueMicrotask(() => {
      if (error) { child.emit('error', error); return; }
      child.stdout.end(lines.map((line) => `${JSON.stringify(line)}\n`).join(''));
      child.stderr.end();
      queueMicrotask(() => child.emit('close', code, null));
    });
    return child;
  };
  implementation.calls = calls;
  return implementation;
}

function liveSpawn() {
  let child;
  const implementation = () => {
    child = new EventEmitter();
    child.stdout = new PassThrough();
    child.stderr = new PassThrough();
    child.kill = (signal) => queueMicrotask(() => child.emit('close', null, signal));
    return child;
  };
  implementation.write = (record) => child.stdout.write(`${JSON.stringify(record)}\n`);
  return implementation;
}

function rawSpawn(lines) {
  const calls = [];
  const implementation = (command, args, options) => {
    calls.push({ command, args, options });
    const child = new EventEmitter();
    child.stdout = new PassThrough();
    child.stderr = new PassThrough();
    child.kill = (signal) => queueMicrotask(() => child.emit('close', null, signal));
    queueMicrotask(() => {
      child.stdout.end(lines.map((line) => `${line}\n`).join(''));
      child.stderr.end();
      queueMicrotask(() => child.emit('close', 0, null));
    });
    return child;
  };
  implementation.calls = calls;
  return implementation;
}

test('Linux journal classifies successful and failed SSH while retaining bounded local context', () => {
  const successful = normalize({ __CURSOR: 's=1', __REALTIME_TIMESTAMP: '1787011200000000', _HOSTNAME: 'server-a', SYSLOG_IDENTIFIER: 'sshd', MESSAGE: 'Accepted publickey for alice from 100.64.0.8 port 53000 ssh2: ED25519 SHA256:abc' })[0];
  const failed = normalize({ __CURSOR: 's=2', _HOSTNAME: 'server-a', SYSLOG_IDENTIFIER: 'sshd', MESSAGE: 'Failed password for invalid user nobody from 192.0.2.4 port 40222 ssh2' })[0];
  assert.equal(successful.class, 'authentication');
  assert.equal(successful.outcome, 'success');
  assert.equal(successful.actor.id, 'alice');
  assert.equal(failed.outcome, 'failure');
  assert.equal(failed.sourceEndpoint.address, '192.0.2.4');
  assert.equal(successful.attributes.message.includes('ED25519 SHA256:abc'), true);
  assert.equal(successful.attributes.messageDigest.length, 64);
});

test('Linux journal detects sudo, account changes, service changes, and log clearing', () => {
  const examples = [
    [{ __CURSOR: 's=3', SYSLOG_IDENTIFIER: 'sudo', MESSAGE: 'alice : TTY=pts/1 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id' }, 'privilege_use'],
    [{ __CURSOR: 's=4', SYSLOG_IDENTIFIER: 'useradd', MESSAGE: 'new user: name=tester, UID=1002' }, 'account_management'],
    [{ __CURSOR: 's=5', SYSLOG_IDENTIFIER: 'systemd', MESSAGE: 'Started OpenSSH server daemon.' }, 'service_activity'],
    [{ __CURSOR: 's=6', SYSLOG_IDENTIFIER: 'journalctl', MESSAGE: 'journalctl --vacuum-time=1s complete' }, 'log_activity']
  ];
  for (const [record, expected] of examples) {
    const event = normalize(record)[0];
    assert.equal(event.class, expected);
    assert.equal(typeof event.attributes.message, 'string');
  }
});

test('Linux audit normalization preserves process/session causal identifiers but not argv', () => {
  const message = 'type=EXECVE msg=audit(1787011200.123:42): argc=3 a0="/usr/bin/curl" a1="--header" a2="Authorization: Bearer very-secret" pid=901 ppid=800 ses=7 auid=1000';
  const event = normalize({ __CURSOR: 's=audit', _TRANSPORT: 'audit', _HOSTNAME: 'server-a', MESSAGE: message })[0];
  assert.equal(event.class, 'process_activity');
  assert.equal(event.activity, 'start');
  assert.equal(event.correlation.auditId, '1787011200.123:42');
  assert.equal(event.correlation.processId, '901');
  assert.equal(event.correlation.parentProcessId, '800');
  assert.equal(event.correlation.sessionId, '7');
  assert.equal(event.attributes.executable, '/usr/bin/curl');
  assert.equal(JSON.stringify(event).includes('very-secret'), false);
});

test('Linux audit recognizes authentication, account/configuration changes, exec log clearing, and outcomes', () => {
  const records = [
    ['type=USER_AUTH msg=audit(1787011200.1:50): pid=1 uid=0 auid=1000 acct="alice" addr=100.64.0.2 res=failed', 'authentication', 'failure'],
    ['type=ADD_USER msg=audit(1787011200.2:51): pid=2 auid=1000 id=1002 res=success', 'account_management', 'success'],
    ['type=CONFIG_CHANGE msg=audit(1787011200.3:52): auid=0 op=add_rule key="identity" res=1', 'configuration_change', 'success'],
    ['type=EXECVE msg=audit(1787011200.4:53): argc=2 a0="/usr/bin/journalctl" a1="--vacuum-time=1s" auid=1000', 'log_activity', 'unknown']
  ];
  for (const [message, eventClass, outcome] of records) {
    const event = normalize({ __CURSOR: `s=${eventClass}`, _TRANSPORT: 'audit', MESSAGE: message })[0];
    assert.equal(event.class, eventClass);
    assert.equal(event.outcome, outcome);
  }
  const generic = normalize({ __CURSOR: 's=noise', SYSLOG_IDENTIFIER: 'kernel', MESSAGE: 'routine unclassified message' })[0];
  assert.equal(generic.class, 'journal_record');
  const numeric = normalize({ __CURSOR: 's=numeric', _TRANSPORT: 'audit', _AUDIT_TYPE: '1100', MESSAGE: 'msg=audit(1787011200.5:54): acct="alice" res=success' })[0];
  assert.equal(numeric.class, 'authentication');
});

test('Linux audit correlates a remote login session to later process execution', () => {
  const normalizer = linuxJournalNormalizer({ entityKey: 'endpoint:server-a' });
  const receivedAt = '2026-08-18T00:00:00.000Z';
  const login = normalizer.normalize({ __CURSOR: 's=login', _TRANSPORT: 'audit', MESSAGE: 'type=USER_LOGIN msg=audit(1787011200.1:60): pid=10 uid=0 auid=1000 acct="alice" addr=100.64.0.8 ses=9 res=success' }, { receivedAt })[0];
  const execution = normalizer.normalize({ __CURSOR: 's=exec', _TRANSPORT: 'audit', MESSAGE: 'type=EXECVE msg=audit(1787011201.1:61): argc=1 a0="/bin/bash" pid=11 ppid=10 auid=1000 ses=9' }, { receivedAt })[0];
  assert.equal(login.activity, 'remote_logon');
  assert.equal(execution.sourceEndpoint.address, '100.64.0.8');
  assert.equal(execution.actor.id, 'alice');
  assert.equal(execution.attributes.parentType, 'remote_session');
  assert.equal(execution.attributes.processType, 'command_interpreter');
});

test('audit parser and journal normalizer enforce parsing bounds', () => {
  assert.equal(parseAuditFields(`type=EXECVE a0="${'x'.repeat(5000)}" ok=yes`).a0, undefined);
  assert.throws(() => normalize({ MESSAGE: 'x'.repeat(65537) }), /exceeds parsing bounds/);
});

test('generic journal forwarding redacts common credential forms', () => {
  const event = normalize({ __CURSOR: 's=redact', SYSLOG_IDENTIFIER: 'app', MESSAGE: 'password=hunter2 Authorization: Bearer abc.def tokenless https://alice:secret@example.test/' })[0];
  assert.equal(event.class, 'journal_record');
  assert.equal(JSON.stringify(event).includes('hunter2'), false);
  assert.equal(JSON.stringify(event).includes('abc.def'), false);
  assert.equal(JSON.stringify(event).includes('alice:secret'), false);
});

test('journal source uses argv without a shell and requires explicit cursor commit', async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'lookout-journal-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const cursorPath = path.join(directory, 'cursor');
  const spawnImpl = fakeSpawn([{ __CURSOR: 'cursor-1', MESSAGE: 'one' }, { __CURSOR: 'cursor-2', _TRANSPORT: 'audit', MESSAGE: 'type=USER_AUTH msg=audit(1.2:3): res=success' }]);
  const source = new LinuxJournalSource({ cursorPath, spawnImpl });
  const staged = [];
  const result = await source.poll({ onRecord: async (_record, acknowledgement) => staged.push(acknowledgement) });
  assert.equal(fs.existsSync(cursorPath), false);
  assert.deepEqual(result.stagedCursors, ['cursor-1', 'cursor-2']);
  staged[1].commit();
  assert.equal(fs.readFileSync(cursorPath, 'utf8').trim(), 'cursor-2');
  assert.throws(() => staged[0].commit(), /not staged/);
  assert.equal(spawnImpl.calls[0].command, '/usr/bin/journalctl');
  assert.equal(spawnImpl.calls[0].options.shell, false);
  assert.ok(spawnImpl.calls[0].args.includes('--since'));
  assert.equal(result.capabilities.find((item) => item.capability === 'linux_audit').status, 'available');
});

test('journal source resumes after committed cursor and reports degraded or unavailable visibility accurately', async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'lookout-journal-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const cursorPath = path.join(directory, 'cursor');
  fs.writeFileSync(cursorPath, 'prior-cursor\n', { mode: 0o600 });
  const noAuditSpawn = fakeSpawn([{ __CURSOR: 'next-cursor', SYSLOG_IDENTIFIER: 'sshd', MESSAGE: 'Accepted publickey for alice from 10.0.0.1 port 2 ssh2' }]);
  const source = new LinuxJournalSource({ cursorPath, spawnImpl: noAuditSpawn });
  const result = await source.poll();
  assert.deepEqual(noAuditSpawn.calls[0].args.slice(-2), ['--after-cursor', 'prior-cursor']);
  assert.equal(result.capabilities.find((item) => item.capability === 'process_execution').status, 'degraded');
  assert.equal(fs.readFileSync(cursorPath, 'utf8').trim(), 'prior-cursor');

  const missing = Object.assign(new Error('not found'), { code: 'ENOENT' });
  const unavailable = new LinuxJournalSource({ cursorPath: path.join(directory, 'other'), spawnImpl: fakeSpawn([], { error: missing }) });
  await assert.rejects(unavailable.poll(), /not found/);
  assert.ok(unavailable.capabilities().every((item) => item.status === 'unavailable'));
});

test('journal cursor commit rejects forged or overlong values', () => {
  const source = new LinuxJournalSource({ cursorPath: '/tmp/lookout-test-cursor', spawnImpl: fakeSpawn([]) });
  assert.throws(() => source.commit('not-staged'), /not staged/);
});

test('journal source async event interface uses daemon-owned cursor durability and collector entity identity', async () => {
  const spawnImpl = fakeSpawn([
    { __CURSOR: 'durable-next', _HOSTNAME: 'host-name', SYSLOG_IDENTIFIER: 'sudo', MESSAGE: 'alice : TTY=pts/1 ; USER=root ; COMMAND=/usr/bin/id' },
    { __CURSOR: 'noise-next', SYSLOG_IDENTIFIER: 'kernel', MESSAGE: 'unclassified noise' }
  ]);
  const source = new LinuxJournalSource({ spawnImpl, collectorId: 'collector-1' });
  const observations = [];
  for await (const observation of source.events({ cursor: 'durable-prior' })) observations.push(observation);
  assert.equal(observations.length, 2);
  assert.equal(observations[0].cursor, 'durable-next');
  assert.ok(observations[0].event.entityKeys.includes('collector-endpoint:collector-1'));
  assert.equal(observations[1].event.class, 'journal_record');
  assert.deepEqual(spawnImpl.calls[0].args.slice(-2), ['--after-cursor', 'durable-prior']);
  assert.equal(source.readCursor(), null);
  assert.deepEqual(source.stagedCursors.size, 0);
});

test('journal source reports live capability state before a follow stream exits', async () => {
  const spawnImpl = liveSpawn();
  const source = new LinuxJournalSource({ spawnImpl, collectorId: 'collector-live' });
  const controller = new AbortController();
  const iterator = source.events({ signal: controller.signal });
  const next = iterator.next();
  spawnImpl.write({ __CURSOR: 'live-1', SYSLOG_IDENTIFIER: 'sshd', MESSAGE: 'Accepted publickey for alice from 10.0.0.1 port 2 ssh2' });
  await next;
  await new Promise((resolve) => setImmediate(resolve));
  const capabilities = Object.fromEntries(source.capabilities().map(({ capability, status }) => [capability, status]));
  assert.equal(capabilities.journal_stream, 'available');
  assert.equal(capabilities.authentication, 'available');
  assert.equal(capabilities.service_state, 'available');
  assert.equal(capabilities.linux_audit, 'degraded');
  assert.equal(capabilities.process_execution, 'degraded');
  controller.abort();
  await iterator.return();

  const auditSpawn = liveSpawn();
  const auditSource = new LinuxJournalSource({ spawnImpl: auditSpawn });
  const auditController = new AbortController();
  const auditIterator = auditSource.events({ signal: auditController.signal });
  const auditNext = auditIterator.next();
  auditSpawn.write({ __CURSOR: 'live-audit', _TRANSPORT: 'audit', MESSAGE: 'type=EXECVE msg=audit(1.2:3): a0="/usr/bin/id"' });
  await auditNext;
  await new Promise((resolve) => setImmediate(resolve));
  const auditCapabilities = Object.fromEntries(auditSource.capabilities().map(({ capability, status }) => [capability, status]));
  for (const capability of ['linux_audit', 'privilege_use', 'process_execution', 'configuration_change', 'log_clearing']) assert.equal(auditCapabilities[capability], 'available');
  auditController.abort();
  await auditIterator.return();
});

test('journal source converts poison records into bounded telemetry gaps and resumes after their cursors', async () => {
  const tooLargeForNormalizer = { __CURSOR: 'poison-normalizer', MESSAGE: 'x'.repeat(70000) };
  const source = new LinuxJournalSource({ spawnImpl: fakeSpawn([tooLargeForNormalizer]), collectorId: 'collector-poison' });
  const observations = [];
  for await (const observation of source.events()) observations.push(observation);
  assert.equal(observations.length, 1);
  assert.equal(observations[0].cursor, 'poison-normalizer');
  assert.equal(observations[0].event.category, 'health');
  assert.equal(observations[0].event.class, 'sensor_activity');
  assert.equal(observations[0].event.activity, 'stop');
  assert.equal(observations[0].event.attributes.reason, 'normalization_rejected');
  assert.equal(JSON.stringify(observations[0].event).includes('xxxx'), false);

  const resumedSpawn = fakeSpawn([{ __CURSOR: 'after-poison', SYSLOG_IDENTIFIER: 'sshd', MESSAGE: 'Failed password for alice from 10.0.0.2 port 2 ssh2' }]);
  const resumed = new LinuxJournalSource({ spawnImpl: resumedSpawn });
  const resumedEvents = [];
  for await (const observation of resumed.events({ cursor: observations[0].cursor })) resumedEvents.push(observation);
  assert.deepEqual(resumedSpawn.calls[0].args.slice(-2), ['--after-cursor', 'poison-normalizer']);
  assert.equal(resumedEvents[0].event.class, 'authentication');
});

test('journal source advances past oversized and malformed JSON when a valid cursor is recoverable', async () => {
  const oversized = JSON.stringify({ __CURSOR: 'poison-oversized', MESSAGE: 'x'.repeat(1024 * 1024) });
  const malformed = '{"__CURSOR":"poison-json","MESSAGE":"truncated"';
  const spawnImpl = rawSpawn([oversized, malformed]);
  const source = new LinuxJournalSource({ spawnImpl, collectorId: 'collector-poison' });
  const observations = [];
  for await (const observation of source.events()) observations.push(observation);
  assert.deepEqual(observations.map(({ cursor }) => cursor), ['poison-oversized', 'poison-json']);
  assert.deepEqual(observations.map(({ event }) => event.attributes.reason), ['record_too_large', 'invalid_json']);
  assert.ok(observations.every(({ event }) => !JSON.stringify(event).includes('truncated')));
  assert.ok(observations.every(({ event }) => event.attributes.recordBytes > 0 && event.attributes.recordBytes <= 2 * 1024 * 1024));
});

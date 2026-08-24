'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { LIVE_RULES, runLiveLinuxValidation, validateTarget } = require('../src/validation/live-linux');

test('live Linux validation performs only bounded non-destructive actions and verifies fresh alerts', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-live-validation-'));
  const knownHosts = path.join(directory, 'known_hosts');
  const identity = path.join(directory, 'id_ed25519');
  await fs.writeFile(knownHosts, '192.0.2.20 ssh-ed25519 fixture\n', { mode: 0o600 });
  await fs.writeFile(identity, 'fixture-private-key\n', { mode: 0o600 });
  const calls = [];
  let alertReads = 0;
  const runner = async (binary, argv) => {
    calls.push({ binary, argv });
    if (binary === '/usr/bin/ssh-keygen') {
      const output = argv[argv.indexOf('-f') + 1];
      await fs.writeFile(output, 'generated-private-key\n', { mode: 0o600 });
      return { code: 0, stdout: '', stderr: '' };
    }
    if (argv.some((value) => /lookout_invalid_\d+@/.test(value))) return { code: 255, stdout: '', stderr: 'Permission denied' };
    if (argv.at(-1).includes('nohup')) return { code: 0, stdout: '4321', stderr: '' };
    return { code: 0, stdout: '', stderr: '' };
  };
  const api = async (pathname) => {
    if (pathname === '/api/v1/detection-plan') return LIVE_RULES.map((analyticId) => ({ analyticId, deploy: true, state: 'ready' }));
    alertReads += 1;
    if (alertReads === 1) return [{ id: 'existing', ruleId: 'auth-failure-burst' }];
    return LIVE_RULES.map((ruleId) => ({ id: `fresh:${ruleId}`, ruleId }));
  };
  try {
    const report = await runLiveLinuxValidation({ address: '192.0.2.20', user: 'operator', knownHostsFile: knownHosts, identityFile: identity, api, runner, wait: async () => {}, surveyWarmupMs: 0 });
    assert.equal(report.passed, true);
    assert.deepEqual(report.results.map((item) => item.ruleId).sort(), [...LIVE_RULES].sort());
    assert.ok(report.results.every((item) => item.status === 'passed'));
    assert.equal(calls.filter((call) => call.argv.some((value) => /lookout_invalid_\d+@/.test(value))).length, 12);
    assert.ok(calls.some((call) => call.argv.at(-1).includes("python3 -c")));
    assert.ok(calls.some((call) => call.argv.at(-1).includes("'/bin/kill' '4321'")));
    assert.ok(report.limitations.some((item) => item.includes('No accounts, credentials, installed services, routes, policies, existing log contents')));
  } finally { await fs.rm(directory, { recursive: true, force: true }); }
});

test('live validation rejects ambiguous targets before any action', () => {
  assert.throws(() => validateTarget({ address: 'server.example', user: 'operator' }), /IP address/);
  assert.throws(() => validateTarget({ address: '192.0.2.20', user: 'root;touch' }), /user is invalid/);
});

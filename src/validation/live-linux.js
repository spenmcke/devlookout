'use strict';

const fs = require('node:fs');
const fsp = require('node:fs/promises');
const http = require('node:http');
const https = require('node:https');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { SshDeploymentTransport, defaultRunner, validateKnownHosts, validatePrivateFile } = require('../fleet/deployment');
const { FileSecretProvider } = require('../security/secrets');

const LIVE_RULES = Object.freeze([
  'auth-failure-burst',
  'auth-source-many-identities',
  'remote-auth-then-privilege-use',
  'network-listener-created',
  'remote-auth-then-listener-created'
]);

function delay(milliseconds) { return new Promise((resolve) => setTimeout(resolve, milliseconds)); }

function validateTarget({ address, user }) {
  if (net.isIP(address || '') === 0) throw new Error('Live validation target must be an IP address');
  if (!/^[a-z_][a-z0-9_-]{0,31}$/i.test(user || '')) throw new Error('Live validation SSH user is invalid');
  return { address, user, deploymentAuthorized: true };
}

function localApiClient({ config, tokenProvider, maximumBytes = 4 * 1024 * 1024 } = {}) {
  if (!config?.server || typeof tokenProvider !== 'function') throw new Error('Live validation API client requires server configuration and a token provider');
  const protocol = config.server.tls ? 'https:' : 'http:';
  const hostname = ['0.0.0.0', '::', 'localhost'].includes(config.server.host) ? '127.0.0.1' : config.server.host;
  const ca = config.server.tls ? fs.readFileSync(config.server.tls.certificateFile) : null;
  return async function request(pathname) {
    const token = await tokenProvider();
    return new Promise((resolve, reject) => {
      const transport = protocol === 'https:' ? https : http;
      const request = transport.request({ protocol, hostname, port: config.server.port, path: pathname, method: 'GET', headers: { authorization: `Bearer ${token}`, accept: 'application/json' }, ...(ca ? { ca, rejectUnauthorized: true } : {}) }, (response) => {
        const chunks = [];
        let bytes = 0;
        response.on('data', (chunk) => {
          bytes += chunk.length;
          if (bytes > maximumBytes) response.destroy(new Error('Lookout API response exceeded the validation bound'));
          else chunks.push(chunk);
        });
        response.once('error', reject);
        response.once('end', () => {
          if (response.statusCode !== 200) return reject(new Error(`Lookout API returned HTTP ${response.statusCode}`));
          try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
          catch { reject(new Error('Lookout API returned invalid JSON')); }
        });
      });
      request.setTimeout(10000, () => request.destroy(new Error('Lookout API request timed out')));
      request.once('error', reject);
      request.end();
    });
  };
}

async function createInvalidIdentity(runner = defaultRunner) {
  const directory = await fsp.mkdtemp(path.join(os.tmpdir(), 'lookout-live-invalid-key-'));
  const identity = path.join(directory, 'id_ed25519');
  const result = await runner('/usr/bin/ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-f', identity], { timeoutMs: 30000 });
  if (result.code !== 0) { await fsp.rm(directory, { recursive: true, force: true }); throw new Error('Unable to generate isolated invalid SSH identity'); }
  validatePrivateFile(identity, 'Generated invalid SSH identity');
  return { directory, identity };
}

async function failedSshAttempt({ address, user, knownHostsFile, identityFile, runner = defaultRunner }) {
  const result = await runner('/usr/bin/ssh', [
    '-o', 'BatchMode=yes', '-o', 'PasswordAuthentication=no', '-o', 'KbdInteractiveAuthentication=no',
    '-o', 'StrictHostKeyChecking=yes', '-o', `UserKnownHostsFile=${knownHostsFile}`,
    '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'ForwardAgent=no', '-o', 'ClearAllForwardings=yes',
    '-o', 'ConnectTimeout=5', '-o', 'ConnectionAttempts=1', '-o', 'IdentitiesOnly=yes', '-i', identityFile,
    '--', `${user}@${address}`, '/usr/bin/false'
  ], { timeoutMs: 10000 });
  if (result.code === 0) throw new Error('Invalid SSH identity unexpectedly authenticated');
  return result;
}

async function waitForRules({ api, baselineIds, expectedRules, timeoutMs = 120000, pollMs = 3000, wait = delay }) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() <= deadline) {
    const alerts = await api('/api/v1/alerts');
    if (!Array.isArray(alerts)) throw new Error('Lookout Alerts API returned an invalid response');
    const fresh = alerts.filter((alert) => !baselineIds.has(alert.id));
    const observed = new Set(fresh.map((alert) => alert.ruleId));
    if (expectedRules.every((rule) => observed.has(rule))) return { alerts: fresh, observed: [...observed].sort() };
    await wait(pollMs);
  }
  const alerts = await api('/api/v1/alerts');
  const fresh = alerts.filter((alert) => !baselineIds.has(alert.id));
  return { alerts: fresh, observed: [...new Set(fresh.map((alert) => alert.ruleId))].sort() };
}

async function runLiveLinuxValidation({
  address, user, knownHostsFile, identityFile, api, runner = defaultRunner, wait = delay,
  authTimeoutMs = 45000, surveyTimeoutMs = 150000, surveyWarmupMs = 65000, listenerPort = 48443
} = {}) {
  const target = validateTarget({ address, user });
  const knownHosts = validateKnownHosts(knownHostsFile);
  const identity = validatePrivateFile(identityFile, 'SSH identity file');
  if (typeof api !== 'function' || typeof runner !== 'function' || typeof wait !== 'function') throw new Error('Live validation dependencies are invalid');
  if (!Number.isInteger(listenerPort) || listenerPort < 1024 || listenerPort > 65535) throw new Error('Live validation listener port is invalid');
  const transport = new SshDeploymentTransport({ knownHostsFile: knownHosts, identityFile: identity, runner, timeoutMs: 30000 });
  const report = { schemaVersion: 1, mode: 'live_non_destructive', target: { address, user }, startedAt: new Date().toISOString(), passed: false, results: [], limitations: [] };
  let listenerPid = null;
  let invalidIdentity = null;
  try {
    const plan = await api('/api/v1/detection-plan');
    const states = new Map((Array.isArray(plan) ? plan : []).map((item) => [item.analyticId, item]));
    const baseline = await api('/api/v1/alerts');
    if (!Array.isArray(baseline)) throw new Error('Lookout Alerts API returned an invalid response');
    const baselineIds = new Set(baseline.map((alert) => alert.id));

    await transport.run(target, ['/usr/bin/true']);
    invalidIdentity = await createInvalidIdentity(runner);
    for (let index = 0; index < 12; index += 1) {
      await failedSshAttempt({ address, user: `lookout_invalid_${index}`, knownHostsFile: knownHosts, identityFile: invalidIdentity.identity, runner });
    }
    const authenticationRules = ['auth-failure-burst', 'auth-source-many-identities'].filter((rule) => states.get(rule)?.deploy !== false);
    const authObserved = await waitForRules({ api, baselineIds, expectedRules: authenticationRules, timeoutMs: authTimeoutMs, wait });
    for (const rule of authenticationRules) report.results.push({ ruleId: rule, status: authObserved.observed.includes(rule) ? 'passed' : 'failed', action: 'Twelve rejected OpenSSH public-key authentications across distinct nonexistent users' });

    let sudoAvailable = true;
    try { await transport.run(target, ['sudo', '-n', '/usr/bin/true']); }
    catch { sudoAvailable = false; }
    if (states.get('remote-auth-then-privilege-use')?.deploy === false) report.results.push({ ruleId: 'remote-auth-then-privilege-use', status: 'skipped', reason: 'Required telemetry capability is blocked' });
    else if (!sudoAvailable) report.results.push({ ruleId: 'remote-auth-then-privilege-use', status: 'skipped', reason: 'The supplied SSH principal does not have noninteractive sudo' });
    else {
      const privilegeObserved = await waitForRules({ api, baselineIds, expectedRules: ['remote-auth-then-privilege-use'], timeoutMs: authTimeoutMs, wait });
      report.results.push({ ruleId: 'remote-auth-then-privilege-use', status: privilegeObserved.observed.includes('remote-auth-then-privilege-use') ? 'passed' : 'failed', action: 'Successful OpenSSH login followed by sudo -n /usr/bin/true' });
    }

    const listenerRules = ['network-listener-created', 'remote-auth-then-listener-created'].filter((rule) => states.get(rule)?.deploy !== false);
    if (listenerRules.length) {
      await wait(surveyWarmupMs);
      const python = "import socket,time; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(('0.0.0.0'," + listenerPort + ")); s.listen(1); time.sleep(180)";
      const started = await transport.run(target, ['/bin/sh', '-c', `nohup /usr/bin/python3 -c ${JSON.stringify(python)} >/dev/null 2>&1 & printf '%s' "$!"`]);
      listenerPid = started.stdout.trim();
      if (!/^\d{1,12}$/.test(listenerPid)) throw new Error('Temporary listener did not return a valid process ID');
      const listenerObserved = await waitForRules({ api, baselineIds, expectedRules: listenerRules, timeoutMs: surveyTimeoutMs, wait });
      for (const rule of listenerRules) report.results.push({ ruleId: rule, status: listenerObserved.observed.includes(rule) ? 'passed' : 'failed', action: `Ephemeral unprivileged TCP listener on port ${listenerPort}` });
    }

    const tested = new Set(report.results.map((item) => item.ruleId));
    report.limitations = [
      'No accounts, credentials, installed services, routes, policies, existing log contents, backups, security controls, or cloud resources were modified; normal audit records were appended by the validation actions.',
      'Rules requiring state changes, destructive actions, five distinct network targets, DNS sensors, service-specific audit APIs, or large data transfer are excluded.',
      ...LIVE_RULES.filter((rule) => !tested.has(rule)).map((rule) => `${rule} was not applicable with the active capabilities.`)
    ];
    report.passed = report.results.some((item) => item.status === 'passed') && report.results.every((item) => item.status !== 'failed');
    report.finishedAt = new Date().toISOString();
    return report;
  } finally {
    if (listenerPid) {
      try { await transport.run(target, ['/bin/kill', listenerPid]); } catch { /* The process may have exited on its own. */ }
    }
    if (invalidIdentity) await fsp.rm(invalidIdentity.directory, { recursive: true, force: true });
  }
}

async function configuredLiveApi(config, tokenFile = '/etc/lookout/admin-token') {
  const provider = new FileSecretProvider({ administrator: tokenFile });
  return localApiClient({ config, tokenProvider: () => provider.get('administrator') });
}

module.exports = { LIVE_RULES, validateTarget, localApiClient, failedSshAttempt, waitForRules, runLiveLinuxValidation, configuredLiveApi };

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { Readable } = require('node:stream');
const { InstallationDiagnosticsService, SURVEY_TEMPLATE } = require('../src/diagnostics/service');
const { createDiagnosticsHttpHandler } = require('../src/diagnostics/http');
const { SlackDiagnosticsNotifier } = require('../src/diagnostics/slack');
const { redactWithGitleaks } = require('../tools/lookout-support-report');
const { reportInstallerDiagnostic } = require('../install/onboard');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const fsSync = require('node:fs');

class MemoryDiagnosticsStore {
  constructor() { this.rows = new Map(); }
  async insert(row) { if (this.rows.has(row.report_id)) throw new Error('duplicate'); this.rows.set(row.report_id, structuredClone(row)); return structuredClone(row); }
  async get(id) { return this.rows.has(id) ? structuredClone(this.rows.get(id)) : null; }
  async getByIdempotency(key) { return structuredClone([...this.rows.values()].find((row) => row.idempotency_key === key) || null); }
  async update(id, patch) { const row = { ...this.rows.get(id), ...structuredClone(patch) }; this.rows.set(id, row); return structuredClone(row); }
  async pendingSlack(now, limit) { return [...this.rows.values()].filter((row) => ['pending', 'delivering'].includes(row.slack_status) && row.slack_next_attempt_at <= now).slice(0, limit).map((row) => structuredClone(row)); }
  async claimSlack(report, now) {
    const current = this.rows.get(report.report_id);
    if (!current || current.slack_status !== report.slack_status || current.slack_next_attempt_at > now) return null;
    current.slack_status = 'delivering';
    current.slack_next_attempt_at = new Date(Date.parse(now) + 5 * 60 * 1000).toISOString();
    return structuredClone(current);
  }
  async deleteExpired(now) { for (const [id, row] of this.rows) if (row.expires_at < now) this.rows.delete(id); return { deleted: true }; }
  async deleteTenant(tenantId) { for (const [id, row] of this.rows) if (row.tenant_id === tenantId) this.rows.delete(id); return { deleted: true }; }
}

const context = Object.freeze({ tenantId: 'user-1', userId: 'user-1', email: 'dev@example.com', sessionId: 'set_abcdefghijklmnopqrstuvwx', deploymentId: 'dpl_abcdefghijklmnopqrstuvwxyzABCDEF' });

function completedSurvey() {
  return SURVEY_TEMPLATE
    .replace('[Replace this line with the detailed timestamped history.]', '2026-08-22T10:00:00Z Ran cloud discovery.\n2026-08-22T10:01:00Z Retried installation.')
    .replace('[Replace this line with the exact error or current blocker.]', 'The cloud CLI returned an access error.');
}

test('two-step survey is account-bound, stored durably, and idempotent', async () => {
  const store = new MemoryDiagnosticsStore();
  const sent = [];
  const service = new InstallationDiagnosticsService({ store, slackNotifier: { send: async (report) => sent.push(report) } });
  const survey = await service.createSurvey(context);
  const pending = await store.get(survey.reportId);
  assert.equal(pending.tenant_id, context.tenantId);
  assert.equal(pending.user_id, context.userId);
  assert.equal(pending.account_email, context.email);
  assert.equal(pending.status, 'survey_pending');
  assert.equal(pending.payload, null);
  assert.equal(survey.survey, SURVEY_TEMPLATE);

  await assert.rejects(service.submitSurvey({ reportId: survey.reportId, submissionToken: `ldr_${'A'.repeat(43)}`, text: completedSurvey(), idempotencyKey: 'idempotency_key_1234' }), /unavailable/);
  const submitted = await service.submitSurvey({ reportId: survey.reportId, submissionToken: survey.submissionToken, text: completedSurvey(), idempotencyKey: 'idempotency_key_1234' });
  assert.equal(submitted.accepted, true);
  await service.submitSurvey({ reportId: survey.reportId, submissionToken: survey.submissionToken, text: completedSurvey(), idempotencyKey: 'idempotency_key_1234' });
  const received = await store.get(survey.reportId);
  assert.equal(received.status, 'received');
  assert.equal(received.payload.dlp.engine, 'gitleaks');
  assert.match(received.payload.answers.history, /timestamped history|2026-08-22/);
  assert.equal(received.slack_status, 'pending');
  await Promise.all([service.flushSlack(), service.flushSlack()]);
  assert.equal(sent.length, 1);
  assert.equal((await store.get(survey.reportId)).slack_status, 'delivered');
});

test('only installer failures and submitted agent reports are queued for Slack', async () => {
  const store = new MemoryDiagnosticsStore();
  const service = new InstallationDiagnosticsService({ store, slackNotifier: { send: async () => {} } });
  const failure = await service.recordInstallerEvent(context, { kind: 'failure', code: 'artifact_download', phase: 'bootstrap', platform: { os: 'linux', architecture: 'x64', installer_version: '0.1.0' }, idempotencyKey: 'installer_failure_key_1' });
  const diagnostic = await service.recordInstallerEvent(context, { kind: 'diagnostic', code: 'reporting_interrupted', phase: 'reporting_interrupted', platform: { os: 'linux' }, idempotencyKey: 'installer_diagnostic_key_1' });
  assert.equal((await store.get(failure.reportId)).slack_status, 'pending');
  assert.equal((await store.get(diagnostic.reportId)).slack_status, 'not_applicable');
  assert.equal((await service.recordInstallerEvent(context, { kind: 'failure', code: 'artifact_download', phase: 'bootstrap', platform: {}, idempotencyKey: 'installer_failure_key_1' })).reportId, failure.reportId);
});

test('diagnostics HTTP derives identity from setup authority and rejects payload identity', async () => {
  const store = new MemoryDiagnosticsStore();
  const service = new InstallationDiagnosticsService({ store });
  const contexts = [];
  const handler = createDiagnosticsHttpHandler({ service, setupAuthority: {
    diagnosticContextBySupportToken: async (body) => { contexts.push(body); return context; },
    diagnosticContextBySetupToken: async () => context
  } });
  const invoke = async (body) => {
    const text = JSON.stringify(body);
    const req = Readable.from([text]);
    req.method = 'POST';
    req.headers = { 'content-type': 'application/json', 'content-length': String(Buffer.byteLength(text)) };
    let status;
    let response = '';
    const res = { writeHead(value) { status = value; }, end(value = '') { response += value; } };
    await handler(req, res, new URL('https://app.devlookout.com/v1/setup-support/surveys'));
    return { status, json: JSON.parse(response) };
  };
  assert.equal((await invoke({ support_token: `ldw_${'A'.repeat(43)}`, tenant_id: 'attacker' })).status, 400);
  const accepted = await invoke({ support_token: `ldw_${'A'.repeat(43)}` });
  assert.equal(accepted.status, 201);
  assert.deepEqual(contexts, [{ support_token: `ldw_${'A'.repeat(43)}` }]);
  assert.equal((await store.get(accepted.json.report_id)).tenant_id, context.tenantId);
});

test('diagnostics HTTP accepts the existing setup credential for a support survey', async () => {
  const store = new MemoryDiagnosticsStore();
  const service = new InstallationDiagnosticsService({ store });
  const seen = [];
  const handler = createDiagnosticsHttpHandler({ service, setupAuthority: {
    diagnosticContextBySupportToken: async () => { throw new Error('unexpected support token'); },
    diagnosticContextBySetupToken: async (body) => { seen.push(body); return context; }
  } });
  const body = JSON.stringify({ setup_token: `lst_${'s'.repeat(43)}` });
  const req = Readable.from([body]);
  req.method = 'POST';
  req.headers = { 'content-type': 'application/json', 'content-length': String(Buffer.byteLength(body)) };
  let status;
  const res = { writeHead(value) { status = value; }, end() {} };
  await handler(req, res, new URL('https://app.devlookout.com/v1/setup-support/surveys'));
  assert.equal(status, 201);
  assert.deepEqual(seen, [{ setup_token: `lst_${'s'.repeat(43)}` }]);
});

test('Slack notifier sends bounded support content only for supported report kinds', async () => {
  const requests = [];
  const notifier = new SlackDiagnosticsNotifier({ webhookUrl: 'https://hooks.slack.com/services/T/B/X', fetchImpl: async (url, options) => {
    requests.push({ url: String(url), body: JSON.parse(options.body) });
    return new Response('ok', { status: 200 });
  } });
  await notifier.send({ kind: 'installer_failure', status: 'received', report_id: 'diag_test', setup_session_id: 'set_test', account_email: 'dev@example.com', received_at: '2026-08-22T00:00:00Z', payload: { phase: 'bootstrap', code: 'artifact_download' } });
  assert.equal(requests.length, 1);
  assert.match(requests[0].body.text, /installation failure/);
  await assert.rejects(notifier.send({ kind: 'installer_diagnostic', status: 'received' }), /invalid/);
});

test('Slack notifier supports a channel-bound bot token without exposing it in the request body', async () => {
  const requests = [];
  const botToken = `xoxb-${'A'.repeat(32)}`;
  const notifier = new SlackDiagnosticsNotifier({ botToken, channelId: 'C0BRVCQCAKD', fetchImpl: async (url, options) => {
    requests.push({ url: String(url), headers: options.headers, body: JSON.parse(options.body) });
    return new Response(JSON.stringify({ ok: true, channel: 'C0BRVCQCAKD' }), { status: 200 });
  } });
  await notifier.send({ kind: 'agent_report', status: 'received', report_id: 'diag_test', setup_session_id: 'set_test', account_email: 'dev@example.com', received_at: '2026-08-22T00:00:00Z', payload: { answers: { blocker: 'Cloud access failed', history: '2026-08-22T00:00:00Z Tried discovery.' } } });
  assert.equal(requests[0].url, 'https://slack.com/api/chat.postMessage');
  assert.equal(requests[0].headers.Authorization, `Bearer ${botToken}`);
  assert.equal(requests[0].body.channel, 'C0BRVCQCAKD');
  assert.doesNotMatch(JSON.stringify(requests[0].body), /xoxb-/);
  assert.throws(() => new SlackDiagnosticsNotifier({ botToken, channelId: '' }), /invalid/);
});

test('support tool runs Gitleaks locally and submits only redacted survey text', async (t) => {
  if (process.platform === 'win32') return t.skip('executable fixture uses a POSIX shebang');
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-gitleaks-test-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const executable = path.join(directory, 'gitleaks');
  await fs.writeFile(executable, `#!/usr/bin/env node
const fs = require('node:fs');
const input = fs.readFileSync(0, 'utf8');
if (!input.includes('TOPSECRET')) process.exit(0);
const index = process.argv.indexOf('--report-path');
if (index >= 0) fs.writeFileSync(process.argv[index + 1], JSON.stringify([{ Secret: 'TOPSECRET', RuleID: 'test-secret' }]));
process.exit(1);
`, { mode: 0o700 });
  const previous = process.env.LOOKOUT_GITLEAKS;
  process.env.LOOKOUT_GITLEAKS = executable;
  t.after(() => { if (previous === undefined) delete process.env.LOOKOUT_GITLEAKS; else process.env.LOOKOUT_GITLEAKS = previous; });
  const result = await redactWithGitleaks('History contained TOPSECRET accidentally.', directory);
  assert.equal(result, 'History contained [REDACTED:gitleaks:test-secret] accidentally.');
});

test('Supabase diagnostics migration is service-role-only and idempotency constrained', () => {
  const sql = fsSync.readFileSync(path.join(__dirname, '../supabase/migrations/20260822120000_installation_diagnostics.sql'), 'utf8');
  assert.match(sql, /enable row level security/i);
  assert.match(sql, /revoke all on table .* from public, anon, authenticated/i);
  assert.match(sql, /grant select, insert, update, delete .* to service_role/i);
  assert.match(sql, /create unique index[\s\S]*idempotency_key/i);
  assert.match(sql, /installer_failure.*installer_diagnostic.*agent_report/i);
});

test('automatic installer diagnostics persist a secret-free outbox and retry with the same idempotency key', async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-diagnostic-outbox-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const filename = path.join(directory, 'outbox.json');
  const setupToken = `lst_${'q'.repeat(43)}`;
  const attempts = [];
  const client = { reportDiagnosticEvent: async (event) => { attempts.push(event); throw new Error('offline'); } };
  await assert.rejects(reportInstallerDiagnostic({ client, setupToken, kind: 'failure', code: 'cloud_discovery', phase: 'cloud_discovery', outboxFile: filename, attempts: 1 }), /offline/);
  const persisted = await fs.readFile(filename, 'utf8');
  assert.doesNotMatch(persisted, new RegExp(setupToken));
  assert.match(persisted, /cloud_discovery/);
  const successful = [];
  await reportInstallerDiagnostic({ client: { reportDiagnosticEvent: async (event) => { successful.push(event); return { accepted: true }; } }, setupToken, outboxFile: filename, enqueue: false, attempts: 1 });
  assert.equal(successful[0].idempotencyKey, attempts[0].idempotencyKey);
  await assert.rejects(fs.stat(filename), { code: 'ENOENT' });
});

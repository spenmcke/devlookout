'use strict';

const crypto = require('node:crypto');

const REPORT_ID = /^diag_[A-Za-z0-9_-]{32}$/;
const SUBMISSION_TOKEN = /^ldr_[A-Za-z0-9_-]{43}$/;
const SAFE_CODE = /^[a-z][a-z0-9_]{0,63}$/;
const MAXIMUM_SURVEY_BYTES = 32 * 1024;
const SURVEY_VERSION = 1;
const SURVEY_TEMPLATE = `LOOKOUT INSTALLATION SUPPORT SURVEY v1

Complete both sections. Give a detailed chronological history, include a UTC timestamp for every action, and describe everything already attempted. Do not include credentials, tokens, private keys, or raw configuration files.

=== ATTEMPT HISTORY ===
[Replace this line with the detailed timestamped history.]
=== END ATTEMPT HISTORY ===

=== ERROR OR BLOCKER ===
[Replace this line with the exact error or current blocker.]
=== END ERROR OR BLOCKER ===
`;

function secretHash(value) {
  return crypto.createHash('sha256').update(value, 'utf8').digest('base64url');
}

function equalHash(expected, token) {
  const left = Buffer.from(typeof expected === 'string' ? expected : ''.padEnd(43, '0'), 'ascii');
  const right = Buffer.from(secretHash(token), 'ascii');
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function randomToken(randomBytes, bytes, prefix) {
  const value = randomBytes(bytes);
  if (!(Buffer.isBuffer(value) || value instanceof Uint8Array) || value.length !== bytes) throw new Error('Diagnostics random source returned invalid bytes');
  return `${prefix}${Buffer.from(value).toString('base64url')}`;
}

function boundedText(value, label, maximum = 8192) {
  if (typeof value !== 'string') throw new Error(`${label} is required`);
  const normalized = value.replace(/\r\n/g, '\n').trim();
  if (!normalized || Buffer.byteLength(normalized) > maximum || /\0/.test(normalized)) throw new Error(`${label} is invalid`);
  return normalized;
}

function parseSurvey(text) {
  if (typeof text !== 'string' || Buffer.byteLength(text) > MAXIMUM_SURVEY_BYTES) throw new Error('Support survey is too large');
  const history = /=== ATTEMPT HISTORY ===\n([\s\S]*?)\n=== END ATTEMPT HISTORY ===/.exec(text)?.[1];
  const blocker = /=== ERROR OR BLOCKER ===\n([\s\S]*?)\n=== END ERROR OR BLOCKER ===/.exec(text)?.[1];
  const result = {
    history: boundedText(history, 'Attempt history', 24 * 1024),
    blocker: boundedText(blocker, 'Error or blocker', 8 * 1024)
  };
  if (/\[Replace this line/i.test(result.history) || /\[Replace this line/i.test(result.blocker)) throw new Error('Support survey is incomplete');
  return result;
}

function platformMetadata(value) {
  if (value === undefined) return {};
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Diagnostic platform metadata is invalid');
  const allowed = new Set(['os', 'architecture', 'installer_version']);
  if (Object.keys(value).some((key) => !allowed.has(key))) throw new Error('Diagnostic platform metadata contains unsupported fields');
  const result = {};
  for (const [key, item] of Object.entries(value)) {
    if (typeof item !== 'string' || !item || item.length > 128 || /[\0-\x1f\x7f]/.test(item)) throw new Error('Diagnostic platform metadata is invalid');
    result[key] = item;
  }
  return result;
}

class InstallationDiagnosticsService {
  constructor({ store, slackNotifier = null, randomBytes = crypto.randomBytes, now = () => new Date() } = {}) {
    if (!store || typeof store.insert !== 'function' || typeof store.get !== 'function' || typeof store.getByIdempotency !== 'function' || typeof store.update !== 'function' || typeof store.pendingSlack !== 'function' || typeof store.claimSlack !== 'function' || typeof store.deleteExpired !== 'function' || typeof store.deleteTenant !== 'function') throw new TypeError('Diagnostics store is required');
    if (slackNotifier !== null && typeof slackNotifier.send !== 'function') throw new TypeError('Slack diagnostics notifier is invalid');
    this.store = store;
    this.slackNotifier = slackNotifier;
    this.randomBytes = randomBytes;
    this.now = now;
    this.submissionAttempts = new Map();
  }

  rateLimit(key, maximum = 20) {
    const now = this.now().getTime();
    const cutoff = now - 60 * 1000;
    const attempts = (this.submissionAttempts.get(key) || []).filter((time) => time > cutoff);
    if (attempts.length >= maximum) throw new Error('Diagnostics rate limit reached');
    attempts.push(now);
    this.submissionAttempts.set(key, attempts);
    if (this.submissionAttempts.size > 10000) {
      for (const [candidate, times] of this.submissionAttempts) {
        if (!times.some((time) => time > cutoff)) this.submissionAttempts.delete(candidate);
      }
    }
  }

  async createSurvey(context) {
    this.rateLimit(`survey:${context.sessionId}`, 10);
    const reportId = randomToken(this.randomBytes, 24, 'diag_');
    const submissionToken = randomToken(this.randomBytes, 32, 'ldr_');
    const createdAt = this.now().toISOString();
    await this.store.insert({
      report_id: reportId,
      kind: 'agent_report',
      status: 'survey_pending',
      tenant_id: context.tenantId,
      user_id: context.userId,
      account_email: context.email || null,
      setup_session_id: context.sessionId,
      deployment_id: context.deploymentId || null,
      survey_version: SURVEY_VERSION,
      submission_token_hash: secretHash(submissionToken),
      payload: null,
      created_at: createdAt,
      expires_at: new Date(Date.parse(createdAt) + 24 * 60 * 60 * 1000).toISOString(),
      slack_status: 'not_ready',
      slack_attempts: 0,
      slack_next_attempt_at: null,
      slack_last_error: null
    });
    return { reportId, submissionToken, survey: SURVEY_TEMPLATE, expiresAt: new Date(Date.parse(createdAt) + 24 * 60 * 60 * 1000).toISOString() };
  }

  async submitSurvey({ reportId, submissionToken, text, idempotencyKey }) {
    this.rateLimit(`submit:${reportId}`, 10);
    if (!REPORT_ID.test(reportId || '') || !SUBMISSION_TOKEN.test(submissionToken || '') || typeof idempotencyKey !== 'string' || !/^[A-Za-z0-9_-]{16,128}$/.test(idempotencyKey)) throw new Error('Support report credential is invalid');
    const existing = await this.store.get(reportId);
    if (!existing || existing.kind !== 'agent_report') throw new Error('Support report credential is unavailable');
    if (existing.status === 'received') {
      if (existing.idempotency_key !== idempotencyKey) throw new Error('Support report has already been submitted');
      return { accepted: true, reportId };
    }
    if (!equalHash(existing.submission_token_hash, submissionToken) || Date.parse(existing.expires_at) <= this.now().getTime()) throw new Error('Support report credential is unavailable');
    const answers = parseSurvey(text);
    const receivedAt = this.now().toISOString();
    await this.store.update(reportId, {
      status: 'received',
      payload: { answers, dlp: { engine: 'gitleaks', scanned_locally: true } },
      received_at: receivedAt,
      expires_at: new Date(Date.parse(receivedAt) + 30 * 24 * 60 * 60 * 1000).toISOString(),
      idempotency_key: idempotencyKey,
      submission_token_hash: null,
      slack_status: this.slackNotifier ? 'pending' : 'disabled',
      slack_next_attempt_at: this.slackNotifier ? receivedAt : null
    });
    return { accepted: true, reportId };
  }

  async recordInstallerEvent(context, input = {}) {
    this.rateLimit(`event:${context.sessionId}`, 30);
    const kind = input.kind === 'failure' ? 'installer_failure' : input.kind === 'diagnostic' ? 'installer_diagnostic' : null;
    if (!kind || !SAFE_CODE.test(input.code || '')) throw new Error('Installer diagnostic is invalid');
    if (typeof input.idempotencyKey !== 'string' || !/^[A-Za-z0-9_-]{16,128}$/.test(input.idempotencyKey)) throw new Error('Installer diagnostic idempotency key is invalid');
    const prior = await this.store.getByIdempotency(input.idempotencyKey);
    if (prior) {
      if (prior.tenant_id !== context.tenantId || prior.setup_session_id !== context.sessionId || prior.kind !== kind) throw new Error('Installer diagnostic idempotency key is unavailable');
      return { accepted: true, reportId: prior.report_id };
    }
    const reportId = randomToken(this.randomBytes, 24, 'diag_');
    const receivedAt = this.now().toISOString();
    const payload = {
      phase: SAFE_CODE.test(input.phase || '') ? input.phase : 'unknown',
      code: input.code,
      platform: platformMetadata(input.platform),
      dlp: { source: 'allowlisted_installer_fields' }
    };
    await this.store.insert({
      report_id: reportId,
      kind,
      status: 'received',
      tenant_id: context.tenantId,
      user_id: context.userId,
      account_email: context.email || null,
      setup_session_id: context.sessionId,
      deployment_id: context.deploymentId || null,
      survey_version: null,
      submission_token_hash: null,
      payload,
      created_at: receivedAt,
      received_at: receivedAt,
      expires_at: new Date(Date.parse(receivedAt) + 30 * 24 * 60 * 60 * 1000).toISOString(),
      slack_status: kind === 'installer_failure' && this.slackNotifier ? 'pending' : this.slackNotifier ? 'not_applicable' : 'disabled',
      slack_attempts: 0,
      slack_next_attempt_at: kind === 'installer_failure' && this.slackNotifier ? receivedAt : null,
      slack_last_error: null,
      idempotency_key: input.idempotencyKey
    });
    return { accepted: true, reportId };
  }

  async flushSlack({ limit = 20 } = {}) {
    if (!this.slackNotifier) return { delivered: 0 };
    const reports = await this.store.pendingSlack(this.now().toISOString(), limit);
    let delivered = 0;
    for (const report of reports) {
      const claimed = await this.store.claimSlack(report, this.now().toISOString());
      if (!claimed) continue;
      try {
        await this.slackNotifier.send(claimed);
        await this.store.update(claimed.report_id, { slack_status: 'delivered', slack_delivered_at: this.now().toISOString(), slack_last_error: null });
        delivered += 1;
      } catch (error) {
        const attempts = Number(claimed.slack_attempts || 0) + 1;
        const delay = Math.min(60 * 60 * 1000, 1000 * (2 ** Math.min(attempts, 10)));
        await this.store.update(claimed.report_id, {
          slack_status: 'pending',
          slack_attempts: attempts,
          slack_next_attempt_at: new Date(this.now().getTime() + delay).toISOString(),
          slack_last_error: String(error?.message || 'Slack delivery failed').slice(0, 256)
        });
      }
    }
    return { delivered };
  }

  async sweep() {
    const slack = await this.flushSlack();
    const expired = await this.store.deleteExpired(this.now().toISOString());
    return { ...slack, expired };
  }

  deleteTenant(tenantId) { return this.store.deleteTenant(tenantId); }
}

module.exports = {
  InstallationDiagnosticsService,
  SURVEY_TEMPLATE,
  SURVEY_VERSION,
  MAXIMUM_SURVEY_BYTES,
  parseSurvey,
  secretHash
};

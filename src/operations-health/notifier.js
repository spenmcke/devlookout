'use strict';

const { stableId } = require('../core/canonical');

function bounded(value, maximum = 256) {
  return String(value ?? '').replace(/[\r\n]+/g, ' ').slice(0, maximum);
}

function notificationText(payload) {
  return [
    `Lookout operational alert ${bounded(payload.transition, 32)}`,
    `Severity: ${bounded(payload.severity, 32)}`,
    `Deployment: ${bounded(payload.deploymentId)}`,
    `Resource: ${bounded(payload.resource)}`,
    `Condition: ${bounded(payload.label)}`,
    `Value: ${bounded(payload.value, 64)} ${bounded(payload.unit, 64)}`,
    `Time: ${bounded(payload.observedAt, 64)}`
  ].join('\n').slice(0, 4000);
}

class OperationalHealthNotifier {
  constructor({ slackWebhookUrl = '', resendApiKey = '', emailFrom = '', emailTo = '', fetchImpl = globalThis.fetch, timeoutMs = 10000 } = {}) {
    if (slackWebhookUrl) {
      let url;
      try { url = new URL(slackWebhookUrl); } catch { throw new Error('Operational Slack webhook URL is invalid'); }
      if (url.protocol !== 'https:' || url.username || url.password || url.hash || !/^hooks\.slack(?:-gov)?\.com$/i.test(url.hostname)) throw new Error('Operational Slack webhook URL is invalid');
      this.slackWebhook = url;
    } else this.slackWebhook = null;
    this.resendApiKey = resendApiKey;
    this.emailFrom = emailFrom;
    this.emailTo = emailTo;
    this.fetchImpl = fetchImpl;
    this.timeoutMs = timeoutMs;
  }

  hasSlack() { return Boolean(this.slackWebhook); }
  hasEmail() { return Boolean(this.resendApiKey && this.emailFrom && this.emailTo); }

  async send(record) {
    const text = notificationText(record?.payload || {});
    if (record?.channel === 'slack') {
      if (!this.hasSlack()) throw new Error('Operational Slack delivery is not configured');
      const response = await this.fetchImpl(this.slackWebhook, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ text }), redirect: 'error', signal: AbortSignal.timeout(this.timeoutMs) });
      if (!response.ok) throw new Error(`Operational Slack delivery returned HTTP ${response.status}`);
      return { providerMessageId: null };
    }
    if (record?.channel === 'email') {
      if (!this.hasEmail()) throw new Error('Operational email delivery is not configured');
      const response = await this.fetchImpl('https://api.resend.com/emails', {
        method: 'POST', redirect: 'error', signal: AbortSignal.timeout(this.timeoutMs),
        headers: { Authorization: `Bearer ${this.resendApiKey}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ from: this.emailFrom, to: [this.emailTo], subject: `Lookout ${bounded(record.payload?.severity, 32)} operational alert`, text })
      });
      const body = Buffer.from(await response.arrayBuffer());
      if (!response.ok || body.length > 64 * 1024) throw new Error(`Operational email delivery returned HTTP ${response.status}`);
      let result = {};
      try { result = JSON.parse(body.toString('utf8')); } catch { /* Resend message ID is optional for acknowledgement. */ }
      return { providerMessageId: typeof result.id === 'string' ? result.id.slice(0, 512) : null };
    }
    throw new Error('Operational notification channel is invalid');
  }
}

class OperationalNotificationWorker {
  constructor({ store, notifier, now = () => new Date() } = {}) {
    if (!store || !notifier) throw new TypeError('Operational notification worker dependencies are required');
    this.store = store;
    this.notifier = notifier;
    this.now = now;
  }

  async flushOne() {
    const now = this.now();
    const record = await this.store.claimNotification({ now, maximumAttempts: 10 });
    if (!record) return { delivered: 0 };
    try {
      const result = await this.notifier.send(record);
      await this.store.acknowledgeNotification({ outboxId: record.outbox_id, attempt: record.attempts, now: this.now(), providerMessageId: result.providerMessageId });
      return { delivered: 1 };
    } catch (error) {
      const maximumAttempts = record.channel === 'slack' ? 5 : 10;
      const retryAt = new Date(this.now().getTime() + Math.min(60 * 60 * 1000, 2000 * (2 ** Math.min(record.attempts, 10))));
      await this.store.failNotification({ outboxId: record.outbox_id, attempt: record.attempts, now: this.now(), nextAttemptAt: retryAt, error: String(error?.message || error).slice(0, 500), maximumAttempts });
      if (record.channel === 'slack' && record.attempts >= maximumAttempts && this.notifier.hasEmail()) {
        const idempotencyKey = stableId('ops_email_fallback', record.idempotency_key);
        await this.store.enqueueNotification({
          outboxId: stableId('ops_outbox', idempotencyKey), idempotencyKey, tenantId: record.tenant_id, deploymentId: record.deployment_id,
          alertKey: record.alert_key, channel: 'email', payload: record.payload, nextAttemptAt: this.now().toISOString()
        });
      }
      return { delivered: 0, failed: true };
    }
  }

  async flush({ limit = 20 } = {}) {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) throw new Error('Operational notification flush limit is invalid');
    let delivered = 0;
    let failed = 0;
    for (let index = 0; index < limit; index += 1) {
      const result = await this.flushOne();
      delivered += result.delivered || 0;
      failed += result.failed ? 1 : 0;
      if (!result.delivered && !result.failed) break;
    }
    return { delivered, failed };
  }
}

module.exports = { OperationalHealthNotifier, OperationalNotificationWorker, notificationText };

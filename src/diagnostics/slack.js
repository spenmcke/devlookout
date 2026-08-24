'use strict';

class SlackDiagnosticsNotifier {
  constructor({ webhookUrl = '', botToken = '', channelId = '', fetchImpl = globalThis.fetch, timeoutMs = 10000 } = {}) {
    const usesWebhook = Boolean(webhookUrl);
    const usesBot = Boolean(botToken || channelId);
    if (usesWebhook === usesBot) throw new Error('Slack diagnostics delivery configuration is invalid');
    if (usesWebhook) {
      let url;
      try { url = new URL(webhookUrl); } catch { throw new Error('Slack diagnostics webhook URL is invalid'); }
      if (url.protocol !== 'https:' || url.username || url.password || url.hash || !/^hooks\.slack(?:-gov)?\.com$/i.test(url.hostname)) throw new Error('Slack diagnostics webhook URL is invalid');
      this.url = url;
      this.mode = 'webhook';
    } else {
      if (!/^xoxb-[A-Za-z0-9-]{20,}$/.test(botToken) || !/^[CG][A-Z0-9]{8,}$/.test(channelId)) throw new Error('Slack diagnostics bot configuration is invalid');
      this.url = new URL('https://slack.com/api/chat.postMessage');
      this.mode = 'bot';
      this.botToken = botToken;
      this.channelId = channelId;
    }
    this.fetchImpl = fetchImpl;
    this.timeoutMs = timeoutMs;
  }

  async send(report) {
    if (!['installer_failure', 'agent_report'].includes(report?.kind) || report.status !== 'received') throw new Error('Slack diagnostics report is invalid');
    const answers = report.payload?.answers;
    const summary = report.kind === 'agent_report'
      ? String(answers?.blocker || 'No blocker supplied')
      : `${report.payload?.phase || 'unknown'}: ${report.payload?.code || 'installation_failed'}`;
    const history = report.kind === 'agent_report' ? String(answers?.history || '') : '';
    const text = [
      `Lookout ${report.kind === 'agent_report' ? 'agent support report' : 'installation failure'}`,
      `Account: ${report.account_email || 'unknown'}`,
      `Report: ${report.report_id}`,
      `Setup: ${report.setup_session_id}`,
      report.deployment_id ? `Deployment: ${report.deployment_id}` : null,
      `Time: ${report.received_at || report.created_at}`,
      `Summary: ${summary.slice(0, 2000)}`,
      history ? `History:\n${history.slice(0, 5000)}` : null
    ].filter(Boolean).join('\n');
    const body = this.mode === 'bot' ? { channel: this.channelId, text: text.slice(0, 9000) } : { text: text.slice(0, 9000) };
    const headers = { 'Content-Type': 'application/json' };
    if (this.mode === 'bot') headers.Authorization = `Bearer ${this.botToken}`;
    const response = await this.fetchImpl(this.url, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
      redirect: 'error',
      signal: AbortSignal.timeout(this.timeoutMs)
    });
    const responseBody = Buffer.from(await response.arrayBuffer());
    if (!response.ok) throw new Error(`Slack diagnostics delivery returned HTTP ${response.status}`);
    if (this.mode === 'bot') {
      if (responseBody.length > 64 * 1024) throw new Error('Slack diagnostics API response is invalid');
      let result;
      try { result = JSON.parse(responseBody.toString('utf8')); } catch { throw new Error('Slack diagnostics API response is invalid'); }
      if (result?.ok !== true) throw new Error(`Slack diagnostics API rejected delivery: ${String(result?.error || 'unknown_error').slice(0, 100)}`);
    }
    return { delivered: true };
  }
}

module.exports = { SlackDiagnosticsNotifier };

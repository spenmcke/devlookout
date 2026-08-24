'use strict';

class RecoveryEmailNotifier {
  constructor({ apiKey, from, dashboardUrl, fetchImpl = globalThis.fetch } = {}) {
    this.apiKey = apiKey || '';
    this.from = from || '';
    this.dashboardUrl = dashboardUrl;
    this.fetchImpl = fetchImpl;
  }

  async sendCentralRecovery({ to, deploymentId, lastHeartbeatAt } = {}) {
    if (!to || !this.apiKey || !this.from) return { delivered: false, reason: 'email_not_configured' };
    const response = await this.fetchImpl('https://api.resend.com/emails', {
      method: 'POST',
      headers: { Authorization: `Bearer ${this.apiKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        from: this.from,
        to: [to],
        subject: 'Lookout central reporting is interrupted',
        text: `Lookout stopped receiving central reports for ${deploymentId} after ${lastHeartbeatAt}. Local protection may still be running. Open ${this.dashboardUrl} to repair reporting before considering a reinstall.`
      }),
      signal: AbortSignal.timeout(10000)
    });
    if (!response.ok) throw new Error(`Recovery email returned HTTP ${response.status}`);
    return { delivered: true };
  }
}

module.exports = { RecoveryEmailNotifier };

'use strict';

class CentralRecoveryMonitor {
  constructor({ consoleStore, setupAuthority, emailNotifier, heartbeatTimeoutMs = 5 * 60 * 1000, clock = () => new Date() } = {}) {
    if (!consoleStore || typeof consoleStore.missingCentral !== 'function' || typeof consoleStore.markCentralMissing !== 'function') throw new TypeError('A recovery-aware console store is required');
    if (!setupAuthority || typeof setupAuthority.createRecovery !== 'function' || typeof setupAuthority.activeRecovery !== 'function') throw new TypeError('A recovery-aware setup authority is required');
    if (!emailNotifier || typeof emailNotifier.sendCentralRecovery !== 'function') throw new TypeError('A central recovery email notifier is required');
    if (!Number.isSafeInteger(heartbeatTimeoutMs) || heartbeatTimeoutMs < 1000) throw new Error('Central heartbeat timeout is invalid');
    this.consoleStore = consoleStore;
    this.setupAuthority = setupAuthority;
    this.emailNotifier = emailNotifier;
    this.heartbeatTimeoutMs = heartbeatTimeoutMs;
    this.clock = clock;
    this.running = null;
  }

  async sweep() {
    if (this.running) return this.running;
    this.running = (async () => {
      const now = this.clock();
      const notifiedAt = (now instanceof Date ? now : new Date(now)).toISOString();
      const missing = await this.consoleStore.missingCentral({ thresholdMs: this.heartbeatTimeoutMs, now });
      const recovered = [];
      for (const deployment of missing) {
        if (deployment.recovery?.session_id) {
          const active = await this.setupAuthority.activeRecovery({ tenantId: deployment.tenantId, deploymentId: deployment.deploymentId });
          if (active) continue;
        }
        const recovery = await this.setupAuthority.createRecovery({ tenantId: deployment.tenantId, deploymentId: deployment.deploymentId });
        await this.emailNotifier.sendCentralRecovery({ to: recovery.notification_email, deploymentId: deployment.deploymentId, lastHeartbeatAt: deployment.updatedAt });
        await this.consoleStore.markCentralMissing({ tenantId: deployment.tenantId, deploymentId: deployment.deploymentId, recoverySessionId: recovery.session_id, notifiedAt });
        recovered.push(deployment.deploymentId);
      }
      return recovered;
    })().finally(() => { this.running = null; });
    return this.running;
  }
}

module.exports = { CentralRecoveryMonitor };

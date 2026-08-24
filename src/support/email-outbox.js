'use strict';

function emit(logger, record) { try { logger(record); } catch {} }

class SupportEmailOutboxWorker {
  constructor({ store, notifier, clock = () => Date.now(), maximumAttempts = 10, logger = () => {} } = {}) { this.store = store; this.notifier = notifier; this.clock = clock; this.maximumAttempts = maximumAttempts; this.logger = logger; }
  async sweep() {
    if (!this.store || !this.notifier) return { processed: 0 };
    let processed = 0;
    for (let count = 0; count < 10; count += 1) {
      const now = new Date(this.clock()).toISOString(); const record = await this.store.claimEmailOutbox({ now, maximumAttempts: this.maximumAttempts }); if (!record) break;
      processed += 1;
      try {
        const delivered = await this.notifier.send(record); await this.store.completeEmailOutbox({ outboxId: record.outboxId, ...delivered, now: new Date(this.clock()).toISOString() });
        emit(this.logger, { event: 'lookout_support_email', outcome: 'delivered', attempt: record.attempts });
      } catch {
        const delay = Math.min(60 * 60 * 1000, 1000 * (2 ** Math.min(record.attempts, 12)));
        await this.store.failEmailOutbox({ outboxId: record.outboxId, now, nextAttemptAt: new Date(this.clock() + delay).toISOString(), maximumAttempts: this.maximumAttempts });
        emit(this.logger, { event: 'lookout_support_email', outcome: record.attempts >= this.maximumAttempts ? 'failed' : 'retry', attempt: record.attempts });
      }
    }
    return { processed };
  }
}

module.exports = { SupportEmailOutboxWorker };

'use strict';

const { signPayload } = require('./envelope');
const { postJson } = require('./transport');

class CollectorRunner {
  constructor({ collectorId, privateKeyPem, modules, initialSequence = 0, clock = () => new Date() } = {}) {
    if (!collectorId || !privateKeyPem || !Array.isArray(modules) || !modules.length) throw new Error('CollectorRunner requires identity, private key, and modules');
    this.collectorId = collectorId;
    this.privateKeyPem = privateKeyPem;
    this.modules = modules;
    this.sequence = initialSequence;
    this.clock = clock;
  }

  collectOnce() {
    this.sequence += 1;
    const collectedAt = this.clock().toISOString();
    const facts = [];
    const events = [];
    for (const module of this.modules) {
      if (!module || typeof module.collect !== 'function') throw new Error('Collector module must implement collect(context)');
      const output = module.collect({ collectorId: this.collectorId, collectedAt, sequence: this.sequence });
      facts.push(...(output.facts || []));
      events.push(...(output.events || []));
    }
    return signPayload({ schemaVersion: 1, collectorId: this.collectorId, sequence: this.sequence, collectedAt, facts, events }, this.privateKeyPem);
  }
}

async function submitEnvelope(url, envelope, { apiToken, fetchImpl = globalThis.fetch, httpsRequestImpl, caPem = null, timeoutMs = 15000 } = {}) {
  const target = new URL(url);
  if (target.protocol !== 'https:' && !['localhost', '127.0.0.1', '::1'].includes(target.hostname)) throw new Error('Collector submissions require HTTPS outside loopback');
  if (target.username || target.password) throw new Error('Collector submission URL must not contain credentials');
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100) throw new Error('Collector submission timeout is invalid');
  try { return await postJson(target, envelope, { authorization: apiToken ? `Bearer ${apiToken}` : null, fetchImpl, httpsRequestImpl, caPem, timeoutMs }); }
  catch (error) { throw new Error(error.message.replace('Collector request', 'Collector submission'), { cause: error }); }
}

module.exports = { CollectorRunner, submitEnvelope };

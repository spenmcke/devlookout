'use strict';

const crypto = require('node:crypto');
const { tailscaleLogNormalizer } = require('../normalizers/tailscale-logs');
const { canonicalJson } = require('../core/canonical');

const MODES = Object.freeze({
  'network-flow': { clientMethod: 'listNetworkLogs', timestampFields: ['logged', 'end', 'start'] },
  'configuration-audit': { clientMethod: 'listConfigurationLogs', timestampFields: ['eventTime', 'time', 'timestamp', 'created'] }
});

function timestamp(record, fields) {
  for (const field of fields) {
    if (typeof record?.[field] === 'string' && !Number.isNaN(Date.parse(record[field]))) return new Date(record[field]).toISOString();
  }
  throw new Error('Tailscale log record has no valid timestamp');
}

function recordId(record) {
  return crypto.createHash('sha256').update(canonicalJson(record)).digest('hex');
}

function validCursor(cursor, modes) {
  if (cursor === undefined) return {};
  if (!cursor || cursor.schemaVersion !== 1 || !cursor.modes || typeof cursor.modes !== 'object' || Array.isArray(cursor.modes)) throw new Error('Tailscale log cursor is invalid');
  const output = {};
  for (const mode of modes) {
    const value = cursor.modes[mode];
    if (value === undefined) continue;
    if (!value || typeof value.at !== 'string' || Number.isNaN(Date.parse(value.at)) || !Array.isArray(value.ids) || value.ids.length > 10000 || value.ids.some((id) => typeof id !== 'string' || !/^[a-f0-9]{64}$/.test(id))) throw new Error('Tailscale log cursor is invalid');
    output[mode] = { at: new Date(value.at).toISOString(), ids: [...new Set(value.ids)] };
  }
  return output;
}

function sleep(milliseconds, signal) {
  if (signal.aborted) return Promise.resolve();
  return new Promise((resolve) => {
    const timer = setTimeout(done, milliseconds);
    function done() {
      clearTimeout(timer);
      signal.removeEventListener('abort', done);
      resolve();
    }
    signal.addEventListener('abort', done, { once: true });
  });
}

class TailscaleLogSource {
  constructor({
    client, tailnet, modes = Object.keys(MODES), pollIntervalMs = 15000,
    initialLookbackMs = 5 * 60 * 1000, ingestionDelayMs = 30000,
    maximumWindowMs = 5 * 60 * 1000, clock = () => new Date(),
    normalizer = null, instance = tailnet
  } = {}) {
    if (!client || typeof client !== 'object') throw new TypeError('Tailscale log source requires a client');
    if (typeof tailnet !== 'string' || !tailnet || tailnet.length > 512) throw new Error('Tailscale log source requires a tailnet ID');
    if (!Array.isArray(modes) || !modes.length || modes.some((mode) => !Object.hasOwn(MODES, mode)) || new Set(modes).size !== modes.length) throw new Error('Tailscale log modes must contain network-flow and/or configuration-audit');
    for (const mode of modes) if (typeof client[MODES[mode].clientMethod] !== 'function') throw new TypeError(`Tailscale client does not support ${mode}`);
    for (const [name, value] of Object.entries({ pollIntervalMs, initialLookbackMs, ingestionDelayMs, maximumWindowMs })) {
      if (!Number.isSafeInteger(value) || value < (name === 'pollIntervalMs' ? 10 : 0)) throw new Error(`${name} is invalid`);
    }
    if (maximumWindowMs < 1000) throw new Error('maximumWindowMs must be at least one second');
    if (typeof clock !== 'function') throw new TypeError('Tailscale log source clock is invalid');
    this.id = 'tailscale-logs';
    this.client = client;
    this.tailnet = tailnet;
    this.modes = [...modes];
    this.pollIntervalMs = pollIntervalMs;
    this.initialLookbackMs = initialLookbackMs;
    this.ingestionDelayMs = ingestionDelayMs;
    this.maximumWindowMs = maximumWindowMs;
    this.clock = clock;
    this.normalizer = normalizer || tailscaleLogNormalizer({ tailnet, instance });
    if (!this.normalizer || typeof this.normalizer.normalize !== 'function') throw new TypeError('Tailscale log source requires a normalizer');
    this.modeStatus = Object.fromEntries(this.modes.map((mode) => [mode, { status: 'unknown', reason: 'The Tailscale log API has not completed a successful poll' }]));
  }

  async *events({ signal, cursor } = {}) {
    if (!(signal instanceof AbortSignal)) throw new TypeError('Tailscale log source requires an AbortSignal');
    const positions = validCursor(cursor, this.modes);
    while (!signal.aborted) {
      let polled = false;
      for (const mode of this.modes) {
        if (signal.aborted) break;
        const now = this.clock();
        if (!(now instanceof Date) || Number.isNaN(now.getTime())) throw new Error('Tailscale log source clock returned an invalid date');
        const availableThrough = now.getTime() - this.ingestionDelayMs;
        const position = positions[mode];
        const startMs = position ? Date.parse(position.at) : availableThrough - this.initialLookbackMs;
        if (startMs > availableThrough) continue;
        const endMs = Math.min(availableThrough, startMs + this.maximumWindowMs);
        const start = new Date(startMs).toISOString();
        const end = new Date(endMs).toISOString();
        const descriptor = MODES[mode];
        let records;
        try {
          records = await this.client[descriptor.clientMethod](this.tailnet, { start, end, signal });
          this.modeStatus[mode] = { status: 'available', reason: null };
        } catch (error) {
          this.modeStatus[mode] = { status: 'unavailable', reason: 'Tailscale log API polling failed; verify plan availability, logging enablement, and read-only credential scopes' };
          throw error;
        }
        if (!Array.isArray(records)) throw new Error('Tailscale client returned invalid logs');
        const ordered = records.map((record) => ({ record, at: timestamp(record, descriptor.timestampFields), id: recordId(record) }))
          .sort((left, right) => left.at.localeCompare(right.at) || left.id.localeCompare(right.id));
        const unseen = ordered.filter((item) => !position || item.at !== position.at || !position.ids.includes(item.id));
        for (let index = 0; index < unseen.length; index += 1) {
          const item = unseen[index];
          if (!positions[mode] || positions[mode].at !== item.at) positions[mode] = { at: item.at, ids: [] };
          if (!positions[mode].ids.includes(item.id)) positions[mode].ids.push(item.id);
          if (positions[mode].ids.length > 10000) throw new Error('Tailscale log cursor boundary exceeds the safe record limit');
          if (index === unseen.length - 1 && item.at < end) positions[mode] = { at: end, ids: [] };
          const normalizedRecord = mode === 'configuration-audit' ? { ...item.record, id: item.record.id || item.id } : item.record;
          const events = this.normalizer.normalize(normalizedRecord, { tailnet: this.tailnet, logType: mode, receivedAt: now.toISOString() });
          if (!Array.isArray(events) || !events.length) throw new Error('Tailscale log normalizer produced no events');
          yield { events, cursor: { schemaVersion: 1, modes: structuredClone(positions) } };
        }
        if (!unseen.length) positions[mode] = { at: end, ids: [] };
        polled = true;
      }
      if (!polled || !signal.aborted) await sleep(this.pollIntervalMs, signal);
    }
  }

  capabilities() {
    const output = [];
    if (this.modes.includes('network-flow')) output.push({ capability: 'network_flow', ...this.modeStatus['network-flow'] });
    if (this.modes.includes('configuration-audit')) {
      output.push({ capability: 'configuration_change', ...this.modeStatus['configuration-audit'] });
      output.push({ capability: 'identity', ...this.modeStatus['configuration-audit'] });
    }
    return output.sort((left, right) => left.capability.localeCompare(right.capability));
  }
}

module.exports = { MODES, TailscaleLogSource, recordId, validCursor };

'use strict';

const net = require('node:net');

const ID_PART = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/;
const PLATFORMS = new Set(['linux', 'macos', 'windows', 'ios', 'android', 'bsd', 'network', 'embedded', 'unknown']);

function cleanText(value, label, maximum = 255) {
  if (value === null || value === undefined || value === '') return null;
  if (typeof value !== 'string' || Buffer.byteLength(value) > maximum || /[\0-\x1f\x7f]/.test(value)) throw new Error(`${label} is invalid`);
  return value;
}

function normalizeCandidate(candidate, adapterId) {
  if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) throw new Error(`Discovery adapter ${adapterId} emitted an invalid candidate`);
  const provider = candidate.provider || adapterId;
  const stableAssetId = candidate.stableAssetId;
  if (!ID_PART.test(provider || '') || !ID_PART.test(stableAssetId || '')) throw new Error(`Discovery adapter ${adapterId} emitted an invalid stable identity`);
  const id = `${provider}:${stableAssetId}`;
  const addresses = [...new Set(candidate.addresses || [])];
  if (addresses.length > 64 || addresses.some((address) => typeof address !== 'string' || net.isIP(address) === 0)) throw new Error(`Discovery adapter ${adapterId} emitted an invalid address`);
  const platform = String(candidate.platform || candidate.platformHint || 'unknown').toLowerCase();
  const normalizedPlatform = PLATFORMS.has(platform) ? platform : 'unknown';
  return Object.freeze({
    id, provider, stableAssetId,
    addresses: Object.freeze(addresses.sort()),
    hostname: cleanText(candidate.hostname, 'Discovery hostname'),
    platform: normalizedPlatform,
    online: candidate.online === true,
    local: candidate.local === true,
    providers: Object.freeze([provider]),
    evidence: Object.freeze([...new Set((candidate.evidence || []).map((item) => cleanText(item, 'Discovery evidence', 512)))].sort()),
    authoritativeIdentity: candidate.authoritativeIdentity !== false,
    deploymentAuthorized: false
  });
}

class DiscoveryRegistry {
  #adapters = new Map();

  register(adapter) {
    const id = adapter?.manifest?.id;
    if (!ID_PART.test(id || '') || typeof adapter.discover !== 'function') throw new Error('Discovery adapter requires a valid manifest ID and discover(context)');
    if (this.#adapters.has(id)) throw new Error(`Discovery adapter already registered: ${id}`);
    this.#adapters.set(id, adapter);
    return this;
  }

  async discover(context = {}) {
    const authorized = new Set(context.authorizedAssetIds || []);
    const nodes = [];
    const gaps = [];
    for (const [id, adapter] of [...this.#adapters].sort(([a], [b]) => a.localeCompare(b))) {
      try {
        const output = await adapter.discover(Object.freeze({ ...context, authorizedAssetIds: undefined }));
        if (!output || typeof output[Symbol.iterator] !== 'function') throw new Error('discover() must return an iterable');
        let count = 0;
        for (const candidate of output) {
          if (++count > 10000) throw new Error('candidate limit exceeded');
          const node = normalizeCandidate(candidate, id);
          nodes.push(Object.freeze({ ...node, deploymentAuthorized: node.authoritativeIdentity && authorized.has(node.id) }));
        }
      } catch (error) {
        gaps.push(Object.freeze({ adapter: id, status: 'unavailable', reason: cleanText(error.message, 'Discovery error', 512) || 'discovery failed' }));
      }
    }
    const byId = new Map();
    const conflicted = new Set();
    for (const node of nodes.sort((a, b) => a.id.localeCompare(b.id))) {
      if (byId.has(node.id)) {
        gaps.push(Object.freeze({ adapter: node.provider, status: 'conflict', reason: `duplicate stable asset identity: ${node.id}` }));
        byId.delete(node.id);
        conflicted.add(node.id);
        continue;
      }
      if (conflicted.has(node.id)) continue;
      byId.set(node.id, node);
    }
    return Object.freeze({ nodes: Object.freeze([...byId.values()]), gaps: Object.freeze(gaps.sort((a, b) => `${a.adapter}:${a.reason}`.localeCompare(`${b.adapter}:${b.reason}`))) });
  }
}

function tailscaleStatusAdapter({ statusProvider, id = 'tailscale-local' } = {}) {
  if (typeof statusProvider !== 'function') throw new Error('Tailscale discovery requires statusProvider');
  return {
    manifest: { id },
    async discover() {
      const status = await statusProvider();
      const records = [];
      if (status?.Self) records.push(status.Self);
      if (status?.Peer && typeof status.Peer === 'object') records.push(...Object.values(status.Peer));
      return records.map((record) => {
        const stableAssetId = record.StableID || record.ID;
        if (!stableAssetId) throw new Error('Tailscale status record lacks a stable node identity');
        return {
          provider: 'tailscale', stableAssetId, addresses: record.TailscaleIPs || [],
          hostname: record.HostName || record.DNSName || null,
          platformHint: record.OS || 'unknown', online: record.Online !== false,
          local: record === status.Self, evidence: ['tailscale-control-plane']
        };
      });
    }
  };
}

function neighborTableAdapter({ recordsProvider, id = 'local-neighbors' } = {}) {
  if (typeof recordsProvider !== 'function') throw new Error('Neighbor discovery requires recordsProvider');
  return {
    manifest: { id },
    async discover() {
      const records = await recordsProvider();
      return records.map(({ address, mac, hostname = null }) => {
        const normalizedMac = typeof mac === 'string' ? mac.toLowerCase().replace(/-/g, ':') : '';
        if (!/^(?:[a-f0-9]{2}:){5}[a-f0-9]{2}$/.test(normalizedMac)) throw new Error('Neighbor record lacks a canonical MAC address');
        return {
          provider: 'link-layer', stableAssetId: normalizedMac, addresses: [address], hostname,
          platformHint: 'unknown', online: true, local: false, evidence: ['passive-neighbor-table'], authoritativeIdentity: false
        };
      });
    }
  };
}

module.exports = { DiscoveryRegistry, normalizeCandidate, tailscaleStatusAdapter, neighborTableAdapter };

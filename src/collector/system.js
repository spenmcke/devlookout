'use strict';

const os = require('node:os');
const fs = require('node:fs');
const { version } = require('../../package.json');
const { createFact } = require('../adapters/contract');
const { createEvent } = require('../events/schema');

function systemCollector({ collectorId, instance = collectorId, entityKey = null } = {}) {
  if (!collectorId) throw new Error('System collector requires collectorId');
  const endpointKey = entityKey || `collector-endpoint:${collectorId}`;
  return {
    manifest: { id: 'system-inventory', version: '1.0.0', intervalSeconds: 300, capabilities: ['inventory', 'sensor_health'] },
    collect({ collectedAt, sequence }) {
      let interfaces = [];
      let inventoryStatus = 'available';
      try {
        interfaces = Object.entries(os.networkInterfaces()).flatMap(([name, addresses]) => (addresses || []).filter((address) => !address.internal).map((address) => ({ name, address: address.address, family: address.family, cidr: address.cidr })));
      } catch {
        // A hardened container or service sandbox may deny netlink interface
        // enumeration. Keep heartbeats flowing and report partial inventory.
        inventoryStatus = 'degraded';
      }
      let lookoutUpdate = null;
      try {
        const updateFile = process.env.LOOKOUT_UPDATE_STATUS || '/run/lookout-update/status.json';
        const stat = fs.lstatSync(updateFile);
        if (stat.isFile() && !stat.isSymbolicLink() && stat.size <= 4096) {
          const value = JSON.parse(fs.readFileSync(updateFile, 'utf8'));
          if (value?.schemaVersion === 1 && typeof value.status === 'string') lookoutUpdate = value;
        }
      } catch { /* Update status is optional and must never interrupt telemetry. */ }
      const source = { adapter: 'system-inventory', instance, recordId: `inventory:${sequence}` };
      const facts = [
        createFact({ kind: 'entity', observedAt: collectedAt, source, data: { entityKey: endpointKey, entityType: 'endpoint', name: os.hostname(), attributes: { platform: os.platform(), release: os.release(), architecture: os.arch(), virtualized: null, networkInterfaces: interfaces, ...(lookoutUpdate ? { lookoutUpdate } : {}) } } }),
        createFact({ kind: 'capability', observedAt: collectedAt, source: { ...source, recordId: `inventory-capability:${sequence}` }, data: { entityKey: endpointKey, capability: 'inventory', status: inventoryStatus, freshnessSeconds: 300 } }),
        createFact({ kind: 'capability', observedAt: collectedAt, source: { ...source, recordId: `health-capability:${sequence}` }, data: { entityKey: endpointKey, capability: 'sensor_health', status: 'available', freshnessSeconds: 300 } })
      ];
      const events = [createEvent({ time: collectedAt, ingestedAt: collectedAt, category: 'health', class: 'sensor_activity', activity: 'heartbeat', outcome: 'success', source: { adapter: 'system-inventory', instance, recordId: `heartbeat:${sequence}` }, entityKeys: [endpointKey], attributes: { collectorVersion: version, uptimeSeconds: os.uptime() } })];
      return { facts, events };
    }
  };
}

module.exports = { systemCollector };

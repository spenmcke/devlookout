'use strict';

const { createFact } = require('./contract');
const { stableId } = require('../core/canonical');

function list(value) {
  return Array.isArray(value) ? value : [];
}

function cleanName(value, fallback) {
  if (typeof value !== 'string' || !value.trim()) return fallback;
  return value.replace(/\.$/, '');
}

function tailscaleAdapter({ client, tailnet, instance = tailnet, includeUsers = true, includePolicy = true }) {
  if (!client || typeof client.listDevices !== 'function') throw new TypeError('Tailscale adapter requires client.listDevices(tailnet)');
  if (typeof tailnet !== 'string' || !tailnet) throw new TypeError('Tailscale adapter requires a tailnet ID');
  const adapterId = 'tailscale';
  const prefix = `tailscale:${tailnet}`;
  const sourceFor = (recordId) => ({ adapter: adapterId, instance, recordId });

  return {
    manifest: {
      id: adapterId,
      version: '1.0.0',
      kind: 'network-overlay',
      capabilities: ['inventory', 'identity', 'network_policy', 'network_flow', 'route', 'configuration_change'],
      permissions: ['devices:core:read', ...(includeUsers ? ['users:read'] : []), ...(includePolicy ? ['policy_file:read'] : [])]
    },
    async survey(context = {}) {
      const observedAt = context.observedAt || new Date().toISOString();
      const [deviceResponse, userResponse, policy] = await Promise.all([
        client.listDevices(tailnet),
        includeUsers && typeof client.listUsers === 'function' ? client.listUsers(tailnet) : null,
        includePolicy && typeof client.getPolicy === 'function' ? client.getPolicy(tailnet) : null
      ]);
      const devices = list(deviceResponse?.devices || deviceResponse);
      const users = list(userResponse?.users || userResponse);
      const facts = [];
      const networkKey = `${prefix}:network`;

      facts.push(createFact({ kind: 'entity', observedAt, source: sourceFor('tailnet'), data: {
        entityKey: networkKey, entityType: 'network', name: tailnet === '-' ? 'Tailnet' : tailnet,
        attributes: { provider: 'tailscale', overlay: true }
      } }));

      const userKeys = new Map();
      for (const user of users) {
        const externalId = String(user.id || user.loginName || user.email || user.displayName);
        const key = `${prefix}:user:${externalId}`;
        userKeys.set(externalId, key);
        if (user.loginName) userKeys.set(String(user.loginName), key);
        facts.push(createFact({ kind: 'entity', observedAt, source: sourceFor(`user:${externalId}`), data: {
          entityKey: key, entityType: 'identity', name: cleanName(user.displayName || user.loginName || user.email, externalId),
          attributes: { provider: 'tailscale', identityKind: 'user', role: user.role || 'member', status: user.status || 'unknown' }
        } }));
        facts.push(createFact({ kind: 'relationship', observedAt, source: sourceFor(`user-member:${externalId}`), data: { from: key, to: networkKey, relation: 'member_of' } }));
      }

      for (const device of devices) {
        const externalId = String(device.nodeId || device.id);
        if (!externalId || externalId === 'undefined') continue;
        const deviceKey = `${prefix}:device:${externalId}`;
        const hostname = cleanName(device.name || device.hostname, externalId);
        facts.push(createFact({ kind: 'entity', observedAt, source: sourceFor(`device:${externalId}`), data: {
          entityKey: deviceKey, entityType: 'endpoint', name: hostname,
          attributes: {
            provider: 'tailscale', platform: device.os || 'unknown', addresses: list(device.addresses).sort(),
            clientVersion: device.clientVersion || 'unknown', authorized: device.authorized !== false,
            external: Boolean(device.isExternal), updateAvailable: Boolean(device.updateAvailable),
            createdAt: device.created || null, lastSeenAt: device.lastSeen || null, expiresAt: device.expires || null,
            keyExpiryDisabled: Boolean(device.keyExpiryDisabled), tags: list(device.tags).sort()
          }
        } }));
        facts.push(createFact({ kind: 'relationship', observedAt, source: sourceFor(`device-member:${externalId}`), data: { from: deviceKey, to: networkKey, relation: 'member_of' } }));

        const ownerRef = String(device.user || device.userId || '');
        if (ownerRef && userKeys.has(ownerRef)) facts.push(createFact({ kind: 'relationship', observedAt, source: sourceFor(`device-owner:${externalId}`), data: { from: userKeys.get(ownerRef), to: deviceKey, relation: 'owns' } }));

        for (const tag of list(device.tags).sort()) {
          const tagKey = `${prefix}:tag:${tag}`;
          facts.push(createFact({ kind: 'entity', observedAt, source: sourceFor(`tag:${tag}`), data: { entityKey: tagKey, entityType: 'identity', name: tag, attributes: { provider: 'tailscale', identityKind: 'device_tag' } } }));
          facts.push(createFact({ kind: 'relationship', observedAt, source: sourceFor(`device-tag:${externalId}:${tag}`), data: { from: deviceKey, to: tagKey, relation: 'assumes_identity' } }));
        }

        const enabled = new Set(list(device.enabledRoutes));
        for (const cidr of list(device.advertisedRoutes).sort()) {
          const routeKey = `${prefix}:route:${externalId}:${cidr}`;
          facts.push(createFact({ kind: 'entity', observedAt, source: sourceFor(`route:${externalId}:${cidr}`), data: { entityKey: routeKey, entityType: 'route', name: cidr, attributes: { cidr, enabled: enabled.has(cidr), exitNode: cidr === '0.0.0.0/0' || cidr === '::/0' } } }));
          facts.push(createFact({ kind: 'relationship', observedAt, source: sourceFor(`advertises:${externalId}:${cidr}`), data: { from: deviceKey, to: routeKey, relation: 'advertises' } }));
        }

        if (device.isExternal) {
          const exposureKey = `${prefix}:share:${externalId}`;
          facts.push(createFact({ kind: 'entity', observedAt, source: sourceFor(`share:${externalId}`), data: { entityKey: exposureKey, entityType: 'exposure', name: `External share: ${hostname}`, attributes: { mechanism: 'tailscale-share' } } }));
          facts.push(createFact({ kind: 'relationship', observedAt, source: sourceFor(`shared:${externalId}`), data: { from: deviceKey, to: exposureKey, relation: 'exposed_through' } }));
        }
      }

      const policyKey = `${prefix}:policy`;
      if (policy) {
        const summary = {
          grants: list(policy.grants).length, acls: list(policy.acls).length, sshRules: list(policy.ssh).length,
          tests: list(policy.tests).length, sshTests: list(policy.sshTests).length,
          postures: Object.keys(policy.postures || {}).length, groups: Object.keys(policy.groups || {}).length,
          tagOwners: Object.keys(policy.tagOwners || {}).length,
          policyDigest: stableId('policy', policy)
        };
        facts.push(createFact({ kind: 'entity', observedAt, source: sourceFor('policy'), data: { entityKey: policyKey, entityType: 'control', name: 'Tailnet policy', attributes: summary } }));
        facts.push(createFact({ kind: 'relationship', observedAt, source: sourceFor('policy-protects'), data: { from: policyKey, to: networkKey, relation: 'protects' } }));
      }

      const capabilities = [
        ['inventory', 'available'], ['identity', users.length ? 'available' : 'unknown'],
        ['network_policy', policy ? 'available' : 'unknown'], ['route', 'available'],
        ['configuration_change', 'unknown'], ['network_flow', 'unknown']
      ];
      for (const [capability, status] of capabilities) facts.push(createFact({ kind: 'capability', observedAt, source: sourceFor(`capability:${capability}`), data: { entityKey: networkKey, capability, status } }));
      return facts;
    }
  };
}

module.exports = { tailscaleAdapter };

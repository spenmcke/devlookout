'use strict';

const http = require('node:http');
const net = require('node:net');

function normalizeAddress(address) {
  if (typeof address !== 'string') return null;
  const value = address.startsWith('::ffff:') ? address.slice(7) : address;
  return net.isIP(value) ? value : null;
}

function readWhoIs(socketPath, address, port, { requestImpl = http.request, timeoutMs = 2000, maximumBytes = 256 * 1024 } = {}) {
  return new Promise((resolve, reject) => {
    const path = `/localapi/v0/whois?addr=${encodeURIComponent(net.isIP(address) === 6 ? `[${address}]:${port}` : `${address}:${port}`)}`;
    const request = requestImpl({ socketPath, path, method: 'GET', headers: { Host: 'local-tailscaled.sock', Accept: 'application/json' } }, (response) => {
      let size = 0; const chunks = [];
      response.on('data', (chunk) => {
        size += chunk.length;
        if (size > maximumBytes) { request.destroy(new Error('Tailscale identity response is too large')); return; }
        chunks.push(chunk);
      });
      response.on('end', () => {
        if (response.statusCode !== 200) { reject(new Error('Tailscale identity lookup failed')); return; }
        try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
        catch { reject(new Error('Tailscale identity response is invalid')); }
      });
    });
    request.setTimeout(timeoutMs, () => request.destroy(new Error('Tailscale identity lookup timed out')));
    request.on('error', reject);
    request.end();
  });
}

class TailscaleAuthenticator {
  constructor({ socketPath = '/var/run/tailscale/tailscaled.sock', allowedUserIds = [], allowedNodeIds = [], roles = ['admin'], requestImpl = http.request, timeoutMs = 2000, cacheTtlMs = 30000, clock = Date.now } = {}) {
    if (typeof socketPath !== 'string' || !socketPath.startsWith('/')) throw new Error('Tailscale LocalAPI socket path must be absolute');
    if (!Array.isArray(allowedUserIds) || allowedUserIds.some((id) => !/^\d+$/.test(String(id)))) throw new Error('Tailscale allowed user IDs must be numeric IDs');
    if (!Array.isArray(allowedNodeIds) || allowedNodeIds.some((id) => typeof id !== 'string' || !/^[A-Za-z0-9]+$/.test(id))) throw new Error('Tailscale allowed node IDs are invalid');
    if (!Array.isArray(roles) || !roles.length || roles.some((role) => typeof role !== 'string' || !role)) throw new Error('Tailscale roles are required');
    if (typeof requestImpl !== 'function' || !Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 10000 || !Number.isSafeInteger(cacheTtlMs) || cacheTtlMs < 0 || cacheTtlMs > 300000) throw new Error('Tailscale authenticator options are invalid');
    this.socketPath = socketPath; this.allowedUserIds = new Set(allowedUserIds.map(String)); this.allowedNodeIds = new Set(allowedNodeIds); this.roles = [...new Set(roles)].sort();
    this.requestImpl = requestImpl; this.timeoutMs = timeoutMs; this.cacheTtlMs = cacheTtlMs; this.clock = clock; this.cache = new Map();
  }

  async authenticate(req) {
    const address = normalizeAddress(req.socket?.remoteAddress);
    const port = Number(req.socket?.remotePort || 0);
    if (!address || !Number.isSafeInteger(port) || port < 1 || port > 65535) return null;
    const cached = this.cache.get(address);
    if (cached && cached.expiresAt > this.clock()) return { ...cached.principal, roles: [...cached.principal.roles] };
    let identity;
    try { identity = await readWhoIs(this.socketPath, address, port, { requestImpl: this.requestImpl, timeoutMs: this.timeoutMs }); }
    catch { return null; }
    const nodeId = identity?.Node?.StableID;
    const userId = String(identity?.UserProfile?.ID ?? identity?.Node?.User ?? '');
    const addresses = Array.isArray(identity?.Node?.Addresses) ? identity.Node.Addresses.map((cidr) => String(cidr).split('/')[0]) : [];
    if (typeof nodeId !== 'string' || !nodeId || !userId || !addresses.includes(address)) return null;
    if (this.allowedUserIds.size && !this.allowedUserIds.has(userId)) return null;
    if (this.allowedNodeIds.size && !this.allowedNodeIds.has(nodeId)) return null;
    if (!this.allowedUserIds.size && !this.allowedNodeIds.size) return null;
    const loginName = typeof identity?.UserProfile?.LoginName === 'string' ? identity.UserProfile.LoginName.slice(0, 256) : null;
    const displayName = typeof identity?.UserProfile?.DisplayName === 'string' ? identity.UserProfile.DisplayName.slice(0, 256) : null;
    const principal = { id: `tailscale-user:${userId}`, roles: [...this.roles], authentication: 'tailscale', tailscaleNodeId: nodeId, loginName, displayName };
    this.cache.set(address, { principal, expiresAt: this.clock() + this.cacheTtlMs });
    return { ...principal, roles: [...principal.roles] };
  }
}

module.exports = { normalizeAddress, readWhoIs, TailscaleAuthenticator };

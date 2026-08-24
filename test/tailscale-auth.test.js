'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { once } = require('node:events');
const { TailscaleAuthenticator, normalizeAddress } = require('../src/security/tailscale-auth');

test('Tailscale LocalAPI identity grants only explicitly allowed users', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-ts-auth-'));
  const socketPath = path.join(directory, 'tailscaled.sock');
  let lookups = 0;
  const server = http.createServer((request, response) => {
    lookups += 1;
    assert.match(request.url, /^\/localapi\/v0\/whois\?addr=100\.97\.66\.45%3A/);
    response.writeHead(200, { 'Content-Type': 'application/json' });
    response.end(JSON.stringify({ Node: { StableID: 'nodeStable123', User: 6633512513925615, Addresses: ['100.97.66.45/32'] }, UserProfile: { ID: 6633512513925615, LoginName: 'operator@example.com', DisplayName: 'Security Operator' } }));
  });
  server.listen(socketPath); await once(server, 'listening');
  try {
    const request = { socket: { remoteAddress: '::ffff:100.97.66.45', remotePort: 49152 } };
    const allowed = new TailscaleAuthenticator({ socketPath, allowedUserIds: ['6633512513925615'] });
    assert.deepEqual(await allowed.authenticate(request), { id: 'tailscale-user:6633512513925615', roles: ['admin'], authentication: 'tailscale', tailscaleNodeId: 'nodeStable123', loginName: 'operator@example.com', displayName: 'Security Operator' });
    assert.equal((await allowed.authenticate(request)).tailscaleNodeId, 'nodeStable123');
    assert.equal(lookups, 1, 'verified identities are briefly cached by source address');
    const denied = new TailscaleAuthenticator({ socketPath, allowedUserIds: ['999'] });
    assert.equal(await denied.authenticate(request), null);
  } finally { server.close(); await once(server, 'close'); await fs.rm(directory, { recursive: true, force: true }); }
});

test('Tailscale authentication fails closed for invalid sources and empty policy', async () => {
  assert.equal(normalizeAddress('::ffff:100.64.0.1'), '100.64.0.1');
  assert.equal(normalizeAddress('not-an-ip'), null);
  const authenticator = new TailscaleAuthenticator();
  assert.equal(await authenticator.authenticate({ socket: { remoteAddress: '192.0.2.1', remotePort: 1 } }), null);
});

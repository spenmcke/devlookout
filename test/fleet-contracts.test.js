'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { DiscoveryRegistry, tailscaleStatusAdapter, neighborTableAdapter } = require('../src/fleet/discovery');
const { SshDeploymentTransport, quoteRemote } = require('../src/fleet/deployment');

test('provider-neutral discovery is deterministic and never treats discovery as authorization', async () => {
  const registry = new DiscoveryRegistry()
    .register(neighborTableAdapter({ recordsProvider: async () => [{ address: '192.168.1.5', mac: 'AA:BB:CC:DD:EE:FF' }] }))
    .register(tailscaleStatusAdapter({ statusProvider: async () => ({
      Self: { ID: 'node-b', HostName: 'admin', OS: 'macOS', TailscaleIPs: ['100.64.0.2'], Online: true },
      Peer: { x: { ID: 'node-a', HostName: 'server; touch /tmp/pwned', OS: 'linux', TailscaleIPs: ['100.64.0.1'], Online: true } }
    }) }));
  const result = await registry.discover({ authorizedAssetIds: ['tailscale:node-a'] });
  assert.deepEqual(result.nodes.map((item) => item.id), ['link-layer:aa:bb:cc:dd:ee:ff', 'tailscale:node-a', 'tailscale:node-b']);
  assert.equal(result.nodes[0].deploymentAuthorized, false);
  assert.equal(result.nodes[1].deploymentAuthorized, true);
  assert.equal(result.nodes[1].hostname, 'server; touch /tmp/pwned');
});

test('discovery isolates provider failures and rejects duplicate stable identities', async () => {
  const adapter = { manifest: { id: 'broken' }, discover() { throw new Error('offline'); } };
  const duplicate = { manifest: { id: 'dup' }, discover() { return [{ stableAssetId: 'x', addresses: ['192.0.2.1'] }, { stableAssetId: 'x', addresses: ['192.0.2.2'] }]; } };
  const result = await new DiscoveryRegistry().register(adapter).register(duplicate).discover();
  assert.equal(result.nodes.length, 0);
  assert.deepEqual(result.gaps.map((gap) => gap.status).sort(), ['conflict', 'unavailable']);
});

test('SSH deployment requires explicit authorization and strict host identity', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-fleet-'));
  try {
    const knownHosts = path.join(directory, 'known_hosts');
    await fs.writeFile(knownHosts, '192.0.2.4 ssh-ed25519 AAAA\n', { mode: 0o600 });
    let invocation;
    const transport = new SshDeploymentTransport({ knownHostsFile: knownHosts, runner: async (binary, argv, options) => {
      invocation = { binary, argv, options };
      return { code: 0, stdout: 'Linux\nx86_64\n0123456789abcdef0123456789abcdef\n', stderr: '' };
    } });
    await assert.rejects(() => transport.probe({ user: 'root', address: '192.0.2.4', deploymentAuthorized: false }), /does not authorize/);
    await transport.probe({ user: 'root', address: '192.0.2.4', deploymentAuthorized: true });
    assert.ok(invocation.argv.includes('StrictHostKeyChecking=yes'));
    assert.ok(invocation.argv.includes('PasswordAuthentication=no'));
    assert.ok(invocation.argv.includes('ForwardAgent=no'));
    assert.equal(invocation.argv.some((arg) => arg.includes('accept-new') || arg.includes('StrictHostKeyChecking=no')), false);
  } finally { await fs.rm(directory, { recursive: true, force: true }); }
});

test('remote command quoting cannot create extra shell arguments', () => {
  assert.equal(quoteRemote("a'; touch /tmp/pwned; '"), `'a'"'"'; touch /tmp/pwned; '"'"''`);
});

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { TailscaleLogSource } = require('../src/collector/tailscale-log-source');

function networkRecord(logged, destination = '100.64.0.2:443') {
  return {
    nodeId: 'node-a', logged, start: logged, end: logged,
    srcNode: { nodeId: 'node-a', addresses: ['100.64.0.1'], os: 'linux' },
    dstNodes: [{ nodeId: 'node-b', addresses: ['100.64.0.2'] }],
    virtualTraffic: [{ proto: 6, src: '100.64.0.1:50000', dst: destination, txPackets: 2, txBytes: 120, rxPackets: 1, rxBytes: 60 }]
  };
}

test('Tailscale source polls both APIs and yields normalized batches with durable mode cursors', async () => {
  const calls = [];
  const client = {
    async listNetworkLogs(tailnet, options) {
      calls.push({ type: 'network', tailnet, ...options });
      return [networkRecord('2026-08-18T12:00:01.000Z')];
    },
    async listConfigurationLogs(tailnet, options) {
      calls.push({ type: 'configuration', tailnet, ...options });
      return [{ eventTime: '2026-08-18T12:00:02.000Z', eventGroupID: 'audit-1', actor: { id: 'user-1', loginName: 'alice@example.test' }, action: 'UPDATE', target: { id: 'policy', type: 'ACL' }, origin: 'ADMIN_UI' }];
    }
  };
  const controller = new AbortController();
  const source = new TailscaleLogSource({ client, tailnet: 'example.test', pollIntervalMs: 10, initialLookbackMs: 10000, ingestionDelayMs: 0, maximumWindowMs: 10000, clock: () => new Date('2026-08-18T12:00:05.000Z') });
  assert.ok(source.capabilities().every((item) => item.status === 'unknown'));
  const iterator = source.events({ signal: controller.signal });
  const flow = (await iterator.next()).value;
  assert.equal(flow.events[0].class, 'network_activity');
  assert.equal(flow.events[0].attributes.packetsSent, 2);
  assert.deepEqual(flow.cursor.modes['network-flow'], { at: '2026-08-18T12:00:05.000Z', ids: [] });
  const audit = (await iterator.next()).value;
  assert.equal(audit.events[0].class, 'network_policy_activity');
  assert.equal(audit.events[0].time, '2026-08-18T12:00:02.000Z');
  assert.equal(audit.events[0].actor.id, 'user-1');
  assert.deepEqual(audit.cursor.modes['configuration-audit'], { at: '2026-08-18T12:00:05.000Z', ids: [] });
  assert.deepEqual(calls.map((call) => call.type), ['network', 'configuration']);
  assert.equal(calls[0].tailnet, 'example.test');
  assert.equal(calls[0].start, '2026-08-18T11:59:55.000Z');
  assert.ok(source.capabilities().every((item) => item.status === 'available'));
  controller.abort();
  await iterator.return();
});

test('Tailscale source reports API and plan failures as explicit coverage gaps', async () => {
  const source = new TailscaleLogSource({ client: { listNetworkLogs: async () => { throw new Error('forbidden'); } }, tailnet: 'example.test', modes: ['network-flow'], pollIntervalMs: 10, ingestionDelayMs: 0 });
  const controller = new AbortController();
  const iterator = source.events({ signal: controller.signal });
  await assert.rejects(() => iterator.next(), /forbidden/);
  assert.deepEqual(source.capabilities().map(({ capability, status }) => ({ capability, status })), [{ capability: 'network_flow', status: 'unavailable' }]);
});

test('Tailscale source resumes inclusively and filters records already committed at the cursor boundary', async () => {
  const first = networkRecord('2026-08-18T12:00:00.000Z', '100.64.0.2:443');
  const second = networkRecord('2026-08-18T12:00:00.000Z', '100.64.0.2:8443');
  const initialSource = new TailscaleLogSource({
    client: { listNetworkLogs: async () => [first, second] }, tailnet: 'example.test', modes: ['network-flow'],
    pollIntervalMs: 10, ingestionDelayMs: 0, maximumWindowMs: 10000, clock: () => new Date('2026-08-18T12:00:00.000Z')
  });
  const firstController = new AbortController();
  const initialIterator = initialSource.events({ signal: firstController.signal });
  const committed = (await initialIterator.next()).value;
  firstController.abort();
  await initialIterator.return();

  let request;
  const resumedSource = new TailscaleLogSource({
    client: { listNetworkLogs: async (_tailnet, options) => { request = options; return [first, second]; } }, tailnet: 'example.test', modes: ['network-flow'],
    pollIntervalMs: 10, ingestionDelayMs: 0, maximumWindowMs: 10000, clock: () => new Date('2026-08-18T12:00:00.000Z')
  });
  const resumedController = new AbortController();
  const resumedIterator = resumedSource.events({ signal: resumedController.signal, cursor: committed.cursor });
  const resumed = (await resumedIterator.next()).value;
  assert.equal(resumed.events[0].destinationEndpoint.port, 8443);
  assert.equal(request.start, '2026-08-18T12:00:00.000Z');
  assert.equal(resumed.cursor.modes['network-flow'].ids.length, 2);
  resumedController.abort();
  await resumedIterator.return();
});

test('Tailscale source rejects malformed durable cursors before making API requests', async () => {
  let called = false;
  const source = new TailscaleLogSource({ client: { listNetworkLogs: async () => { called = true; return []; } }, tailnet: 'example.test', modes: ['network-flow'], pollIntervalMs: 10 });
  const controller = new AbortController();
  const iterator = source.events({ signal: controller.signal, cursor: { schemaVersion: 1, modes: { 'network-flow': { at: 'nope', ids: [] } } } });
  await assert.rejects(() => iterator.next(), /cursor is invalid/);
  assert.equal(called, false);
});

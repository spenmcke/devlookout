'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { parseHuJson, TailscaleClient } = require('../src/adapters/tailscale-client');

test('HuJSON parser handles comments and trailing commas without evaluating code', () => {
  const policy = parseHuJson(`{
    // a policy comment
    "grants": [{ "src": ["user@example.com",], "dst": ["tag:server"], "ip": ["*"], },],
    /* another comment */ "tests": [],
    "url": "https://example.test/a//b",
  }`);
  assert.equal(policy.grants.length, 1);
  assert.equal(policy.url, 'https://example.test/a//b');
});

test('Tailscale client uses scoped authentication without exposing token in URL', async () => {
  const requests = [];
  const fetchImpl = async (url, options) => {
    requests.push({ url: String(url), options });
    return new Response(JSON.stringify({ devices: [] }), { status: 200, headers: { 'content-type': 'application/json' } });
  };
  const client = new TailscaleClient({ tokenProvider: async () => 'sensitive-token', baseUrl: 'https://api.example.test', fetchImpl });
  assert.deepEqual(await client.listDevices('tailnet/example'), { devices: [] });
  assert.ok(requests[0].options.headers.Authorization.startsWith('Basic '));
  assert.ok(!requests[0].url.includes('sensitive-token'));
  assert.ok(requests[0].url.includes('tailnet%2Fexample'));
});

test('Tailscale client requests bounded network and configuration log windows', async () => {
  const requests = [];
  const client = new TailscaleClient({
    tokenProvider: async () => 'token', baseUrl: 'https://api.example.test',
    fetchImpl: async (url) => { requests.push(new URL(url)); return new Response(JSON.stringify({ logs: [] }), { status: 200 }); }
  });
  const options = { start: '2026-08-18T12:00:00.000Z', end: '2026-08-18T12:01:00.000Z' };
  assert.deepEqual(await client.listNetworkLogs('tailnet/example', options), []);
  assert.deepEqual(await client.listConfigurationLogs('tailnet/example', options), []);
  assert.equal(requests[0].pathname, '/api/v2/tailnet/tailnet%2Fexample/logging/network');
  assert.equal(requests[1].pathname, '/api/v2/tailnet/tailnet%2Fexample/logging/configuration');
  assert.equal(requests[0].searchParams.get('start'), options.start);
  assert.equal(requests[0].searchParams.get('end'), options.end);
});

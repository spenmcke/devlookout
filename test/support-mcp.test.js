'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { once } = require('node:events');
const { Client, StreamableHTTPClientTransport } = require('@modelcontextprotocol/client');
const { InMemorySupportStore } = require('../src/support/conversation-store');
const { SupportAccessTokenAuthority } = require('../src/support/access-token-authority');
const { createSupportMcpHttpHandler } = require('../src/support/mcp-http');

test('authenticated Streamable HTTP MCP exposes exactly two tools and compatible structured output', async (t) => {
  const store = new InMemorySupportStore(); const authority = new SupportAccessTokenAuthority({ store });
  const created = await authority.create({ tenantId: 'tenant', userId: 'user', email: 'a@example.test', name: 'test' });
  let modelCalls = 0;
  const supportAgent = {
    ask: async () => { modelCalls += 1; return { request_id: 'srq_test', conversation_id: `scv_${'a'.repeat(32)}`, support_notification: { status: 'queued' }, summary: 'ok', likely_causes: [], next_steps: [], needs_more_information: [], sources: [], escalation: { recommended: false, reason: null }, limitations: [] }; },
    check: async () => ({ conversation_id: `scv_${'a'.repeat(32)}`, status: 'open', messages: [], next_after_message_id: null })
  };
  const handler = createSupportMcpHttpHandler({ tokenAuthority: authority, supportAgent });
  const server = http.createServer(async (req, res) => { const handled = await handler(req, res, new URL(req.url, 'http://localhost')); if (!handled) res.writeHead(404).end(); });
  server.listen(0, '127.0.0.1'); await once(server, 'listening'); t.after(() => server.close());
  const endpoint = `http://127.0.0.1:${server.address().port}/support/mcp`;
  const unauthorized = await fetch(endpoint, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
  assert.equal(unauthorized.status, 401); assert.equal(unauthorized.headers.get('www-authenticate'), 'Bearer');
  const transport = new StreamableHTTPClientTransport(new URL(endpoint), { requestInit: { headers: { Authorization: `Bearer ${created.token}` } } });
  const client = new Client({ name: 'lookout-test', version: '1.0.0' }); t.after(() => client.close());
  await client.connect(transport);
  const tools = (await client.listTools()).tools;
  assert.deepEqual(tools.map((tool) => tool.name), ['ask_lookout_support', 'check_lookout_support']);
  assert.equal(tools[0].annotations.readOnlyHint, false); assert.equal(tools[1].annotations.readOnlyHint, true);
  const called = await client.callTool({ name: 'ask_lookout_support', arguments: { client_request_id: 'request_123456789', question: 'Help' } });
  assert.equal(called.structuredContent.summary, 'ok'); assert.equal(called.content[0].type, 'text'); assert.equal(modelCalls, 1);
  const checked = await client.callTool({ name: 'check_lookout_support', arguments: { conversation_id: `scv_${'a'.repeat(32)}` } });
  assert.equal(checked.structuredContent.status, 'open'); assert.equal(modelCalls, 1);
  const invalid = await client.callTool({ name: 'ask_lookout_support', arguments: { question: 'missing id' } });
  assert.equal(invalid.isError, true); assert.equal(modelCalls, 1);
  const missing = await fetch(`${endpoint}/other`, { headers: { Authorization: `Bearer ${created.token}` } }); assert.equal(missing.status, 404);
  const unsupported = await fetch(endpoint, { method: 'PATCH', headers: { Authorization: `Bearer ${created.token}` } }); assert.equal(unsupported.status, 405);
});

test('configured route returns bounded 503 before MCP parsing when the agent is unavailable', async (t) => {
  const store = new InMemorySupportStore(); const authority = new SupportAccessTokenAuthority({ store });
  const created = await authority.create({ tenantId: 'tenant', userId: 'user', email: 'a@example.test', name: 'test' });
  const handler = createSupportMcpHttpHandler({ tokenAuthority: authority, supportAgent: null });
  const server = http.createServer((req, res) => handler(req, res, new URL(req.url, 'http://localhost')));
  server.listen(0, '127.0.0.1'); await once(server, 'listening'); t.after(() => server.close());
  const response = await fetch(`http://127.0.0.1:${server.address().port}/support/mcp`, { method: 'POST', headers: { Authorization: `Bearer ${created.token}`, 'Content-Type': 'application/json' }, body: '{invalid' });
  assert.equal(response.status, 503);
  assert.deepEqual(await response.json(), { error: 'unavailable' });
});

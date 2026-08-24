'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { InMemorySupportStore } = require('../src/support/conversation-store');
const { SupportAccessTokenAuthority } = require('../src/support/access-token-authority');
const { SupportRateLimiter } = require('../src/support/rate-limiter');
const { LookoutSupportAgent } = require('../src/support/support-agent');
const { OpenAIResponsesClient } = require('../src/support/openai-responses-client');

const validAnswer = () => ({ summary: 'Connected is progress, not completion.', likely_causes: [{ cause: 'Validation is still running.', confidence: 'medium', evidence: ['The supplied status is Connected.'] }], next_steps: [{ action: 'Keep the installer attached.', expected_result: 'Setup reaches complete.', safety_note: null }], needs_more_information: [], sources: [{ title: 'Install Lookout', url: 'https://docs.devlookout.com/install' }], escalation: { recommended: false, reason: null }, limitations: [] });

async function fixture(overrides = {}) {
  let now = Date.parse('2026-08-22T00:00:00.000Z');
  const store = new InMemorySupportStore({ clock: () => now });
  const authority = new SupportAccessTokenAuthority({ store, clock: () => now });
  const created = await authority.create({ tenantId: 'tenant', userId: 'user', email: 'owner@example.test', name: 'Codex' });
  const principal = await authority.authenticate(created.token);
  let modelCalls = 0; let docsCalls = 0;
  const agent = new LookoutSupportAgent({
    store, clock: () => now, limiter: new SupportRateLimiter({ clock: () => now, ...overrides.limits }),
    docsRetriever: { retrieve: async () => { docsCalls += 1; return [{ title: 'Install Lookout', url: 'https://docs.devlookout.com/install', markdown: '# Install\nConnected is progress.' }]; } },
    modelClient: { generate: async (request) => { modelCalls += 1; assert.equal(request.references.length, 1); assert.match(request.safetyIdentifier, /^[a-f0-9]{64}$/); return { result: validAnswer(), usage: { totalTokens: 12 } }; } }
  });
  return { store, principal, agent, counts: () => ({ modelCalls, docsCalls }), advance: (value) => { now += value; } };
}

test('support agent completes, persists, queues email, and exact replay is idempotent', async () => {
  const { store, principal, agent, counts } = await fixture();
  const input = { client_request_id: 'request_123456789', question: 'What does Connected mean?' };
  const first = await agent.ask(principal, input);
  const replay = await agent.ask(principal, input);
  assert.deepEqual(replay, first);
  assert.equal(counts().modelCalls, 1);
  assert.equal(store.conversations.size, 1);
  assert.equal(store.messages.get(first.conversation_id).length, 2);
  assert.equal(store.outbox.size, 1);
  await assert.rejects(() => agent.ask(principal, { ...input, question: 'Different question' }), (error) => error.status === 409);
});

test('high-confidence secrets are removed and blocked before model and docs calls', async () => {
  const { store, principal, agent, counts } = await fixture();
  const secret = `lsp_${'z'.repeat(43)}`;
  const result = await agent.ask(principal, { client_request_id: 'blocked_12345678', question: `Why failed ${secret}?` });
  assert.deepEqual(counts(), { modelCalls: 0, docsCalls: 0 });
  assert.equal(store.conversations.size, 1);
  assert.doesNotMatch(JSON.stringify([...store.messages.values(), ...store.outbox.values()]), new RegExp(secret));
  assert.match(result.summary, /blocked before Support AI/);
});

test('support agent filters fabricated citations and lowers confidence', async () => {
  const { principal, store } = await fixture();
  const agent = new LookoutSupportAgent({ store, limiter: new SupportRateLimiter(), docsRetriever: { retrieve: async () => [{ title: 'Install Lookout', url: 'https://docs.devlookout.com/install', markdown: 'x' }] }, modelClient: { generate: async () => ({ result: { ...validAnswer(), sources: [{ title: 'Fake', url: 'https://evil.example/page' }] } }) } });
  const result = await agent.ask(principal, { client_request_id: 'citation_1234567', question: 'Help' });
  assert.deepEqual(result.sources, []);
  assert.equal(result.likely_causes[0].confidence, 'low');
  assert.match(result.limitations.join(' '), /No retrieved Lookout Documentation/);
});

test('concurrent exact duplicates generate once and follow-up stays in the same email thread', async () => {
  let releaseDocs;
  const pendingDocs = new Promise((resolve) => { releaseDocs = resolve; });
  const { store, principal, agent, counts } = await fixture();
  const originalRetrieve = agent.docsRetriever.retrieve;
  agent.docsRetriever.retrieve = async (...args) => { await pendingDocs; return originalRetrieve(...args); };
  const input = { client_request_id: 'concurrent_12345', question: 'Why is setup waiting?' };
  const firstPromise = agent.ask(principal, input);
  await new Promise((resolve) => setImmediate(resolve));
  await assert.rejects(() => agent.ask(principal, input), (error) => error.status === 409);
  releaseDocs();
  const first = await firstPromise;
  assert.equal(counts().modelCalls, 1);
  store.conversations.get(first.conversation_id).rfcMessageId = '<first@reply.example.test>';
  const second = await agent.ask(principal, { client_request_id: 'followup_1234567', conversation_id: first.conversation_id, question: 'What should I check next?' });
  assert.equal(second.conversation_id, first.conversation_id);
  assert.equal(store.messages.get(first.conversation_id).length, 4);
  assert.equal(store.outbox.size, 2);
  assert.equal([...store.outbox.values()].at(-1).payload.threadRfcMessageId, '<first@reply.example.test>');
});

test('check returns ordered staff replies only to the owning principal without model work', async () => {
  const { store, principal, agent, counts } = await fixture();
  const asked = await agent.ask(principal, { client_request_id: 'check_owner_12345', question: 'Help' });
  await store.appendStaffReply({ providerEventId: 'event-1', providerMessageId: 'message-1', conversationId: asked.conversation_id, text: 'First reply', now: '2026-08-22T00:00:01.000Z' });
  await store.appendStaffReply({ providerEventId: 'event-2', providerMessageId: 'message-2', conversationId: asked.conversation_id, text: 'Second reply', now: '2026-08-22T00:00:02.000Z' });
  const checked = await agent.check(principal, { conversation_id: asked.conversation_id, limit: 1 });
  assert.deepEqual(checked.messages.map((item) => item.text), ['First reply']);
  const after = await agent.check(principal, { conversation_id: asked.conversation_id, after_message_id: checked.next_after_message_id });
  assert.deepEqual(after.messages.map((item) => item.text), ['Second reply']);
  assert.equal(counts().modelCalls, 1);
  await assert.rejects(() => agent.check({ ...principal, tenantId: 'other' }, { conversation_id: asked.conversation_id }), (error) => error.status === 404);
});

test('documentation outage is bounded and rolling limits release rejected reservations', async () => {
  const { store, principal, agent, advance } = await fixture({ limits: { hourlyLimit: 1 } });
  agent.docsRetriever.retrieve = async () => { throw new Error('private upstream detail'); };
  agent.modelClient.generate = async () => ({ result: validAnswer(), usage: { totalTokens: 4 } });
  const first = await agent.ask(principal, { client_request_id: 'outage_123456789', question: 'Help' });
  assert.match(first.limitations.join(' '), /retrieval was unavailable/);
  assert.deepEqual(first.sources, []);
  const secondInput = { client_request_id: 'limited_12345678', question: 'Another question' };
  await assert.rejects(() => agent.ask(principal, secondInput), (error) => error.status === 429);
  advance(60 * 60 * 1000 + 1);
  await agent.ask(principal, secondInput);
  assert.equal(store.conversations.size, 2);
});

test('invalid structured model output is never persisted and is safely retryable', async () => {
  const { store, principal, agent } = await fixture();
  agent.modelClient.generate = async () => ({ result: { ...validAnswer(), unexpected: true } });
  const input = { client_request_id: 'invalid_12345678', question: 'Help' };
  await assert.rejects(() => agent.ask(principal, input), (error) => error.status === 503 && !/unexpected/.test(error.message));
  assert.equal(store.conversations.size, 0);
  assert.equal(store.messages.size, 0);
  await assert.rejects(() => agent.ask(principal, input), (error) => error.status === 503);
});

test('Responses API adapter sends structured output with store false and no tools', async () => {
  let captured;
  const client = new OpenAIResponsesClient({ apiKey: 'test-key', model: 'configured-model', fetchImpl: async (_url, options) => {
    captured = JSON.parse(options.body);
    return new Response(JSON.stringify({ output_text: JSON.stringify(validAnswer()), usage: { total_tokens: 9 } }), { status: 200, headers: { 'Content-Type': 'application/json' } });
  } });
  const generated = await client.generate({ input: { question: 'help' }, references: [], safetyIdentifier: 'a'.repeat(64) });
  assert.equal(captured.store, false);
  assert.equal(captured.model, 'configured-model');
  assert.equal(Object.hasOwn(captured, 'tools'), false);
  assert.equal(captured.safety_identifier, 'a'.repeat(64));
  assert.equal(captured.text.format.type, 'json_schema');
  assert.equal(generated.result.summary, validAnswer().summary);
});

test('Responses API adapter maps upstream details to a generic failure', async () => {
  const client = new OpenAIResponsesClient({ apiKey: 'test-key', model: 'secret-model-name', fetchImpl: async () => new Response('provider stack and secret-model-name', { status: 500 }) });
  await assert.rejects(() => client.generate({ input: { question: 'help' }, references: [], safetyIdentifier: 'a'.repeat(64) }), (error) => error.message === 'Support inference is unavailable' && !error.message.includes('secret-model-name'));
});

test('generation limiter enforces token, global, daily, and check capacity', () => {
  let now = 0;
  const capacity = new SupportRateLimiter({ clock: () => now, hourlyLimit: 10, dailyLimit: 10, checkHourlyLimit: 1, globalConcurrency: 2, tokenConcurrency: 1 });
  const releaseA = capacity.acquireGeneration('token-a');
  assert.throws(() => capacity.acquireGeneration('token-a'), (error) => error.status === 429 && error.retryAfter > 0);
  const releaseB = capacity.acquireGeneration('token-b');
  assert.throws(() => capacity.acquireGeneration('token-c'), (error) => error.status === 429);
  releaseA(); releaseB();
  const rolling = new SupportRateLimiter({ clock: () => now, hourlyLimit: 2, dailyLimit: 2, checkHourlyLimit: 1 });
  rolling.acquireGeneration('token-a')(); rolling.acquireGeneration('token-a')();
  assert.throws(() => rolling.acquireGeneration('token-a'), (error) => error.status === 429);
  rolling.recordCheck('token-a');
  assert.throws(() => rolling.recordCheck('token-a'), (error) => error.status === 429);
  now += 24 * 60 * 60 * 1000 + 1;
  rolling.acquireGeneration('token-a')();
  rolling.recordCheck('token-a');
});

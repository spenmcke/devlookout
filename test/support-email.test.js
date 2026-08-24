'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { Readable } = require('node:stream');
const { Webhook } = require('svix');
const { InMemorySupportStore } = require('../src/support/conversation-store');
const { createSupportReplyAddress, validateSupportReplyAddress, formatSupportEmail, SUPPORT_REPLY_MARKER } = require('../src/support/email-notifier');
const { SupportEmailOutboxWorker } = require('../src/support/email-outbox');
const { createResendInboundHandler, extractSupportEmailReply } = require('../src/support/resend-inbound');

function response() { return { status: 0, body: '', writeHead(status) { this.status = status; }, end(body) { this.body = String(body || ''); } }; }
function request(payload, headers) { const req = Readable.from([Buffer.from(payload)]); req.method = 'POST'; req.url = '/v1/support/email/resend'; req.headers = { ...headers, 'content-length': String(Buffer.byteLength(payload)) }; return req; }

test('reply addresses use constant-time-verifiable 59-character local parts', () => {
  const conversationId = `scv_${'a'.repeat(32)}`; const address = createSupportReplyAddress(conversationId, 'reply.example.test', 'secret-value');
  assert.equal(address.split('@')[0].length, 59);
  assert.equal(validateSupportReplyAddress(address, 'reply.example.test', 'secret-value'), conversationId);
  assert.equal(validateSupportReplyAddress(address.replace(/.$/, 'x'), 'reply.example.test', 'secret-value'), null);
  const body = formatSupportEmail({ accountEmail: 'a@example.test', conversationId, requestId: 'request', createdAt: '2026-08-22T00:00:00.000Z', customerText: 'redacted', result: { sources: [] } });
  assert.match(body, new RegExp(SUPPORT_REPLY_MARKER));
  assert.match(body, /Submitted: 2026-08-22T00:00:00.000Z/);
});

test('email outbox retries temporary delivery failure without losing notification', async () => {
  let now = Date.parse('2026-08-22T00:00:00Z'); const store = new InMemorySupportStore({ clock: () => now });
  store.outbox.set('seo_test', { outboxId: 'seo_test', conversationId: `scv_${'a'.repeat(32)}`, requestId: 'srq_test', idempotencyKey: 'support:test', payload: {}, status: 'pending', attempts: 0, nextAttemptAt: new Date(now).toISOString(), createdAt: new Date(now).toISOString() });
  let calls = 0; const worker = new SupportEmailOutboxWorker({ store, clock: () => now, notifier: { send: async () => { calls += 1; if (calls === 1) throw new Error('temporary'); return { providerMessageId: 'email-1', rfcMessageId: '<one@example.test>' }; } } });
  await worker.sweep(); assert.equal(store.outbox.get('seo_test').status, 'pending');
  now = Date.parse(store.outbox.get('seo_test').nextAttemptAt); await worker.sweep();
  assert.equal(store.outbox.get('seo_test').status, 'delivered'); assert.equal(calls, 2);
});

test('email outbox reclaims a stale delivery after a worker crash', async () => {
  let now = Date.parse('2026-08-22T00:10:00Z'); const store = new InMemorySupportStore({ clock: () => now });
  store.outbox.set('seo_stale', { outboxId: 'seo_stale', conversationId: `scv_${'a'.repeat(32)}`, requestId: 'srq_test', idempotencyKey: 'support:stale', payload: {}, status: 'delivering', attempts: 1, nextAttemptAt: new Date(now - 600000).toISOString(), createdAt: new Date(now - 600000).toISOString(), updatedAt: new Date(now - 600000).toISOString() });
  let delivered = 0; const worker = new SupportEmailOutboxWorker({ store, clock: () => now, notifier: { send: async () => { delivered += 1; return {}; } } });
  await worker.sweep();
  assert.equal(delivered, 1); assert.equal(store.outbox.get('seo_stale').status, 'delivered');
});

test('signed Resend inbound stores only allowlisted plain text above marker and deduplicates', async () => {
  const secret = `whsec_${Buffer.alloc(32, 3).toString('base64')}`; const webhook = new Webhook(secret);
  const store = new InMemorySupportStore(); const conversationId = `scv_${'b'.repeat(32)}`;
  store.conversations.set(conversationId, { conversationId, tenantId: 'tenant', userId: 'user', accountEmail: 'a@example.test', status: 'waiting_on_lookout', createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 100000).toISOString() }); store.messages.set(conversationId, []);
  const replyAddress = createSupportReplyAddress(conversationId, 'reply.example.test', 'reply-secret');
  const handler = createResendInboundHandler({ store, apiKey: 'resend-key', webhookSecret: secret, staffEmails: ['staff@example.test'], replyDomain: 'reply.example.test', replySigningSecret: 'reply-secret', fetchImpl: async () => new Response(JSON.stringify({ from: 'Staff <staff@example.test>', to: [replyAddress], text: `Try the documented retry.\n\n${SUPPORT_REPLY_MARKER}\nquoted`, attachments: [], headers: {}, message_id: '<staff-1@example.test>' }), { status: 200, headers: { 'Content-Type': 'application/json' } }) });
  const payload = JSON.stringify({ type: 'email.received', data: { email_id: 'received-1' } }); const id = 'msg_test'; const timestamp = new Date(); const signature = webhook.sign(id, timestamp, payload); const headers = { 'svix-id': id, 'svix-timestamp': String(Math.floor(timestamp.valueOf() / 1000)), 'svix-signature': signature };
  const first = response(); assert.equal(await handler(request(payload, headers), first, new URL('https://app.devlookout.com/v1/support/email/resend')), true); assert.equal(first.status, 200);
  const second = response(); await handler(request(payload, headers), second, new URL('https://app.devlookout.com/v1/support/email/resend')); assert.equal(second.status, 200);
  assert.equal(store.messages.get(conversationId).length, 1); assert.equal(store.messages.get(conversationId)[0].text, 'Try the documented retry.');
  assert.equal(extractSupportEmailReply(`New answer\nOn yesterday someone wrote:\n> old`), 'New answer');
});

test('Resend inbound rejects invalid signatures before retrieving email content', async () => {
  const secret = `whsec_${Buffer.alloc(32, 4).toString('base64')}`; let fetchCalls = 0;
  const handler = createResendInboundHandler({ store: new InMemorySupportStore(), apiKey: 'key', webhookSecret: secret, staffEmails: ['staff@example.test'], replyDomain: 'reply.example.test', replySigningSecret: 'reply-secret', fetchImpl: async () => { fetchCalls += 1; return new Response('{}'); } });
  const payload = JSON.stringify({ type: 'email.received', data: { email_id: 'one' } });
  const res = response(); await handler(request(payload, { 'svix-id': 'bad', 'svix-timestamp': '1', 'svix-signature': 'v1,bad' }), res, new URL('https://app.devlookout.com/v1/support/email/resend'));
  assert.equal(res.status, 400); assert.equal(fetchCalls, 0);
});

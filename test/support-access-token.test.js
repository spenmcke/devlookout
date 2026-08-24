'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { InMemorySupportStore } = require('../src/support/conversation-store');
const { SupportAccessTokenAuthority, digestSupportToken } = require('../src/support/access-token-authority');
const { DataProtector } = require('../src/security/data-protector');

test('account support token is stable, encrypted, permanent, and isolated by account', async () => {
  const store = new InMemorySupportStore();
  const protector = new DataProtector(Buffer.alloc(32, 9));
  const authority = new SupportAccessTokenAuthority({ store, protector });
  const owner = { tenantId: 'tenant-a', userId: 'user-a', email: 'owner@example.test' };
  const first = await authority.accountToken(owner);
  const second = await authority.accountToken(owner);
  assert.equal(second.token, first.token);
  assert.equal(first.metadata.expires_at, '9999-12-31T23:59:59.999Z');
  const stored = store.tokens.get(first.metadata.id);
  assert.equal(stored.accountToken, true);
  assert.equal(stored.digest, digestSupportToken(first.token));
  assert.doesNotMatch(JSON.stringify(stored), new RegExp(first.token));
  assert.equal((await authority.authenticate(first.token)).tenantId, owner.tenantId);
  const other = await authority.accountToken({ tenantId: 'tenant-b', userId: 'user-b', email: 'other@example.test' });
  assert.notEqual(other.token, first.token);
});

test('support access tokens are one-time, isolated, bounded, revocable, and touch at most hourly', async () => {
  let now = Date.parse('2026-08-22T00:00:00.000Z');
  const store = new InMemorySupportStore({ clock: () => now });
  const authority = new SupportAccessTokenAuthority({ store, clock: () => now });
  const owner = { tenantId: 'tenant-a', userId: 'user-a', email: 'owner@example.test' };
  const created = await authority.create({ ...owner, name: ' Codex on MacBook ' });
  assert.match(created.token, /^lsp_[A-Za-z0-9_-]{43}$/);
  assert.match(created.metadata.id, /^sat_[A-Za-z0-9_-]{32}$/);
  assert.equal(created.metadata.name, 'Codex on MacBook');
  const stored = store.tokens.get(created.metadata.id);
  assert.equal(stored.digest, digestSupportToken(created.token));
  assert.doesNotMatch(JSON.stringify(stored), /lsp_/);
  assert.equal((await authority.list({ tenantId: 'tenant-b', userId: 'user-a' })).length, 0);
  assert.equal((await authority.authenticate(created.token)).tenantId, owner.tenantId);
  const firstUse = store.tokens.get(created.metadata.id).lastUsedAt;
  now += 30 * 60 * 1000;
  await authority.authenticate(created.token);
  assert.equal(store.tokens.get(created.metadata.id).lastUsedAt, firstUse);
  now += 31 * 60 * 1000;
  await authority.authenticate(created.token);
  assert.notEqual(store.tokens.get(created.metadata.id).lastUsedAt, firstUse);
  await assert.rejects(() => authority.revoke({ tenantId: 'tenant-b', userId: 'user-a' }, created.metadata.id), (error) => error.status === 404);
  await authority.revoke(owner, created.metadata.id);
  assert.equal(await authority.authenticate(created.token), null);
  for (let index = 0; index < 5; index += 1) await authority.create({ ...owner, name: `Agent ${index}` });
  await assert.rejects(() => authority.create({ ...owner, name: 'Too many' }), (error) => error.status === 409);
  await store.deleteTenantSupport(owner.tenantId);
  assert.equal((await authority.list(owner)).length, 0);
});

test('support token concurrent creation preserves the five-token limit', async () => {
  const store = new InMemorySupportStore(); const authority = new SupportAccessTokenAuthority({ store });
  const principal = { tenantId: 'tenant', userId: 'user', email: 'a@example.test' };
  const results = await Promise.allSettled(Array.from({ length: 8 }, (_, index) => authority.create({ ...principal, name: `Token ${index}` })));
  assert.equal(results.filter((item) => item.status === 'fulfilled').length, 5);
  assert.equal(results.filter((item) => item.status === 'rejected' && item.reason.status === 409).length, 3);
});

test('support token authentication fails when the atomic active-token touch loses revocation', async () => {
  const store = new InMemorySupportStore(); const authority = new SupportAccessTokenAuthority({ store });
  const created = await authority.create({ tenantId: 'tenant', userId: 'user', email: 'a@example.test', name: 'Token' });
  store.touchTokenAtomic = async () => false;
  assert.equal(await authority.authenticate(created.token), null);
});

test('support expiry and tenant deletion remove conversations, messages, outbox, and tokens', async () => {
  let now = Date.parse('2026-08-22T00:00:00.000Z');
  const store = new InMemorySupportStore({ clock: () => now, retentionDays: 1 });
  const authority = new SupportAccessTokenAuthority({ store, clock: () => now });
  const created = await authority.create({ tenantId: 'tenant', userId: 'user', email: 'a@example.test', name: 'Token' });
  const principal = await authority.authenticate(created.token);
  const reservation = await store.reserveRequest({ supportTokenId: principal.tokenId, clientRequestId: 'retention_123456', requestHash: 'a'.repeat(64), now: new Date(now).toISOString(), leaseMs: 1000 });
  const completed = await store.completeRequest({ principal, clientRequestId: 'retention_123456', requestHash: 'a'.repeat(64), requestId: reservation.requestId, conversationId: null, customerText: '{}', result: { sources: [] }, now: new Date(now).toISOString(), outboxPayload: {} });
  now += 24 * 60 * 60 * 1000 + 1;
  assert.equal(await store.deleteExpired({ now: new Date(now).toISOString() }), 1);
  assert.equal(store.conversations.has(completed.conversation_id), false);
  assert.equal(store.messages.has(completed.conversation_id), false);
  assert.equal(store.outbox.size, 0);
  await store.deleteTenantSupport('tenant');
  assert.equal(store.tokens.size, 0);
});

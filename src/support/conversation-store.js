'use strict';

const crypto = require('node:crypto');

function supportId(prefix, randomBytes = crypto.randomBytes) { return `${prefix}_${randomBytes(24).toString('base64url')}`; }
function clone(value) { return value === undefined ? undefined : structuredClone(value); }

class InMemorySupportStore {
  constructor({ clock = () => Date.now(), randomBytes = crypto.randomBytes, retentionDays = 90 } = {}) {
    this.clock = clock; this.randomBytes = randomBytes; this.retentionDays = retentionDays;
    this.tokens = new Map(); this.requests = new Map(); this.conversations = new Map(); this.messages = new Map(); this.outbox = new Map(); this.inboundEvents = new Map();
  }

  async createTokenAtomic(record) {
    const active = [...this.tokens.values()].filter((item) => item.tenantId === record.tenantId && item.userId === record.userId && !item.revokedAt && Date.parse(item.expiresAt) > Date.parse(record.createdAt));
    if (active.length >= 5) throw Object.assign(new Error('Maximum active support tokens reached'), { status: 409 });
    if ([...this.tokens.values()].some((item) => item.digest === record.digest)) throw Object.assign(new Error('Support token conflict'), { status: 409 });
    this.tokens.set(record.tokenId, { ...clone(record), lastUsedAt: null, revokedAt: null });
    return clone(this.tokens.get(record.tokenId));
  }

  async getOrCreateAccountTokenAtomic(record) {
    const existing = [...this.tokens.values()].find((item) => item.tenantId === record.tenantId && item.userId === record.userId && item.accountToken && !item.revokedAt && Date.parse(item.expiresAt) > Date.parse(record.createdAt));
    if (existing) return clone(existing);
    if ([...this.tokens.values()].some((item) => item.digest === record.digest)) throw Object.assign(new Error('Support token conflict'), { status: 409 });
    this.tokens.set(record.tokenId, { ...clone(record), lastUsedAt: null, revokedAt: null });
    return clone(this.tokens.get(record.tokenId));
  }

  async listTokens({ tenantId, userId }) {
    const recent = this.clock() - 30 * 24 * 60 * 60 * 1000;
    return [...this.tokens.values()].filter((item) => item.tenantId === tenantId && item.userId === userId && (Date.parse(item.expiresAt) > recent || Date.parse(item.revokedAt || 0) > recent)).sort((a, b) => b.createdAt.localeCompare(a.createdAt)).map(clone);
  }

  async revokeTokenAtomic({ tenantId, userId, tokenId, now }) {
    const item = this.tokens.get(tokenId);
    if (!item || item.tenantId !== tenantId || item.userId !== userId) return null;
    if (!item.revokedAt) item.revokedAt = now;
    return clone(item);
  }

  async authenticateTokenDigest({ digest, now }) {
    const item = [...this.tokens.values()].find((record) => record.digest === digest);
    if (!item || item.revokedAt || Date.parse(item.expiresAt) <= Date.parse(now)) return null;
    return clone(item);
  }

  async touchTokenAtomic({ tokenId, now, minimumIntervalMs }) {
    const item = this.tokens.get(tokenId);
    if (!item || item.revokedAt) return false;
    if (!item.lastUsedAt || Date.parse(now) - Date.parse(item.lastUsedAt) >= minimumIntervalMs) item.lastUsedAt = now;
    return true;
  }

  async authorizeConversation({ conversationId, tenantId, userId }) {
    const conversation = this.conversations.get(conversationId);
    return conversation && conversation.tenantId === tenantId && conversation.userId === userId && Date.parse(conversation.expiresAt) > this.clock() ? clone(conversation) : null;
  }

  async getConversationForInbound(conversationId) { const item = this.conversations.get(conversationId); return item && Date.parse(item.expiresAt) > this.clock() ? clone(item) : null; }

  async reserveRequest({ supportTokenId, clientRequestId, requestHash, now, leaseMs }) {
    const key = `${supportTokenId}\0${clientRequestId}`;
    const existing = this.requests.get(key);
    if (existing) {
      if (existing.requestHash !== requestHash) return { state: 'conflict' };
      if (existing.status === 'completed') return { state: 'completed', result: clone(existing.result) };
      if (existing.leaseExpiresAt && Date.parse(existing.leaseExpiresAt) > Date.parse(now)) return { state: 'processing' };
      existing.leaseExpiresAt = new Date(Date.parse(now) + leaseMs).toISOString();
      existing.updatedAt = now;
      return { state: 'acquired', requestId: existing.requestId };
    }
    const requestId = supportId('srq', this.randomBytes);
    this.requests.set(key, { requestId, supportTokenId, clientRequestId, requestHash, status: 'processing', leaseExpiresAt: new Date(Date.parse(now) + leaseMs).toISOString(), createdAt: now, updatedAt: now, result: null, conversationId: null });
    return { state: 'acquired', requestId };
  }

  async releaseRequest({ supportTokenId, clientRequestId, requestHash, now }) {
    const item = this.requests.get(`${supportTokenId}\0${clientRequestId}`);
    if (item && item.requestHash === requestHash && item.status === 'processing') { item.leaseExpiresAt = now; item.updatedAt = now; }
  }

  async completeRequest({ principal, clientRequestId, requestHash, requestId, conversationId, customerText, result, now, outboxPayload }) {
    const key = `${principal.tokenId}\0${clientRequestId}`;
    const request = this.requests.get(key);
    if (!request || request.requestId !== requestId || request.requestHash !== requestHash) throw Object.assign(new Error('Support request lease was lost'), { status: 409 });
    if (request.status === 'completed') return clone(request.result);
    let conversation = conversationId ? this.conversations.get(conversationId) : null;
    if (conversationId && (!conversation || conversation.tenantId !== principal.tenantId || conversation.userId !== principal.userId)) throw Object.assign(new Error('Support conversation was not found'), { status: 404 });
    if (!conversation) {
      conversationId = supportId('scv', this.randomBytes);
      conversation = { conversationId, tenantId: principal.tenantId, userId: principal.userId, accountEmail: principal.accountEmail, status: 'open', createdAt: now, updatedAt: now, expiresAt: this._expiry(now), providerMessageId: null, rfcMessageId: null };
      this.conversations.set(conversationId, conversation);
      this.messages.set(conversationId, []);
    }
    const customerId = supportId('scm', this.randomBytes);
    const assistantId = supportId('scm', this.randomBytes);
    const items = this.messages.get(conversationId) || [];
    items.push({ messageId: customerId, conversationId, role: 'customer', text: customerText, citations: [], createdAt: now, requestId });
    items.push({ messageId: assistantId, conversationId, role: 'assistant', text: JSON.stringify(result), citations: clone(result.sources || []), createdAt: new Date(Date.parse(now) + 1).toISOString(), requestId });
    this.messages.set(conversationId, items);
    conversation.status = 'waiting_on_lookout'; conversation.updatedAt = now; conversation.expiresAt = this._expiry(now);
    const completed = { ...clone(result), request_id: requestId, conversation_id: conversationId, support_notification: { status: 'queued' } };
    request.status = 'completed'; request.result = completed; request.conversationId = conversationId; request.leaseExpiresAt = null; request.updatedAt = now;
    const outboxId = supportId('seo', this.randomBytes);
    this.outbox.set(outboxId, { outboxId, conversationId, requestId, idempotencyKey: `support:${requestId}`, payload: { ...clone(outboxPayload), conversationId, requestId, createdAt: now, customerText, result: completed, threadRfcMessageId: conversation.rfcMessageId || null }, status: 'pending', attempts: 0, nextAttemptAt: now, providerMessageId: null, rfcMessageId: null, createdAt: now, updatedAt: now });
    return clone(completed);
  }

  async checkConversation({ conversationId, tenantId, userId, afterMessageId = null, limit = 20 }) {
    const conversation = await this.authorizeConversation({ conversationId, tenantId, userId });
    if (!conversation) return null;
    const staff = (this.messages.get(conversationId) || []).filter((item) => item.role === 'staff');
    const offset = afterMessageId ? staff.findIndex((item) => item.messageId === afterMessageId) + 1 : 0;
    const selected = staff.slice(Math.max(0, offset), Math.max(0, offset) + limit);
    return { conversation, messages: clone(selected), nextAfterMessageId: selected.length === limit ? selected.at(-1).messageId : null };
  }

  async claimEmailOutbox({ now, maximumAttempts = 10 }) {
    const staleDelivery = Date.parse(now) - 5 * 60 * 1000;
    for (const item of this.outbox.values()) if (item.status === 'delivering' && item.attempts >= maximumAttempts && Date.parse(item.updatedAt || item.createdAt) <= staleDelivery) { item.status = 'failed'; item.updatedAt = now; }
    const record = [...this.outbox.values()].filter((item) => item.attempts < maximumAttempts && ((item.status === 'pending' && Date.parse(item.nextAttemptAt) <= Date.parse(now)) || (item.status === 'delivering' && Date.parse(item.updatedAt || item.createdAt) <= staleDelivery))).sort((a, b) => a.nextAttemptAt.localeCompare(b.nextAttemptAt))[0];
    if (!record) return null;
    record.status = 'delivering'; record.attempts += 1; record.updatedAt = now;
    return clone(record);
  }

  async completeEmailOutbox({ outboxId, providerMessageId, rfcMessageId, now }) {
    const item = this.outbox.get(outboxId); if (!item) return;
    item.status = 'delivered'; item.providerMessageId = providerMessageId || null; item.rfcMessageId = rfcMessageId || null; item.updatedAt = now;
    const conversation = this.conversations.get(item.conversationId);
    if (conversation && !conversation.providerMessageId) { conversation.providerMessageId = providerMessageId || null; conversation.rfcMessageId = rfcMessageId || null; }
  }

  async failEmailOutbox({ outboxId, now, nextAttemptAt, maximumAttempts }) {
    const item = this.outbox.get(outboxId); if (!item) return;
    item.status = item.attempts >= maximumAttempts ? 'failed' : 'pending'; item.nextAttemptAt = nextAttemptAt; item.updatedAt = now;
  }

  async appendStaffReply({ providerEventId, providerMessageId, conversationId, text, now }) {
    if (this.inboundEvents.has(providerEventId) || [...this.inboundEvents.values()].some((item) => item.providerMessageId === providerMessageId)) return { duplicate: true };
    const conversation = this.conversations.get(conversationId); if (!conversation) return null;
    const message = { messageId: supportId('scm', this.randomBytes), conversationId, role: 'staff', text, citations: [], createdAt: now, requestId: null };
    (this.messages.get(conversationId) || []).push(message);
    this.inboundEvents.set(providerEventId, { providerMessageId, messageId: message.messageId });
    conversation.status = 'replied'; conversation.updatedAt = now; conversation.expiresAt = this._expiry(now);
    return { duplicate: false, message: clone(message) };
  }

  async deleteTenantSupport(tenantId) {
    const tokenIds = new Set([...this.tokens.values()].filter((item) => item.tenantId === tenantId).map((item) => item.tokenId));
    for (const [id, token] of this.tokens) if (token.tenantId === tenantId) this.tokens.delete(id);
    const conversationIds = new Set([...this.conversations.values()].filter((item) => item.tenantId === tenantId).map((item) => item.conversationId));
    for (const id of conversationIds) { this.conversations.delete(id); this.messages.delete(id); }
    for (const [key, request] of this.requests) if (tokenIds.has(request.supportTokenId) || conversationIds.has(request.conversationId)) this.requests.delete(key);
    for (const [id, item] of this.outbox) if (conversationIds.has(item.conversationId)) this.outbox.delete(id);
  }

  async deleteExpired({ now }) {
    const expired = [...this.conversations.values()].filter((item) => Date.parse(item.expiresAt) <= Date.parse(now)).map((item) => item.conversationId);
    for (const id of expired) { this.conversations.delete(id); this.messages.delete(id); for (const [outboxId, item] of this.outbox) if (item.conversationId === id) this.outbox.delete(outboxId); }
    return expired.length;
  }

  _expiry(now) { return new Date(Date.parse(now) + this.retentionDays * 24 * 60 * 60 * 1000).toISOString(); }
}

class SupabaseSupportStore {
  constructor({ supabaseUrl, serviceKey, fetchImpl = globalThis.fetch, timeoutMs = 10000, retentionDays = 90 } = {}) {
    const origin = new URL(supabaseUrl);
    if (origin.protocol !== 'https:' || origin.username || origin.password || origin.search || origin.hash) throw new Error('Supabase URL is invalid');
    if (!serviceKey) throw new Error('Supabase service key is required');
    this.origin = origin; this.serviceKey = serviceKey; this.fetch = fetchImpl; this.timeoutMs = timeoutMs; this.retentionDays = retentionDays;
  }

  async rpc(name, body) {
    let response;
    try {
      response = await this.fetch(new URL(`/rest/v1/rpc/${name}`, this.origin), { method: 'POST', redirect: 'error', signal: AbortSignal.timeout(this.timeoutMs), headers: { apikey: this.serviceKey, Authorization: `Bearer ${this.serviceKey}`, Accept: 'application/json', 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    } catch { throw Object.assign(new Error('Support storage is unavailable'), { status: 503 }); }
    const text = await response.text();
    if (!response.ok) {
      if (response.status === 409 || /maximum active/i.test(text)) throw Object.assign(new Error('Support storage conflict'), { status: 409 });
      throw Object.assign(new Error('Support storage is unavailable'), { status: 503 });
    }
    return text ? JSON.parse(text) : null;
  }

  createTokenAtomic(value) { return this.rpc('lookout_support_create_token', { p_record: value }); }
  getOrCreateAccountTokenAtomic(value) { return this.rpc('lookout_support_get_or_create_account_token', { p_record: value }); }
  listTokens(value) { return this.rpc('lookout_support_list_tokens', { p_tenant_id: value.tenantId, p_user_id: value.userId }); }
  revokeTokenAtomic(value) { return this.rpc('lookout_support_revoke_token', { p_tenant_id: value.tenantId, p_user_id: value.userId, p_token_id: value.tokenId, p_now: value.now }); }
  authenticateTokenDigest(value) { return this.rpc('lookout_support_authenticate_token', { p_digest: value.digest, p_now: value.now }); }
  touchTokenAtomic(value) { return this.rpc('lookout_support_touch_token', { p_token_id: value.tokenId, p_now: value.now }); }
  authorizeConversation(value) { return this.rpc('lookout_support_authorize_conversation', { p_conversation_id: value.conversationId, p_tenant_id: value.tenantId, p_user_id: value.userId }); }
  getConversationForInbound(conversationId) { return this.rpc('lookout_support_get_inbound_conversation', { p_conversation_id: conversationId }); }
  reserveRequest(value) { return this.rpc('lookout_support_reserve_request', { p_input: value }); }
  releaseRequest(value) { return this.rpc('lookout_support_release_request', { p_input: value }); }
  completeRequest(value) { return this.rpc('lookout_support_complete_request', { p_input: { ...value, retentionDays: this.retentionDays } }); }
  checkConversation(value) { return this.rpc('lookout_support_check_conversation', { p_input: value }); }
  claimEmailOutbox(value) { return this.rpc('lookout_support_claim_email', { p_input: value }); }
  completeEmailOutbox(value) { return this.rpc('lookout_support_complete_email', { p_input: value }); }
  failEmailOutbox(value) { return this.rpc('lookout_support_fail_email', { p_input: value }); }
  appendStaffReply(value) { return this.rpc('lookout_support_append_staff_reply', { p_input: { ...value, retentionDays: this.retentionDays } }); }
  deleteTenantSupport(tenantId) { return this.rpc('lookout_support_delete_tenant', { p_tenant_id: tenantId }); }
  deleteExpired(value) { return this.rpc('lookout_support_delete_expired', { p_now: value.now }); }
}

module.exports = { InMemorySupportStore, SupabaseSupportStore, createSupportId: supportId };

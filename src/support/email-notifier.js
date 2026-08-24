'use strict';

const crypto = require('node:crypto');

const REPLY_MARKER = '--- Reply above this line ---';

function replySignature(conversationId, secret) { return crypto.createHmac('sha256', secret).update(conversationId).digest().subarray(0, 16).toString('base64url'); }
function createReplyAddress(conversationId, domain, secret) {
  if (!/^scv_[A-Za-z0-9_-]{32}$/.test(conversationId) || !/^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$/.test(domain || '') || !secret) throw new Error('Support reply address configuration is invalid');
  const local = `${conversationId}.${replySignature(conversationId, secret)}`;
  if (local.length !== 59) throw new Error('Support reply address is invalid');
  return `${local}@${domain}`;
}
function validateReplyAddress(address, domain, secret) {
  const match = new RegExp(`^(scv_[A-Za-z0-9_-]{32})\\.([A-Za-z0-9_-]{22})@${String(domain).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, 'i').exec(address || '');
  if (!match) return null;
  const expected = Buffer.from(replySignature(match[1], secret)); const supplied = Buffer.from(match[2]);
  return expected.length === supplied.length && crypto.timingSafeEqual(expected, supplied) ? match[1] : null;
}
function formatSupportEmail(payload) {
  const sources = (payload.result.sources || []).map((source) => `- ${source.title}: ${source.url}`).join('\n') || '- No documentation citation';
  return `${REPLY_MARKER}\n\nAccount: ${payload.accountEmail}\nConversation: ${payload.conversationId}\nRequest: ${payload.requestId}\nSubmitted: ${payload.createdAt}\n\nRedacted customer message\n${payload.customerText}\n\nLookout Support AI answer\n${JSON.stringify(payload.result, null, 2)}\n\nCitations\n${sources}\n`;
}

class ResendSupportEmailNotifier {
  constructor({ apiKey, from, inbox, replyDomain, replySigningSecret, fetchImpl = globalThis.fetch, timeoutMs = 10000 } = {}) {
    if (![apiKey, from, inbox, replyDomain, replySigningSecret].every(Boolean)) throw new Error('Support email is not configured');
    this.apiKey = apiKey; this.from = from; this.inbox = inbox; this.replyDomain = replyDomain; this.replySigningSecret = replySigningSecret; this.fetch = fetchImpl; this.timeoutMs = timeoutMs;
  }
  async send(record) {
    const payload = record.payload; const replyTo = createReplyAddress(record.conversationId, this.replyDomain, this.replySigningSecret);
    const rfcMessageId = record.rfcMessageId || `<${record.requestId}@${this.replyDomain}>`;
    const headers = { 'Message-ID': rfcMessageId };
    if (payload.threadRfcMessageId) { headers['In-Reply-To'] = payload.threadRfcMessageId; headers.References = payload.threadRfcMessageId; }
    let response;
    try { response = await this.fetch('https://api.resend.com/emails', { method: 'POST', redirect: 'error', signal: AbortSignal.timeout(this.timeoutMs), headers: { Authorization: `Bearer ${this.apiKey}`, 'Content-Type': 'application/json', Accept: 'application/json', 'Idempotency-Key': record.idempotencyKey }, body: JSON.stringify({ from: this.from, to: [this.inbox], subject: `[Lookout Support ${record.conversationId}]`, text: formatSupportEmail(payload), reply_to: replyTo, headers }) }); }
    catch { throw new Error('Support email delivery failed'); }
    if (!response.ok) throw new Error('Support email delivery failed');
    const value = await response.json().catch(() => ({}));
    return { providerMessageId: typeof value.id === 'string' ? value.id : null, rfcMessageId };
  }
}

module.exports = { ResendSupportEmailNotifier, createSupportReplyAddress: createReplyAddress, validateSupportReplyAddress: validateReplyAddress, supportReplySignature: replySignature, formatSupportEmail, SUPPORT_REPLY_MARKER: REPLY_MARKER };

'use strict';

const { Webhook } = require('svix');
const { validateSupportReplyAddress, SUPPORT_REPLY_MARKER } = require('./email-notifier');

async function readRaw(req, maximumBytes = 64 * 1024) {
  const declared = req.headers?.['content-length']; if (declared !== undefined && (!/^\d+$/.test(declared) || Number(declared) > maximumBytes)) throw Object.assign(new Error('size'), { status: 413 });
  const chunks = []; let size = 0;
  for await (const chunk of req) { const bytes = Buffer.from(chunk); size += bytes.length; if (size > maximumBytes) throw Object.assign(new Error('size'), { status: 413 }); chunks.push(bytes); }
  return Buffer.concat(chunks, size);
}
function emailAddress(value) { return /<([^<>\s]+@[^<>\s]+)>/.exec(value || '')?.[1] || (/^[^\s@]+@[^\s@]+$/.test(value || '') ? value : null); }
function extractReply(text) {
  if (typeof text !== 'string' || Buffer.byteLength(text) > 16 * 1024) return null;
  let value = text.split(SUPPORT_REPLY_MARKER, 1)[0];
  value = value.split(/^On .{0,500}wrote:\s*$/im, 1)[0];
  value = value.split(/^From:\s*.{0,500}$/im, 1)[0];
  value = value.split(/^>+/m, 1)[0].trim();
  return value && value.length <= 8000 ? value : null;
}
async function boundedJsonResponse(response, maximumBytes = 64 * 1024) {
  if (!response.ok || !/^application\/json(?:;|$)/i.test(response.headers.get('content-type') || '')) throw new Error('Inbound email retrieval failed');
  const declared = response.headers.get('content-length');
  if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > maximumBytes)) throw new Error('Inbound email retrieval failed');
  const chunks = []; let size = 0;
  if (!response.body) throw new Error('Inbound email retrieval failed');
  for await (const chunk of response.body) {
    const bytes = Buffer.from(chunk); size += bytes.length;
    if (size > maximumBytes) throw new Error('Inbound email retrieval failed');
    chunks.push(bytes);
  }
  const text = Buffer.concat(chunks, size).toString('utf8');
  try { return JSON.parse(text); } catch { throw new Error('Inbound email retrieval failed'); }
}
function generic(res, status, value = { received: true }) { const body = Buffer.from(JSON.stringify(value)); res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': body.length, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' }); res.end(body); }
function emit(logger, record) { try { logger(record); } catch {} }

function createResendInboundHandler({ store, apiKey, webhookSecret, staffEmails, replyDomain, replySigningSecret, fetchImpl = globalThis.fetch, clock = () => Date.now(), logger = () => {} } = {}) {
  const allowlist = new Set((staffEmails || []).map((item) => item.trim().toLowerCase()).filter(Boolean));
  const verifier = webhookSecret ? new Webhook(webhookSecret) : null;
  return async function resendInbound(req, res, url) {
    if (url.pathname !== '/v1/support/email/resend') return false;
    if (url.search || url.hash || req.method !== 'POST' || !verifier || !apiKey) { generic(res, req.method === 'POST' ? 503 : 404, { error: 'unavailable' }); return true; }
    let raw; let event;
    try {
      raw = await readRaw(req);
      event = verifier.verify(raw.toString('utf8'), { 'svix-id': String(req.headers['svix-id'] || ''), 'svix-timestamp': String(req.headers['svix-timestamp'] || ''), 'svix-signature': String(req.headers['svix-signature'] || '') });
    } catch (error) { generic(res, error.status || 400, { error: 'bad_request' }); emit(logger, { event: 'lookout_support_inbound', outcome: 'invalid_signature' }); return true; }
    try {
      if (event.type !== 'email.received' || typeof event.data?.email_id !== 'string') throw new Error('event');
      const response = await fetchImpl(`https://api.resend.com/emails/receiving/${encodeURIComponent(event.data.email_id)}`, { method: 'GET', redirect: 'error', signal: AbortSignal.timeout(10000), headers: { Authorization: `Bearer ${apiKey}`, Accept: 'application/json' } });
      const email = await boundedJsonResponse(response);
      if ((email.attachments || []).length) throw new Error('attachments');
      const from = emailAddress(email.from); if (!from || !allowlist.has(from.toLowerCase())) throw new Error('sender');
      const headers = email.headers && typeof email.headers === 'object' ? email.headers : {};
      if (/auto|auto-replied/i.test(String(headers['auto-submitted'] || headers['x-autoreply'] || '')) || /bulk|junk|list/i.test(String(headers.precedence || ''))) throw new Error('automated');
      let conversationId = null;
      for (const recipient of email.to || []) { conversationId = validateSupportReplyAddress(emailAddress(recipient), replyDomain, replySigningSecret); if (conversationId) break; }
      const conversation = conversationId ? await store.getConversationForInbound(conversationId) : null;
      if (!conversation) throw new Error('conversation');
      const text = extractReply(email.text); if (!text) throw new Error('text');
      const appended = await store.appendStaffReply({ providerEventId: String(req.headers['svix-id']), providerMessageId: email.message_id || event.data.email_id, conversationId, text, now: new Date(clock()).toISOString() });
      if (!appended) throw new Error('conversation');
      generic(res, 200); emit(logger, { event: 'lookout_support_inbound', outcome: appended.duplicate ? 'duplicate' : 'accepted', firstReplyLatencyMs: appended.duplicate ? undefined : Math.max(0, clock() - Date.parse(conversation.createdAt)) });
    } catch (error) {
      const reason = ['event', 'attachments', 'sender', 'automated', 'conversation', 'text'].includes(error.message) ? error.message : 'retrieval';
      generic(res, 400, { error: 'bad_request' }); emit(logger, { event: 'lookout_support_inbound', outcome: 'rejected', reason });
    }
    return true;
  };
}

module.exports = { createResendInboundHandler, extractSupportEmailReply: extractReply, readRawSupportWebhook: readRaw, parseSupportEmailAddress: emailAddress };

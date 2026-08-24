'use strict';

const crypto = require('node:crypto');
const { redactSupportInput } = require('./redaction');

const CLIENT_REQUEST_ID = /^[A-Za-z0-9_-]{16,128}$/;
const CONVERSATION_ID = /^scv_[A-Za-z0-9_-]{32}$/;
const INSTALLATION_MODES = new Set(['hosted', 'fleet', 'single-host', 'source', 'unknown']);
const TOP_LEVEL_FIELDS = new Set(['client_request_id', 'conversation_id', 'question', 'context', 'attempted_steps', 'diagnostics']);
const CONTEXT_FIELDS = new Set(['lookout_version', 'installation_mode', 'platform', 'symptoms']);

function invalid(message = 'Support request is invalid', status = 400) { return Object.assign(new Error(message), { status }); }
function emit(logger, record) { try { logger(record); } catch {} }
function stringField(value, { required = false, maximum }) {
  if (value === undefined && !required) return;
  if (typeof value !== 'string' || (required && !value.length) || value.length > maximum) throw invalid();
}

function validateAskInput(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some((key) => !TOP_LEVEL_FIELDS.has(key))) throw invalid();
  if (!CLIENT_REQUEST_ID.test(value.client_request_id || '')) throw invalid();
  if (value.conversation_id !== undefined && !CONVERSATION_ID.test(value.conversation_id)) throw invalid();
  stringField(value.question, { required: true, maximum: 4000 });
  if (value.context !== undefined) {
    if (!value.context || typeof value.context !== 'object' || Array.isArray(value.context) || Object.keys(value.context).some((key) => !CONTEXT_FIELDS.has(key))) throw invalid();
    stringField(value.context.lookout_version, { maximum: 64 }); stringField(value.context.platform, { maximum: 128 }); stringField(value.context.symptoms, { maximum: 2000 });
    if (value.context.installation_mode !== undefined && !INSTALLATION_MODES.has(value.context.installation_mode)) throw invalid();
  }
  if (value.attempted_steps !== undefined && (!Array.isArray(value.attempted_steps) || value.attempted_steps.length > 10 || value.attempted_steps.some((item) => typeof item !== 'string' || item.length > 1000))) throw invalid();
  stringField(value.diagnostics, { maximum: 12000 });
  if (value.diagnostics && /^https?:\/\/\S+$/i.test(value.diagnostics.trim())) throw invalid();
  if (Buffer.byteLength(JSON.stringify(value)) > 24 * 1024) throw invalid('Support request is too large', 413);
  return structuredClone(value);
}

function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}

function validText(value, maximum = 3000) { return typeof value === 'string' && value.length > 0 && value.length <= maximum; }
function exactKeys(value, expected) { return value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === expected.length && expected.every((key) => Object.hasOwn(value, key)); }
function validateAnswer(value, references, retrievalFailure = null) {
  if (!exactKeys(value, ['summary', 'likely_causes', 'next_steps', 'needs_more_information', 'sources', 'escalation', 'limitations']) || !validText(value.summary)) throw invalid('Support inference returned invalid output', 503);
  const referenceMap = new Map(references.map((item) => [item.url, item.title]));
  const likelyCauses = Array.isArray(value.likely_causes) && value.likely_causes.length <= 8 ? value.likely_causes.map((item) => {
    if (!exactKeys(item, ['cause', 'confidence', 'evidence']) || !validText(item.cause, 1000) || !['low', 'medium', 'high'].includes(item.confidence) || !Array.isArray(item.evidence) || item.evidence.length > 10 || item.evidence.some((text) => !validText(text, 1000))) throw invalid('Support inference returned invalid output', 503);
    return { cause: item.cause, confidence: item.confidence, evidence: item.evidence };
  }) : (() => { throw invalid('Support inference returned invalid output', 503); })();
  const nextSteps = Array.isArray(value.next_steps) && value.next_steps.length <= 10 ? value.next_steps.map((item) => {
    if (!exactKeys(item, ['action', 'expected_result', 'safety_note']) || !validText(item.action, 1200) || !validText(item.expected_result, 1000) || (item.safety_note !== null && !validText(item.safety_note, 1000))) throw invalid('Support inference returned invalid output', 503);
    return { action: item.action, expected_result: item.expected_result, safety_note: item.safety_note || null };
  }) : (() => { throw invalid('Support inference returned invalid output', 503); })();
  const stringList = (items) => {
    if (!Array.isArray(items) || items.length > 10 || items.some((item) => !validText(item, 1000))) throw invalid('Support inference returned invalid output', 503);
    return items;
  };
  if (!Array.isArray(value.sources) || value.sources.length > 4 || value.sources.some((item) => !exactKeys(item, ['title', 'url']) || !validText(item.title, 200) || !validText(item.url, 2048))) throw invalid('Support inference returned invalid output', 503);
  const sources = value.sources.filter((item) => referenceMap.get(item.url) === item.title).map((item) => ({ title: item.title, url: item.url }));
  if (!exactKeys(value.escalation, ['recommended', 'reason']) || typeof value.escalation.recommended !== 'boolean' || (value.escalation.reason !== null && !validText(value.escalation.reason, 1000))) throw invalid('Support inference returned invalid output', 503);
  const limitations = stringList(value.limitations).slice();
  const requiredLimitations = [];
  if (retrievalFailure) requiredLimitations.push('Lookout Documentation retrieval was unavailable; the answer is limited to the supplied redacted evidence.');
  if (!sources.length) {
    requiredLimitations.push('No retrieved Lookout Documentation page supports this answer.');
    for (const cause of likelyCauses) cause.confidence = 'low';
  }
  return { summary: value.summary, likely_causes: likelyCauses, next_steps: nextSteps, needs_more_information: stringList(value.needs_more_information), sources, escalation: { recommended: value.escalation.recommended, reason: value.escalation.reason }, limitations: [...new Set([...requiredLimitations, ...limitations])].slice(0, 10) };
}

function blockedAnswer(categories) {
  const labels = categories.length ? categories.join(', ') : 'credential';
  return {
    summary: `The request was blocked before Support AI processing because it contained a likely secret (${labels}). Remove the sensitive value and retry with a newly generated client request ID.`,
    likely_causes: [],
    next_steps: [{ action: 'Revoke or rotate any exposed credential, redact the diagnostic excerpt locally, and retry with only the minimum required context.', expected_result: 'The retry contains placeholders instead of credential values and can be processed safely.', safety_note: 'Do not paste the replacement credential into chat or diagnostics.' }],
    needs_more_information: ['A redacted version of the question or diagnostic excerpt.'], sources: [],
    escalation: { recommended: true, reason: 'Lookout support was notified with the detected values removed.' },
    limitations: ['The model and documentation retriever were not called because the secret-detection gate blocked the request.']
  };
}

class LookoutSupportAgent {
  constructor({ store, modelClient, docsRetriever, limiter, clock = () => Date.now(), logger = () => {} } = {}) {
    if (!store || !modelClient || !docsRetriever || !limiter) throw new TypeError('Lookout Support Agent dependencies are required');
    this.store = store; this.modelClient = modelClient; this.docsRetriever = docsRetriever; this.limiter = limiter; this.clock = clock; this.logger = logger;
  }

  async ask(principal, rawInput) {
    const started = this.clock(); const input = validateAskInput(rawInput); const redacted = redactSupportInput(input);
    const requestHash = crypto.createHash('sha256').update(stableJson(redacted.value)).digest('hex');
    const now = new Date(this.clock()).toISOString();
    if (input.conversation_id && !(await this.store.authorizeConversation({ conversationId: input.conversation_id, tenantId: principal.tenantId, userId: principal.userId }))) throw invalid('Support conversation was not found', 404);
    const reservation = await this.store.reserveRequest({ supportTokenId: principal.tokenId, clientRequestId: input.client_request_id, requestHash, now, leaseMs: 60 * 1000 });
    if (reservation.state === 'conflict') throw invalid('Client request ID was already used for different input', 409);
    if (reservation.state === 'processing') throw invalid('Support request is already processing', 409);
    if (reservation.state === 'completed') return reservation.result;
    let release = null; let references = []; let usage = { totalTokens: 0 }; let retrievalFailure = null;
    try {
      try { release = this.limiter.acquireGeneration(principal.tokenId); }
      catch (error) { await this.store.releaseRequest({ supportTokenId: principal.tokenId, clientRequestId: input.client_request_id, requestHash, now: new Date(this.clock()).toISOString() }); throw error; }
      let answer;
      if (redacted.blocked) answer = blockedAnswer(redacted.categories);
      else {
        try { references = await this.docsRetriever.retrieve(stableJson(redacted.value)); }
        catch (error) { retrievalFailure = error; }
        const generated = await this.modelClient.generate({ input: redacted.value, references, safetyIdentifier: crypto.createHash('sha256').update(`${principal.tenantId}\0${principal.userId}`).digest('hex') });
        usage = generated.usage || usage;
        answer = validateAnswer(generated.result, references, retrievalFailure);
      }
      const result = await this.store.completeRequest({
        principal, clientRequestId: input.client_request_id, requestHash, requestId: reservation.requestId, conversationId: input.conversation_id || null,
        customerText: stableJson(redacted.value), result: answer, now: new Date(this.clock()).toISOString(),
        outboxPayload: { accountEmail: principal.accountEmail, redactionCategories: redacted.categories }
      });
      emit(this.logger, { event: 'lookout_support_ask', requestId: reservation.requestId, tokenMetadataId: crypto.createHash('sha256').update(principal.tokenId).digest('hex').slice(0, 16), outcome: redacted.blocked ? 'blocked_secret' : 'success', latencyMs: this.clock() - started, inputCharacters: JSON.stringify(input).length, outputCharacters: JSON.stringify(result).length, redactions: redacted.counts, modelTokens: usage.totalTokens || 0, documentationFetchCount: references.length });
      emit(this.logger, { event: 'lookout_support_answer', hasCitation: result.sources.length > 0, needsMoreInformation: result.needs_more_information.length > 0, escalationRecommended: result.escalation.recommended });
      return result;
    } catch (error) {
      if (error.status !== 409 || error.message === 'Support request lease was lost') await this.store.releaseRequest({ supportTokenId: principal.tokenId, clientRequestId: input.client_request_id, requestHash, now: new Date(this.clock()).toISOString() });
      emit(this.logger, { event: 'lookout_support_ask', requestId: reservation.requestId, tokenMetadataId: crypto.createHash('sha256').update(principal.tokenId).digest('hex').slice(0, 16), outcome: error.status === 429 ? 'rate_limited' : error.status === 409 ? 'conflict' : 'failed', latencyMs: this.clock() - started, inputCharacters: JSON.stringify(input).length, outputCharacters: 0, redactions: redacted.counts, modelTokens: usage.totalTokens || 0, documentationFetchCount: references.length });
      throw error;
    } finally { release?.(); }
  }

  async check(principal, input) {
    const keys = input && typeof input === 'object' && !Array.isArray(input) ? Object.keys(input) : [];
    if (!input || keys.some((key) => !['conversation_id', 'after_message_id', 'limit'].includes(key)) || !CONVERSATION_ID.test(input.conversation_id || '') || (input.after_message_id !== undefined && !/^scm_[A-Za-z0-9_-]{32}$/.test(input.after_message_id)) || (input.limit !== undefined && (!Number.isInteger(input.limit) || input.limit < 1 || input.limit > 50))) throw invalid();
    this.limiter.recordCheck(principal.tokenId);
    const found = await this.store.checkConversation({ conversationId: input.conversation_id, tenantId: principal.tenantId, userId: principal.userId, afterMessageId: input.after_message_id || null, limit: input.limit || 20 });
    if (!found) throw invalid('Support conversation was not found', 404);
    const result = { conversation_id: input.conversation_id, status: found.conversation.status, messages: found.messages.map((item) => ({ message_id: item.messageId, author: 'lookout_support', text: item.text, created_at: item.createdAt })), next_after_message_id: found.nextAfterMessageId };
    emit(this.logger, { event: 'lookout_support_check', outcome: 'success', hasUnreadStaffReply: result.messages.length > 0 });
    return result;
  }
}

module.exports = { LookoutSupportAgent, validateAskSupportInput: validateAskInput, validateSupportAnswer: validateAnswer, canonicalSupportJson: stableJson, blockedSupportAnswer: blockedAnswer, SUPPORT_CLIENT_REQUEST_ID_PATTERN: CLIENT_REQUEST_ID, SUPPORT_CONVERSATION_ID_PATTERN: CONVERSATION_ID };

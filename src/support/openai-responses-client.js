'use strict';

const { SUPPORT_DEVELOPER_INSTRUCTIONS, SUPPORT_INSTRUCTIONS_VERSION } = require('./instructions');

const ANSWER_SCHEMA = {
  type: 'object', additionalProperties: false,
  required: ['summary', 'likely_causes', 'next_steps', 'needs_more_information', 'sources', 'escalation', 'limitations'],
  properties: {
    summary: { type: 'string', minLength: 1, maxLength: 3000 },
    likely_causes: { type: 'array', maxItems: 8, items: { type: 'object', additionalProperties: false, required: ['cause', 'confidence', 'evidence'], properties: { cause: { type: 'string', minLength: 1, maxLength: 1000 }, confidence: { enum: ['low', 'medium', 'high'] }, evidence: { type: 'array', maxItems: 10, items: { type: 'string', minLength: 1, maxLength: 1000 } } } } },
    next_steps: { type: 'array', maxItems: 10, items: { type: 'object', additionalProperties: false, required: ['action', 'expected_result', 'safety_note'], properties: { action: { type: 'string', minLength: 1, maxLength: 1200 }, expected_result: { type: 'string', minLength: 1, maxLength: 1000 }, safety_note: { type: ['string', 'null'], maxLength: 1000 } } } },
    needs_more_information: { type: 'array', maxItems: 10, items: { type: 'string', minLength: 1, maxLength: 1000 } },
    sources: { type: 'array', maxItems: 4, items: { type: 'object', additionalProperties: false, required: ['title', 'url'], properties: { title: { type: 'string', minLength: 1, maxLength: 200 }, url: { type: 'string', minLength: 1, maxLength: 2048 } } } },
    escalation: { type: 'object', additionalProperties: false, required: ['recommended', 'reason'], properties: { recommended: { type: 'boolean' }, reason: { type: ['string', 'null'], maxLength: 1000 } } },
    limitations: { type: 'array', maxItems: 10, items: { type: 'string', minLength: 1, maxLength: 1000 } }
  }
};

function outputText(response) {
  if (typeof response.output_text === 'string') return response.output_text;
  return (response.output || []).flatMap((item) => item.content || []).filter((item) => item.type === 'output_text' && typeof item.text === 'string').map((item) => item.text).join('');
}

class OpenAIResponsesClient {
  constructor({ apiKey, model, fetchImpl = globalThis.fetch, timeoutMs = 45000, maxOutputTokens = 1400 } = {}) {
    if (!apiKey || !model) throw new Error('OpenAI support inference is not configured');
    this.apiKey = apiKey; this.model = model; this.fetch = fetchImpl; this.timeoutMs = timeoutMs; this.maxOutputTokens = maxOutputTokens;
  }

  async generate({ input, references, safetyIdentifier }) {
    const referenceText = references.length ? references.map((reference, index) => `<lookout_document index="${index + 1}" title=${JSON.stringify(reference.title)} url=${JSON.stringify(reference.url)}>\n${reference.markdown}\n</lookout_document>`).join('\n\n') : '<lookout_documents unavailable="true" />';
    const body = {
      model: this.model, store: false, safety_identifier: safetyIdentifier, max_output_tokens: this.maxOutputTokens,
      input: [
        { role: 'developer', content: [{ type: 'input_text', text: `${SUPPORT_DEVELOPER_INSTRUCTIONS}\n\nInstruction version: ${SUPPORT_INSTRUCTIONS_VERSION}` }] },
        { role: 'user', content: [{ type: 'input_text', text: `Customer input (redacted JSON):\n${JSON.stringify(input)}\n\nUntrusted Lookout Documentation references:\n${referenceText}` }] }
      ],
      text: { format: { type: 'json_schema', name: 'lookout_support_answer', strict: true, schema: ANSWER_SCHEMA } }
    };
    let response;
    try {
      response = await this.fetch('https://api.openai.com/v1/responses', { method: 'POST', redirect: 'error', signal: AbortSignal.timeout(this.timeoutMs), headers: { Authorization: `Bearer ${this.apiKey}`, 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify(body) });
    } catch (error) {
      const failure = new Error(error?.name === 'TimeoutError' ? 'Support inference timed out' : 'Support inference is unavailable'); failure.code = error?.name === 'TimeoutError' ? 'timeout' : 'unavailable'; throw failure;
    }
    if (!response.ok) { const failure = new Error('Support inference is unavailable'); failure.code = response.status === 429 ? 'rate_limit' : 'unavailable'; throw failure; }
    let json;
    try { json = await response.json(); } catch { const failure = new Error('Support inference returned invalid output'); failure.code = 'invalid_output'; throw failure; }
    let result;
    try { result = JSON.parse(outputText(json)); } catch { const failure = new Error('Support inference returned invalid output'); failure.code = 'invalid_output'; throw failure; }
    return { result, usage: { inputTokens: json.usage?.input_tokens || 0, outputTokens: json.usage?.output_tokens || 0, totalTokens: json.usage?.total_tokens || 0 }, request: body };
  }
}

module.exports = { OpenAIResponsesClient, SUPPORT_ANSWER_SCHEMA: ANSWER_SCHEMA, extractResponsesOutputText: outputText };

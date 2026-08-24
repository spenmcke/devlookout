'use strict';

const { McpServer, createMcpHandler } = require('@modelcontextprotocol/server');
const { toNodeHandler } = require('@modelcontextprotocol/node');
const { z } = require('zod');

const MCP_PATH = '/support/mcp';
const askInput = z.strictObject({
  client_request_id: z.string().regex(/^[A-Za-z0-9_-]{16,128}$/),
  conversation_id: z.string().regex(/^scv_[A-Za-z0-9_-]{32}$/).optional(),
  question: z.string().min(1).max(4000),
  context: z.strictObject({
    lookout_version: z.string().max(64).optional(),
    installation_mode: z.enum(['hosted', 'fleet', 'single-host', 'source', 'unknown']).optional(),
    platform: z.string().max(128).optional(), symptoms: z.string().max(2000).optional()
  }).optional(),
  attempted_steps: z.array(z.string().max(1000)).max(10).optional(), diagnostics: z.string().max(12000).optional()
});
const checkInput = z.strictObject({ conversation_id: z.string().regex(/^scv_[A-Za-z0-9_-]{32}$/), after_message_id: z.string().regex(/^scm_[A-Za-z0-9_-]{32}$/).optional(), limit: z.number().int().min(1).max(50).default(20) });

function bearer(req) {
  const value = req.headers?.authorization;
  if (Array.isArray(value)) return null;
  return /^Bearer (lsp_[A-Za-z0-9_-]{43})$/.exec(value || '')?.[1] || null;
}
function send(res, status, value, extra = {}) {
  const body = Buffer.from(JSON.stringify(value));
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': body.length, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', ...extra }); res.end(body);
}
function safeToolError(error) {
  const status = error?.status;
  const text = status === 404 ? 'Support conversation was not found.' : status === 409 ? 'Support request conflicts with an existing request or is already processing.' : status === 429 ? 'Support capacity is temporarily unavailable. Retry later.' : 'Lookout Support AI could not complete the request. Retry later.';
  return { isError: true, content: [{ type: 'text', text }] };
}
function emit(logger, record) { try { logger(record); } catch {} }
async function readBody(req, maximumBytes) {
  if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(String(req.headers?.['content-type'] || ''))) throw Object.assign(new Error('content type'), { status: 400 });
  const declared = req.headers?.['content-length'];
  if (declared !== undefined && (!/^\d+$/.test(declared) || Number(declared) > maximumBytes)) throw Object.assign(new Error('size'), { status: 413 });
  const chunks = []; let size = 0;
  for await (const chunk of req) { const bytes = Buffer.from(chunk); size += bytes.length; if (size > maximumBytes) throw Object.assign(new Error('size'), { status: 413 }); chunks.push(bytes); }
  try { return JSON.parse(Buffer.concat(chunks, size).toString('utf8')); } catch { throw Object.assign(new Error('json'), { status: 400 }); }
}

function createSupportMcpHttpHandler({ tokenAuthority, supportAgent, logger = () => {} } = {}) {
  if (!tokenAuthority) throw new TypeError('Support token authority is required');
  const handler = createMcpHandler((context) => {
    const principal = context.authInfo?.principal;
    const server = new McpServer({ name: 'lookout-support', version: '1.0.0' }, {
      instructions: 'Use ask_lookout_support when Lookout Documentation is insufficient. It stores redacted conversation content for 90 days and emails it to Lookout support. It never accesses or changes a deployment. Use check_lookout_support to poll for human replies.'
    });
    server.registerTool('ask_lookout_support', {
      title: 'Ask the Lookout Support AI Agent',
      description: 'Diagnose a Lookout installation, configuration, operations, or integration question using bounded Lookout Documentation. This tool never accesses or modifies the deployment. It stores the redacted question and answer for 90 days by default and shares them with Lookout support by email. A client_request_id makes retries idempotent.',
      inputSchema: askInput,
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true }
    }, async (input) => {
      try {
        if (!supportAgent) throw Object.assign(new Error('Support AI is not configured'), { status: 503 });
        const result = await supportAgent.ask(principal, input);
        return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }], structuredContent: result };
      } catch (error) { return safeToolError(error); }
    });
    server.registerTool('check_lookout_support', {
      title: 'Check Lookout support replies',
      description: 'Read customer-visible Lookout staff replies and conversation status. This tool does not run the model or send email.',
      inputSchema: checkInput,
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false }
    }, async (input) => {
      try {
        if (!supportAgent) throw Object.assign(new Error('Support AI is not configured'), { status: 503 });
        const result = await supportAgent.check(principal, input);
        return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }], structuredContent: result };
      } catch (error) { return safeToolError(error); }
    });
    return server;
  }, { responseMode: 'auto', legacy: 'stateless', onerror: () => {} });
  const nodeHandler = toNodeHandler(handler);

  return async function supportMcpHttp(req, res, url) {
    if (url.pathname !== MCP_PATH) return false;
    if (url.search || url.hash) { send(res, 404, { error: 'not_found' }); return true; }
    const token = bearer(req);
    const principal = token ? await tokenAuthority.authenticate(token) : null;
    if (!principal) { emit(logger, { event: 'lookout_support_mcp_auth', outcome: 'failure' }); send(res, 401, { error: 'unauthorized' }, { 'WWW-Authenticate': 'Bearer' }); return true; }
    emit(logger, { event: 'lookout_support_mcp_auth', outcome: 'success' });
    if (!supportAgent) { send(res, 503, { error: 'unavailable' }); return true; }
    if (!['GET', 'POST', 'DELETE'].includes(req.method)) { send(res, 405, { error: 'method_not_allowed' }, { Allow: 'GET, POST, DELETE' }); return true; }
    req.auth = { token: principal.tokenId, clientId: principal.userId, scopes: ['lookout:support'], expiresAt: Math.floor(Date.parse(principal.expiresAt) / 1000), principal };
    try {
      const parsedBody = req.method === 'POST' ? await readBody(req, 32 * 1024) : undefined;
      await nodeHandler(req, res, parsedBody);
    } catch (error) { if (!res.headersSent) send(res, error.status || 400, { error: error.status === 413 ? 'payload_too_large' : 'bad_request' }); }
    return true;
  };
}

module.exports = { createSupportMcpHttpHandler, parseSupportMcpBearer: bearer, readSupportMcpBody: readBody, ASK_LOOKOUT_SUPPORT_SCHEMA: askInput, CHECK_LOOKOUT_SUPPORT_SCHEMA: checkInput, SUPPORT_MCP_PATH: MCP_PATH };

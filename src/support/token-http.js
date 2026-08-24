'use strict';

const { TOKEN_ID_PATTERN } = require('./access-token-authority');

function reply(res, status, value, extra = {}) {
  const body = Buffer.from(JSON.stringify(value));
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': body.length, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', ...extra }); res.end(body);
}
function problem(res, status) {
  const code = { 400: 'bad_request', 401: 'unauthorized', 404: 'not_found', 409: 'conflict', 413: 'payload_too_large', 429: 'rate_limited', 503: 'unavailable' }[status] || 'error';
  reply(res, status, { error: code }, status === 401 ? { 'WWW-Authenticate': 'Bearer' } : {});
}
function log(logger, record) { try { logger(record); } catch {} }
async function json(req, maximumBytes) {
  if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(String(req.headers?.['content-type'] || ''))) throw Object.assign(new Error('content type'), { status: 400 });
  const declared = req.headers?.['content-length']; if (declared !== undefined && (!/^\d+$/.test(declared) || Number(declared) > maximumBytes)) throw Object.assign(new Error('size'), { status: 413 });
  const chunks = []; let size = 0;
  for await (const chunk of req) { size += chunk.length; if (size > maximumBytes) throw Object.assign(new Error('size'), { status: 413 }); chunks.push(Buffer.from(chunk)); }
  try { const value = JSON.parse(Buffer.concat(chunks, size).toString('utf8')); if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(); return value; } catch { throw Object.assign(new Error('json'), { status: 400 }); }
}

function createSupportTokenHttpHandler({ tokenAuthority, authenticateBrowser, logger = () => {} } = {}) {
  if (!tokenAuthority || typeof authenticateBrowser !== 'function') throw new TypeError('Support token HTTP dependencies are required');
  return async function supportTokenHttp(req, res, url) {
    const accountToken = url.pathname === '/v1/support/account-token';
    const match = /^\/v1\/support\/tokens(?:\/(sat_[A-Za-z0-9_-]{32}))?$/.exec(url.pathname);
    if (!accountToken && !match) return false;
    if (url.search || url.hash) { problem(res, 400); return true; }
    let principal; try { principal = await authenticateBrowser(req); } catch { principal = null; }
    if (!principal) { problem(res, 401); return true; }
    try {
      if (accountToken && req.method === 'GET') {
        const result = await tokenAuthority.accountToken(principal);
        reply(res, 200, { ...result.metadata, token: result.token });
        log(logger, { event: 'lookout_support_token', action: 'account_accessed' });
        return true;
      }
      if (accountToken) { problem(res, 404); return true; }
      if (!match[1] && req.method === 'GET') { reply(res, 200, { tokens: await tokenAuthority.list(principal) }); return true; }
      if (!match[1] && req.method === 'POST') {
        const input = await json(req, 1024); if (Object.keys(input).length !== 1 || typeof input.name !== 'string') throw Object.assign(new Error('shape'), { status: 400 });
        const created = await tokenAuthority.create({ ...principal, name: input.name }); reply(res, 201, { ...created.metadata, token: created.token }); log(logger, { event: 'lookout_support_token', action: 'created' }); return true;
      }
      if (match[1] && req.method === 'DELETE' && TOKEN_ID_PATTERN.test(match[1])) {
        if (req.headers?.['content-length'] !== undefined && req.headers['content-length'] !== '0') throw Object.assign(new Error('body'), { status: 400 });
        reply(res, 200, { token: await tokenAuthority.revoke(principal, match[1]) }); log(logger, { event: 'lookout_support_token', action: 'revoked' }); return true;
      }
      problem(res, 404); return true;
    } catch (error) { problem(res, error.status || 503); return true; }
  };
}

module.exports = { createSupportTokenHttpHandler };

'use strict';

const MAXIMUM_JSON_BYTES = 32 * 1024;
const SESSION_ID = /^[A-Za-z0-9_-]{16,128}$/;
const JSON_CONTENT_TYPE = /^application\/(?:[a-z0-9.+-]*\+)?json(?:\s*;\s*charset=utf-8)?$/i;

function header(req, name) {
  if (typeof req.getHeader === 'function') return req.getHeader(name);
  const value = req.headers?.[name.toLowerCase()];
  return Array.isArray(value) ? value.join(',') : value;
}

function reply(res, status, value, extraHeaders = {}) {
  const body = JSON.stringify(value);
  const headers = {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    ...extraHeaders
  };
  res.writeHead(status, headers);
  res.end(body);
}

function problem(res, status) {
  const names = { 400: 'bad_request', 401: 'unauthorized', 404: 'not_found', 409: 'conflict', 429: 'rate_limited' };
  const headers = status === 401 ? { 'WWW-Authenticate': 'Bearer' } : status === 429 ? { 'Retry-After': '60' } : {};
  reply(res, status, { error: names[status] || 'conflict' }, headers);
}

function contentLength(req) {
  const value = header(req, 'content-length');
  if (value === undefined) return null;
  if (typeof value !== 'string' || !/^\d+$/.test(value)) throw new Error('bad-request');
  const length = Number(value);
  if (!Number.isSafeInteger(length) || length > MAXIMUM_JSON_BYTES) throw new Error('request-too-large');
  return length;
}

async function readJson(req) {
  if (!JSON_CONTENT_TYPE.test(String(header(req, 'content-type') || ''))) throw new Error('unsupported-content-type');
  const declared = contentLength(req);
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    const bytes = Buffer.from(chunk);
    size += bytes.length;
    if (size > MAXIMUM_JSON_BYTES) throw new Error('request-too-large');
    chunks.push(bytes);
  }
  if (declared !== null && declared !== size) throw new Error('invalid-content-length');
  if (size === 0) throw new Error('empty-json');
  let value;
  try { value = JSON.parse(Buffer.concat(chunks, size).toString('utf8')); }
  catch { throw new Error('invalid-json'); }
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('invalid-json-object');
  return value;
}

function bearer(req) {
  const value = header(req, 'authorization');
  if (typeof value !== 'string') return null;
  const match = /^Bearer ([\x21-\x7e]{24,4096})$/.exec(value);
  return match ? match[1] : null;
}

function containsUntrustedIdentity(value, depth = 0) {
  if (!value || typeof value !== 'object' || depth > 8) return false;
  for (const [key, child] of Object.entries(value)) {
    const normalized = key.replace(/[-_]/g, '').toLowerCase();
    if (normalized === 'tenantid' || normalized === 'userid') return true;
    if (containsUntrustedIdentity(child, depth + 1)) return true;
  }
  return false;
}

function statusFor(error, route) {
  const message = String(error?.message || '');
  if (/rate|capacity/i.test(message)) return 429;
  if (/expired|terminal|backwards|reused|save|provision/i.test(message)) return 409;
  if (/possession proof is unavailable/i.test(message)) return 409;
  if (/unavailable/i.test(message)) return route === 'claim' || route === 'connect' || route === 'failure' || route === 'pair' ? 404 : 401;
  return 400;
}

function createSetupSessionHttpHandler({ authority, authenticateBrowser } = {}) {
  if (!authority || typeof authority.create !== 'function' || typeof authority.connect !== 'function' || typeof authority.reportPreclaimFailure !== 'function' || typeof authority.claim !== 'function' || typeof authority.prove !== 'function' || typeof authority.status !== 'function' || typeof authority.browserStatus !== 'function' || typeof authority.browserActiveStatus !== 'function' || typeof authority.reportPhase !== 'function' || typeof authority.publishBootstrapKey !== 'function') throw new TypeError('A setup session authority is required');
  if (typeof authenticateBrowser !== 'function') throw new TypeError('A browser authenticator is required');

  return async function setupSessionHttpHandler(req, res) {
    let pathname;
    try {
      const url = new URL(req.url, 'https://setup.invalid');
      if (url.search || url.hash) return problem(res, 400);
      pathname = url.pathname;
    } catch { return problem(res, 400); }

    let route = null;
    let sessionId = null;
    if (pathname === '/v1/setup-sessions') route = 'create';
    else if (pathname === '/v1/setup-sessions/active') route = 'active';
    else if (pathname === '/v1/setup-sessions/reset') route = 'reset';
    else if (pathname === '/v1/setup-sessions/connect') route = 'connect';
    else if (pathname === '/v1/setup-sessions/failures') route = 'failure';
    else if (pathname === '/v1/setup-sessions/claim') route = 'claim';
    else {
      const match = /^\/v1\/setup-sessions\/([A-Za-z0-9_-]{16,128})(?:\/(prove|phases|bootstrap-key|diagnostics))?$/.exec(pathname);
      if (match) {
        sessionId = match[1];
        route = match[2] || 'status';
      }
    }
    const method = String(req.method || '').toUpperCase();
    const expected = route === 'status' || route === 'active' ? 'GET' : 'POST';
    if (!route || method !== expected || (sessionId && !SESSION_ID.test(sessionId))) return problem(res, 404);

    try {
      if (route === 'create') {
        const body = await readJson(req);
        if (containsUntrustedIdentity(body)) return problem(res, 400);
        if (Object.keys(body).length !== 0) return problem(res, 400);
        let principal;
        try { principal = await authenticateBrowser(req); } catch { return problem(res, 401); }
        if (!principal || typeof principal.tenantId !== 'string' || typeof principal.userId !== 'string') return problem(res, 401);
        return reply(res, 201, await authority.create({ tenantId: principal.tenantId, userId: principal.userId, email: principal.email }));
      }

      if (route === 'active') {
        const length = contentLength(req);
        if (length !== null && length !== 0) return problem(res, 400);
        let principal;
        try { principal = await authenticateBrowser(req); } catch { return problem(res, 401); }
        if (!principal || typeof principal.tenantId !== 'string' || typeof principal.userId !== 'string') return problem(res, 401);
        return reply(res, 200, await authority.browserActiveStatus({ tenantId: principal.tenantId, userId: principal.userId }));
      }

      if (route === 'reset') {
        const body = await readJson(req);
        if (containsUntrustedIdentity(body) || Object.keys(body).length !== 0) return problem(res, 400);
        let principal;
        try { principal = await authenticateBrowser(req); } catch { return problem(res, 401); }
        if (!principal || typeof principal.tenantId !== 'string' || typeof principal.userId !== 'string') return problem(res, 401);
        return reply(res, 200, await authority.dismissFailed({ tenantId: principal.tenantId, userId: principal.userId }));
      }

      if (route === 'claim') {
        const body = await readJson(req);
        if (containsUntrustedIdentity(body)) return problem(res, 400);
        return reply(res, 200, await authority.claim(body));
      }

      if (route === 'connect') {
        const body = await readJson(req);
        if (containsUntrustedIdentity(body) || Object.keys(body).some((key) => key !== 'setup_token')) return problem(res, 400);
        return reply(res, 200, await authority.connect(body));
      }

      if (route === 'failure') {
        const body = await readJson(req);
        if (containsUntrustedIdentity(body) || Object.keys(body).some((key) => !['setup_token', 'code'].includes(key))) return problem(res, 400);
        return reply(res, 200, await authority.reportPreclaimFailure(body));
      }

      const token = bearer(req);
      if (route === 'status') {
        const length = contentLength(req);
        if (length !== null && length !== 0) return problem(res, 400);
        if (token) {
          try { return reply(res, 200, await authority.status({ sessionId, sessionToken: token })); }
          catch { /* A browser bearer is authenticated below. */ }
        }
        let principal;
        try { principal = await authenticateBrowser(req); } catch { return problem(res, 401); }
        if (!principal || typeof principal.tenantId !== 'string' || typeof principal.userId !== 'string') return problem(res, 401);
        return reply(res, 200, await authority.browserStatus({ sessionId, tenantId: principal.tenantId, userId: principal.userId }));
      }
      if (!token) return problem(res, 401);
      const body = await readJson(req);
      if (containsUntrustedIdentity(body)) return problem(res, 400);
      if (route === 'prove') return reply(res, 200, await authority.prove({ sessionId, sessionToken: token, signatureBase64url: body.signature_base64url }));
      if (route === 'bootstrap-key') return reply(res, 200, await authority.publishBootstrapKey({ sessionId, sessionToken: token, bootstrapKey: body }));
      if (route === 'diagnostics') return reply(res, 202, await authority.recordDiagnostic({ sessionId, sessionToken: token, diagnostic: body }));
      return reply(res, 200, await authority.reportPhase({ sessionId, sessionToken: token, phase: body.phase, completed: body.completed, total: body.total }));
    } catch (error) {
      return problem(res, statusFor(error, route));
    }
  };
}

module.exports = {
  createSetupSessionHttpHandler,
  readSetupSessionJson: readJson,
  parseSetupSessionBearer: bearer,
  MAXIMUM_JSON_BYTES
};

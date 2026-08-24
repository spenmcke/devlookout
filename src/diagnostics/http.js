'use strict';

const { MAXIMUM_SURVEY_BYTES } = require('./service');

const MAXIMUM_JSON_BYTES = 16 * 1024;
const REPORT_ID = /^diag_[A-Za-z0-9_-]{32}$/;
const JSON_TYPE = /^application\/json(?:\s*;\s*charset=utf-8)?$/i;
const TEXT_TYPE = /^text\/plain(?:\s*;\s*charset=utf-8)?$/i;

function reply(res, status, value, extra = {}) {
  const body = Buffer.from(JSON.stringify(value));
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': body.length, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', ...extra });
  res.end(body);
}

function problem(res, status) {
  const names = { 400: 'bad_request', 401: 'unauthorized', 404: 'not_found', 409: 'conflict', 413: 'payload_too_large', 429: 'rate_limited', 503: 'unavailable' };
  reply(res, status, { error: names[status] || 'unavailable' }, status === 401 ? { 'WWW-Authenticate': 'Bearer' } : {});
}

function singleHeader(req, name) {
  const value = req.headers?.[name.toLowerCase()];
  return Array.isArray(value) ? null : value;
}

async function readBody(req, maximum, type) {
  if (!type.test(String(singleHeader(req, 'content-type') || ''))) throw Object.assign(new Error('content-type'), { status: 400 });
  const declared = singleHeader(req, 'content-length');
  if (declared !== undefined && (!/^\d+$/.test(declared) || Number(declared) > maximum)) throw Object.assign(new Error('size'), { status: 413 });
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    const bytes = Buffer.from(chunk);
    size += bytes.length;
    if (size > maximum) throw Object.assign(new Error('size'), { status: 413 });
    chunks.push(bytes);
  }
  if (declared !== undefined && Number(declared) !== size) throw Object.assign(new Error('length'), { status: 400 });
  return Buffer.concat(chunks, size).toString('utf8');
}

async function readJson(req) {
  const text = await readBody(req, MAXIMUM_JSON_BYTES, JSON_TYPE);
  try {
    const value = JSON.parse(text);
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('shape');
    return value;
  } catch { throw Object.assign(new Error('json'), { status: 400 }); }
}

function bearer(req) {
  const value = singleHeader(req, 'authorization');
  return /^Bearer (ldr_[A-Za-z0-9_-]{43})$/.exec(value || '')?.[1] || null;
}

function createDiagnosticsHttpHandler({ service, setupAuthority } = {}) {
  if (!service || typeof service.createSurvey !== 'function' || typeof service.submitSurvey !== 'function' || typeof service.recordInstallerEvent !== 'function') throw new TypeError('Diagnostics service is required');
  if (!setupAuthority || typeof setupAuthority.diagnosticContextBySetupToken !== 'function' || typeof setupAuthority.diagnosticContextBySupportToken !== 'function') throw new TypeError('Setup authority diagnostics context is required');

  return async function diagnosticsHttpHandler(req, res, url) {
    if (url.search || url.hash) return problem(res, 400);
    const surveyMatch = /^\/v1\/setup-support\/surveys\/(diag_[A-Za-z0-9_-]{32})$/.exec(url.pathname);
    try {
      if (url.pathname === '/v1/setup-support/surveys') {
        if (req.method !== 'POST') return problem(res, 404);
        const body = await readJson(req);
        const keys = Object.keys(body);
        const setupCredential = keys.length === 1 && typeof body.setup_token === 'string';
        const supportCredential = keys.length === 1 && typeof body.support_token === 'string';
        if (!setupCredential && !supportCredential) return problem(res, 400);
        const context = setupCredential
          ? await setupAuthority.diagnosticContextBySetupToken(body)
          : await setupAuthority.diagnosticContextBySupportToken(body);
        const survey = await service.createSurvey(context);
        return reply(res, 201, { report_id: survey.reportId, submission_token: survey.submissionToken, survey: survey.survey, expires_at: survey.expiresAt });
      }
      if (surveyMatch) {
        if (req.method !== 'POST' || !REPORT_ID.test(surveyMatch[1])) return problem(res, 404);
        const token = bearer(req);
        const idempotency = singleHeader(req, 'idempotency-key');
        if (!token || typeof idempotency !== 'string') return problem(res, 401);
        const text = await readBody(req, MAXIMUM_SURVEY_BYTES, TEXT_TYPE);
        const result = await service.submitSurvey({ reportId: surveyMatch[1], submissionToken: token, text, idempotencyKey: idempotency });
        service.flushSlack().catch(() => {});
        return reply(res, 202, { accepted: true, report_id: result.reportId });
      }
      if (url.pathname === '/v1/setup-support/events') {
        if (req.method !== 'POST') return problem(res, 404);
        const body = await readJson(req);
        const allowed = new Set(['setup_token', 'kind', 'code', 'phase', 'platform', 'idempotency_key']);
        if (Object.keys(body).some((key) => !allowed.has(key)) || typeof body.setup_token !== 'string') return problem(res, 400);
        const context = await setupAuthority.diagnosticContextBySetupToken(body);
        const result = await service.recordInstallerEvent(context, { ...body, idempotencyKey: body.idempotency_key });
        service.flushSlack().catch(() => {});
        return reply(res, 202, { accepted: true, report_id: result.reportId });
      }
      return problem(res, 404);
    } catch (error) {
      if (error.status) return problem(res, error.status);
      if (/rate limit/i.test(error.message)) return problem(res, 429);
      if (/unavailable|credential/i.test(error.message)) return problem(res, 404);
      if (/already been submitted/i.test(error.message)) return problem(res, 409);
      if (/invalid|required|unsupported|too large|incomplete|idempotency key/i.test(error.message)) return problem(res, 400);
      return problem(res, 503);
    }
  };
}

module.exports = { createDiagnosticsHttpHandler, readDiagnosticsBody: readBody, MAXIMUM_JSON_BYTES };

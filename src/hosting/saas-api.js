'use strict';

const crypto = require('node:crypto');
const { createSetupSessionHttpHandler } = require('../onboarding/setup-session-http');
const { createDiagnosticsHttpHandler } = require('../diagnostics/http');
const { analytics } = require('../detection/catalog');
const { batchIdFor } = require('../export/service');

const MAXIMUM_SNAPSHOT_BATCH_BYTES = 1024 * 1024;
const MAXIMUM_OPERATIONAL_BATCH_BYTES = 1024 * 1024;
const DEPLOYMENT_ID = /^dpl_[A-Za-z0-9_-]{32}$/;
const CLI_AUTHORIZATION_ID = /^cla_[A-Za-z0-9_-]{32}$/;

function cliAuthorizationFailureReason(error) {
  const message = String(error?.message || '');
  if (/active network/i.test(message)) return 'active_network';
  if (/active setup/i.test(message)) return 'active_setup';
  if (/capacity/i.test(message)) return 'capacity';
  if (/deleted/i.test(message)) return 'account_deleted';
  if (/verification/i.test(message)) return 'verification_failed';
  if (/unavailable/i.test(message)) return 'authorization_unavailable';
  if (/invalid|content-type|content type|size|length|json|shape|redirect/i.test(message)) return 'invalid_request';
  return 'internal_error';
}

function logCliAuthorizationFailure(logger, phase, error, requestId = null) {
  const record = { event: 'lookout_cli_authorization', outcome: 'rejected', phase, reason: cliAuthorizationFailureReason(error) };
  if (CLI_AUTHORIZATION_ID.test(requestId || '')) record.request_id = requestId;
  try { logger(record); } catch { /* Logging must not change authentication behavior. */ }
}

function reply(res, status, value, extra = {}) {
  const body = Buffer.from(JSON.stringify(value));
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8', 'Content-Length': body.length,
    'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', ...extra
  });
  res.end(body);
}

function problem(res, status) {
  const code = { 400: 'bad_request', 401: 'unauthorized', 403: 'forbidden', 404: 'not_found', 409: 'conflict', 413: 'payload_too_large', 429: 'rate_limited', 503: 'unavailable' }[status] || 'error';
  reply(res, status, { error: code }, status === 401 ? { 'WWW-Authenticate': 'Bearer' } : {});
}

function strictBearer(req) {
  const value = req.headers?.authorization;
  if (Array.isArray(value)) return null;
  return /^Bearer ([\x21-\x7e]{32,4096})$/.exec(value || '')?.[1] || null;
}

function internalBearerAuthorized(req, expected) {
  const supplied = strictBearer(req);
  if (typeof expected !== 'string' || expected.length < 32 || !supplied) return false;
  const left = Buffer.from(expected);
  const right = Buffer.from(supplied);
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

async function readJson(req, maximumBytes) {
  if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(String(req.headers?.['content-type'] || ''))) throw Object.assign(new Error('content-type'), { status: 400 });
  const declared = req.headers?.['content-length'];
  if (declared !== undefined && (!/^\d+$/.test(declared) || Number(declared) > maximumBytes)) throw Object.assign(new Error('size'), { status: 413 });
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    const bytes = Buffer.from(chunk);
    size += bytes.length;
    if (size > maximumBytes) throw Object.assign(new Error('size'), { status: 413 });
    chunks.push(bytes);
  }
  if (declared !== undefined && Number(declared) !== size) throw Object.assign(new Error('length'), { status: 400 });
  try {
    const value = JSON.parse(Buffer.concat(chunks, size).toString('utf8'));
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('shape');
    return value;
  } catch { throw Object.assign(new Error('json'), { status: 400 }); }
}

function createHostedSaasApi({ setupAuthority, cliAuthorizationAuthority = null, consoleStore, authenticateBrowser, deleteAccount, recoveryMonitor = null, diagnosticsService = null, supportTokenHandler = null, operationalHealthService = null, operationsApiToken = '', logger = () => {} } = {}) {
  if (!setupAuthority || typeof setupAuthority.cancelRecovery !== 'function' || !consoleStore || typeof authenticateBrowser !== 'function' || typeof deleteAccount !== 'function') throw new TypeError('Hosted SaaS API dependencies are required');
  if (typeof logger !== 'function') throw new TypeError('Hosted SaaS API logger must be a function');
  const setup = createSetupSessionHttpHandler({ authority: setupAuthority, authenticateBrowser });
  const diagnostics = diagnosticsService ? createDiagnosticsHttpHandler({ service: diagnosticsService, setupAuthority }) : null;

  return async function hostedSaasApi(req, res, url) {
    if (url.search || url.hash) {
      if (url.pathname.startsWith('/v1/')) { problem(res, 400); return true; }
      return false;
    }
    if (url.pathname === '/v1/setup-support/surveys' || url.pathname === '/v1/setup-support/events' || /^\/v1\/setup-support\/surveys\/diag_[A-Za-z0-9_-]{32}$/.test(url.pathname)) {
      if (!diagnostics) { problem(res, 503); return true; }
      await diagnostics(req, res, url);
      return true;
    }
    if (url.pathname === '/v1/support/account-token' || url.pathname === '/v1/support/tokens' || /^\/v1\/support\/tokens\/sat_[A-Za-z0-9_-]{32}$/.test(url.pathname)) {
      if (!supportTokenHandler) { problem(res, 503); return true; }
      await supportTokenHandler(req, res, url);
      return true;
    }
    if (url.pathname === '/v1/internal/operational-health/alerts') {
      if (!operationalHealthService) { problem(res, 503); return true; }
      if (req.method !== 'GET' || !internalBearerAuthorized(req, operationsApiToken)) { problem(res, 404); return true; }
      try { reply(res, 200, { alerts: await operationalHealthService.listAlerts({ status: 'open' }) }); }
      catch { problem(res, 503); }
      return true;
    }
    let internalMatch = /^\/v1\/internal\/operational-health\/deployments\/(dpl_[A-Za-z0-9_-]{32})$/.exec(url.pathname);
    if (internalMatch) {
      if (!operationalHealthService) { problem(res, 503); return true; }
      if (req.method !== 'GET' || !internalBearerAuthorized(req, operationsApiToken)) { problem(res, 404); return true; }
      try {
        const since = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
        reply(res, 200, { samples: await operationalHealthService.recentDeploymentSamples({ deploymentId: internalMatch[1], since, limit: 2016 }) });
      } catch { problem(res, 404); }
      return true;
    }
    if (url.pathname === '/v1/setup-sessions' || url.pathname === '/v1/setup-sessions/active' || url.pathname === '/v1/setup-sessions/reset' || url.pathname === '/v1/setup-sessions/connect' || url.pathname === '/v1/setup-sessions/failures' || url.pathname === '/v1/setup-sessions/claim' || /^\/v1\/setup-sessions\/[A-Za-z0-9_-]{16,128}(?:\/(?:prove|phases|bootstrap-key|diagnostics))?$/.test(url.pathname)) {
      await setup(req, res);
      return true;
    }

    if (url.pathname === '/v1/cli-authorizations') {
      if (!cliAuthorizationAuthority || req.method !== 'POST') { problem(res, 404); return true; }
      try {
        const body = await readJson(req, 4096);
        reply(res, 201, await cliAuthorizationAuthority.create({
          codeChallenge: body.code_challenge, redirectUri: body.redirect_uri, state: body.state,
          deploymentPublicKeySpkiPem: body.deployment_public_key_spki_pem, installationScope: body.installation_scope
        }));
      } catch (error) {
        logCliAuthorizationFailure(logger, 'create', error);
        problem(res, /capacity/i.test(error.message) ? 429 : 400);
      }
      return true;
    }
    if (url.pathname === '/v1/cli-authorizations/exchange') {
      if (!cliAuthorizationAuthority || req.method !== 'POST') { problem(res, 404); return true; }
      let requestId = null;
      try {
        const body = await readJson(req, 4096);
        requestId = body.request_id;
        reply(res, 200, await cliAuthorizationAuthority.exchange({ requestId: body.request_id, code: body.code, codeVerifier: body.code_verifier }));
      } catch (error) {
        logCliAuthorizationFailure(logger, 'exchange', error, requestId);
        problem(res, 400);
      }
      return true;
    }
    let match = /^\/v1\/cli-authorizations\/(cla_[A-Za-z0-9_-]{32})(?:\/approve)?$/.exec(url.pathname);
    if (match) {
      if (!cliAuthorizationAuthority) { problem(res, 404); return true; }
      const approving = url.pathname.endsWith('/approve');
      if ((!approving && req.method !== 'GET') || (approving && req.method !== 'POST')) { problem(res, 404); return true; }
      try {
        if (!approving) return reply(res, 200, await cliAuthorizationAuthority.describe({ requestId: match[1] })), true;
        const principal = await authenticateBrowser(req);
        if (!principal) return problem(res, 401), true;
        const body = await readJson(req, 1024);
        reply(res, 200, await cliAuthorizationAuthority.approve({ requestId: match[1], tenantId: principal.tenantId, userId: principal.userId, email: principal.email, verificationCode: body.verification_code }));
      } catch (error) {
        logCliAuthorizationFailure(logger, approving ? 'approve' : 'describe', error, match[1]);
        problem(res, /active network/i.test(error.message) ? 409 : 400);
      }
      return true;
    }

    match = /^\/v1\/operational-health\/(dpl_[A-Za-z0-9_-]{32})$/.exec(url.pathname);
    if (match) {
      if (!operationalHealthService) { problem(res, 503); return true; }
      if (req.method !== 'POST') { problem(res, 404); return true; }
      const credential = strictBearer(req);
      if (!credential) { problem(res, 401); return true; }
      try {
        const principal = await setupAuthority.authenticateConsoleCredential({ deploymentId: match[1], credential });
        const batch = await readJson(req, MAXIMUM_OPERATIONAL_BATCH_BYTES);
        if (typeof batch.batchId !== 'string' || req.headers?.['idempotency-key'] !== batch.batchId || req.headers?.['x-lookout-batch-id'] !== batch.batchId || !Array.isArray(batch.events) || batch.events.length !== 1 || !Number.isSafeInteger(batch.firstSequence) || batch.firstSequence !== batch.lastSequence || batch.batchId !== batchIdFor([{ sequence: batch.firstSequence, event: batch.events[0] }])) return problem(res, 400), true;
        const result = await operationalHealthService.acceptSnapshot(principal, batch.events[0]);
        reply(res, 202, result);
      } catch (error) {
        if (/credential/i.test(error.message)) problem(res, 401);
        else problem(res, error.status || 400);
      }
      return true;
    }

    match = /^\/v1\/console-sync\/(dpl_[A-Za-z0-9_-]{32})$/.exec(url.pathname);
    if (match) {
      if (req.method !== 'POST' && req.method !== 'DELETE') { problem(res, 404); return true; }
      const credential = strictBearer(req);
      if (!credential) { problem(res, 401); return true; }
      try {
        const principal = await setupAuthority.authenticateConsoleCredential({ deploymentId: match[1], credential });
        if (req.method === 'DELETE') {
          if (req.headers?.['content-length'] !== undefined && req.headers['content-length'] !== '0') return problem(res, 400), true;
          const result = await consoleStore.markUninstalled(principal);
          await operationalHealthService?.deleteDeployment?.(principal);
          reply(res, 200, result);
          return true;
        }
        const batch = await readJson(req, MAXIMUM_SNAPSHOT_BATCH_BYTES);
        const idempotency = req.headers?.['idempotency-key'];
        if (typeof idempotency !== 'string' || idempotency !== batch.batchId || req.headers?.['x-lookout-batch-id'] !== batch.batchId) return problem(res, 400), true;
        const result = await consoleStore.acceptBatch(principal, batch);
        await setupAuthority.cancelRecovery({ tenantId: principal.tenantId, deploymentId: principal.deploymentId });
        reply(res, 202, result);
      } catch (error) {
        if (/credential/i.test(error.message)) problem(res, 401);
        else if (/sequence conflict|tenant mismatch/i.test(error.message)) problem(res, 409);
        else problem(res, error.status || 400);
      }
      return true;
    }

    match = /^\/v1\/deployments\/(dpl_[A-Za-z0-9_-]{32})\/snapshot$/.exec(url.pathname);
    if (match) {
      if (req.method !== 'GET') { problem(res, 404); return true; }
      try {
        const principal = await authenticateBrowser(req);
        if (!principal) return problem(res, 401), true;
        await setupAuthority.authorizeBrowserDeployment({ tenantId: principal.tenantId, deploymentId: match[1] });
        reply(res, 200, await consoleStore.snapshot({ tenantId: principal.tenantId, deploymentId: match[1] }));
      } catch { problem(res, 404); }
      return true;
    }

    match = /^\/v1\/deployments\/(dpl_[A-Za-z0-9_-]{32})\/alerts\/([^/]{1,768})$/.exec(url.pathname);
    if (match) {
      if (req.method !== 'PATCH') { problem(res, 404); return true; }
      try {
        const principal = await authenticateBrowser(req);
        if (!principal) return problem(res, 401), true;
        await setupAuthority.authorizeBrowserDeployment({ tenantId: principal.tenantId, deploymentId: match[1] });
        const alertId = decodeURIComponent(match[2]);
        const input = await readJson(req, 64 * 1024);
        if (Object.keys(input).some((key) => !['status', 'reason'].includes(key))) return problem(res, 400), true;
        const actor = principal.email || principal.displayName || principal.userId;
        reply(res, 200, await consoleStore.updateAlert({ tenantId: principal.tenantId, deploymentId: match[1] }, alertId, { status: input.status, reason: input.reason, actor }));
      } catch (error) {
        if (/unavailable/i.test(error.message)) problem(res, 404);
        else problem(res, error.status || 400);
      }
      return true;
    }

    if (url.pathname === '/v1/deployments') {
      if (req.method !== 'GET') { problem(res, 404); return true; }
      try {
        const principal = await authenticateBrowser(req);
        if (!principal) return problem(res, 401), true;
        await recoveryMonitor?.sweep();
        const deployments = await consoleStore.listDeployments({ tenantId: principal.tenantId });
        for (const deployment of deployments) {
          if (deployment.status !== 'central_missing') continue;
          const recovery = await setupAuthority.browserRecovery({ tenantId: principal.tenantId, deploymentId: deployment.deployment_id });
          if (recovery) deployment.recovery = recovery;
        }
        reply(res, 200, { deployments });
      } catch { problem(res, 503); }
      return true;
    }

    if (url.pathname === '/v1/me') {
      if (req.method !== 'GET') { problem(res, 404); return true; }
      const principal = await authenticateBrowser(req);
      if (!principal) problem(res, 401);
      else reply(res, 200, { id: principal.userId, email: principal.email, displayName: principal.displayName || null, avatarUrl: principal.avatarUrl || null });
      return true;
    }
    if (url.pathname === '/v1/rules') {
      if (req.method !== 'GET') { problem(res, 404); return true; }
      const principal = await authenticateBrowser(req);
      if (!principal) problem(res, 401);
      else reply(res, 200, analytics.map(({ id, title, severity, enabled }) => ({ id, title, severity, enabled: enabled !== false })));
      return true;
    }
    if (url.pathname === '/v1/account') {
      if (req.method !== 'DELETE') { problem(res, 404); return true; }
      let principal;
      try { principal = await authenticateBrowser(req); } catch { principal = null; }
      if (!principal) { problem(res, 401); return true; }
      let input;
      try { input = await readJson(req, 1024); } catch (error) { problem(res, error.status || 400); return true; }
      if (input.confirmation !== 'DELETE' || Object.keys(input).length !== 1) { problem(res, 400); return true; }
      try {
        await deleteAccount(principal);
        reply(res, 200, { deleted: true });
      } catch { problem(res, 503); }
      return true;
    }
    return false;
  };
}

module.exports = { createHostedSaasApi, readHostedJson: readJson, MAXIMUM_SNAPSHOT_BATCH_BYTES, MAXIMUM_OPERATIONAL_BATCH_BYTES, internalBearerAuthorized };

'use strict';

const http = require('node:http');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');

const REQUEST_ID = /^cla_[A-Za-z0-9_-]{32}$/;
const SETUP_TOKEN = /^(?:lst|lrc)_[A-Za-z0-9_-]{43}$/;

function baseOrigin(value, { allowInsecureLoopback = false } = {}) {
  let url;
  try { url = new URL(value); } catch { throw new Error('Lookout SaaS URL is invalid'); }
  const loopback = allowInsecureLoopback && url.protocol === 'http:' && ['127.0.0.1', 'localhost'].includes(url.hostname);
  if ((!loopback && url.protocol !== 'https:') || url.username || url.password || url.search || url.hash || (url.pathname !== '/' && url.pathname !== '')) throw new Error('Lookout SaaS URL must be an HTTPS origin');
  return url;
}

async function requestJson(origin, path, { method = 'GET', body, fetchImpl = globalThis.fetch, timeoutMs = 15000 } = {}) {
  const url = new URL(path, origin);
  if (url.origin !== origin.origin) throw new Error('CLI authorization request may not change origin');
  const response = await fetchImpl(url, {
    method, redirect: 'error', signal: AbortSignal.timeout(timeoutMs),
    headers: { Accept: 'application/json', ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
    body: body === undefined ? undefined : JSON.stringify(body)
  });
  if (!/^application\/json(?:\s*;|$)/i.test(response.headers.get('content-type') || '')) throw new Error('Lookout SaaS returned an invalid CLI authorization response');
  const text = await response.text();
  if (Buffer.byteLength(text) > 64 * 1024) throw new Error('Lookout SaaS CLI authorization response is too large');
  let value;
  try { value = JSON.parse(text); } catch { throw new Error('Lookout SaaS returned invalid CLI authorization JSON'); }
  if (!response.ok) throw new Error(`Lookout CLI authorization failed with status ${response.status}`);
  return value;
}

function openBrowser(url, { spawnImpl = spawn, platform = process.platform } = {}) {
  const command = platform === 'darwin' ? 'open' : platform === 'win32' ? 'cmd' : 'xdg-open';
  const args = platform === 'win32' ? ['/c', 'start', '', url] : [url];
  const child = spawnImpl(command, args, { detached: true, stdio: 'ignore' });
  child.unref?.();
}

function formatAuthorizationPrompt(url, { verificationCode } = {}, { color = Boolean(process.stdout.isTTY) && !process.env.NO_COLOR } = {}) {
  const paint = (code, text) => color ? `\x1b[${code}m${text}\x1b[0m` : text;
  const rule = paint('2', '────────────────────────────────────────');
  return [
    '',
    rule,
    `  ${paint('1', 'Lookout login')}`,
    '',
    `  Verification code: ${paint('1;33', verificationCode)}`,
    '',
    '  Verification page:',
    `  ${paint('4;36', url)}`,
    '',
    '  Input the verification code in the browser to authorize this login.',
    rule,
    ''
  ].join('\n');
}

function callbackHtml() {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Lookout login complete</title><style>
:root{color-scheme:light}*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;background:#f2e8cd;color:#17382d;font-family:Arial,sans-serif}.card{width:min(420px,100%);padding:42px 38px;background:#f8efd7;border:1px solid rgba(60,69,43,.48);box-shadow:inset 0 0 0 4px rgba(117,91,50,.08),0 20px 55px rgba(48,65,43,.14)}.mark{display:block;width:34px;height:34px;margin-bottom:22px;border-radius:50% 50% 44% 44%;background:#a65e30}h1{margin:0 0 12px;font-size:38px;font-weight:400;letter-spacing:-.04em;line-height:1.05}p{margin:0;color:rgba(23,56,45,.72);font-size:14px;line-height:1.55}
</style></head><body><main class="card"><span class="mark" aria-hidden="true"></span><h1>Login complete</h1><p>Return to your terminal. You can close this window.</p></main></body></html>`;
}

function callbackServer({ state, timeoutMs = 10 * 60 * 1000 } = {}) {
  if (typeof state !== 'string') throw new Error('CLI login state is required');
  let server;
  let timer;
  function close({ force = false } = {}) {
    clearTimeout(timer);
    try { server?.close(); } catch { /* The listener may already be closed. */ }
    server?.closeIdleConnections?.();
    if (force) server?.closeAllConnections?.();
    return Promise.resolve();
  }
  const result = new Promise((resolve, reject) => {
    server = http.createServer((req, res) => {
      let url;
      try { url = new URL(req.url, 'http://127.0.0.1'); } catch { res.writeHead(400).end(); return; }
      if (req.method !== 'GET' || url.pathname !== '/callback' || url.searchParams.get('state') !== state || !url.searchParams.get('code')) { res.writeHead(400).end('Invalid Lookout login callback.'); return; }
      const code = url.searchParams.get('code');
      const body = callbackHtml();
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Content-Length': Buffer.byteLength(body), 'Cache-Control': 'no-store', 'Connection': 'close', 'X-Content-Type-Options': 'nosniff', 'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'" });
      res.once('finish', () => {
        resolve(code);
        close();
      });
      res.end(body);
    });
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      timer = setTimeout(() => {
        reject(new Error('Lookout login timed out'));
        close({ force: true });
      }, timeoutMs);
      timer.unref?.();
    });
  });
  return {
    result,
    address: () => {
      const address = server.address();
      if (!address || typeof address === 'string') throw new Error('CLI login callback is not ready');
      return `http://127.0.0.1:${address.port}/callback`;
    },
    ready: new Promise((resolve, reject) => { server.once('listening', resolve); server.once('error', reject); }),
    close: () => close({ force: true })
  };
}

async function login({ origin: originValue, deploymentIdentity, installationScope, fetchImpl = globalThis.fetch, browserOpener = openBrowser, callbackFactory = callbackServer, timeoutMs = 10 * 60 * 1000, allowInsecureLoopback = false, onUrl, onAuthorization } = {}) {
  const origin = baseOrigin(originValue, { allowInsecureLoopback });
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier, 'utf8').digest('base64url');
  const state = crypto.randomBytes(32).toString('base64url');
  const callback = callbackFactory({ state, timeoutMs });
  try {
    await callback.ready;
    const created = await requestJson(origin, '/v1/cli-authorizations', {
      method: 'POST', fetchImpl, body: {
        code_challenge: challenge, redirect_uri: callback.address(), state,
        deployment_public_key_spki_pem: deploymentIdentity?.publicKeyPem,
        installation_scope: installationScope
      }
    });
    if (!REQUEST_ID.test(created.request_id || '') || !/^dpl_[A-Za-z0-9_-]{32}$/.test(created.deployment_id || '')) throw new Error('Lookout SaaS returned an invalid CLI authorization');
    if (!/^\d{8}$/.test(created.verification_code || '') || !/^[A-Za-z0-9_-]{43}$/.test(created.installation_scope_digest || '') || !/^SHA256:/.test(created.deployment_key_fingerprint || '')) throw new Error('Lookout SaaS returned an invalid CLI authorization binding');
    const authorizationUrl = new URL('/cli-login', origin);
    authorizationUrl.searchParams.set('request', created.request_id);
    await onAuthorization?.({ deploymentId: created.deployment_id, expiresAt: created.expires_at, origin: origin.origin, scopeDigest: created.installation_scope_digest, keyFingerprint: created.deployment_key_fingerprint });
    onUrl?.(authorizationUrl.toString(), {
      verificationCode: created.verification_code,
      installationScope
    });
    browserOpener(authorizationUrl.toString());
    const code = await callback.result;
    const exchanged = await requestJson(origin, '/v1/cli-authorizations/exchange', {
      method: 'POST', fetchImpl, body: { request_id: created.request_id, code, code_verifier: verifier }
    });
    if (!SETUP_TOKEN.test(exchanged.setup_token || '') || Number.isNaN(Date.parse(exchanged.expires_at)) || exchanged.deployment_id !== created.deployment_id) throw new Error('Lookout SaaS returned an invalid installation permission');
    return {
      setupToken: exchanged.setup_token, expiresAt: exchanged.expires_at, origin: origin.origin,
      scopeDigest: created.installation_scope_digest, keyFingerprint: created.deployment_key_fingerprint, deploymentId: created.deployment_id
    };
  } finally {
    await callback.close().catch(() => {});
  }
}

module.exports = { login, openBrowser, callbackServer, callbackHtml, baseOrigin, requestJson, formatAuthorizationPrompt };

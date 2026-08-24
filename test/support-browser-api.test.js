'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { Readable } = require('node:stream');
const { InMemorySupportStore } = require('../src/support/conversation-store');
const { SupportAccessTokenAuthority } = require('../src/support/access-token-authority');
const { createSupportTokenHttpHandler } = require('../src/support/token-http');
const { DataProtector } = require('../src/security/data-protector');

function request(method, path, body, principal) { const bytes = body === undefined ? Buffer.alloc(0) : Buffer.from(JSON.stringify(body)); const req = Readable.from(bytes.length ? [bytes] : []); req.method = method; req.url = path; req.headers = {}; req.principal = principal; if (body !== undefined) { req.headers['content-type'] = 'application/json'; req.headers['content-length'] = String(bytes.length); } return req; }
function response() { return { status: 0, headers: {}, body: '', writeHead(status, headers) { this.status = status; this.headers = headers; }, end(body) { this.body = String(body || ''); }, json() { return JSON.parse(this.body); } }; }
async function invoke(handler, req) { const res = response(); assert.equal(await handler(req, res, new URL(req.url, 'https://app.devlookout.com')), true); return res; }

test('browser token API requires auth and never lists plaintext or digests', async () => {
  const store = new InMemorySupportStore(); const authority = new SupportAccessTokenAuthority({ store });
  const handler = createSupportTokenHttpHandler({ tokenAuthority: authority, authenticateBrowser: async (req) => req.principal });
  const principal = { tenantId: 'tenant-a', userId: 'user-a', email: 'a@example.test' };
  assert.equal((await invoke(handler, request('GET', '/v1/support/tokens'))).status, 401);
  const createdResponse = await invoke(handler, request('POST', '/v1/support/tokens', { name: 'Codex' }, principal));
  assert.equal(createdResponse.status, 201);
  const created = createdResponse.json(); assert.match(created.token, /^lsp_/);
  const listedText = (await invoke(handler, request('GET', '/v1/support/tokens', undefined, principal))).body;
  assert.doesNotMatch(listedText, /lsp_|digest/i);
  assert.equal((await invoke(handler, request('DELETE', `/v1/support/tokens/${created.id}`, undefined, { tenantId: 'other', userId: 'other', email: 'o@example.test' }))).status, 404);
  assert.equal((await invoke(handler, request('DELETE', `/v1/support/tokens/${created.id}`, undefined, principal))).status, 200);
});

test('browser account token API returns the same encrypted-at-rest token to its authenticated owner', async () => {
  const store = new InMemorySupportStore();
  const authority = new SupportAccessTokenAuthority({ store, protector: new DataProtector(Buffer.alloc(32, 4)) });
  const handler = createSupportTokenHttpHandler({ tokenAuthority: authority, authenticateBrowser: async (req) => req.principal });
  const principal = { tenantId: 'tenant-a', userId: 'user-a', email: 'a@example.test' };
  assert.equal((await invoke(handler, request('GET', '/v1/support/account-token'))).status, 401);
  const first = (await invoke(handler, request('GET', '/v1/support/account-token', undefined, principal))).json();
  const second = (await invoke(handler, request('GET', '/v1/support/account-token', undefined, principal))).json();
  assert.match(first.token, /^lsp_[A-Za-z0-9_-]{43}$/);
  assert.equal(second.token, first.token);
  assert.equal((await invoke(handler, request('POST', '/v1/support/account-token', {}, principal))).status, 404);
  assert.doesNotMatch(JSON.stringify(store.tokens.get(first.id)), new RegExp(first.token));
});

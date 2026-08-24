'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { Readable } = require('node:stream');
const { SetupSessionAuthority } = require('../src/onboarding/setup-session-authority');
const { createSetupSessionHttpHandler, MAXIMUM_JSON_BYTES } = require('../src/onboarding/setup-session-http');
const { createProofMessage } = require('../src/onboarding/setup-session-client');

function request(method, url, body, headers = {}) {
  const bytes = body === undefined ? Buffer.alloc(0) : Buffer.from(typeof body === 'string' ? body : JSON.stringify(body));
  const req = Readable.from(bytes.length ? [bytes] : []);
  req.method = method;
  req.url = url;
  req.headers = { ...headers };
  if (body !== undefined) {
    req.headers['content-type'] ||= 'application/json';
    req.headers['content-length'] ||= String(bytes.length);
  }
  return req;
}

function response() {
  return {
    status: null,
    headers: null,
    body: '',
    writeHead(status, headers) { this.status = status; this.headers = headers; },
    end(body) { this.body = String(body || ''); },
    json() { return JSON.parse(this.body); }
  };
}

async function invoke(handler, req) {
  const res = response();
  await handler(req, res);
  assert.equal(res.headers['Cache-Control'], 'no-store');
  assert.match(res.headers['Content-Type'], /^application\/json/);
  return res;
}

function makeAuthority() {
  const provisioned = [];
  const authority = new SetupSessionAuthority({
    provisioningFactory: async (context) => {
      provisioned.push(context);
      return {
        console_sync: { endpoint: `https://sync.example.test/${context.deploymentId}`, credential: crypto.randomBytes(32).toString('base64url') },
        dashboard_url: `https://console.example.test/${context.deploymentId}`
      };
    }
  });
  return { authority, provisioned };
}

function makeHandler(authority) {
  return createSetupSessionHttpHandler({
    authority,
    authenticateBrowser: async (req) => req.browserPrincipal || null
  });
}

test('browser creation uses only authenticated tenant context and rejects body identity', async () => {
  const { authority } = makeAuthority();
  const handler = makeHandler(authority);
  const unauthenticated = await invoke(handler, request('POST', '/v1/setup-sessions', {}));
  assert.equal(unauthenticated.status, 401);
  assert.deepEqual(unauthenticated.json(), { error: 'unauthorized' });

  const forged = request('POST', '/v1/setup-sessions', { tenant_id: 'tenant-b' });
  forged.browserPrincipal = { tenantId: 'tenant-a', userId: 'owner-a' };
  const rejected = await invoke(handler, forged);
  assert.equal(rejected.status, 400);
  assert.equal(rejected.body.includes('tenant-b'), false);

  const valid = request('POST', '/v1/setup-sessions', {});
  valid.browserPrincipal = { tenantId: 'tenant-a', userId: 'owner-a' };
  const created = await invoke(handler, valid);
  assert.equal(created.status, 201);
  assert.match(created.json().setup_token, /^lst_[A-Za-z0-9_-]{43}$/);
  assert.equal(created.body.includes('tenant-a'), false);
});

test('old installer-created pairing routes are removed', async () => {
  const { authority } = makeAuthority();
  const handler = makeHandler(authority);
  const keys = crypto.generateKeyPairSync('ed25519');
  const publicKey = keys.publicKey.export({ type: 'spki', format: 'pem' }).toString('utf8');
  const initiatedResponse = await invoke(handler, request('POST', '/v1/setup-sessions', {
    deployment_identity: { public_key_spki_pem: publicKey }, client: { name: 'lookout', version: '0.1.0' }
  }));
  assert.equal(initiatedResponse.status, 400);
  assert.equal((await invoke(handler, request('POST', '/v1/setup-sessions/pair', { pairing_code: 'ABCD-2345' }))).status, 404);
});

test('HTTP routes connect, claim, prove, report, and read status without tenant input', async () => {
  const { authority, provisioned } = makeAuthority();
  const handler = makeHandler(authority);
  const createReq = request('POST', '/v1/setup-sessions', {});
  createReq.browserPrincipal = { tenantId: 'tenant-a', userId: 'owner-a' };
  const created = (await invoke(handler, createReq)).json();
  const activeRequest = request('GET', '/v1/setup-sessions/active');
  activeRequest.browserPrincipal = { tenantId: 'tenant-a', userId: 'owner-a' };
  assert.deepEqual((await invoke(handler, activeRequest)).json(), { setup: null });
  const browserStatus = request('GET', `/v1/setup-sessions/${created.session_id}`);
  browserStatus.browserPrincipal = { tenantId: 'tenant-a', userId: 'owner-a' };
  assert.equal((await invoke(handler, browserStatus)).json().status, 'pending');
  assert.deepEqual((await invoke(handler, request('POST', '/v1/setup-sessions/connect', { setup_token: created.setup_token }))).json(), { accepted: true });
  const active = (await invoke(handler, activeRequest)).json();
  assert.equal(active.setup.session_id, created.session_id);
  assert.equal(active.setup.status, 'connected');
  assert.equal((await invoke(handler, browserStatus)).json().status, 'connected');
  const resetRequest = request('POST', '/v1/setup-sessions/reset', {});
  resetRequest.browserPrincipal = { tenantId: 'tenant-a', userId: 'owner-a' };
  assert.deepEqual((await invoke(handler, resetRequest)).json(), { dismissed: 0 });
  const keys = crypto.generateKeyPairSync('ed25519');
  const publicKey = keys.publicKey.export({ type: 'spki', format: 'pem' }).toString('utf8');
  const claimedResponse = await invoke(handler, request('POST', '/v1/setup-sessions/claim', {
    setup_token: created.setup_token,
    deployment_identity: { public_key_spki_pem: publicKey },
    installation_scope: { central_vm_id: 'vm-central', vms: [{ id: 'vm-central', local: true }] }
  }));
  assert.equal(claimedResponse.status, 200);
  const claimed = claimedResponse.json();
  const auth = { authorization: `Bearer ${claimed.session_token}` };

  assert.equal((await invoke(handler, request('GET', `/v1/setup-sessions/${claimed.session_id}`, undefined, auth))).json().status, 'claimed');
  const signature = crypto.sign(null, createProofMessage(claimed.session_id, claimed.challenge), keys.privateKey).toString('base64url');
  const proved = await invoke(handler, request('POST', `/v1/setup-sessions/${claimed.session_id}/prove`, { signature_base64url: signature }, auth));
  assert.equal(proved.json().verified, true);
  assert.equal(provisioned[0].tenantId, 'tenant-a');
  assert.equal(proved.body.includes('tenant-a'), false);
  const bootstrapKey = { authorized_keys_line: `restrict ssh-ed25519 ${Buffer.alloc(32, 4).toString('base64')} lookout-bootstrap:test`, fingerprint: `SHA256:${Buffer.alloc(24, 5).toString('base64').replace(/=+$/, '')}` };
  assert.equal((await invoke(handler, request('POST', `/v1/setup-sessions/${claimed.session_id}/bootstrap-key`, bootstrapKey, auth))).json().accepted, true);
  const visibleRequest = request('GET', `/v1/setup-sessions/${claimed.session_id}`);
  visibleRequest.browserPrincipal = { tenantId: 'tenant-a', userId: 'owner-a' };
  const visible = (await invoke(handler, visibleRequest)).json();
  assert.deepEqual(visible.bootstrap_key, bootstrapKey);
  const phase = await invoke(handler, request('POST', `/v1/setup-sessions/${claimed.session_id}/phases`, { phase: 'installing' }, auth));
  assert.deepEqual(phase.json(), { accepted: true });
  assert.equal((await invoke(handler, request('POST', `/v1/setup-sessions/${claimed.session_id}/resume`, { signature_base64url: 'removed' }))).status, 404);
});

test('pre-claim failure endpoint is allowlisted and invalid tokens receive a generic response', async () => {
  const { authority } = makeAuthority();
  const handler = makeHandler(authority);
  const createReq = request('POST', '/v1/setup-sessions', {});
  createReq.browserPrincipal = { tenantId: 'tenant-a', userId: 'owner-a' };
  const created = (await invoke(handler, createReq)).json();
  await invoke(handler, request('POST', '/v1/setup-sessions/connect', { setup_token: created.setup_token }));
  assert.deepEqual((await invoke(handler, request('POST', '/v1/setup-sessions/failures', { setup_token: created.setup_token, code: 'artifact_checksum' }))).json(), { accepted: true });
  const browserStatus = request('GET', `/v1/setup-sessions/${created.session_id}`);
  browserStatus.browserPrincipal = { tenantId: 'tenant-a', userId: 'owner-a' };
  assert.equal((await invoke(handler, browserStatus)).json().status, 'failed');
  const invalidToken = `lst_${'z'.repeat(43)}`;
  const rejected = await invoke(handler, request('POST', '/v1/setup-sessions/failures', { setup_token: invalidToken, code: 'cloud_discovery' }));
  assert.equal(rejected.status, 404);
  assert.deepEqual(rejected.json(), { error: 'not_found' });
  assert.equal(rejected.body.includes(invalidToken), false);
  const reflected = await invoke(handler, request('POST', '/v1/setup-sessions/failures', { setup_token: created.setup_token, code: 'local error: secret' }));
  assert.equal(reflected.status, 404);
  assert.equal(reflected.body.includes('secret'), false);
});

test('protected routes require a strict bearer header', async () => {
  const { authority } = makeAuthority();
  const handler = makeHandler(authority);
  const id = `set_${'a'.repeat(24)}`;
  for (const authorization of [undefined, 'Basic abc', 'bearer abc', 'Bearer short', 'Bearer one two']) {
    const headers = authorization ? { authorization } : {};
    const result = await invoke(handler, request('POST', `/v1/setup-sessions/${id}/phases`, { phase: 'installing' }, headers));
    assert.equal(result.status, 401);
    assert.equal(result.headers['WWW-Authenticate'], 'Bearer');
  }
});

test('active setup recovery requires the authenticated account', async () => {
  const { authority } = makeAuthority();
  const handler = makeHandler(authority);
  assert.equal((await invoke(handler, request('GET', '/v1/setup-sessions/active'))).status, 401);
});

test('the authenticated browser can poll its own setup and receives redirect only after completion', async () => {
  const { authority } = makeAuthority();
  const handler = makeHandler(authority);
  const createReq = request('POST', '/v1/setup-sessions', {});
  createReq.browserPrincipal = { tenantId: 'tenant-a', userId: 'owner-a' };
  const created = (await invoke(handler, createReq)).json();
  const pending = request('GET', `/v1/setup-sessions/${created.session_id}`);
  pending.browserPrincipal = { tenantId: 'tenant-a', userId: 'owner-a' };
  assert.deepEqual((await invoke(handler, pending)).json().status, 'pending');
  const wrongTenant = request('GET', `/v1/setup-sessions/${created.session_id}`);
  wrongTenant.browserPrincipal = { tenantId: 'tenant-b', userId: 'owner-a' };
  assert.equal((await invoke(handler, wrongTenant)).status, 401);
});

test('methods, content types, JSON shape, and query strings are strict', async () => {
  const { authority } = makeAuthority();
  const handler = makeHandler(authority);
  const cases = [
    request('GET', '/v1/setup-sessions', undefined),
    request('POST', '/v1/setup-sessions/claim?tenant=x', {}),
    request('POST', '/v1/setup-sessions/claim', '{}', { 'content-type': 'text/plain' }),
    request('POST', '/v1/setup-sessions/claim', '[]'),
    request('POST', '/v1/setup-sessions/claim', '{')
  ];
  const expected = [404, 400, 400, 400, 400];
  for (let index = 0; index < cases.length; index += 1) {
    const result = await invoke(handler, cases[index]);
    assert.equal(result.status, expected[index]);
  }
});

test('JSON bodies are bounded at 32 KiB before parsing', async () => {
  const { authority } = makeAuthority();
  const handler = makeHandler(authority);
  const declared = request('POST', '/v1/setup-sessions/claim', '{}', { 'content-length': String(MAXIMUM_JSON_BYTES + 1) });
  assert.equal((await invoke(handler, declared)).status, 400);
  const streamed = request('POST', '/v1/setup-sessions/claim', JSON.stringify({ padding: 'x'.repeat(MAXIMUM_JSON_BYTES) }));
  delete streamed.headers['content-length'];
  assert.equal((await invoke(handler, streamed)).status, 400);
});

test('errors are generic and never reflect codes, tenant values, or internals', async () => {
  const { authority } = makeAuthority();
  const handler = makeHandler(authority);
  const keys = crypto.generateKeyPairSync('ed25519');
  const publicKey = keys.publicKey.export({ type: 'spki', format: 'pem' }).toString('utf8');
  const code = 'SECRET-CODE-2345';
  const result = await invoke(handler, request('POST', '/v1/setup-sessions/claim', { setup_code: code, deployment_identity: { public_key_spki_pem: publicKey } }));
  assert.equal(result.status, 404);
  assert.deepEqual(result.json(), { error: 'not_found' });
  assert.equal(result.body.includes(code), false);
  const token = `lst_${'a'.repeat(43)}`;
  const connected = await invoke(handler, request('POST', '/v1/setup-sessions/connect', { setup_token: token }));
  assert.equal(connected.status, 404);
  assert.deepEqual(connected.json(), { error: 'not_found' });
  assert.equal(connected.body.includes(token), false);
});

test('authority rate exhaustion is exposed only as a generic 429', async () => {
  const authority = new SetupSessionAuthority({
    maxClaimsPerWindow: 1,
    maxAttemptHistory: 1,
    provisioningFactory: async () => ({
      console_sync: { endpoint: 'https://sync.example.test/', credential: 'x'.repeat(32) },
      dashboard_url: 'https://console.example.test/'
    })
  });
  const handler = makeHandler(authority);
  const keys = crypto.generateKeyPairSync('ed25519');
  const publicKey = keys.publicKey.export({ type: 'spki', format: 'pem' }).toString('utf8');
  const payload = { setup_token: `lst_${'a'.repeat(43)}`, deployment_identity: { public_key_spki_pem: publicKey }, installation_scope: { central_vm_id: 'vm', vms: [{ id: 'vm', local: true }] } };
  await invoke(handler, request('POST', '/v1/setup-sessions/claim', payload));
  const limited = await invoke(handler, request('POST', '/v1/setup-sessions/claim', payload));
  assert.equal(limited.status, 429);
  assert.deepEqual(limited.json(), { error: 'rate_limited' });
});

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const http = require('node:http');
const { login, callbackServer, callbackHtml, formatAuthorizationPrompt } = require('../src/onboarding/cli-authorization-client');

const deploymentIdentity = { publicKeyPem: crypto.generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' }) };
const installationScope = { central_vm_id: 'api-1', vms: [{ id: 'api-1', name: 'api-1', address: '10.0.1.10', platform: 'linux', provider: 'openssh', local: false }] };

test('CLI login uses a loopback callback and PKCE without exposing the verifier in the browser URL', async () => {
  const requests = [];
  let opened;
  let displayedBinding;
  const callback = {
    ready: Promise.resolve(), address: () => 'http://127.0.0.1:43123/callback',
    result: Promise.resolve('authorization-code-value-abcdefghijklmnopqrstuvwxyz'),
    close: async () => {}
  };
  const result = await login({
    origin: 'http://127.0.0.1:3000', allowInsecureLoopback: true,
    deploymentIdentity, installationScope,
    onUrl: (_url, binding) => { displayedBinding = binding; },
    callbackFactory: () => callback, browserOpener: (url) => { opened = url; },
    fetchImpl: async (url, options) => {
      const body = JSON.parse(options.body);
      requests.push({ url: String(url), body });
      if (String(url).endsWith('/v1/cli-authorizations')) return new Response(JSON.stringify({ request_id: `cla_${'r'.repeat(32)}`, deployment_id: `dpl_${'d'.repeat(32)}`, expires_at: '2026-08-22T13:00:00.000Z', verification_code: '12345678', installation_scope_digest: 'd'.repeat(43), deployment_key_fingerprint: 'SHA256:test' }), { status: 201, headers: { 'content-type': 'application/json' } });
      return new Response(JSON.stringify({ setup_token: `lst_${'s'.repeat(43)}`, deployment_id: `dpl_${'d'.repeat(32)}`, expires_at: '2026-08-22T13:00:00.000Z' }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
  });
  assert.match(opened, /\/cli-login\?request=cla_/);
  assert.equal(opened.includes(requests[1].body.code_verifier), false);
  assert.equal(requests[0].body.code_challenge, crypto.createHash('sha256').update(requests[1].body.code_verifier).digest('base64url'));
  assert.equal(requests[0].body.deployment_public_key_spki_pem, deploymentIdentity.publicKeyPem);
  assert.deepEqual(requests[0].body.installation_scope, installationScope);
  assert.deepEqual(displayedBinding, { verificationCode: '12345678', installationScope });
  assert.equal(result.setupToken, `lst_${'s'.repeat(43)}`);
  assert.equal(result.deploymentId, `dpl_${'d'.repeat(32)}`);
});

test('CLI authorization prompt shows the highlighted verification code and verification page link', () => {
  const url = 'https://app.example/cli-login?request=test';
  const binding = {
    verificationCode: '12345678',
    installationScope: {
      central_vm_id: 'api-1',
      vms: [
        { id: 'api-1', name: 'api-1', address: '10.0.1.10' },
        { id: 'db-1', name: 'db-1', address: '10.0.1.11' }
      ]
    }
  };
  const plain = formatAuthorizationPrompt(url, binding, { color: false });
  assert.match(plain, /Lookout login/);
  assert.match(plain, /Verification code: 12345678/);
  assert.match(plain, /Verification page:/);
  assert.ok(plain.includes(url));
  assert.match(plain, /Input the verification code in the browser/);
  assert.doesNotMatch(plain, /\x1b\[/);
  assert.doesNotMatch(plain, /Selected VMs|Scope:|Deployment key:|expires/);
  const colored = formatAuthorizationPrompt(url, binding, { color: true });
  assert.ok(colored.includes('\x1b[1;33m12345678\x1b[0m'));
  assert.ok(colored.includes(`\x1b[4;36m${url}\x1b[0m`));
});

test('CLI login closes its callback listener when SaaS creation fails', async () => {
  let closed = false;
  const callback = {
    ready: Promise.resolve(), address: () => 'http://127.0.0.1:43123/callback',
    result: new Promise(() => {}), close: async () => { closed = true; }
  };
  await assert.rejects(login({
    origin: 'http://127.0.0.1:3000', allowInsecureLoopback: true,
    deploymentIdentity, installationScope,
    callbackFactory: () => callback, browserOpener: () => {},
    fetchImpl: async () => new Response('{}', { status: 503, headers: { 'content-type': 'application/json' } })
  }), /status 503/);
  assert.equal(closed, true);
});

test('CLI login completes without waiting for the browser connection to close', async (t) => {
  const state = 's'.repeat(32);
  const callback = callbackServer({ state, timeoutMs: 5000 });
  const agent = new http.Agent({ keepAlive: true });
  t.after(async () => { agent.destroy(); await callback.close(); });
  await callback.ready;
  const callbackUrl = new URL(callback.address());
  callbackUrl.searchParams.set('state', state);
  callbackUrl.searchParams.set('code', 'authorization-code');

  const response = await new Promise((resolve, reject) => {
    http.get(callbackUrl, { agent }, (value) => {
      value.resume();
      value.once('end', () => resolve(value));
    }).once('error', reject);
  });
  const code = await Promise.race([
    callback.result,
    new Promise((_, reject) => setTimeout(() => reject(new Error('callback remained blocked by browser connection')), 500))
  ]);

  assert.equal(response.statusCode, 200);
  assert.equal(response.headers.connection, 'close');
  assert.equal(code, 'authorization-code');
});

test('CLI login callback is a self-contained styled completion page', () => {
  const html = callbackHtml();
  assert.match(html, /<style>/);
  assert.match(html, /Login complete/);
  assert.match(html, /Return to your terminal/);
  assert.doesNotMatch(html, /<script|https?:\/\//);
});

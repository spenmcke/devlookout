'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { Readable } = require('node:stream');
const { mkdtemp, writeFile, chmod, rm } = require('node:fs/promises');
const { join } = require('node:path');
const { tmpdir } = require('node:os');
const { generateKeyPairSync, randomBytes, sign, verify } = require('node:crypto');
const {
  SetupSessionClient,
  readSetupTokenFromStream,
  readSetupTokenFromFile,
  createProofMessage
} = require('../src/onboarding/setup-session-client');

const deploymentKeys = generateKeyPairSync('ed25519');
const publicKey = deploymentKeys.publicKey.export({ format: 'pem', type: 'spki' }).toString('utf8');
const sessionId = 'session_abcdefghijklmnop';
const sessionToken = 'secret-session-token-abcdefghijklmnop';
const consoleCredential = 'console-sync-credential-abcdefghijklmnopqrstuvwxyz';
const challenge = randomBytes(32).toString('base64url');
const setupToken = `lst_${'a'.repeat(43)}`;
const installationScope = { central_vm_id: 'vm-central', vms: [{ id: 'vm-central', local: true }] };

function successfulClaim(overrides = {}) {
  return {
    session_id: sessionId,
    deployment_id: 'deployment_12345678',
    session_token: sessionToken,
    expires_at: '2026-08-19T20:00:00Z',
    challenge,
    installation_scope: installationScope,
    ...overrides
  };
}

function successfulProof(overrides = {}) {
  return {
    verified: true,
    provisioning: {
      console_sync: {
        endpoint: 'https://ingest.lookout.example/v1/console-sync',
        credential: consoleCredential
      },
      dashboard_url: 'https://app.lookout.example/deployments/deployment_12345678'
    },
    ...overrides
  };
}

function json(value, status = 200, headers = {}) {
  return new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json', ...headers } });
}

test('claim uses an account-bound setup token and submits the approved scope without tenant input', async () => {
  const requests = [];
  const client = new SetupSessionClient({
    baseUrl: 'https://setup.lookout.example',
    fetchImpl: async (url, options) => {
      requests.push({ url: String(url), options });
      return json(successfulClaim());
    }
  });

  const result = await client.claimSession({ setupTokenProvider: async () => setupToken, deploymentIdentity: { publicKeyPem: publicKey }, installationScope });
  assert.equal(result.deploymentId, 'deployment_12345678');
  assert.equal(result.challenge, challenge);
  assert.equal(result.provisioning, undefined);
  const request = requests[0];
  assert.equal(request.url, 'https://setup.lookout.example/v1/setup-sessions/claim');
  assert.equal(request.options.redirect, 'error');
  assert.ok(!request.url.includes(setupToken));
  assert.ok(!JSON.stringify(request.options.headers).includes(setupToken));
  const body = JSON.parse(request.options.body);
  assert.deepEqual(Object.keys(body).sort(), ['deployment_identity', 'installation_scope', 'setup_token']);
  assert.deepEqual(body.deployment_identity, { public_key_spki_pem: publicKey });
  assert.equal(body.setup_token, setupToken);
  assert.deepEqual(body.installation_scope, installationScope);
  assert.equal(body.tenant_id, undefined);
});

test('connect and pre-claim failure reports keep tokens out of URLs and allowlist codes locally', async () => {
  const requests = [];
  const client = new SetupSessionClient({
    baseUrl: 'https://setup.lookout.example',
    fetchImpl: async (url, options) => { requests.push({ url: String(url), options }); return json({ accepted: true }); }
  });
  await client.connectSession({ setupToken });
  await client.reportPreclaimFailure({ setupToken, code: 'artifact_checksum' });
  assert.deepEqual(requests.map((item) => item.url), [
    'https://setup.lookout.example/v1/setup-sessions/connect',
    'https://setup.lookout.example/v1/setup-sessions/failures'
  ]);
  assert.ok(requests.every((item) => !item.url.includes(setupToken) && !JSON.stringify(item.options.headers).includes(setupToken)));
  await assert.rejects(() => client.reportPreclaimFailure({ setupToken, code: 'secret local text' }), /invalid/);
  assert.equal(requests.length, 2);
});

test('installer diagnostics are allowlisted and keep the setup token out of URLs and headers', async () => {
  const requests = [];
  const client = new SetupSessionClient({
    baseUrl: 'https://setup.lookout.example',
    fetchImpl: async (url, options) => { requests.push({ url: String(url), options }); return json({ accepted: true, report_id: `diag_${'a'.repeat(32)}` }, 202); }
  });
  const result = await client.reportDiagnosticEvent({ setupToken, kind: 'failure', code: 'artifact_download', phase: 'bootstrap', platform: { os: 'linux' }, idempotencyKey: 'diagnostic_key_12345' });
  assert.equal(result.reportId, `diag_${'a'.repeat(32)}`);
  assert.equal(requests[0].url, 'https://setup.lookout.example/v1/setup-support/events');
  assert.ok(!requests[0].url.includes(setupToken));
  assert.ok(!JSON.stringify(requests[0].options.headers).includes(setupToken));
  assert.equal(JSON.parse(requests[0].options.body).setup_token, setupToken);
  await assert.rejects(client.reportDiagnosticEvent({ setupToken, kind: 'failure', code: 'raw error text', phase: 'bootstrap', platform: {}, idempotencyKey: 'diagnostic_key_12345' }), /invalid/);
});

test('session status and phase reports authenticate without placing credentials in URLs', async () => {
  const requests = [];
  const client = new SetupSessionClient({
    baseUrl: 'https://setup.lookout.example',
    fetchImpl: async (url, options) => {
      requests.push({ url: String(url), options });
      return options.method === 'POST' ? json({ accepted: true }) : json({ status: 'validating' });
    }
  });
  assert.deepEqual(await client.getStatus({ sessionId, sessionToken }), { status: 'validating' });
  assert.deepEqual(await client.reportPhase({ sessionId, sessionToken, phase: 'validating' }), { accepted: true });
  for (const request of requests) {
    assert.ok(!request.url.includes(sessionToken));
    assert.equal(request.options.headers.Authorization, `Bearer ${sessionToken}`);
    assert.equal(request.options.redirect, 'error');
  }
});

test('API errors do not reflect setup tokens or response bodies', async () => {
  const client = new SetupSessionClient({
    baseUrl: 'https://setup.lookout.example',
    fetchImpl: async () => json({ error: 'invalid code ABCD-EFGH' }, 401)
  });
  await assert.rejects(
    client.claimSession({ setupTokenProvider: async () => setupToken, deploymentIdentity: { publicKeyPem: publicKey }, installationScope }),
    (error) => error.message === 'Lookout setup service request failed with status 401' && error.status === 401 && !error.message.includes('ABCD-EFGH')
  );
});

test('setup endpoint requires HTTPS and proof response URLs cannot contain credentials', async () => {
  assert.throws(() => new SetupSessionClient({ baseUrl: 'http://setup.lookout.example' }), /must use HTTPS/);
  assert.throws(() => new SetupSessionClient({ baseUrl: 'https://user:pass@setup.lookout.example' }), /must not contain credentials/);
  const client = new SetupSessionClient({
    baseUrl: 'https://setup.lookout.example',
    fetchImpl: async () => json(successfulProof({
      provisioning: {
        console_sync: { endpoint: 'https://ingest.lookout.example/v1/console-sync', credential: consoleCredential },
        dashboard_url: 'https://user:pass@app.lookout.example/'
      }
    }))
  });
  await assert.rejects(client.proveSession({
    sessionId, sessionToken, challenge,
    signatureProvider: async (message) => sign(null, message, deploymentKeys.privateKey)
  }), /without credentials/);
});

test('proof of Ed25519 key possession releases strictly validated memory-only provisioning', async () => {
  let request;
  let signedMessage;
  const client = new SetupSessionClient({
    baseUrl: 'https://setup.lookout.example',
    fetchImpl: async (url, options) => { request = { url: String(url), options }; return json(successfulProof()); }
  });
  const result = await client.proveSession({
    sessionId, sessionToken, challenge,
    signatureProvider: async (message) => { signedMessage = message; return sign(null, message, deploymentKeys.privateKey); }
  });
  assert.deepEqual(result.provisioning, {
    consoleSync: { endpoint: 'https://ingest.lookout.example/v1/console-sync', credential: consoleCredential },
    dashboardUrl: 'https://app.lookout.example/deployments/deployment_12345678'
  });
  assert.equal(request.url, `https://setup.lookout.example/v1/setup-sessions/${sessionId}/prove`);
  assert.equal(request.options.headers.Authorization, `Bearer ${sessionToken}`);
  const submitted = Buffer.from(JSON.parse(request.options.body).signature_base64url, 'base64url');
  assert.equal(submitted.length, 64);
  assert.equal(verify(null, signedMessage, deploymentKeys.publicKey, submitted), true);
  assert.deepEqual(signedMessage, createProofMessage(sessionId, challenge));
});

test('proof responses require strictly validated provisioning', async () => {
  const prove = async (payload) => new SetupSessionClient({
    baseUrl: 'https://setup.lookout.example', fetchImpl: async () => json(payload)
  }).proveSession({ sessionId, sessionToken, challenge, signatureProvider: async (message) => sign(null, message, deploymentKeys.privateKey) });

  await assert.rejects(prove(successfulProof({ verified: false })), /did not verify/);
  await assert.rejects(prove(successfulProof({ provisioning: undefined })), /invalid provisioning/);
  await assert.rejects(prove(successfulProof({
    provisioning: { console_sync: { endpoint: 'http://ingest.lookout.example/', credential: consoleCredential }, dashboard_url: 'https://app.lookout.example/' }
  })), /Console sync endpoint must be an HTTPS URL/);
  await assert.rejects(prove(successfulProof({
    provisioning: { console_sync: { endpoint: 'https://ingest.lookout.example/?tenant=chosen', credential: consoleCredential }, dashboard_url: 'https://app.lookout.example/' }
  })), /query parameters/);
  await assert.rejects(prove(successfulProof({
    provisioning: { console_sync: { endpoint: 'https://ingest.lookout.example/', credential: 'too-short' }, dashboard_url: 'https://app.lookout.example/' }
  })), /invalid console sync credential/);
  await assert.rejects(prove(successfulProof({
    provisioning: { console_sync: { endpoint: 'https://ingest.lookout.example/', credential: `${consoleCredential}\nleak` }, dashboard_url: 'https://app.lookout.example/' }
  })), /invalid console sync credential/);
  await assert.rejects(prove(successfulProof({
    provisioning: { console_sync: { endpoint: 'https://ingest.lookout.example/', credential: consoleCredential }, dashboard_url: 'https://app.lookout.example/#token' }
  })), /fragments/);
});

test('claim rejects premature provisioning, malformed challenges, and non-Ed25519 identities', async () => {
  const claim = async (payload, key = publicKey) => new SetupSessionClient({
    baseUrl: 'https://setup.lookout.example', fetchImpl: async () => json(payload)
  }).claimSession({ setupTokenProvider: async () => setupToken, deploymentIdentity: { publicKeyPem: key }, installationScope });
  await assert.rejects(claim(successfulClaim({ provisioning: successfulProof().provisioning })), /before proof of possession/);
  await assert.rejects(claim(successfulClaim({ challenge: 'not_base64url!' })), /invalid proof challenge/);
  const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey.export({ format: 'pem', type: 'spki' }).toString('utf8');
  await assert.rejects(claim(successfulClaim(), rsa), /canonical PEM SPKI Ed25519/);
  await assert.rejects(claim(successfulClaim(), publicKey.trim()), /canonical PEM SPKI Ed25519/);
});

test('proof rejects malformed challenges and signatures before making a request', async () => {
  let requests = 0;
  const client = new SetupSessionClient({
    baseUrl: 'https://setup.lookout.example',
    fetchImpl: async () => { requests += 1; return json(successfulProof()); }
  });
  await assert.rejects(client.proveSession({
    sessionId, sessionToken, challenge: `${challenge}=`, signatureProvider: async () => Buffer.alloc(64)
  }), /invalid proof challenge/);
  await assert.rejects(client.proveSession({
    sessionId, sessionToken, challenge, signatureProvider: async () => Buffer.alloc(63)
  }), /64-byte Ed25519 signature/);
  assert.equal(requests, 0);
});

test('responses are content-type and size bounded', async () => {
  const wrongType = new SetupSessionClient({
    baseUrl: 'https://setup.lookout.example',
    fetchImpl: async () => new Response('{}', { headers: { 'content-type': 'text/html' } })
  });
  await assert.rejects(wrongType.claimSession({ setupTokenProvider: async () => setupToken, deploymentIdentity: { publicKeyPem: publicKey }, installationScope }), /non-JSON/);

  const oversized = new SetupSessionClient({
    baseUrl: 'https://setup.lookout.example', maximumResponseBytes: 1024,
    fetchImpl: async () => json({}, 200, { 'content-length': '2048' })
  });
  await assert.rejects(oversized.claimSession({ setupTokenProvider: async () => setupToken, deploymentIdentity: { publicKeyPem: publicKey }, installationScope }), /too large/);
});

test('setup tokens can be read from stdin or an owner-only regular file', async () => {
  assert.equal(await readSetupTokenFromStream(Readable.from([setupToken, '\n'])), setupToken);
  const directory = await mkdtemp(join(tmpdir(), 'lookout-setup-token-'));
  const path = join(directory, 'token');
  try {
    await writeFile(path, `${setupToken}\n`, { mode: 0o600 });
    assert.equal(await readSetupTokenFromFile(path), setupToken);
    await chmod(path, 0o644);
    await assert.rejects(readSetupTokenFromFile(path), /must not allow group or other access/);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('polling reports transitions and stops at completion', async () => {
  const states = ['installing', 'installing', 'complete'];
  const seen = [];
  const client = new SetupSessionClient({
    baseUrl: 'https://setup.lookout.example',
    fetchImpl: async () => json({ status: states.shift() })
  });
  const result = await client.pollUntilTerminal({
    sessionId, sessionToken, intervalMs: 100, timeoutMs: 1000,
    onStatus: ({ status }) => seen.push(status)
  });
  assert.equal(result.status, 'complete');
  assert.deepEqual(seen, ['installing', 'complete']);
});

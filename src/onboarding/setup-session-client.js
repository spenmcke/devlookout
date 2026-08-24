'use strict';

const { readFile, open } = require('node:fs/promises');
const { constants } = require('node:fs');
const { createPublicKey } = require('node:crypto');

const DEFAULT_MAXIMUM_RESPONSE_BYTES = 256 * 1024;
const SESSION_ID = /^[A-Za-z0-9_-]{16,128}$/;
const DEPLOYMENT_ID = /^[A-Za-z0-9_-]{8,128}$/;
const LEGACY_PHASES = ['installing', 'enrolling', 'surveying', 'configuring', 'validating'];
const PHASES = new Set(['connected', 'discovering', 'deploying', 'verifying', 'needs_access', 'reporting_interrupted', 'complete', 'failed', ...LEGACY_PHASES]);
const STATUSES = new Set(['pending', 'claimed', ...PHASES, 'expired']);
const PRECLAIM_FAILURE_CODES = new Set(['artifact_checksum', 'artifact_download', 'artifact_extract', 'cloud_discovery', 'local_state', 'orchestration_failed']);

function validateBaseUrl(value, { allowInsecureLoopback = false } = {}) {
  const url = new URL(value);
  const loopback = ['localhost', '127.0.0.1', '::1'].includes(url.hostname);
  if (url.protocol !== 'https:' && !(allowInsecureLoopback && loopback && url.protocol === 'http:')) {
    throw new Error('Lookout setup service URL must use HTTPS');
  }
  if (url.username || url.password || url.search || url.hash) throw new Error('Lookout setup service URL must not contain credentials, query parameters, or fragments');
  if (url.pathname !== '/' && url.pathname !== '') throw new Error('Lookout setup service URL must be an origin without a path');
  url.pathname = '';
  return url;
}

function validateHttpsUrl(value, name) {
  let url;
  try { url = new URL(value); } catch { throw new Error(`${name} is invalid`); }
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash) throw new Error(`${name} must be an HTTPS URL without credentials, query parameters, or fragments`);
  return url.toString();
}

function validateSetupToken(value) {
  if (typeof value !== 'string') throw new Error('Setup token provider did not return a token');
  const token = value.trim();
  if (!/^(?:lst|lrc)_[A-Za-z0-9_-]{43}$/.test(token)) throw new Error('Setup token is invalid');
  return token;
}

function validateDeploymentIdentity(identity) {
  if (!identity || typeof identity !== 'object' || Array.isArray(identity)) throw new Error('Deployment identity is required');
  if (typeof identity.publicKeyPem !== 'string' || identity.publicKeyPem.length < 64 || identity.publicKeyPem.length > 1024) throw new Error('Deployment identity public key is invalid');
  let key;
  try { key = createPublicKey({ key: identity.publicKeyPem, format: 'pem', type: 'spki' }); } catch { throw new Error('Deployment identity public key must be canonical PEM SPKI Ed25519'); }
  if (key.type !== 'public' || key.asymmetricKeyType !== 'ed25519') throw new Error('Deployment identity public key must be canonical PEM SPKI Ed25519');
  const canonical = key.export({ format: 'pem', type: 'spki' }).toString('utf8');
  if (identity.publicKeyPem !== canonical) throw new Error('Deployment identity public key must be canonical PEM SPKI Ed25519');
  return { public_key_spki_pem: canonical };
}

function decodeChallenge(value) {
  if (typeof value !== 'string' || value.length < 22 || value.length > 1366 || !/^[A-Za-z0-9_-]+$/.test(value)) throw new Error('Lookout setup service returned an invalid proof challenge');
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.length < 16 || bytes.length > 1024 || bytes.toString('base64url') !== value) throw new Error('Lookout setup service returned an invalid proof challenge');
  return bytes;
}

function createProofMessage(sessionId, challenge) {
  if (!SESSION_ID.test(sessionId || '')) throw new Error('Setup session identifier is invalid');
  const challengeBytes = decodeChallenge(challenge);
  return Buffer.concat([
    Buffer.from('lookout-setup-possession-v1\0', 'utf8'),
    Buffer.from(sessionId, 'utf8'),
    Buffer.from([0]),
    challengeBytes
  ]);
}

async function readBoundedJson(response, maximumBytes) {
  const contentType = response.headers.get('content-type') || '';
  if (!/^application\/(?:[a-z0-9.+-]*\+)?json(?:\s*;|$)/i.test(contentType)) throw new Error('Lookout setup service returned a non-JSON response');
  const declared = response.headers.get('content-length');
  if (declared && (!/^\d+$/.test(declared) || Number(declared) > maximumBytes)) throw new Error('Lookout setup service response is too large');
  const chunks = [];
  let size = 0;
  if (response.body && typeof response.body[Symbol.asyncIterator] === 'function') {
    for await (const chunk of response.body) {
      const bytes = Buffer.from(chunk);
      size += bytes.length;
      if (size > maximumBytes) {
        await response.body.cancel?.().catch?.(() => {});
        throw new Error('Lookout setup service response is too large');
      }
      chunks.push(bytes);
    }
  } else {
    const bytes = Buffer.from(await response.arrayBuffer());
    size = bytes.length;
    if (size > maximumBytes) throw new Error('Lookout setup service response is too large');
    chunks.push(bytes);
  }
  try { return JSON.parse(Buffer.concat(chunks, size).toString('utf8')); } catch { throw new Error('Lookout setup service returned invalid JSON'); }
}

async function readSetupTokenFromStream(stream, { maximumBytes = 128 } = {}) {
  if (!stream || typeof stream[Symbol.asyncIterator] !== 'function') throw new TypeError('Setup token input must be a readable stream');
  const chunks = [];
  let size = 0;
  for await (const chunk of stream) {
    const bytes = Buffer.from(chunk);
    size += bytes.length;
    if (size > maximumBytes) throw new Error('Setup token input is too large');
    chunks.push(bytes);
  }
  return validateSetupToken(Buffer.concat(chunks, size).toString('utf8'));
}

async function readSetupTokenFromFile(path, { maximumBytes = 128 } = {}) {
  if (typeof path !== 'string' || !path) throw new TypeError('Setup token file path is required');
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const stats = await handle.stat();
    if (!stats.isFile()) throw new Error('Setup token path must be a regular file');
    if (process.platform !== 'win32') {
      const permittedOwners = new Set([process.getuid?.(), Number(process.env.SUDO_UID)].filter(Number.isSafeInteger));
      if (!permittedOwners.has(stats.uid)) throw new Error('Setup token file must be owned by root or the invoking user');
      if ((stats.mode & 0o077) !== 0) throw new Error('Setup token file permissions must not allow group or other access');
    }
    if (stats.size > maximumBytes) throw new Error('Setup token input is too large');
    return validateSetupToken(await readFile(handle, 'utf8'));
  } finally { await handle.close(); }
}

function validateSessionResponse(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || !SESSION_ID.test(value.session_id || '')) throw new Error('Lookout setup service returned an invalid session');
  const result = { sessionId: value.session_id };
  if (value.expires_at !== undefined) {
    if (typeof value.expires_at !== 'string' || Number.isNaN(Date.parse(value.expires_at))) throw new Error('Lookout setup service returned an invalid expiry');
    result.expiresAt = value.expires_at;
  }
  if (value.verification_url !== undefined) result.verificationUrl = validateHttpsUrl(value.verification_url, 'Verification URL');
  return result;
}

function validateClaimResponse(value) {
  const result = validateSessionResponse(value);
  if (!DEPLOYMENT_ID.test(value.deployment_id || '')) throw new Error('Lookout setup service returned an invalid deployment identity');
  if (typeof value.session_token !== 'string' || value.session_token.length < 24 || value.session_token.length > 4096) throw new Error('Lookout setup service returned an invalid session credential');
  if (Object.hasOwn(value, 'provisioning')) throw new Error('Lookout setup service released provisioning before proof of possession');
  const challenge = value.challenge;
  decodeChallenge(challenge);
  result.deploymentId = value.deployment_id;
  result.sessionToken = value.session_token;
  result.challenge = challenge;
  if (!value.installation_scope || typeof value.installation_scope !== 'object') throw new Error('Lookout setup service returned an invalid installation scope');
  result.installationScope = structuredClone(value.installation_scope);
  result.recovery = value.recovery === true;
  return result;
}

function validateProvisioningResponse(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || value.verified !== true) throw new Error('Lookout setup service did not verify deployment identity');
  if (!value.provisioning || typeof value.provisioning !== 'object' || Array.isArray(value.provisioning)) throw new Error('Lookout setup service returned invalid provisioning');
  const sync = value.provisioning.console_sync;
  if (!sync || typeof sync !== 'object' || Array.isArray(sync)) throw new Error('Lookout setup service returned invalid console sync provisioning');
  if (typeof sync.credential !== 'string' || sync.credential.length < 32 || sync.credential.length > 4096 || !/^[\x21-\x7e]+$/.test(sync.credential)) {
    throw new Error('Lookout setup service returned an invalid console sync credential');
  }
  return {
    consoleSync: {
      endpoint: validateHttpsUrl(sync.endpoint, 'Console sync endpoint'),
      credential: sync.credential
    },
    dashboardUrl: validateHttpsUrl(value.provisioning.dashboard_url, 'Dashboard URL')
  };
}

class SetupSessionClient {
  constructor({ baseUrl, fetchImpl = globalThis.fetch, timeoutMs = 15000, maximumResponseBytes = DEFAULT_MAXIMUM_RESPONSE_BYTES, allowInsecureLoopback = false } = {}) {
    if (typeof fetchImpl !== 'function') throw new TypeError('SetupSessionClient requires fetch support');
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 120000) throw new Error('Setup request timeout is invalid');
    if (!Number.isSafeInteger(maximumResponseBytes) || maximumResponseBytes < 1024 || maximumResponseBytes > 5 * 1024 * 1024) throw new Error('Setup response limit is invalid');
    this.baseUrl = validateBaseUrl(baseUrl, { allowInsecureLoopback });
    this.fetchImpl = fetchImpl;
    this.timeoutMs = timeoutMs;
    this.maximumResponseBytes = maximumResponseBytes;
  }

  async request(path, { method = 'GET', body, sessionToken, signal } = {}) {
    if (typeof path !== 'string' || (!path.startsWith('/v1/setup-sessions') && !path.startsWith('/v1/setup-support/'))) throw new Error('Setup API path is invalid');
    const url = new URL(path, `${this.baseUrl.toString()}/`);
    if (url.origin !== this.baseUrl.origin) throw new Error('Setup API request may not change origin');
    const headers = { Accept: 'application/json', 'User-Agent': 'lookout-setup/0.1' };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    if (sessionToken !== undefined) {
      if (typeof sessionToken !== 'string' || sessionToken.length < 24 || sessionToken.length > 4096) throw new Error('Setup session credential is invalid');
      headers.Authorization = `Bearer ${sessionToken}`;
    }
    const timeoutSignal = AbortSignal.timeout(this.timeoutMs);
    const requestSignal = signal ? AbortSignal.any([signal, timeoutSignal]) : timeoutSignal;
    const response = await this.fetchImpl(url, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), redirect: 'error', signal: requestSignal });
    const payload = await readBoundedJson(response, this.maximumResponseBytes);
    if (!response.ok) {
      const error = new Error(`Lookout setup service request failed with status ${response.status}`);
      error.status = response.status;
      throw error;
    }
    return payload;
  }

  async claimSession({ setupTokenProvider, setupCodeProvider, deploymentIdentity, installationScope, signal } = {}) {
    const provider = setupTokenProvider || setupCodeProvider;
    if (typeof provider !== 'function') throw new TypeError('A setup token provider is required');
    const validatedIdentity = validateDeploymentIdentity(deploymentIdentity);
    const token = String(await provider()).trim();
    if (!/^(?:lst|lrc)_[A-Za-z0-9_-]{43}$/.test(token)) throw new Error('Setup token is invalid');
    const payload = await this.request('/v1/setup-sessions/claim', {
      method: 'POST', signal,
      body: { setup_token: token, deployment_identity: validatedIdentity, installation_scope: installationScope }
    });
    return validateClaimResponse(payload);
  }

  async connectSession({ setupToken, signal } = {}) {
    const token = validateSetupToken(setupToken);
    const payload = await this.request('/v1/setup-sessions/connect', { method: 'POST', signal, body: { setup_token: token } });
    if (!payload || payload.accepted !== true) throw new Error('Lookout setup service did not accept the connection');
    return { accepted: true };
  }

  async reportPreclaimFailure({ setupToken, code, signal } = {}) {
    const token = validateSetupToken(setupToken);
    if (!PRECLAIM_FAILURE_CODES.has(code)) throw new Error('Pre-claim failure code is invalid');
    const payload = await this.request('/v1/setup-sessions/failures', { method: 'POST', signal, body: { setup_token: token, code } });
    if (!payload || payload.accepted !== true) throw new Error('Lookout setup service did not accept the failure report');
    return { accepted: true };
  }

  async reportDiagnosticEvent({ setupToken, kind, code, phase, platform, idempotencyKey, signal } = {}) {
    const token = validateSetupToken(setupToken);
    if (!['failure', 'diagnostic'].includes(kind) || !/^[a-z][a-z0-9_]{0,63}$/.test(code || '') || !/^[a-z][a-z0-9_]{0,63}$/.test(phase || '') || typeof idempotencyKey !== 'string' || !/^[A-Za-z0-9_-]{16,128}$/.test(idempotencyKey)) throw new Error('Installer diagnostic is invalid');
    const payload = await this.request('/v1/setup-support/events', {
      method: 'POST', signal,
      body: { setup_token: token, kind, code, phase, platform, idempotency_key: idempotencyKey }
    });
    if (!payload || payload.accepted !== true || typeof payload.report_id !== 'string') throw new Error('Lookout support did not accept the installer diagnostic');
    return { accepted: true, reportId: payload.report_id };
  }

  async proveSession({ sessionId, sessionToken, challenge, signatureProvider, signal } = {}) {
    if (typeof signatureProvider !== 'function') throw new TypeError('A deployment identity signature provider is required');
    const proofMessage = createProofMessage(sessionId, challenge);
    const provided = await signatureProvider(Buffer.from(proofMessage));
    if (!(Buffer.isBuffer(provided) || provided instanceof Uint8Array)) throw new Error('Deployment identity signature provider returned an invalid signature');
    const signature = Buffer.from(provided);
    if (signature.length !== 64) throw new Error('Deployment identity signature must be a 64-byte Ed25519 signature');
    const payload = await this.request(`/v1/setup-sessions/${sessionId}/prove`, {
      method: 'POST', sessionToken, signal,
      body: { signature_base64url: signature.toString('base64url') }
    });
    return { provisioning: validateProvisioningResponse(payload) };
  }

  async getStatus({ sessionId, sessionToken, signal } = {}) {
    if (!SESSION_ID.test(sessionId || '')) throw new Error('Setup session identifier is invalid');
    const payload = await this.request(`/v1/setup-sessions/${sessionId}`, { sessionToken, signal });
    if (!payload || typeof payload !== 'object' || !STATUSES.has(payload.status)) throw new Error('Lookout setup service returned an invalid status');
    const result = { status: payload.status };
    if (payload.deployment_id !== undefined) {
      if (!DEPLOYMENT_ID.test(payload.deployment_id)) throw new Error('Lookout setup service returned an invalid deployment identity');
      result.deploymentId = payload.deployment_id;
    }
    if (payload.challenge !== undefined) {
      decodeChallenge(payload.challenge);
      result.challenge = payload.challenge;
    }
    if (payload.bootstrap_key !== undefined) {
      const key = payload.bootstrap_key;
      if (!key || typeof key !== 'object' || typeof key.authorized_keys_line !== 'string' || typeof key.fingerprint !== 'string') throw new Error('Lookout setup service returned an invalid bootstrap key');
      result.bootstrapKey = { authorizedKeysLine: key.authorized_keys_line, fingerprint: key.fingerprint };
    }
    if (payload.console_url !== undefined) result.consoleUrl = validateHttpsUrl(payload.console_url, 'Console URL');
    return result;
  }

  async publishBootstrapKey({ sessionId, sessionToken, authorizedKeysLine, fingerprint, signal } = {}) {
    const payload = await this.request(`/v1/setup-sessions/${sessionId}/bootstrap-key`, { method: 'POST', sessionToken, signal, body: { authorized_keys_line: authorizedKeysLine, fingerprint } });
    if (!payload || payload.accepted !== true) throw new Error('Lookout setup service did not accept the bootstrap public key');
    return { accepted: true, confirmed: payload.confirmed === true };
  }

  async reportPhase({ sessionId, sessionToken, phase, completed, total, signal } = {}) {
    if (!SESSION_ID.test(sessionId || '')) throw new Error('Setup session identifier is invalid');
    if (!PHASES.has(phase)) throw new Error('Setup phase is invalid');
    if ((completed !== undefined || total !== undefined) && (!Number.isSafeInteger(completed) || !Number.isSafeInteger(total) || completed < 0 || total < 1 || completed > total)) throw new Error('Setup phase progress is invalid');
    const body = { phase, ...(completed !== undefined ? { completed, total } : {}) };
    const payload = await this.request(`/v1/setup-sessions/${sessionId}/phases`, { method: 'POST', sessionToken, body, signal });
    if (!payload || payload.accepted !== true) throw new Error('Lookout setup service did not accept the phase update');
    return { accepted: true };
  }

  async reportDiagnostic({ sessionId, sessionToken, diagnostic, signal } = {}) {
    if (!SESSION_ID.test(sessionId || '') || !diagnostic || typeof diagnostic !== 'object' || Array.isArray(diagnostic)) throw new Error('Setup diagnostic is invalid');
    const payload = await this.request(`/v1/setup-sessions/${sessionId}/diagnostics`, { method: 'POST', sessionToken, body: diagnostic, signal });
    if (!payload || typeof payload.diagnostic_id !== 'string' || !/^diag_[A-Za-z0-9_-]{16}$/.test(payload.diagnostic_id)) throw new Error('Lookout setup service returned an invalid diagnostic receipt');
    return { diagnosticId: payload.diagnostic_id };
  }

  async pollUntilTerminal({ sessionId, sessionToken, intervalMs = 2000, timeoutMs = 15 * 60 * 1000, signal, onStatus } = {}) {
    if (!Number.isSafeInteger(intervalMs) || intervalMs < 100 || intervalMs > 60000 || !Number.isSafeInteger(timeoutMs) || timeoutMs < intervalMs || timeoutMs > 60 * 60 * 1000) throw new Error('Setup polling limits are invalid');
    if (onStatus !== undefined && typeof onStatus !== 'function') throw new TypeError('Setup status callback must be a function');
    const started = Date.now();
    let previous;
    while (Date.now() - started <= timeoutMs) {
      const status = await this.getStatus({ sessionId, sessionToken, signal });
      if (status.status !== previous) await onStatus?.(status);
      previous = status.status;
      if (['complete', 'failed', 'expired'].includes(status.status)) return status;
      await new Promise((resolve, reject) => {
        if (signal?.aborted) { reject(signal.reason || new Error('Setup polling aborted')); return; }
        const timer = setTimeout(resolve, intervalMs);
        if (signal) signal.addEventListener('abort', () => { clearTimeout(timer); reject(signal.reason || new Error('Setup polling aborted')); }, { once: true });
      });
    }
    throw new Error('Lookout setup session polling timed out');
  }
}

module.exports = {
  SetupSessionClient,
  readBoundedJson,
  readSetupTokenFromStream,
  readSetupTokenFromFile,
  validateSetupToken,
  validateBaseUrl,
  validateDeploymentIdentity,
  createProofMessage
};

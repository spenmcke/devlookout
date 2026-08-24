'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const { constants: fsConstants } = require('node:fs');
const path = require('node:path');
const { SnapshotStore } = require('../storage/snapshot-store');
const { stableId } = require('../core/canonical');
const { generateCollectorKeyPair } = require('./envelope');
const { generateApiToken, constantEqual } = require('../security/auth');
const { assertSafePath, syncDirectory, writeFileDurably } = require('../storage/safe-files');
const { postJson } = require('./transport');

const TOKEN_PATTERN = /^le1\.([a-f0-9]{32})\.([A-Za-z0-9_-]{43})$/;
const ASSET_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9:._/-]{0,255}$/;
const DEPLOYMENT_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

function digest(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function validatePublicIdentity(collectorId, publicKeyPem) {
  let key;
  try { key = crypto.createPublicKey(publicKeyPem); }
  catch { throw new Error('Enrollment public key is invalid'); }
  if (key.asymmetricKeyType !== 'ed25519') throw new Error('Enrollment public key must be Ed25519');
  const canonicalPem = key.export({ type: 'spki', format: 'pem' });
  if (stableId('collector', canonicalPem) !== collectorId) throw new Error('Enrollment collector ID does not match its public key');
  return canonicalPem;
}

function createCollectorEnrollmentRequest(enrollmentToken, { assetId, deploymentId } = {}) {
  if (typeof enrollmentToken !== 'string' || !TOKEN_PATTERN.test(enrollmentToken)) throw new Error('Enrollment token format is invalid');
  if (typeof assetId !== 'string' || !ASSET_ID_PATTERN.test(assetId)) throw new Error('Enrollment asset ID is invalid');
  if (typeof deploymentId !== 'string' || !DEPLOYMENT_ID_PATTERN.test(deploymentId)) throw new Error('Enrollment deployment ID is invalid');
  const keys = generateCollectorKeyPair();
  const submission = generateApiToken();
  return {
    private: { collectorId: keys.collectorId, privateKeyPem: keys.privateKeyPem, submissionToken: submission.token },
    request: {
      schemaVersion: 1, enrollmentToken, collectorId: keys.collectorId,
      assetId, deploymentId, publicKeyPem: keys.publicKeyPem, submissionTokenHash: submission.hash
    }
  };
}

function validateCollectorEnrollmentBundle(bundle) {
  if (!bundle?.private || !bundle.request || bundle.request.schemaVersion !== 1 || !TOKEN_PATTERN.test(bundle.request.enrollmentToken || '') || !ASSET_ID_PATTERN.test(bundle.request.assetId || '') || !DEPLOYMENT_ID_PATTERN.test(bundle.request.deploymentId || '') || bundle.private.collectorId !== bundle.request.collectorId || typeof bundle.private.submissionToken !== 'string' || digest(bundle.private.submissionToken) !== bundle.request.submissionTokenHash) throw new Error('Persisted enrollment bundle credentials do not match its request');
  let privateKey;
  try { privateKey = crypto.createPrivateKey(bundle.private.privateKeyPem); }
  catch { throw new Error('Persisted enrollment private key is invalid'); }
  const publicKeyPem = crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'pem' });
  if (publicKeyPem !== validatePublicIdentity(bundle.request.collectorId, bundle.request.publicKeyPem)) throw new Error('Persisted enrollment private and public keys do not match');
  return bundle;
}

class CollectorEnrollmentAuthority {
  #queue = Promise.resolve();

  constructor({ dataDirectory, protector = null, requireEncryption = false, maximumInvitations = 1000, maximumCollectors = 10000 } = {}) {
    if (!Number.isSafeInteger(maximumInvitations) || maximumInvitations < 1 || !Number.isSafeInteger(maximumCollectors) || maximumCollectors < 1) throw new Error('Enrollment capacity is invalid');
    this.store = new SnapshotStore(dataDirectory, 'collector-enrollment.json', { protector, requireEncryption });
    this.maximumInvitations = maximumInvitations;
    this.maximumCollectors = maximumCollectors;
    this.state = { schemaVersion: 1, invitations: {}, collectors: {} };
  }

  async initialize() {
    const state = await this.store.load();
    if (state) this.#validateState(state);
    if (state) this.state = state;
    return this;
  }

  #validateState(state) {
    if (state?.schemaVersion !== 1 || !state.invitations || !state.collectors || Array.isArray(state.invitations) || Array.isArray(state.collectors)) throw new Error('Collector enrollment state is invalid');
    if (Object.keys(state.invitations).length > this.maximumInvitations || Object.keys(state.collectors).length > this.maximumCollectors) throw new Error('Collector enrollment state exceeds capacity');
    const invitationHashes = new Set();
    const activeBindings = new Set();
    for (const [id, invitation] of Object.entries(state.invitations)) {
      if (!/^[a-f0-9]{32}$/.test(id) || !/^[a-f0-9]{64}$/.test(invitation?.tokenHash) || Number.isNaN(Date.parse(invitation.createdAt)) || Number.isNaN(Date.parse(invitation.expiresAt)) || !ASSET_ID_PATTERN.test(invitation.assetId || '') || !DEPLOYMENT_ID_PATTERN.test(invitation.deploymentId || '') || (invitation.usedBy !== null && typeof invitation.usedBy !== 'string') || (invitation.usedAt !== null && Number.isNaN(Date.parse(invitation.usedAt)))) throw new Error('Collector enrollment invitation state is invalid');
      if ((invitation.usedBy === null) !== (invitation.usedAt === null)) throw new Error('Collector enrollment invitation usage state is inconsistent');
      if (invitationHashes.has(invitation.tokenHash)) throw new Error('Collector enrollment state contains duplicate invitation credentials');
      invitationHashes.add(invitation.tokenHash);
      if (invitation.usedBy === null) {
        const binding = `${invitation.assetId}\0${invitation.deploymentId}`;
        if (activeBindings.has(binding)) throw new Error('Collector enrollment state contains duplicate active deployment invitations');
        activeBindings.add(binding);
      }
    }
    const submissionHashes = new Set();
    const collectorBindings = new Set();
    for (const [collectorId, record] of Object.entries(state.collectors)) {
      validatePublicIdentity(collectorId, record?.publicKeyPem);
      if (!ASSET_ID_PATTERN.test(record.assetId || '') || !DEPLOYMENT_ID_PATTERN.test(record.deploymentId || '')) throw new Error('Enrolled collector state has an invalid deployment binding');
      if (!/^[a-f0-9]{64}$/.test(record.submissionTokenHash) || Number.isNaN(Date.parse(record.enrolledAt)) || typeof record.invitationId !== 'string' || typeof record.disabled !== 'boolean') throw new Error('Enrolled collector state is invalid');
      if (submissionHashes.has(record.submissionTokenHash)) throw new Error('Collector enrollment state contains duplicate submission credentials');
      submissionHashes.add(record.submissionTokenHash);
      const binding = `${record.assetId}\0${record.deploymentId}`;
      if (collectorBindings.has(binding)) throw new Error('Collector enrollment state contains duplicate collector deployment bindings');
      collectorBindings.add(binding);
      const invitation = state.invitations[record.invitationId];
      if (invitation && (invitation.usedBy !== collectorId || invitation.assetId !== record.assetId || invitation.deploymentId !== record.deploymentId)) throw new Error('Enrolled collector does not match its invitation state');
    }
  }

  #serialize(operation) {
    const result = this.#queue.then(operation, operation);
    this.#queue = result.then(() => undefined, () => undefined);
    return result;
  }

  async issueInvitation({ assetId, deploymentId, ttlSeconds = 900, label = null, now = new Date(), replaceActive = false } = {}) {
    if (!Number.isSafeInteger(ttlSeconds) || ttlSeconds < 60 || ttlSeconds > 86400) throw new Error('Enrollment invitation lifetime must be between 60 seconds and 24 hours');
    if (!(now instanceof Date) || Number.isNaN(now.getTime())) throw new Error('Enrollment clock is invalid');
    if (label !== null && (typeof label !== 'string' || !label.trim() || Buffer.byteLength(label) > 256)) throw new Error('Enrollment invitation label is invalid');
    if (typeof assetId !== 'string' || !ASSET_ID_PATTERN.test(assetId)) throw new Error('Enrollment asset ID is invalid');
    if (typeof deploymentId !== 'string' || !DEPLOYMENT_ID_PATTERN.test(deploymentId)) throw new Error('Enrollment deployment ID is invalid');
    if (typeof replaceActive !== 'boolean') throw new Error('Enrollment invitation replacement option is invalid');
    return this.#serialize(async () => {
      const next = structuredClone(this.state);
      for (const [key, item] of Object.entries(next.invitations)) if ((item.usedBy === null && Date.parse(item.expiresAt) <= now.getTime()) || (item.usedAt && Date.parse(item.usedAt) < now.getTime() - 86400000)) delete next.invitations[key];
      if (replaceActive) for (const [key, item] of Object.entries(next.invitations)) if (item.usedBy === null && item.assetId === assetId && item.deploymentId === deploymentId) delete next.invitations[key];
      const active = Object.values(next.invitations).filter((item) => item.usedBy === null && Date.parse(item.expiresAt) > now.getTime()).length;
      if (active >= this.maximumInvitations) throw new Error('Enrollment invitation capacity reached');
      if (Object.values(next.invitations).some((item) => item.usedBy === null && item.assetId === assetId && item.deploymentId === deploymentId && Date.parse(item.expiresAt) > now.getTime())) throw new Error('An active invitation already exists for this asset deployment');
      const evictable = Object.entries(next.invitations)
        .filter(([, item]) => item.usedBy !== null)
        .sort(([, left], [, right]) => Date.parse(left.usedAt) - Date.parse(right.usedAt));
      while (Object.keys(next.invitations).length >= this.maximumInvitations && evictable.length) delete next.invitations[evictable.shift()[0]];
      if (Object.keys(next.invitations).length >= this.maximumInvitations) throw new Error('Enrollment invitation capacity reached');
      let id; let secret; let token;
      do { id = crypto.randomBytes(16).toString('hex'); secret = crypto.randomBytes(32).toString('base64url'); token = `le1.${id}.${secret}`; }
      while (next.invitations[id] || Object.values(next.invitations).some((item) => item.tokenHash === digest(token)));
      const expiresAt = new Date(now.getTime() + ttlSeconds * 1000).toISOString();
      next.invitations[id] = { tokenHash: digest(token), createdAt: now.toISOString(), expiresAt, assetId, deploymentId, label, usedBy: null, usedAt: null };
      await this.store.save(next);
      this.state = next;
      return { token, invitationId: id, expiresAt };
    });
  }

  async enroll(request, { now = new Date(), refresh = false } = {}) {
    if (!(now instanceof Date) || Number.isNaN(now.getTime())) throw new Error('Enrollment clock is invalid');
    if (request?.schemaVersion !== 1 || typeof request.enrollmentToken !== 'string' || typeof request.collectorId !== 'string' || !ASSET_ID_PATTERN.test(request.assetId || '') || !DEPLOYMENT_ID_PATTERN.test(request.deploymentId || '') || typeof request.publicKeyPem !== 'string' || !/^[a-f0-9]{64}$/.test(request.submissionTokenHash || '')) throw new Error('Collector enrollment request is invalid');
    const match = TOKEN_PATTERN.exec(request.enrollmentToken);
    if (!match) throw new Error('Enrollment token format is invalid');
    const publicKeyPem = validatePublicIdentity(request.collectorId, request.publicKeyPem);
    return this.#serialize(async () => {
      let base = this.state;
      if (refresh) {
        const durable = await this.store.load();
        if (durable) this.#validateState(durable);
        if (durable) base = durable;
      }
      const next = structuredClone(base);
      const invitation = next.invitations[match[1]];
      if (!invitation || !constantEqual(invitation.tokenHash, digest(request.enrollmentToken))) throw new Error('Enrollment token is not valid');
      if (invitation.assetId !== request.assetId || invitation.deploymentId !== request.deploymentId) throw new Error('Enrollment request does not match invitation asset and deployment binding');
      const existing = next.collectors[request.collectorId];
      const identical = existing && existing.publicKeyPem === publicKeyPem && existing.submissionTokenHash === request.submissionTokenHash && existing.assetId === request.assetId && existing.deploymentId === request.deploymentId && existing.invitationId === match[1];
      if (invitation.usedBy !== null) {
        if (invitation.usedBy === request.collectorId && identical) return this.#publicRecord(request.collectorId, existing, true);
        throw new Error('Enrollment token has already been used');
      }
      if (Date.parse(invitation.expiresAt) <= now.getTime()) throw new Error('Enrollment token has expired');
      if (existing) throw new Error('Collector identity is already enrolled with different credentials');
      if (Object.values(next.collectors).some((record) => record.assetId === request.assetId && record.deploymentId === request.deploymentId)) throw new Error('Asset deployment is already enrolled with a different collector identity');
      if (Object.values(next.collectors).some((record) => record.submissionTokenHash === request.submissionTokenHash)) throw new Error('Collector submission credential is already enrolled');
      if (Object.keys(next.collectors).length >= this.maximumCollectors) throw new Error('Collector enrollment capacity reached');
      const record = { assetId: request.assetId, deploymentId: request.deploymentId, publicKeyPem, submissionTokenHash: request.submissionTokenHash, invitationId: match[1], enrolledAt: now.toISOString(), disabled: false };
      next.collectors[request.collectorId] = record;
      invitation.usedBy = request.collectorId;
      invitation.usedAt = now.toISOString();
      await this.store.save(next);
      this.state = next;
      return this.#publicRecord(request.collectorId, record, false);
    });
  }

  #publicRecord(collectorId, record, idempotent) {
    return { collectorId, assetId: record.assetId, deploymentId: record.deploymentId, publicKeyPem: record.publicKeyPem, enrolledAt: record.enrolledAt, idempotent };
  }

  authenticateBearer(header) {
    if (typeof header !== 'string' || !header.startsWith('Bearer ')) return null;
    const candidate = digest(header.slice(7));
    for (const [collectorId, record] of Object.entries(this.state.collectors)) {
      if (!record.disabled && constantEqual(candidate, record.submissionTokenHash)) return { id: `collector:${collectorId}`, collectorId, roles: ['collector'], authentication: 'collector-enrollment' };
    }
    return null;
  }

  publicKeys() {
    return Object.fromEntries(Object.entries(this.state.collectors).filter(([, record]) => !record.disabled).map(([id, record]) => [id, record.publicKeyPem]).sort(([a], [b]) => a.localeCompare(b)));
  }

  async setDisabled(collectorId, disabled = true) {
    return this.#serialize(async () => {
      const next = structuredClone(this.state);
      const record = next.collectors[collectorId];
      if (!record) throw new Error('Collector is not enrolled');
      record.disabled = Boolean(disabled);
      await this.store.save(next);
      this.state = next;
      return { collectorId, disabled: record.disabled };
    });
  }

  async revoke(collectorId) { return this.setDisabled(collectorId, true); }
}

async function loadOrCreateEnrollmentBundle(directory, enrollmentToken, binding) {
  const targetDirectory = path.resolve(directory);
  await fs.mkdir(targetDirectory, { recursive: true, mode: 0o700 });
  await assertSafePath(targetDirectory, { allowMissing: false, type: 'directory', privateDirectory: true });
  const target = path.join(targetDirectory, 'enrollment.json');
  try {
    const handle = await fs.open(target, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW || 0));
    let existing;
    try {
      const stat = await handle.stat();
      if (!stat.isFile() || stat.size > 1024 * 1024) throw new Error('Persisted enrollment bundle must be a bounded regular file');
      if (process.platform !== 'win32' && (stat.mode & 0o077) !== 0) throw new Error('Persisted enrollment bundle permissions are too broad');
      if (typeof process.geteuid === 'function' && stat.uid !== process.geteuid()) throw new Error('Persisted enrollment bundle is not owned by the current user');
      let document;
      try { document = JSON.parse(await handle.readFile('utf8')); }
      catch { throw new Error('Persisted enrollment bundle is not valid JSON'); }
      existing = validateCollectorEnrollmentBundle(document);
    } finally { await handle.close(); }
    if (existing.request?.enrollmentToken !== enrollmentToken || existing.request?.assetId !== binding.assetId || existing.request?.deploymentId !== binding.deploymentId) throw new Error('Existing enrollment bundle does not match requested deployment');
    return existing;
  } catch (error) {
    if (['ELOOP', 'EMLINK'].includes(error.code)) throw new Error('Persisted enrollment bundle must not be a symbolic link');
    if (error.code !== 'ENOENT') throw error;
  }
  const bundle = createCollectorEnrollmentRequest(enrollmentToken, binding);
  const temporary = path.join(targetDirectory, `.enrollment.${process.pid}.${crypto.randomUUID()}.tmp`);
  try {
    await writeFileDurably(temporary, `${JSON.stringify(bundle)}\n`, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
    await fs.rename(temporary, target);
    await syncDirectory(targetDirectory);
  } catch (error) { await fs.rm(temporary, { force: true }); throw error; }
  return bundle;
}

async function submitEnrollment(serverUrl, request, { fetchImpl = globalThis.fetch, httpsRequestImpl, caPem = null, timeoutMs = 15000 } = {}) {
  const target = new URL('/api/v1/collector/enroll', serverUrl);
  if (target.protocol !== 'https:' && !['localhost', '127.0.0.1', '::1'].includes(target.hostname)) throw new Error('Collector enrollment requires HTTPS outside loopback');
  if (target.username || target.password) throw new Error('Collector enrollment URL must not contain credentials');
  try { return await postJson(target, request, { fetchImpl, httpsRequestImpl, caPem, timeoutMs }); }
  catch (error) { throw new Error(error.message.replace('Collector request', 'Collector enrollment'), { cause: error }); }
}

module.exports = { TOKEN_PATTERN, ASSET_ID_PATTERN, DEPLOYMENT_ID_PATTERN, validatePublicIdentity, validateCollectorEnrollmentBundle, createCollectorEnrollmentRequest, loadOrCreateEnrollmentBundle, CollectorEnrollmentAuthority, submitEnrollment };

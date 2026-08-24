'use strict';

const crypto = require('node:crypto');
const path = require('node:path');
const { SnapshotStore } = require('../storage/snapshot-store');

const PROOF_DOMAIN = Buffer.from('lookout-setup-possession-v1\0', 'utf8');
const PHASES = ['connected', 'discovering', 'deploying', 'verifying', 'complete'];
const INTERRUPTIONS = new Set(['needs_access', 'reporting_interrupted']);
const LEGACY_PHASES = new Map([['installing', 'deploying'], ['enrolling', 'deploying'], ['surveying', 'verifying'], ['configuring', 'verifying'], ['validating', 'verifying']]);
const TERMINAL = new Set(['complete', 'failed']);
const PRECLAIM = new Set(['pending', 'connected']);
const STALLED_CLAIM_MS = 30 * 1000;
const PRECLAIM_FAILURE_CODES = new Set(['artifact_checksum', 'artifact_download', 'artifact_extract', 'cloud_discovery', 'local_state', 'orchestration_failed']);
const SAFE_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$/;
const SAFE_SCOPE_TEXT = /^[^\0-\x1f\x7f]{1,255}$/;
const THIRTY_DAYS_MS = 30 * 24 * 60 * 60 * 1000;

function emptyState() { return { schemaVersion: 1, sessions: [], claimAttempts: [], deletedTenants: [] }; }

function copy(value) {
  return structuredClone(value);
}

function timestamp(value) {
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) throw new Error('Setup authority clock returned an invalid time');
  return date;
}

function secretHash(value) {
  return crypto.createHash('sha256').update(value, 'utf8').digest('base64url');
}

function equalSecretHash(stored, supplied) {
  const actual = Buffer.from(secretHash(supplied), 'ascii');
  const expected = Buffer.from(typeof stored === 'string' ? stored : ''.padEnd(43, '0'), 'ascii');
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

function randomToken(randomBytes, bytes, prefix = '') {
  const value = randomBytes(bytes);
  if (!(Buffer.isBuffer(value) || value instanceof Uint8Array) || value.length !== bytes) throw new Error('Setup authority random source returned invalid bytes');
  return `${prefix}${Buffer.from(value).toString('base64url')}`;
}


function canonicalEd25519(value) {
  if (typeof value !== 'string' || value.length > 1024) throw new Error('Deployment identity must be canonical PEM SPKI Ed25519');
  let key;
  try { key = crypto.createPublicKey({ key: value, type: 'spki', format: 'pem' }); }
  catch { throw new Error('Deployment identity must be canonical PEM SPKI Ed25519'); }
  if (key.type !== 'public' || key.asymmetricKeyType !== 'ed25519') throw new Error('Deployment identity must be canonical PEM SPKI Ed25519');
  const canonical = key.export({ type: 'spki', format: 'pem' }).toString('utf8');
  if (canonical !== value) throw new Error('Deployment identity must be canonical PEM SPKI Ed25519');
  return { key, canonical, der: key.export({ type: 'spki', format: 'der' }) };
}

function publicSession(session, now) {
  const expired = !TERMINAL.has(session.status) && now.getTime() >= Date.parse(session.expiresAt);
  const stalledClaim = session.status === 'claimed' && !session.provedAt && Number.isFinite(Date.parse(session.claimedAt)) && now.getTime() - Date.parse(session.claimedAt) >= STALLED_CLAIM_MS;
  const result = { status: expired || stalledClaim ? 'expired' : session.status, expires_at: session.expiresAt };
  if (Number.isSafeInteger(session.completed) && Number.isSafeInteger(session.total)) {
    result.completed = session.completed;
    result.total = session.total;
  } else if (Array.isArray(session.installationScope?.vms)) {
    result.total = session.installationScope.vms.length;
  }
  if (session.bootstrapKey) result.bootstrap_key = copy(session.bootstrapKey);
  return result;
}

function validateBootstrapKey(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Bootstrap public key is invalid');
  const line = value.authorizedKeysLine ?? value.authorized_keys_line;
  const fingerprint = value.fingerprint;
  if (typeof line !== 'string' || line.length > 2048 || !/^restrict ssh-ed25519 [A-Za-z0-9+/]+={0,2} lookout-bootstrap:[A-Za-z0-9._:-]{1,128}$/.test(line)) throw new Error('Bootstrap public key is invalid');
  if (typeof fingerprint !== 'string' || !/^SHA256:[A-Za-z0-9+/]{20,64}$/.test(fingerprint)) throw new Error('Bootstrap public key fingerprint is invalid');
  return { authorized_keys_line: line, fingerprint };
}

function assertIdentifier(value, label) {
  if (typeof value !== 'string' || !SAFE_IDENTIFIER.test(value)) throw new Error(`Trusted ${label} is invalid`);
}

function containsTenantInput(value) {
  if (!value || typeof value !== 'object') return false;
  return Object.hasOwn(value, 'tenantId') || Object.hasOwn(value, 'tenant_id') || Object.hasOwn(value, 'userId') || Object.hasOwn(value, 'user_id');
}

function validateInstallationScope(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Approved installation scope is required');
  const centralVmId = value.central_vm_id ?? value.centralVmId;
  const inputVms = value.vms;
  if ((centralVmId !== undefined && (typeof centralVmId !== 'string' || !SAFE_IDENTIFIER.test(centralVmId))) || !Array.isArray(inputVms) || inputVms.length < 1 || inputVms.length > 256) throw new Error('Approved installation scope is invalid');
  const ids = new Set();
  const vms = inputVms.map((input) => {
    if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('Approved VM is invalid');
    const allowed = new Set(['id', 'provider', 'name', 'instance_id', 'region', 'zone', 'address', 'public_address', 'aws_profile', 'ssh_host', 'ssh_user', 'platform', 'local', 'project', 'resource_group', 'resource_id']);
    if (Object.keys(input).some((key) => !allowed.has(key))) throw new Error('Approved VM contains an unsupported field');
    if (typeof input.id !== 'string' || !SAFE_IDENTIFIER.test(input.id) || ids.has(input.id)) throw new Error('Approved VM identity is invalid');
    ids.add(input.id);
    const vm = { id: input.id };
    for (const key of ['provider', 'name', 'instance_id', 'region', 'zone', 'address', 'public_address', 'aws_profile', 'ssh_host', 'ssh_user', 'platform', 'project', 'resource_group', 'resource_id']) {
      if (input[key] !== undefined && (typeof input[key] !== 'string' || !SAFE_SCOPE_TEXT.test(input[key]))) throw new Error(`Approved VM ${key} is invalid`);
      if (input[key] !== undefined) vm[key] = input[key];
    }
    if (input.local !== undefined) {
      if (typeof input.local !== 'boolean') throw new Error('Approved VM local flag is invalid');
      vm.local = input.local;
    }
    if (input.provider !== undefined && !['aws', 'gcp', 'azure', 'digitalocean', 'openssh', 'local', 'test'].includes(input.provider)) throw new Error('Approved VM provider is unsupported');
    return vm;
  });
  if (centralVmId !== undefined && !ids.has(centralVmId)) throw new Error('Approved central VM must be in the approved VM list');
  return { ...(centralVmId !== undefined ? { central_vm_id: centralVmId } : {}), vms };
}

function validateLimits(options) {
  const limits = {
    codeTtlMs: options.codeTtlMs ?? options.ttlMs ?? THIRTY_DAYS_MS,
    sessionTtlMs: options.sessionTtlMs ?? 15 * 60 * 1000,
    maxCodeAttempts: options.maxCodeAttempts ?? options.maxAttempts ?? 5,
    maxProofAttempts: options.maxProofAttempts ?? 5,
    claimWindowMs: options.claimWindowMs ?? 60 * 1000,
    maxClaimsPerWindow: options.maxClaimsPerWindow ?? 120,
    maxSessions: options.maxSessions ?? 10000,
    maxAttemptHistory: options.maxAttemptHistory ?? 256
  };
  for (const [name, value] of Object.entries(limits)) {
    if (!Number.isSafeInteger(value) || value < 1) throw new Error(`Setup authority ${name} limit is invalid`);
  }
  if (limits.codeTtlMs > THIRTY_DAYS_MS || limits.sessionTtlMs > 24 * 60 * 60 * 1000 || limits.claimWindowMs > 60 * 60 * 1000 || limits.maxCodeAttempts > 100 || limits.maxProofAttempts > 100 || limits.maxClaimsPerWindow > 100000 || limits.maxSessions > 100000 || limits.maxAttemptHistory > 100000) throw new Error('Setup authority limit is too large');
  return limits;
}

class SetupSessionAuthority {
  constructor(options = {}) {
    if (!options || typeof options !== 'object' || Array.isArray(options)) throw new TypeError('Setup authority options are required');
    if (options.dataDirectory && options.requireEncryption !== true) throw new Error('Persistent setup authority state requires encryption');
    this.store = options.snapshotStore || options.store || (options.dataDirectory
      ? new SnapshotStore(path.resolve(options.dataDirectory), options.filename || 'setup-sessions.json', { protector: options.protector || null, requireEncryption: options.requireEncryption === true })
      : null);
    this.provisioningFactory = options.provisioningFactory;
    if (typeof this.provisioningFactory !== 'function' && typeof this.provisioningFactory?.provision !== 'function' && typeof this.provisioningFactory?.create !== 'function') throw new TypeError('A provisioning factory is required');
    this.deploymentReplacementHandler = options.deploymentReplacementHandler || null;
    if (this.deploymentReplacementHandler !== null && typeof this.deploymentReplacementHandler !== 'function') throw new TypeError('A deployment replacement handler must be a function');
    this.activeDeploymentChecker = options.activeDeploymentChecker || null;
    if (this.activeDeploymentChecker !== null && typeof this.activeDeploymentChecker !== 'function') throw new TypeError('An active deployment checker must be a function');
    this.completionValidator = options.completionValidator || null;
    if (this.completionValidator !== null && typeof this.completionValidator !== 'function') throw new TypeError('Setup completion validator must be a function');
    if (this.store && (typeof this.store.load !== 'function' || typeof this.store.save !== 'function')) throw new TypeError('Setup authority store must implement load and save');
    this.clock = options.now || options.clock || (() => new Date());
    if (typeof this.clock !== 'function') throw new TypeError('Setup authority clock must be a function');
    this.randomBytes = options.randomBytes || crypto.randomBytes;
    if (typeof this.randomBytes !== 'function') throw new TypeError('Setup authority random source must be a function');
    this.limits = validateLimits(options);
    this.state = emptyState();
    this.loaded = false;
    this.loading = null;
    this.serial = Promise.resolve();
  }

  async initialize() {
    if (this.loaded) return this;
    if (!this.loading) this.loading = (async () => {
      const persisted = this.store ? await this.store.load() : null;
      if (persisted !== null) this.state = this.#validateState(persisted);
      this.loaded = true;
      return this;
    })().finally(() => { this.loading = null; });
    return this.loading;
  }

  #validateState(value) {
    if (!value || value.schemaVersion !== 1 || !Array.isArray(value.sessions) || !Array.isArray(value.claimAttempts) || value.sessions.length > this.limits.maxSessions || value.claimAttempts.length > this.limits.maxAttemptHistory) throw new Error('Persisted setup authority state is invalid');
    const normalized = copy(value);
    normalized.sessions = normalized.sessions.filter((session) => typeof session?.tenantId === 'string' && typeof session?.userId === 'string');
    normalized.deletedTenants ||= [];
    if (!Array.isArray(normalized.deletedTenants) || normalized.deletedTenants.length > 100000 || new Set(normalized.deletedTenants).size !== normalized.deletedTenants.length || normalized.deletedTenants.some((tenantId) => !SAFE_IDENTIFIER.test(tenantId))) throw new Error('Persisted setup authority tenant deletion state is invalid');
    for (const session of normalized.sessions) {
      if (!session || typeof session.id !== 'string' || typeof session.tenantId !== 'string' || typeof session.userId !== 'string' || typeof session.expiresAt !== 'string' || Number.isNaN(Date.parse(session.expiresAt))) throw new Error('Persisted setup authority session is invalid');
      if (session.setupTokenHash !== undefined && session.setupTokenHash !== null && (typeof session.setupTokenHash !== 'string' || session.setupTokenHash.length !== 43)) throw new Error('Persisted setup authority token is invalid');
      if (session.supportTokenHash !== undefined && session.supportTokenHash !== null && (typeof session.supportTokenHash !== 'string' || session.supportTokenHash.length !== 43)) throw new Error('Persisted setup support token is invalid');
      if (session.installationScope) validateInstallationScope(session.installationScope);
      if (session.deploymentId !== undefined && !/^dpl_[A-Za-z0-9_-]{32}$/.test(session.deploymentId)) throw new Error('Persisted setup authority deployment is invalid');
      if (session.authorizedInstallationScope) session.authorizedInstallationScope = validateInstallationScope(session.authorizedInstallationScope);
      if (session.authorizedPublicKeySpkiPem) session.authorizedPublicKeySpkiPem = canonicalEd25519(session.authorizedPublicKeySpkiPem).canonical;
      if (session.bootstrapKey) validateBootstrapKey(session.bootstrapKey);
      if (session.bootstrapKeyPublishedAt !== undefined && Number.isNaN(Date.parse(session.bootstrapKeyPublishedAt))) throw new Error('Persisted setup authority bootstrap key state is invalid');
      if (session.bootstrapConnectedAt !== undefined && Number.isNaN(Date.parse(session.bootstrapConnectedAt))) throw new Error('Persisted setup authority connection state is invalid');
      if (session.dismissedAt !== undefined && Number.isNaN(Date.parse(session.dismissedAt))) throw new Error('Persisted setup authority dismissal state is invalid');
      if (session.diagnostics !== undefined && (!Array.isArray(session.diagnostics) || session.diagnostics.length > 50 || session.diagnostics.some((item) => typeof item?.id !== 'string' || typeof item.phase !== 'string' || typeof item.message !== 'string' || Number.isNaN(Date.parse(item.occurredAt))))) throw new Error('Persisted setup diagnostic state is invalid');
    }
    return normalized;
  }

  async #read(operation) {
    await this.initialize();
    await this.serial;
    if (this.store?.shared) {
      const persisted = await this.store.load();
      this.state = persisted === null ? emptyState() : this.#validateState(persisted);
    }
    return operation(this.state);
  }

  async #mutate(operation) {
    await this.initialize();
    const run = this.serial.then(async () => {
      if (this.store?.shared) {
        const persisted = await this.store.load();
        this.state = persisted === null ? emptyState() : this.#validateState(persisted);
      }
      const draft = copy(this.state);
      const result = await operation(draft);
      if (this.store) await this.store.save(draft);
      this.state = draft;
      return result;
    });
    this.serial = run.catch(() => {});
    return run;
  }

  #now() { return timestamp(this.clock()); }

  #prune(draft, now) {
    const cutoff = now.getTime() - this.limits.claimWindowMs;
    draft.claimAttempts = draft.claimAttempts.filter((entry) => Number.isFinite(entry) && entry > cutoff).slice(-this.limits.maxAttemptHistory);
    if (draft.sessions.length < this.limits.maxSessions) return;
    draft.sessions.sort((a, b) => Date.parse(a.createdAt) - Date.parse(b.createdAt));
    draft.sessions = draft.sessions.filter((session) => session.provedAt || (!TERMINAL.has(session.status) && now.getTime() < Date.parse(session.expiresAt)));
  }

  async create({ tenantId, userId, email, ttlMs, authorizedPublicKeySpkiPem, authorizedInstallationScope, authorizedDeploymentId } = {}) {
    assertIdentifier(tenantId, 'tenant ID');
    assertIdentifier(userId, 'user ID');
    if (email !== undefined && (typeof email !== 'string' || email.length > 320 || !email.includes('@'))) throw new Error('Trusted account email is invalid');
    const tokenTtlMs = ttlMs === undefined ? this.limits.codeTtlMs : ttlMs;
    if (!Number.isSafeInteger(tokenTtlMs) || tokenTtlMs < 60 * 1000 || tokenTtlMs > this.limits.codeTtlMs) throw new Error('Trusted setup token TTL is invalid');
    const authorizedIdentity = authorizedPublicKeySpkiPem === undefined ? null : canonicalEd25519(authorizedPublicKeySpkiPem).canonical;
    const authorizedScope = authorizedInstallationScope === undefined ? null : validateInstallationScope(authorizedInstallationScope);
    if ((authorizedIdentity === null) !== (authorizedScope === null)) throw new Error('Trusted CLI authorization binding is incomplete');
    if (authorizedDeploymentId !== undefined && (!authorizedIdentity || !/^dpl_[A-Za-z0-9_-]{32}$/.test(authorizedDeploymentId))) throw new Error('Trusted CLI authorization deployment is invalid');
    return this.#mutate(async (draft) => {
      if (draft.deletedTenants.includes(tenantId)) throw new Error('Tenant has been deleted');
      const now = this.#now();
      this.#prune(draft, now);
      const completedDeploymentIds = [...new Set(draft.sessions
        .filter((session) => session.tenantId === tenantId && session.provedAt && session.status !== 'failed' && !session.recovery && typeof session.deploymentId === 'string')
        .map((session) => session.deploymentId))];
      let hasActiveNetwork = completedDeploymentIds.length > 0;
      if (hasActiveNetwork && this.activeDeploymentChecker) {
        hasActiveNetwork = await this.activeDeploymentChecker({ tenantId, deploymentIds: completedDeploymentIds });
        if (typeof hasActiveNetwork !== 'boolean') throw new Error('Active deployment checker returned an invalid result');
      }
      if (hasActiveNetwork) throw new Error('Account already has an active network');
      const activeInstaller = draft.sessions.some((session) => session.tenantId === tenantId
        && !session.provedAt
        && !TERMINAL.has(session.status)
        && (session.status === 'connected'
          || (session.status === 'claimed' && Number.isFinite(Date.parse(session.claimedAt)) && now.getTime() - Date.parse(session.claimedAt) < STALLED_CLAIM_MS)));
      if (activeInstaller) throw new Error('Account already has an active setup');
      for (const session of draft.sessions) {
        const stalledClaim = session.status === 'claimed'
          && Number.isFinite(Date.parse(session.claimedAt))
          && now.getTime() - Date.parse(session.claimedAt) >= STALLED_CLAIM_MS;
        if (session.tenantId === tenantId && !session.provedAt && !TERMINAL.has(session.status) && !session.recovery && stalledClaim) {
          session.status = 'failed';
          session.setupTokenHash = null;
          delete session.sessionTokenHash;
          delete session.challenge;
        }
      }
      if (draft.sessions.length >= this.limits.maxSessions) throw new Error('Setup session capacity reached');
      if (authorizedDeploymentId && draft.sessions.some((session) => session.deploymentId === authorizedDeploymentId)) throw new Error('Trusted CLI authorization deployment is unavailable');
      let setupToken;
      let setupTokenHash;
      for (let attempt = 0; attempt < 16; attempt += 1) {
        setupToken = randomToken(this.randomBytes, 32, 'lst_');
        setupTokenHash = secretHash(setupToken);
        if (!draft.sessions.some((session) => session.setupTokenHash === setupTokenHash)) break;
        setupToken = null;
      }
      if (!setupToken) throw new Error('Unable to generate a unique setup token');
      let supportToken;
      let supportTokenHash;
      for (let attempt = 0; attempt < 16; attempt += 1) {
        supportToken = randomToken(this.randomBytes, 32, 'ldw_');
        supportTokenHash = secretHash(supportToken);
        if (!draft.sessions.some((session) => session.supportTokenHash === supportTokenHash)) break;
        supportToken = null;
      }
      if (!supportToken) throw new Error('Unable to generate a unique setup support token');
      let id;
      for (let attempt = 0; attempt < 16; attempt += 1) {
        id = randomToken(this.randomBytes, 18, 'set_');
        if (!draft.sessions.some((session) => session.id === id)) break;
        id = null;
      }
      if (!id) throw new Error('Unable to generate a unique setup session identifier');
      const expiresAt = new Date(now.getTime() + tokenTtlMs).toISOString();
      draft.sessions.push({
        id, tenantId, userId, ...(email ? { accountEmail: email } : {}), setupTokenHash, supportTokenHash,
        ...(authorizedIdentity ? { authorizedPublicKeySpkiPem: authorizedIdentity, authorizedInstallationScope: authorizedScope } : {}),
        ...(authorizedDeploymentId ? { deploymentId: authorizedDeploymentId } : {}),
        tokenAttempts: 0, createdAt: now.toISOString(), expiresAt, status: 'pending', recovery: false
      });
      return { session_id: id, setup_token: setupToken, support_token: supportToken, expires_at: expiresAt };
    });
  }

  async createRecovery({ tenantId, deploymentId } = {}) {
    assertIdentifier(tenantId, 'tenant ID');
    if (typeof deploymentId !== 'string' || !/^dpl_[A-Za-z0-9_-]{32}$/.test(deploymentId)) throw new Error('Deployment is unavailable');
    return this.#mutate(async (draft) => {
      const source = [...draft.sessions].reverse().find((session) => session.tenantId === tenantId && session.deploymentId === deploymentId && session.provedAt && session.status !== 'failed');
      if (!source) throw new Error('Deployment is unavailable');
      const existing = [...draft.sessions].reverse().find((session) => session.recovery && session.recoveryForDeploymentId === deploymentId && PRECLAIM.has(session.status) && session.setupToken && session.supportToken && this.#now().getTime() < Date.parse(session.expiresAt));
      if (existing) return { session_id: existing.id, setup_token: existing.setupToken, support_token: existing.supportToken, expires_at: existing.expiresAt, recovery: true, deployment_id: deploymentId, notification_email: existing.accountEmail || source.accountEmail || null };
      const now = this.#now();
      let id;
      let setupToken;
      let supportToken;
      for (let attempt = 0; attempt < 16; attempt += 1) {
        id = randomToken(this.randomBytes, 18, 'set_');
        if (!draft.sessions.some((session) => session.id === id)) break;
        id = null;
      }
      for (let attempt = 0; attempt < 16; attempt += 1) {
        setupToken = randomToken(this.randomBytes, 32, 'lrc_');
        if (!draft.sessions.some((session) => equalSecretHash(session.setupTokenHash, setupToken))) break;
        setupToken = null;
      }
      for (let attempt = 0; attempt < 16; attempt += 1) {
        supportToken = randomToken(this.randomBytes, 32, 'ldw_');
        if (!draft.sessions.some((session) => equalSecretHash(session.supportTokenHash, supportToken))) break;
        supportToken = null;
      }
      if (!id || !setupToken || !supportToken) throw new Error('Unable to generate a unique recovery session');
      const expiresAt = new Date(now.getTime() + this.limits.codeTtlMs).toISOString();
      draft.sessions.push({ id, tenantId, userId: source.userId, ...(source.accountEmail ? { accountEmail: source.accountEmail } : {}), setupTokenHash: secretHash(setupToken), supportTokenHash: secretHash(supportToken), setupToken, supportToken, tokenAttempts: 0, createdAt: now.toISOString(), expiresAt, status: 'pending', recovery: true, recoveryForDeploymentId: deploymentId });
      return { session_id: id, setup_token: setupToken, support_token: supportToken, expires_at: expiresAt, recovery: true, deployment_id: deploymentId, notification_email: source.accountEmail || null };
    });
  }

  async browserRecovery({ tenantId, deploymentId } = {}) {
    assertIdentifier(tenantId, 'tenant ID');
    return this.#read((state) => {
      const now = this.#now();
      const session = [...state.sessions].reverse().find((entry) => entry.tenantId === tenantId && entry.recovery && entry.recoveryForDeploymentId === deploymentId && PRECLAIM.has(entry.status) && entry.setupToken && entry.supportToken && now.getTime() < Date.parse(entry.expiresAt));
      if (!session) return null;
      return { session_id: session.id, setup_token: session.setupToken, support_token: session.supportToken, expires_at: session.expiresAt, recovery: true, deployment_id: deploymentId };
    });
  }

  async activeRecovery({ tenantId, deploymentId } = {}) {
    assertIdentifier(tenantId, 'tenant ID');
    return this.#read((state) => {
      const now = this.#now();
      return state.sessions.some((entry) => entry.tenantId === tenantId && entry.recovery && entry.recoveryForDeploymentId === deploymentId && !TERMINAL.has(entry.status) && now.getTime() < Date.parse(entry.expiresAt));
    });
  }

  async cancelRecovery({ tenantId, deploymentId } = {}) {
    assertIdentifier(tenantId, 'tenant ID');
    if (typeof deploymentId !== 'string' || !/^dpl_[A-Za-z0-9_-]{32}$/.test(deploymentId)) throw new Error('Deployment is unavailable');
    return this.#mutate(async (draft) => {
      let cancelled = 0;
      for (const session of draft.sessions) {
        if (session.tenantId !== tenantId || !session.recovery || session.recoveryForDeploymentId !== deploymentId || TERMINAL.has(session.status)) continue;
        session.status = 'failed';
        session.setupTokenHash = null;
        session.supportTokenHash = null;
        delete session.setupToken;
        delete session.supportToken;
        delete session.sessionTokenHash;
        delete session.challenge;
        cancelled += 1;
      }
      return { cancelled };
    });
  }

  async createSession(trustedContext) { return this.create(trustedContext); }
  async createSetupSession(trustedContext) { return this.create(trustedContext); }


  async deleteTenant({ tenantId, userId } = {}) {
    assertIdentifier(tenantId, 'tenant ID');
    assertIdentifier(userId, 'user ID');
    if (tenantId !== userId) throw new Error('Shared tenant deletion requires an administrator');
    return this.#mutate(async (draft) => {
      const removedSessions = draft.sessions.filter((session) => session.tenantId === tenantId).length;
      draft.sessions = draft.sessions.filter((session) => session.tenantId !== tenantId);
      if (!draft.deletedTenants.includes(tenantId)) {
        if (draft.deletedTenants.length >= 100000) throw new Error('Tenant deletion capacity reached');
        draft.deletedTenants.push(tenantId);
        draft.deletedTenants.sort();
      }
      return { removedSessions };
    });
  }

  async restoreTenantAfterFailedDeletion({ tenantId, userId } = {}) {
    assertIdentifier(tenantId, 'tenant ID');
    assertIdentifier(userId, 'user ID');
    if (tenantId !== userId) throw new Error('Shared tenant deletion recovery requires an administrator');
    return this.#mutate(async (draft) => {
      const before = draft.deletedTenants.length;
      draft.deletedTenants = draft.deletedTenants.filter((candidate) => candidate !== tenantId);
      return { restored: draft.deletedTenants.length !== before };
    });
  }

  async connect(input = {}) {
    if (Object.hasOwn(input, 'tenantId') || Object.hasOwn(input, 'tenant_id')) throw new Error('Connection requests may not supply a tenant ID');
    const setupToken = input.setupToken ?? input.setup_token;
    if (typeof setupToken !== 'string' || !/^(?:lst|lrc)_[A-Za-z0-9_-]{43}$/.test(setupToken)) throw new Error('Setup token is unavailable');
    const result = await this.#mutate(async (draft) => {
      const now = this.#now();
      this.#prune(draft, now);
      if (draft.claimAttempts.length >= this.limits.maxClaimsPerWindow) throw new Error('Setup connection rate limit reached');
      draft.claimAttempts.push(now.getTime());
      draft.claimAttempts = draft.claimAttempts.slice(-this.limits.maxAttemptHistory);
      let session = null;
      for (const candidate of draft.sessions) {
        if (equalSecretHash(candidate.setupTokenHash, setupToken)) session = candidate;
      }
      const retryable = session?.status !== 'complete' && (Boolean(session?.bootstrapConnectedAt) || session?.status === 'failed');
      if (!session || (!PRECLAIM.has(session.status) && !retryable) || !session.setupTokenHash || (!retryable && now.getTime() >= Date.parse(session.expiresAt))) return { connectRejected: true };
      for (const candidate of draft.sessions) {
        if (candidate.id === session.id || candidate.tenantId !== session.tenantId || candidate.recovery || candidate.provedAt || candidate.status !== 'pending') continue;
        candidate.status = 'failed';
        candidate.setupTokenHash = null;
        delete candidate.sessionTokenHash;
        delete candidate.challenge;
      }
      if (PRECLAIM.has(session.status) || (session.status === 'failed' && !session.publicKeySpkiPem)) session.status = 'connected';
      session.bootstrapConnectedAt ||= now.toISOString();
      session.expiresAt = new Date(now.getTime() + this.limits.sessionTtlMs).toISOString();
      return { accepted: true };
    });
    if (result.connectRejected) throw new Error('Setup token is unavailable');
    return result;
  }

  async reportPreclaimFailure(input = {}) {
    if (Object.hasOwn(input, 'tenantId') || Object.hasOwn(input, 'tenant_id')) throw new Error('Failure reports may not supply a tenant ID');
    const setupToken = input.setupToken ?? input.setup_token;
    const code = input.code;
    if (typeof setupToken !== 'string' || !/^(?:lst|lrc)_[A-Za-z0-9_-]{43}$/.test(setupToken) || !PRECLAIM_FAILURE_CODES.has(code)) throw new Error('Setup token is unavailable');
    const result = await this.#mutate(async (draft) => {
      const now = this.#now();
      this.#prune(draft, now);
      if (draft.claimAttempts.length >= this.limits.maxClaimsPerWindow) throw new Error('Setup failure reporting rate limit reached');
      draft.claimAttempts.push(now.getTime());
      draft.claimAttempts = draft.claimAttempts.slice(-this.limits.maxAttemptHistory);
      let session = null;
      for (const candidate of draft.sessions) if (equalSecretHash(candidate.setupTokenHash, setupToken)) session = candidate;
      if (!session || !PRECLAIM.has(session.status) || !session.setupTokenHash || now.getTime() >= Date.parse(session.expiresAt)) return { rejected: true };
      session.status = 'failed';
      session.failureCode = code;
      session.phaseUpdatedAt = now.toISOString();
      return { accepted: true };
    });
    if (result.rejected) throw new Error('Setup token is unavailable');
    return result;
  }

  async diagnosticContextBySetupToken(input = {}) {
    if (Object.hasOwn(input, 'tenantId') || Object.hasOwn(input, 'tenant_id') || Object.hasOwn(input, 'userId') || Object.hasOwn(input, 'user_id')) throw new Error('Diagnostic requests may not supply account identity');
    const setupToken = input.setupToken ?? input.setup_token;
    if (typeof setupToken !== 'string' || !/^(?:lst|lrc)_[A-Za-z0-9_-]{43}$/.test(setupToken)) throw new Error('Setup token is unavailable');
    return this.#read((state) => {
      const now = this.#now();
      let matched = null;
      for (const session of state.sessions) if (typeof session.setupTokenHash === 'string' && equalSecretHash(session.setupTokenHash, setupToken) && now.getTime() < Date.parse(session.expiresAt)) matched = session;
      if (!matched) throw new Error('Setup token is unavailable');
      return {
        tenantId: matched.tenantId,
        userId: matched.userId,
        email: matched.accountEmail || null,
        sessionId: matched.id,
        deploymentId: matched.deploymentId || matched.recoveryForDeploymentId || null
      };
    });
  }

  async diagnosticContextBySupportToken(input = {}) {
    if (Object.hasOwn(input, 'tenantId') || Object.hasOwn(input, 'tenant_id') || Object.hasOwn(input, 'userId') || Object.hasOwn(input, 'user_id')) throw new Error('Diagnostic requests may not supply account identity');
    const supportToken = input.supportToken ?? input.support_token;
    if (typeof supportToken !== 'string' || !/^ldw_[A-Za-z0-9_-]{43}$/.test(supportToken)) throw new Error('Support token is unavailable');
    return this.#read((state) => {
      const now = this.#now();
      let matched = null;
      for (const session of state.sessions) if (typeof session.supportTokenHash === 'string' && equalSecretHash(session.supportTokenHash, supportToken) && now.getTime() < Date.parse(session.expiresAt)) matched = session;
      if (!matched) throw new Error('Support token is unavailable');
      return {
        tenantId: matched.tenantId,
        userId: matched.userId,
        email: matched.accountEmail || null,
        sessionId: matched.id,
        deploymentId: matched.deploymentId || matched.recoveryForDeploymentId || null
      };
    });
  }

  async claim(input = {}) {
    if (Object.hasOwn(input, 'tenantId') || Object.hasOwn(input, 'tenant_id')) throw new Error('Claim requests may not supply a tenant ID');
    const setupToken = input.setupToken ?? input.setup_token;
    if (typeof setupToken !== 'string' || !/^(?:lst|lrc)_[A-Za-z0-9_-]{43}$/.test(setupToken)) throw new Error('Setup token is unavailable');
    const installationScope = validateInstallationScope(input.installationScope ?? input.installation_scope);
    const identityValue = input.publicKeySpkiPem ?? input.public_key_spki_pem ?? input.deploymentIdentity?.public_key_spki_pem ?? input.deployment_identity?.public_key_spki_pem;
    const identity = canonicalEd25519(identityValue);
    const result = await this.#mutate(async (draft) => {
      const now = this.#now();
      this.#prune(draft, now);
      if (draft.claimAttempts.length >= this.limits.maxClaimsPerWindow) throw new Error('Setup claim rate limit reached');
      draft.claimAttempts.push(now.getTime());
      draft.claimAttempts = draft.claimAttempts.slice(-this.limits.maxAttemptHistory);
      let session = null;
      for (const candidate of draft.sessions) {
        if (equalSecretHash(candidate.setupTokenHash, setupToken)) session = candidate;
      }
      const retryable = session?.status !== 'complete' && (Boolean(session?.bootstrapConnectedAt) || session?.status === 'failed');
      if (!session || (!PRECLAIM.has(session.status) && !retryable) || !session.setupTokenHash || session.tokenAttempts >= this.limits.maxCodeAttempts || (!retryable && now.getTime() >= Date.parse(session.expiresAt))) return { claimRejected: true };
      if (session.authorizedPublicKeySpkiPem && session.authorizedPublicKeySpkiPem !== identity.canonical) return { claimRejected: true };
      if (session.authorizedInstallationScope && JSON.stringify(session.authorizedInstallationScope) !== JSON.stringify(installationScope)) return { claimRejected: true };
      const tenantBinding = Buffer.from(session.tenantId, 'utf8');
      const derivedDeploymentId = `dpl_${crypto.createHash('sha256').update(tenantBinding).update(Buffer.from([0])).update(identity.der).digest('base64url').slice(0, 32)}`;
      const replacingIdentity = retryable && session.publicKeySpkiPem && session.publicKeySpkiPem !== identity.canonical;
      const reclaiming = retryable && Boolean(session.publicKeySpkiPem);
      const deploymentId = session.recoveryForDeploymentId || (replacingIdentity ? derivedDeploymentId : session.deploymentId || derivedDeploymentId);
      if (retryable) {
        delete session.bootstrapKey;
        delete session.bootstrapKeyPublishedAt;
      }
      if (reclaiming && this.deploymentReplacementHandler) await this.deploymentReplacementHandler({ tenantId: session.tenantId, deploymentId: session.deploymentId, replacementDeploymentId: deploymentId });
      if (replacingIdentity) {
        session.consoleCredentialHash = null;
        delete session.provisioning;
        delete session.provedAt;
        delete session.proofSignatureHash;
      }
      const token = randomToken(this.randomBytes, 32);
      const challenge = randomToken(this.randomBytes, 32);
      session.tokenAttempts = 1;
      session.installationScope = installationScope;
      session.publicKeySpkiPem = identity.canonical;
      session.deploymentId = deploymentId;
      session.sessionTokenHash = secretHash(token);
      session.challenge = challenge;
      session.proofAttempts = 0;
      session.claimedAt = now.toISOString();
      session.expiresAt = new Date(now.getTime() + this.limits.sessionTtlMs).toISOString();
      session.status = 'claimed';
      return { session_id: session.id, deployment_id: deploymentId, session_token: token, challenge, expires_at: session.expiresAt, installation_scope: copy(installationScope), recovery: session.recovery === true };
    });
    if (result.claimRejected) throw new Error('Setup token is unavailable');
    return result;
  }

  async claimSession(input) { return this.claim(input); }

  #authenticate(draft, sessionId, sessionToken, now, { allowExpired = false } = {}) {
    const session = draft.sessions.find((entry) => entry.id === sessionId);
    const supplied = typeof sessionToken === 'string' ? sessionToken : '';
    const matches = equalSecretHash(session?.sessionTokenHash, supplied);
    if (!session || !matches) throw new Error('Setup session is unavailable');
    if (!allowExpired && !TERMINAL.has(session.status) && now.getTime() >= Date.parse(session.expiresAt)) throw new Error('Setup session is expired');
    return session;
  }

  async prove(input = {}) {
    if (Object.hasOwn(input, 'tenantId') || Object.hasOwn(input, 'tenant_id')) throw new Error('Proof requests may not supply a tenant ID');
    const sessionId = input.sessionId ?? input.session_id;
    const sessionToken = input.sessionToken ?? input.session_token;
    const encoded = input.signatureBase64url ?? input.signature_base64url;
    if (typeof encoded !== 'string' || !/^[A-Za-z0-9_-]{86}$/.test(encoded)) throw new Error('Deployment possession proof is invalid');
    const signature = Buffer.from(encoded, 'base64url');
    if (signature.length !== 64 || signature.toString('base64url') !== encoded) throw new Error('Deployment possession proof is invalid');
    const result = await this.#mutate(async (draft) => {
      const now = this.#now();
      const session = this.#authenticate(draft, sessionId, sessionToken, now);
      if (session.status === 'claimed' && session.provedAt && session.provisioning && equalSecretHash(session.proofSignatureHash, encoded)) {
        return { verified: true, provisioning: copy(session.provisioning) };
      }
      if (typeof session.challenge !== 'string' || session.status !== 'claimed' || session.proofAttempts >= this.limits.maxProofAttempts) throw new Error('Deployment possession proof is unavailable');
      const message = Buffer.concat([PROOF_DOMAIN, Buffer.from(session.id, 'utf8'), Buffer.from([0]), Buffer.from(session.challenge, 'base64url')]);
      if (!crypto.verify(null, message, session.publicKeySpkiPem, signature)) {
        session.proofAttempts += 1;
        return { proofRejected: true };
      }
      let provisioning = session.provisioning;
      if (!session.provedAt) {
        const context = Object.freeze({ tenantId: session.tenantId, userId: session.userId, deploymentId: session.deploymentId, sessionId: session.id });
        const factory = typeof this.provisioningFactory === 'function' ? this.provisioningFactory : (this.provisioningFactory.provision || this.provisioningFactory.create).bind(this.provisioningFactory);
        provisioning = this.#validateProvisioning(await factory(context), draft, session.id);
        for (const prior of draft.sessions) {
          if (prior.id !== session.id && prior.deploymentId === session.deploymentId) prior.consoleCredentialHash = null;
        }
        session.provisioning = copy(provisioning);
        session.consoleCredentialHash = secretHash(provisioning.console_sync.credential);
      }
      session.challenge = null;
      session.proofSignatureHash = secretHash(encoded);
      session.provedAt = now.toISOString();
      session.expiresAt = new Date(now.getTime() + this.limits.sessionTtlMs).toISOString();
      return { verified: true, provisioning: copy(provisioning) };
    });
    if (result.proofRejected) throw new Error('Deployment possession proof is invalid');
    return result;
  }

  async proveSession(input) { return this.prove(input); }

  #validateProvisioning(value, draft, sessionId) {
    const sync = value?.console_sync;
    if (!value || typeof value !== 'object' || Array.isArray(value) || !sync || typeof sync !== 'object' || Array.isArray(sync)) throw new Error('Provisioning factory returned invalid provisioning');
    for (const [candidate, label] of [[sync.endpoint, 'console sync endpoint'], [value.dashboard_url, 'dashboard URL']]) {
      let url;
      try { url = new URL(candidate); } catch { throw new Error(`Provisioning factory returned an invalid ${label}`); }
      if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash) throw new Error(`Provisioning factory returned an invalid ${label}`);
    }
    if (typeof sync.credential !== 'string' || sync.credential.length < 32 || sync.credential.length > 4096 || !/^[\x21-\x7e]+$/.test(sync.credential)) throw new Error('Provisioning factory returned an invalid console credential');
    const hash = secretHash(sync.credential);
    if (draft.sessions.some((entry) => entry.id !== sessionId && equalSecretHash(entry.consoleCredentialHash, sync.credential))) throw new Error('Provisioning factory reused a console credential');
    if (!hash) throw new Error('Provisioning factory returned an invalid console credential');
    return {
      console_sync: { endpoint: sync.endpoint, credential: sync.credential },
      dashboard_url: value.dashboard_url
    };
  }

  async status(input = {}) {
    if (Object.hasOwn(input, 'tenantId') || Object.hasOwn(input, 'tenant_id')) throw new Error('Status requests may not supply a tenant ID');
    const sessionId = input.sessionId ?? input.session_id;
    const sessionToken = input.sessionToken ?? input.session_token;
    return this.#read((state) => {
      const now = this.#now();
      const session = this.#authenticate(state, sessionId, sessionToken, now, { allowExpired: true });
      const result = publicSession(session, now);
      if (session.status !== 'pending') {
        result.deployment_id = session.deploymentId;
        if (session.challenge) result.challenge = session.challenge;
      }
      if (result.status === 'complete' && session.provisioning?.dashboard_url) result.dashboard_url = session.provisioning.dashboard_url;
      return result;
    });
  }

  async getStatus(input) { return this.status(input); }

  async recordDiagnostic(input = {}) {
    const sessionId = input.sessionId ?? input.session_id;
    const sessionToken = input.sessionToken ?? input.session_token;
    const value = input.diagnostic;
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Setup diagnostic is invalid');
    const allowed = new Set(['phase', 'vm', 'error_code', 'message', 'cli_version', 'installer_version']);
    if (Object.keys(value).some((key) => !allowed.has(key))) throw new Error('Setup diagnostic is invalid');
    const clean = {};
    for (const [key, limit] of [['phase', 64], ['vm', 255], ['error_code', 128], ['message', 2048], ['cli_version', 64], ['installer_version', 64]]) {
      if (value[key] === undefined) continue;
      if (typeof value[key] !== 'string' || !value[key] || value[key].length > limit || /(?:bearer\s+|private[ _-]?key|setup[_ -]?token|session[_ -]?token|password)/i.test(value[key])) throw new Error('Setup diagnostic contains unsafe content');
      clean[key] = value[key];
    }
    if (!clean.phase || !clean.message) throw new Error('Setup diagnostic is invalid');
    return this.#mutate((draft) => {
      const now = this.#now();
      const session = this.#authenticate(draft, sessionId, sessionToken, now, { allowExpired: true });
      if (!session.provedAt) throw new Error('Setup diagnostic requires proof of possession');
      const diagnostic = { id: randomToken(this.randomBytes, 12, 'diag_'), occurredAt: now.toISOString(), ...clean };
      session.diagnostics = [...(session.diagnostics || []), diagnostic].slice(-50);
      return { diagnostic_id: diagnostic.id };
    });
  }

  async authenticateConsoleCredential({ deploymentId, credential } = {}) {
    if (typeof deploymentId !== 'string' || !/^dpl_[A-Za-z0-9_-]{32}$/.test(deploymentId) || typeof credential !== 'string' || credential.length < 32 || credential.length > 4096) throw new Error('Console credential is unavailable');
    return this.#read((state) => {
      let matched = null;
      for (const session of state.sessions) {
        const valid = session.deploymentId === deploymentId && typeof session.consoleCredentialHash === 'string' && equalSecretHash(session.consoleCredentialHash, credential);
        if (valid) matched = session;
      }
      if (!matched?.provedAt) throw new Error('Console credential is unavailable');
      return { tenantId: matched.tenantId, userId: matched.userId, deploymentId: matched.deploymentId };
    });
  }

  async authorizeBrowserDeployment({ deploymentId, tenantId } = {}) {
    assertIdentifier(tenantId, 'tenant ID');
    if (typeof deploymentId !== 'string' || !/^dpl_[A-Za-z0-9_-]{32}$/.test(deploymentId)) throw new Error('Deployment is unavailable');
    return this.#read((state) => {
      const session = [...state.sessions].reverse().find((entry) => entry.deploymentId === deploymentId && entry.tenantId === tenantId && entry.provedAt);
      if (!session) throw new Error('Deployment is unavailable');
      return { tenantId: session.tenantId, deploymentId: session.deploymentId, status: session.status };
    });
  }

  async browserStatus({ sessionId, tenantId, userId } = {}) {
    assertIdentifier(tenantId, 'tenant ID');
    assertIdentifier(userId, 'user ID');
    return this.#read((state) => {
      const now = this.#now();
      const session = state.sessions.find((entry) => entry.id === sessionId);
      if (!session || session.tenantId !== tenantId || session.userId !== userId) throw new Error('Setup session is unavailable');
      const result = publicSession(session, now);
      if (session.recovery) result.recovery = true;
      if (session.installationScope) result.installation_scope = copy(session.installationScope);
      if (session.deploymentId) result.deployment_id = session.deploymentId;
      if (session.diagnostics?.length) result.diagnostics = copy(session.diagnostics);
      if (result.status === 'complete' && session.provisioning?.dashboard_url) result.dashboard_url = session.provisioning.dashboard_url;
      return result;
    });
  }

  async browserActiveStatus({ tenantId, userId } = {}) {
    assertIdentifier(tenantId, 'tenant ID');
    assertIdentifier(userId, 'user ID');
    return this.#read((state) => {
      const now = this.#now();
      const session = [...state.sessions].reverse().find((entry) => entry.tenantId === tenantId
        && !entry.dismissedAt
        && (!TERMINAL.has(entry.status) || (entry.status === 'failed' && entry.provedAt))
        && now.getTime() < Date.parse(entry.expiresAt)
        && !(entry.status === 'claimed' && !entry.provedAt && now.getTime() - Date.parse(entry.claimedAt) >= STALLED_CLAIM_MS)
        && (entry.bootstrapConnectedAt || entry.provedAt));
      if (!session) return { setup: null };
      const setup = { session_id: session.id, ...publicSession(session, now) };
      if (session.recovery) setup.recovery = true;
      if (session.deploymentId) setup.deployment_id = session.deploymentId;
      return { setup };
    });
  }

  async dismissFailed({ tenantId, userId } = {}) {
    assertIdentifier(tenantId, 'tenant ID');
    assertIdentifier(userId, 'user ID');
    return this.#mutate(async (draft) => {
      const now = this.#now().toISOString();
      let dismissed = 0;
      for (const session of draft.sessions) {
        if (session.tenantId !== tenantId || session.status !== 'failed' || !session.provedAt || session.dismissedAt) continue;
        session.dismissedAt = now;
        dismissed += 1;
      }
      return { dismissed };
    });
  }

  async publishBootstrapKey(input = {}) {
    const sessionId = input.sessionId ?? input.session_id;
    const sessionToken = input.sessionToken ?? input.session_token;
    const key = validateBootstrapKey(input.bootstrapKey ?? input.bootstrap_key);
    return this.#mutate(async (draft) => {
      const now = this.#now();
      const session = this.#authenticate(draft, sessionId, sessionToken, now);
      if (!session.provedAt || TERMINAL.has(session.status)) throw new Error('Bootstrap public key cannot be published for this setup session');
      if (session.bootstrapKey && JSON.stringify(session.bootstrapKey) !== JSON.stringify(key)) throw new Error('Bootstrap public key cannot be changed');
      session.bootstrapKey = key;
      session.bootstrapKeyPublishedAt ||= now.toISOString();
      session.expiresAt = new Date(now.getTime() + this.limits.sessionTtlMs).toISOString();
      return { accepted: true };
    });
  }

  async reportPhase(input = {}) {
    if (Object.hasOwn(input, 'tenantId') || Object.hasOwn(input, 'tenant_id')) throw new Error('Phase requests may not supply a tenant ID');
    const sessionId = input.sessionId ?? input.session_id;
    const sessionToken = input.sessionToken ?? input.session_token;
    const requestedPhase = input.phase;
    const phase = LEGACY_PHASES.get(requestedPhase) || requestedPhase;
    const completed = input.completed;
    const total = input.total;
    if (phase !== 'failed' && !PHASES.includes(phase) && !INTERRUPTIONS.has(phase)) throw new Error('Setup phase is invalid');
    if ((completed !== undefined || total !== undefined) && (!Number.isSafeInteger(completed) || !Number.isSafeInteger(total) || completed < 0 || total < 1 || completed > total)) throw new Error('Setup phase progress is invalid');
    return this.#mutate(async (draft) => {
      const now = this.#now();
      const session = this.#authenticate(draft, sessionId, sessionToken, now);
      if (!session.provedAt) throw new Error('Setup phase reporting requires proof of possession');
      if (TERMINAL.has(session.status)) {
        if (session.status === phase) return { accepted: true };
        throw new Error('Setup phase is terminal');
      }
      if (phase !== 'failed' && !INTERRUPTIONS.has(phase) && !INTERRUPTIONS.has(session.status)) {
        const previous = PHASES.indexOf(session.status);
        const next = PHASES.indexOf(phase);
        if (next < previous) throw new Error('Setup phase may not move backwards');
      }
      if (phase === 'complete' && this.completionValidator) {
        await this.completionValidator({ tenantId: session.tenantId, userId: session.userId, deploymentId: session.deploymentId, sessionId: session.id });
      }
      session.status = phase;
      if (phase === 'complete') { session.setupTokenHash = null; session.supportTokenHash = null; delete session.supportToken; }
      if (completed !== undefined) { session.completed = completed; session.total = total; }
      session.phaseUpdatedAt = now.toISOString();
      if (!TERMINAL.has(phase)) session.expiresAt = new Date(now.getTime() + this.limits.sessionTtlMs).toISOString();
      return { accepted: true };
    });
  }
}

module.exports = {
  SetupSessionAuthority,
  createSetupSessionAuthority: (options) => new SetupSessionAuthority(options),
  canonicalEd25519,
  validateInstallationScope
};

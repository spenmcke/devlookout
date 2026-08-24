#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const childProcess = require('node:child_process');
const { artifactPreflightScript } = require('../src/fleet/release-artifact');
const { verifyManifest } = require('../src/update/manifest');

const DEFAULT_CONFIG = '/etc/lookout-update/update.json';
const DEFAULT_STATE = '/var/lib/lookout-install/update-state.json';
const DEFAULT_LOCK = '/run/lookout-update/update.lock';
const DEFAULT_STATUS = '/run/lookout-update/status.json';
const MAXIMUM_MANIFEST_BYTES = 256 * 1024;

function architecture(value = process.arch) {
  if (['x64', 'amd64'].includes(value)) return 'amd64';
  if (['arm64', 'aarch64'].includes(value)) return 'arm64';
  throw new Error(`Unsupported update architecture: ${value}`);
}

function readJsonFile(filename, label, { missing = null, maximumBytes = 1024 * 1024 } = {}) {
  let stat;
  try { stat = fs.lstatSync(filename); } catch (error) { if (error.code === 'ENOENT') return missing; throw error; }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > maximumBytes) throw new Error(`${label} must be a bounded regular file`);
  try { return JSON.parse(fs.readFileSync(filename, 'utf8')); } catch { throw new Error(`${label} is not valid JSON`); }
}

function validateConfig(value) {
  if (!value || value.schemaVersion !== 1 || typeof value.channelUrl !== 'string' || !Array.isArray(value.artifactOrigins) || !Array.isArray(value.trustedKeys)) throw new Error('Update configuration is invalid');
  let channel;
  try { channel = new URL(value.channelUrl); } catch { throw new Error('Update channel URL is invalid'); }
  if (channel.protocol !== 'https:' || channel.username || channel.password || channel.search || channel.hash) throw new Error('Update channel URL is invalid');
  const origins = value.artifactOrigins.map((item) => {
    let origin;
    try { origin = new URL(item); } catch { throw new Error('Update artifact origin is invalid'); }
    if (origin.protocol !== 'https:' || origin.username || origin.password || origin.search || origin.hash || origin.pathname !== '/') throw new Error('Update artifact origin is invalid');
    return origin.origin;
  });
  if (origins.length < 1 || origins.length > 8 || new Set(origins).size !== origins.length) throw new Error('Update artifact origins are invalid');
  return { ...value, channelUrl: channel.toString(), artifactOrigins: origins };
}

function initialState() {
  return { schemaVersion: 1, highestSequence: 0, manifestDigest: null, currentArtifactSha256: null, previousArtifactSha256: null, etag: null, consecutiveFailures: 0, nextAttemptAt: null, lastResult: null };
}

function validateState(value) {
  const state = value || initialState();
  if (state.schemaVersion !== 1 || !Number.isSafeInteger(state.highestSequence) || state.highestSequence < 0 || !Number.isSafeInteger(state.consecutiveFailures) || state.consecutiveFailures < 0) throw new Error('Update state is invalid');
  for (const field of ['manifestDigest', 'currentArtifactSha256', 'previousArtifactSha256']) if (state[field] !== null && !/^[a-f0-9]{64}$/.test(state[field])) throw new Error('Update state digest is invalid');
  if (state.etag !== null && (typeof state.etag !== 'string' || Buffer.byteLength(state.etag) > 512)) throw new Error('Update state ETag is invalid');
  if (state.nextAttemptAt !== null && Number.isNaN(Date.parse(state.nextAttemptAt))) throw new Error('Update state retry time is invalid');
  return { ...initialState(), ...state };
}

function writeJsonAtomic(filename, value) {
  const directory = path.dirname(filename);
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  const temporary = path.join(directory, `.${path.basename(filename)}.${process.pid}.${crypto.randomUUID()}.tmp`);
  fs.writeFileSync(temporary, `${JSON.stringify(value)}\n`, { mode: 0o600, flag: 'wx' });
  fs.renameSync(temporary, filename);
}

function writePublicStatus(filename, result) {
  const directory = path.dirname(filename);
  fs.mkdirSync(directory, { recursive: true, mode: 0o755 });
  fs.chmodSync(directory, 0o755);
  const safe = {
    schemaVersion: 1,
    status: result?.status || 'unknown',
    release: typeof result?.release === 'string' ? result.release : null,
    sequence: Number.isSafeInteger(result?.sequence) ? result.sequence : null,
    at: typeof result?.at === 'string' ? result.at : new Date().toISOString(),
    code: typeof result?.code === 'string' ? result.code.slice(0, 200) : null
  };
  const temporary = path.join(directory, `.status.${process.pid}.${crypto.randomUUID()}.tmp`);
  fs.writeFileSync(temporary, `${JSON.stringify(safe)}\n`, { mode: 0o644, flag: 'wx' });
  fs.chmodSync(temporary, 0o644);
  fs.renameSync(temporary, filename);
}

async function boundedResponse(response, maximumBytes) {
  const declared = response.headers.get('content-length');
  if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > maximumBytes)) throw new Error('Update response exceeds its size limit');
  const chunks = [];
  let total = 0;
  for await (const chunk of response.body || []) {
    const bytes = Buffer.from(chunk);
    total += bytes.length;
    if (total > maximumBytes) throw new Error('Update response exceeds its size limit');
    chunks.push(bytes);
  }
  return Buffer.concat(chunks, total);
}

async function fetchManifest(config, state, fetchImpl = globalThis.fetch) {
  const headers = { Accept: 'application/json' };
  if (state.etag) headers['If-None-Match'] = state.etag;
  const response = await fetchImpl(config.channelUrl, { headers, redirect: 'error', signal: AbortSignal.timeout(15000) });
  if (response.status === 304) return { unchanged: true, etag: state.etag };
  if (!response.ok) throw new Error(`Update channel returned HTTP ${response.status}`);
  const body = await boundedResponse(response, MAXIMUM_MANIFEST_BYTES);
  let envelope;
  try { envelope = JSON.parse(body.toString('utf8')); } catch { throw new Error('Update channel returned invalid JSON'); }
  const contentType = response.headers.get('content-type') || '';
  if (!/^application\/json(?:;|$)/i.test(contentType)) throw new Error('Update channel returned an invalid content type');
  const etag = response.headers.get('etag');
  if (etag !== null && (Buffer.byteLength(etag) > 512 || /[\x00-\x1f\x7f]/.test(etag))) throw new Error('Update channel returned an invalid ETag');
  return { unchanged: false, envelope, etag };
}

async function downloadArtifact(artifact, destination, config, fetchImpl = globalThis.fetch) {
  const target = new URL(artifact.url);
  if (!config.artifactOrigins.includes(target.origin)) throw new Error('Update artifact origin is not allowed');
  const response = await fetchImpl(target, { redirect: 'follow', signal: AbortSignal.timeout(5 * 60 * 1000) });
  if (!response.ok) throw new Error(`Update artifact returned HTTP ${response.status}`);
  const finalUrl = new URL(response.url || target);
  if (finalUrl.protocol !== 'https:' || finalUrl.username || finalUrl.password) throw new Error('Update artifact redirect is invalid');
  if (response.headers.get('content-length') !== null && Number(response.headers.get('content-length')) !== artifact.size) throw new Error('Update artifact size does not match the manifest');
  const handle = fs.openSync(destination, 'wx', 0o600);
  const digest = crypto.createHash('sha256');
  let total = 0;
  try {
    for await (const chunk of response.body || []) {
      const bytes = Buffer.from(chunk);
      total += bytes.length;
      if (total > artifact.size) throw new Error('Update artifact exceeds the signed size');
      digest.update(bytes);
      fs.writeSync(handle, bytes);
    }
    fs.fsyncSync(handle);
  } finally { fs.closeSync(handle); }
  if (total !== artifact.size || digest.digest('hex') !== artifact.sha256) throw new Error('Update artifact does not match its signed digest');
}

function commandResult(result, label) {
  if (result.error || result.status !== 0) throw new Error(`${label} failed${String(result.stderr || '').trim() ? `: ${String(result.stderr).trim().slice(-1000)}` : ''}`);
  return result.stdout;
}

function systemctl(args, label) {
  return commandResult(childProcess.spawnSync('systemctl', args, { encoding: 'utf8', timeout: 5 * 60 * 1000, maxBuffer: 4 * 1024 * 1024 }), label);
}

function preflightArtifact(archive, digest, prepared, listing, validateRuntime) {
  const args = ['-c', artifactPreflightScript(), 'lookout-update-preflight', archive, digest, prepared, listing, validateRuntime ? '1' : '0'];
  return commandResult(childProcess.spawnSync('/bin/sh', args, { encoding: 'utf8', timeout: 5 * 60 * 1000, maxBuffer: 4 * 1024 * 1024 }), 'update artifact preflight');
}

function linkedRelease(prefix, linkName = 'current') {
  const link = path.join(prefix, linkName);
  const stat = fs.lstatSync(link);
  if (!stat.isSymbolicLink()) throw new Error('Current Lookout release is not an atomic link');
  const resolved = fs.realpathSync(link);
  const releases = fs.realpathSync(path.join(prefix, 'releases'));
  if (!resolved.startsWith(`${releases}${path.sep}`)) throw new Error('Current Lookout release escapes its release directory');
  return resolved;
}

function atomicLink(target, link) {
  const temporary = `${link}.update.${process.pid}`;
  try { fs.unlinkSync(temporary); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  fs.symlinkSync(target, temporary);
  fs.renameSync(temporary, link);
}

function activeUnits() {
  const units = [];
  for (const unit of ['lookout.service', 'lookout-collector.service']) {
    const result = childProcess.spawnSync('systemctl', ['is-active', '--quiet', unit], { timeout: 10000 });
    if (result.status === 0) units.push(unit);
  }
  return units;
}

function releaseCompatibility(directory, { allowLegacy = false } = {}) {
  const value = readJsonFile(path.join(directory, 'package.json'), 'Release package');
  const protocol = value?.lookout?.collectorProtocol;
  const minimum = value?.lookout?.minimumCollectorProtocol;
  if (allowLegacy && protocol === undefined && minimum === undefined) return { protocol: 1, minimum: 1 };
  if (!Number.isSafeInteger(protocol) || protocol < 1 || !Number.isSafeInteger(minimum) || minimum < 1 || minimum > protocol) throw new Error('Release collector compatibility metadata is invalid');
  return { protocol, minimum };
}

function validateRollingCompatibility(current, candidate) {
  const oldRelease = releaseCompatibility(current, { allowLegacy: true });
  const newRelease = releaseCompatibility(candidate);
  if (newRelease.minimum > oldRelease.protocol || oldRelease.minimum > newRelease.protocol) throw new Error('Release is not compatible with a rolling central and collector update');
}

function trustedKeysFromRelease(directory) {
  const value = readJsonFile(path.join(directory, 'config/update-signing-public-keys.json'), 'Release update signing keys', { maximumBytes: 64 * 1024 });
  if (!value || value.schemaVersion !== 1 || !Array.isArray(value.trustedKeys) || value.trustedKeys.length < 1 || value.trustedKeys.length > 8 || Object.keys(value).some((key) => !['schemaVersion', 'trustedKeys'].includes(key))) throw new Error('Release update signing keys are invalid');
  const identifiers = new Set();
  return value.trustedKeys.map((record) => {
    if (!record || Object.keys(record).sort().join(',') !== 'keyId,publicKeySpkiPem' || !/^[A-Za-z0-9._-]{1,64}$/.test(record.keyId || '') || typeof record.publicKeySpkiPem !== 'string' || identifiers.has(record.keyId)) throw new Error('Release update signing keys are invalid');
    let publicKey;
    try { publicKey = crypto.createPublicKey(record.publicKeySpkiPem); } catch { throw new Error('Release update signing keys are invalid'); }
    if (publicKey.asymmetricKeyType !== 'ed25519') throw new Error('Release update signing keys are invalid');
    identifiers.add(record.keyId);
    return { keyId: record.keyId, publicKeySpkiPem: publicKey.export({ type: 'spki', format: 'pem' }).toString() };
  });
}

function restartAndVerify(units) {
  systemctl(['daemon-reload'], 'systemd reload');
  for (const unit of units) systemctl(['restart', unit], `${unit} restart`);
  for (const unit of units) systemctl(['is-active', '--quiet', unit], `${unit} health check`);
}

function installPreparedRelease({ prepared, artifact, release, prefix = '/opt/lookout', advanceUpdater = true }) {
  const releases = path.join(prefix, 'releases');
  const releaseName = `${release.replace(/^v/, '')}-${artifact.sha256.slice(0, 16)}`;
  const destination = path.join(releases, releaseName);
  const previous = linkedRelease(prefix);
  const units = activeUnits();
  if (!fs.existsSync(destination)) {
    fs.renameSync(prepared, destination);
    fs.writeFileSync(path.join(destination, '.lookout-release'), `${releaseName}\n`, { mode: 0o644, flag: 'wx' });
  }
  validateRollingCompatibility(previous, destination);
  atomicLink(destination, path.join(prefix, 'current'));
  try { restartAndVerify(units); }
  catch (error) {
    atomicLink(previous, path.join(prefix, 'current'));
    restartAndVerify(units);
    throw new Error(`Update health verification failed and the previous release was restored: ${error.message}`);
  }
  if (advanceUpdater) atomicLink(destination, path.join(prefix, 'updater-current'));
  return { previous, current: destination };
}

function cleanOldReleases(prefix, keep) {
  const releases = path.join(prefix, 'releases');
  const retained = new Set(keep.map((item) => path.resolve(item)));
  for (const name of fs.readdirSync(releases).sort()) {
    const candidate = path.join(releases, name);
    if (retained.has(path.resolve(candidate))) continue;
    let stat;
    try { stat = fs.lstatSync(candidate); } catch { continue; }
    if (!stat.isDirectory() || stat.isSymbolicLink() || !fs.existsSync(path.join(candidate, '.lookout-release'))) continue;
    fs.rmSync(candidate, { recursive: true, force: false });
  }
}

function acquireLock(filename) {
  try {
    const descriptor = fs.openSync(filename, 'wx', 0o600);
    fs.writeFileSync(descriptor, `${process.pid}\n`);
    return () => { try { fs.closeSync(descriptor); } finally { try { fs.unlinkSync(filename); } catch {} } };
  } catch (error) {
    if (error.code !== 'EEXIST') throw error;
    const pid = Number(String(fs.readFileSync(filename, 'utf8')).trim());
    if (Number.isSafeInteger(pid) && pid > 1) {
      try { process.kill(pid, 0); return null; } catch (signalError) { if (signalError.code === 'EPERM') return null; }
    }
    fs.unlinkSync(filename);
    return acquireLock(filename);
  }
}

async function updateOnce(options = {}) {
  const configFile = options.configFile || process.env.LOOKOUT_UPDATE_CONFIG || DEFAULT_CONFIG;
  const stateFile = options.stateFile || process.env.LOOKOUT_UPDATE_STATE || DEFAULT_STATE;
  const lockFile = options.lockFile || process.env.LOOKOUT_UPDATE_LOCK || DEFAULT_LOCK;
  const statusFile = options.statusFile || process.env.LOOKOUT_UPDATE_STATUS || DEFAULT_STATUS;
  const prefix = options.prefix || process.env.LOOKOUT_PREFIX || '/opt/lookout';
  if (typeof process.getuid === 'function' && process.getuid() !== 0 && options.allowNonRoot !== true) throw new Error('Lookout updates must run as root');
  const releaseLock = acquireLock(lockFile);
  if (!releaseLock) return { status: 'already_running' };
  let state = validateState(readJsonFile(stateFile, 'Update state', { missing: null }));
  try {
    const now = options.now || new Date();
    if (state.nextAttemptAt && Date.parse(state.nextAttemptAt) > now.getTime()) return { status: 'backing_off', nextAttemptAt: state.nextAttemptAt };
    const config = validateConfig(readJsonFile(configFile, 'Update configuration'));
    const fetched = await fetchManifest(config, state, options.fetchImpl);
    if (fetched.unchanged) {
      state = { ...state, consecutiveFailures: 0, nextAttemptAt: null, lastResult: { status: 'unchanged', at: now.toISOString() } };
      writeJsonAtomic(stateFile, state);
      writePublicStatus(statusFile, state.lastResult);
      return state.lastResult;
    }
    const payload = verifyManifest(fetched.envelope, config.trustedKeys, { channel: 'stable' });
    const manifestDigest = crypto.createHash('sha256').update(JSON.stringify(fetched.envelope)).digest('hex');
    if (payload.sequence < state.highestSequence || (payload.sequence === state.highestSequence && state.manifestDigest && state.manifestDigest !== manifestDigest)) throw new Error('Update manifest sequence is a replay or equivocation');
    if (payload.action === 'pause') {
      state = { ...state, highestSequence: payload.sequence, manifestDigest, etag: fetched.etag, consecutiveFailures: 0, nextAttemptAt: null, lastResult: { status: 'paused', release: payload.release, sequence: payload.sequence, at: now.toISOString() } };
      writeJsonAtomic(stateFile, state);
      writePublicStatus(statusFile, state.lastResult);
      return state.lastResult;
    }
    const artifact = payload.artifacts[architecture(options.architecture)];
    if (artifact.sha256 === state.currentArtifactSha256) {
      state = { ...state, highestSequence: payload.sequence, manifestDigest, etag: fetched.etag, consecutiveFailures: 0, nextAttemptAt: null, lastResult: { status: 'current', release: payload.release, sequence: payload.sequence, at: now.toISOString() } };
      writeJsonAtomic(stateFile, state);
      writePublicStatus(statusFile, state.lastResult);
      return state.lastResult;
    }
    const workRoot = options.workRoot || path.join(path.dirname(stateFile), 'updates');
    fs.mkdirSync(workRoot, { recursive: true, mode: 0o700 });
    const work = fs.mkdtempSync(path.join(workRoot, '.update-'));
    const archive = path.join(work, 'artifact.tar.gz');
    const prepared = path.join(work, 'prepared');
    const listing = path.join(work, 'listing');
    try {
      await downloadArtifact(artifact, archive, config, options.fetchImpl);
      preflightArtifact(archive, artifact.sha256, prepared, listing, options.validateRuntime !== false);
      const candidateTrustedKeys = payload.action === 'install' ? trustedKeysFromRelease(prepared) : null;
      const installed = installPreparedRelease({ prepared, artifact, release: payload.release, prefix, advanceUpdater: payload.action === 'install' });
      if (payload.action === 'install') {
        writeJsonAtomic(configFile, { schemaVersion: 1, channelUrl: config.channelUrl, artifactOrigins: config.artifactOrigins, trustedKeys: candidateTrustedKeys });
      }
      let updaterRelease = null;
      try { updaterRelease = linkedRelease(prefix, 'updater-current'); } catch { /* A seed updater may live outside the application release directory. */ }
      cleanOldReleases(prefix, [installed.current, installed.previous, updaterRelease].filter(Boolean));
      state = { ...state, highestSequence: payload.sequence, manifestDigest, previousArtifactSha256: state.currentArtifactSha256, currentArtifactSha256: artifact.sha256, etag: fetched.etag, consecutiveFailures: 0, nextAttemptAt: null, lastResult: { status: payload.action === 'rollback' ? 'rolled_back' : 'updated', release: payload.release, sequence: payload.sequence, at: now.toISOString() } };
      writeJsonAtomic(stateFile, state);
      writePublicStatus(statusFile, state.lastResult);
      return state.lastResult;
    } finally { fs.rmSync(work, { recursive: true, force: true }); }
  } catch (error) {
    const failures = Math.min(16, state.consecutiveFailures + 1);
    const delayMinutes = Math.min(60, 2 ** Math.max(0, failures - 1));
    const failedAt = options.now || new Date();
    state = { ...state, consecutiveFailures: failures, nextAttemptAt: new Date(failedAt.getTime() + delayMinutes * 60000).toISOString(), lastResult: { status: 'failed', code: String(error.message).slice(0, 200), at: failedAt.toISOString() } };
    writeJsonAtomic(stateFile, state);
    writePublicStatus(statusFile, state.lastResult);
    throw error;
  } finally { releaseLock(); }
}

if (require.main === module) updateOnce().then((result) => process.stdout.write(`${JSON.stringify(result)}\n`)).catch((error) => { console.error(`lookout-update: ${error.message}`); process.exitCode = 1; });

module.exports = { architecture, validateConfig, validateState, fetchManifest, downloadArtifact, linkedRelease, releaseCompatibility, validateRollingCompatibility, trustedKeysFromRelease, installPreparedRelease, cleanOldReleases, acquireLock, writePublicStatus, updateOnce };

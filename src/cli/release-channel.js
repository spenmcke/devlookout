'use strict';

const crypto = require('node:crypto');
const { verifyManifest } = require('../update/manifest');
const updateSigningKeys = require('../../config/update-signing-public-keys.json');

const MAXIMUM_MANIFEST_BYTES = 256 * 1024;
const DEFAULT_ORIGIN = 'https://app.devlookout.com';
const INSTALLED_RELEASE = `v${require('../../package.json').version}`;

function compareRelease(left, right) {
  const parse = (value) => {
    const match = /^v(\d+)\.(\d+)\.(\d+)$/.exec(value || '');
    if (!match) throw new Error('CLI release version is invalid');
    return match.slice(1).map(Number);
  };
  const leftParts = parse(left);
  const rightParts = parse(right);
  for (let index = 0; index < leftParts.length; index += 1) {
    if (leftParts[index] !== rightParts[index]) return leftParts[index] > rightParts[index] ? 1 : -1;
  }
  return 0;
}

function validOrigin(value) {
  let origin;
  try { origin = new URL(value); } catch { throw new Error('CLI release channel origin is invalid'); }
  if (origin.protocol !== 'https:' || origin.username || origin.password || origin.search || origin.hash || (origin.pathname !== '/' && origin.pathname !== '')) throw new Error('CLI release channel origin is invalid');
  return origin.origin;
}

function normalizeTargets(value, allowedOrigins) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).sort().join(',') !== 'amd64,arm64') throw new Error('CLI release targets are invalid');
  return Object.fromEntries(['amd64', 'arm64'].map((architecture) => {
    const item = value[architecture];
    let url;
    try { url = new URL(item?.url); } catch { throw new Error('CLI release targets are invalid'); }
    if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || !allowedOrigins.has(url.origin) || !/^[a-f0-9]{64}$/.test(item?.sha256 || '')) throw new Error('CLI release targets are invalid');
    return [architecture, { url: url.toString(), sha256: item.sha256 }];
  }));
}

async function boundedJson(response) {
  const declared = response.headers.get('content-length');
  if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > MAXIMUM_MANIFEST_BYTES)) throw new Error('CLI release manifest exceeds its size limit');
  const chunks = [];
  let size = 0;
  for await (const chunk of response.body || []) {
    const bytes = Buffer.from(chunk);
    size += bytes.length;
    if (size > MAXIMUM_MANIFEST_BYTES) throw new Error('CLI release manifest exceeds its size limit');
    chunks.push(bytes);
  }
  try { return JSON.parse(Buffer.concat(chunks, size).toString('utf8')); }
  catch { throw new Error('CLI release channel returned invalid JSON'); }
}

async function refreshReleaseTargets({ store, pinnedTargets, pinnedRelease = INSTALLED_RELEASE, origin = DEFAULT_ORIGIN, fetchImpl = globalThis.fetch, trustedKeys = updateSigningKeys.trustedKeys, retryDelayMs = 500, waitImpl = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)) } = {}) {
  if (!store || typeof store.loadReleaseChannelState !== 'function' || typeof store.saveReleaseChannelState !== 'function') throw new TypeError('CLI release channel store is required');
  if (typeof fetchImpl !== 'function') throw new TypeError('CLI release channel fetch support is required');
  const channelOrigin = validOrigin(origin);
  const channelUrl = new URL('/v1/updates/cli-stable', channelOrigin).toString();
  const pinnedOrigins = new Set([channelOrigin, 'https://github.com']);
  for (const item of Object.values(pinnedTargets || {})) {
    try { pinnedOrigins.add(new URL(item.url).origin); } catch { /* Validation below reports malformed pinned metadata. */ }
  }
  const pinned = normalizeTargets(pinnedTargets, pinnedOrigins);
  compareRelease(pinnedRelease, pinnedRelease);
  const registry = await store.loadReleaseChannelState() || { schemaVersion: 2, channels: [] };
  const state = registry.channels.find((record) => record.channelUrl === channelUrl) || null;
  const cachedTargets = state?.targets && state.targetsRelease && compareRelease(state.targetsRelease, pinnedRelease) > 0
    ? normalizeTargets(state.targets, pinnedOrigins)
    : null;
  let response;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    try {
      response = await fetchImpl(channelUrl, { headers: { Accept: 'application/json' }, redirect: 'error', signal: AbortSignal.timeout(15000) });
      if (response.ok || (response.status < 500 && ![408, 429].includes(response.status))) break;
    } catch { response = null; }
    if (attempt < 2 && retryDelayMs > 0) await waitImpl(retryDelayMs * (attempt + 1));
  }
  if (!response?.ok) return cachedTargets || pinned;
  if (!/^application\/json(?:;|$)/i.test(response.headers.get('content-type') || '')) throw new Error('CLI release channel returned an invalid content type');
  const envelope = await boundedJson(response);
  const payload = verifyManifest(envelope, trustedKeys, { channel: 'cli-stable' });
  const manifestDigest = crypto.createHash('sha256').update(JSON.stringify({ schemaVersion: 1, keyId: envelope.keyId, payload, signature: envelope.signature })).digest('hex');
  if (state && (payload.sequence < state.highestSequence || (payload.sequence === state.highestSequence && state.manifestDigest !== manifestDigest))) throw new Error('CLI release manifest sequence is a replay or equivocation');
  let targets = cachedTargets;
  let targetsRelease = cachedTargets ? state.targetsRelease : null;
  if (payload.action !== 'pause') {
    if (compareRelease(payload.release, pinnedRelease) > 0) {
      targets = normalizeTargets(Object.fromEntries(['amd64', 'arm64'].map((architecture) => [architecture, {
        url: payload.artifacts[architecture].url, sha256: payload.artifacts[architecture].sha256
      }])), pinnedOrigins);
      targetsRelease = payload.release;
    } else {
      targets = null;
      targetsRelease = null;
    }
  }
  const channels = registry.channels.filter((record) => record.channelUrl !== channelUrl);
  channels.push({ channelUrl, highestSequence: payload.sequence, manifestDigest, targets, targetsRelease });
  channels.sort((left, right) => left.channelUrl.localeCompare(right.channelUrl));
  await store.saveReleaseChannelState({ schemaVersion: 2, channels });
  return targets || pinned;
}

module.exports = { refreshReleaseTargets, normalizeReleaseTargets: normalizeTargets, compareRelease, DEFAULT_ORIGIN };

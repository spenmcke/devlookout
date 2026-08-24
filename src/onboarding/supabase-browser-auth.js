'use strict';

const MAXIMUM_RESPONSE_BYTES = 64 * 1024;
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$/;

function bearer(req) {
  const value = req.headers?.authorization;
  const single = Array.isArray(value) ? null : value;
  const match = /^Bearer ([\x21-\x7e]{32,4096})$/.exec(single || '');
  return match?.[1] || null;
}

async function boundedJson(response) {
  if (!/^application\/json(?:\s*;.*)?$/i.test(response.headers.get('content-type') || '')) throw new Error('Supabase authentication returned an invalid response');
  const reader = response.body?.getReader();
  if (!reader) throw new Error('Supabase authentication returned an invalid response');
  const chunks = [];
  let size = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > MAXIMUM_RESPONSE_BYTES) { await reader.cancel(); throw new Error('Supabase authentication response is too large'); }
    chunks.push(Buffer.from(value));
  }
  try { return JSON.parse(Buffer.concat(chunks, size).toString('utf8')); }
  catch { throw new Error('Supabase authentication returned invalid JSON'); }
}

function createSupabaseBrowserAuthenticator({ supabaseUrl, publishableKey, fetchImpl = globalThis.fetch, timeoutMs = 5000 } = {}) {
  let origin;
  try { origin = new URL(supabaseUrl); } catch { throw new Error('Supabase URL is invalid'); }
  if (origin.protocol !== 'https:' || origin.username || origin.password || origin.search || origin.hash || (origin.pathname !== '/' && origin.pathname !== '')) throw new Error('Supabase URL must be an HTTPS origin');
  if (typeof publishableKey !== 'string' || publishableKey.length < 32 || publishableKey.length > 4096 || !/^[\x21-\x7e]+$/.test(publishableKey)) throw new Error('Supabase publishable key is invalid');
  if (typeof fetchImpl !== 'function' || !Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 30000) throw new Error('Supabase authenticator configuration is invalid');
  const endpoint = new URL('/auth/v1/user', origin);
  return async function authenticateBrowser(req) {
    const token = bearer(req);
    if (!token) return null;
    let response;
    try {
      response = await fetchImpl(endpoint, {
        method: 'GET', redirect: 'error', signal: AbortSignal.timeout(timeoutMs),
        headers: { Accept: 'application/json', apikey: publishableKey, Authorization: `Bearer ${token}` }
      });
    } catch { return null; }
    if (response.status !== 200) return null;
    const user = await boundedJson(response);
    const userId = user?.id;
    const tenantId = user?.app_metadata?.tenant_id || userId;
    if (!SAFE_ID.test(userId || '') || !SAFE_ID.test(tenantId || '')) return null;
    const metadata = user.user_metadata && typeof user.user_metadata === 'object' ? user.user_metadata : {};
    const displayNameValue = metadata.full_name || metadata.name || metadata.display_name;
    const avatarValue = metadata.avatar_url || metadata.picture;
    let avatarUrl = null;
    try {
      const parsed = new URL(avatarValue);
      if (parsed.protocol === 'https:' && !parsed.username && !parsed.password && parsed.href.length <= 2048) avatarUrl = parsed.href;
    } catch { /* Email signups may not have an avatar. */ }
    return {
      tenantId, userId,
      email: typeof user.email === 'string' ? user.email.slice(0, 320) : null,
      displayName: typeof displayNameValue === 'string' && displayNameValue.trim() ? displayNameValue.trim().slice(0, 256) : null,
      avatarUrl
    };
  };
}

module.exports = { createSupabaseBrowserAuthenticator, parseBrowserBearer: bearer };

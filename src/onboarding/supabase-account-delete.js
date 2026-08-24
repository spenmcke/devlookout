'use strict';

const SAFE_USER_ID = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$/;

async function drainLimited(response, maximumBytes = 64 * 1024) {
  const reader = response.body?.getReader();
  if (!reader) return;
  let size = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) return;
    size += value.byteLength;
    if (size > maximumBytes) {
      await reader.cancel();
      throw new Error('Supabase account deletion response is too large');
    }
  }
}

function createSupabaseAuthUserDeleter({ supabaseUrl, serviceKey, fetchImpl = globalThis.fetch, timeoutMs = 5000 } = {}) {
  let origin;
  try { origin = new URL(supabaseUrl); } catch { throw new Error('Supabase URL is invalid'); }
  if (origin.protocol !== 'https:' || origin.username || origin.password || origin.search || origin.hash || (origin.pathname !== '/' && origin.pathname !== '')) throw new Error('Supabase URL must be an HTTPS origin');
  if (typeof serviceKey !== 'string' || serviceKey.length < 32 || serviceKey.length > 8192 || /[\r\n]/.test(serviceKey)) throw new Error('Supabase service key is invalid');
  if (typeof fetchImpl !== 'function' || !Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 30000) throw new Error('Supabase account deletion configuration is invalid');

  return async function deleteSupabaseAuthUser(userId) {
    if (typeof userId !== 'string' || !SAFE_USER_ID.test(userId)) throw new Error('Supabase user ID is invalid');
    let response;
    try {
      response = await fetchImpl(new URL(`/auth/v1/admin/users/${encodeURIComponent(userId)}`, origin), {
        method: 'DELETE', redirect: 'error', signal: AbortSignal.timeout(timeoutMs),
        headers: { Accept: 'application/json', 'Content-Type': 'application/json', apikey: serviceKey, Authorization: `Bearer ${serviceKey}` },
        body: JSON.stringify({ should_soft_delete: false })
      });
    } catch { throw new Error('Supabase account deletion failed'); }
    await drainLimited(response);
    if (response.status !== 200 && response.status !== 204 && response.status !== 404) throw new Error('Supabase account deletion was rejected');
    if (response.status !== 404) {
      let verification;
      try {
        verification = await fetchImpl(new URL(`/auth/v1/admin/users/${encodeURIComponent(userId)}`, origin), {
          method: 'GET', redirect: 'error', signal: AbortSignal.timeout(timeoutMs),
          headers: { Accept: 'application/json', apikey: serviceKey, Authorization: `Bearer ${serviceKey}` }
        });
      } catch { throw new Error('Supabase account deletion could not be verified'); }
      await drainLimited(verification);
      if (verification.status !== 404) throw new Error('Supabase account deletion could not be verified');
    }
    return { deleted: true };
  };
}

module.exports = { createSupabaseAuthUserDeleter, drainLimitedDeletionResponse: drainLimited };

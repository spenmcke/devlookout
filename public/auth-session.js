'use strict';

const LookoutAuth = (() => {
  const config = window.__LOOKOUT_AUTH__ || {};
  const configured = Boolean(config.configured && window.supabase?.createClient);
  const client = configured ? window.supabase.createClient(config.supabaseUrl, config.publishableKey, {
    auth: { persistSession: true, autoRefreshToken: true, detectSessionInUrl: true }
  }) : null;

  async function session() {
    if (!client) return null;
    const { data, error } = await client.auth.getSession();
    if (error) return null;
    if (data.session && typeof LookoutAnalytics !== 'undefined') LookoutAnalytics.identify(data.session.user);
    return data.session;
  }

  async function signOut() {
    if (client) await client.auth.signOut();
    if (typeof LookoutAnalytics !== 'undefined') LookoutAnalytics.reset();
    window.location.assign('/signup');
  }

  async function clearSession() {
    if (client) {
      const { error } = await client.auth.signOut({ scope: 'local' });
      if (error) throw error;
    }
    if (typeof LookoutAnalytics !== 'undefined') LookoutAnalytics.reset();
  }

  async function authorizationHeaders() {
    const active = await session();
    return active?.access_token ? { Authorization: `Bearer ${active.access_token}` } : {};
  }

  return { configured, session, signOut, clearSession, authorizationHeaders };
})();

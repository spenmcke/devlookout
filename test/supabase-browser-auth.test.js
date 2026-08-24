'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createSupabaseBrowserAuthenticator } = require('../src/onboarding/supabase-browser-auth');

test('Supabase browser authentication derives tenant only from verified user metadata', async () => {
  let request;
  const authenticate = createSupabaseBrowserAuthenticator({
    supabaseUrl: 'https://project.supabase.co', publishableKey: 'p'.repeat(40),
    fetchImpl: async (url, options) => {
      request = { url: url.toString(), options };
      return new Response(JSON.stringify({ id: 'user-123', email: 'owner@example.test', app_metadata: { tenant_id: 'tenant-abc' }, user_metadata: { full_name: 'Ada Lovelace', avatar_url: 'https://images.example.test/ada.png' } }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
  });
  const principal = await authenticate({ headers: { authorization: `Bearer ${'t'.repeat(40)}` } });
  assert.deepEqual(principal, { tenantId: 'tenant-abc', userId: 'user-123', email: 'owner@example.test', displayName: 'Ada Lovelace', avatarUrl: 'https://images.example.test/ada.png' });
  assert.equal(request.url, 'https://project.supabase.co/auth/v1/user');
  assert.equal(request.options.redirect, 'error');
  assert.equal(request.options.headers.Authorization.includes('t'.repeat(40)), true);
});

test('Supabase browser authentication omits unsafe profile images', async () => {
  const authenticate = createSupabaseBrowserAuthenticator({
    supabaseUrl: 'https://project.supabase.co', publishableKey: 'p'.repeat(40),
    fetchImpl: async () => new Response(JSON.stringify({ id: 'user-123', email: 'owner@example.test', user_metadata: { avatar_url: 'javascript:alert(1)' } }), { status: 200, headers: { 'content-type': 'application/json' } })
  });
  assert.deepEqual(await authenticate({ headers: { authorization: `Bearer ${'t'.repeat(40)}` } }), { tenantId: 'user-123', userId: 'user-123', email: 'owner@example.test', displayName: null, avatarUrl: null });
});

test('Supabase browser authentication fails closed for invalid or oversized responses', async () => {
  const base = { supabaseUrl: 'https://project.supabase.co', publishableKey: 'p'.repeat(40) };
  const missing = createSupabaseBrowserAuthenticator({ ...base, fetchImpl: async () => new Response('{}', { status: 401, headers: { 'content-type': 'application/json' } }) });
  assert.equal(await missing({ headers: { authorization: `Bearer ${'t'.repeat(40)}` } }), null);
  const oversized = createSupabaseBrowserAuthenticator({ ...base, fetchImpl: async () => new Response(JSON.stringify({ padding: 'x'.repeat(70 * 1024) }), { status: 200, headers: { 'content-type': 'application/json' } }) });
  await assert.rejects(() => oversized({ headers: { authorization: `Bearer ${'t'.repeat(40)}` } }), /too large/);
});

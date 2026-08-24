'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createSupabaseAuthUserDeleter } = require('../src/onboarding/supabase-account-delete');

test('Supabase account deletion is a bounded hard delete using only the service credential header', async () => {
  const calls = [];
  const deleteUser = createSupabaseAuthUserDeleter({
    supabaseUrl: 'https://project.supabase.co', serviceKey: 's'.repeat(64),
    fetchImpl: async (url, options) => {
      calls.push({ url: url.toString(), options });
      return options.method === 'DELETE'
        ? new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } })
        : new Response(null, { status: 404 });
    }
  });
  assert.deepEqual(await deleteUser('user-123'), { deleted: true });
  assert.equal(calls[0].url, 'https://project.supabase.co/auth/v1/admin/users/user-123');
  assert.equal(calls[0].options.method, 'DELETE');
  assert.equal(calls[0].url.includes('s'.repeat(32)), false);
  assert.deepEqual(JSON.parse(calls[0].options.body), { should_soft_delete: false });
  assert.equal(calls[1].options.method, 'GET');
  assert.equal(calls[1].url, calls[0].url);
});

test('Supabase account deletion fails closed on rejection and oversized responses', async () => {
  const rejected = createSupabaseAuthUserDeleter({ supabaseUrl: 'https://project.supabase.co', serviceKey: 's'.repeat(64), fetchImpl: async () => new Response('{}', { status: 500 }) });
  await assert.rejects(() => rejected('user-123'), /rejected/);
  const oversized = createSupabaseAuthUserDeleter({ supabaseUrl: 'https://project.supabase.co', serviceKey: 's'.repeat(64), fetchImpl: async () => new Response('x'.repeat(65537), { status: 200 }) });
  await assert.rejects(() => oversized('user-123'), /too large/);
});

test('Supabase account deletion rejects a user that still exists after deletion', async () => {
  const deleteUser = createSupabaseAuthUserDeleter({
    supabaseUrl: 'https://project.supabase.co', serviceKey: 's'.repeat(64),
    fetchImpl: async () => new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } })
  });
  await assert.rejects(() => deleteUser('user-123'), /could not be verified/);
});

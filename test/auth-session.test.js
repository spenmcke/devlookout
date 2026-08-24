'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const source = fs.readFileSync(path.resolve(__dirname, '../public/auth-session.js'), 'utf8');
const appSource = fs.readFileSync(path.resolve(__dirname, '../public/app.js'), 'utf8');
const apiSource = fs.readFileSync(path.resolve(__dirname, '../public/api.js'), 'utf8');

test('account deletion can clear the persisted browser session without another server request', async () => {
  const signOutCalls = [];
  let analyticsResets = 0;
  const auth = {
    getSession: async () => ({ data: { session: null }, error: null }),
    signOut: async (options) => {
      signOutCalls.push(options);
      return { error: null };
    }
  };
  const window = {
    __LOOKOUT_AUTH__: { configured: true, supabaseUrl: 'https://project.supabase.co', publishableKey: 'publishable-key' },
    supabase: { createClient: () => ({ auth }) },
    location: { assign: () => assert.fail('clearSession must not navigate') }
  };
  const context = vm.createContext({ window, LookoutAnalytics: { reset: () => { analyticsResets += 1; } } });
  vm.runInContext(source, context);
  const lookoutAuth = vm.runInContext('LookoutAuth', context);

  await lookoutAuth.clearSession();

  assert.equal(signOutCalls.length, 1);
  assert.equal(signOutCalls[0].scope, 'local');
  assert.equal(analyticsResets, 1);
});

test('account deletion clears the browser session before navigating to signup', () => {
  assert.match(appSource, /await LookoutApi\.deleteAccount\(\);[\s\S]{0,300}await LookoutAuth\.clearSession\(\);[\s\S]{0,200}window\.location\.replace\('\/signup'\);/);
});

test('hosted API requests stop waiting at the configured deadline', async () => {
  let fetchCalls = 0;
  const context = vm.createContext({
    window: { location: { pathname: '/map' }, __LOOKOUT_AUTH__: { hosted: true } },
    fetch: async () => { fetchCalls += 1; return new Promise(() => {}); },
    LookoutAuth: { authorizationHeaders: async () => ({ Authorization: 'Bearer test' }) },
    AbortController, URLSearchParams, setTimeout, clearTimeout, Date, Promise, Error
  });
  vm.runInContext(apiSource.replace('const REQUEST_TIMEOUT_MS = 10000;', 'const REQUEST_TIMEOUT_MS = 20;'), context);
  const api = vm.runInContext('LookoutApi', context);

  await assert.rejects(() => api.deployments(), (error) => error.code === 'LOOKOUT_REQUEST_TIMEOUT');
  assert.equal(fetchCalls, 1);
});

test('setup preparation failure is rendered as stopped and retryable', () => {
  assert.match(appSource, /setupPreparationFailed = true;[\s\S]{0,400}SETUP NOT READY[\s\S]{0,200}STOPPED/);
  assert.match(appSource, /setupPreparationFailed[\s\S]{0,500}await ensureSetupSession\(\)/);
});

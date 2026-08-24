'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

test('hosted console shares one in-flight snapshot request across initial views', async () => {
  let snapshotRequests = 0;
  const deploymentId = `dpl_${'a'.repeat(32)}`;
  const snapshot = {
    graph: { entities: [], relationships: [], capabilities: [] },
    alerts: [], detections: [], health: { status: 'ok' }
  };
  const context = vm.createContext({
    window: { location: { pathname: `/deployments/${deploymentId}` }, __LOOKOUT_AUTH__: { hosted: true } },
    fetch: async (url) => {
      if (String(url).includes('/snapshot')) snapshotRequests += 1;
      return new Response(JSON.stringify(snapshot), { status: 200, headers: { 'content-type': 'application/json' } });
    },
    Response, AbortController, URLSearchParams, encodeURIComponent, setTimeout, clearTimeout, structuredClone
  });
  const source = fs.readFileSync(path.join(__dirname, '..', 'public', 'api.js'), 'utf8');
  vm.runInContext(`${source}\n;globalThis.client = LookoutApi;`, context);
  await Promise.all([context.client.graph(), context.client.alerts(), context.client.detectionPlan(), context.client.consoleHealth()]);
  assert.equal(snapshotRequests, 1);
});

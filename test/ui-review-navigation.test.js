'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const appSource = fs.readFileSync(path.resolve(__dirname, '../public/app.js'), 'utf8');

test('review systems navigate from map and assets to their corresponding active alert', () => {
  assert.match(appSource, /stateForKey\(element\.dataset\.key, stateSets\(\)\) === 'watch'[\s\S]{0,160}openAlertsForEntity\(element\.dataset\.key\)/);
  assert.match(appSource, /row\.dataset\.state === 'watch'[\s\S]{0,160}openAlertsForEntity\(row\.dataset\.key\)/);
  assert.match(appSource, /function openAlertsForEntity\(entityKey\)[\s\S]{0,240}goToView\('alerts'\)/);
  assert.match(appSource, /data-review-alerts/);
});

test('corresponding alert selection prefers severity and ignores unrelated systems', () => {
  const start = appSource.indexOf('function highestPriorityOpenAlert');
  const end = appSource.indexOf('function openHighestPriorityAlert');
  const context = vm.createContext({
    openAlerts: () => [
      { id: 'unrelated', severity: 'critical', time: '2026-08-22T00:00:00.000Z', entities: ['endpoint:b'] },
      { id: 'older-high', severity: 'high', time: '2026-08-21T00:00:00.000Z', entities: ['endpoint:a'] },
      { id: 'newer-high', severity: 'high', time: '2026-08-22T00:00:00.000Z', entities: ['endpoint:a'] }
    ],
    alertTime: (alert) => alert.time
  });
  vm.runInContext(appSource.slice(start, end), context);

  assert.equal(vm.runInContext("highestPriorityOpenAlert('endpoint:a').id", context), 'newer-high');
});

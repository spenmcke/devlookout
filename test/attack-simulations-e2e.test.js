'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { analytics } = require('../src/detection/catalog');
const { scenarios, runAttackSimulations } = require('../scripts/run-attack-simulations');

test('every deterministic rule has an isolated raw-telemetry attack simulation', () => {
  const required = analytics.map((rule) => rule.id).sort();
  assert.deepEqual(scenarios.map((scenario) => scenario.expectedRuleId).sort(), required);
});

test('raw sensor records traverse normalization, capability planning, detection, and alert creation', { timeout: 60000 }, async () => {
  const report = await runAttackSimulations();
  assert.equal(report.passed, true, JSON.stringify(report, null, 2));
  assert.ok(report.results.every((result) => result.findingId));
  assert.ok(report.results.filter((result) => result.expectedDisposition === 'alert').every((result) => result.alertId));
  assert.ok(report.results.filter((result) => result.expectedDisposition === 'correlation_only').every((result) => !result.alertId));
  assert.ok(report.results.every((result) => result.nearMissRejected));
});

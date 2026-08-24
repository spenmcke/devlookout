'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createEvent } = require('../src/events/schema');
const { evaluate } = require('../src/detection/engine');
const { parseSigmaYaml } = require('../src/detection/sigma');
const { analytics } = require('../src/detection/catalog');
const { prioritizeBehaviors } = require('../src/detection/behaviors');

test('Sigma YAML compiles supported selectors, modifiers, conditions, and exclusions', () => {
  const yaml = `
title: Service Spawns Shell
id: 11111111-1111-1111-1111-111111111111
status: test
logsource:
  category: process_creation
detection:
  selection_parent:
    ParentImage|endswith:
      - /nginx
      - /apache2
  selection_child:
    Image|endswith: /sh
  filter_admin:
    User: service-admin
  condition: selection_parent and selection_child and not filter_admin
falsepositives:
  - documented maintenance
level: high
`;
  const [rule] = parseSigmaYaml(yaml);
  const matching = createEvent({ time: '2026-08-17T20:00:00.000Z', ingestedAt: '2026-08-17T20:00:00.000Z', category: 'system', class: 'process_activity', activity: 'start', source: { adapter: 'fixture', instance: 'site', recordId: 'sigma-1' }, entityKeys: ['endpoint:1'], actor: { id: 'www-data' }, attributes: { parentProcessPath: '/usr/sbin/nginx', processPath: '/bin/sh' } });
  const excluded = createEvent({ ...matching, source: { ...matching.source, recordId: 'sigma-2' }, actor: { id: 'service-admin' } });
  assert.equal(evaluate([rule], [matching]).length, 1);
  assert.equal(evaluate([rule], [excluded]).length, 0);
  assert.equal(rule.requirements.all[0], 'process_execution');
});

test('Sigma importer fails closed on unmapped fields and unsupported modifiers', () => {
  const base = (field) => `title: Bad rule\nlogsource:\n  category: process_creation\ndetection:\n  selection:\n    ${field}: value\n  condition: selection\n`;
  assert.throws(() => parseSigmaYaml(base('UnknownField')), /Unmapped Sigma field/);
  assert.throws(() => parseSigmaYaml(base('Image|re')), /Unsupported Sigma modifier/);
});

test('behavior prioritization is driven by graph terrain and maps catalog analytics', () => {
  const graph = { entities: [{ id: '1', type: 'endpoint' }, { id: '2', type: 'endpoint' }, { id: '3', type: 'network' }, { id: '4', type: 'identity' }, { id: '5', type: 'telemetry' }], relationships: [], capabilities: [] };
  const plan = prioritizeBehaviors(graph, analytics);
  assert.equal(plan.find((item) => item.id === 'lateral-movement').applicable, true);
  assert.equal(plan.find((item) => item.id === 'credential-abuse').state, 'planned');
  assert.equal(plan.find((item) => item.id === 'impact').state, 'not_applicable');
  assert.ok(plan.find((item) => item.id === 'defense-evasion').rules.includes('telemetry-disabled'));
  assert.equal(plan.find((item) => item.id === 'lateral-movement').surveyCoverage, 'gap');
  assert.ok(plan.find((item) => item.id === 'lateral-movement').missingSurvey.relationships.includes('member_of'));
  assert.ok(plan.find((item) => item.id === 'credential-abuse').desiredCapabilities.includes('authentication'));
});

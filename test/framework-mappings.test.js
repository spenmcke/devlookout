'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { analytics } = require('../src/detection/catalog');
const {
  ATTACK_TECHNIQUES, NIST_CSF_OUTCOMES, CISA_CPG_OUTCOMES,
  FRAMEWORK_SOURCES, ANALOG_FAMILIES, RULE_FRAMEWORK_MAPPINGS
} = require('../src/detection/framework-mappings');

test('every deterministic analytic has complete versioned framework metadata', () => {
  assert.deepEqual(Object.keys(RULE_FRAMEWORK_MAPPINGS).sort(), analytics.map((rule) => rule.id).sort());
  for (const rule of analytics) {
    const mapping = rule.frameworks;
    assert.ok(mapping && mapping.attack.length && mapping.nist.length && mapping.cisa.length, rule.id);
    for (const technique of mapping.attack) {
      assert.ok(ATTACK_TECHNIQUES[technique.id], `${rule.id}: ${technique.id}`);
      assert.ok(['direct', 'correlated', 'contextual'].includes(technique.relation), rule.id);
    }
    for (const outcome of mapping.nist) assert.ok(NIST_CSF_OUTCOMES[outcome], `${rule.id}: ${outcome}`);
    for (const outcome of mapping.cisa) assert.ok(CISA_CPG_OUTCOMES[outcome], `${rule.id}: ${outcome}`);
    for (const family of mapping.analogs) assert.ok(ANALOG_FAMILIES[family], `${rule.id}: ${family}`);
    if (rule.kind === 'sequence') assert.ok(mapping.nist.includes('DE.AE-03'), `${rule.id} must map correlation`);
    if (rule.severity === 'critical') assert.ok(mapping.attack.some((item) => item.relation !== 'contextual'), `${rule.id} needs a high-confidence ATT&CK relationship`);
  }
});

test('mappings use current ATT&CK v19 defense-impairment identifiers', () => {
  assert.equal(FRAMEWORK_SOURCES.mitreAttack.version, '19.2');
  const used = new Set(Object.values(RULE_FRAMEWORK_MAPPINGS).flatMap((mapping) => mapping.attack.map((item) => item.id)));
  assert.ok(used.has('T1685'));
  assert.ok(used.has('T1685.006'));
  assert.equal(used.has('T1562'), false);
  assert.equal(used.has('T1070.002'), false);
});

test('external comparisons are immutable, attributable, and explicitly semantic', () => {
  assert.deepEqual(Object.keys(FRAMEWORK_SOURCES).sort(), ['cisaCpg', 'elastic', 'mitreAttack', 'nistCsf', 'sentinel', 'sigma', 'splunk']);
  for (const source of Object.values(FRAMEWORK_SOURCES)) {
    assert.match(source.url, /^https:\/\//);
    assert.equal(source.retrieved, '2026-08-19');
  }
  for (const family of Object.values(ANALOG_FAMILIES)) {
    assert.ok(['semantic', 'supporting'].includes(family.relation));
    assert.ok(family.references.length > 0);
    for (const reference of family.references) {
      assert.match(reference, /^https:\/\/github\.com\//);
      assert.match(reference, /\/[a-f0-9]{40}\//);
    }
  }
});

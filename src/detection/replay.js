'use strict';

const { evaluate } = require('./engine');

function replay({ name = 'unnamed', rules, events, expectedRuleIds = [], forbiddenRuleIds = [] }) {
  const findings = evaluate(rules, events);
  const observed = new Set(findings.map((finding) => finding.ruleId));
  const missing = [...new Set(expectedRuleIds)].filter((id) => !observed.has(id)).sort();
  const forbidden = [...new Set(forbiddenRuleIds)].filter((id) => observed.has(id)).sort();
  return { name, passed: missing.length === 0 && forbidden.length === 0, missing, forbidden, findings };
}

function assertReplay(scenario) {
  const result = replay(scenario);
  if (!result.passed) throw new Error(`Replay ${result.name} failed; missing=[${result.missing.join(',')}], forbidden=[${result.forbidden.join(',')}]`);
  return result;
}

module.exports = { replay, assertReplay };

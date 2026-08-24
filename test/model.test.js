'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { nodes, edges, rules, adapterKinds, buildGraph, coverage, capabilityPlan, snapshot } = require('../src/model');

test('every relationship resolves to known nodes', () => {
  const ids = new Set(nodes.map((node) => node.id));
  for (const edge of edges) {
    assert.ok(ids.has(edge.from), `missing source ${edge.from}`);
    assert.ok(ids.has(edge.to), `missing target ${edge.to}`);
  }
});

test('behavior mappings resolve to rules', () => {
  const ids = new Set(rules.map((rule) => rule.id));
  for (const behavior of coverage()) for (const rule of behavior.rules) assert.ok(ids.has(rule));
  assert.ok(coverage().every((behavior) => behavior.coverageState === 'covered'));
});

test('graph output is stable independent of source order', () => {
  const graph = buildGraph();
  assert.deepEqual(graph.nodes.map((node) => node.id), [...graph.nodes.map((node) => node.id)].sort());
  assert.equal(new Set(graph.nodes.map((node) => node.id)).size, graph.nodes.length);
});

test('snapshot separates anomalies from incidents', () => {
  const value = snapshot();
  assert.ok(value.alerts.some((alert) => alert.rule === 'rule-rare-destination'));
  assert.ok(value.rules.some((rule) => rule.kind === 'behavioral'));
});

test('adapters are generic capability producers', () => {
  assert.ok(adapterKinds.some((adapter) => adapter.id === 'endpoint'));
  assert.ok(adapterKinds.some((adapter) => adapter.id === 'service'));
  assert.ok(adapterKinds.every((adapter) => adapter.emits.length > 0));
});

test('coverage planner exposes missing capabilities', () => {
  const plan = capabilityPlan();
  assert.equal(plan.length, coverage().length);
  assert.ok(plan.some((item) => item.state === 'partial'));
  assert.ok(plan.every((item) => Array.isArray(item.present) && Array.isArray(item.missing)));
});

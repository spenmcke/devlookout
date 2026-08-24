'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { authenticationFailureEvents, startSimulation } = require('../scripts/simulate-alert');

test('standalone simulation harness exercises the production Rule and Alert APIs', async () => {
  const events = authenticationFailureEvents(Date.parse('2026-08-18T20:00:00.000Z'));
  assert.equal(events.length, 12);
  assert.equal(events.every((event) => event.source.adapter === 'simulation-harness'), true);
  const simulation = await startSimulation({ port: 0 });
  try {
    assert.equal(simulation.alert.title, 'Repeated authentication failures from one source');
    const detail = await fetch(`${simulation.baseUrl}/api/v1/alerts/${simulation.alert.id}`);
    assert.equal(detail.status, 200);
    assert.equal((await detail.json()).evidenceTimeline.length, 12);
  } finally { await simulation.close(); }
});

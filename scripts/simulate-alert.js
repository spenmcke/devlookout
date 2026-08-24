#!/usr/bin/env node
'use strict';

const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { once } = require('node:events');
const crypto = require('node:crypto');
const { LookoutRuntime } = require('../src/runtime');
const { AdapterRegistry } = require('../src/adapters/contract');
const { declarationAdapter } = require('../src/adapters/declaration');
const { createEvent } = require('../src/events/schema');
const { createServer } = require('../src/server');

function authenticationFailureEvents(now = Date.now()) {
  const runId = crypto.randomUUID();
  const startedAt = now - 11000;
  return Array.from({ length: 12 }, (_, index) => {
    const time = new Date(startedAt + index * 1000).toISOString();
    return createEvent({
      time,
      ingestedAt: new Date(now).toISOString(),
      category: 'identity',
      class: 'authentication',
      activity: 'logon',
      outcome: 'failure',
      source: { adapter: 'simulation-harness', instance: 'local', recordId: `${runId}:${index}` },
      entityKeys: ['endpoint:simulation-source', 'endpoint:simulation-target'],
      actor: { id: `identity:simulation-user-${index}`, type: 'simulation' },
      sourceEndpoint: { id: 'endpoint:simulation-source', address: '192.0.2.10' },
      destinationEndpoint: { id: 'endpoint:simulation-target', address: '192.0.2.20' },
      attributes: { simulation: true, scenario: 'auth-failure-burst', runId }
    });
  });
}

async function startSimulation({ port = 4273, dataDirectory = null } = {}) {
  const ownsDirectory = !dataDirectory;
  const directory = dataDirectory || await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-alert-simulation-'));
  let server;
  try {
    const runtime = await new LookoutRuntime({ dataDirectory: directory }).initialize();
    const adapter = declarationAdapter({
      entities: [
        { key: 'telemetry:simulation-auth', type: 'telemetry', name: 'Simulation auth sensor' },
        { key: 'endpoint:simulation-source', type: 'endpoint', name: 'Simulation client' },
        { key: 'endpoint:simulation-target', type: 'endpoint', name: 'Simulation server' }
      ],
      capabilities: [{ entityKey: 'telemetry:simulation-auth', capability: 'authentication', status: 'available' }]
    });
    await runtime.applySurveyFacts(await new AdapterRegistry().register(adapter).survey('declaration'));
    server = createServer({ runtime });
    server.listen(port, '127.0.0.1');
    await once(server, 'listening');
    const actualPort = server.address().port;
    const baseUrl = `http://127.0.0.1:${actualPort}`;
    const response = await fetch(`${baseUrl}/api/v1/events`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(authenticationFailureEvents())
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || `Simulation ingestion returned HTTP ${response.status}`);
    const alert = result.alerts.find((item) => item.ruleId === 'auth-failure-burst');
    if (!alert) throw new Error('Simulation did not create the expected Alert');
    const close = async () => {
      if (server.listening) { server.close(); await once(server, 'close'); }
      if (ownsDirectory) await fs.rm(directory, { recursive: true, force: true });
    };
    return { baseUrl, directory, runtime, server, alert, close };
  } catch (error) {
    if (server?.listening) { server.close(); await once(server, 'close'); }
    if (ownsDirectory) await fs.rm(directory, { recursive: true, force: true });
    throw error;
  }
}

async function main() {
  const port = Number(process.env.LOOKOUT_TEST_PORT || 4273);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('LOOKOUT_TEST_PORT must be an integer between 1 and 65535');
  const simulation = await startSimulation({ port });
  console.log(`Simulated Alert ready: ${simulation.baseUrl}/#alerts`);
  console.log('Press Ctrl+C to stop and delete the temporary test data.');
  await new Promise((resolve) => {
    process.once('SIGINT', resolve);
    process.once('SIGTERM', resolve);
  });
  await simulation.close();
}

if (require.main === module) main().catch((error) => { console.error(error.message); process.exitCode = 1; });

module.exports = { authenticationFailureEvents, startSimulation };

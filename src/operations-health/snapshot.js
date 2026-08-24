'use strict';

const { validateOperationalHealthSample } = require('../collector/operational-telemetry');

const MAXIMUM_NODES = 10000;

function validateOperationalHealthSnapshot(snapshot) {
  if (!snapshot || typeof snapshot !== 'object' || Array.isArray(snapshot)) throw new Error('Operational health snapshot is invalid');
  const allowed = ['schemaVersion', 'kind', 'id', 'deploymentId', 'generatedAt', 'nodes'].sort();
  const actual = Object.keys(snapshot).sort();
  if (actual.length !== allowed.length || actual.some((key, index) => key !== allowed[index])) throw new Error('Operational health snapshot has invalid fields');
  if (snapshot.schemaVersion !== 1 || snapshot.kind !== 'lookout_operational_health' || typeof snapshot.id !== 'string' || !snapshot.id) throw new Error('Operational health snapshot identity is invalid');
  if (typeof snapshot.deploymentId !== 'string' || !snapshot.deploymentId || snapshot.deploymentId.length > 256 || Number.isNaN(Date.parse(snapshot.generatedAt))) throw new Error('Operational health snapshot deployment is invalid');
  if (!Array.isArray(snapshot.nodes) || snapshot.nodes.length > MAXIMUM_NODES) throw new Error('Operational health snapshot nodes are invalid');
  const collectors = new Set();
  for (const node of snapshot.nodes) {
    if (!Number.isSafeInteger(node?.collectorSequence) || node.collectorSequence < 1) throw new Error('Operational health collector sequence is invalid');
    const { collectorSequence, ...sample } = node;
    validateOperationalHealthSample(sample);
    if (collectors.has(sample.collectorId)) throw new Error('Operational health snapshot contains duplicate collectors');
    collectors.add(sample.collectorId);
  }
  return snapshot;
}

module.exports = { MAXIMUM_NODES, validateOperationalHealthSnapshot };

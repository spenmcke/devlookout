'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const PHASES = ['connected', 'discovering', 'access', 'artifact', 'central', 'deploying', 'verifying', 'protected'];

class DeploymentState {
  constructor(filename, deploymentId, nodes = []) {
    this.filename = path.resolve(filename);
    this.deploymentId = deploymentId;
    this.value = { schemaVersion: 1, deploymentId, phase: 'connected', nodes: {}, updatedAt: new Date(0).toISOString() };
    try {
      const stored = JSON.parse(fs.readFileSync(this.filename, 'utf8'));
      if (stored.schemaVersion === 1 && stored.deploymentId === deploymentId && stored.nodes && typeof stored.nodes === 'object') this.value = stored;
    } catch { /* First attempt or invalid stale state. */ }
    for (const node of nodes) this.value.nodes[node.id] ||= { phase: 'connected', attempts: 0 };
  }

  completed(nodeId, phase) {
    return PHASES.indexOf(this.value.nodes[nodeId]?.phase) >= PHASES.indexOf(phase);
  }

  checkpoint(phase, { nodeId = null, error = null, total = null, completed = null } = {}) {
    if (!PHASES.includes(phase) && phase !== 'needs_access' && phase !== 'reporting_interrupted') throw new Error('Deployment checkpoint phase is invalid');
    this.value.phase = phase;
    this.value.updatedAt = new Date().toISOString();
    if (total !== null) this.value.total = total;
    if (completed !== null) this.value.completed = completed;
    if (nodeId) {
      const prior = this.value.nodes[nodeId] || { phase: 'connected', attempts: 0 };
      this.value.nodes[nodeId] = { ...prior, phase, attempts: prior.attempts + 1, ...(error ? { error: String(error).slice(0, 512) } : { error: null }) };
    }
    this.save();
    return this.value;
  }

  save() {
    fs.mkdirSync(path.dirname(this.filename), { recursive: true, mode: 0o700 });
    const temporary = `${this.filename}.${process.pid}.${crypto.randomUUID()}.tmp`;
    fs.writeFileSync(temporary, `${JSON.stringify(this.value, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
    fs.renameSync(temporary, this.filename);
  }
}

module.exports = { DeploymentState, DEPLOYMENT_PHASES: PHASES };

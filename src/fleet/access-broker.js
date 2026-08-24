'use strict';

const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._:@/+\-=]{0,511}$/;
const SAFE_RESOURCE_ID = /^\/[A-Za-z0-9][A-Za-z0-9._:@/+\-=]{0,510}$/;
const CACHEABLE_FAILURES = new Set(['aws-ssm', 'gcp-os-login', 'gcp-iap', 'azure-run-command']);
function safe(value, label) {
  if (typeof value !== 'string' || !SAFE_ID.test(value)) throw new Error(`${label} is invalid`);
  return value;
}
function safeResourceId(value) {
  if (typeof value !== 'string' || !SAFE_RESOURCE_ID.test(value)) throw new Error('Azure resource ID is invalid');
  return value;
}

function accessPlan(node) {
  switch (node.provider) {
    case 'aws': return ['aws-ssm', 'aws-instance-connect', 'openssh'];
    case 'gcp': return ['gcp-os-login', 'gcp-iap', 'openssh'];
    case 'azure': return ['azure-run-command', 'openssh'];
    default: return ['openssh'];
  }
}

function shellCommand(argv) {
  return argv.map((value) => `'${String(value).replaceAll("'", "'\\''")}'`).join(' ');
}

class ProviderAccessBroker {
  constructor({ run, ssh, publicKey = null } = {}) {
    if (typeof run !== 'function' || typeof ssh !== 'function') throw new TypeError('Access broker requires command and SSH runners');
    this.run = run;
    this.ssh = ssh;
    this.publicKey = publicKey;
  }

  execute(node, argv, { input = null } = {}) {
    const failures = [];
    const unavailable = new Set(node.unavailableAccessMethods || []);
    const planned = accessPlan(node);
    const methods = planned.includes(node.managementTransport) ? [node.managementTransport, ...planned.filter((method) => method !== node.managementTransport)] : planned;
    for (const method of methods) {
      if (unavailable.has(method)) continue;
      if (input !== null && ['aws-ssm', 'azure-run-command'].includes(method)) {
        failures.push(`${method}: provider command history cannot carry secret input`);
        continue;
      }
      try {
        const result = this.#execute(method, node, argv, input);
        node.managementTransport = method === 'aws-instance-connect' ? 'openssh' : method;
        return result;
      } catch (error) {
        if (error.code === 'LOOKOUT_REMOTE_COMMAND_FAILED' || (method === 'openssh' && !error.failureKind)) throw error;
        failures.push(`${method}: ${error.message}`);
        if (CACHEABLE_FAILURES.has(method)) unavailable.add(method);
        node.unavailableAccessMethods = [...unavailable];
      }
    }
    node.unavailableAccessMethods = [...unavailable];
    const error = new Error(`Needs access for ${node.hostname || node.id}: ${failures.join('; ')}`);
    error.code = 'LOOKOUT_NEEDS_ACCESS';
    throw error;
  }

  #execute(method, node, argv, input) {
    const command = shellCommand(['aws-ssm', 'azure-run-command'].includes(method) ? argv : ['sudo', '-n', ...argv]);
    if (method === 'aws-ssm') {
      const instanceId = safe(node.instanceId, 'AWS instance ID');
      return this.run('aws-ssm', { instanceId, command, profile: node.awsProfile, region: node.region });
    }
    if (method === 'aws-instance-connect') {
      if (!this.publicKey) throw new Error('temporary public key is unavailable');
      this.run('aws-instance-connect', { instanceId: safe(node.instanceId, 'AWS instance ID'), zone: safe(node.zone, 'AWS availability zone'), user: node.sshUser, publicKey: this.publicKey, profile: node.awsProfile, region: node.region });
      return this.ssh(node, argv, input);
    }
    if (method === 'gcp-os-login') return this.run('gcp-os-login', { instance: safe(node.hostname, 'GCP instance'), zone: safe(node.zone, 'GCP zone'), project: node.project, command, input });
    if (method === 'gcp-iap') return this.run('gcp-iap', { instance: safe(node.hostname, 'GCP instance'), zone: safe(node.zone, 'GCP zone'), project: node.project, command, input });
    if (method === 'azure-run-command') {
      const resourceId = node.resourceId ? safeResourceId(node.resourceId) : null;
      return this.run('azure-run-command', { resourceId, resourceGroup: resourceId ? null : safe(node.resourceGroup, 'Azure resource group'), name: resourceId ? null : safe(node.hostname, 'Azure VM name'), command, input });
    }
    return this.ssh(node, argv, input);
  }
}

module.exports = { ProviderAccessBroker, accessPlan, shellCommand };

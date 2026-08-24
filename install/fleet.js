#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const net = require('node:net');
const { spawnSync } = require('node:child_process');
const { Worker, isMainThread, parentPort, workerData } = require('node:worker_threads');
const { quoteRemote } = require('../src/fleet/deployment');
const { ProviderAccessBroker } = require('../src/fleet/access-broker');
const { artifactPreflightScript } = require('../src/fleet/release-artifact');
const { resolveExecutable, requireExecutable } = require('../src/platform/executable');
const { createSshControlDirectory } = require('../src/cli/ssh-control-path');

const source = path.resolve(__dirname, '..');
const port = Number(process.env.LOOKOUT_PORT || 4173);
const configuredSshUser = process.env.LOOKOUT_SSH_USER || null;
const sshUsers = [...new Set([configuredSshUser, process.env.SUDO_USER, process.env.USER, 'root', 'ubuntu', 'ec2-user', 'debian', 'admin', 'centos'].filter((item) => item && /^[a-z_][a-z0-9_-]{0,31}$/i.test(item)))];
function invokingHome() {
  if (!process.env.SUDO_USER || process.env.SUDO_USER === 'root') return os.homedir();
  try { return fs.readFileSync('/etc/passwd', 'utf8').split('\n').map((line) => line.split(':')).find((row) => row[0] === process.env.SUDO_USER)?.[5] || os.homedir(); } catch { return os.homedir(); }
}
const managedKnownHosts = path.join(invokingHome(), '.lookout', 'known_hosts');
const knownHosts = process.env.LOOKOUT_SSH_KNOWN_HOSTS || (fs.existsSync(managedKnownHosts) ? managedKnownHosts : path.join(invokingHome(), '.ssh', 'known_hosts'));
const sshIdentity = process.env.LOOKOUT_SSH_IDENTITY ? path.resolve(process.env.LOOKOUT_SSH_IDENTITY) : null;
const consoleEndpoint = process.env.LOOKOUT_CONSOLE_ENDPOINT || null;
const consoleCredentialSource = process.env.LOOKOUT_CONSOLE_CREDENTIAL_SOURCE ? path.resolve(process.env.LOOKOUT_CONSOLE_CREDENTIAL_SOURCE) : null;
const consoleCredentialRemote = process.env.LOOKOUT_CONSOLE_CREDENTIAL_REMOTE || null;
const requestedDeploymentId = process.env.LOOKOUT_CONSOLE_DEPLOYMENT_ID || process.env.LOOKOUT_DEPLOYMENT_ID || null;
const approvedScopeFile = process.env.LOOKOUT_INSTALLATION_SCOPE_FILE ? path.resolve(process.env.LOOKOUT_INSTALLATION_SCOPE_FILE) : null;
const bootstrapPublicKeyFile = process.env.LOOKOUT_BOOTSTRAP_PUBLIC_KEY_FILE ? path.resolve(process.env.LOOKOUT_BOOTSTRAP_PUBLIC_KEY_FILE) : null;
const releaseUrl = process.env.LOOKOUT_RELEASE_URL || null;
const releaseSha256 = process.env.LOOKOUT_RELEASE_SHA256 || null;
const releaseTargetsJson = process.env.LOOKOUT_RELEASE_TARGETS || null;
const workstationMode = process.env.LOOKOUT_WORKSTATION === '1';
const preparedCentralVm = process.env.LOOKOUT_PREPARED_CENTRAL_VM || null;
const preparedCentralSource = process.env.LOOKOUT_PREPARED_CENTRAL_SOURCE || null;
const prepareOnly = process.env.LOOKOUT_PREPARE_ONLY === '1';
const attachConsoleOnly = process.env.LOOKOUT_ATTACH_CONSOLE === '1';
const preparedFleetFile = process.env.LOOKOUT_PREPARED_FLEET_FILE || null;
const preparationScopeDigest = process.env.LOOKOUT_PREPARATION_SCOPE_DIGEST || null;
const preparationReleaseFingerprint = process.env.LOOKOUT_PREPARATION_RELEASE_FINGERPRINT || null;
const SAFE_HOSTNAME = /^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/;
const deploymentConfigName = 'security-observability-config.json';
const legacyDeploymentConfigName = 'fleet.json';
const remoteDeploymentConfig = `/var/lib/lookout-install/${deploymentConfigName}`;
const legacyRemoteDeploymentConfig = `/var/lib/lookout-install/${legacyDeploymentConfigName}`;
const sshConnectionOptions = [
  '-o', 'ConnectTimeout=5',
  '-o', 'ConnectionAttempts=1',
  '-o', 'ServerAliveInterval=5',
  '-o', 'ServerAliveCountMax=1'
];
let sshControlDirectory = null;
function sshMultiplexOptions() {
  if (process.platform === 'win32') return [];
  if (!sshControlDirectory) {
    sshControlDirectory = createSshControlDirectory();
  }
  return ['-o', 'ControlMaster=auto', '-o', 'ControlPersist=30', '-o', `ControlPath=${sshControlDirectory}/%C`];
}
function shouldRetrySshCandidate(error) {
  return ['timeout', 'transport', 'identity', 'authentication'].includes(error?.failureKind);
}

function probeFailureAction(error) {
  if (['timeout', 'transport', 'identity'].includes(error?.failureKind)) return 'stop';
  if (error?.failureKind === 'authentication') return 'continue';
  if (error?.code === 'LOOKOUT_NEEDS_ACCESS') return 'needs-access';
  throw error;
}

function reportProgress(message) { process.stderr.write(`[fleet] ${message}\n`); }
function reportStatus(phase, completed, total) {
  process.stderr.write(`[fleet-status] ${JSON.stringify({ phase, ...(Number.isSafeInteger(completed) ? { completed, total } : {}) })}\n`);
}
function nodeLabel(node) { return node.hostname || node.address || node.id; }
function persistedFleetNode(node) {
  const result = {};
  for (const key of [
    'id', 'provider', 'instanceId', 'hostname', 'address', 'publicAddress', 'managementAddress',
    'platform', 'architecture', 'online', 'local', 'transport', 'sshUser', 'sshIdentityMode', 'awsProfile',
    'zone', 'region', 'project', 'resourceGroup', 'resourceId', 'managementTransport', 'reachable'
  ]) {
    if (node[key] !== undefined && node[key] !== null) result[key] = node[key];
  }
  if (Array.isArray(node.unavailableAccessMethods)) result.unavailableAccessMethods = [...node.unavailableAccessMethods];
  return result;
}
function fleetConcurrency(targetCount) {
  const configured = process.env.LOOKOUT_FLEET_CONCURRENCY;
  if (configured !== undefined && (!/^\d+$/.test(configured) || Number(configured) < 1 || Number(configured) > 16)) throw new Error('LOOKOUT_FLEET_CONCURRENCY must be an integer between 1 and 16');
  return Math.min(targetCount, configured === undefined ? 8 : Number(configured));
}

async function runBounded(items, limit, operation) {
  if (!Array.isArray(items) || !Number.isSafeInteger(limit) || limit < 1 || typeof operation !== 'function') throw new Error('Bounded work queue configuration is invalid');
  const results = new Array(items.length);
  let next = 0;
  async function consume() {
    while (next < items.length) {
      const index = next;
      next += 1;
      try { results[index] = { status: 'fulfilled', value: await operation(items[index], index) }; }
      catch (reason) { results[index] = { status: 'rejected', reason }; }
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, () => consume()));
  return results;
}

function validateSshFile(filename, label, { privateFile = false } = {}) {
  const metadata = fs.lstatSync(filename);
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > 4 * 1024 * 1024) throw new Error(`${label} must be a bounded, non-symlink regular file`);
  if (process.platform !== 'win32') {
    const permittedOwners = new Set([typeof process.geteuid === 'function' ? process.geteuid() : metadata.uid, Number(process.env.SUDO_UID)].filter(Number.isSafeInteger));
    if (!permittedOwners.has(metadata.uid)) throw new Error(`${label} is not owned by the invoking user`);
    if ((metadata.mode & (privateFile ? 0o077 : 0o022)) !== 0) throw new Error(`${label} permissions are unsafe`);
  }
  return filename;
}

function bootstrapKeyMarker() {
  if (!sshIdentity) return null;
  const manifestFile = path.join(path.dirname(sshIdentity), 'lookout-bootstrap-key.json');
  if (!fs.existsSync(manifestFile)) return null;
  validateSshFile(manifestFile, 'SSH bootstrap manifest', { privateFile: true });
  const manifest = JSON.parse(fs.readFileSync(manifestFile, 'utf8'));
  if (manifest.schemaVersion !== 1 || path.resolve(manifest.privateKeyFile || '') !== sshIdentity || !/^lookout-bootstrap:[A-Za-z0-9._:-]{1,128}$/.test(manifest.comment || '')) throw new Error('SSH bootstrap manifest does not match the selected identity');
  return manifest.comment;
}
const bootstrapComment = bootstrapKeyMarker();

function run(binary, args, options = {}) {
  const result = spawnSync(binary, args, { encoding: options.binary ? null : 'utf8', input: options.input, maxBuffer: 64 * 1024 * 1024, env: options.env || process.env, timeout: options.timeoutMs || 120000, killSignal: 'SIGKILL' });
  if (result.error || result.status !== 0) {
    const detail = String(result.stderr || result.error?.message || '').replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, '').trim().slice(-2048);
    const error = new Error(`${options.label || `${path.basename(binary)} failed`}${detail ? `: ${detail}` : ''}`);
    error.exitCode = result.status;
    if (result.error?.code === 'ETIMEDOUT') error.failureKind = 'timeout';
    else if (/Permission denied|Authentication failed|not have permission|PERMISSION_DENIED|Unauthorized|Unauthenticated|credentials? (?:were|are|is)|login required/i.test(detail)) error.failureKind = 'authentication';
    else if (/Host key verification failed|REMOTE HOST IDENTIFICATION HAS CHANGED/i.test(detail)) error.failureKind = 'identity';
    else if (/Connection refused|No route to host|Operation timed out|Could not resolve hostname|Network is unreachable/i.test(detail)) error.failureKind = 'transport';
    throw error;
  }
  return result.stdout;
}

function commandExists(command) { return Boolean(resolveExecutable(command)); }
function stableDeploymentId(nodes) {
  return `fleet-${crypto.createHash('sha256').update(nodes.map((node) => node.id).sort().join('\0')).digest('hex').slice(0, 24)}`;
}

function buildFleetSurvey(nodes, central, deploymentId) {
  const networkKey = `network:${deploymentId}`;
  const entities = [
    { key: networkKey, type: 'network', name: nodes.some((node) => node.transport === 'tailscale') ? 'Tailscale private network' : 'Private network', attributes: { private: true, deploymentId, discoveryProvider: nodes.some((node) => node.transport === 'tailscale') ? 'tailscale' : 'local' } },
    ...nodes.map((node) => ({
      key: node.id, type: 'endpoint', name: node.hostname || node.id,
      attributes: { platform: node.platform, address: node.address, discoveryProvider: node.transport, reachable: Boolean(node.reachable), coverageStatus: node.platform === 'linux' && node.reachable ? 'collector-deployed' : 'requires-adapter' }
    }))
  ];
  const relationships = [
    ...nodes.map((node) => ({ from: node.id, to: networkKey, relation: 'member_of' }))
  ];
  const capabilities = [
    ...nodes.flatMap((node) => [
      { entityKey: node.id, capability: 'inventory', status: 'available', freshnessSeconds: 300 },
      { entityKey: node.id, capability: 'sensor_health', status: node.platform === 'linux' && node.reachable ? 'available' : 'unavailable', freshnessSeconds: 300 }
    ])
  ];
  return { entities, relationships, capabilities };
}
function chooseCentral(nodes, existing = [], approvedCentralId = null) {
  if (approvedCentralId) {
    const approved = nodes.find((node) => node.id === approvedCentralId);
    if (!approved || !approved.reachable || approved.platform !== 'linux') throw new Error('The selected central VM is not a reachable Linux VM');
    return approved;
  }
  if (existing.length > 1) throw new Error('Multiple existing fleet central nodes were found; refusing split-brain deployment');
  if (existing.length === 1) return existing[0];
  const eligible = nodes.filter((node) => node.reachable && node.platform === 'linux').sort((a, b) => a.id.localeCompare(b.id));
  if (!eligible.length) throw new Error('No reachable supported Linux node is available for the central service');
  return eligible.find((node) => node.local) || eligible[0];
}

function loadApprovedScope(filename, { workstation = workstationMode } = {}) {
  if (!filename) throw new Error('An approved installation scope is required');
  validateSshFile(filename, 'Approved installation scope');
  const value = JSON.parse(fs.readFileSync(filename, 'utf8'));
  if (!value || typeof value !== 'object' || Array.isArray(value) || (value.central_vm_id !== undefined && typeof value.central_vm_id !== 'string') || !Array.isArray(value.vms) || value.vms.length < 1 || value.vms.length > 256) throw new Error('Approved installation scope is invalid');
  const ids = new Set();
  const nodes = value.vms.map((vm) => {
    if (!vm || typeof vm !== 'object' || Array.isArray(vm) || typeof vm.id !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$/.test(vm.id) || ids.has(vm.id)) throw new Error('Approved VM identity is invalid');
    ids.add(vm.id);
    if (vm.address !== undefined && net.isIP(vm.address) === 0 && !SAFE_HOSTNAME.test(vm.address)) throw new Error(`Approved VM address is invalid for ${vm.id}`);
    if (vm.public_address !== undefined && net.isIP(vm.public_address) === 0) throw new Error(`Approved VM public address is invalid for ${vm.id}`);
    if (vm.aws_profile !== undefined && !/^[A-Za-z0-9_+=,.@-]{1,128}$/.test(vm.aws_profile)) throw new Error(`Approved VM AWS profile is invalid for ${vm.id}`);
    if (vm.ssh_host !== undefined && net.isIP(vm.ssh_host) === 0 && !SAFE_HOSTNAME.test(vm.ssh_host)) throw new Error(`Approved VM SSH host is invalid for ${vm.id}`);
    if (vm.ssh_user !== undefined && !/^[a-z_][a-z0-9_-]{0,31}$/i.test(vm.ssh_user)) throw new Error(`Approved VM SSH user is invalid for ${vm.id}`);
    const local = vm.local === true;
    return {
      id: vm.id,
      hostname: vm.name || null,
      address: vm.address || null,
      managementAddress: vm.ssh_host || null,
      publicAddress: vm.public_address || null,
      platform: String(vm.platform || 'linux').toLowerCase(),
      online: true,
      local,
      transport: local ? 'local' : (vm.provider === 'tailscale' ? 'tailscale' : 'ssh'),
      ...(vm.ssh_user ? { sshUser: vm.ssh_user } : {}),
      provider: vm.provider || 'openssh', instanceId: vm.instance_id || vm.id,
      awsProfile: vm.aws_profile || null,
      zone: vm.zone || null, region: vm.region || null, project: vm.project || null,
      resourceGroup: vm.resource_group || null, resourceId: vm.resource_id || null
    };
  });
  if (value.central_vm_id !== undefined && !ids.has(value.central_vm_id)) throw new Error('Approved central VM is outside the approved VM list');
  if (nodes.filter((node) => node.local).length > 1) throw new Error('Installation scope contains multiple local VMs');
  if (value.central_vm_id !== undefined && nodes.some((node) => node.local) && !nodes.find((node) => node.id === value.central_vm_id)?.local) throw new Error('A local target must be the selected central VM');
  if (workstation && nodes.some((node) => node.local)) throw new Error('A workstation installation scope may not mark a managed VM as local');
  return { centralVmId: value.central_vm_id || null, nodes };
}

function tailscaleNodes() {
  if (!commandExists('tailscale')) return [];
  let status;
  try { status = JSON.parse(run('tailscale', ['status', '--json'], { label: 'Tailscale discovery failed' })); } catch { return []; }
  const records = [status.Self, ...Object.values(status.Peer || {})].filter(Boolean);
  return records.map((record) => ({
    id: `tailscale:${record.StableID || record.ID}`,
    hostname: String(record.HostName || record.DNSName || '').replace(/\.$/, ''),
    address: (record.TailscaleIPs || []).find((item) => /^\d+\.\d+\.\d+\.\d+$/.test(item)) || null,
    platform: String(record.OS || 'unknown').toLowerCase(), online: record.Online !== false,
    local: record === status.Self, transport: 'tailscale', userId: record.UserID === undefined ? null : String(record.UserID)
  })).filter((node) => node.id !== 'tailscale:undefined');
}

function localNode() {
  const machine = fs.existsSync('/etc/machine-id') ? fs.readFileSync('/etc/machine-id', 'utf8').trim() : os.hostname();
  const addresses = Object.values(os.networkInterfaces()).flat().filter((item) => item && item.family === 'IPv4' && !item.internal).map((item) => item.address).sort();
  return { id: `local:${machine}`, hostname: os.hostname(), address: addresses[0] || null, platform: process.platform === 'linux' ? 'linux' : process.platform, online: true, local: true, transport: 'local' };
}

function neighborNodes(existingAddresses) {
  if (process.platform !== 'linux' || !commandExists('ip')) return [];
  try {
    const records = JSON.parse(run('ip', ['-j', 'neigh', 'show'], { label: 'Neighbor discovery failed' }));
    return records.filter((item) => item.dst && !existingAddresses.has(item.dst) && !['FAILED', 'INCOMPLETE'].includes(item.state)).map((item) => ({
      id: `link-layer:${String(item.lladdr || item.dst).toLowerCase()}`, hostname: null, address: item.dst,
      platform: 'unknown', online: true, local: false, transport: 'ssh'
    }));
  } catch { return []; }
}

function sshCandidates(node, bootstrapIdentity = sshIdentity) {
  const addresses = [...new Set([node.managementAddress, node.publicAddress, node.address].filter(Boolean))];
  const modes = bootstrapIdentity ? ['existing', 'bootstrap'] : ['existing'];
  const preferredModes = node.sshIdentityMode && modes.includes(node.sshIdentityMode)
    ? [node.sshIdentityMode, ...modes.filter((mode) => mode !== node.sshIdentityMode)]
    : modes;
  return addresses.flatMap((address) => preferredModes.map((identityMode) => ({ address, identityMode })));
}

function openSshRemote(node, argv, input = null) {
  const sshUser = node.sshUser || configuredSshUser || (workstationMode ? null : sshUsers[0]);
  const remoteCommand = ['sudo', '-n', ...argv].map(quoteRemote).join(' ');
  if (node.transport === 'tailscale' && node.managementTransport !== 'openssh' && !node.tailscaleSshUnavailable) {
    try {
      const output = run('tailscale', ['ssh', `${sshUser}@${node.hostname || node.address}`, remoteCommand], { input, binary: Buffer.isBuffer(input), timeoutMs: node.managementTransport === 'tailscale' ? 120000 : 5000, label: `Tailscale SSH failed for ${node.id}` });
      node.managementTransport = 'tailscale';
      return output;
    } catch {
      node.tailscaleSshUnavailable = true;
      if (node.managementTransport === 'tailscale') throw new Error(`Selected Tailscale SSH transport failed for ${node.id}`);
    }
  }
  if (!fs.existsSync(knownHosts)) throw new Error(`No pinned SSH known-hosts file is available for ${node.id}`);
  validateSshFile(knownHosts, 'SSH known-hosts file');
  const ssh = requireExecutable('ssh');
  let lastError = new Error(`No SSH address is available for ${node.id}`);
  const unavailableAddresses = new Set();
  for (const candidate of sshCandidates(node)) {
    if (unavailableAddresses.has(candidate.address)) continue;
    const destination = sshUser ? `${sshUser}@${candidate.address}` : candidate.address;
    const args = ['-o', 'BatchMode=yes', '-o', 'PasswordAuthentication=no', '-o', 'StrictHostKeyChecking=yes', '-o', `UserKnownHostsFile=${knownHosts}`, '-o', 'ForwardAgent=no', ...sshConnectionOptions, ...sshMultiplexOptions(), '--', destination, remoteCommand];
    if (candidate.identityMode === 'bootstrap') {
      validateSshFile(sshIdentity, 'SSH bootstrap identity', { privateFile: true });
      args.splice(args.indexOf('--'), 0, '-o', 'IdentitiesOnly=yes', '-i', sshIdentity);
    }
    try {
      const output = run(ssh, args, { input, binary: Buffer.isBuffer(input), timeoutMs: node.managementTransport === 'openssh' ? 120000 : 8000, label: `Remote operation failed for ${node.id}` });
      node.managementAddress = candidate.address;
      node.sshIdentityMode = candidate.identityMode;
      node.managementTransport = 'openssh';
      return output;
    } catch (error) {
      lastError = error;
      if (!shouldRetrySshCandidate(error)) {
        node.managementAddress = candidate.address;
        node.sshIdentityMode = candidate.identityMode;
        node.managementTransport = 'openssh';
        throw error;
      }
      if (['transport', 'identity'].includes(error.failureKind)) unavailableAddresses.add(candidate.address);
    }
  }
  throw lastError;
}

function awsArguments(args, options) {
  return [...args, ...(options.region ? ['--region', options.region] : []), ...(options.profile ? ['--profile', options.profile] : [])];
}

const remoteStatusMarker = '__LOOKOUT_REMOTE_STATUS__:';
function commandWithRemoteStatus(command) {
  return `set +e\n${command}\nlookout_status=$?\nprintf '\n${remoteStatusMarker}%s\n' "$lookout_status"\nexit 0`;
}
function parseRemoteStatus(output, label) {
  const text = String(output || '');
  const matches = [...text.matchAll(/__LOOKOUT_REMOTE_STATUS__:(\d+)/g)];
  if (!matches.length) return text;
  const status = Number(matches.at(-1)[1]);
  const clean = text.replace(/\n?__LOOKOUT_REMOTE_STATUS__:\d+\n?/g, '').trim();
  if (status !== 0) {
    const error = new Error(`${label} exited with status ${status}${clean ? `: ${clean.slice(-2048)}` : ''}`);
    if (/sudo:.*(?:password|not in the sudoers)|permission denied/i.test(clean)) error.failureKind = 'authentication';
    else error.code = 'LOOKOUT_REMOTE_COMMAND_FAILED';
    error.exitCode = status;
    throw error;
  }
  return clean;
}

function nativeProviderRun(method, options) {
  if (method === 'aws-ssm') {
    const parameters = JSON.stringify({ commands: [commandWithRemoteStatus(options.command)] });
    const response = JSON.parse(run('aws', awsArguments(['ssm', 'send-command', '--instance-ids', options.instanceId, '--document-name', 'AWS-RunShellScript', '--parameters', parameters, '--output', 'json'], options), { label: `AWS SSM command failed for ${options.instanceId}` }));
    const commandId = response.Command?.CommandId;
    if (!commandId) throw new Error('AWS SSM returned no command ID');
    for (let attempt = 0; attempt < 60; attempt += 1) {
      try {
        const result = JSON.parse(run('aws', awsArguments(['ssm', 'get-command-invocation', '--command-id', commandId, '--instance-id', options.instanceId, '--output', 'json'], options), { timeoutMs: 10000, label: 'AWS SSM command status failed' }));
        if (result.Status === 'Success') return parseRemoteStatus(result.StandardOutputContent || '', 'AWS SSM remote command');
        if (result.Status === 'Failed') {
          const error = new Error(result.StandardErrorContent || 'AWS SSM remote command failed');
          error.code = 'LOOKOUT_REMOTE_COMMAND_FAILED';
          throw error;
        }
        if (['Cancelled', 'TimedOut', 'Undeliverable', 'Terminated'].includes(result.Status)) {
          const error = new Error(result.StandardErrorContent || `AWS SSM ended with ${result.Status}`);
          error.failureKind = 'transport';
          throw error;
        }
      } catch (error) { if (!/status failed/.test(error.message)) throw error; }
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 500);
    }
    throw new Error('AWS SSM command timed out');
  }
  if (method === 'aws-instance-connect') {
    run('aws', awsArguments(['ec2-instance-connect', 'send-ssh-public-key', '--instance-id', options.instanceId, '--instance-os-user', options.user || configuredSshUser || 'ubuntu', '--availability-zone', options.zone, '--ssh-public-key', `file://${bootstrapPublicKeyFile}`, '--output', 'json'], options), { label: `EC2 Instance Connect failed for ${options.instanceId}` });
    return '';
  }
  if (method === 'gcp-os-login' || method === 'gcp-iap') {
    const args = ['compute', 'ssh', options.instance, '--zone', options.zone, '--quiet', `--command=${commandWithRemoteStatus(options.command)}`];
    if (options.project) args.push('--project', options.project);
    if (method === 'gcp-iap') args.push('--tunnel-through-iap');
    return parseRemoteStatus(run('gcloud', args, { input: options.input, binary: Buffer.isBuffer(options.input), label: `GCP access failed for ${options.instance}` }), 'GCP remote command');
  }
  if (method === 'azure-run-command') {
    const target = options.resourceId ? ['--ids', options.resourceId] : ['--resource-group', options.resourceGroup, '--name', options.name];
    const result = JSON.parse(run('az', ['vm', 'run-command', 'invoke', ...target, '--command-id', 'RunShellScript', '--scripts', commandWithRemoteStatus(options.command), '-o', 'json'], { label: `Azure Run Command failed for ${options.name}` }));
    return parseRemoteStatus((result.value || []).map((item) => item.message || '').join('\n'), 'Azure remote command');
  }
  throw new Error(`Unsupported provider access method: ${method}`);
}

let accessBroker;
function remote(node, argv, input = null) {
  accessBroker ||= new ProviderAccessBroker({
    run: nativeProviderRun,
    ssh: (target, command, commandInput) => openSshRemote(target, command, commandInput),
    publicKey: bootstrapPublicKeyFile && fs.existsSync(bootstrapPublicKeyFile) ? fs.readFileSync(bootstrapPublicKeyFile, 'utf8').trim() : null
  });
  return accessBroker.execute(node, argv, { input });
}

function probe(node) {
  if (node.local) { node.reachable = node.platform === 'linux'; node.architecture = normalizeLinuxArchitecture(os.arch()); return node; }
  if (!node.online || !node.address) { node.reachable = false; return node; }
  const userCandidates = workstationMode && !node.sshUser ? [null] : [...new Set([node.sshUser, ...sshUsers].filter(Boolean))];
  for (const candidate of userCandidates) {
    try {
      node.sshUser = candidate;
      const output = String(remote(node, ['uname', '-s', '-m'])).trim().split(/\s+/);
      const system = String(output[0] || '').toLowerCase();
      node.platform = system === 'linux' ? 'linux' : node.platform;
      node.architecture = system === 'linux' ? normalizeLinuxArchitecture(output[1]) : null;
      node.reachable = system === 'linux';
      return node;
    } catch (error) {
      const action = probeFailureAction(error);
      if (action === 'stop') break;
      if (action === 'continue') continue;
      if (action === 'needs-access') {
        node.sshUser = null;
        node.reachable = false;
        node.accessRequirement = error.message.replace(/^Needs access(?: for [^:]+)?:\s*/i, '');
        return node;
      }
      throw error;
    }
  }
  node.sshUser = null;
  node.reachable = false;
  node.accessRequirement = leastPrivilegeAccess(node);
  return node;
}

function leastPrivilegeAccess(node) {
  if (node.provider === 'aws') return `allow ssm:SendCommand and ssm:GetCommandInvocation for ${node.instanceId}, or enable EC2 Instance Connect for this instance`;
  if (node.provider === 'gcp') return `grant OS Login for ${node.project || 'the instance project'} and IAP tunnel access for ${node.instanceId}`;
  if (node.provider === 'azure') return `allow Microsoft.Compute/virtualMachines/runCommand/action for ${node.resourceId || node.instanceId}`;
  if (node.provider === 'digitalocean') return `authorize the temporary Lookout SSH public key for droplet ${node.instanceId}`;
  return `authorize the temporary Lookout SSH public key for ${node.id}`;
}

function spawnProbeWorker(node) {
  return new Promise((resolve, reject) => {
    const worker = new Worker(__filename, { workerData: { mode: 'access-probe', node } });
    let settled = false;
    worker.once('message', (message) => {
      settled = true;
      if (message?.ok) resolve(message.value);
      else reject(new Error(message?.error || 'Access probe failed'));
    });
    worker.once('error', (error) => { if (!settled) reject(error); });
    worker.once('exit', (code) => { if (!settled) reject(new Error(`Access probe worker exited without a result (status ${code})`)); });
  });
}

function assertApprovedLinuxAccess(nodes) {
  const unavailable = nodes.filter((node) => node.platform === 'linux' && !node.reachable);
  if (!unavailable.length) return;
  throw new Error(`Needs access: ${unavailable.map((node) => `${node.id} (${nodeLabel(node)}): ${node.accessRequirement || leastPrivilegeAccess(node)}`).join('; ')}`);
}

function archiveSource() {
  if (!fs.existsSync(path.join(source, 'node_modules', 'yaml', 'package.json'))) throw new Error('The verified release is missing prebuilt production dependencies');
  return run('tar', ['-C', source, '--exclude=.git', '--exclude=data', '--exclude=.env*', '--exclude=._*', '--exclude=.DS_Store', '-czf', '-', '.'], { binary: true, env: { ...process.env, COPYFILE_DISABLE: '1' }, label: 'Unable to package the prebuilt Lookout artifact' });
}

function normalizeLinuxArchitecture(value) {
  const architecture = String(value || '').trim().toLowerCase();
  if (['x86_64', 'amd64', 'x64'].includes(architecture)) return 'amd64';
  if (['aarch64', 'arm64'].includes(architecture)) return 'arm64';
  return null;
}

function parseReleaseTargets(raw = releaseTargetsJson) {
  if (!raw) return null;
  let value;
  try { value = typeof raw === 'string' ? JSON.parse(raw) : raw; } catch { throw new Error('Pinned release targets are invalid'); }
  const targets = {};
  for (const architecture of ['amd64', 'arm64']) {
    const item = value?.[architecture];
    if (!item?.url || !item?.sha256) throw new Error('Pinned release targets are invalid');
    validateReleaseConfiguration(item?.url, item?.sha256);
    targets[architecture] = { url: new URL(item.url).toString(), sha256: item.sha256 };
  }
  return targets;
}

function releaseForArchitecture(architecture, options = {}) {
  const targets = options.targets === undefined ? parseReleaseTargets() : parseReleaseTargets(options.targets);
  if (targets) {
    const normalized = normalizeLinuxArchitecture(architecture);
    if (!normalized || !targets[normalized]) throw new Error(`Unsupported Linux architecture: ${architecture || 'unknown'}`);
    return targets[normalized];
  }
  const url = options.url === undefined ? releaseUrl : options.url;
  const sha256 = options.sha256 === undefined ? releaseSha256 : options.sha256;
  validateReleaseConfiguration(url, sha256);
  return url ? { url: new URL(url).toString(), sha256 } : null;
}

function assertSupportedReleaseArchitectures(nodes, targets = releaseTargetsJson) {
  if (!targets) return;
  const parsed = parseReleaseTargets(targets);
  const unsupported = nodes.filter((node) => node.platform === 'linux' && node.reachable && (!node.architecture || !parsed[node.architecture]));
  if (unsupported.length) throw new Error(`Unsupported Linux architecture before release download: ${unsupported.map((node) => `${node.id} (${node.architecture || 'unknown'})`).join(', ')}`);
}

function deploymentArchive({ url = releaseUrl, sha256 = releaseSha256, targets = releaseTargetsJson } = {}) {
  if (targets) { parseReleaseTargets(targets); return Buffer.alloc(0); }
  if (!url) return archiveSource();
  validateReleaseConfiguration(url, sha256);
  return Buffer.alloc(0);
}

function validateReleaseConfiguration(url = releaseUrl, sha256 = releaseSha256) {
  if (!url) return;
  const parsed = new URL(url);
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.hash) throw new Error('Pinned release URL is invalid');
  if (!/^[a-f0-9]{64}$/.test(sha256 || '')) throw new Error('Pinned release SHA-256 is required for direct artifact distribution');
}

function preflightRemoteArtifact(node, archive, deploymentId) {
  const configured = releaseForArchitecture(node.architecture);
  const root = `/var/tmp/lookout-preflight-${deploymentId}-${crypto.randomUUID()}`;
  const incoming = `${root}/artifact.tar.gz`;
  const unpacked = `${root}/source`;
  const listing = `${root}/listing`;
  const digest = configured?.sha256 || crypto.createHash('sha256').update(archive).digest('hex');
  remote(node, ['install', '-d', '-m', '700', root]);
  try {
    if (configured) remote(node, ['curl', '--proto', '=https', '--tlsv1.2', '--fail', '--silent', '--show-error', '--location', '--retry', '3', '--output', incoming, configured.url]);
    else remote(node, ['install', '-m', '600', '/dev/stdin', incoming], archive);
    remote(node, ['sh', '-c', artifactPreflightScript(), 'lookout-artifact-preflight', incoming, digest, unpacked, listing, '1']);
    remote(node, ['rm', '-f', incoming, listing]);
    return { root, source: unpacked };
  } catch (error) {
    try { remote(node, ['rm', '-rf', root]); } catch { /* Preserve the preflight error. */ }
    throw new Error(`Release preflight failed for ${node.id}: ${error.message}`);
  }
}

function spawnArtifactPreflightWorker(node, archive, deploymentId) {
  return new Promise((resolve, reject) => {
    const worker = new Worker(__filename, { workerData: { mode: 'artifact-preflight', node, archive, deploymentId } });
    let settled = false;
    worker.once('message', (message) => {
      settled = true;
      if (message?.ok) resolve(message.value);
      else reject(new Error(message?.error || 'Release artifact preflight failed'));
    });
    worker.once('error', (error) => { if (!settled) reject(error); });
    worker.once('exit', (code) => { if (!settled) reject(new Error(`Artifact preflight worker exited without a result (status ${code})`)); });
  });
}

function activateRemoteStage(node, prepared, deploymentId) {
  const stage = `/var/lib/lookout-install/fleet-source-${deploymentId}`;
  const incoming = `/var/lib/lookout-install/.source-${deploymentId}-${crypto.randomUUID()}`;
  remote(node, ['mkdir', '-p', '/var/lib/lookout-install']);
  const script = 'set -eu; prepared=$1; incoming=$2; stage=$3; root=$4; rm -rf "$incoming"; cp -a "$prepared" "$incoming"; previous="$stage.previous.$$"; if test -e "$stage"; then mv "$stage" "$previous"; fi; mv "$incoming" "$stage"; rm -rf "$previous"; if test -n "$root"; then rm -rf "$root"; fi';
  remote(node, ['sh', '-c', script, 'lookout-artifact-activation', prepared.source, incoming, stage, prepared.root || '']);
  return stage;
}

function preflightLocalArtifact(archive, directory, node = { architecture: os.arch() }) {
  const configured = releaseForArchitecture(node.architecture);
  const incoming = path.join(directory, 'artifact.tar.gz');
  const unpacked = path.join(directory, 'source');
  const listing = path.join(directory, 'listing');
  if (configured) run(requireExecutable('curl'), ['--proto', '=https', '--tlsv1.2', '--fail', '--silent', '--show-error', '--location', '--retry', '3', '--output', incoming, configured.url], { label: 'Unable to download the pinned release artifact' });
  else fs.writeFileSync(incoming, archive, { mode: 0o600 });
  const digest = configured?.sha256 || crypto.createHash('sha256').update(archive).digest('hex');
  run('sh', ['-c', artifactPreflightScript(), 'lookout-artifact-preflight', incoming, digest, unpacked, listing, process.platform === 'linux' ? '1' : '0'], { label: 'Release artifact preflight failed' });
  fs.rmSync(incoming, { force: true });
  fs.rmSync(listing, { force: true });
  return unpacked;
}

function installFileRemote(node, filename, contents, mode = '600') {
  const incoming = `${filename}.lookout-${crypto.randomUUID()}`;
  const encoded = Buffer.from(contents).toString('base64');
  remote(node, ['mkdir', '-p', path.posix.dirname(filename)]);
  remote(node, ['rm', '-f', incoming]);
  try {
    for (let offset = 0; offset < encoded.length; offset += 8000) {
      const chunk = encoded.slice(offset, offset + 8000);
      remote(node, ['sh', '-c', 'printf %s "$2" | base64 -d >> "$1"', 'lookout-public-file', incoming, chunk]);
    }
    remote(node, ['install', '-m', mode, incoming, filename]);
  } finally { try { remote(node, ['rm', '-f', incoming]); } catch { /* Preserve the primary transfer result. */ } }
}

function encryptSecretForPublicKey(publicKey, contents) {
  const plaintext = Buffer.from(contents);
  if (plaintext.length > 190) throw new Error('Provider-native secret transfer payload is too large');
  return crypto.publicEncrypt({ key: publicKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, plaintext);
}

function installSecretFileRemote(node, filename, contents, mode = '600') {
  if (!['aws-ssm', 'azure-run-command'].includes(node.managementTransport)) {
    remote(node, ['install', '-m', mode, '/dev/stdin', filename], contents);
    return;
  }
  const keyFile = `/var/lib/lookout-install/.transfer-${crypto.randomUUID()}.key`;
  const publicOutput = String(remote(node, ['sh', '-c', 'set -eu; umask 077; openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$1" 2>/dev/null; openssl pkey -in "$1" -pubout', 'lookout-secret-key', keyFile]));
  const match = /-----BEGIN PUBLIC KEY-----[\s\S]+?-----END PUBLIC KEY-----/.exec(publicOutput);
  if (!match) { try { remote(node, ['rm', '-f', keyFile]); } catch { /* The original validation error is more useful. */ } throw new Error(`Provider-native secret transfer could not establish a key for ${node.id}`); }
  let ciphertext;
  try { ciphertext = encryptSecretForPublicKey(match[0], contents).toString('base64'); }
  catch (error) { try { remote(node, ['rm', '-f', keyFile]); } catch { /* Preserve the encryption error. */ } throw error; }
  const script = 'set -eu; key=$1; target=$2; mode=$3; ciphertext=$4; plain="$target.lookout.$$"; trap \'rm -f "$key" "$plain"\' EXIT; printf %s "$ciphertext" | base64 -d | openssl pkeyutl -decrypt -inkey "$key" -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 > "$plain"; install -m "$mode" "$plain" "$target"';
  remote(node, ['sh', '-c', script, 'lookout-secret-file', keyFile, filename, mode, ciphertext]);
}

function prepareRemoteTls(node, directory, address, deploymentId) {
  const certificate = path.join(directory, 'server.crt');
  const installedCertificate = '/etc/lookout/tls/server.crt';
  const installedKey = '/etc/lookout/tls/server.key';
  try {
    remote(node, ['test', '-f', installedCertificate, '-a', '-f', installedKey]);
    remote(node, ['openssl', 'x509', '-in', installedCertificate, '-noout', '-checkip', address]);
    fs.writeFileSync(certificate, remote(node, ['cat', installedCertificate]));
    return { certificate, remoteCertificate: installedCertificate, remoteKey: installedKey, temporary: false };
  } catch { /* Generate the private key on the selected central VM. */ }
  const remoteCertificate = `/var/lib/lookout-install/${deploymentId}.crt`;
  const remoteKey = `/var/lib/lookout-install/${deploymentId}.key`;
  remote(node, ['mkdir', '-p', '/var/lib/lookout-install']);
  remote(node, ['openssl', 'req', '-x509', '-newkey', 'rsa:3072', '-sha256', '-nodes', '-days', '825', '-subj', '/CN=Lookout Fleet', '-addext', `subjectAltName=IP:${address},IP:127.0.0.1,DNS:localhost`, '-keyout', remoteKey, '-out', remoteCertificate]);
  fs.writeFileSync(certificate, remote(node, ['cat', remoteCertificate]));
  return { certificate, remoteCertificate, remoteKey, temporary: true };
}
function localInstaller(environment, sourceDirectory = source) { run(path.join(sourceDirectory, 'install/install.sh'), [], { env: { ...process.env, LOOKOUT_SOURCE_DIR: sourceDirectory, ...environment }, label: 'Local Lookout installation failed' }); }
function remoteInstaller(node, stage, environment) {
  const assignments = Object.entries({ LOOKOUT_SOURCE_DIR: stage, ...environment }).map(([key, value]) => `${key}=${value}`);
  remote(node, ['env', ...assignments, `${stage}/install/install.sh`]);
}

const lookoutInstallMarkers = [
  '/opt/lookout', '/etc/lookout', '/etc/lookout-collector', '/var/lib/lookout', '/var/lib/lookout-collector',
  '/var/lib/lookout-install', '/etc/systemd/system/lookout.service', '/etc/systemd/system/lookout-collector.service',
  '/etc/lookout-update', '/etc/systemd/system/lookout-update.service', '/etc/systemd/system/lookout-update.timer',
  '/usr/local/bin/lookout', '/usr/local/sbin/lookout-uninstall'
];

function hasLocalLookoutInstallation() {
  return lookoutInstallMarkers.some((filename) => fs.existsSync(filename));
}

function hasRemoteLookoutInstallation(node) {
  const script = 'for candidate do if test -e "$candidate"; then printf installed; exit 0; fi; done; printf clean';
  return String(remote(node, ['sh', '-c', script, 'lookout-install-detection', ...lookoutInstallMarkers])).trim() === 'installed';
}

function freshUninstall(node) {
  const installed = node.local ? hasLocalLookoutInstallation() : hasRemoteLookoutInstallation(node);
  if (!installed) return { nodeId: node.id, cleaned: false };
  const uninstaller = path.join(source, 'install', 'uninstall.sh');
  if (node.local) {
    run(uninstaller, ['--purge', '--yes'], { env: { ...process.env, LOOKOUT_SKIP_CONSOLE_NOTIFICATION: '1', LOOKOUT_PRESERVE_INSTALL_STATE: '1' }, label: `Fresh uninstall failed for ${node.id}` });
  } else {
    const remoteScript = `/tmp/lookout-fresh-uninstall-${crypto.randomUUID()}.sh`;
    installFileRemote(node, remoteScript, fs.readFileSync(uninstaller), '700');
    try { remote(node, ['env', 'LOOKOUT_SKIP_CONSOLE_NOTIFICATION=1', 'sh', remoteScript, '--purge', '--yes']); }
    finally { try { remote(node, ['rm', '-f', remoteScript]); } catch { /* Preserve the uninstall result. */ } }
  }
  return { nodeId: node.id, cleaned: true };
}

async function freshUninstallSelected(nodes, uninstall = freshUninstall) {
  const operation = uninstall === freshUninstall ? spawnFreshUninstallWorker : uninstall;
  const results = await runBounded(nodes, Math.max(1, fleetConcurrency(nodes.length)), (node) => operation(node));
  const failures = results.map((result, index) => result.status === 'rejected' ? `${nodes[index].id}: ${result.reason.message}` : null).filter(Boolean);
  if (failures.length) throw new Error(`Fresh reinstall cleanup failed: ${failures.join('; ')}`);
  return results.map((result) => result.value);
}

function spawnFreshUninstallWorker(node) {
  return new Promise((resolve, reject) => {
    const worker = new Worker(__filename, { workerData: { mode: 'fresh-uninstall', node } });
    let settled = false;
    worker.once('message', (message) => {
      settled = true;
      if (message?.ok) resolve(message.value);
      else reject(new Error(message?.error || 'Fresh uninstall check failed'));
    });
    worker.once('error', (error) => { if (!settled) reject(error); });
    worker.once('exit', (code) => { if (!settled) reject(new Error(`Fresh uninstall worker exited without a result (status ${code})`)); });
  });
}

async function preflightBeforeUninstall(preflight, uninstall) {
  const prepared = await preflight();
  const cleanup = await uninstall();
  return { prepared, cleanup };
}

function reusableCentralArtifact(central, { workstation = workstationMode, vm = preparedCentralVm, sourceDirectory = preparedCentralSource, remoteImpl = remote } = {}) {
  if (!vm && !sourceDirectory) return null;
  const validSource = /^\/var\/tmp\/lookout-workstation-source-[A-Za-z0-9-]{1,128}(?:\/source)?$/.test(sourceDirectory || '') || /^\/var\/tmp\/lookout-preflight-[A-Za-z0-9._:-]{1,128}-[A-Za-z0-9-]{1,128}\/source$/.test(sourceDirectory || '');
  if (!workstation || vm !== central.id || !validSource) throw new Error('Prepared central release metadata is invalid');
  try { remoteImpl(central, ['test', '-f', `${sourceDirectory}/package.json`, '-a', '-f', `${sourceDirectory}/install/install.sh`]); }
  catch { return null; }
  return { root: null, source: sourceDirectory };
}

function loadPreparedFleet(filename = preparedFleetFile, { now = Date.now() } = {}) {
  if (!filename) return null;
  const target = path.resolve(filename);
  validateSshFile(target, 'Prepared fleet state', { privateFile: true });
  const value = JSON.parse(fs.readFileSync(target, 'utf8'));
  if (value.schemaVersion !== 1 || value.scopeDigest !== preparationScopeDigest || value.releaseFingerprint !== preparationReleaseFingerprint || !Array.isArray(value.nodes) || value.nodes.length > 256 || Number.isNaN(Date.parse(value.preparedAt)) || Number.isNaN(Date.parse(value.expiresAt)) || Date.parse(value.expiresAt) <= now || Date.parse(value.expiresAt) - Date.parse(value.preparedAt) > 10 * 60 * 1000) throw new Error('Prepared fleet state is invalid or expired');
  const ids = new Set();
  for (const node of value.nodes) {
    const root = node?.preparedArtifact?.root;
    if (typeof node?.id !== 'string' || ids.has(node.id) || node.platform !== 'linux' || node.reachable !== true || !['amd64', 'arm64'].includes(node.architecture) || !/^\/var\/tmp\/lookout-preflight-[A-Za-z0-9._:-]{1,128}-[A-Za-z0-9-]{1,128}$/.test(root || '') || node.preparedArtifact.source !== `${root}/source`) throw new Error('Prepared fleet state is invalid or expired');
    ids.add(node.id);
  }
  return value;
}

function mergePreparedNodes(nodes, preparation) {
  if (!preparation) return nodes;
  const prepared = new Map(preparation.nodes.map((node) => [node.id, node]));
  if (prepared.size !== nodes.length || nodes.some((node) => !prepared.has(node.id))) throw new Error('Prepared fleet does not match the approved VM list');
  return nodes.map((node) => {
    const prior = prepared.get(node.id);
    return { ...node, architecture: prior.architecture, reachable: prior.reachable, ...(prior.sshUser ? { sshUser: prior.sshUser } : {}), ...(prior.managementAddress ? { managementAddress: prior.managementAddress } : {}), ...(prior.sshIdentityMode ? { sshIdentityMode: prior.sshIdentityMode } : {}), ...(prior.managementTransport ? { managementTransport: prior.managementTransport } : {}) };
  });
}

function shouldRetireBootstrap(gaps, nodes) {
  return !gaps.some((gap) => gap.status === 'deployment-failed')
    && nodes.filter((node) => !node.local && node.platform === 'linux').every((node) => node.reachable)
    && !gaps.some((gap) => gap.status === 'bootstrap-key-removal-failed');
}

function generateTls(directory, address) {
  if (!commandExists('openssl')) throw new Error('OpenSSL is required to create the private fleet trust anchor');
  const certificate = path.join(directory, 'server.crt'); const key = path.join(directory, 'server.key');
  run('openssl', ['req', '-x509', '-newkey', 'rsa:3072', '-sha256', '-nodes', '-days', '825', '-subj', '/CN=Lookout Fleet', '-addext', `subjectAltName=IP:${address},IP:127.0.0.1,DNS:localhost`, '-keyout', key, '-out', certificate], { label: 'TLS certificate generation failed' });
  return { certificate, key };
}

function centralLookout(central, args) {
  const command = ['runuser', '-u', 'lookout', '--', '/usr/local/bin/lookout', ...args];
  return String(central.local ? run('runuser', command.slice(1), { label: 'Central Lookout command failed' }) : remote(central, command));
}

function verifyHeartbeat(central, collectorId) {
  for (let attempt = 0; attempt < 15; attempt += 1) {
    const status = JSON.parse(centralLookout(central, ['collector-status', collectorId]));
    if (status.enrolled && status.active && status.acceptedSequence > 0) return;
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 1000);
  }
  throw new Error('Collector enrolled but did not deliver a verified heartbeat');
}

function removeBootstrapAuthorization(node) {
  if (!bootstrapComment || node.local || !node.sshUser) return;
  const script = 'set -eu; home=$(getent passwd "$1" | cut -d: -f6); test -n "$home"; file="$home/.ssh/authorized_keys"; test -f "$file" || exit 0; tmp="$file.lookout.$$"; trap \'rm -f "$tmp"\' EXIT; awk -v marker="$2" \'index($0, marker) == 0 { print }\' "$file" > "$tmp"; chown --reference="$file" "$tmp"; chmod --reference="$file" "$tmp"; mv "$tmp" "$file"; trap - EXIT';
  remote(node, ['sh', '-c', script, 'lookout-bootstrap-cleanup', node.sshUser, bootstrapComment]);
}

function collectorWorkerProgress(node, phase) {
  parentPort?.postMessage({ type: 'progress', nodeId: node.id, label: nodeLabel(node), phase });
}

function installCollectorJob(job) {
  const { node, central, preparedArtifact, certificateFile, deploymentId, centralUrl, alreadyEnrolled, replaceEnrollment, invitationToken } = job;
  let stage = null; let invite = null;
  try {
    collectorWorkerProgress(node, 'staging application');
    stage = activateRemoteStage(node, preparedArtifact, deploymentId);
    const ca = `/var/lib/lookout-install/${deploymentId}.ca.pem`;
    installFileRemote(node, ca, fs.readFileSync(certificateFile), '644');
    const baseEnvironment = { LOOKOUT_ROLE: 'collector', LOOKOUT_COLLECTOR_SERVER_URL: centralUrl, LOOKOUT_COLLECTOR_CA_SOURCE: ca, LOOKOUT_COLLECTOR_ASSET_ID: node.id, LOOKOUT_DEPLOYMENT_ID: deploymentId };
    collectorWorkerProgress(node, alreadyEnrolled ? 'upgrading collector' : 'installing collector');
    if (alreadyEnrolled) remoteInstaller(node, stage, baseEnvironment);
    else {
      invite = `/var/lib/lookout-install/${deploymentId}.${crypto.randomUUID()}.invite`;
      installSecretFileRemote(node, invite, `${invitationToken}\n`, '600');
      remoteInstaller(node, stage, { ...baseEnvironment, LOOKOUT_ENROLLMENT_TOKEN_SOURCE: invite, ...(replaceEnrollment ? { LOOKOUT_REPLACE_ENROLLMENT: '1' } : {}) });
    }
    collectorWorkerProgress(node, 'validating signed heartbeat');
    const enrollment = JSON.parse(String(remote(node, ['cat', '/var/lib/lookout-collector/enrollment-result.json'])));
    verifyHeartbeat(central, enrollment.collectorId);
    return { nodeId: node.id, collectorId: enrollment.collectorId };
  } finally {
    collectorWorkerProgress(node, 'cleaning temporary files');
    if (invite) { try { remote(node, ['rm', '-f', invite]); } catch { /* Failure is reported by the worker result. */ } }
    if (stage) { try { remote(node, ['find', stage, '-depth', '-delete']); } catch { /* Installed releases are independent of staging. */ } }
  }
}

function spawnCollectorWorker(job, onProgress) {
  return new Promise((resolve, reject) => {
    const worker = new Worker(__filename, { workerData: { mode: 'collector-install', job } });
    let settled = false;
    worker.on('message', (message) => {
      if (message?.type === 'progress') onProgress(message);
      if (message?.type === 'result') {
        settled = true;
        if (message.ok) resolve(message.value);
        else reject(new Error(message.error || 'Collector installation failed'));
      }
    });
    worker.once('error', (error) => { if (!settled) reject(error); });
    worker.once('exit', (code) => { if (!settled) reject(new Error(`Collector worker exited without a result (status ${code})`)); });
  });
}

function spawnStateSaveWorker(node, contents) {
  return new Promise((resolve, reject) => {
    const worker = new Worker(__filename, { workerData: { mode: 'state-save', node, contents } });
    let settled = false;
    worker.once('message', (message) => {
      settled = true;
      if (message?.ok) resolve(message.value);
      else reject(new Error(message?.error || 'Fleet state save failed'));
    });
    worker.once('error', (error) => { if (!settled) reject(error); });
    worker.once('exit', (code) => { if (!settled) reject(new Error(`Fleet state worker exited without a result (status ${code})`)); });
  });
}

async function main() {
  if (requestedDeploymentId && !/^[A-Za-z0-9._:-]{1,128}$/.test(requestedDeploymentId)) throw new Error('Requested deployment identity is invalid');
  if (consoleCredentialSource && consoleCredentialRemote) throw new Error('SaaS console setup accepts only one credential source');
  if ((consoleEndpoint || consoleCredentialSource || consoleCredentialRemote) && !(consoleEndpoint && (consoleCredentialSource || consoleCredentialRemote) && requestedDeploymentId)) throw new Error('SaaS console setup requires endpoint, credential source, and deployment identity together');
  if (consoleEndpoint) {
    const parsed = new URL(consoleEndpoint);
    if (parsed.protocol !== 'https:' || parsed.username || parsed.password) throw new Error('SaaS console endpoint must be HTTPS without embedded credentials');
    if (consoleCredentialSource) validateSshFile(consoleCredentialSource, 'SaaS console credential', { privateFile: true });
    if (consoleCredentialRemote && (!workstationMode || !/^\/[A-Za-z0-9._/-]{1,1023}$/.test(consoleCredentialRemote) || consoleCredentialRemote.includes('/../'))) throw new Error('Remote SaaS console credential path is invalid');
  }
  const gaps = [];
  const approvedScope = loadApprovedScope(approvedScopeFile);
  const preparation = loadPreparedFleet();
  let nodes = mergePreparedNodes(approvedScope.nodes, preparation);
  if (!preparation) {
    reportStatus('discovering');
    const probeConcurrency = Math.max(1, fleetConcurrency(nodes.length));
    reportProgress(`Checking administrative access to ${nodes.length} approved node${nodes.length === 1 ? '' : 's'} with up to ${probeConcurrency} probes in parallel`);
    const probeResults = await runBounded(nodes, probeConcurrency, (node) => spawnProbeWorker(node));
    nodes = probeResults.map((result, index) => result.status === 'fulfilled' ? result.value : { ...nodes[index], reachable: false, sshUser: null });
  } else reportProgress(`Reusing fresh access checks for ${nodes.length} approved node${nodes.length === 1 ? '' : 's'}`);
  nodes = nodes.sort((a, b) => a.id.localeCompare(b.id));
  try { assertApprovedLinuxAccess(nodes); }
  catch (error) { reportStatus('needs_access'); throw error; }
  assertSupportedReleaseArchitectures(nodes);
  const deploymentId = requestedDeploymentId || stableDeploymentId(nodes);
  const standalone = nodes.length === 1 && nodes[0].local && nodes[0].platform === 'linux';
  const central = standalone ? nodes[0] : chooseCentral(nodes, [], approvedScope.centralVmId);
  if (!standalone && !central.address) throw new Error('The selected central node has no private IPv4 address for TLS');
  if (attachConsoleOnly) {
    if (standalone || !consoleEndpoint || !consoleCredentialRemote || !requestedDeploymentId) throw new Error('SaaS attachment requires a remote central VM and complete console details');
    remoteInstaller(central, '/opt/lookout/current', {
      LOOKOUT_ROLE: 'central', LOOKOUT_BIND_HOST: central.address,
      LOOKOUT_TLS_CERT_SOURCE: '/etc/lookout/tls/server.crt', LOOKOUT_TLS_KEY_SOURCE: '/etc/lookout/tls/server.key',
      LOOKOUT_COLLECTOR_ASSET_ID: central.id, LOOKOUT_RECONCILE_CONFIG: '1',
      LOOKOUT_ATTACH_CONSOLE_ONLY: '1',
      LOOKOUT_CONSOLE_ENDPOINT: consoleEndpoint, LOOKOUT_CONSOLE_DEPLOYMENT_ID: requestedDeploymentId,
      LOOKOUT_CONSOLE_CREDENTIAL_SOURCE: consoleCredentialRemote
    });
    process.stdout.write(`${JSON.stringify({ schemaVersion: 1, deploymentId: requestedDeploymentId, central: central.id, attached: true }, null, 2)}\n`);
    return;
  }
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'lookout-fleet-'));
  const preparedArtifacts = new Map();
  try {
    if (prepareOnly) {
      if (!/^[A-Za-z0-9_-]{43}$/.test(preparationScopeDigest || '') || !/^[a-f0-9]{64}$/.test(preparationReleaseFingerprint || '')) throw new Error('Preparation binding metadata is invalid');
      const archive = deploymentArchive();
      const remoteNodes = nodes.filter((node) => !node.local);
      reportProgress(`Downloading and verifying the release on ${remoteNodes.length} VM${remoteNodes.length === 1 ? '' : 's'} in parallel`);
      const results = await runBounded(remoteNodes, Math.max(1, fleetConcurrency(remoteNodes.length)), (node) => spawnArtifactPreflightWorker(node, archive, `prepare-${preparationScopeDigest.slice(0, 24)}`));
      const failures = results.map((result, index) => result.status === 'rejected' ? `${remoteNodes[index].id}: ${result.reason.message}` : null).filter(Boolean);
      if (failures.length) {
        for (const [index, result] of results.entries()) if (result.status === 'fulfilled') { try { remote(remoteNodes[index], ['rm', '-rf', result.value.root]); } catch { /* Preserve the preparation failure. */ } }
        throw new Error(`VM preparation failed: ${failures.join('; ')}`);
      }
      const preparedAt = new Date();
      const result = {
        schemaVersion: 1, scopeDigest: preparationScopeDigest, releaseFingerprint: preparationReleaseFingerprint,
        centralVm: central.id, preparedAt: preparedAt.toISOString(), expiresAt: new Date(preparedAt.getTime() + 10 * 60 * 1000).toISOString(),
        nodes: remoteNodes.map((node, index) => ({ ...persistedFleetNode(node), platform: 'linux', reachable: true, preparedArtifact: results[index].value }))
      };
      process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
      return;
    }
    if (preparation) {
      const preparedById = new Map(preparation.nodes.map((node) => [node.id, node.preparedArtifact]));
      const checks = await runBounded(nodes.filter((node) => !node.local), Math.max(1, fleetConcurrency(nodes.length)), (node) => {
        const artifact = preparedById.get(node.id);
        if (!artifact) return null;
        remote(node, ['test', '-f', `${artifact.source}/package.json`, '-a', '-f', `${artifact.source}/install/install.sh`]);
        return artifact;
      });
      const remoteNodes = nodes.filter((node) => !node.local);
      for (const [index, result] of checks.entries()) if (result.status === 'fulfilled' && result.value) preparedArtifacts.set(remoteNodes[index].id, result.value);
    }
    const reusableCentral = reusableCentralArtifact(central);
    if (reusableCentral) preparedArtifacts.set(central.id, reusableCentral);
    const { prepared: { localSource }, cleanup } = await preflightBeforeUninstall(async () => {
      const archive = deploymentArchive();
      reportProgress(`Validating the pinned release on ${nodes.length} selected node${nodes.length === 1 ? '' : 's'} before changing any installation`);
      const localNode = nodes.find((node) => node.local);
      const validatedLocalSource = localNode || !releaseTargetsJson ? preflightLocalArtifact(archive, temporary, localNode) : null;
      const remoteNodes = nodes.filter((node) => !node.local && !preparedArtifacts.has(node.id));
      const preflightResults = await runBounded(remoteNodes, Math.max(1, fleetConcurrency(remoteNodes.length)), (node) => spawnArtifactPreflightWorker(node, archive, deploymentId));
      const preflightFailures = [];
      for (const [index, result] of preflightResults.entries()) {
        if (result.status === 'fulfilled') preparedArtifacts.set(remoteNodes[index].id, result.value);
        else preflightFailures.push(result.reason.message);
      }
      if (preflightFailures.length) throw new Error(`Release preflight failed before uninstall: ${preflightFailures.join('; ')}`);
      reportProgress('Release artifact and VM prerequisites passed on every selected node');
      return { localSource: validatedLocalSource };
    }, async () => {
      reportProgress(`Checking ${nodes.length} selected node${nodes.length === 1 ? '' : 's'} for an existing Lookout installation`);
      return freshUninstallSelected(nodes);
    });
    const cleaned = cleanup.filter((item) => item.cleaned).length;
    if (cleaned) reportProgress(`Removed existing Lookout installation from ${cleaned} selected node${cleaned === 1 ? '' : 's'}`);
    if (standalone) {
      reportStatus('deploying', 0, 1);
      reportProgress('Installing the standalone service on this node');
      localInstaller({
        LOOKOUT_ROLE: 'standalone', LOOKOUT_DEPLOYMENT_ID: deploymentId,
        LOOKOUT_RECONCILE_CONFIG: '1',
        ...(consoleEndpoint ? { LOOKOUT_CONSOLE_ENDPOINT: consoleEndpoint, LOOKOUT_CONSOLE_DEPLOYMENT_ID: deploymentId, LOOKOUT_CONSOLE_CREDENTIAL_SOURCE: consoleCredentialSource } : {})
      }, localSource);
      const surveyPath = '/etc/lookout/fleet-survey.json';
      fs.writeFileSync(surveyPath, `${JSON.stringify(buildFleetSurvey(nodes, nodes[0], deploymentId))}\n`, { mode: 0o600 });
      run('chown', ['lookout:lookout', surveyPath], { label: 'Unable to secure local survey' });
      centralLookout(nodes[0], ['survey-declaration', surveyPath]);
      run('systemctl', ['restart', 'lookout.service'], { label: 'Unable to reload local survey' });
      reportProgress('Standalone installation and validation complete');
      reportStatus('verifying');
      reportStatus('protected', 1, 1);
      process.stdout.write(`${JSON.stringify({ schemaVersion: 1, mode: 'standalone', deploymentId, central: nodes[0].id, gaps: [] }, null, 2)}\n`);
      return;
    }
    let tls;
    if (central.local) {
      try {
        const certificate = path.join(temporary, 'server.crt'); const key = path.join(temporary, 'server.key');
        fs.copyFileSync('/etc/lookout/tls/server.crt', certificate); fs.copyFileSync('/etc/lookout/tls/server.key', key);
        run('openssl', ['x509', '-in', certificate, '-noout', '-checkip', central.address], { label: 'Existing fleet certificate does not match the central address' });
        tls = { certificate, key, temporary: false };
      } catch { tls = { ...generateTls(temporary, central.address), temporary: true }; }
    } else {
      tls = prepareRemoteTls(central, temporary, central.address, deploymentId);
    }
    const operatorUserId = nodes.find((node) => node.local && node.transport === 'tailscale')?.userId;
    const consoleEnvironment = consoleEndpoint ? { LOOKOUT_CONSOLE_ENDPOINT: consoleEndpoint, LOOKOUT_CONSOLE_DEPLOYMENT_ID: deploymentId, LOOKOUT_CONSOLE_CREDENTIAL_SOURCE: consoleCredentialSource || consoleCredentialRemote } : {};
    const centralEnvironment = { LOOKOUT_ROLE: 'central', LOOKOUT_BIND_HOST: central.address, ...(central.local ? { LOOKOUT_TLS_CERT_SOURCE: tls.certificate, LOOKOUT_TLS_KEY_SOURCE: tls.key } : {}), LOOKOUT_COLLECTOR_ASSET_ID: central.id, LOOKOUT_RECONCILE_CONFIG: '1', ...consoleEnvironment, ...(operatorUserId ? { LOOKOUT_TAILSCALE_ALLOWED_USER_IDS: operatorUserId } : {}) };
    let centralStage = null;
    reportProgress(`Installing central service on ${nodeLabel(central)}`);
    reportStatus('deploying', 0, nodes.length);
    if (central.local) localInstaller(centralEnvironment, localSource);
    else {
      centralStage = activateRemoteStage(central, preparedArtifacts.get(central.id), deploymentId);
      const remoteConsoleCredential = consoleEndpoint ? (consoleCredentialRemote || `/var/lib/lookout-install/${deploymentId}.console-token`) : null;
      let centralInstallError = null;
      try {
        if (remoteConsoleCredential && !consoleCredentialRemote) installSecretFileRemote(central, remoteConsoleCredential, fs.readFileSync(consoleCredentialSource), '600');
        remoteInstaller(central, centralStage, { ...centralEnvironment, LOOKOUT_TLS_CERT_SOURCE: tls.remoteCertificate, LOOKOUT_TLS_KEY_SOURCE: tls.remoteKey, ...(remoteConsoleCredential ? { LOOKOUT_CONSOLE_CREDENTIAL_SOURCE: remoteConsoleCredential } : {}) });
      } catch (error) {
        centralInstallError = error;
        throw error;
      } finally {
        const cleanupCredential = remoteConsoleCredential && !consoleCredentialRemote ? [remoteConsoleCredential] : [];
        const cleanup = [...(tls.temporary ? [tls.remoteCertificate, tls.remoteKey] : []), ...cleanupCredential];
        try { if (cleanup.length) remote(central, ['rm', '-f', ...cleanup]); }
        catch (error) { if (!centralInstallError) throw error; }
      }
    }
    reportStatus('deploying', 1, nodes.length);
    const centralUrl = `https://${central.address}:${port}`;
    reportProgress(`Central service ready at ${centralUrl}`);
    const collectorTargets = [];
    for (const node of nodes) {
      if (node.id === central.id || !node.reachable || node.platform !== 'linux') {
        if (node.id !== central.id) {
          const status = node.platform === 'linux' ? 'unreachable' : 'requires-adapter';
          gaps.push({ assetId: node.id, status, platform: node.platform });
          reportProgress(`${nodeLabel(node)} skipped: ${status}`);
        }
        continue;
      }
      collectorTargets.push(node);
    }
    const concurrency = fleetConcurrency(collectorTargets.length);
    if (collectorTargets.length) reportProgress(`Preparing ${collectorTargets.length} collector${collectorTargets.length === 1 ? '' : 's'} for installation with up to ${concurrency} running in parallel`);
    const collectorJobs = [];
    let invitationByAsset = new Map();
    if (collectorTargets.length) {
      const batch = JSON.parse(centralLookout(central, ['collector-invite-batch', deploymentId, JSON.stringify(collectorTargets.map((node) => node.id))]));
      if (!Array.isArray(batch.invitations) || batch.invitations.length !== collectorTargets.length) throw new Error('Central returned an invalid collector invitation batch');
      invitationByAsset = new Map(batch.invitations.map((invitation) => [invitation.assetId, invitation]));
    }
    for (const [index, node] of collectorTargets.entries()) {
      try {
        reportProgress(`[prepare ${index + 1}/${collectorTargets.length}] ${nodeLabel(node)}: creating fresh enrollment`);
        const invitation = invitationByAsset.get(node.id);
        if (!invitation?.token) throw new Error('Central returned no invitation for this collector');
        collectorJobs.push({ node, central, preparedArtifact: preparedArtifacts.get(node.id), certificateFile: tls.certificate, deploymentId, centralUrl, alreadyEnrolled: false, replaceEnrollment: false, invitationToken: invitation.token });
      } catch (error) {
        gaps.push({ assetId: node.id, status: 'deployment-failed', platform: node.platform });
        reportProgress(`[prepare ${index + 1}/${collectorTargets.length}] ${nodeLabel(node)}: failed (${error.message})`);
      }
    }
    let completedCollectors = 0;
    const collectorResults = await runBounded(collectorJobs, Math.max(1, concurrency), async (job, index) => {
      const value = await spawnCollectorWorker(job, ({ label, phase }) => reportProgress(`[node ${index + 1}/${collectorJobs.length}] ${label}: ${phase}`));
      completedCollectors += 1;
      reportStatus('deploying', 1 + completedCollectors, nodes.length);
      reportProgress(`[${completedCollectors}/${collectorTargets.length} active] ${nodeLabel(job.node)} collector is active`);
      return value;
    });
    for (const [index, result] of collectorResults.entries()) {
      if (result.status === 'fulfilled') continue;
      const node = collectorJobs[index].node;
      gaps.push({ assetId: node.id, status: 'deployment-failed', platform: node.platform });
      reportProgress(`${nodeLabel(node)} collector failed: ${result.reason.message}`);
    }
    if (collectorTargets.length) reportProgress(`Collector deployment finished: ${completedCollectors} active, ${collectorTargets.length - completedCollectors} failed`);
    reportProgress('Publishing the fleet survey and restarting the central service');
    reportStatus('verifying');
    const survey = buildFleetSurvey(nodes, central, deploymentId);
    const surveyPath = '/etc/lookout/fleet-survey.json';
    if (central.local) {
      fs.writeFileSync(surveyPath, `${JSON.stringify(survey)}\n`, { mode: 0o600 });
      run('chown', ['lookout:lookout', surveyPath], { label: 'Unable to secure fleet survey' });
      centralLookout(central, ['survey-declaration', surveyPath]);
      run('systemctl', ['restart', 'lookout.service'], { label: 'Unable to reload fleet survey' });
    } else {
      installFileRemote(central, surveyPath, `${JSON.stringify(survey)}\n`, '600');
      remote(central, ['chown', 'lookout:lookout', surveyPath]);
      centralLookout(central, ['survey-declaration', surveyPath]);
      remote(central, ['systemctl', 'restart', 'lookout.service']);
    }
    const result = { schemaVersion: 1, deploymentId, central: central.id, centralUrl, nodes: nodes.map(persistedFleetNode), gaps };
    const encodedResult = `${JSON.stringify(result, null, 2)}\n`;
    reportProgress('Saving fleet state on reachable nodes');
    const stateTargets = nodes.filter((item) => item.reachable && !item.local);
    await runBounded(stateTargets, Math.max(1, fleetConcurrency(stateTargets.length)), (node) => spawnStateSaveWorker(node, encodedResult));
    const stateDirectory = process.platform === 'linux' && process.getuid?.() === 0 ? '/var/lib/lookout-install' : path.join(invokingHome(), '.lookout');
    fs.mkdirSync(stateDirectory, { recursive: true, mode: 0o700 });
    const stateFile = path.join(stateDirectory, deploymentConfigName);
    fs.writeFileSync(stateFile, encodedResult, { mode: 0o600 });
    if (process.getuid?.() === 0 && process.env.SUDO_USER && process.env.SUDO_USER !== 'root' && stateDirectory !== '/var/lib/lookout-install') {
      try {
        const uid = Number(run('id', ['-u', process.env.SUDO_USER]).trim());
        const gid = Number(run('id', ['-g', process.env.SUDO_USER]).trim());
        fs.chownSync(stateDirectory, uid, gid); fs.chownSync(stateFile, uid, gid);
      } catch { throw new Error('Fleet state was written but ownership could not be returned to the invoking user'); }
    }
    const deploymentFailed = gaps.some((gap) => gap.status === 'deployment-failed');
    const cleanupTargets = nodes.filter((item) => item.reachable && !item.local);
    if (deploymentFailed && bootstrapComment) reportProgress('Retaining the temporary bootstrap key because deployment is incomplete');
    if (!deploymentFailed && bootstrapComment && cleanupTargets.length) reportProgress(`Removing the temporary bootstrap authorization from ${cleanupTargets.length} remote node${cleanupTargets.length === 1 ? '' : 's'}`);
    if (!deploymentFailed) for (const node of cleanupTargets) {
      try { removeBootstrapAuthorization(node); }
      catch { gaps.push({ assetId: node.id, status: 'bootstrap-key-removal-failed', platform: node.platform }); process.exitCode = 1; }
    }
    if (bootstrapComment && shouldRetireBootstrap(gaps, nodes)) {
      for (const filename of [sshIdentity, `${sshIdentity}.pub`, path.join(path.dirname(sshIdentity), 'lookout-bootstrap-key.json')]) {
        try { fs.unlinkSync(filename); } catch (error) { if (error.code !== 'ENOENT') throw error; }
      }
      result.bootstrapKeyRetired = true;
      reportProgress('Temporary bootstrap key retired');
    }
    fs.writeFileSync(stateFile, `${JSON.stringify(result, null, 2)}\n`, { mode: 0o600 });
    if (deploymentFailed) {
      reportProgress(`Fleet setup incomplete: ${1 + completedCollectors} of ${nodes.length} selected Linux nodes are protected`);
    } else {
      reportStatus('protected', 1 + completedCollectors, nodes.length);
      reportProgress(`Fleet setup complete: ${1 + completedCollectors} protected Linux node${completedCollectors === 0 ? '' : 's'}`);
    }
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    if (deploymentFailed) process.exitCode = 1;
    if (centralStage) { try { remote(central, ['find', centralStage, '-depth', '-delete']); } catch { /* Installed release is independent of staging. */ } }
  } finally {
    for (const node of nodes.filter((item) => !item.local)) {
      const prepared = preparedArtifacts.get(node.id);
      if (!prepared) continue;
      if (!prepared.root) continue;
      try { remote(node, ['rm', '-rf', prepared.root]); } catch { /* Preserve the primary installation result. */ }
    }
    fs.rmSync(temporary, { recursive: true, force: true });
    if (sshControlDirectory) fs.rmSync(sshControlDirectory, { recursive: true, force: true });
  }
}

if (!isMainThread && workerData?.mode) {
  try {
    let value;
    if (workerData.mode === 'collector-install') value = installCollectorJob(workerData.job);
    else if (workerData.mode === 'access-probe') value = probe(workerData.node);
    else if (workerData.mode === 'artifact-preflight') value = preflightRemoteArtifact(workerData.node, Buffer.from(workerData.archive), workerData.deploymentId);
    else if (workerData.mode === 'fresh-uninstall') value = freshUninstall(workerData.node);
    else if (workerData.mode === 'state-save') { installFileRemote(workerData.node, remoteDeploymentConfig, workerData.contents, '600'); value = { saved: true }; }
    else throw new Error('Unknown fleet worker mode');
    parentPort.postMessage({ type: 'result', ok: true, value });
  } catch (error) { parentPort.postMessage({ type: 'result', ok: false, error: error.message }); }
  finally { if (sshControlDirectory) fs.rmSync(sshControlDirectory, { recursive: true, force: true }); }
} else if (require.main === module) {
  main().catch((error) => { console.error(`lookout-fleet: ${error.message}`); process.exitCode = 1; });
}
module.exports = { buildFleetSurvey, chooseCentral, loadApprovedScope, stableDeploymentId, fleetConcurrency, runBounded, spawnProbeWorker, spawnArtifactPreflightWorker, spawnFreshUninstallWorker, spawnStateSaveWorker, deploymentArchive, encryptSecretForPublicKey, leastPrivilegeAccess, assertApprovedLinuxAccess, sshCandidates, sshConnectionOptions, sshMultiplexOptions, shouldRetrySshCandidate, probeFailureAction, awsArguments, persistedFleetNode, freshUninstallSelected, preflightBeforeUninstall, reusableCentralArtifact, loadPreparedFleet, mergePreparedNodes, shouldRetireBootstrap, lookoutInstallMarkers, deploymentConfigName, legacyDeploymentConfigName, normalizeLinuxArchitecture, parseReleaseTargets, releaseForArchitecture, assertSupportedReleaseArchitectures };

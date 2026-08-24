'use strict';

const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const crypto = require('node:crypto');
const { canonicalJson } = require('../core/canonical');

const NAME = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const HOST = /^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/;
const SSH_USER = /^[a-z_][a-z0-9_-]{0,31}$/i;

function defaultDirectory(environment = process.env) {
  return path.resolve(environment.LOOKOUT_CLI_STATE_DIR || path.join(os.homedir(), '.lookout', 'workstation'));
}

async function privateDirectory(directory) {
  const target = path.resolve(directory);
  await fs.mkdir(target, { recursive: true, mode: 0o700 });
  const stat = await fs.lstat(target);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error('Lookout CLI state directory must be a non-symlink directory');
  if (process.platform !== 'win32' && ((stat.mode & 0o077) !== 0 || (typeof process.geteuid === 'function' && stat.uid !== process.geteuid()))) throw new Error('Lookout CLI state directory must be private and owned by the current user');
  return target;
}

function validateAddress(value) {
  if (typeof value !== 'string' || (!net.isIP(value) && !HOST.test(value))) throw new Error('VM address must be an IP address or hostname');
  return value.toLowerCase();
}

function validateConfig(value) {
  if (!value || value.schemaVersion !== 1 || !Array.isArray(value.vms) || value.vms.length > 256 || (value.centralVm !== null && value.centralVm !== undefined && !NAME.test(value.centralVm))) throw new Error('Lookout workstation configuration is invalid');
  const names = new Set();
  const vms = value.vms.map((vm) => {
    if (!vm || !NAME.test(vm.name || '') || names.has(vm.name) || (vm.sshUser !== undefined && !SSH_USER.test(vm.sshUser))) throw new Error('Lookout VM configuration is invalid');
    names.add(vm.name);
    return { name: vm.name, address: validateAddress(vm.address), ...(vm.sshHost ? { sshHost: validateAddress(vm.sshHost) } : {}), ...(vm.sshUser ? { sshUser: vm.sshUser } : {}) };
  });
  if (value.centralVm && !names.has(value.centralVm)) throw new Error('Configured central VM is not in the VM list');
  return { schemaVersion: 1, centralVm: value.centralVm || null, vms };
}

async function readPrivateJson(filename, label) {
  const handle = await fs.open(filename, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size > 128 * 1024) throw new Error(`${label} must be a bounded regular file`);
    if (process.platform !== 'win32' && ((stat.mode & 0o077) !== 0 || (typeof process.geteuid === 'function' && stat.uid !== process.geteuid()))) throw new Error(`${label} must be private and owned by the current user`);
    return JSON.parse(await handle.readFile('utf8'));
  } finally { await handle.close(); }
}

async function atomicWrite(filename, value) {
  const temporary = `${filename}.${process.pid}.tmp`;
  try {
    await fs.writeFile(temporary, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
    await fs.rename(temporary, filename);
  } finally { await fs.rm(temporary, { force: true }); }
}

class WorkstationConfigStore {
  constructor({ directory = defaultDirectory() } = {}) { this.directory = path.resolve(directory); }
  get configFile() { return path.join(this.directory, 'config.json'); }
  get loginFile() { return path.join(this.directory, 'login.json'); }
  get installationFile() { return path.join(this.directory, 'installation.json'); }
  get preparationFile() { return path.join(this.directory, 'preparation.json'); }
  get pendingLoginFile() { return path.join(this.directory, 'pending-login.json'); }
  get releaseChannelFile() { return path.join(this.directory, 'release-channel.json'); }

  async load() {
    await privateDirectory(this.directory);
    try { return validateConfig(await readPrivateJson(this.configFile, 'Lookout workstation configuration')); }
    catch (error) { if (error.code === 'ENOENT') return { schemaVersion: 1, centralVm: null, vms: [] }; throw error; }
  }

  async save(value) {
    await privateDirectory(this.directory);
    const config = validateConfig(value);
    await atomicWrite(this.configFile, config);
    return config;
  }

  async addVm({ name, address, sshHost, sshUser } = {}) {
    if (!NAME.test(name || '') || (sshUser !== undefined && !SSH_USER.test(sshUser))) throw new Error('VM name or SSH user is invalid');
    const config = await this.load();
    const vm = { name, address: validateAddress(address), ...(sshHost ? { sshHost: validateAddress(sshHost) } : {}), ...(sshUser ? { sshUser } : {}) };
    const index = config.vms.findIndex((item) => item.name === name);
    if (index === -1) config.vms.push(vm); else config.vms[index] = vm;
    config.vms.sort((a, b) => a.name.localeCompare(b.name));
    return this.save(config);
  }

  async setCentral(name) {
    if (!NAME.test(name || '')) throw new Error('Central VM name is invalid');
    const config = await this.load();
    if (!config.vms.some((vm) => vm.name === name)) throw new Error('Central VM must be configured first');
    config.centralVm = name;
    return this.save(config);
  }

  async saveLogin(value) {
    await privateDirectory(this.directory);
    if (!value || typeof value.setupToken !== 'string' || !/^dpl_[A-Za-z0-9_-]{32}$/.test(value.deploymentId || '') || Number.isNaN(Date.parse(value.expiresAt)) || typeof value.origin !== 'string') throw new Error('Lookout login result is invalid');
    const origin = new URL(value.origin);
    const insecureLoopback = process.env.LOOKOUT_ALLOW_INSECURE_LOOPBACK === '1' && origin.protocol === 'http:' && ['127.0.0.1', 'localhost'].includes(origin.hostname);
    if ((!insecureLoopback && origin.protocol !== 'https:') || origin.username || origin.password || origin.search || origin.hash || (origin.pathname !== '/' && origin.pathname !== '')) throw new Error('Lookout login origin is invalid');
    await atomicWrite(this.loginFile, { schemaVersion: 1, ...value });
  }

  async loadLogin({ allowExpired = false } = {}) {
    let value;
    try { value = await readPrivateJson(this.loginFile, 'Lookout installation permission'); }
    catch (error) { if (error.code === 'ENOENT') throw new Error('Lookout installation permission is missing or expired; run lookout login'); throw error; }
    if (value.schemaVersion !== 1 || typeof value.setupToken !== 'string' || Number.isNaN(Date.parse(value.expiresAt)) || (!allowExpired && Date.parse(value.expiresAt) <= Date.now())) throw new Error('Lookout installation permission is missing or expired; run lookout login');
    return value;
  }

  async clearLogin() { await fs.rm(this.loginFile, { force: true }); }

  async savePendingLogin(value) {
    await privateDirectory(this.directory);
    if (!value || !/^dpl_[A-Za-z0-9_-]{32}$/.test(value.deploymentId || '') || Number.isNaN(Date.parse(value.expiresAt)) || typeof value.origin !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(value.scopeDigest || '') || !/^SHA256:/.test(value.keyFingerprint || '')) throw new Error('Lookout pending login is invalid');
    await atomicWrite(this.pendingLoginFile, { schemaVersion: 1, ...value });
  }

  async loadPendingLogin() {
    let value;
    try { value = await readPrivateJson(this.pendingLoginFile, 'Lookout pending login'); }
    catch (error) { if (error.code === 'ENOENT') throw new Error('Lookout browser login has not started; run lookout login'); throw error; }
    if (value.schemaVersion !== 1 || !/^dpl_[A-Za-z0-9_-]{32}$/.test(value.deploymentId || '') || Date.parse(value.expiresAt) <= Date.now()) throw new Error('Lookout browser login has not started; run lookout login');
    return value;
  }

  async clearPendingLogin() { await fs.rm(this.pendingLoginFile, { force: true }); }

  async savePreparation(value) {
    await privateDirectory(this.directory);
    if (!value || value.schemaVersion !== 1 || !/^[A-Za-z0-9_-]{43}$/.test(value.scopeDigest || '') || !/^[a-f0-9]{64}$/.test(value.releaseFingerprint || '') || Number.isNaN(Date.parse(value.preparedAt)) || Number.isNaN(Date.parse(value.expiresAt)) || !Array.isArray(value.nodes) || value.nodes.length > 256) throw new Error('Lookout preparation result is invalid');
    await atomicWrite(this.preparationFile, value);
    return value;
  }

  async loadPreparation() {
    try { return await readPrivateJson(this.preparationFile, 'Lookout preparation state'); }
    catch (error) { if (error.code === 'ENOENT') return null; throw error; }
  }

  async clearPreparation() { await fs.rm(this.preparationFile, { force: true }); }

  async loadReleaseChannelState() {
    try {
      const value = await readPrivateJson(this.releaseChannelFile, 'Lookout CLI release channel state');
      if (!value || value.schemaVersion !== 2 || !Array.isArray(value.channels) || value.channels.length > 8) throw new Error('Lookout CLI release channel state is invalid');
      for (const record of value.channels) {
        if (!record || typeof record.channelUrl !== 'string' || !Number.isSafeInteger(record.highestSequence) || record.highestSequence < 1 || !/^[a-f0-9]{64}$/.test(record.manifestDigest || '') || (record.targets !== null && (!record.targets || typeof record.targets !== 'object' || Array.isArray(record.targets))) || (record.targetsRelease !== undefined && record.targetsRelease !== null && !/^v\d+\.\d+\.\d+$/.test(record.targetsRelease))) throw new Error('Lookout CLI release channel state is invalid');
      }
      return value;
    } catch (error) { if (error.code === 'ENOENT') return null; throw error; }
  }

  async saveReleaseChannelState(value) {
    await privateDirectory(this.directory);
    if (!value || value.schemaVersion !== 2 || !Array.isArray(value.channels) || value.channels.length > 8) throw new Error('Lookout CLI release channel state is invalid');
    for (const record of value.channels) {
      if (!record || typeof record.channelUrl !== 'string' || !Number.isSafeInteger(record.highestSequence) || record.highestSequence < 1 || !/^[a-f0-9]{64}$/.test(record.manifestDigest || '') || (record.targets !== null && (!record.targets || typeof record.targets !== 'object' || Array.isArray(record.targets))) || (record.targetsRelease !== undefined && record.targetsRelease !== null && !/^v\d+\.\d+\.\d+$/.test(record.targetsRelease))) throw new Error('Lookout CLI release channel state is invalid');
    }
    await atomicWrite(this.releaseChannelFile, value);
    return value;
  }

  async loadInstallation() {
    try { return await readPrivateJson(this.installationFile, 'Lookout installation state'); }
    catch (error) { if (error.code === 'ENOENT') return null; throw error; }
  }
}

function installationScope(config) {
  const validated = validateConfig(config);
  if (!validated.vms.length || !validated.centralVm) throw new Error('Configure at least one VM and select the central VM before installation');
  const central = validated.vms.find((vm) => vm.name === validated.centralVm);
  if (!central || net.isIP(central.address) === 0) throw new Error('The central VM address must be a private IP address reachable by the other VMs');
  return {
    central_vm_id: validated.centralVm,
    vms: validated.vms.map((vm) => ({ id: vm.name, name: vm.name, address: vm.address, ...(vm.sshHost ? { ssh_host: vm.sshHost } : {}), ...(vm.sshUser ? { ssh_user: vm.sshUser } : {}), platform: 'linux', provider: 'openssh', local: false }))
  };
}

function installationScopeDigest(config) {
  return crypto.createHash('sha256').update(canonicalJson(installationScope(config))).digest('base64url');
}

module.exports = { WorkstationConfigStore, installationScope, installationScopeDigest, validateConfig, defaultDirectory, privateDirectory, atomicWrite };

#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const home = os.homedir();
const stateFiles = [path.join(home, '.lookout', 'security-observability-config.json'), path.join(home, '.lookout', 'fleet.json')];
const remoteStateFiles = ['/var/lib/lookout-install/security-observability-config.json', '/var/lib/lookout-install/fleet.json'];
const managedKnownHosts = path.join(home, '.lookout', 'known_hosts');
const knownHosts = process.env.LOOKOUT_SSH_KNOWN_HOSTS || (fs.existsSync(managedKnownHosts) ? managedKnownHosts : path.join(home, '.ssh', 'known_hosts'));
const defaultSshUser = process.env.LOOKOUT_SSH_USER || process.env.SUDO_USER || process.env.USER || 'root';

function purgeLocalOrchestrationState(homeDirectory = home) {
  const root = path.join(homeDirectory, '.lookout');
  for (const filename of ['security-observability-config.json', 'fleet.json', 'deployment-state.json', 'known_hosts']) {
    fs.rmSync(path.join(root, filename), { force: true });
  }
  fs.rmSync(path.join(root, 'install'), { recursive: true, force: true });
  try { fs.rmdirSync(root); } catch (error) { if (!['ENOENT', 'ENOTEMPTY'].includes(error.code)) throw error; }
}

function purgeCompleteLocalState(homeDirectory = home) {
  const root = path.join(homeDirectory, '.lookout');
  let stat;
  try { stat = fs.lstatSync(root); } catch (error) { if (error.code === 'ENOENT') return; throw error; }
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error('Refusing to completely remove an unsafe Lookout state path');
  if (process.platform !== 'win32' && typeof process.getuid === 'function' && stat.uid !== process.getuid()) throw new Error('Refusing to completely remove Lookout state owned by another user');
  const marker = ['security-observability-config.json', 'fleet.json'].some((filename) => fs.existsSync(path.join(root, filename)));
  if (!marker) throw new Error('Refusing to completely remove unrecognized Lookout state');
  fs.rmSync(root, { recursive: true, force: true });
}

function purgeWorkstationCli({ homeDirectory = home, environment = process.env, platform = process.platform } = {}) {
  const dataRoot = path.resolve(environment.LOOKOUT_CLI_DATA_DIR || (platform === 'win32'
    ? path.join(environment.LOCALAPPDATA || path.join(homeDirectory, 'AppData', 'Local'), 'Lookout', 'cli')
    : path.join(environment.XDG_DATA_HOME || path.join(homeDirectory, '.local', 'share'), 'lookout', 'cli')));
  const launcher = path.resolve(environment.LOOKOUT_CLI_BIN_DIR || (platform === 'win32'
    ? path.join(environment.LOCALAPPDATA || path.join(homeDirectory, 'AppData', 'Local'), 'Lookout', 'bin')
    : path.join(homeDirectory, '.local', 'bin')), platform === 'win32' ? 'lookout.cmd' : 'lookout');
  let rootStat;
  try { rootStat = fs.lstatSync(dataRoot); } catch (error) { if (error.code === 'ENOENT') return; throw error; }
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) throw new Error('Refusing to remove an unsafe Lookout CLI directory');
  if (platform !== 'win32' && typeof process.getuid === 'function' && rootStat.uid !== process.getuid()) throw new Error('Refusing to remove a Lookout CLI directory owned by another user');
  const releases = path.join(dataRoot, 'releases');
  const recognized = fs.existsSync(releases) && fs.readdirSync(releases).some((name) => {
    try {
      const marker = JSON.parse(fs.readFileSync(path.join(releases, name, '.lookout-cli-release.json'), 'utf8'));
      return marker.schemaVersion === 1 && /^v\d+\.\d+\.\d+$/.test(marker.releaseVersion || '') && /^[a-f0-9]{64}$/.test(marker.artifactSha256 || '');
    } catch { return false; }
  });
  if (!recognized) throw new Error('Refusing to remove an unrecognized Lookout CLI directory');
  if (fs.existsSync(launcher)) {
    const stat = fs.lstatSync(launcher);
    if (platform === 'win32') {
      if (!stat.isFile() || !fs.readFileSync(launcher, 'utf8').startsWith('@rem Lookout CLI\r\n')) throw new Error('Refusing to remove an unrelated workstation launcher');
    } else {
      if (!stat.isSymbolicLink()) throw new Error('Refusing to remove an unrelated workstation launcher');
      const target = path.resolve(path.dirname(launcher), fs.readlinkSync(launcher));
      const relative = path.relative(path.join(dataRoot, 'releases'), target);
      if (relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative) || !relative.endsWith(`${path.sep}bin${path.sep}lookout.js`)) throw new Error('Refusing to remove an unrelated workstation launcher');
    }
    fs.rmSync(launcher, { force: true });
  }
  fs.rmSync(dataRoot, { recursive: true, force: true });
}

function run(binary, args, options = {}) {
  const result = spawnSync(binary, args, { encoding: 'utf8', maxBuffer: 4 * 1024 * 1024, input: options.input });
  if (result.error || result.status !== 0) throw new Error(options.label || `${path.basename(binary)} failed`);
  return result.stdout;
}

function currentTailscaleNodes(status) {
  return [status.Self, ...Object.values(status.Peer || {})].filter(Boolean).map((record) => ({
    id: `tailscale:${record.StableID || record.ID}`,
    hostname: String(record.DNSName || record.HostName || '').replace(/\.$/, ''),
    address: (record.TailscaleIPs || []).find((item) => /^\d+\.\d+\.\d+\.\d+$/.test(item)) || null,
    platform: String(record.OS || 'unknown').toLowerCase(), local: record === status.Self
  }));
}

function remote(node, argv) {
  const sshUser = node.sshUser || defaultSshUser;
  try { return run('tailscale', ['ssh', `${sshUser}@${node.hostname || node.address}`, '--', 'sudo', '-n', ...argv], { label: `Tailscale SSH failed for ${node.id}` }); }
  catch { /* Use only strict, previously pinned OpenSSH as the fallback. */ }
  if (!fs.existsSync(knownHosts)) throw new Error(`No pinned SSH identity is available for ${node.id}`);
  return run('/usr/bin/ssh', ['-o', 'BatchMode=yes', '-o', 'PasswordAuthentication=no', '-o', 'StrictHostKeyChecking=yes', '-o', `UserKnownHostsFile=${knownHosts}`, '-o', 'ForwardAgent=no', '--', `${sshUser}@${node.address}`, 'sudo', '-n', ...argv], { label: `Remote uninstall failed for ${node.id}` });
}

function main() {
  if (process.argv.includes('--help') || process.argv.includes('-h')) {
    process.stdout.write('Usage: lookout-uninstall-fleet [--purge | --complete --yes]\n');
    return;
  }
  const unknown = process.argv.slice(2).filter((item) => !['--purge', '--complete', '--yes'].includes(item));
  if (unknown.length) throw new Error(`Unknown option: ${unknown[0]}`);
  const complete = process.argv.includes('--complete');
  const purge = complete || process.argv.includes('--purge');
  if (complete && !process.argv.includes('--yes')) throw new Error('--complete requires --yes');
  const stateFile = stateFiles.find((filename) => fs.existsSync(filename));
  if (!stateFile) throw new Error('No local Lookout deployment config was found; refusing an unscoped uninstall');
  const fleet = JSON.parse(fs.readFileSync(stateFile, 'utf8'));
  const status = JSON.parse(run('tailscale', ['status', '--json'], { label: 'Unable to rediscover the installed fleet' }));
  const current = new Map(currentTailscaleNodes(status).map((node) => [node.id, node]));
  const results = [];
  for (const installed of fleet.nodes || []) {
    if (installed.platform !== 'linux') continue;
    const node = current.get(installed.id);
    if (node && installed.sshUser) node.sshUser = installed.sshUser;
    if (!node || !node.address) { results.push({ assetId: installed.id, status: 'unreachable' }); continue; }
    try {
      let remoteState;
      for (const filename of remoteStateFiles) {
        try { remoteState = JSON.parse(remote(node, ['cat', filename])); break; } catch { /* Read the legacy marker only when needed. */ }
      }
      if (!remoteState) throw new Error('deployment config missing');
      if (remoteState.deploymentId !== fleet.deploymentId) throw new Error('fleet identity mismatch');
      remote(node, ['/usr/local/sbin/lookout-uninstall', ...(complete ? ['--complete', '--yes'] : purge ? ['--purge', '--yes'] : [])]);
      results.push({ assetId: installed.id, status: 'uninstalled' });
    } catch { results.push({ assetId: installed.id, status: 'failed' }); }
  }
  if (purge && results.length > 0 && results.every((item) => item.status === 'uninstalled')) {
    if (complete) purgeCompleteLocalState();
    else purgeLocalOrchestrationState();
    if (complete) purgeWorkstationCli();
  }
  process.stdout.write(`${JSON.stringify({ schemaVersion: 1, deploymentId: fleet.deploymentId, purge, complete, results }, null, 2)}\n`);
  if (results.some((item) => item.status !== 'uninstalled')) process.exitCode = 1;
}

if (require.main === module) { try { main(); } catch (error) { console.error(`lookout-uninstall-fleet: ${error.message}`); process.exitCode = 1; } }
module.exports = { currentTailscaleNodes, purgeLocalOrchestrationState, purgeCompleteLocalState, purgeWorkstationCli };

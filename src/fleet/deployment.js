'use strict';

const fs = require('node:fs');
const net = require('node:net');
const path = require('node:path');
const { spawn } = require('node:child_process');

const USER_PATTERN = /^[a-z_][a-z0-9_-]{0,31}$/i;

function quoteRemote(value) {
  if (typeof value !== 'string' || value.includes('\0')) throw new Error('Remote command argument is invalid');
  return `'${value.replace(/'/g, `'"'"'`)}'`;
}

function validatePrivateFile(filename, label, { executable = false } = {}) {
  const target = path.resolve(filename);
  const stat = fs.lstatSync(target);
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error(`${label} must be a regular, non-symlink file`);
  if (stat.size > 4 * 1024 * 1024) throw new Error(`${label} is too large`);
  if (executable && (stat.mode & 0o111) === 0) throw new Error(`${label} must be executable`);
  if (!executable && process.platform !== 'win32' && (stat.mode & 0o077) !== 0) throw new Error(`${label} permissions must be owner-only`);
  if (!executable && process.platform !== 'win32' && typeof process.geteuid === 'function' && stat.uid !== process.geteuid()) throw new Error(`${label} must be owned by the current user`);
  return target;
}

function validateKnownHosts(filename) { return validatePrivateFile(filename, 'SSH known-hosts file'); }

function defaultRunner(binary, argv, { input = null, timeoutMs = 30000 } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(binary, argv, { shell: false, stdio: ['pipe', 'pipe', 'pipe'] });
    const stdout = [];
    const stderr = [];
    let size = 0;
    const timer = setTimeout(() => child.kill('SIGKILL'), timeoutMs);
    const collect = (target) => (chunk) => {
      size += chunk.length;
      if (size > 4 * 1024 * 1024) child.kill('SIGKILL');
      else target.push(chunk);
    };
    child.stdout.on('data', collect(stdout));
    child.stderr.on('data', collect(stderr));
    child.once('error', reject);
    child.once('close', (code, signal) => {
      clearTimeout(timer);
      resolve({ code, signal, stdout: Buffer.concat(stdout).toString('utf8'), stderr: Buffer.concat(stderr).toString('utf8') });
    });
    if (input !== null) child.stdin.end(input); else child.stdin.end();
  });
}

class SshDeploymentTransport {
  constructor({ knownHostsFile, identityFile = null, runner = defaultRunner, sshBinary = '/usr/bin/ssh', timeoutMs = 30000 } = {}) {
    if (typeof runner !== 'function') throw new Error('SSH deployment runner must be a function');
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1000 || timeoutMs > 300000) throw new Error('SSH deployment timeout is invalid');
    this.knownHostsFile = validateKnownHosts(knownHostsFile);
    this.identityFile = identityFile ? validatePrivateFile(identityFile, 'SSH identity file') : null;
    this.runner = runner;
    this.sshBinary = validatePrivateFile(sshBinary, 'SSH binary', { executable: true });
    this.timeoutMs = timeoutMs;
  }

  #target(target) {
    if (!target?.deploymentAuthorized) throw new Error('Discovery does not authorize deployment to this asset');
    if (!USER_PATTERN.test(target.user || '') || net.isIP(target.address || '') === 0) throw new Error('SSH deployment target is invalid');
    return `${target.user}@${target.address}`;
  }

  async run(target, command, { input = null } = {}) {
    if (!Array.isArray(command) || command.length === 0 || command.length > 128) throw new Error('Remote command must be a bounded argument array');
    const destination = this.#target(target);
    const argv = [
      '-o', 'BatchMode=yes', '-o', 'PasswordAuthentication=no', '-o', 'KbdInteractiveAuthentication=no',
      '-o', 'StrictHostKeyChecking=yes', '-o', `UserKnownHostsFile=${this.knownHostsFile}`,
      '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'ForwardAgent=no', '-o', 'ClearAllForwardings=yes',
      '-o', `ConnectTimeout=${Math.max(1, Math.ceil(this.timeoutMs / 1000))}`
    ];
    if (this.identityFile) argv.push('-o', 'IdentitiesOnly=yes', '-i', this.identityFile);
    argv.push('--', destination, command.map(quoteRemote).join(' '));
    const result = await this.runner(this.sshBinary, argv, { input, timeoutMs: this.timeoutMs });
    if (!result || result.code !== 0) {
      const error = new Error('Authenticated remote command failed');
      error.code = 'REMOTE_COMMAND_FAILED';
      throw error;
    }
    return { stdout: result.stdout || '', stderr: result.stderr || '' };
  }

  async probe(target) {
    const result = await this.run(target, ['sudo', '-n', 'sh', '-c', 'uname -s; uname -m; cat /etc/machine-id']);
    const lines = result.stdout.trim().split(/\r?\n/);
    if (lines.length !== 3 || !/^(Linux|Darwin|FreeBSD|OpenBSD|NetBSD)$/.test(lines[0]) || !/^[A-Za-z0-9_.-]{1,64}$/.test(lines[1]) || !/^[a-f0-9]{32}$/.test(lines[2])) throw new Error('Authenticated endpoint returned an invalid platform identity');
    return { platform: lines[0], architecture: lines[1], machineId: lines[2] };
  }
}

module.exports = { SshDeploymentTransport, defaultRunner, quoteRemote, validateKnownHosts, validatePrivateFile };

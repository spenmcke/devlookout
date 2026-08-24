#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const fsp = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');

function requiredEnvironment(environment = process.env) {
  if (!environment.LOOKOUT_CLI_SOURCE_DIR) throw new Error('CLI source directory is required');
  const sourceDirectory = path.resolve(environment.LOOKOUT_CLI_SOURCE_DIR);
  const releaseVersion = environment.LOOKOUT_CLI_RELEASE_VERSION || '';
  const artifactSha256 = environment.LOOKOUT_CLI_ARTIFACT_SHA256 || '';
  const targets = {};
  if (!/^v\d+\.\d+\.\d+$/.test(releaseVersion)) throw new Error('CLI release version is invalid');
  if (!/^[a-f0-9]{64}$/.test(artifactSha256)) throw new Error('CLI release checksum is invalid');
  for (const architecture of ['amd64', 'arm64']) {
    const prefix = `LOOKOUT_CLI_TARGET_${architecture.toUpperCase()}`;
    const targetUrl = environment[`${prefix}_URL`] || '';
    const sha256 = environment[`${prefix}_SHA256`] || '';
    let parsed;
    try { parsed = new URL(targetUrl); } catch { throw new Error(`Linux ${architecture} target URL is invalid`); }
    if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.hash) throw new Error(`Linux ${architecture} target URL must be HTTPS without credentials or a fragment`);
    if (!/^[a-f0-9]{64}$/.test(sha256)) throw new Error(`Linux ${architecture} target checksum is invalid`);
    targets[architecture] = { url: parsed.toString(), sha256 };
  }
  return { sourceDirectory, releaseVersion, artifactSha256, targets };
}

async function directory(filename, { mode = 0o755 } = {}) {
  await fsp.mkdir(filename, { recursive: true, mode });
  const stat = await fsp.lstat(filename);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error(`CLI installation path must be a non-symlink directory: ${filename}`);
  if (process.platform !== 'win32' && typeof process.geteuid === 'function' && stat.uid !== process.geteuid()) throw new Error(`CLI installation path must be owned by the current user: ${filename}`);
}

async function regular(filename, label) {
  let stat;
  try { stat = await fsp.lstat(filename); }
  catch (error) {
    if (error.code === 'ENOENT') throw new Error(`${label} is missing from the verified CLI release`);
    throw error;
  }
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error(`${label} is missing from the verified CLI release`);
}

async function executable(filename, label) {
  let resolved;
  try { resolved = await fsp.realpath(filename); }
  catch (error) {
    if (error.code === 'ENOENT') throw new Error(`${label} is missing from the verified CLI release`);
    throw error;
  }
  await regular(resolved, label);
  if (process.platform !== 'win32') {
    try { await fsp.access(resolved, fs.constants.X_OK); }
    catch { throw new Error(`${label} is not executable`); }
  }
  return resolved;
}

async function ownedLookoutSymlink(executable, dataRoot) {
  let target;
  try { target = await fsp.readlink(executable); } catch { return false; }
  const resolved = path.resolve(path.dirname(executable), target);
  const relative = path.relative(path.join(dataRoot, 'releases'), resolved);
  const parts = relative.split(path.sep);
  if (relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative) || parts.length !== 3 || parts[1] !== 'bin' || parts[2] !== 'lookout.js') return false;
  try {
    const marker = JSON.parse(await fsp.readFile(path.join(path.dirname(path.dirname(resolved)), '.lookout-cli-release.json'), 'utf8'));
    return marker.schemaVersion === 1 && /^v\d+\.\d+\.\d+$/.test(marker.releaseVersion || '') && /^[a-f0-9]{64}$/.test(marker.artifactSha256 || '');
  } catch { return false; }
}

function paths({ environment = process.env, platform = process.platform, home = os.homedir(), releaseVersion, artifactSha256 }) {
  const dataRoot = path.resolve(environment.LOOKOUT_CLI_DATA_DIR || (platform === 'win32'
    ? path.join(environment.LOCALAPPDATA || path.join(home, 'AppData', 'Local'), 'Lookout', 'cli')
    : path.join(environment.XDG_DATA_HOME || path.join(home, '.local', 'share'), 'lookout', 'cli')));
  const binDirectory = path.resolve(environment.LOOKOUT_CLI_BIN_DIR || (platform === 'win32'
    ? path.join(environment.LOCALAPPDATA || path.join(home, 'AppData', 'Local'), 'Lookout', 'bin')
    : path.join(home, '.local', 'bin')));
  const releaseDirectory = path.join(dataRoot, 'releases', `${releaseVersion}-${artifactSha256.slice(0, 16)}`);
  const executable = path.join(binDirectory, platform === 'win32' ? 'lookout.cmd' : 'lookout');
  return { dataRoot, binDirectory, releaseDirectory, executable };
}

async function existingRelease(releaseDirectory, expected) {
  try {
    const marker = JSON.parse(await fsp.readFile(path.join(releaseDirectory, '.lookout-cli-release.json'), 'utf8'));
    return marker.schemaVersion === 1 && marker.releaseVersion === expected.releaseVersion && marker.artifactSha256 === expected.artifactSha256;
  } catch (error) {
    if (error.code === 'ENOENT') return false;
    throw new Error('Existing CLI release marker is invalid');
  }
}

async function installRelease(sourceDirectory, releaseDirectory, metadata) {
  if (await existingRelease(releaseDirectory, metadata)) return;
  try { await fsp.lstat(releaseDirectory); throw new Error('Existing CLI release does not match the verified artifact'); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
  const parent = path.dirname(releaseDirectory);
  await directory(parent);
  const staging = path.join(parent, `.staging-${process.pid}-${crypto.randomUUID()}`);
  try {
    await fsp.cp(sourceDirectory, staging, { recursive: true, dereference: true, errorOnExist: true });
    await fsp.writeFile(path.join(staging, '.lookout-cli-release.json'), `${JSON.stringify({ schemaVersion: 1, ...metadata }, null, 2)}\n`, { mode: 0o644, flag: 'wx' });
    await fsp.chmod(path.join(staging, 'bin', 'lookout.js'), 0o755);
    await fsp.rename(staging, releaseDirectory);
  } finally { await fsp.rm(staging, { recursive: true, force: true }); }
}

async function installLauncher({ dataRoot, releaseDirectory, binDirectory, executable, platform = process.platform, nodePath = process.execPath }) {
  await directory(binDirectory);
  let current = null;
  try { current = await fsp.lstat(executable); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  if (current && platform !== 'win32' && (!current.isSymbolicLink() || !await ownedLookoutSymlink(executable, dataRoot))) throw new Error(`Refusing to replace a non-Lookout executable: ${executable}`);
  if (current && platform === 'win32') {
    if (!current.isFile() || !String(await fsp.readFile(executable, 'utf8')).startsWith('@rem Lookout CLI\r\n')) throw new Error(`Refusing to replace a non-Lookout executable: ${executable}`);
  }
  const temporary = `${executable}.${process.pid}.${crypto.randomUUID()}.tmp`;
  let previous = null;
  try {
    if (platform === 'win32') {
      const quote = (value) => String(value).replaceAll('%', '%%').replaceAll('"', '""');
      const script = `@rem Lookout CLI\r\n@"${quote(nodePath)}" "${quote(path.join(releaseDirectory, 'bin', 'lookout.js'))}" %*\r\n`;
      await fsp.writeFile(temporary, script, { flag: 'wx' });
    } else {
      await fsp.symlink(path.join(releaseDirectory, 'bin', 'lookout.js'), temporary);
    }
    if (current && platform === 'win32') {
      previous = `${executable}.${process.pid}.${crypto.randomUUID()}.previous`;
      await fsp.rename(executable, previous);
    }
    await fsp.rename(temporary, executable);
    if (previous) {
      await fsp.rm(previous, { force: true });
      previous = null;
    }
  } catch (error) {
    if (previous) {
      try {
        await fsp.rename(previous, executable);
        previous = null;
      } catch { error.message = `${error.message}; previous Lookout launcher retained at ${previous}`; }
    }
    throw error;
  } finally {
    await fsp.rm(temporary, { force: true });
  }
}

async function install(options = {}) {
  const environment = options.environment || process.env;
  const platform = options.platform || process.platform;
  const release = requiredEnvironment(environment);
  await regular(path.join(release.sourceDirectory, 'package.json'), 'Package metadata');
  await regular(path.join(release.sourceDirectory, 'bin', 'lookout.js'), 'CLI executable');
  await regular(path.join(release.sourceDirectory, 'install', 'fleet.js'), 'Fleet installer');
  await regular(path.join(release.sourceDirectory, 'install', 'workstation-link.js'), 'SaaS link helper');
  await regular(path.join(release.sourceDirectory, 'src', 'cli', 'workstation-prepare.js'), 'Workstation preparation tool');
  await regular(path.join(release.sourceDirectory, 'tools', 'lookout-support-report.js'), 'Support report tool');
  await regular(path.join(release.sourceDirectory, 'node_modules', 'yaml', 'package.json'), 'Production dependencies');
  const destination = paths({ environment, platform, home: options.home, ...release });
  const metadata = {
    releaseVersion: release.releaseVersion,
    artifactSha256: release.artifactSha256,
    targets: release.targets
  };
  await installRelease(release.sourceDirectory, destination.releaseDirectory, metadata);
  const nodePath = await executable(path.resolve(environment.LOOKOUT_CLI_NODE_PATH || process.execPath), 'Node.js executable');
  await installLauncher({ ...destination, platform, nodePath });
  return { version: release.releaseVersion, executable: destination.executable, releaseDirectory: destination.releaseDirectory };
}

if (require.main === module) install().then((result) => {
  process.stdout.write(`Lookout CLI ${result.version} installed at ${result.executable}\n`);
  if (!String(process.env.PATH || '').split(path.delimiter).includes(path.dirname(result.executable))) process.stdout.write(`Add ${path.dirname(result.executable)} to PATH for this terminal.\n`);
}).catch((error) => { process.stderr.write(`lookout-cli-install: ${error.message}\n`); process.exitCode = 1; });

module.exports = { install, paths, requiredEnvironment };

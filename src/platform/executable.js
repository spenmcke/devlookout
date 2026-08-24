'use strict';

const fs = require('node:fs');
const path = require('node:path');

function executableExtensions(platform = process.platform, environment = process.env) {
  if (platform !== 'win32') return [''];
  const configured = String(environment.PATHEXT || '.EXE;.CMD;.BAT;.COM')
    .split(';')
    .filter(Boolean)
    .map((extension) => extension.startsWith('.') ? extension : `.${extension}`);
  return ['', ...new Set(configured)];
}

function isExecutable(filename, platform = process.platform) {
  try {
    const stat = fs.statSync(filename);
    if (!stat.isFile()) return false;
    if (platform === 'win32') return true;
    fs.accessSync(filename, fs.constants.X_OK);
    return true;
  } catch { return false; }
}

function resolveExecutable(command, { environment = process.env, platform = process.platform } = {}) {
  if (typeof command !== 'string' || !command || command.includes('\0')) return null;
  const extensions = executableExtensions(platform, environment);
  const hasDirectory = command.includes('/') || command.includes('\\') || path.isAbsolute(command);
  const directories = hasDirectory ? [''] : String(environment.PATH || '').split(path.delimiter).filter(Boolean);
  for (const directory of directories) {
    const base = hasDirectory ? path.resolve(command) : path.join(directory, command);
    const alreadyExtended = platform === 'win32' && extensions.some((extension) => extension && base.toLowerCase().endsWith(extension.toLowerCase()));
    for (const extension of alreadyExtended ? [''] : extensions) {
      const candidate = `${base}${extension}`;
      if (isExecutable(candidate, platform)) return candidate;
    }
  }
  return null;
}

function requireExecutable(command, options = {}) {
  const resolved = resolveExecutable(command, options);
  if (resolved) return resolved;
  const error = new Error(`${command} is required`);
  error.code = 'LOOKOUT_PREREQUISITE_MISSING';
  throw error;
}

module.exports = { resolveExecutable, requireExecutable, executableExtensions, isExecutable };

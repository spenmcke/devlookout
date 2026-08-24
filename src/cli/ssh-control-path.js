'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const OPENSSH_HASH_LENGTH = 40;
const SAFE_CONTROL_PATH_BYTES = 100;

function expandedControlPath(directory) {
  return path.join(directory, 'x'.repeat(OPENSSH_HASH_LENGTH));
}

function fitsOpenSshControlPath(directory) {
  return Buffer.byteLength(expandedControlPath(directory)) <= SAFE_CONTROL_PATH_BYTES;
}

function createSshControlDirectory({ temporaryDirectory = os.tmpdir(), fallbackDirectory = '/tmp', platform = process.platform } = {}) {
  if (platform === 'win32') return null;
  const candidates = [...new Set([temporaryDirectory, fallbackDirectory].filter((item) => typeof item === 'string' && path.isAbsolute(item)))];
  for (const base of candidates) {
    const prospective = path.join(base, 'lo-ssh-XXXXXX');
    if (!fitsOpenSshControlPath(prospective)) continue;
    try {
      const directory = fs.mkdtempSync(path.join(base, 'lo-ssh-'));
      fs.chmodSync(directory, 0o700);
      return directory;
    } catch (error) {
      if (base === candidates.at(-1)) throw error;
    }
  }
  throw new Error('Unable to create a short OpenSSH control socket directory');
}

module.exports = { createSshControlDirectory, expandedControlPath, fitsOpenSshControlPath, SAFE_CONTROL_PATH_BYTES };

'use strict';

const fs = require('node:fs/promises');

async function assertSafePath(target, { allowMissing = true, type = 'file', privateDirectory = false } = {}) {
  let stat;
  try { stat = await fs.lstat(target); }
  catch (error) { if (allowMissing && error.code === 'ENOENT') return null; throw error; }
  if (stat.isSymbolicLink()) throw new Error(`Refusing symbolic link for protected ${type}: ${target}`);
  if (type === 'directory' && !stat.isDirectory()) throw new Error(`Protected storage path is not a directory: ${target}`);
  if (type === 'file' && !stat.isFile()) throw new Error(`Protected storage path is not a regular file: ${target}`);
  if (privateDirectory && process.platform !== 'win32') {
    if ((stat.mode & 0o077) !== 0) throw new Error(`Protected storage directory permissions are too broad: ${target}`);
    if (typeof process.geteuid === 'function' && stat.uid !== process.geteuid()) throw new Error(`Protected storage directory is not owned by the current user: ${target}`);
  }
  return stat;
}

async function syncDirectory(directory) {
  let handle;
  try {
    handle = await fs.open(directory, 'r');
    await handle.sync();
  } finally { await handle?.close(); }
}

async function writeFileDurably(target, content, options = {}) {
  const handle = await fs.open(target, options.flag || 'wx', options.mode || 0o600);
  try {
    await handle.writeFile(content, options.encoding ? { encoding: options.encoding } : undefined);
    await handle.sync();
  } finally { await handle.close(); }
}

module.exports = { assertSafePath, syncDirectory, writeFileDurably };

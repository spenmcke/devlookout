'use strict';

const fs = require('node:fs/promises');
const fsConstants = require('node:fs').constants;
const path = require('node:path');

class SecretReferenceNotFoundError extends Error {}

class SecretProvider {
  async get() { throw new Error('SecretProvider.get must be implemented'); }
}

class EnvironmentSecretProvider extends SecretProvider {
  constructor(mapping, environment = process.env) { super(); this.mapping = new Map(Object.entries(mapping)); this.environment = environment; }
  async get(reference) {
    const variable = this.mapping.get(reference);
    if (!variable) throw new SecretReferenceNotFoundError(`Secret reference is not allowlisted: ${reference}`);
    const value = this.environment[variable];
    if (!value) throw new Error(`Secret environment variable is unset: ${variable}`);
    if (Buffer.byteLength(value, 'utf8') > 65536) throw new Error(`Secret environment variable exceeds the maximum size: ${variable}`);
    return value;
  }
}

class FileSecretProvider extends SecretProvider {
  constructor(mapping) { super(); this.mapping = new Map(Object.entries(mapping).map(([key, value]) => [key, path.resolve(value)])); }
  async get(reference) {
    const file = this.mapping.get(reference);
    if (!file) throw new SecretReferenceNotFoundError(`Secret reference is not allowlisted: ${reference}`);
    let handle;
    try {
      handle = await fs.open(file, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW || 0));
      const stat = await handle.stat();
      if (!stat.isFile()) throw new Error(`Secret path is not a regular file: ${file}`);
      if (stat.size > 65536) throw new Error(`Secret file exceeds the maximum size: ${file}`);
      if (process.platform !== 'win32') {
        if ((stat.mode & 0o077) !== 0) throw new Error(`Secret file permissions are too broad: ${file}`);
        if (typeof process.geteuid === 'function' && stat.uid !== process.geteuid()) throw new Error(`Secret file is not owned by the current user: ${file}`);
      }
      const value = (await handle.readFile('utf8')).trimEnd();
      if (!value) throw new Error(`Secret file is empty: ${file}`);
      return value;
    } catch (error) {
      if (['ELOOP', 'EMLINK'].includes(error.code)) throw new Error(`Secret file must not be a symbolic link: ${file}`);
      throw error;
    } finally { await handle?.close(); }
  }
}

class CompositeSecretProvider extends SecretProvider {
  constructor(providers) { super(); this.providers = providers; }
  async get(reference) {
    const errors = [];
    for (const provider of this.providers) {
      try { return await provider.get(reference); }
      catch (error) {
        if (!(error instanceof SecretReferenceNotFoundError)) throw error;
        errors.push(error.message);
      }
    }
    throw new Error(`Unable to resolve secret reference ${reference}: ${errors.join('; ')}`);
  }
}

module.exports = { SecretReferenceNotFoundError, SecretProvider, EnvironmentSecretProvider, FileSecretProvider, CompositeSecretProvider };

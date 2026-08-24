'use strict';

const crypto = require('node:crypto');

function canonicalize(value) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('Canonical values must contain only finite numbers');
    return value;
  }
  if (Array.isArray(value)) return value.map(canonicalize);
  if (typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().filter((key) => value[key] !== undefined).map((key) => [key, canonicalize(value[key])]));
  }
  throw new TypeError(`Unsupported canonical value type: ${typeof value}`);
}

function canonicalJson(value) {
  return JSON.stringify(canonicalize(value));
}

function stableId(namespace, value) {
  const digest = crypto.createHash('sha256').update(namespace).update('\0').update(canonicalJson(value)).digest('hex');
  return `${namespace}_${digest.slice(0, 24)}`;
}

module.exports = { canonicalize, canonicalJson, stableId };

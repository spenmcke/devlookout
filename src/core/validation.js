'use strict';

const ENTITY_TYPES = new Set([
  'endpoint', 'service', 'software', 'identity', 'credential', 'network', 'zone',
  'route', 'exposure', 'cloud_resource', 'data_resource', 'control', 'telemetry'
]);
const FACT_KINDS = new Set(['entity', 'relationship', 'capability']);
const SECRET_FIELD = /(^|_)(password|passphrase|secret|private_?key|access_?key|api_?key|auth_?token|refresh_?token|session_?token|credential_?value)($|_)/i;
const REFERENCE_FIELD = /(ref|reference|identifier|id)$/i;
const VALUE_LIMITS = Object.freeze({ maximumDepth: 16, maximumNodes: 10000, maximumArrayLength: 4096, maximumObjectKeys: 512, maximumStringBytes: 65536, maximumTotalStringBytes: 1048576 });

class ValidationError extends Error {
  constructor(message, issues = []) {
    super(message);
    this.name = 'ValidationError';
    this.issues = issues;
  }
}

function isPlainObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}

function requireString(value, path, issues) {
  if (typeof value !== 'string' || value.trim() === '') issues.push(`${path} must be a non-empty string`);
}

function assertBoundedValue(value, path = '$', issues = [], limits = VALUE_LIMITS) {
  const seen = new WeakSet();
  let nodes = 0;
  let stringBytes = 0;
  const visit = (item, itemPath, depth, arrayElement = false) => {
    nodes += 1;
    if (nodes > limits.maximumNodes) { issues.push(`${path} exceeds the maximum structural complexity`); return; }
    if (depth > limits.maximumDepth) { issues.push(`${itemPath} exceeds the maximum nesting depth`); return; }
    if (typeof item === 'string') {
      const bytes = Buffer.byteLength(item, 'utf8');
      stringBytes += bytes;
      if (bytes > limits.maximumStringBytes) issues.push(`${itemPath} exceeds the maximum string length`);
      if (stringBytes > limits.maximumTotalStringBytes) issues.push(`${path} exceeds the maximum total string data`);
      return;
    }
    if (typeof item === 'number' && !Number.isFinite(item)) { issues.push(`${itemPath} must be a finite number`); return; }
    if (item === undefined) {
      if (arrayElement) issues.push(`${itemPath} is not JSON-compatible`);
      return;
    }
    if (item !== null && !['string', 'number', 'boolean', 'object'].includes(typeof item)) { issues.push(`${itemPath} is not JSON-compatible`); return; }
    if (!item || typeof item !== 'object') return;
    if (seen.has(item)) { issues.push(`${itemPath} contains a circular reference`); return; }
    seen.add(item);
    if (Array.isArray(item)) {
      if (item.length > limits.maximumArrayLength) issues.push(`${itemPath} exceeds the maximum array length`);
      item.slice(0, limits.maximumArrayLength + 1).forEach((child, index) => visit(child, `${itemPath}[${index}]`, depth + 1, true));
    } else {
      const entries = Object.entries(item);
      if (entries.length > limits.maximumObjectKeys) issues.push(`${itemPath} exceeds the maximum object key count`);
      entries.slice(0, limits.maximumObjectKeys + 1).forEach(([key, child]) => {
        if (Buffer.byteLength(key, 'utf8') > 512) issues.push(`${itemPath} contains an overlong object key`);
        if (['__proto__', 'prototype', 'constructor'].includes(key)) issues.push(`${itemPath}.${key} is not an allowed object key`);
        visit(child, `${itemPath}.${key}`, depth + 1);
      });
    }
    seen.delete(item);
  };
  visit(value, path, 0);
  return issues;
}

function assertNoSecretMaterial(value, path = '$', issues = []) {
  if (Array.isArray(value)) value.forEach((item, index) => assertNoSecretMaterial(item, `${path}[${index}]`, issues));
  else if (isPlainObject(value)) {
    for (const [key, item] of Object.entries(value)) {
      if (SECRET_FIELD.test(key) && !REFERENCE_FIELD.test(key)) issues.push(`${path}.${key} may contain secret material; emit only a reference`);
      assertNoSecretMaterial(item, `${path}.${key}`, issues);
    }
  }
  return issues;
}

function validateAdapterManifest(manifest) {
  const issues = [];
  if (!isPlainObject(manifest)) throw new ValidationError('Adapter manifest must be an object', ['$ must be an object']);
  requireString(manifest.id, '$.id', issues);
  requireString(manifest.version, '$.version', issues);
  requireString(manifest.kind, '$.kind', issues);
  if (!Array.isArray(manifest.capabilities) || manifest.capabilities.length === 0) issues.push('$.capabilities must be a non-empty array');
  else manifest.capabilities.forEach((item, index) => requireString(item, `$.capabilities[${index}]`, issues));
  if (manifest.permissions !== undefined && !Array.isArray(manifest.permissions)) issues.push('$.permissions must be an array when present');
  if (issues.length) throw new ValidationError('Invalid adapter manifest', issues);
  return manifest;
}

function validateFact(fact) {
  const issues = [];
  if (!isPlainObject(fact)) throw new ValidationError('Fact must be an object', ['$ must be an object']);
  assertBoundedValue(fact, '$', issues);
  if (fact.schemaVersion !== 1) issues.push('$.schemaVersion must equal 1');
  requireString(fact.id, '$.id', issues);
  if (!FACT_KINDS.has(fact.kind)) issues.push(`$.kind must be one of: ${[...FACT_KINDS].join(', ')}`);
  if (Number.isNaN(Date.parse(fact.observedAt))) issues.push('$.observedAt must be an ISO-compatible timestamp');
  if (typeof fact.confidence !== 'number' || fact.confidence < 0 || fact.confidence > 1) issues.push('$.confidence must be between 0 and 1');
  if (!isPlainObject(fact.source)) issues.push('$.source must be an object');
  else {
    requireString(fact.source.adapter, '$.source.adapter', issues);
    requireString(fact.source.instance, '$.source.instance', issues);
    requireString(fact.source.recordId, '$.source.recordId', issues);
  }
  if (!isPlainObject(fact.data)) issues.push('$.data must be an object');
  else if (fact.kind === 'entity') {
    requireString(fact.data.entityKey, '$.data.entityKey', issues);
    if (!ENTITY_TYPES.has(fact.data.entityType)) issues.push(`$.data.entityType must be one of: ${[...ENTITY_TYPES].join(', ')}`);
    requireString(fact.data.name, '$.data.name', issues);
    if (fact.data.attributes !== undefined && !isPlainObject(fact.data.attributes)) issues.push('$.data.attributes must be an object');
  } else if (fact.kind === 'relationship') {
    requireString(fact.data.from, '$.data.from', issues);
    requireString(fact.data.to, '$.data.to', issues);
    requireString(fact.data.relation, '$.data.relation', issues);
  } else if (fact.kind === 'capability') {
    requireString(fact.data.entityKey, '$.data.entityKey', issues);
    requireString(fact.data.capability, '$.data.capability', issues);
    if (!['available', 'degraded', 'unavailable', 'unknown'].includes(fact.data.status)) issues.push('$.data.status must be available, degraded, unavailable, or unknown');
  }
  assertNoSecretMaterial(fact.data, '$.data', issues);
  if (issues.length) throw new ValidationError('Invalid observation fact', issues);
  return fact;
}

module.exports = { ENTITY_TYPES, FACT_KINDS, VALUE_LIMITS, ValidationError, isPlainObject, assertBoundedValue, assertNoSecretMaterial, validateAdapterManifest, validateFact };

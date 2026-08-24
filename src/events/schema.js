'use strict';

const { stableId } = require('../core/canonical');
const { ValidationError, assertBoundedValue, assertNoSecretMaterial, isPlainObject } = require('../core/validation');

const EVENT_CATEGORIES = new Set(['identity', 'network', 'system', 'application', 'discovery', 'configuration', 'data', 'health', 'finding']);
const OUTCOMES = new Set(['success', 'failure', 'unknown']);

function nonEmpty(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function validateEvent(event) {
  const issues = [];
  if (!isPlainObject(event)) throw new ValidationError('Event must be an object', ['$ must be an object']);
  assertBoundedValue(event, '$', issues);
  if (event.schemaVersion !== 1) issues.push('$.schemaVersion must equal 1');
  if (!nonEmpty(event.id)) issues.push('$.id must be a non-empty string');
  if (!EVENT_CATEGORIES.has(event.category)) issues.push(`$.category must be one of: ${[...EVENT_CATEGORIES].join(', ')}`);
  if (!nonEmpty(event.class)) issues.push('$.class must be a non-empty string');
  if (!nonEmpty(event.activity)) issues.push('$.activity must be a non-empty string');
  if (!OUTCOMES.has(event.outcome)) issues.push('$.outcome must be success, failure, or unknown');
  if (typeof event.time !== 'string' || Number.isNaN(Date.parse(event.time))) issues.push('$.time must be an ISO-compatible timestamp string');
  if (typeof event.ingestedAt !== 'string' || Number.isNaN(Date.parse(event.ingestedAt))) issues.push('$.ingestedAt must be an ISO-compatible timestamp string');
  if (!isPlainObject(event.source) || !nonEmpty(event.source.adapter) || !nonEmpty(event.source.instance) || !nonEmpty(event.source.recordId)) issues.push('$.source must identify adapter, instance, and recordId');
  if (!Array.isArray(event.entityKeys)) issues.push('$.entityKeys must be an array');
  else if (event.entityKeys.length > 256) issues.push('$.entityKeys must contain at most 256 entries');
  else event.entityKeys.forEach((key, index) => { if (!nonEmpty(key)) issues.push(`$.entityKeys[${index}] must be a non-empty string`); });
  if (!isPlainObject(event.attributes)) issues.push('$.attributes must be an object');
  assertNoSecretMaterial(event, '$', issues);
  if (issues.length) throw new ValidationError('Invalid normalized event', issues);
  return event;
}

function createEvent({ time, ingestedAt = new Date().toISOString(), category, class: eventClass, activity, outcome = 'unknown', severity = 0, source, entityKeys = [], actor = null, sourceEndpoint = null, destinationEndpoint = null, service = null, correlation = {}, attributes = {}, rawReference = null }) {
  const event = {
    schemaVersion: 1,
    id: stableId('event', { adapter: source.adapter, instance: source.instance, recordId: source.recordId, class: eventClass }),
    time,
    ingestedAt,
    category,
    class: eventClass,
    activity,
    outcome,
    severity: Number.isFinite(severity) ? Math.max(0, Math.min(10, severity)) : 0,
    source: structuredClone(source),
    entityKeys: [...new Set(entityKeys)].sort(),
    actor: actor ? structuredClone(actor) : null,
    sourceEndpoint: sourceEndpoint ? structuredClone(sourceEndpoint) : null,
    destinationEndpoint: destinationEndpoint ? structuredClone(destinationEndpoint) : null,
    service: service ? structuredClone(service) : null,
    correlation: structuredClone(correlation),
    attributes: structuredClone(attributes),
    rawReference
  };
  return validateEvent(event);
}

module.exports = { EVENT_CATEGORIES, OUTCOMES, validateEvent, createEvent };

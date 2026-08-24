'use strict';

const YAML = require('yaml');
const { stableId } = require('../core/canonical');

const DEFAULT_FIELD_MAP = {
  User: 'actor.id', UserName: 'actor.id', SourceIp: 'sourceEndpoint.address', SourceIP: 'sourceEndpoint.address',
  DestinationIp: 'destinationEndpoint.address', DestinationIP: 'destinationEndpoint.address', DestinationPort: 'destinationEndpoint.port',
  Image: 'attributes.processPath', ParentImage: 'attributes.parentProcessPath', CommandLine: 'attributes.commandLine',
  TargetFilename: 'attributes.resourcePath', EventID: 'attributes.eventId', ProcessId: 'attributes.processId', ParentProcessId: 'attributes.parentProcessId'
};

const LOGSOURCE_MAP = {
  process_creation: { selector: { class: 'process_activity', activity: 'start' }, requirements: { all: ['process_execution'] } },
  network_connection: { selector: { class: 'network_activity' }, requirements: { all: ['network_flow'] } },
  authentication: { selector: { class: 'authentication' }, requirements: { all: ['authentication'] } },
  file_event: { selector: { class: 'file_activity' }, requirements: { all: ['file_access'] } },
  dns_query: { selector: { class: 'dns_activity' }, requirements: { all: ['dns'] } },
  registry_event: { selector: { class: 'configuration_activity' }, requirements: { all: ['configuration_change'] } }
};

function wildcardCondition(value) {
  if (typeof value !== 'string' || !value.includes('*')) return value;
  if (value.startsWith('*') && value.endsWith('*') && value.slice(1, -1).includes('*') === false) return { contains: value.slice(1, -1) };
  if (value.endsWith('*') && !value.slice(0, -1).includes('*')) return { startsWith: value.slice(0, -1) };
  if (value.startsWith('*') && !value.slice(1).includes('*')) return { endsWith: value.slice(1) };
  throw new Error(`Unsupported Sigma wildcard expression: ${value}`);
}

function compileSelection(selection, fieldMap) {
  if (Array.isArray(selection)) return { $or: selection.map((item) => compileSelection(item, fieldMap)) };
  if (!selection || typeof selection !== 'object') throw new Error('Sigma selections must be mappings or arrays of mappings');
  const clauses = [];
  for (const [rawField, rawValue] of Object.entries(selection)) {
    const [field, ...modifiers] = rawField.split('|');
    const path = fieldMap[field];
    if (!path) throw new Error(`Unmapped Sigma field: ${field}`);
    const unsupported = modifiers.filter((modifier) => !['contains', 'startswith', 'endswith', 'all'].includes(modifier));
    if (unsupported.length) throw new Error(`Unsupported Sigma modifier: ${unsupported.join(', ')}`);
    const values = Array.isArray(rawValue) ? rawValue : [rawValue];
    let condition;
    if (modifiers.includes('contains')) condition = modifiers.includes('all') ? { containsAll: values } : values.length === 1 ? { contains: values[0] } : { $orValues: values.map((value) => ({ contains: value })) };
    else if (modifiers.includes('startswith')) condition = values.length === 1 ? { startsWith: values[0] } : { $orValues: values.map((value) => ({ startsWith: value })) };
    else if (modifiers.includes('endswith')) condition = values.length === 1 ? { endsWith: values[0] } : { $orValues: values.map((value) => ({ endsWith: value })) };
    else if (values.length === 1) condition = wildcardCondition(values[0]);
    else condition = { in: values };
    if (condition.$orValues) {
      clauses.push({ $or: condition.$orValues.map((item) => ({ [path]: item })) });
    } else clauses.push({ [path]: condition });
  }
  return clauses.length === 1 ? clauses[0] : { $and: clauses };
}

function expandQuantifiers(condition, names) {
  return condition.replace(/\b(1|all)\s+of\s+([\w*]+|them)\b/gi, (_, count, pattern) => {
    const selected = pattern.toLowerCase() === 'them' ? names : names.filter((name) => pattern.endsWith('*') ? name.startsWith(pattern.slice(0, -1)) : name === pattern);
    if (!selected.length) throw new Error(`Sigma condition pattern matched no selections: ${pattern}`);
    return `(${selected.join(count.toLowerCase() === 'all' ? ' and ' : ' or ')})`;
  });
}

function parseCondition(condition, selections) {
  const names = Object.keys(selections).sort();
  const expanded = expandQuantifiers(condition, names);
  const tokens = expanded.match(/\(|\)|\b(?:and|or|not)\b|[A-Za-z0-9_-]+/gi) || [];
  let index = 0;
  const primary = () => {
    const token = tokens[index++];
    if (token === '(') { const value = expression(); if (tokens[index++] !== ')') throw new Error('Unbalanced Sigma condition parentheses'); return value; }
    if (!token || !selections[token]) throw new Error(`Unknown Sigma selection in condition: ${token || '<end>'}`);
    return selections[token];
  };
  const unary = () => tokens[index]?.toLowerCase() === 'not' ? (index += 1, { $not: unary() }) : primary();
  const conjunction = () => { let left = unary(); while (tokens[index]?.toLowerCase() === 'and') { index += 1; left = { $and: [left, unary()] }; } return left; };
  const expression = () => { let left = conjunction(); while (tokens[index]?.toLowerCase() === 'or') { index += 1; left = { $or: [left, conjunction()] }; } return left; };
  const result = expression();
  if (index !== tokens.length) throw new Error(`Unexpected Sigma condition token: ${tokens[index]}`);
  return result;
}

function compileSigmaDocument(document, { fieldMap = DEFAULT_FIELD_MAP, logsourceMap = LOGSOURCE_MAP } = {}) {
  if (!document || typeof document.title !== 'string' || !document.detection || typeof document.detection.condition !== 'string') throw new Error('Sigma rule requires title and detection.condition');
  if (document.correlation) throw new Error('Sigma correlation documents require a dedicated correlation importer');
  const logsourceKey = document.logsource?.category || document.logsource?.service;
  const logsource = logsourceMap[logsourceKey];
  if (!logsource) throw new Error(`Unsupported Sigma logsource: ${logsourceKey || '<missing>'}`);
  const selections = Object.fromEntries(Object.entries(document.detection).filter(([name]) => name !== 'condition' && !name.startsWith('timeframe')).map(([name, selection]) => [name, compileSelection(selection, fieldMap)]));
  const detectionSelector = parseCondition(document.detection.condition, selections);
  const levelMap = { informational: 'informational', low: 'low', medium: 'medium', high: 'high', critical: 'critical' };
  return {
    id: document.id || stableId('sigma', { title: document.title, logsource: document.logsource, detection: document.detection }),
    version: String(document.modified || document.date || '1.0.0'),
    title: document.title,
    kind: 'event',
    severity: levelMap[document.level] || 'medium',
    enabled: !['deprecated', 'unsupported'].includes(document.status),
    requirements: structuredClone(logsource.requirements),
    selector: { $and: [structuredClone(logsource.selector), detectionSelector] },
    exclusions: [],
    source: { format: 'sigma', status: document.status || 'unknown', references: document.references || [], falsePositives: document.falsepositives || [] }
  };
}

function parseSigmaYaml(text, options) {
  if (typeof text !== 'string' || Buffer.byteLength(text) > 2 * 1024 * 1024) throw new Error('Sigma YAML must be a string no larger than 2 MiB');
  const documents = YAML.parseAllDocuments(text, { maxAliasCount: 50, prettyErrors: true });
  return documents.map((document) => {
    if (document.errors.length) throw document.errors[0];
    return compileSigmaDocument(document.toJS({ maxAliasCount: 50 }), options);
  });
}

module.exports = { DEFAULT_FIELD_MAP, LOGSOURCE_MAP, wildcardCondition, compileSelection, parseCondition, compileSigmaDocument, parseSigmaYaml };

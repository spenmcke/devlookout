'use strict';

const { stableId } = require('../core/canonical');
const { validateEvent } = require('../events/schema');
const { getPath, matches } = require('./predicates');

const SEVERITY_SCORE = { informational: 1, low: 3, medium: 5, high: 8, critical: 10 };

function groupKey(event, paths = []) {
  const values = paths.map((path) => getPath(event, path));
  if (values.some((value) => value === undefined || value === null)) return null;
  return values.map((value) => JSON.stringify(value)).join('|');
}

function excluded(event, rule) {
  return (rule.exclusions || []).some((exclusion) => matches(event, exclusion.selector));
}

function finding(rule, events, rationale, confidence = 1) {
  const ordered = [...events].sort((a, b) => a.time.localeCompare(b.time) || a.id.localeCompare(b.id));
  const evidence = ordered.map((event) => event.id);
  const entities = [...new Set(ordered.flatMap((event) => event.entityKeys))].sort();
  return {
    schemaVersion: 1,
    id: stableId('finding', { rule: rule.id, version: rule.version, evidence }),
    ruleId: rule.id,
    ruleVersion: rule.version,
    title: rule.title,
    severity: rule.severity,
    severityScore: SEVERITY_SCORE[rule.severity] || 0,
    alertDisposition: rule.alertDisposition || (SEVERITY_SCORE[rule.severity] >= 8 ? 'high_confidence' : 'correlation_only'),
    kind: rule.kind,
    time: ordered.at(-1).time,
    firstSeen: ordered[0].time,
    confidence: Math.max(0, Math.min(1, confidence)),
    status: 'open',
    evidence,
    entities,
    rationale
  };
}

function eventFindings(rule, events) {
  return events.filter((event) => matches(event, rule.selector) && (!rule.scope || matches(event, rule.scope)) && !excluded(event, rule)).map((event) => finding(rule, [event], 'A normalized event matched every required condition.'));
}

function thresholdFindings(rule, events) {
  const candidates = events.filter((event) => matches(event, rule.selector) && (!rule.scope || matches(event, rule.scope)) && !excluded(event, rule));
  const groups = new Map();
  for (const event of candidates) {
    const key = groupKey(event, rule.groupBy);
    if (key === null && rule.groupBy.length) continue;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(event);
  }
  const output = [];
  const windowMs = rule.windowSeconds * 1000;
  for (const group of groups.values()) {
    group.sort((a, b) => a.time.localeCompare(b.time) || a.id.localeCompare(b.id));
    let start = 0;
    for (let end = 0; end < group.length; end += 1) {
      while (Date.parse(group[end].time) - Date.parse(group[start].time) > windowMs) start += 1;
      const window = group.slice(start, end + 1);
      const count = rule.distinctBy ? new Set(window.map((event) => getPath(event, rule.distinctBy)).filter((value) => value !== undefined && value !== null).map(JSON.stringify)).size : window.length;
      if (count >= rule.threshold) {
        output.push(finding(rule, window, `${count}${rule.distinctBy ? ' distinct' : ''} matching observations occurred within ${rule.windowSeconds} seconds.`));
        start = end + 1;
      }
    }
  }
  return output;
}

function sequenceFindings(rule, events) {
  const ordered = events.filter((event) => (!rule.scope || matches(event, rule.scope)) && !excluded(event, rule)).sort((a, b) => a.time.localeCompare(b.time) || a.id.localeCompare(b.id));
  const output = [];
  const consumed = new Set();
  const windowMs = rule.windowSeconds * 1000;
  for (let index = 0; index < ordered.length; index += 1) {
    if (consumed.has(ordered[index].id)) continue;
    if (!matches(ordered[index], rule.sequence[0])) continue;
    const initialGroup = groupKey(ordered[index], rule.groupBy);
    if (initialGroup === null && rule.groupBy.length) continue;
    const chain = [ordered[index]];
    let cursor = index + 1;
    for (let step = 1; step < rule.sequence.length; step += 1) {
      const next = ordered.slice(cursor).findIndex((candidate) => !consumed.has(candidate.id) && Date.parse(candidate.time) - Date.parse(chain[0].time) <= windowMs && groupKey(candidate, rule.groupBy) === initialGroup && matches(candidate, rule.sequence[step]));
      if (next < 0) { chain.length = 0; break; }
      cursor += next + 1;
      chain.push(ordered[cursor - 1]);
    }
    if (chain.length === rule.sequence.length) {
      output.push(finding(rule, chain, `${chain.length} ordered behaviors occurred within ${rule.windowSeconds} seconds.`));
      for (const event of chain) consumed.add(event.id);
    }
  }
  return output;
}

function validateRule(rule) {
  if (!rule || typeof rule.id !== 'string' || typeof rule.version !== 'string' || typeof rule.title !== 'string') throw new Error('Rule requires id, version, and title');
  if (!['event', 'threshold', 'sequence'].includes(rule.kind)) throw new Error(`Unsupported rule kind: ${rule.kind}`);
  if (!SEVERITY_SCORE[rule.severity]) throw new Error(`Unsupported rule severity: ${rule.severity}`);
  if (rule.alertDisposition != null && !['always', 'high_confidence', 'correlation_only'].includes(rule.alertDisposition)) throw new Error(`Unsupported alert disposition: ${rule.alertDisposition}`);
  if (rule.kind === 'threshold' && (!Number.isSafeInteger(rule.threshold) || rule.threshold < 1 || rule.threshold > 100000 || !Number.isSafeInteger(rule.windowSeconds) || rule.windowSeconds < 1 || rule.windowSeconds > 2592000 || !Array.isArray(rule.groupBy) || rule.groupBy.length > 16)) throw new Error('Threshold rule requires bounded positive threshold, windowSeconds, and groupBy');
  if (rule.kind === 'sequence' && (!Array.isArray(rule.sequence) || rule.sequence.length < 2 || rule.sequence.length > 32 || !Number.isSafeInteger(rule.windowSeconds) || rule.windowSeconds < 1 || rule.windowSeconds > 2592000 || !Array.isArray(rule.groupBy) || rule.groupBy.length > 16)) throw new Error('Sequence rule requires a bounded sequence, positive windowSeconds, and groupBy');
  return rule;
}

function evaluate(rules, events) {
  const normalized = [...events].map(validateEvent);
  const findings = [];
  for (const rule of [...rules].map(validateRule).filter((item) => item.enabled !== false).sort((a, b) => a.id.localeCompare(b.id))) {
    if (rule.kind === 'event') findings.push(...eventFindings(rule, normalized));
    else if (rule.kind === 'threshold') findings.push(...thresholdFindings(rule, normalized));
    else findings.push(...sequenceFindings(rule, normalized));
  }
  return [...new Map(findings.map((item) => [item.id, item])).values()].sort((a, b) => b.time.localeCompare(a.time) || a.id.localeCompare(b.id));
}

module.exports = { SEVERITY_SCORE, validateRule, evaluate, finding };

'use strict';

function getPath(value, path) {
  if (typeof path !== 'string' || path.length > 512) return undefined;
  const segments = path.split('.');
  if (segments.some((key) => !key || ['__proto__', 'prototype', 'constructor'].includes(key))) return undefined;
  return segments.reduce((current, key) => current == null ? undefined : current[key], value);
}

function matchesCondition(actual, condition) {
  if (condition === null || typeof condition !== 'object' || Array.isArray(condition)) return actual === condition;
  if (Object.hasOwn(condition, 'equals') && actual !== condition.equals) return false;
  if (Object.hasOwn(condition, 'notEquals') && actual === condition.notEquals) return false;
  if (condition.in && !condition.in.includes(actual)) return false;
  if (condition.notIn && condition.notIn.includes(actual)) return false;
  if (Object.hasOwn(condition, 'exists') && condition.exists !== (actual !== undefined && actual !== null)) return false;
  if (Object.hasOwn(condition, 'gt') && !(actual > condition.gt)) return false;
  if (Object.hasOwn(condition, 'gte') && !(actual >= condition.gte)) return false;
  if (Object.hasOwn(condition, 'lt') && !(actual < condition.lt)) return false;
  if (Object.hasOwn(condition, 'lte') && !(actual <= condition.lte)) return false;
  if (condition.contains !== undefined) {
    if (Array.isArray(actual) && !actual.includes(condition.contains)) return false;
    if (typeof actual === 'string' && !actual.includes(condition.contains)) return false;
    if (!Array.isArray(actual) && typeof actual !== 'string') return false;
  }
  if (condition.containsAll !== undefined) {
    if (!Array.isArray(condition.containsAll)) return false;
    if (Array.isArray(actual) && !condition.containsAll.every((value) => actual.includes(value))) return false;
    if (typeof actual === 'string' && !condition.containsAll.every((value) => actual.includes(value))) return false;
    if (!Array.isArray(actual) && typeof actual !== 'string') return false;
  }
  if (condition.startsWith !== undefined && (typeof actual !== 'string' || !actual.startsWith(condition.startsWith))) return false;
  if (condition.endsWith !== undefined && (typeof actual !== 'string' || !actual.endsWith(condition.endsWith))) return false;
  return true;
}

function matches(event, selector = {}) {
  if (selector.$and && !selector.$and.every((item) => matches(event, item))) return false;
  if (selector.$or && !selector.$or.some((item) => matches(event, item))) return false;
  if (selector.$not && matches(event, selector.$not)) return false;
  return Object.entries(selector).filter(([path]) => !path.startsWith('$')).every(([path, condition]) => matchesCondition(getPath(event, path), condition));
}

function selectorSpecificity(selector = {}) {
  return Object.entries(selector).reduce((score, [path, value]) => {
    if (path === '$and' || path === '$or') return score + value.reduce((sum, item) => sum + selectorSpecificity(item), 0);
    if (path === '$not') return score + selectorSpecificity(value);
    return score + (path === 'entityKeys' || path.endsWith('.id') || path.endsWith('Key') ? 2 : 1);
  }, 0);
}

module.exports = { getPath, matchesCondition, matches, selectorSpecificity };
